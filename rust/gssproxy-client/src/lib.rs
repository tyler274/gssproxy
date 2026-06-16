//! `gssproxy-client`: the client-side transport that talks to the gssproxy
//! daemon over its Unix socket.
//!
//! This is the Rust port of `src/client/gpm_common.c` — specifically the
//! connection-management and `gpm_make_call` machinery. The per-procedure
//! `gpm_*` wrappers in C also performed the GSSAPI <-> gssx conversion; in the
//! Rust split that conversion lives in the interposer (`gssproxy-interposer`),
//! which calls into [`make_call`] here with already-encoded `gssx_arg_*`
//! values and decodes the returned `gssx_res_*`.
//!
//! The transport mirrors the C client's behaviour:
//!   - a single process-global connection guarded by a recursive-friendly
//!     mutex (here a plain [`std::sync::Mutex`], since `make_call` never
//!     re-enters itself),
//!   - fork / euid / egid change detection that drops a stale socket (C:
//!     `gpm_grab_sock`),
//!   - SunRPC single-fragment record-marking framing (C: `gpm_send_buffer` /
//!     `gpm_recv_buffer`),
//!   - a 15s response timeout with up to 3 reconnect-and-retry attempts (C:
//!     `RESPONSE_TIMEOUT` / `MAX_TIMEOUT_RETRY` driven by epoll + timerfd).
//!
//! Environment lookups use `secure_getenv` (C: `gp_getenv`) so the library is
//! safe to load into setuid programs.

use std::ffi::{CStr, CString, OsString};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Duration;

use gssproxy_proto::frame::{encode_header, parse_header};
use gssproxy_proto::proc::GssxProc;
use gssproxy_proto::rpc::{Message, ReplyBody, MAX_RPC_SIZE};
use gssproxy_proto::xdr::{Xdr, XdrDecoder};

pub mod gpm;

/// Compiled-in default socket path (autotools `GP_SOCKET_NAME`).
const GP_SOCKET_NAME: &str = "/var/lib/gssproxy/default.sock";

/// Per-call response timeout (C: `RESPONSE_TIMEOUT`).
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// Number of reconnect-and-retry attempts on timeout (C: `MAX_TIMEOUT_RETRY`).
const MAX_TIMEOUT_RETRY: usize = 3;

/// Error returned by [`make_call`].
///
/// The interposer maps these onto GSSAPI major/minor status codes; the
/// `errno`-style value (where one exists) is preserved so callers can
/// distinguish "daemon unreachable" from "bad reply".
#[derive(Debug)]
pub enum GpmError {
    /// Underlying socket I/O failed (connect/read/write), including timeouts.
    Io(io::Error),
    /// The RPC framing header was malformed (multi-fragment or oversized).
    Frame(gssproxy_proto::FrameError),
    /// The reply could not be decoded as the expected `gssx_res_*` type.
    Decode(gssproxy_proto::XdrError),
    /// The reply envelope was well-formed but not an accepted-success reply
    /// for our xid (wrong xid, denied, or non-success accept status).
    BadReply,
    /// The request body exceeded `MAX_RPC_SIZE`.
    TooLarge,
}

impl GpmError {
    /// Best-effort `errno` for the failure, mirroring the integer returned by
    /// the C `gpm_make_call`. Defaults to `EIO` for protocol-level errors.
    pub fn errno(&self) -> i32 {
        match self {
            GpmError::Io(e) => e.raw_os_error().unwrap_or(libc::EIO),
            GpmError::TooLarge => libc::EMSGSIZE,
            _ => libc::EIO,
        }
    }
}

impl std::fmt::Display for GpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpmError::Io(e) => write!(f, "gssproxy socket I/O error: {e}"),
            GpmError::Frame(e) => write!(f, "gssproxy framing error: {e}"),
            GpmError::Decode(e) => write!(f, "gssproxy reply decode error: {e}"),
            GpmError::BadReply => write!(f, "gssproxy returned an unexpected RPC reply"),
            GpmError::TooLarge => write!(f, "gssproxy request exceeds MAX_RPC_SIZE"),
        }
    }
}

impl std::error::Error for GpmError {}

impl From<io::Error> for GpmError {
    fn from(e: io::Error) -> Self {
        GpmError::Io(e)
    }
}

/// Result alias for client transport operations.
pub type Result<T> = std::result::Result<T, GpmError>;

extern "C" {
    // glibc's secure_getenv (not exposed by the libc crate on all versions).
    fn secure_getenv(name: *const libc::c_char) -> *mut libc::c_char;
}

/// `secure_getenv` wrapper (C: `gp_getenv`). Returns `None` in setuid/setgid
/// contexts so an attacker cannot redirect the proxy socket.
fn secure_getenv_os(name: &str) -> Option<OsString> {
    let cname = CString::new(name).ok()?;
    // SAFETY: `cname` is a valid NUL-terminated string; secure_getenv returns
    // either NULL or a pointer into the environment that we copy immediately.
    let ptr = unsafe { secure_getenv(cname.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec();
    Some(OsString::from_vec(bytes))
}

/// Resolve the daemon socket path (C: `get_pipe_name`).
fn socket_path() -> OsString {
    secure_getenv_os("GSSPROXY_SOCKET").unwrap_or_else(|| OsString::from(GP_SOCKET_NAME))
}

/// Process-global connection state, mirroring C's `gpm_global_ctx`.
struct ClientConn {
    stream: Option<UnixStream>,
    /// Identity captured when `stream` was opened, used to detect fork/setuid.
    pid: libc::pid_t,
    uid: libc::uid_t,
    gid: libc::gid_t,
    next_xid: u32,
    seeded: bool,
}

static CONN: Mutex<ClientConn> = Mutex::new(ClientConn {
    stream: None,
    pid: 0,
    uid: 0,
    gid: 0,
    next_xid: 0,
    seeded: false,
});

impl ClientConn {
    /// Seed the xid counter once from the kernel CSPRNG (C: `getrandom` in
    /// `gpm_init_once`). The daemon merely echoes the xid, so any sequence is
    /// acceptable; we randomise the start only to match upstream behaviour.
    fn ensure_seeded(&mut self) {
        if self.seeded {
            return;
        }
        let mut buf = [0u8; 4];
        // SAFETY: writing exactly buf.len() bytes into a valid local buffer.
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = unsafe {
                libc::getrandom(
                    buf.as_mut_ptr().add(filled) as *mut libc::c_void,
                    buf.len() - filled,
                    0,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // Fall back to a fixed seed; correctness does not depend on it.
                break;
            }
            filled += n as usize;
        }
        self.next_xid = u32::from_ne_bytes(buf);
        self.seeded = true;
    }

    /// Return the next xid, mirroring `gpm_next_xid`'s wrap handling.
    fn next_xid(&mut self) -> u32 {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        xid
    }

    /// Drop a connection whose owning identity changed (C: fork/setuid check
    /// in `gpm_grab_sock`).
    fn refresh_identity(&mut self) {
        if self.stream.is_none() {
            return;
        }
        // SAFETY: these syscalls are always safe to call.
        let p = unsafe { libc::getpid() };
        let u = unsafe { libc::geteuid() };
        let g = unsafe { libc::getegid() };
        if p != self.pid || u != self.uid || g != self.gid {
            self.disconnect();
        }
    }

    /// Open the socket and record the owning identity (C: `gpm_open_socket`).
    fn connect(&mut self) -> Result<()> {
        let stream = UnixStream::connect(socket_path())?;
        stream.set_read_timeout(Some(RESPONSE_TIMEOUT))?;
        stream.set_write_timeout(Some(RESPONSE_TIMEOUT))?;
        // SAFETY: always-safe syscalls.
        self.pid = unsafe { libc::getpid() };
        self.uid = unsafe { libc::geteuid() };
        self.gid = unsafe { libc::getegid() };
        self.stream = Some(stream);
        Ok(())
    }

    fn disconnect(&mut self) {
        self.stream = None;
    }

    /// Send a framed request body and read back the framed reply body
    /// (C: `gpm_send_buffer` + `gpm_recv_buffer`, single fragment).
    fn try_transact(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        let stream = self.stream.as_mut().expect("transact without a stream");

        stream.write_all(&encode_header(body.len()))?;
        stream.write_all(body)?;
        stream.flush()?;

        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr)?;
        let len = parse_header(u32::from_be_bytes(hdr)).map_err(GpmError::Frame)?;

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Run one request/response transaction with reconnect-and-retry on
    /// timeout or broken socket (C: `gpm_send_recv_loop`).
    fn transact(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        if body.len() > MAX_RPC_SIZE {
            return Err(GpmError::TooLarge);
        }

        let mut last_err: Option<GpmError> = None;
        for _ in 0..MAX_TIMEOUT_RETRY {
            if self.stream.is_none() {
                self.connect()?;
            }
            match self.try_transact(body) {
                Ok(buf) => return Ok(buf),
                Err(GpmError::Io(e)) if is_retryable(&e) => {
                    // Close and reopen before trying again (C: gpm_retry_socket).
                    self.disconnect();
                    last_err = Some(GpmError::Io(e));
                    continue;
                }
                Err(e) => {
                    self.disconnect();
                    return Err(e);
                }
            }
        }
        Err(last_err.unwrap_or(GpmError::BadReply))
    }
}

/// Whether a socket error warrants a reconnect-and-retry (timeout, reset,
/// closed pipe). Mirrors the C client's handling of `ETIMEDOUT`/`EIO`.
fn is_retryable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
    )
}

/// Perform a complete gssproxy RPC: encode the call envelope plus `arg`, send
/// it to the daemon, and decode the accepted-success reply into `R`.
///
/// This is the typed analogue of C's `gpm_make_call`: instead of a runtime
/// `xdrproc_t` table indexed by procedure number, the argument and result
/// types are supplied as generics by the caller.
pub fn make_call<A: Xdr, R: Xdr>(proc: GssxProc, arg: &A) -> Result<R> {
    let mut conn = CONN.lock().unwrap_or_else(|e| e.into_inner());
    conn.ensure_seeded();
    conn.refresh_identity();

    let xid = conn.next_xid();
    let body = gssproxy_proto::encode_request(xid, proc as u32, arg);

    let reply = conn.transact(&body)?;
    // The lock is intentionally held across the whole conversation, matching
    // the C client which serialises all traffic on a single socket.
    drop(conn);

    let mut d = XdrDecoder::new(&reply);
    let msg = Message::decode(&mut d).map_err(GpmError::Decode)?;
    if msg.xid != xid || msg.is_call {
        return Err(GpmError::BadReply);
    }
    match msg.reply {
        Some(ReplyBody::AcceptedSuccess { .. }) => {}
        _ => return Err(GpmError::BadReply),
    }

    R::decode(&mut d).map_err(GpmError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gssproxy_proto::proc::{
        ArgIndicateMechs, ArgInitSecContext, ResIndicateMechs, ResInitSecContext,
    };
    use gssproxy_proto::rpc::{ReplyBody, FRAGMENT_BIT, GSSPROXY, GSSPROXYVERS, RPC_VERS};
    use gssproxy_proto::xdr::XdrEncoder;
    use gssproxy_proto::{encode_reply, encode_request, frame, Message};
    use proptest::prelude::*;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};

    // make_call drives a *process-global* connection keyed on the
    // GSSPROXY_SOCKET environment variable. Serialise every test that touches
    // that state so parallel test threads don't clobber each other.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static S: Mutex<()> = Mutex::new(());
        S.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Force the next make_call to open a fresh connection (drops any socket
    /// left connected by a previous test).
    fn reset_connection() {
        CONN.lock().unwrap_or_else(|e| e.into_inner()).stream = None;
    }

    fn unique() -> u64 {
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed)
    }

    /// Create a private temp dir + socket path and point GSSPROXY_SOCKET at it.
    fn setup_socket(tag: &str) -> (PathBuf, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("gpm-{tag}-{}-{}", std::process::id(), unique()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s.sock");
        let _ = std::fs::remove_file(&sock);
        std::env::set_var("GSSPROXY_SOCKET", &sock);
        reset_connection();
        (dir, sock)
    }

    fn cleanup(dir: PathBuf, sock: PathBuf) {
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir(&dir);
    }

    /// Read one record frame (4-byte header + body). Returns `None` on EOF.
    fn read_frame(c: &mut UnixStream) -> Option<(u32, Vec<u8>)> {
        let mut hdr = [0u8; 4];
        c.read_exact(&mut hdr).ok()?;
        let word = u32::from_be_bytes(hdr);
        let len = parse_header(word).expect("client must set the fragment bit");
        let mut body = vec![0u8; len];
        c.read_exact(&mut body).ok()?;
        Some((word, body))
    }

    fn xid_of(body: &[u8]) -> u32 {
        Message::decode(&mut XdrDecoder::new(body)).unwrap().xid
    }

    fn success_reply<R: Xdr>(xid: u32, res: &R) -> Vec<u8> {
        frame(&encode_reply(xid, res))
    }

    /// Server accepting exactly `conns` connections, reading exactly one
    /// request per connection. `script(i, body)` returns the raw bytes to write
    /// back (already framed), or `None` to close without replying. Returns the
    /// recorded `(header_word, body)` of every request seen.
    fn spawn_server<F>(path: PathBuf, conns: usize, script: F) -> JoinHandle<Vec<(u32, Vec<u8>)>>
    where
        F: Fn(usize, &[u8]) -> Option<Vec<u8>> + Send + 'static,
    {
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let mut recorded = Vec::new();
            for i in 0..conns {
                let (mut c, _) = match listener.accept() {
                    Ok(x) => x,
                    Err(_) => break,
                };
                if let Some((word, body)) = read_frame(&mut c) {
                    recorded.push((word, body.clone()));
                    if let Some(raw) = script(i, &body) {
                        let _ = c.write_all(&raw);
                        let _ = c.flush();
                    }
                }
            }
            recorded
        })
    }

    /// Server accepting a single connection and replying success to every
    /// request until the client closes the socket (models the C daemon's
    /// long-lived per-client connection). Returns the recorded request bodies.
    fn spawn_server_persistent(path: PathBuf) -> JoinHandle<Vec<Vec<u8>>> {
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let mut recorded = Vec::new();
            if let Ok((mut c, _)) = listener.accept() {
                while let Some((_, body)) = read_frame(&mut c) {
                    let xid = xid_of(&body);
                    recorded.push(body);
                    let reply = success_reply(xid, &ResIndicateMechs::default());
                    if c.write_all(&reply).is_err() {
                        break;
                    }
                    let _ = c.flush();
                }
            }
            recorded
        })
    }

    #[test]
    fn request_is_byte_exact_with_c_envelope() {
        let _g = serial();
        let (dir, sock) = setup_socket("byteexact");
        let server = spawn_server(sock.clone(), 1, |_, body| {
            Some(success_reply(xid_of(body), &ResIndicateMechs::default()))
        });

        let _res: ResIndicateMechs =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default()).unwrap();

        let recorded = server.join().unwrap();
        assert_eq!(recorded.len(), 1);
        let (word, body) = &recorded[0];

        // Framing: the fragment (last-record) bit is set and the advertised
        // length matches the body (C: FRAGMENT_BIT in gpm_send_buffer).
        assert_ne!(word & FRAGMENT_BIT, 0, "fragment bit must be set");
        assert_eq!((word & !FRAGMENT_BIT) as usize, body.len());

        // The body is byte-for-byte what gssproxy-proto encodes (the same XDR
        // the C client emits via xdr_gp_rpc_msg + the proc arg encoder).
        let xid = xid_of(body);
        let expected = encode_request(
            xid,
            GssxProc::IndicateMechs as u32,
            &ArgIndicateMechs::default(),
        );
        assert_eq!(body, &expected);

        // Envelope fields match the constants gpm_common.c hard-codes.
        let msg = Message::decode(&mut XdrDecoder::new(body)).unwrap();
        assert!(msg.is_call);
        let ch = msg.call.unwrap();
        assert_eq!(ch.rpcvers, RPC_VERS);
        assert_eq!(ch.prog, GSSPROXY);
        assert_eq!(ch.vers, GSSPROXYVERS);
        assert_eq!(ch.proc_num, GssxProc::IndicateMechs as u32);
        assert_eq!(ch.cred.flavor, 0); // AUTH_NONE
        assert!(ch.cred.body.is_empty());
        assert_eq!(ch.verf.flavor, 0);
        assert!(ch.verf.body.is_empty());

        cleanup(dir, sock);
    }

    #[test]
    fn round_trips_multiple_procs() {
        let _g = serial();
        let (dir, sock) = setup_socket("multiproc");
        // Two connections: one indicate_mechs, one init_sec_context.
        let server = spawn_server(sock.clone(), 2, |i, body| {
            let xid = xid_of(body);
            Some(if i == 0 {
                success_reply(xid, &ResIndicateMechs::default())
            } else {
                success_reply(xid, &ResInitSecContext::default())
            })
        });

        let r1: ResIndicateMechs =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default()).unwrap();
        assert_eq!(r1, ResIndicateMechs::default());
        reset_connection(); // force the second proc onto a new connection
        let r2: ResInitSecContext =
            make_call(GssxProc::InitSecContext, &ArgInitSecContext::default()).unwrap();
        assert_eq!(r2, ResInitSecContext::default());

        let recorded = server.join().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            Message::decode(&mut XdrDecoder::new(&recorded[1].1))
                .unwrap()
                .call
                .unwrap()
                .proc_num,
            GssxProc::InitSecContext as u32
        );
        cleanup(dir, sock);
    }

    #[test]
    fn reuses_connection_and_increments_xid() {
        let _g = serial();
        let (dir, sock) = setup_socket("reuse");
        let server = spawn_server_persistent(sock.clone());

        let _a: ResIndicateMechs =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default()).unwrap();
        let _b: ResIndicateMechs =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default()).unwrap();
        // Closing the client connection lets the single-connection server exit.
        reset_connection();

        let recorded = server.join().unwrap();
        assert_eq!(recorded.len(), 2, "both calls used the same connection");
        let x0 = xid_of(&recorded[0]);
        let x1 = xid_of(&recorded[1]);
        assert_eq!(x1, x0.wrapping_add(1), "xid increments by one per call");
        cleanup(dir, sock);
    }

    #[test]
    fn rejects_reply_with_wrong_xid() {
        let _g = serial();
        let (dir, sock) = setup_socket("wrongxid");
        let server = spawn_server(sock.clone(), 1, |_, body| {
            Some(success_reply(
                xid_of(body).wrapping_add(99),
                &ResIndicateMechs::default(),
            ))
        });
        let r: Result<ResIndicateMechs> =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default());
        assert!(matches!(r, Err(GpmError::BadReply)));
        server.join().unwrap();
        cleanup(dir, sock);
    }

    #[test]
    fn rejects_reply_that_is_a_call() {
        let _g = serial();
        let (dir, sock) = setup_socket("iscall");
        let server = spawn_server(sock.clone(), 1, |_, body| {
            // Echo a CALL message back instead of a REPLY.
            Some(frame(&encode_request(
                xid_of(body),
                GssxProc::IndicateMechs as u32,
                &ArgIndicateMechs::default(),
            )))
        });
        let r: Result<ResIndicateMechs> =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default());
        assert!(matches!(r, Err(GpmError::BadReply)));
        server.join().unwrap();
        cleanup(dir, sock);
    }

    fn encode_reply_body(reply: ReplyBody, xid: u32) -> Vec<u8> {
        let msg = Message {
            xid,
            is_call: false,
            call: None,
            reply: Some(reply),
        };
        let mut e = XdrEncoder::new();
        msg.encode(&mut e);
        frame(&e.into_bytes())
    }

    #[test]
    fn rejects_denied_reply() {
        let _g = serial();
        let (dir, sock) = setup_socket("denied");
        let server = spawn_server(sock.clone(), 1, |_, body| {
            Some(encode_reply_body(
                ReplyBody::Denied {
                    reject_status: 1,
                    value: 0,
                },
                xid_of(body),
            ))
        });
        let r: Result<ResIndicateMechs> =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default());
        assert!(matches!(r, Err(GpmError::BadReply)));
        server.join().unwrap();
        cleanup(dir, sock);
    }

    #[test]
    fn rejects_accepted_non_success_reply() {
        let _g = serial();
        let (dir, sock) = setup_socket("garbage");
        let server = spawn_server(sock.clone(), 1, |_, body| {
            Some(encode_reply_body(
                ReplyBody::AcceptedOther {
                    verf: Default::default(),
                    status: 4, // GARBAGE_ARGS
                },
                xid_of(body),
            ))
        });
        let r: Result<ResIndicateMechs> =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default());
        assert!(matches!(r, Err(GpmError::BadReply)));
        server.join().unwrap();
        cleanup(dir, sock);
    }

    #[test]
    fn rejects_multi_fragment_reply_header() {
        let _g = serial();
        let (dir, sock) = setup_socket("multifrag");
        let server = spawn_server(sock.clone(), 1, |_, _| {
            // A 4-byte header WITHOUT the fragment bit, then a byte of body.
            let mut raw = (8u32).to_be_bytes().to_vec();
            raw.extend_from_slice(&[0u8; 8]);
            Some(raw)
        });
        let r: Result<ResIndicateMechs> =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default());
        assert!(matches!(r, Err(GpmError::Frame(_))));
        server.join().unwrap();
        cleanup(dir, sock);
    }

    #[test]
    fn rejects_oversized_reply_header() {
        let _g = serial();
        let (dir, sock) = setup_socket("bigreply");
        let server = spawn_server(sock.clone(), 1, |_, _| {
            let word = ((MAX_RPC_SIZE as u32) + 1) | FRAGMENT_BIT;
            Some(word.to_be_bytes().to_vec())
        });
        let r: Result<ResIndicateMechs> =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default());
        assert!(matches!(r, Err(GpmError::Frame(_))));
        server.join().unwrap();
        cleanup(dir, sock);
    }

    #[test]
    fn truncated_reply_body_errors_after_retries() {
        let _g = serial();
        let (dir, sock) = setup_socket("truncated");
        // Every attempt advertises 100 bytes but sends only 4, then closes.
        // The short read is retryable, so all MAX_TIMEOUT_RETRY connections are
        // consumed before the error surfaces.
        let server = spawn_server(sock.clone(), MAX_TIMEOUT_RETRY, |_, _| {
            let mut raw = (100u32 | FRAGMENT_BIT).to_be_bytes().to_vec();
            raw.extend_from_slice(&[0u8; 4]);
            Some(raw)
        });
        let r: Result<ResIndicateMechs> =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default());
        assert!(matches!(r, Err(GpmError::Io(_))));
        server.join().unwrap();
        cleanup(dir, sock);
    }

    #[test]
    fn reconnects_after_dropped_connection() {
        let _g = serial();
        let (dir, sock) = setup_socket("reconnect");
        // First connection: read the request then drop it (dead daemon).
        // Second connection (the retry): reply success.
        let server = spawn_server(sock.clone(), 2, |i, body| {
            if i == 0 {
                None
            } else {
                Some(success_reply(xid_of(body), &ResIndicateMechs::default()))
            }
        });
        let r: ResIndicateMechs =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default()).unwrap();
        assert_eq!(r, ResIndicateMechs::default());
        let recorded = server.join().unwrap();
        assert_eq!(recorded.len(), 2, "request was retried on a new connection");
        cleanup(dir, sock);
    }

    #[test]
    fn oversize_request_is_rejected_locally() {
        let _g = serial();
        // No server needed: transact rejects on size before connecting.
        let big = vec![0u8; MAX_RPC_SIZE + 1];
        let mut conn = CONN.lock().unwrap_or_else(|e| e.into_inner());
        let r = conn.transact(&big);
        assert!(matches!(r, Err(GpmError::TooLarge)));
    }

    #[test]
    fn errno_mapping_matches_c_intent() {
        assert_eq!(GpmError::TooLarge.errno(), libc::EMSGSIZE);
        assert_eq!(GpmError::BadReply.errno(), libc::EIO);
        let io = GpmError::Io(io::Error::from_raw_os_error(libc::ECONNREFUSED));
        assert_eq!(io.errno(), libc::ECONNREFUSED);
    }

    #[test]
    fn refresh_identity_drops_connection_on_pid_change() {
        let _g = serial();
        let (a, _b) = UnixStream::pair().unwrap();
        let mut conn = CONN.lock().unwrap_or_else(|e| e.into_inner());
        conn.stream = Some(a);
        // Pretend the connection was opened by a different process (post-fork).
        conn.pid = unsafe { libc::getpid() }.wrapping_add(1);
        conn.uid = unsafe { libc::geteuid() };
        conn.gid = unsafe { libc::getegid() };
        conn.refresh_identity();
        assert!(
            conn.stream.is_none(),
            "stale post-fork socket must be dropped"
        );
    }

    #[test]
    fn refresh_identity_keeps_connection_for_same_identity() {
        let _g = serial();
        let (a, _b) = UnixStream::pair().unwrap();
        let mut conn = CONN.lock().unwrap_or_else(|e| e.into_inner());
        conn.stream = Some(a);
        conn.pid = unsafe { libc::getpid() };
        conn.uid = unsafe { libc::geteuid() };
        conn.gid = unsafe { libc::getegid() };
        conn.refresh_identity();
        assert!(conn.stream.is_some(), "live connection must be retained");
        conn.stream = None;
    }

    #[test]
    fn socket_path_defaults_when_env_unset() {
        let _g = serial();
        std::env::remove_var("GSSPROXY_SOCKET");
        assert_eq!(socket_path(), OsString::from(GP_SOCKET_NAME));
        std::env::set_var("GSSPROXY_SOCKET", "/tmp/custom.sock");
        assert_eq!(socket_path(), OsString::from("/tmp/custom.sock"));
        std::env::remove_var("GSSPROXY_SOCKET");
    }

    #[test]
    fn survives_fork_with_independent_connection() {
        let _g = serial();
        let (dir, sock) = setup_socket("fork");
        // Parent uses connection 0, child (after fork) uses connection 1.
        let server = spawn_server(sock.clone(), 2, |_, body| {
            Some(success_reply(xid_of(body), &ResIndicateMechs::default()))
        });

        // Parent call.
        let _parent: ResIndicateMechs =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default()).unwrap();

        // SAFETY: single-threaded section guarded by the serial lock; the child
        // only performs an async-signal-unsafe-free make_call then _exit.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            let ok = make_call::<_, ResIndicateMechs>(
                GssxProc::IndicateMechs,
                &ArgIndicateMechs::default(),
            )
            .is_ok();
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        }

        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let child_ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        assert!(child_ok, "child make_call after fork should succeed");

        let recorded = server.join().unwrap();
        assert_eq!(
            recorded.len(),
            2,
            "parent and child each opened a connection"
        );
        cleanup(dir, sock);
    }

    // ---- chaos-monkey transport tests --------------------------------------
    //
    // A misbehaving daemon shouldn't be able to panic, hang, or corrupt the
    // client. We model the daemon as a per-connection behaviour and assert the
    // observable outcome of `make_call` matches the C `gpm_send_recv_loop`
    // contract: retryable transport faults are retried up to MAX_TIMEOUT_RETRY
    // times (each on a fresh connection), while protocol-level faults surface
    // immediately as a typed error. No input should ever produce a panic.

    #[derive(Debug, Clone, Copy)]
    enum Behavior {
        /// Correct accepted-success reply echoing our xid.
        SuccessCorrect,
        /// Same, but after a short (sub-timeout) delay.
        SuccessSlow,
        /// Correct reply with extra bytes inside the record frame (ignored).
        SuccessTrailingGarbage,
        /// Accepted-success reply for the wrong xid.
        WrongXid,
        /// A CALL message instead of a REPLY.
        ReplyIsCall,
        /// MSG_DENIED.
        Denied,
        /// MSG_ACCEPTED with a non-success accept status.
        AcceptedOther,
        /// Accepted-success envelope with no result body (undecodable result).
        EmptyResult,
        /// Record header without the last-fragment bit.
        BadHeaderNoFragment,
        /// Record header advertising more than MAX_RPC_SIZE.
        BadHeaderOversized,
        /// Header promising a long body, then a short body + close.
        ShortBody,
        /// Read the request, then close without replying.
        DropAfterRead,
        /// Close immediately without reading the request.
        DropBeforeRead,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Expect {
        Ok,
        BadReply,
        Frame,
        Decode,
        Io,
    }

    /// Terminal outcome for a behaviour, or `None` if it is a retryable
    /// transport fault that makes the client reconnect and try again.
    fn classify(b: Behavior) -> Option<Expect> {
        match b {
            Behavior::SuccessCorrect | Behavior::SuccessSlow | Behavior::SuccessTrailingGarbage => {
                Some(Expect::Ok)
            }
            Behavior::WrongXid
            | Behavior::ReplyIsCall
            | Behavior::Denied
            | Behavior::AcceptedOther => Some(Expect::BadReply),
            Behavior::BadHeaderNoFragment | Behavior::BadHeaderOversized => Some(Expect::Frame),
            Behavior::EmptyResult => Some(Expect::Decode),
            Behavior::ShortBody | Behavior::DropAfterRead | Behavior::DropBeforeRead => None,
        }
    }

    /// Predict `make_call`'s result from the per-attempt behaviour sequence,
    /// applying the same retry budget the client uses.
    fn simulate(behs: &[Behavior]) -> Expect {
        for &b in behs.iter().take(MAX_TIMEOUT_RETRY) {
            if let Some(e) = classify(b) {
                return e;
            }
        }
        Expect::Io
    }

    fn apply_behavior(b: Behavior, c: &mut UnixStream) {
        if let Behavior::DropBeforeRead = b {
            return; // dropping `c` closes it before the request is read
        }
        let body = match read_frame(c) {
            Some((_, body)) => body,
            None => return,
        };
        let xid = xid_of(&body);
        let bytes: Vec<u8> = match b {
            Behavior::DropBeforeRead => return,
            Behavior::DropAfterRead => return,
            Behavior::SuccessCorrect => success_reply(xid, &ResIndicateMechs::default()),
            Behavior::SuccessSlow => {
                thread::sleep(Duration::from_millis(8));
                success_reply(xid, &ResIndicateMechs::default())
            }
            Behavior::SuccessTrailingGarbage => {
                let mut env = encode_reply(xid, &ResIndicateMechs::default());
                env.extend_from_slice(&[0xAA; 7]);
                frame(&env)
            }
            Behavior::WrongXid => success_reply(xid.wrapping_add(99), &ResIndicateMechs::default()),
            Behavior::ReplyIsCall => frame(&encode_request(
                xid,
                GssxProc::IndicateMechs as u32,
                &ArgIndicateMechs::default(),
            )),
            Behavior::Denied => encode_reply_body(
                ReplyBody::Denied {
                    reject_status: 1,
                    value: 0,
                },
                xid,
            ),
            Behavior::AcceptedOther => encode_reply_body(
                ReplyBody::AcceptedOther {
                    verf: Default::default(),
                    status: 4,
                },
                xid,
            ),
            Behavior::EmptyResult => {
                let mut e = XdrEncoder::new();
                Message::reply_success(xid).encode(&mut e);
                frame(&e.into_bytes())
            }
            Behavior::BadHeaderNoFragment => 8u32.to_be_bytes().to_vec(),
            Behavior::BadHeaderOversized => (((MAX_RPC_SIZE as u32) + 1) | FRAGMENT_BIT)
                .to_be_bytes()
                .to_vec(),
            Behavior::ShortBody => {
                let mut raw = (100u32 | FRAGMENT_BIT).to_be_bytes().to_vec();
                raw.extend_from_slice(&[0u8; 4]);
                raw
            }
        };
        let _ = c.write_all(&bytes);
        let _ = c.flush();
    }

    /// Drive one `make_call` against a daemon that applies `behs[i]` to the
    /// i-th connection the client opens. Returns the client's result.
    fn run_sequence(behs: Vec<Behavior>) -> Result<ResIndicateMechs> {
        let (dir, sock) = setup_socket("chaos");
        let listener = UnixListener::bind(&sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_srv = stop.clone();
        let behs_srv = behs.clone();
        let handle = thread::spawn(move || {
            let mut i = 0usize;
            loop {
                match listener.accept() {
                    Ok((mut c, _)) => {
                        c.set_nonblocking(false).ok();
                        let b = behs_srv[i.min(behs_srv.len() - 1)];
                        apply_behavior(b, &mut c);
                        i += 1;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if stop_srv.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        let r: Result<ResIndicateMechs> =
            make_call(GssxProc::IndicateMechs, &ArgIndicateMechs::default());

        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        reset_connection();
        cleanup(dir, sock);
        r
    }

    fn behavior() -> impl Strategy<Value = Behavior> {
        prop_oneof![
            Just(Behavior::SuccessCorrect),
            Just(Behavior::SuccessSlow),
            Just(Behavior::SuccessTrailingGarbage),
            Just(Behavior::WrongXid),
            Just(Behavior::ReplyIsCall),
            Just(Behavior::Denied),
            Just(Behavior::AcceptedOther),
            Just(Behavior::EmptyResult),
            Just(Behavior::BadHeaderNoFragment),
            Just(Behavior::BadHeaderOversized),
            Just(Behavior::ShortBody),
            Just(Behavior::DropAfterRead),
            Just(Behavior::DropBeforeRead),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 96,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// For any sequence of daemon misbehaviours, `make_call` returns a
        /// result consistent with the C retry contract and never panics/hangs.
        #[test]
        fn chaos_retry_matches_c_semantics(
            behs in prop::collection::vec(behavior(), MAX_TIMEOUT_RETRY)
        ) {
            let _g = serial();
            let expected = simulate(&behs);
            let r = run_sequence(behs.clone());
            let ok = match (expected, &r) {
                (Expect::Ok, Ok(v)) => *v == ResIndicateMechs::default(),
                (Expect::BadReply, Err(GpmError::BadReply)) => true,
                (Expect::Frame, Err(GpmError::Frame(_))) => true,
                (Expect::Decode, Err(GpmError::Decode(_))) => true,
                (Expect::Io, Err(GpmError::Io(_))) => true,
                _ => false,
            };
            prop_assert!(ok, "behaviors {:?}: expected {:?}, got {:?}", behs, expected, r);
        }
    }
}
