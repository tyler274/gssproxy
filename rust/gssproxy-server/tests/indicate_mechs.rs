//! End-to-end tests of the daemon's socket path: bind the listener, then drive
//! real requests over the Unix socket and decode the framed replies. This
//! exercises the whole pipeline (listener -> SunRPC framing -> envelope
//! validation -> dispatch -> handler -> encode), which the upstream test suite
//! cannot reach until more procedures are ported.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gssproxy_server::config::Config;

use gssproxy_proto::frame::{encode_header, parse_header};
use gssproxy_proto::proc::{
    ArgGetCallContext, ArgIndicateMechs, ArgStoreCred, GssxProc, ResGetCallContext,
    ResIndicateMechs, ResStoreCred,
};
use gssproxy_proto::rpc::ReplyBody;
use gssproxy_proto::{encode_request, Message, Xdr, XdrDecoder};

/// DER encoding of the krb5 mechanism OID 1.2.840.113554.1.2.2.
const KRB5_MECH_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

fn unique_socket_path() -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!(
        "gssproxy-rs-test-{}-{}.sock",
        std::process::id(),
        nanos
    ));
    p
}

/// Start a daemon listener on a fresh socket and return a connected client.
fn connect_daemon() -> UnixStream {
    let socket = unique_socket_path();
    let socket_for_server = socket.to_string_lossy().into_owned();
    let config = Arc::new(Mutex::new(Config::empty(&socket.to_string_lossy())));

    // Detached listener thread; torn down when the test process exits. The
    // config path is never read here (no SIGHUP is sent during the test).
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let _ = rt.block_on(gssproxy_server::server::run(
            socket_for_server,
            PathBuf::from("/nonexistent/gssproxy.conf"),
            config,
        ));
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match UnixStream::connect(&socket) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("daemon never came up: {e}"),
        }
    }
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).expect("read record header");
    let len = parse_header(u32::from_be_bytes(header)).expect("valid record header");
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("read record body");
    body
}

/// Send one request and return the decoder positioned at the result body, after
/// validating the reply envelope (xid echo + MSG_ACCEPTED/SUCCESS).
fn round_trip<A: Xdr>(stream: &mut UnixStream, xid: u32, proc: GssxProc, arg: &A) -> Vec<u8> {
    let body = encode_request(xid, proc as u32, arg);
    let mut request = encode_header(body.len()).to_vec();
    request.extend_from_slice(&body);
    stream.write_all(&request).expect("write request");
    stream.flush().expect("flush request");
    read_frame(stream)
}

fn expect_success(reply: &[u8], xid: u32) -> XdrDecoder<'_> {
    let mut d = XdrDecoder::new(reply);
    let msg = Message::decode(&mut d).expect("decode reply envelope");
    assert_eq!(msg.xid, xid, "reply xid must echo the request xid");
    assert!(!msg.is_call, "reply must be a REPLY, not a CALL");
    assert!(
        matches!(msg.reply, Some(ReplyBody::AcceptedSuccess { .. })),
        "reply must be MSG_ACCEPTED + SUCCESS, got {:?}",
        msg.reply
    );
    d
}

#[test]
fn indicate_mechs_round_trips_over_socket() {
    let mut stream = connect_daemon();
    let xid = 0x1234_5678;
    let reply = round_trip(
        &mut stream,
        xid,
        GssxProc::IndicateMechs,
        &ArgIndicateMechs::default(),
    );
    let mut d = expect_success(&reply, xid);

    let res = ResIndicateMechs::decode(&mut d).expect("decode indicate_mechs result");
    assert_eq!(d.remaining(), 0, "no trailing bytes after the result");

    // The build sandbox always has MIT krb5 compiled in, so indicate_mechs must
    // succeed and advertise the krb5 mechanism.
    assert_eq!(
        res.status.major_status, 0,
        "indicate_mechs failed: major=0x{:x}",
        res.status.major_status
    );
    assert!(
        res.mechs.iter().any(|m| m.mech.0 == KRB5_MECH_OID),
        "krb5 mechanism OID missing from indicate_mechs result"
    );
}

/// `get_call_context` and `store_cred` are `GP_EXEC_UNUSED_FUNC` stubs in the C
/// daemon: they return `GSS_S_COMPLETE` with a zero-initialized result. Verify
/// the Rust daemon matches that on the wire (success + empty default body).
#[test]
fn unused_stub_procs_return_zeroed_success() {
    let mut stream = connect_daemon();

    let xid = 0xaaaa_0001;
    let reply = round_trip(
        &mut stream,
        xid,
        GssxProc::GetCallContext,
        &ArgGetCallContext::default(),
    );
    let mut d = expect_success(&reply, xid);
    let res = ResGetCallContext::decode(&mut d).expect("decode get_call_context result");
    assert_eq!(d.remaining(), 0);
    assert_eq!(res, ResGetCallContext::default(), "must be zeroed-success");

    let xid = 0xaaaa_0002;
    let reply = round_trip(
        &mut stream,
        xid,
        GssxProc::StoreCred,
        &ArgStoreCred::default(),
    );
    let mut d = expect_success(&reply, xid);
    let res = ResStoreCred::decode(&mut d).expect("decode store_cred result");
    assert_eq!(d.remaining(), 0);
    assert_eq!(res, ResStoreCred::default(), "must be zeroed-success");
}
