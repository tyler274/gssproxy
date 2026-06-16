//! Unix-socket listener and SunRPC record-marking framing loop.
//!
//! GSSAPI is synchronous, so the per-request dispatch runs on tokio's blocking
//! pool while the socket I/O stays async.

use std::io::{self, ErrorKind};
use std::path::Path;
use std::sync::{Arc, Mutex};

use gssproxy_proto::{frame, parse_header};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::call::CallContext;
use crate::config::Config;
use crate::dispatch;

/// Bind `path` and serve connections until an unrecoverable accept error.
///
/// `config` is shared (and may be swapped out on `SIGHUP`); each connection
/// resolves its service against the current configuration at accept time.
pub async fn run(path: &Path, config: Arc<Mutex<Config>>) -> io::Result<()> {
    // Best-effort removal of a stale socket from a previous run.
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;

    let socket = path.to_string_lossy().into_owned();

    // The test suite waits for this exact substring in the daemon log before it
    // starts driving requests (see `gssproxy_reload` in tests/testlib.py).
    eprintln!("gssproxy: Initialization complete.");

    loop {
        let (stream, _addr) = listener.accept().await?;
        let ctx = resolve_context(&stream, &config, &socket);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, ctx).await {
                eprintln!("gssproxy: connection error: {e}");
            }
        });
    }
}

/// Resolve the per-connection [`CallContext`] from the peer credentials.
fn resolve_context(stream: &UnixStream, config: &Arc<Mutex<Config>>, socket: &str) -> CallContext {
    match stream.peer_cred() {
        Ok(cred) => {
            let guard = config.lock().unwrap();
            CallContext::resolve(&guard, socket, cred.uid(), cred.gid(), cred.pid())
        }
        Err(e) => {
            eprintln!("gssproxy: failed to read peer credentials: {e}");
            CallContext::anonymous(socket)
        }
    }
}

async fn handle_conn(mut stream: UnixStream, ctx: CallContext) -> io::Result<()> {
    let ctx = Arc::new(ctx);
    loop {
        let mut header = [0u8; 4];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            // Clean client disconnect between requests.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }

        let len = parse_header(u32::from_be_bytes(header))
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;

        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;

        let ctx = ctx.clone();
        let reply = tokio::task::spawn_blocking(move || dispatch::handle_request(&ctx, &body))
            .await
            .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;

        if let Some(reply_body) = reply {
            stream.write_all(&frame(&reply_body)).await?;
            stream.flush().await?;
        }
    }
}
