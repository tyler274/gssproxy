//! Unix-socket listener and SunRPC record-marking framing loop.
//!
//! GSSAPI is synchronous, so the per-request dispatch runs on tokio's blocking
//! pool while the socket I/O stays async.

use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use gssproxy_proto::{frame, parse_header};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinHandle;

use crate::call::CallContext;
use crate::config::Config;
use crate::creds::CredsRegistry;
use crate::dispatch;

/// Serve the daemon: bind the main socket plus every per-service `socket`, then
/// reload the configuration (and reconcile the set of bound sockets) on every
/// `SIGHUP`.
///
/// `config` is shared (and is swapped out on reload); each connection resolves
/// its service against the current configuration at accept time. Mirroring the
/// C daemon, services may declare their own `socket`, so the daemon listens on
/// the union of the main socket and all service sockets.
pub async fn run(
    main_socket: String,
    config_path: PathBuf,
    config: Arc<Mutex<Config>>,
) -> io::Result<()> {
    // Per-service sealing keys, derived lazily and shared for the daemon's
    // lifetime (a config reload keeps the existing handles, keyed by name).
    let registry = Arc::new(CredsRegistry::new());

    // Active listeners, keyed by socket path.
    let mut listeners: HashMap<String, JoinHandle<()>> = HashMap::new();
    reconcile_listeners(&main_socket, &config, &registry, &mut listeners);

    // The test suite waits for this exact substring in the daemon log before it
    // starts driving requests (see `gssproxy_reload` in tests/testlib.py).
    eprintln!("gssproxy: Initialization complete.");

    let mut hup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            // Without a reload handler we can still serve indefinitely.
            eprintln!("gssproxy: cannot install SIGHUP handler: {e}");
            std::future::pending::<()>().await;
            unreachable!()
        }
    };

    while hup.recv().await.is_some() {
        match Config::parse_file(&config_path, &main_socket) {
            Ok(cfg) => {
                *config.lock().unwrap() = cfg;
                reconcile_listeners(&main_socket, &config, &registry, &mut listeners);
                // The test suite waits for this exact substring after a SIGHUP.
                eprintln!("gssproxy: New config loaded successfully.");
            }
            Err(e) => eprintln!("gssproxy: config reload failed: {e}"),
        }
    }

    Ok(())
}

/// Bring the set of bound sockets in line with the current configuration: bind
/// any newly required socket and tear down any socket no longer referenced.
fn reconcile_listeners(
    main_socket: &str,
    config: &Arc<Mutex<Config>>,
    registry: &Arc<CredsRegistry>,
    listeners: &mut HashMap<String, JoinHandle<()>>,
) {
    let desired: HashSet<String> = {
        let guard = config.lock().unwrap();
        let mut set = HashSet::new();
        set.insert(main_socket.to_string());
        for svc in &guard.services {
            if let Some(sock) = &svc.socket {
                set.insert(sock.clone());
            }
        }
        set
    };

    // Tear down listeners that are no longer wanted (the main socket always is).
    let stale: Vec<String> = listeners
        .keys()
        .filter(|path| !desired.contains(*path))
        .cloned()
        .collect();
    for path in stale {
        if let Some(handle) = listeners.remove(&path) {
            handle.abort();
            let _ = std::fs::remove_file(&path);
        }
    }

    // Bind any sockets we are not yet listening on.
    for path in desired {
        if listeners.contains_key(&path) {
            continue;
        }
        match spawn_listener(path.clone(), config.clone(), registry.clone()) {
            Ok(handle) => {
                listeners.insert(path, handle);
            }
            Err(e) => eprintln!("gssproxy: failed to bind socket {path}: {e}"),
        }
    }
}

/// Bind `path` and spawn an accept loop for it. Each accepted connection is
/// served on its own task and tagged with `path` so service matching keys on
/// the socket the client used.
fn spawn_listener(
    path: String,
    config: Arc<Mutex<Config>>,
    registry: Arc<CredsRegistry>,
) -> io::Result<JoinHandle<()>> {
    // Best-effort removal of a stale socket from a previous run.
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;

    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let ctx = resolve_context(&stream, &config, &registry, &path);
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(stream, ctx).await {
                            eprintln!("gssproxy: connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("gssproxy: accept error on {path}: {e}");
                    break;
                }
            }
        }
    }))
}

/// Resolve the per-connection [`CallContext`] from the peer credentials, then
/// attach the matched service's sealing handle.
fn resolve_context(
    stream: &UnixStream,
    config: &Arc<Mutex<Config>>,
    registry: &Arc<CredsRegistry>,
    socket: &str,
) -> CallContext {
    let mut ctx = match stream.peer_cred() {
        Ok(cred) => {
            let guard = config.lock().unwrap();
            CallContext::resolve(&guard, socket, cred.uid(), cred.gid(), cred.pid())
        }
        Err(e) => {
            eprintln!("gssproxy: failed to read peer credentials: {e}");
            CallContext::anonymous(socket)
        }
    };
    if let Some(svc) = &ctx.service {
        ctx.creds = registry.get_or_init(svc);
    }
    ctx
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
