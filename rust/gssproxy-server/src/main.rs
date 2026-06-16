//! The gssproxy daemon binary (Rust port).
//!
//! Mirrors the command-line surface the test suite drives (`gssproxy -i -s
//! <socket> -c <conf>`): it loads `gssproxy.conf`, binds the Unix socket,
//! prints "Initialization complete." once it is ready to accept connections,
//! and reloads the configuration on `SIGHUP` (logging "New config loaded
//! successfully.").

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use gssproxy_server::{config::Config, server};

/// Compiled-in default config path (autotools `GSSCONF`).
const DEFAULT_CONF: &str = "/etc/gssproxy/gssproxy.conf";
/// Compiled-in default socket path (autotools `GP_SOCKET_NAME`).
const DEFAULT_SOCKET: &str = "/var/lib/gssproxy/default.sock";

struct Args {
    socket: String,
    config: PathBuf,
    interactive: bool,
}

fn usage(code: i32) -> ! {
    eprintln!(
        "Usage: gssproxy [-i|--interactive] [-s|--socket PATH] [-c|--config FILE] [-d|--config-dir DIR]"
    );
    std::process::exit(code);
}

fn parse_args() -> Args {
    let mut socket = DEFAULT_SOCKET.to_string();
    let mut config = PathBuf::from(DEFAULT_CONF);
    let mut interactive = false;

    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        // Split `--opt=value` / `-s=value` into name and inline value.
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        let value = |a: &mut dyn Iterator<Item = String>| -> String {
            inline.clone().or_else(|| a.next()).unwrap_or_else(|| {
                eprintln!("gssproxy: option {name} requires an argument");
                usage(1)
            })
        };
        match name.as_str() {
            "-i" | "--interactive" => interactive = true,
            "-D" | "--daemon" => interactive = false,
            "-s" | "--socket" => socket = value(&mut argv),
            "-c" | "--config" => config = PathBuf::from(value(&mut argv)),
            // Drop-in config directories are not consulted yet; accept and ignore.
            "-d" | "--config-dir" => {
                let _ = value(&mut argv);
            }
            "--version" => {
                println!("gssproxy {} (rust)", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => usage(0),
            other => {
                eprintln!("gssproxy: unknown option '{other}'");
                usage(1);
            }
        }
    }

    Args {
        socket,
        config,
        interactive,
    }
}

fn load_config(path: &Path, socket: &str) -> Config {
    match Config::parse_file(path, socket) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("gssproxy: failed to load config {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

fn main() {
    let args = parse_args();
    let _ = args.interactive; // daemonization is not implemented; always foreground.

    // Validate the configuration up front (matches the C daemon, which refuses
    // to start with an unparsable or empty config).
    let config = load_config(&args.config, &args.socket);
    let shared = Arc::new(Mutex::new(config));

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("gssproxy: failed to start tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    let result = runtime.block_on(async move {
        server::run(args.socket.clone(), args.config.clone(), shared).await
    });

    if let Err(e) = result {
        eprintln!("gssproxy: {e}");
        std::process::exit(1);
    }
}
