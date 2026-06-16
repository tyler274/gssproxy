//! The gssproxy daemon binary (Rust port).
//!
//! Mirrors the command-line surface of the C daemon (`src/gssproxy.c`, which
//! uses popt): `gssproxy [-D|--daemon] [-i|--interactive] [-c|--config FILE]
//! [-C|--configdir DIR] [-s|--socket PATH] [-u|--userproxy] [-d|--debug]
//! [--debug-level N] [--syslog-status] [--idle-timeout N] [--version]
//! [-h|--help]`, plus the hidden `--extract-ccache SRC [--into-ccache DST]`
//! admin utility (port of `src/extract_ccache.c`).
//!
//! It loads `gssproxy.conf`, binds the Unix socket, prints "Initialization
//! complete." once it is ready to accept connections, and reloads the
//! configuration on `SIGHUP` (logging "New config loaded successfully.").

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use gssproxy_server::{config::Config, server};

/// Compiled-in default config path (autotools `GSSCONF`).
const DEFAULT_CONF: &str = "/etc/gssproxy/gssproxy.conf";
/// Compiled-in default socket path (autotools `GP_SOCKET_NAME`).
const DEFAULT_SOCKET: &str = "/var/lib/gssproxy/default.sock";

const USAGE: &str = "Usage: gssproxy [-D|--daemon] [-i|--interactive] \
[-c|--config FILE] [-C|--configdir DIR] [-s|--socket PATH] [-u|--userproxy] \
[-d|--debug] [--debug-level N] [--syslog-status] [--idle-timeout N] \
[--version] [-h|--help]";

/// Default user-mode idle timeout in seconds (C `opt_idle_timeout`).
const DEFAULT_IDLE_TIMEOUT: i32 = 1000;

/// Parsed command-line arguments. Several flags are accepted for CLI
/// compatibility with the C daemon even where the behaviour they toggle is not
/// yet implemented in the Rust port (recorded here, applied where possible).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    socket: String,
    config: PathBuf,
    config_dir: Option<String>,
    interactive: bool,
    daemon: bool,
    debug: bool,
    debug_level: i32,
    syslog_status: bool,
    userproxy: bool,
    idle_timeout: i32,
}

impl Args {
    fn defaults() -> Args {
        Args {
            socket: DEFAULT_SOCKET.to_string(),
            config: PathBuf::from(DEFAULT_CONF),
            config_dir: None,
            interactive: false,
            daemon: false,
            debug: false,
            debug_level: 0,
            syslog_status: false,
            userproxy: false,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

/// Outcome of parsing argv, separated from process side-effects so it is unit
/// testable. The ordering of the terminal outcomes mirrors `src/gssproxy.c`:
/// an unknown option or `--help` short-circuits during the popt parse loop,
/// while `--version`, `--extract-ccache`, and the `-D`+`-i` conflict are honored
/// (in that order) only after a fully successful parse.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Parsed {
    Run(Args),
    Help,
    Version,
    /// `--extract-ccache SRC [--into-ccache DST]`: run the ccache extractor.
    ExtractCcache {
        source: String,
        dest: Option<String>,
    },
    /// `-D` and `-i` given together: the C daemon prints a message and exits 0.
    DaemonInteractiveConflict,
    Error(String),
}

fn take_value(
    name: &str,
    inline: Option<String>,
    argv: &[String],
    i: &mut usize,
) -> std::result::Result<String, String> {
    if let Some(v) = inline {
        return Ok(v);
    }
    *i += 1;
    argv.get(*i)
        .cloned()
        .ok_or_else(|| format!("option {name} requires an argument"))
}

fn parse_args_from<I: IntoIterator<Item = String>>(args: I) -> Parsed {
    let argv: Vec<String> = args.into_iter().collect();
    let mut a = Args::defaults();
    // popt sets all option flags during the parse loop, then `main` applies the
    // version/extract/conflict precedence afterwards, so we accumulate rather
    // than short-circuit on these (unlike `--help`, which popt's autohelp
    // handles inline).
    let mut want_version = false;
    let mut extract_ccache: Option<String> = None;
    let mut into_ccache: Option<String> = None;
    let mut i = 0;

    while i < argv.len() {
        let arg = argv[i].clone();
        // Split `--opt=value` / `-s=value` into name and inline value.
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };

        macro_rules! value {
            () => {
                match take_value(&name, inline.clone(), &argv, &mut i) {
                    Ok(v) => v,
                    Err(e) => return Parsed::Error(e),
                }
            };
        }

        match name.as_str() {
            "-i" | "--interactive" => a.interactive = true,
            "-D" | "--daemon" => a.daemon = true,
            "-s" | "--socket" => a.socket = value!(),
            "-c" | "--config" => a.config = PathBuf::from(value!()),
            // Drop-in config directories are not consulted yet; accept + record.
            "-C" | "--configdir" => a.config_dir = Some(value!()),
            "-u" | "--userproxy" => a.userproxy = true,
            "-d" | "--debug" => a.debug = true,
            "--debug-level" => {
                a.debug_level = match value!().parse() {
                    Ok(n) => n,
                    Err(_) => return Parsed::Error("--debug-level expects an integer".into()),
                };
            }
            "--syslog-status" => a.syslog_status = true,
            "--idle-timeout" => {
                a.idle_timeout = match value!().parse() {
                    Ok(n) => n,
                    Err(_) => return Parsed::Error("--idle-timeout expects an integer".into()),
                };
            }
            // Hidden admin options (POPT_ARGFLAG_DOC_HIDDEN in the C daemon).
            "--extract-ccache" => extract_ccache = Some(value!()),
            "--into-ccache" => into_ccache = Some(value!()),
            "--version" => want_version = true,
            "-h" | "--help" | "--usage" | "-?" => return Parsed::Help,
            other => return Parsed::Error(format!("unknown option '{other}'")),
        }
        i += 1;
    }

    // Terminal-outcome precedence, mirroring src/gssproxy.c: version first, then
    // the (hidden) ccache extractor, then the daemon/interactive conflict.
    if want_version {
        return Parsed::Version;
    }
    if let Some(source) = extract_ccache {
        return Parsed::ExtractCcache {
            source,
            dest: into_ccache,
        };
    }
    if a.daemon && a.interactive {
        return Parsed::DaemonInteractiveConflict;
    }

    Parsed::Run(a)
}

/// Install the global `tracing` subscriber, writing human-readable events to
/// stderr (matching where the C daemon logs). The verbosity follows, in order
/// of precedence: the `RUST_LOG` environment variable, then the C-compatible
/// `-d`/`--debug-level` flags, defaulting to `info` (which still emits the
/// lifecycle lines the test suite waits for).
///
/// Idempotent: uses `try_init`, so a second call (or a host that already set a
/// subscriber) is a no-op rather than a panic.
fn init_tracing(debug: bool, debug_level: i32) {
    use tracing_subscriber::EnvFilter;

    // `--debug-level` raises verbosity: >=2 -> trace, >=1 (or -d) -> debug.
    let level = if debug_level >= 2 {
        "trace"
    } else if debug || debug_level >= 1 {
        "debug"
    } else {
        "info"
    };

    // RUST_LOG wins outright; otherwise keep third-party crates (tokio, mio) at
    // `info` and only turn our own crates up to the requested level.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "info,gssproxy_server={level},gssproxy_client={level}"
        ))
    });

    // The daemon logs to stderr (and, under the test harness, into a log file);
    // neither is an interactive terminal, so suppress ANSI colour codes to keep
    // the output as plain, greppable text in every environment.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

fn load_config(path: &Path, socket: &str) -> Config {
    match Config::parse_file(path, socket) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "failed to load config");
            std::process::exit(1);
        }
    }
}

fn run(args: Args) {
    init_tracing(args.debug, args.debug_level);

    let _ = (
        args.interactive,
        args.daemon,
        args.syslog_status,
        args.userproxy,
        &args.config_dir,
        args.idle_timeout,
    );
    // Daemonization and userproxy mode are not implemented; the daemon always
    // runs in the foreground.
    tracing::debug!(
        socket = %args.socket,
        config = %args.config.display(),
        daemon = args.daemon,
        interactive = args.interactive,
        userproxy = args.userproxy,
        idle_timeout = args.idle_timeout,
        "starting gssproxy daemon"
    );

    // Validate the configuration up front (matches the C daemon, which refuses
    // to start with an unparsable or empty config).
    let config = load_config(&args.config, &args.socket);
    let shared = Arc::new(Mutex::new(config));

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "failed to start tokio runtime");
            std::process::exit(1);
        }
    };

    let result = runtime.block_on(async move {
        server::run(args.socket.clone(), args.config.clone(), shared).await
    });

    if let Err(e) = result {
        tracing::error!(error = %e, "daemon exited with error");
        std::process::exit(1);
    }
}

fn main() {
    match parse_args_from(std::env::args().skip(1)) {
        Parsed::Run(args) => run(args),
        Parsed::Help => {
            println!("{USAGE}");
            std::process::exit(0);
        }
        Parsed::Version => {
            // Bare version string, matching the C daemon's `puts(VERSION)`.
            println!("{}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Parsed::ExtractCcache { source, dest } => {
            match gssproxy_server::extract::extract_ccache(&source, dest.as_deref()) {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("gssproxy: extract-ccache failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Parsed::DaemonInteractiveConflict => {
            // The C daemon prints this to stderr and exits 0.
            eprintln!("Option -i|--interactive is not allowed together with -D|--daemon");
            eprintln!("{USAGE}");
            std::process::exit(0);
        }
        Parsed::Error(msg) => {
            eprintln!("gssproxy: {msg}");
            eprintln!("{USAGE}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Parsed {
        parse_args_from(args.iter().map(|s| s.to_string()))
    }

    fn run_args(args: &[&str]) -> Args {
        match parse(args) {
            Parsed::Run(a) => a,
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn defaults_when_no_args() {
        let a = run_args(&[]);
        assert_eq!(a.socket, DEFAULT_SOCKET);
        assert_eq!(a.config, PathBuf::from(DEFAULT_CONF));
        assert!(!a.interactive && !a.daemon && !a.debug);
    }

    #[test]
    fn parses_test_harness_invocation() {
        // The exact form the upstream suite uses: `gssproxy -i -s SOCK -c CONF`.
        let a = run_args(&["-i", "-s", "/run/gp.sock", "-c", "/etc/gp.conf"]);
        assert!(a.interactive);
        assert_eq!(a.socket, "/run/gp.sock");
        assert_eq!(a.config, PathBuf::from("/etc/gp.conf"));
    }

    #[test]
    fn long_options_and_inline_values() {
        let a = run_args(&["--socket=/s", "--config=/c", "--interactive"]);
        assert_eq!(a.socket, "/s");
        assert_eq!(a.config, PathBuf::from("/c"));
        assert!(a.interactive);
    }

    #[test]
    fn config_dir_matches_c_capital_c_flag() {
        // C uses -C/--configdir for the config directory (and -d for debug).
        let a = run_args(&["-C", "/etc/gssproxy.d"]);
        assert_eq!(a.config_dir.as_deref(), Some("/etc/gssproxy.d"));
        let a = run_args(&["--configdir=/x"]);
        assert_eq!(a.config_dir.as_deref(), Some("/x"));
    }

    #[test]
    fn debug_and_daemon_flags() {
        let a = run_args(&["-d", "-D"]);
        assert!(a.debug);
        assert!(a.daemon);
        let a = run_args(&["--debug-level", "3"]);
        assert_eq!(a.debug_level, 3);
        let a = run_args(&["--syslog-status", "-u"]);
        assert!(a.syslog_status);
        assert!(a.userproxy);
    }

    #[test]
    fn version_and_help() {
        assert_eq!(parse(&["--version"]), Parsed::Version);
        assert_eq!(parse(&["-h"]), Parsed::Help);
        assert_eq!(parse(&["--help"]), Parsed::Help);
        assert_eq!(parse(&["--usage"]), Parsed::Help);
        assert_eq!(parse(&["-?"]), Parsed::Help);
    }

    #[test]
    fn unknown_option_is_error() {
        assert!(matches!(parse(&["--bogus"]), Parsed::Error(_)));
        assert!(matches!(parse(&["-z"]), Parsed::Error(_)));
    }

    #[test]
    fn missing_option_argument_is_error() {
        assert!(matches!(parse(&["-s"]), Parsed::Error(_)));
        assert!(matches!(parse(&["--config"]), Parsed::Error(_)));
        assert!(matches!(
            parse(&["--debug-level", "notanint"]),
            Parsed::Error(_)
        ));
    }

    #[test]
    fn idle_timeout_parses_like_c() {
        assert_eq!(run_args(&[]).idle_timeout, DEFAULT_IDLE_TIMEOUT);
        assert_eq!(run_args(&["--idle-timeout", "42"]).idle_timeout, 42);
        assert_eq!(run_args(&["--idle-timeout=7"]).idle_timeout, 7);
        assert!(matches!(parse(&["--idle-timeout", "x"]), Parsed::Error(_)));
        assert!(matches!(parse(&["--idle-timeout"]), Parsed::Error(_)));
    }

    #[test]
    fn extract_ccache_options() {
        assert_eq!(
            parse(&["--extract-ccache", "FILE:/tmp/cc"]),
            Parsed::ExtractCcache {
                source: "FILE:/tmp/cc".into(),
                dest: None
            }
        );
        assert_eq!(
            parse(&["--extract-ccache=FILE:/a", "--into-ccache=FILE:/b"]),
            Parsed::ExtractCcache {
                source: "FILE:/a".into(),
                dest: Some("FILE:/b".into()),
            }
        );
    }

    #[test]
    fn daemon_interactive_conflict_matches_c() {
        // C prints a message and exits 0 when -D and -i are combined.
        assert_eq!(parse(&["-D", "-i"]), Parsed::DaemonInteractiveConflict);
        assert_eq!(
            parse(&["--daemon", "--interactive"]),
            Parsed::DaemonInteractiveConflict
        );
        // Either alone is fine.
        assert!(matches!(parse(&["-D"]), Parsed::Run(_)));
        assert!(matches!(parse(&["-i"]), Parsed::Run(_)));
    }

    #[test]
    fn version_precedence_matches_popt() {
        // popt parses the whole argv before honoring --version, so an unknown
        // option anywhere still errors (it does not short-circuit on version).
        assert_eq!(parse(&["--version"]), Parsed::Version);
        assert_eq!(parse(&["-D", "--version"]), Parsed::Version);
        assert!(matches!(parse(&["--version", "--bogus"]), Parsed::Error(_)));
        // version wins over the -D/-i conflict and over extract-ccache.
        assert_eq!(parse(&["-D", "-i", "--version"]), Parsed::Version);
        assert_eq!(
            parse(&["--version", "--extract-ccache", "FILE:/x"]),
            Parsed::Version
        );
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    /// Value-less flags that, on their own, always yield a `Run`.
    fn known_flag() -> impl Strategy<Value = &'static str> {
        prop_oneof![
            Just("-i"),
            Just("--interactive"),
            Just("-D"),
            Just("--daemon"),
            Just("-u"),
            Just("--userproxy"),
            Just("-d"),
            Just("--debug"),
            Just("--syslog-status"),
        ]
    }

    /// A grab-bag of real flags, values, terminal tokens, and junk.
    fn token() -> impl Strategy<Value = String> {
        prop_oneof![
            known_flag().prop_map(str::to_string),
            Just("-s".to_string()),
            Just("--socket".to_string()),
            Just("-c".to_string()),
            Just("--config".to_string()),
            Just("-C".to_string()),
            Just("--configdir".to_string()),
            Just("--debug-level".to_string()),
            Just("--socket=/s".to_string()),
            Just("--debug-level=7".to_string()),
            Just("--debug-level=x".to_string()),
            Just("--version".to_string()),
            Just("-h".to_string()),
            Just("--help".to_string()),
            Just("-?".to_string()),
            Just("/some/path".to_string()),
            Just("5".to_string()),
            Just("--unknown".to_string()),
            Just(String::new()),
            "[ -~]{0,8}".prop_map(|s| s),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 1024,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// No argv - however malformed - makes the parser panic, and parsing is
        /// deterministic.
        #[test]
        fn parse_never_panics_and_is_deterministic(argv in prop::collection::vec(token(), 0..10)) {
            let a = parse_args_from(argv.clone());
            let b = parse_args_from(argv.clone());
            prop_assert_eq!(a, b);
        }

        /// Any sequence of value-less known flags parses to `Run`, with each
        /// boolean set iff its flag (short or long) is present - except that
        /// `-D` and `-i` together trigger the daemon/interactive conflict.
        #[test]
        fn known_flags_only_always_run(flags in prop::collection::vec(known_flag(), 0..8)) {
            let argv: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
            let has = |s: &str, l: &str| flags.iter().any(|f| *f == s || *f == l);
            let interactive = has("-i", "--interactive");
            let daemon = has("-D", "--daemon");
            match parse_args_from(argv) {
                _ if interactive && daemon => {
                    prop_assert_eq!(
                        parse_args_from(flags.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
                        Parsed::DaemonInteractiveConflict
                    );
                }
                Parsed::Run(a) => {
                    prop_assert_eq!(a.interactive, interactive);
                    prop_assert_eq!(a.daemon, daemon);
                    prop_assert_eq!(a.userproxy, has("-u", "--userproxy"));
                    prop_assert_eq!(a.debug, has("-d", "--debug"));
                    prop_assert_eq!(a.syslog_status, flags.contains(&"--syslog-status"));
                }
                other => prop_assert!(false, "value-less flags must Run, got {:?}", other),
            }
        }

        /// `--help` short-circuits inline (popt autohelp) and an unknown leading
        /// token errors, regardless of what follows. `--version`, by contrast,
        /// is only honored after a fully successful parse, so it does NOT
        /// short-circuit past a later bad option.
        #[test]
        fn leading_token_decides_outcome(rest in prop::collection::vec(token(), 0..6)) {
            let with = |head: &str| {
                let mut v = vec![head.to_string()];
                v.extend(rest.iter().cloned());
                parse_args_from(v)
            };
            prop_assert_eq!(with("-h"), Parsed::Help);
            prop_assert!(matches!(with("--definitely-not-a-flag"), Parsed::Error(_)));
        }
    }
}
