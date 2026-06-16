//! End-to-end CLI tests that exercise the built `gssproxy` daemon binary.
//!
//! These complement the pure-parser unit tests in `main.rs` by checking the
//! real process behaviour (exit codes, output, socket binding, the
//! "Initialization complete." readiness line the test harness waits for). The
//! C-vs-Rust parity for the shared flags is validated separately in
//! `nix/cli-tests.nix`, which has both binaries available.

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_gssproxy")
}

fn unique() -> u64 {
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("gp-cli-{tag}-{}-{}", std::process::id(), unique()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn version_exits_zero_with_output() {
    let out = Command::new(bin()).arg("--version").output().unwrap();
    assert!(out.status.success(), "--version should exit 0");
    assert!(!out.stdout.is_empty(), "--version should print something");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains(env!("CARGO_PKG_VERSION")), "version output: {s:?}");
}

#[test]
fn help_exits_zero() {
    for flag in ["-h", "--help", "--usage"] {
        let out = Command::new(bin()).arg(flag).output().unwrap();
        assert!(out.status.success(), "{flag} should exit 0");
    }
}

#[test]
fn unknown_option_exits_nonzero_with_usage() {
    let out = Command::new(bin()).arg("--definitely-not-a-flag").output().unwrap();
    assert!(!out.status.success(), "unknown option should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Usage:"), "stderr should show usage: {err:?}");
}

#[test]
fn missing_config_exits_nonzero() {
    let dir = tmpdir("noconf");
    let out = Command::new(bin())
        .args([
            "-i",
            "-s",
            dir.join("s.sock").to_str().unwrap(),
            "-c",
            dir.join("does-not-exist.conf").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success(), "missing config should fail to start");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn starts_and_prints_initialization_complete() {
    let dir = tmpdir("init");
    let conf = dir.join("gssproxy.conf");
    let sock = dir.join("default.sock");
    // Minimal valid config: a single krb5 service (the loader requires at
    // least one service section). The daemon binds the socket and reports
    // readiness without needing a live KDC.
    std::fs::write(&conf, "[service/test]\n  mechs = krb5\n  euid = 0\n").unwrap();

    let mut child = Command::new(bin())
        .args(["-i", "-s", sock.to_str().unwrap(), "-c", conf.to_str().unwrap()])
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut r = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if line.contains("Initialization complete.") {
                        let _ = tx.send(true);
                    }
                }
                Err(_) => break,
            }
        }
        // Drain remaining output so the pipe doesn't block the child on exit.
        let mut sink = Vec::new();
        let _ = r.read_to_end(&mut sink);
    });

    let ready = rx.recv_timeout(Duration::from_secs(15)).unwrap_or(false);

    // Give the socket a brief moment to appear after the readiness line.
    let deadline = Instant::now() + Duration::from_secs(2);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let socket_bound = sock.exists();

    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();

    assert!(ready, "daemon should print 'Initialization complete.'");
    assert!(socket_bound, "daemon should bind the requested socket path");
    let _ = std::fs::remove_dir_all(&dir);
}
