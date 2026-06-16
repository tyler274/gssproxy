{ pkgs, gssproxy, gssproxy-rs }:

# CLI parity check between the C daemon (`src/gssproxy.c`, popt-based) and the
# Rust daemon (`rust/gssproxy-server/src/main.rs`). It exercises the flag-level
# behaviours that do not require a live KDC, asserting both binaries agree:
#   * `--version` exits 0 with non-empty output,
#   * `--help` exits 0,
#   * an unknown option exits non-zero,
#   * a missing config file exits non-zero (no daemon left running).
#
# The Rust-only readiness behaviour ("Initialization complete." + socket bind)
# is covered by the cargo integration test `gssproxy-server/tests/cli.rs`.
pkgs.runCommand "gssproxy-cli-parity" { } ''
  set -u

  C=${gssproxy}/bin/gssproxy
  R=${gssproxy-rs}/bin/gssproxy

  fail() { echo "CLI PARITY FAIL: $*"; exit 1; }

  # --version: exit 0, non-empty stdout, for both implementations.
  # (Note: avoid the variable name `out`, which is the derivation output path.)
  for impl in C R; do
    bin=$C; [ "$impl" = R ] && bin=$R
    vers=$("$bin" --version 2>/dev/null) || fail "$impl --version exited non-zero"
    [ -n "$vers" ] || fail "$impl --version produced no output"
    echo "$impl --version -> $vers"
  done

  # --help: exit 0 for both.
  "$C" --help >/dev/null 2>&1 || fail "C --help exited non-zero"
  "$R" --help >/dev/null 2>&1 || fail "Rust --help exited non-zero"

  # Unknown option: non-zero exit for both.
  if "$C" --definitely-not-a-flag >/dev/null 2>&1; then
    fail "C accepted an unknown option"
  fi
  if "$R" --definitely-not-a-flag >/dev/null 2>&1; then
    fail "Rust accepted an unknown option"
  fi

  # Missing config file: non-zero exit for both (and must not hang / daemonize).
  if "$C" -i -s "$PWD/none.sock" -c "$PWD/does-not-exist.conf" >/dev/null 2>&1; then
    fail "C started with a missing config file"
  fi
  if "$R" -i -s "$PWD/none.sock" -c "$PWD/does-not-exist.conf" >/dev/null 2>&1; then
    fail "Rust started with a missing config file"
  fi

  echo "CLI parity OK" > $out
''
