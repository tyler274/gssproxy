{ pkgs, gssproxy, gssproxy-rs }:

# CLI parity check between the C daemon (`src/gssproxy.c`, popt-based) and the
# Rust daemon (`rust/gssproxy-server/src/main.rs`). It exercises the flag-level
# behaviours that do not require a live KDC, asserting both binaries agree on
# inputs and outputs:
#   * `--version` exits 0 with identical single-line output,
#   * `--help` exits 0,
#   * an unknown option exits non-zero,
#   * a non-integer `--idle-timeout` exits non-zero,
#   * combining `-D` and `-i` exits 0 (popt conflict message, success exit),
#   * `--extract-ccache` on a missing ccache exits non-zero (no hang),
#   * a missing config file exits non-zero (no daemon left running).
#
# The Rust-only readiness behaviour ("Initialization complete." + socket bind)
# is covered by the cargo integration test `gssproxy-server/tests/cli.rs`.
pkgs.runCommand "gssproxy-cli-parity" { } ''
  set -u

  C=${gssproxy}/bin/gssproxy
  R=${gssproxy-rs}/bin/gssproxy

  fail() { echo "CLI PARITY FAIL: $*"; exit 1; }

  # --version: exit 0, single non-empty line, identical output for both.
  # (Note: avoid the variable name `out`, which is the derivation output path.)
  cvers=$("$C" --version 2>/dev/null) || fail "C --version exited non-zero"
  rvers=$("$R" --version 2>/dev/null) || fail "Rust --version exited non-zero"
  [ -n "$cvers" ] || fail "C --version produced no output"
  [ -n "$rvers" ] || fail "Rust --version produced no output"
  echo "C --version -> $cvers ; Rust --version -> $rvers"
  [ "$cvers" = "$rvers" ] || fail "version output differs: C='$cvers' Rust='$rvers'"

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

  # --idle-timeout requires an integer; a non-integer errors for both.
  if "$C" --idle-timeout notanint >/dev/null 2>&1; then
    fail "C accepted a non-integer --idle-timeout"
  fi
  if "$R" --idle-timeout notanint >/dev/null 2>&1; then
    fail "Rust accepted a non-integer --idle-timeout"
  fi

  # Combining -D and -i: both print a conflict message and exit 0.
  "$C" -D -i >/dev/null 2>&1 || fail "C -D -i did not exit 0"
  "$R" -D -i >/dev/null 2>&1 || fail "Rust -D -i did not exit 0"

  # --extract-ccache on a missing ccache: non-zero exit for both (no hang).
  if "$C" --extract-ccache "FILE:$PWD/nope.ccache" >/dev/null 2>&1; then
    fail "C extract-ccache succeeded on a missing ccache"
  fi
  if "$R" --extract-ccache "FILE:$PWD/nope.ccache" >/dev/null 2>&1; then
    fail "Rust extract-ccache succeeded on a missing ccache"
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
