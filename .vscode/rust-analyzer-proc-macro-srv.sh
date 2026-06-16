#!/usr/bin/env bash
# Proc-macro server for rust-analyzer, sourced from the flake dev shell's rustc.
#
# rust-analyzer's built-in expander matches whatever rustc the rust-analyzer
# package was built with, which is not necessarily the dev shell's rustc that
# compiles rust/target. Point rust-analyzer.procMacro.server at this script so
# the expander always comes from the *same* rustc sysroot that builds the
# crates, avoiding proc-macro ABI mismatches. The sysroot is resolved at runtime
# (no hardcoded /nix/store path, so it survives toolchain updates).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec nix develop "$repo_root" --command \
  sh -c 'exec "$(rustc --print sysroot)/libexec/rust-analyzer-proc-macro-srv" "$@"' sh "$@"
