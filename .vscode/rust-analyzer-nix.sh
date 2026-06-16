#!/usr/bin/env bash
# Launch rust-analyzer inside the Nix flake dev shell.
#
# This keeps a single toolchain in play: the server's proc-macro expander,
# the sysroot, and every cargo/rustc invocation rust-analyzer spawns all come
# from the flake's pinned rustc (matching the artifacts built into rust/target).
# It also inherits LIBCLANG_PATH (via rustPlatform.bindgenHook) so the bindgen
# build scripts (libgssapi-sys, gssapi-sys) work.
#
# Without this, the IDE's bundled rust-analyzer uses the host rustup toolchain,
# producing "Unable to find libclang" and proc-macro ABI mismatch errors.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec nix develop "$repo_root" --command rust-analyzer "$@"
