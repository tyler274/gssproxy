# Local Kani runner.
#
# Kani is not packaged in nixpkgs (it needs a pinned nightly toolchain and
# downloads the CBMC backend into KANI_HOME at runtime), so we sandbox it in an
# FHS environment that provides rustup/cargo/gcc plus the krb5/clang headers the
# `gssapi-sys` build script needs. On first use it installs the Kani driver and
# CBMC into a project-local `.kani/` directory; subsequent runs are fast.
#
# Wired into the flake as:
#   nix run    .#kani -- -p gssproxy-proto
#   nix develop .#kani            (interactive FHS shell, then `cargo kani ...`)
#
# Deliberately NOT part of `nix flake check`, which stays hermetic.
{ pkgs }:
let
  # Note: we deliberately do NOT use nixpkgs' `rustup`, which patches toolchains
  # with a NixOS-specific lld wrapper that fails inside a plain FHS. Instead the
  # runner bootstraps upstream rustup via rustup-init, whose toolchains link
  # against the FHS gcc/ld normally.
  targetPkgs = p: with p; [
    gcc
    binutils
    gnumake
    python3
    pkg-config
    git
    curl
    cacert
    which
    gnutar
    gzip
    xz
    krb5
    krb5.dev
    openssl
    openssl.dev
    # libclang + a full clang (its resource headers) so libgssapi-sys's bindgen
    # build script can parse gssapi.h; glibc.dev supplies sys/types.h etc.
    llvmPackages.libclang.lib
    clang
    glibc.dev
    zlib
  ];

  # Shared environment: project-local cargo/rustup/kani state (isolated from any
  # host ~/.rustup, whose NixOS-wrapped toolchains don't work inside this FHS)
  # plus the paths bindgen needs to find libclang and the krb5/gssapi headers.
  # Sourced both by the interactive shell (`profile`) and the runner script.
  # NOTE: forced (not `:-` defaulted) because a NixOS host typically exports
  # RUSTUP_HOME/CARGO_HOME pointing at a nixpkgs-rustup install whose toolchains
  # carry an lld wrapper that is broken inside this FHS. We must isolate to a
  # project-local, FHS-built rust toolchain. KANI_ROOT lets callers relocate it.
  envSetup = ''
    KANI_ROOT="''${KANI_ROOT:-$PWD/.kani}"
    export CARGO_HOME="$KANI_ROOT/cargo"
    export RUSTUP_HOME="$KANI_ROOT/rustup"
    export KANI_HOME="$KANI_ROOT/home"
    export PATH="$CARGO_HOME/bin:$PATH"
    export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
    export SSL_CERT_FILE="${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
  '';

  profile = envSetup;

  # Bootstrap the Kani driver + CBMC on first use, then run `cargo kani` in the
  # rust workspace with whatever args were passed (e.g. -p gssproxy-proto).
  # We set the environment here too (not just via `profile`) so the project-local
  # RUSTUP_HOME/CARGO_HOME are guaranteed to apply to this non-interactive run.
  runScript = pkgs.writeShellScript "gssproxy-kani-run" ''
    set -euo pipefail
    ${envSetup}

    if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
      echo "kani: installing upstream rustup + stable toolchain (first run)..." >&2
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --no-modify-path --profile minimal --default-toolchain stable
    fi
    if ! command -v cargo-kani >/dev/null 2>&1; then
      echo "kani: installing kani-verifier (first run)..." >&2
      cargo install --locked kani-verifier
    fi
    if [ ! -x "$KANI_HOME/bin/kani" ] && ! ls -d "$KANI_HOME"/kani-* >/dev/null 2>&1; then
      echo "kani: running 'cargo kani setup' to fetch CBMC (first run)..." >&2
      cargo kani setup
    fi

    if [ -f rust/Cargo.toml ]; then
      cd rust
    fi
    exec cargo kani "$@"
  '';
in
{
  # `nix run .#kani -- <args>`
  app = pkgs.buildFHSEnv {
    name = "gssproxy-kani";
    inherit targetPkgs profile;
    runScript = "${runScript}";
  };

  # `nix develop .#kani` (interactive shell with the same environment)
  shell = pkgs.buildFHSEnv {
    name = "gssproxy-kani-shell";
    inherit targetPkgs profile;
    runScript = "bash";
  };
}
