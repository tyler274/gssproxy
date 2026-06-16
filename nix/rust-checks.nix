{ pkgs }:

# Rust formatting and lint gates for the ./rust workspace. Each entry is a
# derivation that fails to build if the corresponding check fails, so they can
# be wired straight into `flake.checks`.
#
# Both gates reuse the same vendored dependency set (via cargoSetupHook +
# importCargoLock) as nix/rust.nix, so they run fully offline in the sandbox.
let
  inherit (pkgs) lib rustPlatform;

  src = lib.cleanSource ../rust;

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ../rust/Cargo.lock;
  };

  common = {
    inherit src cargoDeps;
    # The committed .cargo/config.toml disables rustup's self-contained lld,
    # which Nixpkgs' rustc rejects; drop it like nix/rust.nix does.
    postPatch = ''
      rm -f .cargo/config.toml
    '';
    # bindgenHook supplies libclang for libgssapi-sys; pkg-config + krb5 let the
    # FFI crates resolve the system GSSAPI during macro/type expansion.
    buildInputs = [ pkgs.krb5 ];
    dontInstall = false;
    installPhase = "touch $out";
  };
in
{
  # `cargo fmt --check`: the workspace must be rustfmt-clean.
  rust-fmt = pkgs.stdenv.mkDerivation (common // {
    name = "gssproxy-rs-rustfmt-check";
    nativeBuildInputs = [
      rustPlatform.cargoSetupHook
      pkgs.cargo
      pkgs.rustc
      pkgs.rustfmt
      pkgs.pkg-config
      rustPlatform.bindgenHook
    ];
    buildPhase = ''
      runHook preBuild
      echo "cargo fmt --all --check"
      cargo fmt --all -- --check
      runHook postBuild
    '';
  });

  # `cargo clippy` with warnings denied across all crates and targets.
  clippy = pkgs.stdenv.mkDerivation (common // {
    name = "gssproxy-rs-clippy";
    nativeBuildInputs = [
      rustPlatform.cargoSetupHook
      pkgs.cargo
      pkgs.rustc
      pkgs.clippy
      pkgs.pkg-config
      rustPlatform.bindgenHook
    ];
    buildPhase = ''
      runHook preBuild
      echo "cargo clippy --workspace --all-targets -- -D warnings"
      cargo clippy --workspace --all-targets -- -D warnings
      runHook postBuild
    '';
  });

  # Whole-workspace `cargo test` as an explicit gate. This is where the
  # property-based tests (proptest round-trip fidelity in gssproxy-proto, the
  # config/CLI parsers in gssproxy-server) and the "chaos monkey" robustness
  # fuzzers (gssproxy-proto/tests/proptest_proto.rs: decode arbitrary/truncated/
  # biased byte streams must never panic, hang, or over-allocate) are validated.
  # Run in release so the higher proptest case counts (up to 512) stay fast.
  rust-tests = pkgs.stdenv.mkDerivation (common // {
    name = "gssproxy-rs-tests";
    nativeBuildInputs = [
      rustPlatform.cargoSetupHook
      pkgs.cargo
      pkgs.rustc
      pkgs.pkg-config
      rustPlatform.bindgenHook
    ];
    # Deterministic, reproducible fuzzing run; raise the floor for any
    # non-pinned proptest blocks and surface full backtraces on failure.
    PROPTEST_CASES = "1024";
    RUST_BACKTRACE = "1";
    buildPhase = ''
      runHook preBuild
      echo "cargo test --workspace --release (property + chaos/fuzz suite)"
      cargo test --workspace --release
      runHook postBuild
    '';
  });
}
