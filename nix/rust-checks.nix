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
}
