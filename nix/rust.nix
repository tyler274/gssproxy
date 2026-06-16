{ lib
, rustPlatform
, pkg-config
, krb5
}:

# Builds the Rust reimplementation workspace under ../rust:
#   - the `gssproxy` daemon binary,
#   - the `proxymech.so` interposer cdylib,
#   - and the supporting library crates.
#
# Kept as a separate derivation from the autotools package (nix/package.nix) so
# both can coexist during the port; flake.nix exposes this as `gssproxy-rs`.
rustPlatform.buildRustPackage {
  pname = "gssproxy-rs";
  version = "0.9.2";

  src = lib.cleanSource ../rust;

  cargoLock.lockFile = ../rust/Cargo.lock;

  # The committed .cargo/config.toml disables the rustup self-contained lld
  # (needed only on the non-Nix dev host). Nixpkgs' rust ships a working
  # linker, so drop the override here to avoid pinning linker behaviour.
  postPatch = ''
    rm -f .cargo/config.toml
  '';

  # pkg-config locates the MIT GSSAPI; bindgenHook supplies libclang/LIBCLANG_PATH
  # for libgssapi-sys's bindgen build script.
  nativeBuildInputs = [ pkg-config rustPlatform.bindgenHook ];

  # The daemon and interposer link against the system GSSAPI/krb5.
  buildInputs = [ krb5 ];

  meta = {
    description = "Rust reimplementation of the gssproxy daemon and proxymech.so interposer";
    homepage = "https://github.com/gssapi/gssproxy";
    license = lib.licenses.gpl3Plus;
    platforms = lib.platforms.linux;
    mainProgram = "gssproxy";
  };
}
