{ pkgs }:

# A reproducible developer container image, built entirely by Nix (no Dockerfile).
#
# Build and load it with:
#   nix build .#devcontainer
#   docker load < result            # (or: podman load < result)
#   docker run --rm -it -v "$PWD:/workspace" gssproxy-devcontainer:latest
#
# It bundles the full toolchain needed to hack on both the autotools C build and
# the ./rust port (daemon + proxymech.so), matching the flake's devShell.
let
  inherit (pkgs) lib;

  # Everything a developer needs on PATH inside the container.
  devTools = with pkgs; [
    # Shell / base userland so the image is usable interactively.
    bashInteractive
    coreutils
    findutils
    gnugrep
    gnused
    gawk
    which
    less
    gnumake
    git
    # C build toolchain for the autotools project.
    gcc
    binutils
    autoconf
    automake
    libtool
    gettext
    pkg-config
    krb5
    # Rust toolchain for the ./rust workspace.
    cargo
    rustc
    clippy
    rustfmt
    rust-analyzer
    # Formatting / Nix tooling.
    nixpkgs-fmt
    # Test helpers used by the upstream suite.
    python3
  ];
in
pkgs.dockerTools.buildLayeredImage {
  name = "gssproxy-devcontainer";
  tag = "latest";

  contents = devTools ++ [
    pkgs.dockerTools.binSh
    pkgs.dockerTools.usrBinEnv
    pkgs.dockerTools.caCertificates
  ];

  # Create a writable /tmp and the default workspace mount point.
  extraCommands = ''
    mkdir -p tmp workspace
    chmod 1777 tmp
  '';

  config = {
    Cmd = [ "${pkgs.bashInteractive}/bin/bash" ];
    WorkingDir = "/workspace";
    Env = [
      "PKG_CONFIG_PATH=${pkgs.krb5.dev}/lib/pkgconfig"
      # bindgen (libgssapi-sys build script) needs libclang at runtime.
      "LIBCLANG_PATH=${pkgs.libclang.lib}/lib"
      "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
      "RUSTFLAGS= "
      "PAGER=less"
    ];
    Labels = {
      "org.opencontainers.image.title" = "gssproxy-devcontainer";
      "org.opencontainers.image.description" =
        "Dev container for gssproxy (C autotools build + Rust port)";
    };
  };

  meta = {
    description = "Nix-built developer container image for gssproxy";
    platforms = lib.platforms.linux;
  };
}
