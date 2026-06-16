# Benchmark tooling for the ./rust port.
#
# Provides a dev shell and a `cargo flamegraph` runner for the `gssproxy-bench`
# crate, which compares the Rust gssx codec against the C rpcgen XDR. The crate
# links gssrpc + krb5-gssapi (via its build.rs) and reads ../../rpcgen, so it is
# excluded from the workspace and only built here.
#
# Wired into the flake as:
#   nix develop .#bench     # then: cargo bench --bench codec
#   nix run     .#flamegraph -- <extra cargo-flamegraph args>
#
# Deliberately NOT a flake check: benchmarks are non-deterministic and the crate
# reaches outside the sealed rust/ source tree.
{ pkgs }:
let
  benchInputs = with pkgs; [
    cargo
    rustc
    stdenv.cc # `cc` for the linker and the cc-rs build script
    pkg-config
    krb5
    krb5.dev
    cargo-flamegraph
    linuxPackages.perf
  ];

  # krb5-gssapi.pc / krb5.pc live in the dev output.
  pkgConfigPath = "${pkgs.krb5.dev}/lib/pkgconfig";
in
{
  shell = pkgs.mkShell {
    packages = benchInputs;
    # Match the default shell: neutralise the .cargo/config.toml lld override
    # that Nixpkgs' rustc rejects.
    RUSTFLAGS = " ";
    shellHook = ''
      export PKG_CONFIG_PATH="${pkgConfigPath}''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
      echo "gssproxy bench shell: cd rust/gssproxy-bench && cargo bench --bench codec" >&2
    '';
  };

  flamegraph = pkgs.writeShellApplication {
    name = "gssproxy-flamegraph";
    runtimeInputs = benchInputs;
    text = ''
      export PKG_CONFIG_PATH="${pkgConfigPath}''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
      export RUSTFLAGS="''${RUSTFLAGS:- }"
      cd "''${BENCH_DIR:-rust/gssproxy-bench}"
      # Run from inside target/ so BOTH the flamegraph.svg (-o) and perf.data
      # (cargo-flamegraph always writes it to the cwd) land under target/ and are
      # therefore removed by `cargo clean`.
      out="target/flamegraph"
      mkdir -p "$out"
      cd "$out"
      # cargo-flamegraph runs the criterion bench binary under perf; the trailing
      # `--bench` puts criterion in bench mode. Extra args are forwarded.
      exec cargo flamegraph --manifest-path ../../Cargo.toml \
        --output flamegraph.svg --bench codec -- --bench "$@"
    '';
  };
}
