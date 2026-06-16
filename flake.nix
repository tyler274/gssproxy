{
  description = "GSS Proxy: a GSSAPI proxy daemon and a NixOS module that uses it as a drop-in replacement for rpc.svcgssd";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f {
        inherit system;
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ self.overlays.default ];
        };
      });
    in
    {
      overlays.default = final: prev: {
        gssproxy = final.callPackage ./nix/package.nix { };
        # Rust reimplementation (daemon + proxymech.so interposer).
        gssproxy-rs = final.callPackage ./nix/rust.nix { };
      };

      packages = forAllSystems ({ pkgs, ... }: {
        inherit (pkgs) gssproxy gssproxy-rs;
        default = pkgs.gssproxy;
      });

      nixosModules.gssproxy = {
        imports = [ ./nix/module.nix ];
        nixpkgs.overlays = [ self.overlays.default ];
      };
      nixosModules.default = self.nixosModules.gssproxy;

      checks = forAllSystems ({ pkgs, system, ... }: {
        vm-test = import ./nix/test.nix {
          inherit pkgs;
          module = self.nixosModules.gssproxy;
        };

        # Full upstream in-repo test suite (tests/runtests.py via `make check`).
        integration-tests = import ./nix/integration-tests.nix {
          inherit pkgs;
          inherit (pkgs) gssproxy;
        };

        # Same upstream suite, but driven against the Rust daemon (oracle gate
        # #1): the C-built proxymech.so and test programs talk to the Rust
        # gssproxy over the wire, proving protocol/ABI compatibility.
        integration-tests-rust = import ./nix/integration-tests.nix {
          inherit pkgs;
          inherit (pkgs) gssproxy;
          daemon = pkgs.gssproxy-rs;
        };

        # CLI behaviour parity between the C and Rust gssproxy binaries
        # (--version/--help/unknown-option/missing-config).
        cli-parity = import ./nix/cli-tests.nix {
          inherit pkgs;
          inherit (pkgs) gssproxy gssproxy-rs;
        };

        # Interposer ABI parity: the Rust proxymech.so's exported
        # gss_mech_interposer/gssi_* surface must be a subset of the C plugin's.
        interposer-symbol-parity = import ./nix/interposer-symbols.nix {
          inherit pkgs;
          inherit (pkgs) gssproxy gssproxy-rs;
        };

        # Upstream suite with the Rust libproxymech.so loaded in place of the
        # C interposer (oracle gate #2), talking to the C daemon. This proves
        # the Rust interposer data path is wire/ABI compatible.
        integration-tests-rust-proxymech = import ./nix/integration-tests.nix {
          inherit pkgs;
          inherit (pkgs) gssproxy;
          proxymech = pkgs.gssproxy-rs;
        };

        # Upstream suite end-to-end on the Rust port: Rust daemon AND Rust
        # interposer, with only the C test programs unchanged.
        integration-tests-all-rust = import ./nix/integration-tests.nix {
          inherit pkgs;
          inherit (pkgs) gssproxy;
          daemon = pkgs.gssproxy-rs;
          proxymech = pkgs.gssproxy-rs;
        };
      });

      devShells = forAllSystems ({ pkgs, ... }: {
        default = pkgs.mkShell {
          inputsFrom = [ pkgs.gssproxy ];
          packages = with pkgs; [
            autoconf
            automake
            libtool
            gettext
            python3
            # Rust toolchain for the port under ./rust.
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            pkg-config
            krb5
            # Supplies libclang/LIBCLANG_PATH so libgssapi-sys's bindgen build
            # script works in the dev shell, matching nix/rust.nix.
            rustPlatform.bindgenHook
          ];
          # The committed .cargo/config.toml disables rustup's self-contained
          # lld for the non-Nix host, but Nixpkgs' rustc rejects that flag, so
          # neutralise the override inside the dev shell. (cargo uses RUSTFLAGS
          # in preference to target.*.rustflags from the config file.)
          RUSTFLAGS = " ";
        };
      });

      formatter = forAllSystems ({ pkgs, ... }: pkgs.nixpkgs-fmt);
    };
}
