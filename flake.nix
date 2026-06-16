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
            pkg-config
            krb5
          ];
        };
      });

      formatter = forAllSystems ({ pkgs, ... }: pkgs.nixpkgs-fmt);
    };
}
