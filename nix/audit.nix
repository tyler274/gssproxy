# Supply-chain auditing tools for the ./rust workspace.
#
# cargo-audit (RustSec CVE scan) and the network-dependent parts of cargo-deny
# need to fetch the RustSec advisory database, so unlike the offline
# `cargo-deny` flake check they are exposed as a dev shell + apps rather than as
# sealed Nix checks:
#
#   nix develop .#audit              # cargo audit / cargo deny available
#   nix run     .#audit              # cargo audit (CVEs + yanked crates)
#   nix run     .#deny               # cargo deny check (all, incl. advisories)
{ pkgs }:
let
  auditInputs = with pkgs; [
    cargo
    rustc
    cargo-audit
    cargo-deny
    # cargo-audit / cargo-deny fetch the advisory DB over git/https.
    git
    cacert
  ];
in
{
  shell = pkgs.mkShell {
    packages = auditInputs;
    RUSTFLAGS = " ";
  };

  audit = pkgs.writeShellApplication {
    name = "gssproxy-audit";
    runtimeInputs = auditInputs;
    text = ''
      cd "''${RUST_DIR:-rust}"
      # Scan Cargo.lock for crates with RustSec advisories or that are yanked.
      exec cargo audit "$@"
    '';
  };

  deny = pkgs.writeShellApplication {
    name = "gssproxy-deny";
    runtimeInputs = auditInputs;
    text = ''
      cd "''${RUST_DIR:-rust}"
      # Full cargo-deny run including the network-fetched advisories check.
      exec cargo deny check "$@"
    '';
  };
}
