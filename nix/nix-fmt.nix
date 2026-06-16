{ pkgs, src }:

# Formatting gate for the Nix sources: every tracked *.nix file (the flake plus
# everything under ./nix) must be nixpkgs-fmt clean. `src` should be a filtered
# source tree containing flake.nix and the nix/ directory.
pkgs.runCommand "gssproxy-nix-fmt-check"
{
  nativeBuildInputs = [ pkgs.nixpkgs-fmt ];
} ''
  set -eu
  cd ${src}
  echo "== checking nix formatting (nixpkgs-fmt --check) =="
  # List the files we check so failures are easy to map back.
  files=$(find . -name '*.nix' | sort)
  echo "$files"
  nixpkgs-fmt --check $files
  echo "nix formatting OK" > $out
''
