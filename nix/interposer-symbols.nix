{ pkgs, gssproxy, gssproxy-rs }:

# ABI parity check for the interposer plugin: the GSSAPI mechglue resolves a
# fixed set of symbols from proxymech.so (the entry point `gss_mech_interposer`
# plus the per-operation `gssi_*` functions). This derivation compares that
# surface between the C build (`$out/lib/gssproxy/proxymech.so`) and the Rust
# build (`$out/lib/libproxymech.so`).
#
# Gate (fails the build): every interposer symbol the Rust library exports must
# also be exported by the C library, with an identical name. This catches typos
# and accidentally-exported/mis-named symbols. As the Rust data path is filled
# in, the set grows toward full parity; the C-only remainder is reported for
# visibility but does not fail the check.
pkgs.runCommand "gssproxy-interposer-symbol-parity"
{
  nativeBuildInputs = [ pkgs.binutils ];
} ''
  set -eu

  cso=${gssproxy}/lib/gssproxy/proxymech.so
  rso=${gssproxy-rs}/lib/libproxymech.so

  test -f "$cso" || { echo "missing C proxymech.so at $cso"; exit 1; }
  test -f "$rso" || { echo "missing Rust libproxymech.so at $rso"; exit 1; }

  # Extract the interposer ABI surface (globally-defined text symbols named
  # gss_mech_interposer or gssi_*), sorted, from each library.
  extract() {
    nm -D --defined-only "$1" \
      | awk '$2=="T" && $3 ~ /^(gss_mech_interposer|gssi_)/ { print $3 }' \
      | sort -u
  }

  extract "$cso" > c.txt
  extract "$rso" > r.txt

  echo "== C interposer symbols ($(wc -l < c.txt)) =="
  cat c.txt
  echo "== Rust interposer symbols ($(wc -l < r.txt)) =="
  cat r.txt

  # Sanity: C must export the canonical entry point and a large gssi_* surface.
  grep -qx gss_mech_interposer c.txt || { echo "C lacks gss_mech_interposer"; exit 1; }
  if [ "$(wc -l < c.txt)" -lt 50 ]; then
    echo "unexpectedly few C interposer symbols"; exit 1
  fi

  # Rust must at least export the entry point.
  grep -qx gss_mech_interposer r.txt || { echo "Rust lacks gss_mech_interposer"; exit 1; }

  # Correctness gate: Rust-exported interposer symbols must be a subset of C's.
  comm -23 r.txt c.txt > extra.txt
  if [ -s extra.txt ]; then
    echo "FAIL: Rust exports interposer symbols absent from the C ABI:"
    cat extra.txt
    exit 1
  fi

  # Coverage report (informational): C interposer symbols not yet in Rust.
  comm -13 r.txt c.txt > todo.txt
  echo "== Implemented in Rust: $(wc -l < r.txt) / $(wc -l < c.txt) =="
  echo "== C interposer symbols not yet implemented in Rust ($(wc -l < todo.txt)) =="
  cat todo.txt

  echo "interposer symbol parity OK (Rust subset of C)" > $out
''
