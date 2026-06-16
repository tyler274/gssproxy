# Benchmarking the gssx codec (Rust vs C) with flamegraphs

The [`gssproxy-bench`](../gssproxy-bench) crate benchmarks the gssx wire codec
and compares the pure-Rust [`gssproxy-proto`](../gssproxy-proto) implementation
head-to-head against the C rpcgen XDR (`rpcgen/gss_proxy_xdr.c`,
`gp_rpc_xdr.c`, `gp_xdr.c`, linking MIT krb5's `gssrpc`).

It is **excluded from the Rust workspace** (see `exclude` in
[rust/Cargo.toml](../Cargo.toml)) because its `build.rs` compiles the C sources
under `../../rpcgen` and links `gssrpc` + `krb5-gssapi`. The hermetic
`--workspace` gates (clippy, `rust-tests`, Kani) therefore never build it, and
it is intentionally not a `nix flake check`.

## What is measured

Criterion groups, each with a `rust` and a `c` function (rendered side by side):

- `encode/indicate_mechs`, `decode/indicate_mechs` - the minimal CALL envelope.
- `encode/init_sec_context`, `decode/init_sec_context` - the krb5 CALL with an
  `input_token` swept over `0, 256, 4096, 65536` bytes (exercises the
  opaque/length-prefix/padding hot path and optional-pointer fields), tagged
  with `Throughput::Bytes`.

Both sides serialize the same wire body (`gp_rpc_msg` + arg); the benches assert
the C and Rust encoders agree on the body length and can each decode the other's
bytes before timing. The C struct construction is done once in
`cbench_setup_*`, so only encode/decode is timed.

### Fairness caveat

The C path uses MIT krb5's `gssrpc` `xdrmem` routines; the Rust path uses the
hand-rolled `XdrEncoder`/`XdrDecoder`. Both go through one in-process call, but
they are different implementations of the same wire format - treat the numbers
as an implementation comparison, not a controlled microbenchmark of a single
algorithm.

## Running

Enter the bench shell (provides cargo, the C toolchain, krb5/gssrpc,
cargo-flamegraph, and perf):

```sh
nix develop .#bench
cd rust/gssproxy-bench

# Full comparison report (HTML at target/criterion/report/index.html):
cargo bench --bench codec

# Quick run while iterating:
cargo bench --bench codec -- --warm-up-time 1 --measurement-time 2
```

## Flamegraphs

Two complementary mechanisms:

### 1. pprof-rs, per-benchmark (no perf/root)

The Criterion harness is configured with a `pprof` profiler, so passing
`--profile-time` samples each benchmark in-process and writes a flamegraph:

```sh
cargo bench --bench codec -- --profile-time=5
# -> target/criterion/<group>/<bench>/profile/flamegraph.svg
```

### 2. cargo-flamegraph, whole binary (perf-based)

```sh
nix run .#flamegraph            # profiles `cargo bench --bench codec`
nix run .#flamegraph -- decode  # forward a filter to the bench binary
# -> rust/gssproxy-bench/target/flamegraph/flamegraph.svg (+ perf.data)
```

The app runs from inside `target/` so both `flamegraph.svg` and perf's
`perf.data` land under `target/flamegraph/` and are removed by `cargo clean`
(the pprof SVGs under `target/criterion` are cleaned too). If you instead run
`cargo flamegraph` by hand from the crate root, it writes `flamegraph.svg` /
`perf.data` to the cwd, outside `target/` - those are gitignored but not removed
by `cargo clean`.

`cargo flamegraph` uses Linux `perf`, which usually needs relaxed kernel
permissions. If it fails with a permissions error:

```sh
sudo sysctl kernel.perf_event_paranoid=1
# and, if needed for kernel symbols:
sudo sysctl kernel.kptr_restrict=0
```

(perf access is environment-specific; in containers/VMs it may require
`--cap-add SYS_ADMIN` or a privileged session.)
