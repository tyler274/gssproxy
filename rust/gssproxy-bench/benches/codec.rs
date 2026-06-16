//! Criterion benchmarks for the gssx wire codec, comparing the pure-Rust
//! `gssproxy-proto` implementation against the C rpcgen XDR (via the FFI shim).
//!
//! Run:
//!   cargo bench --bench codec                 # full comparison report
//!   cargo bench --bench codec -- --profile-time=5   # pprof flamegraph SVGs
//!
//! Each group holds a `rust` and a `c` function so the HTML report renders them
//! side by side. See rust/docs/benchmarking.md.

use std::fs::File;
use std::hint::black_box;
use std::path::Path;

use criterion::profiler::Profiler;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use pprof::ProfilerGuard;

use gssproxy_bench::{SCRATCH, c, rust};

/// init_sec_context input_token sizes (bytes): empty, small, page, large.
const TOKEN_SIZES: &[usize] = &[0, 256, 4096, 65536];

/// A Criterion `Profiler` that samples with pprof and writes a flamegraph SVG.
///
/// pprof ships its own `PProfProfiler`, but its `criterion` feature is locked to
/// criterion 0.5; this mirrors that logic for criterion 0.8. Activated by
/// `cargo bench --bench codec -- --profile-time=<secs>`, it emits
/// `target/criterion/<group>/<bench>/profile/flamegraph.svg`.
struct FlamegraphProfiler<'a> {
    frequency: std::os::raw::c_int,
    guard: Option<ProfilerGuard<'a>>,
}

impl FlamegraphProfiler<'_> {
    fn new(frequency: std::os::raw::c_int) -> Self {
        Self {
            frequency,
            guard: None,
        }
    }
}

impl Profiler for FlamegraphProfiler<'_> {
    fn start_profiling(&mut self, _benchmark_id: &str, _benchmark_dir: &Path) {
        self.guard = Some(ProfilerGuard::new(self.frequency).expect("failed to start pprof"));
    }

    fn stop_profiling(&mut self, _benchmark_id: &str, benchmark_dir: &Path) {
        if let Some(guard) = self.guard.take() {
            std::fs::create_dir_all(benchmark_dir).expect("failed to create profile dir");
            let path = benchmark_dir.join("flamegraph.svg");
            let file = File::create(&path)
                .unwrap_or_else(|e| panic!("failed to create {}: {e}", path.display()));
            guard
                .report()
                .build()
                .expect("failed to build pprof report")
                .flamegraph(file)
                .expect("failed to write flamegraph");
        }
    }
}

fn bench_indicate_mechs(crit: &mut Criterion) {
    c::setup_indicate_mechs();
    let arg = rust::indicate_mechs_arg();
    let bytes = rust::encode_indicate_mechs(&arg);

    // Sanity: both encoders agree on the body length before we benchmark.
    let mut scratch = vec![0u8; SCRATCH];
    let c_len = c::encode_indicate_mechs(&mut scratch);
    assert_eq!(
        c_len,
        bytes.len(),
        "C/Rust indicate_mechs body length differ"
    );
    assert!(c::decode_indicate_mechs(&bytes), "C must decode Rust bytes");
    assert!(
        rust::decode_indicate_mechs(&scratch[..c_len]),
        "Rust must decode C bytes"
    );

    let mut g = crit.benchmark_group("encode/indicate_mechs");
    g.bench_function("rust", |b| {
        b.iter(|| black_box(rust::encode_indicate_mechs(black_box(&arg))))
    });
    g.bench_function("c", |b| {
        b.iter(|| black_box(c::encode_indicate_mechs(black_box(&mut scratch))))
    });
    g.finish();

    let mut g = crit.benchmark_group("decode/indicate_mechs");
    g.bench_function("rust", |b| {
        b.iter(|| black_box(rust::decode_indicate_mechs(black_box(&bytes))))
    });
    g.bench_function("c", |b| {
        b.iter(|| black_box(c::decode_indicate_mechs(black_box(&bytes))))
    });
    g.finish();
}

fn bench_init_sec_context(crit: &mut Criterion) {
    let mut scratch = vec![0u8; SCRATCH];

    let mut enc = crit.benchmark_group("encode/init_sec_context");
    for &n in TOKEN_SIZES {
        c::setup_init_sec_context(n);
        let arg = rust::init_sec_context_arg(n);
        let bytes = rust::encode_init_sec_context(&arg);
        let c_len = c::encode_init_sec_context(&mut scratch);
        assert_eq!(
            c_len,
            bytes.len(),
            "C/Rust init_sec_context len differ at {n}"
        );

        enc.throughput(Throughput::Bytes(bytes.len() as u64));
        enc.bench_with_input(BenchmarkId::new("rust", n), &arg, |b, arg| {
            b.iter(|| black_box(rust::encode_init_sec_context(black_box(arg))))
        });
        enc.bench_with_input(BenchmarkId::new("c", n), &n, |b, _| {
            b.iter(|| black_box(c::encode_init_sec_context(black_box(&mut scratch))))
        });
    }
    enc.finish();

    let mut dec = crit.benchmark_group("decode/init_sec_context");
    for &n in TOKEN_SIZES {
        c::setup_init_sec_context(n);
        let arg = rust::init_sec_context_arg(n);
        let bytes = rust::encode_init_sec_context(&arg);
        assert!(
            c::decode_init_sec_context(&bytes),
            "C must decode Rust bytes at {n}"
        );
        assert!(
            rust::decode_init_sec_context(&bytes),
            "Rust must decode its bytes at {n}"
        );

        dec.throughput(Throughput::Bytes(bytes.len() as u64));
        dec.bench_with_input(BenchmarkId::new("rust", n), &bytes, |b, bytes| {
            b.iter(|| black_box(rust::decode_init_sec_context(black_box(bytes))))
        });
        dec.bench_with_input(BenchmarkId::new("c", n), &bytes, |b, bytes| {
            b.iter(|| black_box(c::decode_init_sec_context(black_box(bytes))))
        });
    }
    dec.finish();
}

criterion_group! {
    name = benches;
    // 997 Hz: high enough to get usable stacks on the larger token cases
    // (the sub-µs benches are dominated by the iteration loop regardless).
    config = Criterion::default().with_profiler(FlamegraphProfiler::new(997));
    targets = bench_indicate_mechs, bench_init_sec_context
}
criterion_main!(benches);
