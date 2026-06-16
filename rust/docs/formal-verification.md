# Formal verification of the Rust port: Creusot vs Kani

This document evaluates two Rust verification tools - [Creusot](https://creusot.rs)
and [Kani](https://github.com/model-checking/kani) - for **documenting and proving
the safety invariants of the unsafe code** in this workspace, records the decision,
and describes how the chosen tooling is wired into the project.

## The problem: an FFI-dominated unsafe surface

The Rust port is a drop-in replacement for a C GSSAPI daemon and its
`proxymech.so` interposer, so it is unavoidably unsafe-heavy. There are ~225
`unsafe` sites, concentrated in:

| Area | Nature of the unsafe |
| --- | --- |
| `gssapi-sys/src/wrap.rs` (53), `seal.rs`, `ccache.rs` | Calls into MIT `gss_*` / `krb5_*` C functions; marshal `gss_buffer_desc`, OID sets |
| `gssproxy-interposer/*` (`creds.rs`, `names.rs`, `handle.rs`, `convert.rs`, `msgprot.rs`, `ctxlife.rs`, `special.rs`, `mechstatus.rs`) | ~125 `#[no_mangle] extern "C"` `gssi_*` entry points the mechglue calls; raw `gss_*` pointer/handle marshaling; `Box::into_raw`/`from_raw` handle round-trips |
| `gssproxy-client/src/lib.rs` | RPC client FFI glue |
| `gssproxy-proto/*` | **No FFI** - pure XDR/gssx wire codec (the one large body of self-contained, security-critical logic) |

The defining characteristic is that **most unsafe blocks are FFI calls** whose
real behavior lives in the external MIT krb5/GSSAPI C libraries. No Rust-level
tool can see across that boundary; both tools can only reason about the Rust
side (the pointer/length/lifetime contracts we must uphold *around* each call),
and about the pure Rust logic that never crosses into C.

## Tool comparison

| Criterion | Kani | Creusot |
| --- | --- | --- |
| Technique | Bit-precise bounded model checking (CBMC backend) over MIR | Deductive verification: contracts (`#[requires]`/`#[ensures]`/invariants) → Why3 → SMT |
| What it proves | No panic / no UB / no overflow / no OOB / termination, for **all** inputs within given bounds | Full functional correctness + absence of panics/overflow/UB, unbounded, relative to a spec |
| Unsafe / raw pointers | First-class; designed for unsafe Rust | Supported via linear ghost `Perm` tokens ([2026 work](https://creusot.rs)); high annotation cost |
| FFI (`extern "C"`) | **Not supported** - "call to foreign C function … is not currently supported" ([kani#2423](https://github.com/model-checking/kani/issues/2423)); needs experimental [`#[kani::stub]`](https://model-checking.github.io/kani/reference/experimental/stubbing.html) mocks | Cannot model external C behavior; foreign functions must be axiomatized as `trusted` |
| Proof authoring effort | Low - harnesses look like tests (`kani::any()`, asserts) | High - contracts + loop invariants + ghost code, per function |
| Annotation burden on prod code | None (harnesses are `#[cfg(kani)]`, separate) | Invasive - specs/ghost args woven into the code under test |
| CI integration | Turnkey [`model-checking/kani-github-action`](https://github.com/model-checking/kani-github-action), SARIF → Code Scanning | No first-class action; needs Why3 + SMT solvers (Z3/CVC5/Alt-Ergo) installed |
| Nix story | Painful: not in nixpkgs ([request closed](https://github.com/NixOS/nixpkgs/issues/394161)), nightly toolchain, downloads CBMC into `KANI_HOME`; usually run via `buildFHSEnv` or the GH Action | Also nightly-pinned + solver stack; heavier |
| Toolchain stability | Pinned Kani release; stable Rust harnesses | Tied to a specific rustc nightly |

## Decision

**Adopt Kani now, scoped to the FFI-free logic; document Creusot as future work.**

Rationale:

1. The single highest-value, self-contained target is the **gssx wire codec**
   (`gssproxy-proto`): security-critical (it parses attacker-influenced bytes off
   a socket), pure Rust, and already exercised by the chaos/property fuzzers in
   `gssproxy-proto/tests/proptest_proto.rs`. Kani upgrades those fuzz properties
   to **proofs over all bounded inputs** with near-zero authoring cost and no
   changes to production code.
2. Kani's FFI limitation is not a blocker for that target (no `gss_*` is
   reachable), and we deliberately keep harnesses on the FFI boundary out of
   scope - those invariants are documented (see below) and exercised by the
   integration suite, not model-checked, because every such harness would
   require hand-written `#[kani::stub]` mocks of the krb5/GSSAPI C surface.
3. Kani's GitHub Action makes CI trivial; the Nix friction is sidestepped by
   running Kani via the Action in CI and a `buildFHSEnv` wrapper locally
   (`nix run .#kani`), keeping it out of `nix flake check`.
4. Creusot's higher ceiling (functional-correctness proofs) does not pay for its
   invasive annotation burden here, where the dominant risk is *memory safety
   around FFI* rather than algorithmic correctness of pure functions. It is
   recorded as a future option, most plausibly for the codec's round-trip
   fidelity spec, should we want unbounded guarantees.

## What we verify with Kani

Harnesses live under `#[cfg(kani)]` (compiled only with `cargo kani`, never in
normal builds), alongside the code:

- `gssproxy-proto/src/verification.rs` - the codec:
  - XDR primitive round-trips (`u32`/`u64`/`bool`): `decode(encode(v)) == v` and
    the decoder consumes exactly the produced bytes.
  - `Opaque`/`xdr_bytes` decode over arbitrary bounded byte streams: never
    panics, never over-allocates (length is validated against remaining bytes
    before any copy), and accepted values re-encode self-consistently.
  - `frame::parse_header`/`encode_header`: the fragment-bit/size-cap contract
    holds for every 32-bit word, and every in-range body length round-trips.
- `gssproxy-interposer/src/oids.rs` (`#[cfg(kani)]`) - pure OID helpers:
  - `oid_equal` is exactly byte-equality (and reflexive).
  - `is_krb5_oid` is true iff the OID bytes are one of the four known
    krb5/iakerb OIDs.

These mirror the invariants asserted probabilistically in
`tests/proptest_proto.rs` and `oids.rs`'s `prop_tests`, but prove them
exhaustively within the input bounds.

## Running Kani

CI: the [`Kani` workflow](../../.github/workflows/kani.yaml) runs
`cargo kani` via `model-checking/kani-github-action@v1.1` (pinned to Kani
`0.67.0`) on every push/PR. The job's pass/fail status is the gate — `cargo
kani` exits non-zero if any harness fails to verify.

> Note: SARIF / GitHub Code-Scanning upload is intentionally not wired up yet.
> The `--sarif` flag is documented upstream but is only present in unreleased
> Kani `main`, not in the latest release (`0.67.0`); passing it makes
> `cargo kani` error out. Once a release ships `--sarif`, add it to the workflow
> args and re-add a `github/codeql-action/upload-sarif` step (which will need
> `permissions: security-events: write`).

Locally (Kani is not packaged in nixpkgs, so we use an FHS sandbox that installs
the pinned Kani release into a project-local `KANI_HOME` on first use):

```sh
# Enter the FHS shell with rustup/cargo/CBMC deps, then run Kani:
nix run .#kani -- -p gssproxy-proto
nix run .#kani -- -p gssproxy-interposer
```

The first invocation runs `cargo install --locked kani-verifier && cargo kani
setup`, which downloads the CBMC toolchain; subsequent runs are fast. This is
intentionally **not** part of `nix flake check` (which stays hermetic).

## Documenting unsafe invariants (`# Safety` convention)

Independent of proving, every unsafe item documents its contract:

- Every `pub unsafe fn` carries a `# Safety` doc section stating the caller's
  obligations (pointer validity, length, ownership transfer). This is already
  enforced for public items by clippy's `missing_safety_doc`, which is denied
  via the `-D warnings` clippy gate.
- Every `unsafe { ... }` block should carry a `// SAFETY:` comment explaining
  why the operation is sound at that site.

Optional follow-up (not enabled here, since it is a large mechanical change):
turn on `#![warn(clippy::undocumented_unsafe_blocks)]` workspace-wide to require
a `// SAFETY:` comment on *every* unsafe block, then backfill comments.

## Future work

- Extend Kani harnesses to more codec types (`proc::Arg*`/`Res*`) via
  `kani::Arbitrary` derives with bounded collections.
- Evaluate `#[kani::stub]` mocks for a few high-risk FFI marshalers
  (e.g. `convert::read_buffer`, handle `Box` round-trips) if memory-safety bugs
  are suspected there.
- Consider a Creusot pilot on `xdr.rs` round-trip fidelity for an unbounded
  functional-correctness proof, if the bounded Kani guarantees prove
  insufficient.
