//! Compile the C rpcgen XDR layer + a thin benchmark shim so the Criterion
//! benches can time the C codec head-to-head with the Rust `gssproxy-proto`
//! codec.
//!
//! The three rpcgen sources live at the repo root (`../../rpcgen`), outside this
//! crate's tree; that is why `gssproxy-bench` is excluded from the Rust
//! workspace and only ever built from a checkout (e.g. `nix develop .#bench`).

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // rust/gssproxy-bench -> rust -> repo root
    let repo_root = manifest
        .join("../..")
        .canonicalize()
        .expect("failed to resolve repo root from CARGO_MANIFEST_DIR");
    let rpcgen = repo_root.join("rpcgen");

    for f in ["gp_rpc_xdr.c", "gss_proxy_xdr.c", "gp_xdr.c"] {
        assert!(
            rpcgen.join(f).exists(),
            "missing rpcgen source {}; run from a full checkout",
            rpcgen.join(f).display()
        );
    }

    // krb5-gssapi supplies the gssrpc headers (gssrpc/rpc.h) and pulls in the
    // krb5/gssapi link flags. It also emits the cargo:rustc-link-lib lines.
    let krb5 = pkg_config::Config::new()
        .probe("krb5-gssapi")
        .expect("pkg-config could not find krb5-gssapi (install krb5 dev headers)");

    let mut build = cc::Build::new();
    build
        .file(rpcgen.join("gp_rpc_xdr.c"))
        .file(rpcgen.join("gss_proxy_xdr.c"))
        .file(rpcgen.join("gp_xdr.c"))
        .file("csrc/bench_shim.c")
        // rpcgen sources include "rpcgen/..." relative to the repo root.
        .include(&repo_root)
        .include(repo_root.join("include"))
        .include("csrc")
        // Keep debug info + frame pointers so pprof can unwind into the C XDR
        // functions instead of stopping at the FFI boundary.
        .debug(true)
        .flag_if_supported("-fno-omit-frame-pointer")
        .warnings(false);
    for p in &krb5.include_paths {
        build.include(p);
    }
    build.compile("gpbenchc");

    // gssrpc has no .pc file (configure.ac links it explicitly); the krb5 lib
    // dir is already on the search path from the krb5-gssapi probe.
    println!("cargo:rustc-link-lib=gssrpc");

    println!("cargo:rerun-if-changed=csrc/bench_shim.c");
    println!("cargo:rerun-if-changed=csrc/bench_shim.h");
    println!("cargo:rerun-if-changed=build.rs");
}
