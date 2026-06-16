//! Generate krb5 crypto/keytab bindings and link libkrb5.
//!
//! `libgssapi-sys` only binds the gssapi headers, but the credential sealing
//! layer (a port of `src/gp_export.c`) needs the low-level krb5 crypto and
//! keytab API. We generate a tight, allowlisted binding for just those symbols.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=krb5_wrapper.h");

    // Locate krb5 (include path + link flags) via pkg-config; this also emits
    // the cargo:rustc-link-lib lines needed to resolve krb5_c_* / krb5_kt_*.
    let lib = pkg_config::Config::new()
        .probe("krb5")
        .expect("pkg-config could not find krb5");

    let mut builder = bindgen::Builder::default()
        .header("krb5_wrapper.h")
        .allowlist_function("krb5_init_context")
        .allowlist_function("krb5_free_context")
        .allowlist_function("krb5_kt_resolve")
        .allowlist_function("krb5_kt_default")
        .allowlist_function("krb5_kt_default_name")
        .allowlist_function("krb5_kt_have_content")
        .allowlist_function("krb5_kt_close")
        .allowlist_function("krb5_kt_start_seq_get")
        .allowlist_function("krb5_kt_next_entry")
        .allowlist_function("krb5_kt_end_seq_get")
        .allowlist_function("krb5_free_keytab_entry_contents")
        .allowlist_function("krb5_get_permitted_enctypes")
        .allowlist_function("krb5_free_enctypes")
        .allowlist_function("krb5_copy_keyblock")
        .allowlist_function("krb5_free_keyblock")
        .allowlist_function("krb5_init_keyblock")
        .allowlist_function("krb5_c_make_random_key")
        .allowlist_function("krb5_c_encrypt_length")
        .allowlist_function("krb5_c_encrypt")
        .allowlist_function("krb5_c_decrypt")
        .allowlist_type("krb5_keyblock")
        .allowlist_type("krb5_data")
        .allowlist_type("krb5_enc_data")
        .allowlist_type("krb5_keytab_entry")
        .allowlist_type("krb5_context")
        .allowlist_type("krb5_keytab")
        .allowlist_type("krb5_kt_cursor")
        .allowlist_type("krb5_enctype")
        .allowlist_type("krb5_error_code")
        .allowlist_var("ENCTYPE_AES256_CTS_HMAC_SHA1_96")
        .allowlist_var("KRB5_KEYUSAGE_APP_DATA_ENCRYPT")
        .allowlist_var("KRB5_KT_END")
        .allowlist_var("KRB5_WRONG_ETYPE")
        .allowlist_var("MAX_KEYTAB_NAME_LEN")
        .layout_tests(false)
        .generate_comments(false);

    for path in &lib.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }

    let bindings = builder.generate().expect("failed to generate krb5 bindings");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out.join("krb5_bindings.rs"))
        .expect("failed to write krb5 bindings");
}
