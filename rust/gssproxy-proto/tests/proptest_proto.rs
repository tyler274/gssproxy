//! Property-based and "chaos" fuzz tests for the gssx wire codec.
//!
//! These use `proptest` to validate two classes of invariant against the
//! hand-ported C behaviour:
//!
//!   1. Round-trip fidelity: for every `gssx_*` type and every `gssx_arg_*` /
//!      `gssx_res_*` procedure, `decode(encode(v)) == v` and the decoder
//!      consumes exactly the bytes the encoder produced. This is what
//!      guarantees the Rust codec stays byte-compatible with rpcgen's
//!      `xdr_gssx_*`.
//!
//!   2. Robustness on hostile input: decoding arbitrary / truncated / biased
//!      byte streams must never panic, never over-allocate, and never hang
//!      (matching the C `xdrmem_*` routines which fail cleanly on short or
//!      corrupt buffers). When a decode happens to succeed, re-encoding it
//!      must reproduce a canonical, self-consistent buffer.

use gssproxy_proto::frame::{FrameError, encode_header, parse_header};
use gssproxy_proto::gssx::*;
use gssproxy_proto::proc::*;
use gssproxy_proto::rpc::{
    CallHeader, FRAGMENT_BIT, MAX_RPC_SIZE, Message, MismatchInfo, OpaqueAuth, ReplyBody,
};
use gssproxy_proto::xdr::{Xdr, XdrDecoder, XdrEncoder};
use proptest::prelude::*;

// Keep generated structures small but non-trivial so the test matrix stays
// fast while still exercising arrays, optionals and padding.
const MAXB: usize = 16; // opaque/string byte cap
const MAXV: usize = 2; // array/element cap

// ---- leaf + shared gssx strategies -----------------------------------------

fn opaque() -> impl Strategy<Value = Opaque> {
    prop::collection::vec(any::<u8>(), 0..=MAXB).prop_map(Opaque)
}

fn oid_set() -> impl Strategy<Value = Vec<Opaque>> {
    prop::collection::vec(opaque(), 0..=MAXV)
}

fn option() -> impl Strategy<Value = GssxOption> {
    (opaque(), opaque()).prop_map(|(option, value)| GssxOption { option, value })
}

fn options() -> impl Strategy<Value = Vec<GssxOption>> {
    prop::collection::vec(option(), 0..=MAXV)
}

fn name_attr() -> impl Strategy<Value = GssxNameAttr> {
    (opaque(), opaque(), options()).prop_map(|(attr, value, extensions)| GssxNameAttr {
        attr,
        value,
        extensions,
    })
}

fn name() -> impl Strategy<Value = GssxName> {
    (
        opaque(),
        opaque(),
        opaque(),
        opaque(),
        prop::collection::vec(name_attr(), 0..=MAXV),
        options(),
    )
        .prop_map(
            |(
                display_name,
                name_type,
                exported_name,
                exported_composite_name,
                name_attributes,
                extensions,
            )| {
                GssxName {
                    display_name,
                    name_type,
                    exported_name,
                    exported_composite_name,
                    name_attributes,
                    extensions,
                }
            },
        )
}

fn status() -> impl Strategy<Value = GssxStatus> {
    (
        any::<u64>(),
        opaque(),
        any::<u64>(),
        opaque(),
        opaque(),
        opaque(),
        options(),
    )
        .prop_map(
            |(
                major_status,
                mech,
                minor_status,
                major_status_string,
                minor_status_string,
                server_ctx,
                options,
            )| GssxStatus {
                major_status,
                mech,
                minor_status,
                major_status_string,
                minor_status_string,
                server_ctx,
                options,
            },
        )
}

fn call_ctx() -> impl Strategy<Value = GssxCallCtx> {
    (opaque(), opaque(), options()).prop_map(|(locale, server_ctx, options)| GssxCallCtx {
        locale,
        server_ctx,
        options,
    })
}

fn cb() -> impl Strategy<Value = GssxCb> {
    (any::<u64>(), opaque(), any::<u64>(), opaque(), opaque()).prop_map(
        |(
            initiator_addrtype,
            initiator_address,
            acceptor_addrtype,
            acceptor_address,
            application_data,
        )| {
            GssxCb {
                initiator_addrtype,
                initiator_address,
                acceptor_addrtype,
                acceptor_address,
                application_data,
            }
        },
    )
}

fn ctx() -> impl Strategy<Value = GssxCtx> {
    (
        (opaque(), opaque(), any::<bool>(), opaque(), name()),
        (
            name(),
            any::<u64>(),
            any::<u64>(),
            any::<bool>(),
            any::<bool>(),
            options(),
        ),
    )
        .prop_map(
            |(
                (exported_context_token, state, needs_release, mech, src_name),
                (targ_name, lifetime, ctx_flags, locally_initiated, open, options),
            )| GssxCtx {
                exported_context_token,
                state,
                needs_release,
                mech,
                src_name,
                targ_name,
                lifetime,
                ctx_flags,
                locally_initiated,
                open,
                options,
            },
        )
}

fn cred_element() -> impl Strategy<Value = GssxCredElement> {
    (
        name(),
        opaque(),
        any::<i32>(),
        any::<u64>(),
        any::<u64>(),
        options(),
    )
        .prop_map(
            |(mn, mech, cred_usage, initiator_time_rec, acceptor_time_rec, options)| {
                GssxCredElement {
                    mn,
                    mech,
                    cred_usage,
                    initiator_time_rec,
                    acceptor_time_rec,
                    options,
                }
            },
        )
}

fn cred() -> impl Strategy<Value = GssxCred> {
    (
        name(),
        prop::collection::vec(cred_element(), 0..=MAXV),
        opaque(),
        any::<bool>(),
    )
        .prop_map(
            |(desired_name, elements, cred_handle_reference, needs_release)| GssxCred {
                desired_name,
                elements,
                cred_handle_reference,
                needs_release,
            },
        )
}

fn handle() -> impl Strategy<Value = GssxHandle> {
    prop_oneof![
        ctx().prop_map(GssxHandle::SecCtx),
        cred().prop_map(GssxHandle::Cred),
        // Any discriminant other than the two known union arms decodes back to
        // the opaque `Extensions` variant, so exclude 0/1 to keep round-trip.
        (
            any::<i32>().prop_filter("not a known handle discriminant", |t| *t != 0 && *t != 1),
            opaque()
        )
            .prop_map(|(handle_type, data)| GssxHandle::Extensions { handle_type, data }),
    ]
}

fn mech_attr() -> impl Strategy<Value = GssxMechAttr> {
    (opaque(), opaque(), opaque(), opaque(), options()).prop_map(
        |(attr, name, short_desc, long_desc, extensions)| GssxMechAttr {
            attr,
            name,
            short_desc,
            long_desc,
            extensions,
        },
    )
}

fn mech_info() -> impl Strategy<Value = GssxMechInfo> {
    (
        (opaque(), oid_set(), oid_set(), oid_set(), oid_set()),
        (oid_set(), opaque(), opaque(), opaque(), options()),
    )
        .prop_map(
            |(
                (mech, name_types, mech_attrs, known_mech_attrs, cred_options),
                (
                    sec_ctx_options,
                    saslname_sasl_mech_name,
                    saslname_mech_name,
                    saslname_mech_desc,
                    extensions,
                ),
            )| GssxMechInfo {
                mech,
                name_types,
                mech_attrs,
                known_mech_attrs,
                cred_options,
                sec_ctx_options,
                saslname_sasl_mech_name,
                saslname_mech_name,
                saslname_mech_desc,
                extensions,
            },
        )
}

// ---- per-procedure strategies ----------------------------------------------

fn arg_release_handle() -> impl Strategy<Value = ArgReleaseHandle> {
    (call_ctx(), handle()).prop_map(|(call_ctx, cred_handle)| ArgReleaseHandle {
        call_ctx,
        cred_handle,
    })
}

fn res_release_handle() -> impl Strategy<Value = ResReleaseHandle> {
    status().prop_map(|status| ResReleaseHandle { status })
}

fn arg_indicate_mechs() -> impl Strategy<Value = ArgIndicateMechs> {
    call_ctx().prop_map(|call_ctx| ArgIndicateMechs { call_ctx })
}

fn res_indicate_mechs() -> impl Strategy<Value = ResIndicateMechs> {
    (
        status(),
        prop::collection::vec(mech_info(), 0..=MAXV),
        prop::collection::vec(mech_attr(), 0..=MAXV),
        prop::collection::vec(opaque(), 0..=MAXV),
        options(),
    )
        .prop_map(
            |(status, mechs, mech_attr_descs, supported_extensions, options)| ResIndicateMechs {
                status,
                mechs,
                mech_attr_descs,
                supported_extensions,
                options,
            },
        )
}

fn arg_import_canon() -> impl Strategy<Value = ArgImportAndCanonName> {
    (
        call_ctx(),
        name(),
        opaque(),
        prop::collection::vec(name_attr(), 0..=MAXV),
        options(),
    )
        .prop_map(|(call_ctx, input_name, mech, name_attributes, options)| {
            ArgImportAndCanonName {
                call_ctx,
                input_name,
                mech,
                name_attributes,
                options,
            }
        })
}

fn res_import_canon() -> impl Strategy<Value = ResImportAndCanonName> {
    (status(), prop::option::of(name()), options()).prop_map(|(status, output_name, options)| {
        ResImportAndCanonName {
            status,
            output_name,
            options,
        }
    })
}

fn arg_get_call_context() -> impl Strategy<Value = ArgGetCallContext> {
    (call_ctx(), options()).prop_map(|(call_ctx, options)| ArgGetCallContext { call_ctx, options })
}

fn res_get_call_context() -> impl Strategy<Value = ResGetCallContext> {
    (status(), opaque(), options()).prop_map(|(status, server_call_ctx, options)| {
        ResGetCallContext {
            status,
            server_call_ctx,
            options,
        }
    })
}

fn arg_acquire_cred() -> impl Strategy<Value = ArgAcquireCred> {
    (
        (
            call_ctx(),
            prop::option::of(cred()),
            any::<bool>(),
            prop::option::of(name()),
            any::<u64>(),
        ),
        (
            oid_set(),
            any::<i32>(),
            any::<u64>(),
            any::<u64>(),
            options(),
        ),
    )
        .prop_map(
            |(
                (call_ctx, input_cred_handle, add_cred_to_input_handle, desired_name, time_req),
                (desired_mechs, cred_usage, initiator_time_req, acceptor_time_req, options),
            )| ArgAcquireCred {
                call_ctx,
                input_cred_handle,
                add_cred_to_input_handle,
                desired_name,
                time_req,
                desired_mechs,
                cred_usage,
                initiator_time_req,
                acceptor_time_req,
                options,
            },
        )
}

fn res_acquire_cred() -> impl Strategy<Value = ResAcquireCred> {
    (status(), prop::option::of(cred()), options()).prop_map(
        |(status, output_cred_handle, options)| ResAcquireCred {
            status,
            output_cred_handle,
            options,
        },
    )
}

fn arg_export_cred() -> impl Strategy<Value = ArgExportCred> {
    (call_ctx(), cred(), any::<i32>(), options()).prop_map(
        |(call_ctx, input_cred_handle, cred_usage, options)| ArgExportCred {
            call_ctx,
            input_cred_handle,
            cred_usage,
            options,
        },
    )
}

fn res_export_cred() -> impl Strategy<Value = ResExportCred> {
    (
        status(),
        any::<i32>(),
        prop::option::of(opaque()),
        options(),
    )
        .prop_map(
            |(status, usage_exported, exported_handle, options)| ResExportCred {
                status,
                usage_exported,
                exported_handle,
                options,
            },
        )
}

fn arg_import_cred() -> impl Strategy<Value = ArgImportCred> {
    (call_ctx(), opaque(), options()).prop_map(|(call_ctx, exported_handle, options)| {
        ArgImportCred {
            call_ctx,
            exported_handle,
            options,
        }
    })
}

fn res_import_cred() -> impl Strategy<Value = ResImportCred> {
    (status(), prop::option::of(cred()), options()).prop_map(
        |(status, output_cred_handle, options)| ResImportCred {
            status,
            output_cred_handle,
            options,
        },
    )
}

fn arg_store_cred() -> impl Strategy<Value = ArgStoreCred> {
    (
        call_ctx(),
        cred(),
        any::<i32>(),
        opaque(),
        any::<bool>(),
        any::<bool>(),
        options(),
    )
        .prop_map(
            |(
                call_ctx,
                input_cred_handle,
                cred_usage,
                desired_mech,
                overwrite_cred,
                default_cred,
                options,
            )| {
                ArgStoreCred {
                    call_ctx,
                    input_cred_handle,
                    cred_usage,
                    desired_mech,
                    overwrite_cred,
                    default_cred,
                    options,
                }
            },
        )
}

fn res_store_cred() -> impl Strategy<Value = ResStoreCred> {
    (status(), oid_set(), any::<i32>(), options()).prop_map(
        |(status, elements_stored, cred_usage_stored, options)| ResStoreCred {
            status,
            elements_stored,
            cred_usage_stored,
            options,
        },
    )
}

fn arg_init_sec_context() -> impl Strategy<Value = ArgInitSecContext> {
    (
        (
            call_ctx(),
            prop::option::of(ctx()),
            prop::option::of(cred()),
            prop::option::of(name()),
            opaque(),
        ),
        (
            any::<u64>(),
            any::<u64>(),
            prop::option::of(cb()),
            prop::option::of(opaque()),
            options(),
        ),
    )
        .prop_map(
            |(
                (call_ctx, context_handle, cred_handle, target_name, mech_type),
                (req_flags, time_req, input_cb, input_token, options),
            )| ArgInitSecContext {
                call_ctx,
                context_handle,
                cred_handle,
                target_name,
                mech_type,
                req_flags,
                time_req,
                input_cb,
                input_token,
                options,
            },
        )
}

fn res_init_sec_context() -> impl Strategy<Value = ResInitSecContext> {
    (
        status(),
        prop::option::of(ctx()),
        prop::option::of(opaque()),
        options(),
    )
        .prop_map(
            |(status, context_handle, output_token, options)| ResInitSecContext {
                status,
                context_handle,
                output_token,
                options,
            },
        )
}

fn arg_accept_sec_context() -> impl Strategy<Value = ArgAcceptSecContext> {
    (
        call_ctx(),
        prop::option::of(ctx()),
        prop::option::of(cred()),
        opaque(),
        prop::option::of(cb()),
        any::<bool>(),
        options(),
    )
        .prop_map(
            |(
                call_ctx,
                context_handle,
                cred_handle,
                input_token,
                input_cb,
                ret_deleg_cred,
                options,
            )| {
                ArgAcceptSecContext {
                    call_ctx,
                    context_handle,
                    cred_handle,
                    input_token,
                    input_cb,
                    ret_deleg_cred,
                    options,
                }
            },
        )
}

fn res_accept_sec_context() -> impl Strategy<Value = ResAcceptSecContext> {
    (
        status(),
        prop::option::of(ctx()),
        prop::option::of(opaque()),
        prop::option::of(cred()),
        options(),
    )
        .prop_map(
            |(status, context_handle, output_token, delegated_cred_handle, options)| {
                ResAcceptSecContext {
                    status,
                    context_handle,
                    output_token,
                    delegated_cred_handle,
                    options,
                }
            },
        )
}

fn arg_get_mic() -> impl Strategy<Value = ArgGetMic> {
    (call_ctx(), ctx(), any::<u64>(), opaque()).prop_map(
        |(call_ctx, context_handle, qop_req, message_buffer)| ArgGetMic {
            call_ctx,
            context_handle,
            qop_req,
            message_buffer,
        },
    )
}

fn res_get_mic() -> impl Strategy<Value = ResGetMic> {
    (
        status(),
        prop::option::of(ctx()),
        opaque(),
        prop::option::of(any::<u64>()),
    )
        .prop_map(
            |(status, context_handle, token_buffer, qop_state)| ResGetMic {
                status,
                context_handle,
                token_buffer,
                qop_state,
            },
        )
}

fn arg_verify_mic() -> impl Strategy<Value = ArgVerifyMic> {
    (call_ctx(), ctx(), opaque(), opaque()).prop_map(
        |(call_ctx, context_handle, message_buffer, token_buffer)| ArgVerifyMic {
            call_ctx,
            context_handle,
            message_buffer,
            token_buffer,
        },
    )
}

fn res_verify_mic() -> impl Strategy<Value = ResVerifyMic> {
    (
        status(),
        prop::option::of(ctx()),
        prop::option::of(any::<u64>()),
    )
        .prop_map(|(status, context_handle, qop_state)| ResVerifyMic {
            status,
            context_handle,
            qop_state,
        })
}

fn arg_wrap() -> impl Strategy<Value = ArgWrap> {
    (
        call_ctx(),
        ctx(),
        any::<bool>(),
        prop::collection::vec(opaque(), 0..=MAXV),
        any::<u64>(),
    )
        .prop_map(
            |(call_ctx, context_handle, conf_req, message_buffer, qop_state)| ArgWrap {
                call_ctx,
                context_handle,
                conf_req,
                message_buffer,
                qop_state,
            },
        )
}

fn res_wrap() -> impl Strategy<Value = ResWrap> {
    (
        status(),
        prop::option::of(ctx()),
        prop::collection::vec(opaque(), 0..=MAXV),
        prop::option::of(any::<bool>()),
        prop::option::of(any::<u64>()),
    )
        .prop_map(
            |(status, context_handle, token_buffer, conf_state, qop_state)| ResWrap {
                status,
                context_handle,
                token_buffer,
                conf_state,
                qop_state,
            },
        )
}

fn arg_unwrap() -> impl Strategy<Value = ArgUnwrap> {
    (
        call_ctx(),
        ctx(),
        prop::collection::vec(opaque(), 0..=MAXV),
        any::<u64>(),
    )
        .prop_map(
            |(call_ctx, context_handle, token_buffer, qop_state)| ArgUnwrap {
                call_ctx,
                context_handle,
                token_buffer,
                qop_state,
            },
        )
}

fn res_unwrap() -> impl Strategy<Value = ResUnwrap> {
    (
        status(),
        prop::option::of(ctx()),
        prop::collection::vec(opaque(), 0..=MAXV),
        prop::option::of(any::<bool>()),
        prop::option::of(any::<u64>()),
    )
        .prop_map(
            |(status, context_handle, message_buffer, conf_state, qop_state)| ResUnwrap {
                status,
                context_handle,
                message_buffer,
                conf_state,
                qop_state,
            },
        )
}

fn arg_wrap_size_limit() -> impl Strategy<Value = ArgWrapSizeLimit> {
    (call_ctx(), ctx(), any::<bool>(), any::<u64>(), any::<u64>()).prop_map(
        |(call_ctx, context_handle, conf_req, qop_state, req_output_size)| ArgWrapSizeLimit {
            call_ctx,
            context_handle,
            conf_req,
            qop_state,
            req_output_size,
        },
    )
}

fn res_wrap_size_limit() -> impl Strategy<Value = ResWrapSizeLimit> {
    (status(), any::<u64>()).prop_map(|(status, max_input_size)| ResWrapSizeLimit {
        status,
        max_input_size,
    })
}

// ---- RPC envelope strategies ------------------------------------------------

fn opaque_auth() -> impl Strategy<Value = OpaqueAuth> {
    (
        prop_oneof![Just(0i32), Just(1), Just(2), Just(3), Just(6)],
        prop::collection::vec(any::<u8>(), 0..=MAXB),
    )
        .prop_map(|(flavor, body)| OpaqueAuth { flavor, body })
}

fn call_header() -> impl Strategy<Value = CallHeader> {
    (
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        opaque_auth(),
        opaque_auth(),
    )
        .prop_map(|(rpcvers, prog, vers, proc_num, cred, verf)| CallHeader {
            rpcvers,
            prog,
            vers,
            proc_num,
            cred,
            verf,
        })
}

fn reply_body() -> impl Strategy<Value = ReplyBody> {
    prop_oneof![
        opaque_auth().prop_map(|verf| ReplyBody::AcceptedSuccess { verf }),
        (opaque_auth(), any::<u32>(), any::<u32>()).prop_map(|(verf, low, high)| {
            ReplyBody::ProgMismatch {
                verf,
                info: MismatchInfo { low, high },
            }
        }),
        (
            opaque_auth(),
            any::<i32>().prop_filter("not success/mismatch", |s| *s != 0 && *s != 2)
        )
            .prop_map(|(verf, status)| ReplyBody::AcceptedOther { verf, status }),
        (any::<i32>(), any::<i32>()).prop_map(|(reject_status, value)| ReplyBody::Denied {
            reject_status,
            value
        }),
    ]
}

fn message() -> impl Strategy<Value = Message> {
    prop_oneof![
        (any::<u32>(), call_header()).prop_map(|(xid, ch)| Message {
            xid,
            is_call: true,
            call: Some(ch),
            reply: None,
        }),
        (any::<u32>(), reply_body()).prop_map(|(xid, rb)| Message {
            xid,
            is_call: false,
            call: None,
            reply: Some(rb),
        }),
    ]
}

// ---- helpers ---------------------------------------------------------------

/// Assert the full encode/decode round-trip for a single value, including that
/// the decoder consumes exactly the produced bytes (no over/under-read).
fn rt<T: Xdr + PartialEq + std::fmt::Debug>(v: T) {
    let mut e = XdrEncoder::new();
    v.encode(&mut e);
    let bytes = e.into_bytes();
    let mut d = XdrDecoder::new(&bytes);
    let got = T::decode(&mut d).expect("decode of self-encoded value must succeed");
    assert_eq!(got, v, "round-trip changed the value");
    assert_eq!(
        d.remaining(),
        0,
        "decoder left {} trailing bytes after a self-encoded value",
        d.remaining()
    );
}

/// Decode arbitrary bytes as `T`. Must never panic. When decode succeeds, the
/// canonical re-encoding must decode back to an identical value and be fully
/// consumed (idempotence of decode∘encode).
fn fuzz_decode<T: Xdr + PartialEq + std::fmt::Debug>(bytes: &[u8]) {
    let mut d = XdrDecoder::new(bytes);
    if let Ok(v1) = T::decode(&mut d) {
        let mut e = XdrEncoder::new();
        v1.encode(&mut e);
        let b2 = e.into_bytes();
        let mut d2 = XdrDecoder::new(&b2);
        let v2 = T::decode(&mut d2).expect("re-decode of canonical encoding must succeed");
        assert_eq!(v1, v2, "decode/encode is not idempotent");
        assert_eq!(d2.remaining(), 0, "canonical re-encode left trailing bytes");
    }
}

/// Same robustness contract for the RPC envelope, which is not an `Xdr` impl.
fn fuzz_message(bytes: &[u8]) {
    let mut d = XdrDecoder::new(bytes);
    if let Ok(v1) = Message::decode(&mut d) {
        let consumed = d.position();
        let mut e = XdrEncoder::new();
        v1.encode(&mut e);
        let b2 = e.into_bytes();
        assert_eq!(
            b2.len(),
            consumed,
            "envelope re-encode length differs from consumed length: {v1:?}"
        );
        let mut d2 = XdrDecoder::new(&b2);
        let v2 = Message::decode(&mut d2).expect("re-decode of envelope must succeed");
        assert_eq!(v1, v2, "envelope decode/encode is not idempotent");
        assert_eq!(d2.position(), b2.len());
    }
}

/// Byte stream of 4-byte big-endian words biased toward small values, so that
/// length/count/bool/enum discriminants are frequently in range and the fuzzer
/// reaches deep into nested decoders instead of bailing at the first word.
fn fuzzy_words() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop_oneof![
            6 => 0u32..6u32,
            2 => 0u32..256u32,
            1 => any::<u32>(),
        ],
        0..96usize,
    )
    .prop_map(|words| {
        let mut b = Vec::with_capacity(words.len() * 4);
        for w in words {
            b.extend_from_slice(&w.to_be_bytes());
        }
        b
    })
}

// ---- round-trip property tests ---------------------------------------------

macro_rules! roundtrip_tests {
    ($($name:ident => $strat:expr_2021;)*) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]
            $(
                #[test]
                fn $name(v in $strat) {
                    rt(v);
                }
            )*
        }
    };
}

roundtrip_tests! {
    rt_opaque              => opaque();
    rt_option             => option();
    rt_name_attr          => name_attr();
    rt_name               => name();
    rt_status             => status();
    rt_call_ctx           => call_ctx();
    rt_cb                 => cb();
    rt_ctx                => ctx();
    rt_cred_element       => cred_element();
    rt_cred               => cred();
    rt_handle             => handle();
    rt_mech_attr          => mech_attr();
    rt_mech_info          => mech_info();
    rt_arg_release_handle => arg_release_handle();
    rt_res_release_handle => res_release_handle();
    rt_arg_indicate_mechs => arg_indicate_mechs();
    rt_res_indicate_mechs => res_indicate_mechs();
    rt_arg_import_canon   => arg_import_canon();
    rt_res_import_canon   => res_import_canon();
    rt_arg_get_callctx    => arg_get_call_context();
    rt_res_get_callctx    => res_get_call_context();
    rt_arg_acquire_cred   => arg_acquire_cred();
    rt_res_acquire_cred   => res_acquire_cred();
    rt_arg_export_cred    => arg_export_cred();
    rt_res_export_cred    => res_export_cred();
    rt_arg_import_cred    => arg_import_cred();
    rt_res_import_cred    => res_import_cred();
    rt_arg_store_cred     => arg_store_cred();
    rt_res_store_cred     => res_store_cred();
    rt_arg_init_sec_ctx   => arg_init_sec_context();
    rt_res_init_sec_ctx   => res_init_sec_context();
    rt_arg_accept_sec_ctx => arg_accept_sec_context();
    rt_res_accept_sec_ctx => res_accept_sec_context();
    rt_arg_get_mic        => arg_get_mic();
    rt_res_get_mic        => res_get_mic();
    rt_arg_verify_mic     => arg_verify_mic();
    rt_res_verify_mic     => res_verify_mic();
    rt_arg_wrap           => arg_wrap();
    rt_res_wrap           => res_wrap();
    rt_arg_unwrap         => arg_unwrap();
    rt_res_unwrap         => res_unwrap();
    rt_arg_wrap_size      => arg_wrap_size_limit();
    rt_res_wrap_size      => res_wrap_size_limit();
    rt_opaque_auth        => opaque_auth();
    rt_call_header        => call_header();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// The RPC envelope (`Message`) uses inherent encode/decode rather than the
    /// `Xdr` trait, so it gets its own round-trip property.
    #[test]
    fn rt_message(m in message()) {
        let mut e = XdrEncoder::new();
        m.encode(&mut e);
        let bytes = e.into_bytes();
        let mut d = XdrDecoder::new(&bytes);
        let got = Message::decode(&mut d).expect("decode of self-encoded message must succeed");
        prop_assert_eq!(got, m);
        prop_assert_eq!(d.remaining(), 0);
    }
}

// ---- chaos / robustness tests ----------------------------------------------

/// Run every top-level decoder over the same hostile byte stream and assert the
/// no-panic + idempotence contract for each.
fn fuzz_all(bytes: &[u8]) {
    // Primitives + shared gssx types.
    fuzz_decode::<Opaque>(bytes);
    fuzz_decode::<GssxOption>(bytes);
    fuzz_decode::<GssxNameAttr>(bytes);
    fuzz_decode::<GssxName>(bytes);
    fuzz_decode::<GssxStatus>(bytes);
    fuzz_decode::<GssxCallCtx>(bytes);
    fuzz_decode::<GssxCb>(bytes);
    fuzz_decode::<GssxCtx>(bytes);
    fuzz_decode::<GssxCredElement>(bytes);
    fuzz_decode::<GssxCred>(bytes);
    fuzz_decode::<GssxHandle>(bytes);
    fuzz_decode::<GssxMechAttr>(bytes);
    fuzz_decode::<GssxMechInfo>(bytes);
    // RPC envelope pieces.
    fuzz_decode::<OpaqueAuth>(bytes);
    fuzz_decode::<CallHeader>(bytes);
    fuzz_message(bytes);
    // Every procedure arg/res.
    fuzz_decode::<ArgReleaseHandle>(bytes);
    fuzz_decode::<ResReleaseHandle>(bytes);
    fuzz_decode::<ArgIndicateMechs>(bytes);
    fuzz_decode::<ResIndicateMechs>(bytes);
    fuzz_decode::<ArgImportAndCanonName>(bytes);
    fuzz_decode::<ResImportAndCanonName>(bytes);
    fuzz_decode::<ArgGetCallContext>(bytes);
    fuzz_decode::<ResGetCallContext>(bytes);
    fuzz_decode::<ArgAcquireCred>(bytes);
    fuzz_decode::<ResAcquireCred>(bytes);
    fuzz_decode::<ArgExportCred>(bytes);
    fuzz_decode::<ResExportCred>(bytes);
    fuzz_decode::<ArgImportCred>(bytes);
    fuzz_decode::<ResImportCred>(bytes);
    fuzz_decode::<ArgStoreCred>(bytes);
    fuzz_decode::<ResStoreCred>(bytes);
    fuzz_decode::<ArgInitSecContext>(bytes);
    fuzz_decode::<ResInitSecContext>(bytes);
    fuzz_decode::<ArgAcceptSecContext>(bytes);
    fuzz_decode::<ResAcceptSecContext>(bytes);
    fuzz_decode::<ArgGetMic>(bytes);
    fuzz_decode::<ResGetMic>(bytes);
    fuzz_decode::<ArgVerifyMic>(bytes);
    fuzz_decode::<ResVerifyMic>(bytes);
    fuzz_decode::<ArgWrap>(bytes);
    fuzz_decode::<ResWrap>(bytes);
    fuzz_decode::<ArgUnwrap>(bytes);
    fuzz_decode::<ResUnwrap>(bytes);
    fuzz_decode::<ArgWrapSizeLimit>(bytes);
    fuzz_decode::<ResWrapSizeLimit>(bytes);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// Structured-random (word-aligned, small-biased) bytes never break any
    /// decoder and round-trip when accepted.
    #[test]
    fn biased_bytes_never_panic(bytes in fuzzy_words()) {
        fuzz_all(&bytes);
    }

    /// Fully unstructured bytes (including non-aligned lengths) never break any
    /// decoder either.
    #[test]
    fn raw_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        fuzz_all(&bytes);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every truncation of a valid encoding decodes cleanly (Ok/Err, no panic),
    /// mirroring partial reads off the socket.
    #[test]
    fn truncated_encodings_never_panic(a in arg_init_sec_context(), m in message()) {
        let mut e = XdrEncoder::new();
        a.encode(&mut e);
        let b = e.into_bytes();
        for cut in 0..=b.len() {
            let mut d = XdrDecoder::new(&b[..cut]);
            let _ = ArgInitSecContext::decode(&mut d);
        }

        let mut e2 = XdrEncoder::new();
        m.encode(&mut e2);
        let b2 = e2.into_bytes();
        for cut in 0..=b2.len() {
            let mut d = XdrDecoder::new(&b2[..cut]);
            let _ = Message::decode(&mut d);
        }
    }

    /// A valid encoding with arbitrary trailing garbage still decodes to the
    /// original value and reports the correct number of consumed bytes.
    #[test]
    fn trailing_garbage_is_ignored(a in arg_wrap(), tail in prop::collection::vec(any::<u8>(), 0..32)) {
        let mut e = XdrEncoder::new();
        a.encode(&mut e);
        let n = e.position();
        let mut bytes = e.into_bytes();
        bytes.extend_from_slice(&tail);
        let mut d = XdrDecoder::new(&bytes);
        let got = ArgWrap::decode(&mut d).expect("valid prefix must decode");
        prop_assert_eq!(got, a);
        prop_assert_eq!(d.position(), n);
    }
}

// ---- framing fuzz ----------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// `parse_header` accepts/rejects exactly per the record-marking rules and
    /// never panics for any 32-bit word.
    #[test]
    fn parse_header_matches_rules(word in any::<u32>()) {
        match parse_header(word) {
            Ok(len) => {
                prop_assert!(word & FRAGMENT_BIT != 0);
                prop_assert!(len <= MAX_RPC_SIZE);
                prop_assert_eq!(len as u32, word & !FRAGMENT_BIT);
            }
            Err(FrameError::MultiFragment) => {
                prop_assert_eq!(word & FRAGMENT_BIT, 0);
            }
            Err(FrameError::TooLarge(n)) => {
                prop_assert!(word & FRAGMENT_BIT != 0);
                prop_assert!(n > MAX_RPC_SIZE);
            }
        }
    }

    /// Header encode/parse round-trips for every in-range body length.
    #[test]
    fn header_roundtrip_in_range(len in 0usize..=MAX_RPC_SIZE) {
        let word = u32::from_be_bytes(encode_header(len));
        prop_assert_eq!(parse_header(word).expect("in-range length must parse"), len);
    }
}
