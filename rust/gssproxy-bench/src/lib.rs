//! Shared helpers for the codec benchmarks: safe wrappers over the C rpcgen
//! shim ([`c`]) and matching Rust fixtures built from `gssproxy-proto` types.
//!
//! The C and Rust encoders produce the same wire body (`gp_rpc_msg` + arg), so
//! the Criterion groups in `benches/codec.rs` compare like with like.

use gssproxy_proto::gssx::Opaque;
use gssproxy_proto::proc::{ArgIndicateMechs, ArgInitSecContext, GssxProc};
use gssproxy_proto::{Message, Xdr, XdrDecoder, encode_request};

/// krb5 mech OID DER bytes (1.2.840.113554.1.2.2) - mirrors the C shim.
pub const KRB5_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";

/// A generous scratch buffer for the C encoder (it writes into caller memory).
pub const SCRATCH: usize = 2 * 1024 * 1024;

/// Safe wrappers around the C benchmark shim (`csrc/bench_shim.c`).
pub mod c {
    use std::os::raw::c_int;

    unsafe extern "C" {
        fn cbench_setup_indicate_mechs();
        fn cbench_encode_indicate_mechs(buf: *mut u8, cap: usize) -> usize;
        fn cbench_decode_indicate_mechs(buf: *const u8, len: usize) -> c_int;

        fn cbench_setup_init_sec_context(payload_len: usize);
        fn cbench_encode_init_sec_context(buf: *mut u8, cap: usize) -> usize;
        fn cbench_decode_init_sec_context(buf: *const u8, len: usize) -> c_int;
    }

    pub fn setup_indicate_mechs() {
        // SAFETY: builds file-static C state; no aliasing, single-threaded bench.
        unsafe { cbench_setup_indicate_mechs() }
    }

    /// Encode the pre-built indicate_mechs CALL into `buf`, returning its length.
    pub fn encode_indicate_mechs(buf: &mut [u8]) -> usize {
        // SAFETY: the shim writes at most `buf.len()` bytes into `buf`.
        unsafe { cbench_encode_indicate_mechs(buf.as_mut_ptr(), buf.len()) }
    }

    pub fn decode_indicate_mechs(buf: &[u8]) -> bool {
        // SAFETY: the shim only reads `buf.len()` bytes from `buf`.
        unsafe { cbench_decode_indicate_mechs(buf.as_ptr(), buf.len()) != 0 }
    }

    pub fn setup_init_sec_context(payload_len: usize) {
        // SAFETY: builds file-static C state; allocates a payload_len token.
        unsafe { cbench_setup_init_sec_context(payload_len) }
    }

    pub fn encode_init_sec_context(buf: &mut [u8]) -> usize {
        // SAFETY: the shim writes at most `buf.len()` bytes into `buf`.
        unsafe { cbench_encode_init_sec_context(buf.as_mut_ptr(), buf.len()) }
    }

    pub fn decode_init_sec_context(buf: &[u8]) -> bool {
        // SAFETY: the shim only reads `buf.len()` bytes from `buf`.
        unsafe { cbench_decode_init_sec_context(buf.as_ptr(), buf.len()) != 0 }
    }
}

/// Rust fixtures + codec, mirroring the C shim's structs via `gssproxy-proto`.
pub mod rust {
    use super::*;

    pub fn indicate_mechs_arg() -> ArgIndicateMechs {
        ArgIndicateMechs::default()
    }

    /// init_sec_context CALL arg with the krb5 mech OID and an `input_token` of
    /// `payload_len` zero bytes.
    pub fn init_sec_context_arg(payload_len: usize) -> ArgInitSecContext {
        ArgInitSecContext {
            mech_type: Opaque::new(KRB5_OID.to_vec()),
            input_token: Some(Opaque::new(vec![0u8; payload_len])),
            ..Default::default()
        }
    }

    pub fn encode_indicate_mechs(arg: &ArgIndicateMechs) -> Vec<u8> {
        encode_request(1, GssxProc::IndicateMechs as u32, arg)
    }

    pub fn encode_init_sec_context(arg: &ArgInitSecContext) -> Vec<u8> {
        encode_request(1, GssxProc::InitSecContext as u32, arg)
    }

    /// Decode a full request body (`Message` envelope + arg), matching the C
    /// `xdr_gp_rpc_msg` + `xdr_gssx_arg_*` decode path.
    pub fn decode_indicate_mechs(bytes: &[u8]) -> bool {
        let mut d = XdrDecoder::new(bytes);
        Message::decode(&mut d).is_ok() && ArgIndicateMechs::decode(&mut d).is_ok()
    }

    pub fn decode_init_sec_context(bytes: &[u8]) -> bool {
        let mut d = XdrDecoder::new(bytes);
        Message::decode(&mut d).is_ok() && ArgInitSecContext::decode(&mut d).is_ok()
    }
}
