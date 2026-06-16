//! `gssproxy-proto`: a byte-exact, dependency-free implementation of the
//! gssproxy (gssx) wire protocol.
//!
//! This is a hand-written port of the rpcgen output (`rpcgen/gp_xdr.c`,
//! `rpcgen/gp_rpc_xdr.c`, `rpcgen/gss_proxy_xdr.c`). It is hand-written on
//! purpose: the available Rust XDR generators (`xdr-codec`, `xdrgen`) are
//! unmaintained and cannot parse the NFSv4-style `.x` specs this protocol is
//! derived from, so we mirror the C field order directly instead.
//!
//! Layers:
//!   - [`xdr`]: primitive XDR encode/decode and the [`xdr::Xdr`] trait.
//!   - [`rpc`]: the SunRPC message envelope (`gp_rpc_msg`).
//!   - [`frame`]: SunRPC record-marking framing used on the Unix socket.
//!   - [`gssx`]: the shared `gssx_*` data types.
//!   - [`proc`]: per-procedure `gssx_arg_*`/`gssx_res_*` types + proc numbers.
//!
//! A full request on the wire is: `frame(rpc_call_header ++ xdr(arg))`, and the
//! reply is `frame(rpc_reply_header ++ xdr(res))`.

pub mod frame;
pub mod gssx;
pub mod proc;
pub mod rpc;
pub mod xdr;

pub use frame::{frame, parse_header, FrameError};
pub use rpc::{Message, GSSPROXY, GSSPROXYVERS, MAX_RPC_SIZE};
pub use xdr::{Xdr, XdrDecoder, XdrEncoder, XdrError, XdrResult};

/// Encode a complete client request body (RPC call header + procedure args)
/// ready to be wrapped by [`frame`].
pub fn encode_request<A: Xdr>(xid: u32, proc_num: u32, arg: &A) -> Vec<u8> {
    let mut e = XdrEncoder::new();
    Message::call(xid, proc_num).encode(&mut e);
    arg.encode(&mut e);
    e.into_bytes()
}

/// Encode a complete successful reply body (RPC reply header + procedure
/// result) ready to be wrapped by [`frame`].
pub fn encode_reply<R: Xdr>(xid: u32, res: &R) -> Vec<u8> {
    let mut e = XdrEncoder::new();
    Message::reply_success(xid).encode(&mut e);
    res.encode(&mut e);
    e.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc::{ArgIndicateMechs, ArgInitSecContext, ResInitSecContext};

    #[test]
    fn request_envelope_then_arg() {
        let arg = ArgInitSecContext::default();
        let body = encode_request(42, proc::GssxProc::InitSecContext as u32, &arg);
        let mut d = XdrDecoder::new(&body);
        let msg = Message::decode(&mut d).unwrap();
        assert_eq!(msg.xid, 42);
        assert!(msg.is_call);
        assert_eq!(msg.call.unwrap().proc_num, 8);
        // Remaining bytes decode as the argument.
        let got = ArgInitSecContext::decode(&mut d).unwrap();
        assert_eq!(got, arg);
    }

    #[test]
    fn golden_indicate_mechs_request() {
        // Hand-computed byte vector for encode_request(xid=1, proc=1, default
        // ArgIndicateMechs), derived directly from the XDR rules. This locks
        // the envelope layout, crucially the program number 400112 = 0x61AF0.
        let body = encode_request(1, proc::GssxProc::IndicateMechs as u32, &ArgIndicateMechs::default());
        #[rustfmt::skip]
        let expected: &[u8] = &[
            0x00, 0x00, 0x00, 0x01, // xid = 1
            0x00, 0x00, 0x00, 0x00, // msg type = CALL
            0x00, 0x00, 0x00, 0x02, // rpcvers = 2
            0x00, 0x06, 0x1A, 0xF0, // prog = 400112
            0x00, 0x00, 0x00, 0x01, // vers = 1
            0x00, 0x00, 0x00, 0x01, // proc = 1 (INDICATE_MECHS)
            0x00, 0x00, 0x00, 0x00, // cred flavor = AUTH_NONE
            0x00, 0x00, 0x00, 0x00, // cred body length = 0
            0x00, 0x00, 0x00, 0x00, // verf flavor = AUTH_NONE
            0x00, 0x00, 0x00, 0x00, // verf body length = 0
            // ArgIndicateMechs = call_ctx { locale="", server_ctx="", options=[] }
            0x00, 0x00, 0x00, 0x00, // locale length = 0
            0x00, 0x00, 0x00, 0x00, // server_ctx length = 0
            0x00, 0x00, 0x00, 0x00, // options count = 0
        ];
        assert_eq!(body, expected);
    }

    #[test]
    fn reply_envelope_then_res() {
        let res = ResInitSecContext::default();
        let body = encode_reply(42, &res);
        let mut d = XdrDecoder::new(&body);
        let msg = Message::decode(&mut d).unwrap();
        assert_eq!(msg.xid, 42);
        assert!(!msg.is_call);
        let got = ResInitSecContext::decode(&mut d).unwrap();
        assert_eq!(got, res);
    }
}
