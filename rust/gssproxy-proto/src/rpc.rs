//! SunRPC message envelope used by gssproxy (a private ONC RPC program).
//!
//! Port of `rpcgen/gp_rpc.h` + `rpcgen/gp_rpc_xdr.c`. The daemon program is
//! number `GSSPROXY` (400112), version `GSSPROXYVERS` (1); procedures are the
//! `GSSX_*` values 1..=15 (see `proc.rs`).

use crate::xdr::{Xdr, XdrDecoder, XdrEncoder, XdrError, XdrResult};

/// RPC program number for gssproxy.
pub const GSSPROXY: u32 = 400112;
/// RPC program version.
pub const GSSPROXYVERS: u32 = 1;
/// RPC protocol version carried in the call header.
pub const RPC_VERS: u32 = 2;

/// Maximum size of a single RPC message body (matches `MAX_RPC_SIZE`).
pub const MAX_RPC_SIZE: usize = 1024 * 1024;
/// Last-fragment marker in the record-marking length word.
pub const FRAGMENT_BIT: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFlavor {
    None = 0,
    Sys = 1,
    Short = 2,
    Dh = 3,
    RpcSecGss = 6,
}

impl AuthFlavor {
    fn from_i32(v: i32) -> XdrResult<Self> {
        Ok(match v {
            0 => AuthFlavor::None,
            1 => AuthFlavor::Sys,
            2 => AuthFlavor::Short,
            3 => AuthFlavor::Dh,
            6 => AuthFlavor::RpcSecGss,
            _ => return Err(XdrError::InvalidValue("auth_flavor")),
        })
    }
}

/// `gp_rpc_opaque_auth` — flavour plus up to 400 bytes of body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpaqueAuth {
    pub flavor: i32,
    pub body: Vec<u8>,
}

impl OpaqueAuth {
    pub fn none() -> Self {
        OpaqueAuth {
            flavor: AuthFlavor::None as i32,
            body: Vec::new(),
        }
    }
}

impl Xdr for OpaqueAuth {
    fn encode(&self, e: &mut XdrEncoder) {
        e.put_enum(self.flavor);
        e.put_opaque(&self.body);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        let flavor = d.get_enum()?;
        // Validate against the known set, mirroring xdr_gp_rpc_auth_flavor.
        let _ = AuthFlavor::from_i32(flavor)?;
        let body = d.get_opaque()?;
        if body.len() > 400 {
            return Err(XdrError::TooLong);
        }
        Ok(OpaqueAuth { flavor, body })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallHeader {
    pub rpcvers: u32,
    pub prog: u32,
    pub vers: u32,
    pub proc_num: u32,
    pub cred: OpaqueAuth,
    pub verf: OpaqueAuth,
}

impl CallHeader {
    /// Build a client call header for a given procedure.
    pub fn new(proc_num: u32) -> Self {
        CallHeader {
            rpcvers: RPC_VERS,
            prog: GSSPROXY,
            vers: GSSPROXYVERS,
            proc_num,
            cred: OpaqueAuth::none(),
            verf: OpaqueAuth::none(),
        }
    }
}

impl Xdr for CallHeader {
    fn encode(&self, e: &mut XdrEncoder) {
        e.put_u32(self.rpcvers);
        e.put_u32(self.prog);
        e.put_u32(self.vers);
        e.put_u32(self.proc_num);
        self.cred.encode(e);
        self.verf.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(CallHeader {
            rpcvers: d.get_u32()?,
            prog: d.get_u32()?,
            vers: d.get_u32()?,
            proc_num: d.get_u32()?,
            cred: OpaqueAuth::decode(d)?,
            verf: OpaqueAuth::decode(d)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptStatus {
    Success = 0,
    ProgUnavail = 1,
    ProgMismatch = 2,
    ProcUnavail = 3,
    GarbageArgs = 4,
    SystemErr = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MismatchInfo {
    pub low: u32,
    pub high: u32,
}

/// Reply header. The C side only ever needs the "accepted + success" path on
/// decode (anything else is an error), and the daemon only ever emits that
/// path on encode, so this captures the success case faithfully and reports
/// other cases as a discriminated status for completeness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyBody {
    /// MSG_ACCEPTED + SUCCESS: verifier, then the procedure result follows.
    AcceptedSuccess { verf: OpaqueAuth },
    /// MSG_ACCEPTED + PROG_MISMATCH.
    ProgMismatch { verf: OpaqueAuth, info: MismatchInfo },
    /// MSG_ACCEPTED with another accept status (no body).
    AcceptedOther { verf: OpaqueAuth, status: i32 },
    /// MSG_DENIED with the raw reject discriminant and value.
    Denied { reject_status: i32, value: i32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub xid: u32,
    /// True for a CALL, false for a REPLY.
    pub is_call: bool,
    pub call: Option<CallHeader>,
    pub reply: Option<ReplyBody>,
}

const MSG_CALL: i32 = 0;
const MSG_REPLY: i32 = 1;
const REPLY_ACCEPTED: i32 = 0;
const REPLY_DENIED: i32 = 1;
const ACCEPT_SUCCESS: i32 = 0;
const ACCEPT_PROG_MISMATCH: i32 = 2;

impl Message {
    /// Construct a CALL message for the given xid and procedure.
    pub fn call(xid: u32, proc_num: u32) -> Self {
        Message {
            xid,
            is_call: true,
            call: Some(CallHeader::new(proc_num)),
            reply: None,
        }
    }

    /// Construct a successful accepted REPLY message.
    pub fn reply_success(xid: u32) -> Self {
        Message {
            xid,
            is_call: false,
            call: None,
            reply: Some(ReplyBody::AcceptedSuccess {
                verf: OpaqueAuth::none(),
            }),
        }
    }

    /// Encode just the RPC envelope (the procedure args/results are appended by
    /// the caller into the same encoder).
    pub fn encode(&self, e: &mut XdrEncoder) {
        e.put_u32(self.xid);
        if self.is_call {
            e.put_enum(MSG_CALL);
            self.call
                .as_ref()
                .expect("call message without header")
                .encode(e);
        } else {
            e.put_enum(MSG_REPLY);
            match self.reply.as_ref().expect("reply message without body") {
                ReplyBody::AcceptedSuccess { verf } => {
                    e.put_enum(REPLY_ACCEPTED);
                    verf.encode(e);
                    e.put_enum(ACCEPT_SUCCESS);
                    // GP_RPC_SUCCESS results follow inline (zero-length opaque
                    // discriminant body in C: xdr_opaque(.., 0) emits nothing).
                }
                ReplyBody::ProgMismatch { verf, info } => {
                    e.put_enum(REPLY_ACCEPTED);
                    verf.encode(e);
                    e.put_enum(ACCEPT_PROG_MISMATCH);
                    e.put_u32(info.low);
                    e.put_u32(info.high);
                }
                ReplyBody::AcceptedOther { verf, status } => {
                    e.put_enum(REPLY_ACCEPTED);
                    verf.encode(e);
                    e.put_enum(*status);
                }
                ReplyBody::Denied {
                    reject_status,
                    value,
                } => {
                    e.put_enum(REPLY_DENIED);
                    e.put_enum(*reject_status);
                    e.put_enum(*value);
                }
            }
        }
    }

    /// Decode the RPC envelope. The decoder is left positioned at the start of
    /// the procedure args/results.
    pub fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        let xid = d.get_u32()?;
        match d.get_enum()? {
            MSG_CALL => Ok(Message {
                xid,
                is_call: true,
                call: Some(CallHeader::decode(d)?),
                reply: None,
            }),
            MSG_REPLY => {
                let reply = match d.get_enum()? {
                    REPLY_ACCEPTED => {
                        let verf = OpaqueAuth::decode(d)?;
                        match d.get_enum()? {
                            ACCEPT_SUCCESS => ReplyBody::AcceptedSuccess { verf },
                            ACCEPT_PROG_MISMATCH => ReplyBody::ProgMismatch {
                                verf,
                                info: MismatchInfo {
                                    low: d.get_u32()?,
                                    high: d.get_u32()?,
                                },
                            },
                            status => ReplyBody::AcceptedOther { verf, status },
                        }
                    }
                    REPLY_DENIED => ReplyBody::Denied {
                        reject_status: d.get_enum()?,
                        value: d.get_enum()?,
                    },
                    _ => return Err(XdrError::InvalidValue("reply_status")),
                };
                Ok(Message {
                    xid,
                    is_call: false,
                    call: None,
                    reply: Some(reply),
                })
            }
            _ => Err(XdrError::InvalidValue("msg_type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_header_roundtrip() {
        let mut e = XdrEncoder::new();
        let msg = Message::call(0xdeadbeef, 8);
        msg.encode(&mut e);
        let mut d = XdrDecoder::new(e.as_bytes());
        let got = Message::decode(&mut d).unwrap();
        assert_eq!(got, msg);
        let call = got.call.unwrap();
        assert_eq!(call.prog, GSSPROXY);
        assert_eq!(call.vers, GSSPROXYVERS);
        assert_eq!(call.proc_num, 8);
        assert_eq!(call.rpcvers, RPC_VERS);
    }

    #[test]
    fn reply_success_roundtrip() {
        let mut e = XdrEncoder::new();
        Message::reply_success(7).encode(&mut e);
        let mut d = XdrDecoder::new(e.as_bytes());
        let got = Message::decode(&mut d).unwrap();
        assert_eq!(got.xid, 7);
        assert!(!got.is_call);
        assert!(matches!(
            got.reply,
            Some(ReplyBody::AcceptedSuccess { .. })
        ));
        // No trailing bytes: a success reply envelope has no result body here.
        assert_eq!(d.remaining(), 0);
    }
}
