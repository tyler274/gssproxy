//! The `gssx_*` data types, ported field-for-field from `rpcgen/gss_proxy.h`
//! and `rpcgen/gss_proxy_xdr.c`.
//!
//! Naming mirrors the C structs so the two can be cross-checked. The XDR
//! field order in every `encode`/`decode` matches the corresponding
//! `xdr_gssx_*` function exactly; this is what guarantees wire compatibility
//! with the C daemon and the C interposer.

use crate::xdr::{decode_array, encode_array, Xdr, XdrDecoder, XdrEncoder, XdrResult};

/// XDR enum is encoded as a signed 4-byte integer; model gssx enums as i32.
impl Xdr for i32 {
    fn encode(&self, e: &mut XdrEncoder) {
        e.put_enum(*self);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        d.get_enum()
    }
}

/// Variable-length opaque/string value (`octet_string`, `gssx_buffer`,
/// `gssx_OID`, `utf8string` all share this wire form: `xdr_bytes`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Opaque(pub Vec<u8>);

impl Opaque {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Opaque(data.into())
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Opaque {
    fn from(v: Vec<u8>) -> Self {
        Opaque(v)
    }
}

impl From<&[u8]> for Opaque {
    fn from(v: &[u8]) -> Self {
        Opaque(v.to_vec())
    }
}

impl Xdr for Opaque {
    fn encode(&self, e: &mut XdrEncoder) {
        e.put_opaque(&self.0);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(Opaque(d.get_opaque()?))
    }
}

/// Semantic aliases matching the rpcgen typedefs.
pub type GssxBuffer = Opaque;
pub type GssxOid = Opaque;
pub type OctetString = Opaque;
pub type Utf8String = Opaque;
/// `gssx_OID_set` is an XDR array of OIDs.
pub type GssxOidSet = Vec<GssxOid>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxOption {
    pub option: GssxBuffer,
    pub value: GssxBuffer,
}

impl Xdr for GssxOption {
    fn encode(&self, e: &mut XdrEncoder) {
        self.option.encode(e);
        self.value.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxOption {
            option: Opaque::decode(d)?,
            value: Opaque::decode(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxMechAttr {
    pub attr: GssxOid,
    pub name: GssxBuffer,
    pub short_desc: GssxBuffer,
    pub long_desc: GssxBuffer,
    pub extensions: Vec<GssxOption>,
}

impl Xdr for GssxMechAttr {
    fn encode(&self, e: &mut XdrEncoder) {
        self.attr.encode(e);
        self.name.encode(e);
        self.short_desc.encode(e);
        self.long_desc.encode(e);
        encode_array(e, &self.extensions);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxMechAttr {
            attr: Opaque::decode(d)?,
            name: Opaque::decode(d)?,
            short_desc: Opaque::decode(d)?,
            long_desc: Opaque::decode(d)?,
            extensions: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxMechInfo {
    pub mech: GssxOid,
    pub name_types: GssxOidSet,
    pub mech_attrs: GssxOidSet,
    pub known_mech_attrs: GssxOidSet,
    pub cred_options: GssxOidSet,
    pub sec_ctx_options: GssxOidSet,
    pub saslname_sasl_mech_name: GssxBuffer,
    pub saslname_mech_name: GssxBuffer,
    pub saslname_mech_desc: GssxBuffer,
    pub extensions: Vec<GssxOption>,
}

impl Xdr for GssxMechInfo {
    fn encode(&self, e: &mut XdrEncoder) {
        self.mech.encode(e);
        encode_array(e, &self.name_types);
        encode_array(e, &self.mech_attrs);
        encode_array(e, &self.known_mech_attrs);
        encode_array(e, &self.cred_options);
        encode_array(e, &self.sec_ctx_options);
        self.saslname_sasl_mech_name.encode(e);
        self.saslname_mech_name.encode(e);
        self.saslname_mech_desc.encode(e);
        encode_array(e, &self.extensions);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxMechInfo {
            mech: Opaque::decode(d)?,
            name_types: decode_array(d)?,
            mech_attrs: decode_array(d)?,
            known_mech_attrs: decode_array(d)?,
            cred_options: decode_array(d)?,
            sec_ctx_options: decode_array(d)?,
            saslname_sasl_mech_name: Opaque::decode(d)?,
            saslname_mech_name: Opaque::decode(d)?,
            saslname_mech_desc: Opaque::decode(d)?,
            extensions: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxNameAttr {
    pub attr: GssxBuffer,
    pub value: GssxBuffer,
    pub extensions: Vec<GssxOption>,
}

impl Xdr for GssxNameAttr {
    fn encode(&self, e: &mut XdrEncoder) {
        self.attr.encode(e);
        self.value.encode(e);
        encode_array(e, &self.extensions);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxNameAttr {
            attr: Opaque::decode(d)?,
            value: Opaque::decode(d)?,
            extensions: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxStatus {
    pub major_status: u64,
    pub mech: GssxOid,
    pub minor_status: u64,
    pub major_status_string: Utf8String,
    pub minor_status_string: Utf8String,
    pub server_ctx: OctetString,
    pub options: Vec<GssxOption>,
}

impl Xdr for GssxStatus {
    fn encode(&self, e: &mut XdrEncoder) {
        self.major_status.encode(e);
        self.mech.encode(e);
        self.minor_status.encode(e);
        self.major_status_string.encode(e);
        self.minor_status_string.encode(e);
        self.server_ctx.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxStatus {
            major_status: u64::decode(d)?,
            mech: Opaque::decode(d)?,
            minor_status: u64::decode(d)?,
            major_status_string: Opaque::decode(d)?,
            minor_status_string: Opaque::decode(d)?,
            server_ctx: Opaque::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxCallCtx {
    pub locale: Utf8String,
    pub server_ctx: OctetString,
    pub options: Vec<GssxOption>,
}

impl Xdr for GssxCallCtx {
    fn encode(&self, e: &mut XdrEncoder) {
        self.locale.encode(e);
        self.server_ctx.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxCallCtx {
            locale: Opaque::decode(d)?,
            server_ctx: Opaque::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxName {
    pub display_name: GssxBuffer,
    pub name_type: GssxOid,
    pub exported_name: GssxBuffer,
    pub exported_composite_name: GssxBuffer,
    pub name_attributes: Vec<GssxNameAttr>,
    pub extensions: Vec<GssxOption>,
}

impl Xdr for GssxName {
    fn encode(&self, e: &mut XdrEncoder) {
        self.display_name.encode(e);
        self.name_type.encode(e);
        self.exported_name.encode(e);
        self.exported_composite_name.encode(e);
        encode_array(e, &self.name_attributes);
        encode_array(e, &self.extensions);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxName {
            display_name: Opaque::decode(d)?,
            name_type: Opaque::decode(d)?,
            exported_name: Opaque::decode(d)?,
            exported_composite_name: Opaque::decode(d)?,
            name_attributes: decode_array(d)?,
            extensions: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxCredElement {
    pub mn: GssxName,
    pub mech: GssxOid,
    pub cred_usage: i32,
    pub initiator_time_rec: u64,
    pub acceptor_time_rec: u64,
    pub options: Vec<GssxOption>,
}

impl Xdr for GssxCredElement {
    fn encode(&self, e: &mut XdrEncoder) {
        self.mn.encode(e);
        self.mech.encode(e);
        self.cred_usage.encode(e);
        self.initiator_time_rec.encode(e);
        self.acceptor_time_rec.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxCredElement {
            mn: GssxName::decode(d)?,
            mech: Opaque::decode(d)?,
            cred_usage: i32::decode(d)?,
            initiator_time_rec: u64::decode(d)?,
            acceptor_time_rec: u64::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxCred {
    pub desired_name: GssxName,
    pub elements: Vec<GssxCredElement>,
    pub cred_handle_reference: OctetString,
    pub needs_release: bool,
}

impl Xdr for GssxCred {
    fn encode(&self, e: &mut XdrEncoder) {
        self.desired_name.encode(e);
        encode_array(e, &self.elements);
        self.cred_handle_reference.encode(e);
        self.needs_release.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxCred {
            desired_name: GssxName::decode(d)?,
            elements: decode_array(d)?,
            cred_handle_reference: Opaque::decode(d)?,
            needs_release: bool::decode(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxCtx {
    pub exported_context_token: GssxBuffer,
    pub state: OctetString,
    pub needs_release: bool,
    pub mech: GssxOid,
    pub src_name: GssxName,
    pub targ_name: GssxName,
    pub lifetime: u64,
    pub ctx_flags: u64,
    pub locally_initiated: bool,
    pub open: bool,
    pub options: Vec<GssxOption>,
}

impl Xdr for GssxCtx {
    fn encode(&self, e: &mut XdrEncoder) {
        self.exported_context_token.encode(e);
        self.state.encode(e);
        self.needs_release.encode(e);
        self.mech.encode(e);
        self.src_name.encode(e);
        self.targ_name.encode(e);
        self.lifetime.encode(e);
        self.ctx_flags.encode(e);
        self.locally_initiated.encode(e);
        self.open.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxCtx {
            exported_context_token: Opaque::decode(d)?,
            state: Opaque::decode(d)?,
            needs_release: bool::decode(d)?,
            mech: Opaque::decode(d)?,
            src_name: GssxName::decode(d)?,
            targ_name: GssxName::decode(d)?,
            lifetime: u64::decode(d)?,
            ctx_flags: u64::decode(d)?,
            locally_initiated: bool::decode(d)?,
            open: bool::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

/// `gssx_handle` — a union discriminated by `handle_type`.
pub const GSSX_C_HANDLE_SEC_CTX: i32 = 0;
pub const GSSX_C_HANDLE_CRED: i32 = 1;

// Mirrors the on-wire `gssx_handle` XDR union; variant sizes follow the
// protocol structs, so we intentionally keep them inline rather than boxing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GssxHandle {
    SecCtx(GssxCtx),
    Cred(GssxCred),
    /// Any other discriminant: opaque extensions blob.
    Extensions {
        handle_type: i32,
        data: OctetString,
    },
}

impl Xdr for GssxHandle {
    fn encode(&self, e: &mut XdrEncoder) {
        match self {
            GssxHandle::SecCtx(ctx) => {
                e.put_enum(GSSX_C_HANDLE_SEC_CTX);
                ctx.encode(e);
            }
            GssxHandle::Cred(cred) => {
                e.put_enum(GSSX_C_HANDLE_CRED);
                cred.encode(e);
            }
            GssxHandle::Extensions { handle_type, data } => {
                e.put_enum(*handle_type);
                data.encode(e);
            }
        }
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        let handle_type = d.get_enum()?;
        Ok(match handle_type {
            GSSX_C_HANDLE_CRED => GssxHandle::Cred(GssxCred::decode(d)?),
            GSSX_C_HANDLE_SEC_CTX => GssxHandle::SecCtx(GssxCtx::decode(d)?),
            other => GssxHandle::Extensions {
                handle_type: other,
                data: Opaque::decode(d)?,
            },
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GssxCb {
    pub initiator_addrtype: u64,
    pub initiator_address: GssxBuffer,
    pub acceptor_addrtype: u64,
    pub acceptor_address: GssxBuffer,
    pub application_data: GssxBuffer,
}

impl Xdr for GssxCb {
    fn encode(&self, e: &mut XdrEncoder) {
        self.initiator_addrtype.encode(e);
        self.initiator_address.encode(e);
        self.acceptor_addrtype.encode(e);
        self.acceptor_address.encode(e);
        self.application_data.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(GssxCb {
            initiator_addrtype: u64::decode(d)?,
            initiator_address: Opaque::decode(d)?,
            acceptor_addrtype: u64::decode(d)?,
            acceptor_address: Opaque::decode(d)?,
            application_data: Opaque::decode(d)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Xdr + PartialEq + std::fmt::Debug>(v: &T) {
        let mut e = XdrEncoder::new();
        v.encode(&mut e);
        let mut d = XdrDecoder::new(e.as_bytes());
        let got = T::decode(&mut d).unwrap();
        assert_eq!(&got, v);
        assert_eq!(d.remaining(), 0, "decoder did not consume entire buffer");
    }

    #[test]
    fn name_roundtrip() {
        let n = GssxName {
            display_name: Opaque::new(b"user@REALM".to_vec()),
            name_type: Opaque::new(vec![0x2a, 0x86, 0x48]),
            exported_name: Opaque::default(),
            exported_composite_name: Opaque::default(),
            name_attributes: vec![],
            extensions: vec![GssxOption {
                option: Opaque::new(b"k".to_vec()),
                value: Opaque::new(b"v".to_vec()),
            }],
        };
        roundtrip(&n);
    }

    #[test]
    fn handle_union_variants() {
        roundtrip(&GssxHandle::Cred(GssxCred::default()));
        roundtrip(&GssxHandle::SecCtx(GssxCtx::default()));
        roundtrip(&GssxHandle::Extensions {
            handle_type: 7,
            data: Opaque::new(b"x".to_vec()),
        });
    }

    #[test]
    fn ctx_roundtrip() {
        let c = GssxCtx {
            exported_context_token: Opaque::new(b"tok".to_vec()),
            ctx_flags: 0x1122334455667788,
            lifetime: 3600,
            open: true,
            locally_initiated: true,
            ..Default::default()
        };
        roundtrip(&c);
    }
}
