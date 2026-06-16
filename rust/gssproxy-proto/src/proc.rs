//! Per-procedure argument/result types (`gssx_arg_*` / `gssx_res_*`) and the
//! procedure number table, ported from `rpcgen/gss_proxy.h` and
//! `rpcgen/gss_proxy_xdr.c`.

use crate::gssx::*;
use crate::xdr::{
    Xdr, XdrDecoder, XdrEncoder, XdrResult, decode_array, decode_optional, encode_array,
    encode_optional,
};

/// GSSX procedure numbers (program 400112, version 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum GssxProc {
    IndicateMechs = 1,
    GetCallContext = 2,
    ImportAndCanonName = 3,
    ExportCred = 4,
    ImportCred = 5,
    AcquireCred = 6,
    StoreCred = 7,
    InitSecContext = 8,
    AcceptSecContext = 9,
    ReleaseHandle = 10,
    GetMic = 11,
    VerifyMic = 12,
    Wrap = 13,
    Unwrap = 14,
    WrapSizeLimit = 15,
}

impl GssxProc {
    pub const MIN: u32 = 1;
    pub const MAX: u32 = 15;

    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => GssxProc::IndicateMechs,
            2 => GssxProc::GetCallContext,
            3 => GssxProc::ImportAndCanonName,
            4 => GssxProc::ExportCred,
            5 => GssxProc::ImportCred,
            6 => GssxProc::AcquireCred,
            7 => GssxProc::StoreCred,
            8 => GssxProc::InitSecContext,
            9 => GssxProc::AcceptSecContext,
            10 => GssxProc::ReleaseHandle,
            11 => GssxProc::GetMic,
            12 => GssxProc::VerifyMic,
            13 => GssxProc::Wrap,
            14 => GssxProc::Unwrap,
            15 => GssxProc::WrapSizeLimit,
            _ => return None,
        })
    }
}

// ---- release_handle (10) ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgReleaseHandle {
    pub call_ctx: GssxCallCtx,
    pub cred_handle: GssxHandle,
}

impl Xdr for ArgReleaseHandle {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        self.cred_handle.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgReleaseHandle {
            call_ctx: GssxCallCtx::decode(d)?,
            cred_handle: GssxHandle::decode(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResReleaseHandle {
    pub status: GssxStatus,
}

impl Xdr for ResReleaseHandle {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResReleaseHandle {
            status: GssxStatus::decode(d)?,
        })
    }
}

// ---- indicate_mechs (1) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgIndicateMechs {
    pub call_ctx: GssxCallCtx,
}

impl Xdr for ArgIndicateMechs {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgIndicateMechs {
            call_ctx: GssxCallCtx::decode(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResIndicateMechs {
    pub status: GssxStatus,
    pub mechs: Vec<GssxMechInfo>,
    pub mech_attr_descs: Vec<GssxMechAttr>,
    pub supported_extensions: Vec<GssxBuffer>,
    pub options: Vec<GssxOption>,
}

impl Xdr for ResIndicateMechs {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_array(e, &self.mechs);
        encode_array(e, &self.mech_attr_descs);
        encode_array(e, &self.supported_extensions);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResIndicateMechs {
            status: GssxStatus::decode(d)?,
            mechs: decode_array(d)?,
            mech_attr_descs: decode_array(d)?,
            supported_extensions: decode_array(d)?,
            options: decode_array(d)?,
        })
    }
}

// ---- import_and_canon_name (3) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgImportAndCanonName {
    pub call_ctx: GssxCallCtx,
    pub input_name: GssxName,
    pub mech: GssxOid,
    pub name_attributes: Vec<GssxNameAttr>,
    pub options: Vec<GssxOption>,
}

impl Xdr for ArgImportAndCanonName {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        self.input_name.encode(e);
        self.mech.encode(e);
        encode_array(e, &self.name_attributes);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgImportAndCanonName {
            call_ctx: GssxCallCtx::decode(d)?,
            input_name: GssxName::decode(d)?,
            mech: Opaque::decode(d)?,
            name_attributes: decode_array(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResImportAndCanonName {
    pub status: GssxStatus,
    pub output_name: Option<GssxName>,
    pub options: Vec<GssxOption>,
}

impl Xdr for ResImportAndCanonName {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_optional(e, &self.output_name);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResImportAndCanonName {
            status: GssxStatus::decode(d)?,
            output_name: decode_optional(d)?,
            options: decode_array(d)?,
        })
    }
}

// ---- get_call_context (2) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgGetCallContext {
    pub call_ctx: GssxCallCtx,
    pub options: Vec<GssxOption>,
}

impl Xdr for ArgGetCallContext {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgGetCallContext {
            call_ctx: GssxCallCtx::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResGetCallContext {
    pub status: GssxStatus,
    pub server_call_ctx: OctetString,
    pub options: Vec<GssxOption>,
}

impl Xdr for ResGetCallContext {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        self.server_call_ctx.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResGetCallContext {
            status: GssxStatus::decode(d)?,
            server_call_ctx: Opaque::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

// ---- acquire_cred (6) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgAcquireCred {
    pub call_ctx: GssxCallCtx,
    pub input_cred_handle: Option<GssxCred>,
    pub add_cred_to_input_handle: bool,
    pub desired_name: Option<GssxName>,
    pub time_req: u64,
    pub desired_mechs: GssxOidSet,
    pub cred_usage: i32,
    pub initiator_time_req: u64,
    pub acceptor_time_req: u64,
    pub options: Vec<GssxOption>,
}

impl Xdr for ArgAcquireCred {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        encode_optional(e, &self.input_cred_handle);
        self.add_cred_to_input_handle.encode(e);
        encode_optional(e, &self.desired_name);
        self.time_req.encode(e);
        encode_array(e, &self.desired_mechs);
        self.cred_usage.encode(e);
        self.initiator_time_req.encode(e);
        self.acceptor_time_req.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgAcquireCred {
            call_ctx: GssxCallCtx::decode(d)?,
            input_cred_handle: decode_optional(d)?,
            add_cred_to_input_handle: bool::decode(d)?,
            desired_name: decode_optional(d)?,
            time_req: u64::decode(d)?,
            desired_mechs: decode_array(d)?,
            cred_usage: i32::decode(d)?,
            initiator_time_req: u64::decode(d)?,
            acceptor_time_req: u64::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResAcquireCred {
    pub status: GssxStatus,
    pub output_cred_handle: Option<GssxCred>,
    pub options: Vec<GssxOption>,
}

impl Xdr for ResAcquireCred {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_optional(e, &self.output_cred_handle);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResAcquireCred {
            status: GssxStatus::decode(d)?,
            output_cred_handle: decode_optional(d)?,
            options: decode_array(d)?,
        })
    }
}

// ---- export_cred (4) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgExportCred {
    pub call_ctx: GssxCallCtx,
    pub input_cred_handle: GssxCred,
    pub cred_usage: i32,
    pub options: Vec<GssxOption>,
}

impl Xdr for ArgExportCred {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        self.input_cred_handle.encode(e);
        self.cred_usage.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgExportCred {
            call_ctx: GssxCallCtx::decode(d)?,
            input_cred_handle: GssxCred::decode(d)?,
            cred_usage: i32::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResExportCred {
    pub status: GssxStatus,
    pub usage_exported: i32,
    pub exported_handle: Option<OctetString>,
    pub options: Vec<GssxOption>,
}

impl Xdr for ResExportCred {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        self.usage_exported.encode(e);
        encode_optional(e, &self.exported_handle);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResExportCred {
            status: GssxStatus::decode(d)?,
            usage_exported: i32::decode(d)?,
            exported_handle: decode_optional(d)?,
            options: decode_array(d)?,
        })
    }
}

// ---- import_cred (5) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgImportCred {
    pub call_ctx: GssxCallCtx,
    pub exported_handle: OctetString,
    pub options: Vec<GssxOption>,
}

impl Xdr for ArgImportCred {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        self.exported_handle.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgImportCred {
            call_ctx: GssxCallCtx::decode(d)?,
            exported_handle: Opaque::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResImportCred {
    pub status: GssxStatus,
    pub output_cred_handle: Option<GssxCred>,
    pub options: Vec<GssxOption>,
}

impl Xdr for ResImportCred {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_optional(e, &self.output_cred_handle);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResImportCred {
            status: GssxStatus::decode(d)?,
            output_cred_handle: decode_optional(d)?,
            options: decode_array(d)?,
        })
    }
}

// ---- store_cred (7) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgStoreCred {
    pub call_ctx: GssxCallCtx,
    pub input_cred_handle: GssxCred,
    pub cred_usage: i32,
    pub desired_mech: GssxOid,
    pub overwrite_cred: bool,
    pub default_cred: bool,
    pub options: Vec<GssxOption>,
}

impl Xdr for ArgStoreCred {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        self.input_cred_handle.encode(e);
        self.cred_usage.encode(e);
        self.desired_mech.encode(e);
        self.overwrite_cred.encode(e);
        self.default_cred.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgStoreCred {
            call_ctx: GssxCallCtx::decode(d)?,
            input_cred_handle: GssxCred::decode(d)?,
            cred_usage: i32::decode(d)?,
            desired_mech: Opaque::decode(d)?,
            overwrite_cred: bool::decode(d)?,
            default_cred: bool::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResStoreCred {
    pub status: GssxStatus,
    pub elements_stored: GssxOidSet,
    pub cred_usage_stored: i32,
    pub options: Vec<GssxOption>,
}

impl Xdr for ResStoreCred {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_array(e, &self.elements_stored);
        self.cred_usage_stored.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResStoreCred {
            status: GssxStatus::decode(d)?,
            elements_stored: decode_array(d)?,
            cred_usage_stored: i32::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

// ---- init_sec_context (8) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgInitSecContext {
    pub call_ctx: GssxCallCtx,
    pub context_handle: Option<GssxCtx>,
    pub cred_handle: Option<GssxCred>,
    pub target_name: Option<GssxName>,
    pub mech_type: GssxOid,
    pub req_flags: u64,
    pub time_req: u64,
    pub input_cb: Option<GssxCb>,
    pub input_token: Option<GssxBuffer>,
    pub options: Vec<GssxOption>,
}

impl Xdr for ArgInitSecContext {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        encode_optional(e, &self.context_handle);
        encode_optional(e, &self.cred_handle);
        encode_optional(e, &self.target_name);
        self.mech_type.encode(e);
        self.req_flags.encode(e);
        self.time_req.encode(e);
        encode_optional(e, &self.input_cb);
        encode_optional(e, &self.input_token);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgInitSecContext {
            call_ctx: GssxCallCtx::decode(d)?,
            context_handle: decode_optional(d)?,
            cred_handle: decode_optional(d)?,
            target_name: decode_optional(d)?,
            mech_type: Opaque::decode(d)?,
            req_flags: u64::decode(d)?,
            time_req: u64::decode(d)?,
            input_cb: decode_optional(d)?,
            input_token: decode_optional(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResInitSecContext {
    pub status: GssxStatus,
    pub context_handle: Option<GssxCtx>,
    pub output_token: Option<GssxBuffer>,
    pub options: Vec<GssxOption>,
}

impl Xdr for ResInitSecContext {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_optional(e, &self.context_handle);
        encode_optional(e, &self.output_token);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResInitSecContext {
            status: GssxStatus::decode(d)?,
            context_handle: decode_optional(d)?,
            output_token: decode_optional(d)?,
            options: decode_array(d)?,
        })
    }
}

// ---- accept_sec_context (9) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgAcceptSecContext {
    pub call_ctx: GssxCallCtx,
    pub context_handle: Option<GssxCtx>,
    pub cred_handle: Option<GssxCred>,
    pub input_token: GssxBuffer,
    pub input_cb: Option<GssxCb>,
    pub ret_deleg_cred: bool,
    pub options: Vec<GssxOption>,
}

impl Xdr for ArgAcceptSecContext {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        encode_optional(e, &self.context_handle);
        encode_optional(e, &self.cred_handle);
        self.input_token.encode(e);
        encode_optional(e, &self.input_cb);
        self.ret_deleg_cred.encode(e);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgAcceptSecContext {
            call_ctx: GssxCallCtx::decode(d)?,
            context_handle: decode_optional(d)?,
            cred_handle: decode_optional(d)?,
            input_token: Opaque::decode(d)?,
            input_cb: decode_optional(d)?,
            ret_deleg_cred: bool::decode(d)?,
            options: decode_array(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResAcceptSecContext {
    pub status: GssxStatus,
    pub context_handle: Option<GssxCtx>,
    pub output_token: Option<GssxBuffer>,
    pub delegated_cred_handle: Option<GssxCred>,
    pub options: Vec<GssxOption>,
}

impl Xdr for ResAcceptSecContext {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_optional(e, &self.context_handle);
        encode_optional(e, &self.output_token);
        encode_optional(e, &self.delegated_cred_handle);
        encode_array(e, &self.options);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResAcceptSecContext {
            status: GssxStatus::decode(d)?,
            context_handle: decode_optional(d)?,
            output_token: decode_optional(d)?,
            delegated_cred_handle: decode_optional(d)?,
            options: decode_array(d)?,
        })
    }
}

// ---- get_mic (11) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgGetMic {
    pub call_ctx: GssxCallCtx,
    pub context_handle: GssxCtx,
    pub qop_req: u64,
    pub message_buffer: GssxBuffer,
}

impl Xdr for ArgGetMic {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        self.context_handle.encode(e);
        self.qop_req.encode(e);
        self.message_buffer.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgGetMic {
            call_ctx: GssxCallCtx::decode(d)?,
            context_handle: GssxCtx::decode(d)?,
            qop_req: u64::decode(d)?,
            message_buffer: Opaque::decode(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResGetMic {
    pub status: GssxStatus,
    pub context_handle: Option<GssxCtx>,
    pub token_buffer: GssxBuffer,
    pub qop_state: Option<u64>,
}

impl Xdr for ResGetMic {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_optional(e, &self.context_handle);
        self.token_buffer.encode(e);
        encode_optional(e, &self.qop_state);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResGetMic {
            status: GssxStatus::decode(d)?,
            context_handle: decode_optional(d)?,
            token_buffer: Opaque::decode(d)?,
            qop_state: decode_optional(d)?,
        })
    }
}

// ---- verify_mic (12) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgVerifyMic {
    pub call_ctx: GssxCallCtx,
    pub context_handle: GssxCtx,
    pub message_buffer: GssxBuffer,
    pub token_buffer: GssxBuffer,
}

impl Xdr for ArgVerifyMic {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        self.context_handle.encode(e);
        self.message_buffer.encode(e);
        self.token_buffer.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgVerifyMic {
            call_ctx: GssxCallCtx::decode(d)?,
            context_handle: GssxCtx::decode(d)?,
            message_buffer: Opaque::decode(d)?,
            token_buffer: Opaque::decode(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResVerifyMic {
    pub status: GssxStatus,
    pub context_handle: Option<GssxCtx>,
    pub qop_state: Option<u64>,
}

impl Xdr for ResVerifyMic {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_optional(e, &self.context_handle);
        encode_optional(e, &self.qop_state);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResVerifyMic {
            status: GssxStatus::decode(d)?,
            context_handle: decode_optional(d)?,
            qop_state: decode_optional(d)?,
        })
    }
}

// ---- wrap (13) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgWrap {
    pub call_ctx: GssxCallCtx,
    pub context_handle: GssxCtx,
    pub conf_req: bool,
    pub message_buffer: Vec<GssxBuffer>,
    pub qop_state: u64,
}

impl Xdr for ArgWrap {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        self.context_handle.encode(e);
        self.conf_req.encode(e);
        encode_array(e, &self.message_buffer);
        self.qop_state.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgWrap {
            call_ctx: GssxCallCtx::decode(d)?,
            context_handle: GssxCtx::decode(d)?,
            conf_req: bool::decode(d)?,
            message_buffer: decode_array(d)?,
            qop_state: u64::decode(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResWrap {
    pub status: GssxStatus,
    pub context_handle: Option<GssxCtx>,
    pub token_buffer: Vec<GssxBuffer>,
    pub conf_state: Option<bool>,
    pub qop_state: Option<u64>,
}

impl Xdr for ResWrap {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_optional(e, &self.context_handle);
        encode_array(e, &self.token_buffer);
        encode_optional(e, &self.conf_state);
        encode_optional(e, &self.qop_state);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResWrap {
            status: GssxStatus::decode(d)?,
            context_handle: decode_optional(d)?,
            token_buffer: decode_array(d)?,
            conf_state: decode_optional(d)?,
            qop_state: decode_optional(d)?,
        })
    }
}

// ---- unwrap (14) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgUnwrap {
    pub call_ctx: GssxCallCtx,
    pub context_handle: GssxCtx,
    pub token_buffer: Vec<GssxBuffer>,
    pub qop_state: u64,
}

impl Xdr for ArgUnwrap {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        self.context_handle.encode(e);
        encode_array(e, &self.token_buffer);
        self.qop_state.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgUnwrap {
            call_ctx: GssxCallCtx::decode(d)?,
            context_handle: GssxCtx::decode(d)?,
            token_buffer: decode_array(d)?,
            qop_state: u64::decode(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResUnwrap {
    pub status: GssxStatus,
    pub context_handle: Option<GssxCtx>,
    pub message_buffer: Vec<GssxBuffer>,
    pub conf_state: Option<bool>,
    pub qop_state: Option<u64>,
}

impl Xdr for ResUnwrap {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        encode_optional(e, &self.context_handle);
        encode_array(e, &self.message_buffer);
        encode_optional(e, &self.conf_state);
        encode_optional(e, &self.qop_state);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResUnwrap {
            status: GssxStatus::decode(d)?,
            context_handle: decode_optional(d)?,
            message_buffer: decode_array(d)?,
            conf_state: decode_optional(d)?,
            qop_state: decode_optional(d)?,
        })
    }
}

// ---- wrap_size_limit (15) ----

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgWrapSizeLimit {
    pub call_ctx: GssxCallCtx,
    pub context_handle: GssxCtx,
    pub conf_req: bool,
    pub qop_state: u64,
    pub req_output_size: u64,
}

impl Xdr for ArgWrapSizeLimit {
    fn encode(&self, e: &mut XdrEncoder) {
        self.call_ctx.encode(e);
        self.context_handle.encode(e);
        self.conf_req.encode(e);
        self.qop_state.encode(e);
        self.req_output_size.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ArgWrapSizeLimit {
            call_ctx: GssxCallCtx::decode(d)?,
            context_handle: GssxCtx::decode(d)?,
            conf_req: bool::decode(d)?,
            qop_state: u64::decode(d)?,
            req_output_size: u64::decode(d)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResWrapSizeLimit {
    pub status: GssxStatus,
    pub max_input_size: u64,
}

impl Xdr for ResWrapSizeLimit {
    fn encode(&self, e: &mut XdrEncoder) {
        self.status.encode(e);
        self.max_input_size.encode(e);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        Ok(ResWrapSizeLimit {
            status: GssxStatus::decode(d)?,
            max_input_size: u64::decode(d)?,
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
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn proc_numbers() {
        assert_eq!(GssxProc::from_u32(8), Some(GssxProc::InitSecContext));
        assert_eq!(GssxProc::from_u32(0), None);
        assert_eq!(GssxProc::from_u32(16), None);
        assert_eq!(GssxProc::InitSecContext as u32, 8);
    }

    #[test]
    fn init_sec_context_roundtrip() {
        let arg = ArgInitSecContext {
            mech_type: Opaque::new(vec![1, 2, 3]),
            req_flags: 0x3e,
            input_token: Some(Opaque::new(b"token".to_vec())),
            ..Default::default()
        };
        roundtrip(&arg);
        let res = ResInitSecContext {
            status: GssxStatus {
                major_status: 0,
                ..Default::default()
            },
            context_handle: Some(GssxCtx::default()),
            output_token: Some(Opaque::new(b"out".to_vec())),
            options: vec![],
        };
        roundtrip(&res);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let arg = ArgWrap {
            conf_req: true,
            message_buffer: vec![Opaque::new(b"hello".to_vec())],
            qop_state: 0,
            ..Default::default()
        };
        roundtrip(&arg);
        let res = ResWrap {
            token_buffer: vec![Opaque::new(b"wrapped".to_vec())],
            conf_state: Some(true),
            qop_state: Some(0),
            ..Default::default()
        };
        roundtrip(&res);
    }
}
