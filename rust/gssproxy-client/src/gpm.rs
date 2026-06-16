//! The typed `gpm_*` RPC layer, mirroring `src/client/gpm_*.c`.
//!
//! Each function here is the Rust analogue of one `gpm_*` entry point: it builds
//! the `gssx_arg_*` for a daemon procedure (or operates purely on cached/handle
//! state), drives [`crate::make_call`], and decodes the `gssx_res_*` into plain
//! Rust / `gssx` values for the interposer (`gssproxy-interposer`) to translate
//! back into the GSSAPI C ABI.
//!
//! Unlike the C client - which threads opaque `gss_OID` "static" pointers and
//! `gss_buffer_t` out-params throughout - this layer returns owned `gssx`
//! structs and byte vectors. The interposer owns the C-ABI concerns: the
//! mech-OID static cache (`gpm_mech_to_static`) and name-type static mapping
//! (`gpm_name_oid_to_static`) live there, since those produce stable pointers
//! handed across the ABI.

use std::cell::RefCell;

use gssapi_sys::consts;
use gssapi_sys::sys::{GSS_S_COMPLETE, GSS_S_CONTINUE_NEEDED};
use gssproxy_proto::gssx::{
    GssxBuffer, GssxCb, GssxCred, GssxCtx, GssxName, GssxOption, GssxStatus, Opaque,
};
use gssproxy_proto::proc::*;
use gssproxy_proto::xdr::{Xdr, XdrDecoder, XdrEncoder};

use crate::make_call;

// ---- option keys (sizeof() in C includes the trailing NUL) ----
const ACQUIRE_TYPE_OPTION: &[u8] = b"acquire_type\0";
const ACQUIRE_IMPERSONATE_NAME: &[u8] = b"impersonate_name\0";
const CRED_SYNC_OPTION: &[u8] = b"sync_modified_creds\0";
const CRED_SYNC_DEFAULT: &[u8] = b"default\0";
const CRED_SYNC_PAYLOAD: &[u8] = b"sync_creds\0";
const LOCALNAME_OPTION: &[u8] = b"localname\0";

// ---- gssx_cred_usage enum values (x-files/gss_proxy.x) ----
const GSSX_C_INITIATE: i32 = 1;
const GSSX_C_ACCEPT: i32 = 2;
const GSSX_C_BOTH: i32 = 3;

// ---- GSS_C_* credential usage (gssapi.h) ----
const GSS_C_BOTH: i32 = 0;
const GSS_C_INITIATE: i32 = 1;
const GSS_C_ACCEPT: i32 = 2;

/// `GSS_C_INDEFINITE`.
const GSS_C_INDEFINITE: u32 = 0xffff_ffff;

/// `gp_conv_cred_usage_to_gssx`.
fn cred_usage_to_gssx(usage: i32) -> i32 {
    match usage {
        GSS_C_BOTH => GSSX_C_BOTH,
        GSS_C_INITIATE => GSSX_C_INITIATE,
        GSS_C_ACCEPT => GSSX_C_ACCEPT,
        _ => 0,
    }
}

/// Build a `GssxOption` with a key/value, matching `gp_add_option`'s bytewise
/// copy (the trailing NUL is part of the key/value as the `sizeof()` callers
/// pass it).
fn option(key: &[u8], value: &[u8]) -> GssxOption {
    GssxOption {
        option: Opaque::new(key.to_vec()),
        value: Opaque::new(value.to_vec()),
    }
}

/// `gp_options_find`: locate an option by exact key bytes.
fn find_option<'a>(options: &'a [GssxOption], key: &[u8]) -> Option<&'a GssxBuffer> {
    options
        .iter()
        .find(|o| o.option.as_slice() == key)
        .map(|o| &o.value)
}

// ===========================================================================
// Thread-local saved status (gpm_display_status.c)
// ===========================================================================

thread_local! {
    static LAST_STATUS: RefCell<Option<GssxStatus>> = const { RefCell::new(None) };
}

/// `gpm_save_status`: stash the last remote `gssx_status` for `display_status`.
pub fn save_status(status: &GssxStatus) {
    LAST_STATUS.with(|s| *s.borrow_mut() = Some(status.clone()));
}

/// `gpm_save_internal_status`: record a client-internal failure.
pub fn save_internal_status(err: u32, err_str: &str) {
    const STD_MAJ_ERROR_STR: &[u8] = b"Internal gssproxy error\0";
    let mut minor_string = err_str.as_bytes().to_vec();
    minor_string.push(0);
    let status = GssxStatus {
        major_status: consts::GSS_S_FAILURE as u64,
        major_status_string: Opaque::new(STD_MAJ_ERROR_STR.to_vec()),
        minor_status: err as u64,
        minor_status_string: Opaque::new(minor_string),
        ..Default::default()
    };
    save_status(&status);
}

/// `gpm_display_status`: render a saved major/minor status string. Returns
/// `(major, minor, message_bytes)`.
pub fn display_status(
    status_value: u32,
    status_type: i32,
    message_context: u32,
) -> (u32, u32, Vec<u8>) {
    // GSS_C_GSS_CODE == 1, GSS_C_MECH_CODE == 2 (gssapi.h).
    const GSS_C_GSS_CODE: i32 = 1;
    const GSS_C_MECH_CODE: i32 = 2;
    LAST_STATUS.with(|s| {
        let last = s.borrow();
        match status_type {
            GSS_C_GSS_CODE => match last.as_ref() {
                Some(st)
                    if st.major_status == status_value as u64
                        && !st.major_status_string.is_empty() =>
                {
                    (
                        GSS_S_COMPLETE,
                        0,
                        st.major_status_string.as_slice().to_vec(),
                    )
                }
                _ => (consts::GSS_S_UNAVAILABLE, 0, Vec::new()),
            },
            GSS_C_MECH_CODE => match last.as_ref() {
                Some(st)
                    if st.minor_status == status_value as u64
                        && !st.minor_status_string.is_empty() =>
                {
                    if message_context != 0 {
                        (consts::GSS_S_FAILURE, libc::EINVAL as u32, Vec::new())
                    } else {
                        (
                            GSS_S_COMPLETE,
                            0,
                            st.minor_status_string.as_slice().to_vec(),
                        )
                    }
                }
                _ => (consts::GSS_S_UNAVAILABLE, 0, Vec::new()),
            },
            _ => (consts::GSS_S_BAD_STATUS, libc::EINVAL as u32, Vec::new()),
        }
    })
}

// ===========================================================================
// Names (gpm_import_and_canon_name.c)
// ===========================================================================

/// `gpm_import_name`: build a `gssx_name` from a display buffer + name-type OID.
pub fn import_name(value: &[u8], name_type: &[u8]) -> GssxName {
    GssxName {
        display_name: Opaque::new(value.to_vec()),
        name_type: Opaque::new(name_type.to_vec()),
        ..Default::default()
    }
}

/// `gpm_display_name`: returns `(major, minor, display_bytes, name_type_bytes)`.
///
/// When `in_name` has no display name it is reconstructed from the exported
/// blob (the exported bytes become the display name, tagged `GSS_C_NT_EXPORT_NAME`),
/// matching the C "steal display_name/name_type" path. The returned name-type
/// bytes are mapped to a static OID by the caller when requested.
pub fn display_name(in_name: &mut GssxName) -> (u32, u32, Vec<u8>, Vec<u8>) {
    if in_name.display_name.is_empty() {
        if in_name.exported_name.is_empty() {
            return (consts::GSS_S_BAD_NAME, 0, Vec::new(), Vec::new());
        }
        let imported = import_name(in_name.exported_name.as_slice(), consts::NT_EXPORT_NAME_OID);
        in_name.display_name = imported.display_name;
        in_name.name_type = imported.name_type;
    }
    (
        GSS_S_COMPLETE,
        0,
        in_name.display_name.as_slice().to_vec(),
        in_name.name_type.as_slice().to_vec(),
    )
}

/// `gpm_canonicalize_name`: GSSX_IMPORT_AND_CANON_NAME, returning the canonical
/// `gssx_name`.
pub fn canonicalize_name(input: &GssxName, mech: &[u8]) -> (u32, u32, Option<GssxName>) {
    let arg = ArgImportAndCanonName {
        input_name: input.clone(),
        mech: Opaque::new(mech.to_vec()),
        ..Default::default()
    };
    let res: ResImportAndCanonName = match make_call(GssxProc::ImportAndCanonName, &arg) {
        Ok(r) => r,
        Err(e) => return (consts::GSS_S_FAILURE, e.errno() as u32, None),
    };
    if res.status.major_status != 0 {
        save_status(&res.status);
        return (
            res.status.major_status as u32,
            res.status.minor_status as u32,
            None,
        );
    }
    (GSS_S_COMPLETE, 0, res.output_name)
}

/// `gpm_localname`: GSSX_IMPORT_AND_CANON_NAME with the `localname` option,
/// returning the local name bytes.
pub fn localname(input: &GssxName, mech: &[u8]) -> (u32, u32, Option<Vec<u8>>) {
    let arg = ArgImportAndCanonName {
        input_name: input.clone(),
        mech: Opaque::new(mech.to_vec()),
        options: vec![option(LOCALNAME_OPTION, b"")],
        ..Default::default()
    };
    let res: ResImportAndCanonName = match make_call(GssxProc::ImportAndCanonName, &arg) {
        Ok(r) => r,
        Err(e) => return (consts::GSS_S_FAILURE, e.errno() as u32, None),
    };
    if res.status.major_status != 0 {
        save_status(&res.status);
        return (
            res.status.major_status as u32,
            res.status.minor_status as u32,
            None,
        );
    }
    match find_option(&res.options, LOCALNAME_OPTION) {
        Some(v) => (GSS_S_COMPLETE, 0, Some(v.as_slice().to_vec())),
        None => (consts::GSS_S_FAILURE, libc::ENOTSUP as u32, None),
    }
}

/// Result of [`inquire_name`].
pub struct InquireName {
    pub name_is_mn: bool,
    pub name_type: Vec<u8>,
    pub attrs: Vec<Vec<u8>>,
}

/// `gpm_inquire_name`: returns whether the name is a mechanism name, its
/// name-type bytes (mapped to a static OID by the caller), and its attribute
/// keys.
pub fn inquire_name(name: &GssxName) -> InquireName {
    InquireName {
        name_is_mn: !name.exported_name.is_empty(),
        name_type: name.name_type.as_slice().to_vec(),
        attrs: name
            .name_attributes
            .iter()
            .map(|a| a.attr.as_slice().to_vec())
            .collect(),
    }
}

/// `gpm_compare_name`: byte-for-byte port of the (quirky) C comparison.
pub fn compare_name(name1: &GssxName, name2: &GssxName) -> (u32, u32, bool) {
    let mut n1 = name1.clone();
    let mut n2 = name2.clone();
    let (maj1, min1, b1, t1) = display_name(&mut n1);
    if maj1 != GSS_S_COMPLETE {
        return (maj1, min1, false);
    }
    let (maj2, min2, b2, t2) = display_name(&mut n2);
    if maj2 != GSS_S_COMPLETE {
        return (maj2, min2, false);
    }

    // C: c = len1 - len2; if 0, memcmp; if still 0, c = gss_oid_equal(t1,t2).
    // *name_equal = (c != 0). (This mirrors the upstream behaviour verbatim.)
    let mut c: i64 = b1.len() as i64 - b2.len() as i64;
    if c == 0 {
        c = match b1.cmp(&b2) {
            std::cmp::Ordering::Equal => {
                if t1 == t2 {
                    1
                } else {
                    0
                }
            }
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Greater => 1,
        };
    }
    (GSS_S_COMPLETE, 0, c != 0)
}

// ===========================================================================
// Credentials (gpm_acquire_cred.c)
// ===========================================================================

/// Result of [`acquire_cred`].
pub struct AcquireCred {
    pub major: u32,
    pub minor: u32,
    pub cred: Option<GssxCred>,
    pub time_rec: u32,
}

/// `gpm_acquire_cred`: GSSX_ACQUIRE_CRED.
pub fn acquire_cred(
    in_cred: Option<&GssxCred>,
    desired_name: Option<&GssxName>,
    time_req: u32,
    desired_mechs: &[Vec<u8>],
    cred_usage: i32,
    impersonate: bool,
) -> AcquireCred {
    let mut options = Vec::new();
    if impersonate {
        options.push(option(ACQUIRE_TYPE_OPTION, ACQUIRE_IMPERSONATE_NAME));
    }
    let arg = ArgAcquireCred {
        input_cred_handle: in_cred.cloned(),
        desired_name: desired_name.cloned(),
        time_req: time_req as u64,
        desired_mechs: desired_mechs
            .iter()
            .map(|m| Opaque::new(m.clone()))
            .collect(),
        cred_usage: cred_usage_to_gssx(cred_usage),
        options,
        ..Default::default()
    };
    let res: ResAcquireCred = match make_call(GssxProc::AcquireCred, &arg) {
        Ok(r) => r,
        Err(e) => {
            return AcquireCred {
                major: consts::GSS_S_FAILURE,
                minor: e.errno() as u32,
                cred: None,
                time_rec: 0,
            };
        }
    };
    if res.status.major_status != 0 {
        save_status(&res.status);
        return AcquireCred {
            major: res.status.major_status as u32,
            minor: res.status.minor_status as u32,
            cred: None,
            time_rec: 0,
        };
    }
    let mut time_rec = 0u32;
    if let Some(c) = &res.output_cred_handle
        && let Some(e) = c.elements.first()
    {
        time_rec = std::cmp::min(e.initiator_time_rec, e.acceptor_time_rec) as u32;
    }
    AcquireCred {
        major: GSS_S_COMPLETE,
        minor: 0,
        cred: res.output_cred_handle,
        time_rec,
    }
}

/// Result of [`inquire_cred`].
pub struct InquireCred {
    pub major: u32,
    pub minor: u32,
    pub name: Option<GssxName>,
    pub lifetime: u32,
    pub usage: i32,
    pub mechs: Vec<Vec<u8>>,
}

/// `gpm_inquire_cred`: derive overall name/lifetime/usage/mechs from a cred's
/// elements (no RPC).
pub fn inquire_cred(cred: &GssxCred) -> InquireCred {
    if cred.elements.is_empty() {
        return InquireCred {
            major: consts::GSS_S_FAILURE,
            minor: 0,
            name: None,
            lifetime: 0,
            usage: 0,
            mechs: Vec::new(),
        };
    }
    let mut life = GSS_C_INDEFINITE;
    let mut cu: i32 = -1;
    let mut mechs = Vec::new();
    for e in &cred.elements {
        match e.cred_usage {
            GSSX_C_INITIATE => {
                if e.initiator_time_rec != 0 && (e.initiator_time_rec as u32) < life {
                    life = e.initiator_time_rec as u32;
                }
                cu = match cu {
                    GSS_C_BOTH => GSS_C_BOTH,
                    GSS_C_ACCEPT => GSS_C_BOTH,
                    _ => GSS_C_INITIATE,
                };
            }
            GSSX_C_ACCEPT => {
                if e.acceptor_time_rec != 0 && (e.acceptor_time_rec as u32) < life {
                    life = e.acceptor_time_rec as u32;
                }
                cu = match cu {
                    GSS_C_BOTH => GSS_C_BOTH,
                    GSS_C_INITIATE => GSS_C_BOTH,
                    _ => GSS_C_ACCEPT,
                };
            }
            GSSX_C_BOTH => {
                if e.initiator_time_rec != 0 && (e.initiator_time_rec as u32) < life {
                    life = e.initiator_time_rec as u32;
                }
                if e.acceptor_time_rec != 0 && (e.acceptor_time_rec as u32) < life {
                    life = e.acceptor_time_rec as u32;
                }
                cu = GSS_C_BOTH;
            }
            _ => {}
        }
        mechs.push(e.mech.as_slice().to_vec());
    }
    InquireCred {
        major: GSS_S_COMPLETE,
        minor: 0,
        name: Some(cred.desired_name.clone()),
        lifetime: life,
        usage: cu,
        mechs,
    }
}

/// Result of [`inquire_cred_by_mech`].
pub struct InquireCredByMech {
    pub major: u32,
    pub minor: u32,
    pub name: Option<GssxName>,
    pub initiator_lifetime: u32,
    pub acceptor_lifetime: u32,
    pub usage: i32,
}

/// `gpm_inquire_cred_by_mech`.
pub fn inquire_cred_by_mech(cred: &GssxCred, mech_type: &[u8]) -> InquireCredByMech {
    let mut out = InquireCredByMech {
        major: consts::GSS_S_FAILURE,
        minor: 0,
        name: None,
        initiator_lifetime: 0,
        acceptor_lifetime: 0,
        usage: 0,
    };
    if cred.elements.is_empty() {
        return out;
    }
    for e in &cred.elements {
        if e.mech.as_slice() != mech_type {
            continue;
        }
        match e.cred_usage {
            GSSX_C_INITIATE => {
                out.initiator_lifetime = e.initiator_time_rec as u32;
                out.usage = GSS_C_INITIATE;
            }
            GSSX_C_ACCEPT => {
                out.acceptor_lifetime = e.acceptor_time_rec as u32;
                out.usage = GSS_C_ACCEPT;
            }
            GSSX_C_BOTH => {
                out.initiator_lifetime = e.initiator_time_rec as u32;
                out.acceptor_lifetime = e.acceptor_time_rec as u32;
                out.usage = GSS_C_BOTH;
            }
            _ => {}
        }
        out.major = GSS_S_COMPLETE;
        out.name = Some(e.mn.clone());
        return out;
    }
    out
}

// ===========================================================================
// Context establishment (gpm_init_sec_context.c / gpm_accept_sec_context.c)
// ===========================================================================

/// Result of [`init_sec_context`].
pub struct InitSecContext {
    pub major: u32,
    pub minor: u32,
    pub context: Option<GssxCtx>,
    pub output_token: Option<Vec<u8>>,
    pub actual_mech: Vec<u8>,
    pub out_cred: Option<GssxCred>,
}

/// `gpm_init_sec_context`: GSSX_INIT_SEC_CONTEXT (always requests cred sync).
#[allow(clippy::too_many_arguments)]
pub fn init_sec_context(
    cred: Option<&GssxCred>,
    context: Option<&GssxCtx>,
    target: Option<&GssxName>,
    mech: &[u8],
    req_flags: u32,
    time_req: u32,
    input_cb: Option<&GssxCb>,
    input_token: Option<&[u8]>,
) -> InitSecContext {
    let arg = ArgInitSecContext {
        context_handle: context.cloned(),
        cred_handle: cred.cloned(),
        target_name: target.cloned(),
        mech_type: Opaque::new(mech.to_vec()),
        req_flags: req_flags as u64,
        time_req: time_req as u64,
        input_cb: input_cb.cloned(),
        input_token: input_token.map(|t| Opaque::new(t.to_vec())),
        options: vec![option(CRED_SYNC_OPTION, CRED_SYNC_DEFAULT)],
        ..Default::default()
    };
    let res: ResInitSecContext = match make_call(GssxProc::InitSecContext, &arg) {
        Ok(r) => r,
        Err(e) => {
            save_internal_status(e.errno() as u32, &e.to_string());
            return InitSecContext {
                major: consts::GSS_S_FAILURE,
                minor: e.errno() as u32,
                context: None,
                output_token: None,
                actual_mech: Vec::new(),
                out_cred: None,
            };
        }
    };

    let actual_mech = res.status.mech.as_slice().to_vec();
    let major = res.status.major_status as u32;
    let minor = res.status.minor_status as u32;
    save_status(&res.status);

    let keep = major == GSS_S_COMPLETE || major == GSS_S_CONTINUE_NEEDED;

    // Cred sync: a returned gssx_cred is XDR-encoded inside the option value.
    let mut out_cred = None;
    if let Some(v) = find_option(&res.options, CRED_SYNC_PAYLOAD) {
        let mut d = XdrDecoder::new(v.as_slice());
        if let Ok(c) = GssxCred::decode(&mut d) {
            out_cred = Some(c);
        }
    }

    InitSecContext {
        major,
        minor,
        context: if keep { res.context_handle } else { None },
        output_token: if keep {
            res.output_token.map(|t| t.0)
        } else {
            None
        },
        actual_mech,
        out_cred,
    }
}

/// Result of [`accept_sec_context`].
pub struct AcceptSecContext {
    pub major: u32,
    pub minor: u32,
    pub context: Option<GssxCtx>,
    pub src_name: Option<GssxName>,
    pub output_token: Option<Vec<u8>>,
    pub actual_mech: Vec<u8>,
    pub delegated_cred: Option<GssxCred>,
}

/// `gpm_accept_sec_context`: GSSX_ACCEPT_SEC_CONTEXT.
pub fn accept_sec_context(
    context: Option<&GssxCtx>,
    acceptor_cred: Option<&GssxCred>,
    input_token: &[u8],
    input_cb: Option<&GssxCb>,
    want_deleg: bool,
) -> AcceptSecContext {
    let arg = ArgAcceptSecContext {
        context_handle: context.cloned(),
        cred_handle: acceptor_cred.cloned(),
        input_token: Opaque::new(input_token.to_vec()),
        input_cb: input_cb.cloned(),
        ret_deleg_cred: want_deleg,
        ..Default::default()
    };
    let res: ResAcceptSecContext = match make_call(GssxProc::AcceptSecContext, &arg) {
        Ok(r) => r,
        Err(e) => {
            return AcceptSecContext {
                major: consts::GSS_S_FAILURE,
                minor: e.errno() as u32,
                context: None,
                src_name: None,
                output_token: None,
                actual_mech: Vec::new(),
                delegated_cred: None,
            };
        }
    };

    if res.status.major_status != 0 {
        save_status(&res.status);
        return AcceptSecContext {
            major: res.status.major_status as u32,
            minor: res.status.minor_status as u32,
            context: None,
            src_name: None,
            output_token: None,
            actual_mech: res.status.mech.as_slice().to_vec(),
            delegated_cred: None,
        };
    }

    let ctx = match res.context_handle {
        Some(c) => c,
        None => {
            return AcceptSecContext {
                major: consts::GSS_S_FAILURE,
                minor: libc::EINVAL as u32,
                context: None,
                src_name: None,
                output_token: None,
                actual_mech: Vec::new(),
                delegated_cred: None,
            };
        }
    };

    let src_name = Some(ctx.src_name.clone());
    AcceptSecContext {
        major: GSS_S_COMPLETE,
        minor: 0,
        src_name,
        output_token: res.output_token.map(|t| t.0),
        actual_mech: res.status.mech.as_slice().to_vec(),
        delegated_cred: res.delegated_cred_handle,
        context: Some(ctx),
    }
}

// ===========================================================================
// Context inquiry / release (gpm_inquire_context.c / gpm_release_handle.c)
// ===========================================================================

/// Result of [`inquire_context`].
pub struct InquireContext {
    pub src_name: GssxName,
    pub targ_name: GssxName,
    pub lifetime: u32,
    pub mech: Vec<u8>,
    pub ctx_flags: u32,
    pub locally_initiated: bool,
    pub open: bool,
}

/// `gpm_inquire_context`: read context attributes from a cached `gssx_ctx`.
pub fn inquire_context(ctx: &GssxCtx) -> InquireContext {
    InquireContext {
        src_name: ctx.src_name.clone(),
        targ_name: ctx.targ_name.clone(),
        lifetime: ctx.lifetime as u32,
        mech: ctx.mech.as_slice().to_vec(),
        ctx_flags: ctx.ctx_flags as u32,
        locally_initiated: ctx.locally_initiated,
        open: ctx.open,
    }
}

/// `gpm_release_cred`: GSSX_RELEASE_HANDLE when the cred needs daemon release.
pub fn release_cred(cred: &GssxCred) -> (u32, u32) {
    if !cred.needs_release {
        return (GSS_S_COMPLETE, 0);
    }
    let arg = ArgReleaseHandle {
        call_ctx: Default::default(),
        cred_handle: gssproxy_proto::gssx::GssxHandle::Cred(cred.clone()),
    };
    let res: ResReleaseHandle = match make_call(GssxProc::ReleaseHandle, &arg) {
        Ok(r) => r,
        Err(e) => return (consts::GSS_S_FAILURE, e.errno() as u32),
    };
    if res.status.major_status != 0 {
        save_status(&res.status);
        return (
            res.status.major_status as u32,
            res.status.minor_status as u32,
        );
    }
    (GSS_S_COMPLETE, 0)
}

/// `gpm_delete_sec_context`: GSSX_RELEASE_HANDLE when the ctx needs release.
pub fn delete_sec_context(ctx: &GssxCtx) -> (u32, u32) {
    if !ctx.needs_release {
        return (GSS_S_COMPLETE, 0);
    }
    let arg = ArgReleaseHandle {
        call_ctx: Default::default(),
        cred_handle: gssproxy_proto::gssx::GssxHandle::SecCtx(ctx.clone()),
    };
    let res: ResReleaseHandle = match make_call(GssxProc::ReleaseHandle, &arg) {
        Ok(r) => r,
        Err(e) => return (consts::GSS_S_FAILURE, e.errno() as u32),
    };
    if res.status.major_status != 0 {
        save_status(&res.status);
        return (
            res.status.major_status as u32,
            res.status.minor_status as u32,
        );
    }
    (GSS_S_COMPLETE, 0)
}

// ===========================================================================
// Mech inquiry (gpm_indicate_mechs.c)
// ===========================================================================

/// `gpm_indicate_mechs` (raw): GSSX_INDICATE_MECHS, returning the wire result
/// for the interposer to build its static-OID mech cache from.
pub fn indicate_mechs() -> (u32, u32, ResIndicateMechs) {
    let arg = ArgIndicateMechs::default();
    match make_call::<_, ResIndicateMechs>(GssxProc::IndicateMechs, &arg) {
        Ok(res) => {
            if res.status.major_status != 0 {
                save_status(&res.status);
            }
            (
                res.status.major_status as u32,
                res.status.minor_status as u32,
                res,
            )
        }
        Err(e) => (
            consts::GSS_S_FAILURE,
            e.errno() as u32,
            ResIndicateMechs::default(),
        ),
    }
}

// ===========================================================================
// Message protection (gpm_wrap.c / unwrap / get_mic / verify_mic /
// wrap_size_limit). The interposer performs these locally, so these wrappers
// exist for completeness of the gpm library surface and are not on its hot
// path.
// ===========================================================================

/// `gpm_wrap`: GSSX_WRAP, returning `(major, minor, token, conf_state)`.
pub fn wrap(
    ctx: &GssxCtx,
    conf_req: bool,
    qop: u32,
    message: &[u8],
) -> (u32, u32, Option<Vec<u8>>, bool) {
    let arg = ArgWrap {
        context_handle: ctx.clone(),
        conf_req,
        message_buffer: vec![Opaque::new(message.to_vec())],
        qop_state: qop as u64,
        ..Default::default()
    };
    let res: ResWrap = match make_call(GssxProc::Wrap, &arg) {
        Ok(r) => r,
        Err(e) => return (consts::GSS_S_FAILURE, e.errno() as u32, None, false),
    };
    if res.status.major_status != 0 {
        save_status(&res.status);
        return (
            res.status.major_status as u32,
            res.status.minor_status as u32,
            None,
            false,
        );
    }
    (
        GSS_S_COMPLETE,
        0,
        res.token_buffer.into_iter().next().map(|t| t.0),
        res.conf_state.unwrap_or(false),
    )
}

/// `gpm_unwrap`: GSSX_UNWRAP, returning `(major, minor, message, conf, qop)`.
pub fn unwrap(ctx: &GssxCtx, token: &[u8]) -> (u32, u32, Option<Vec<u8>>, bool, u32) {
    let arg = ArgUnwrap {
        context_handle: ctx.clone(),
        token_buffer: vec![Opaque::new(token.to_vec())],
        ..Default::default()
    };
    let res: ResUnwrap = match make_call(GssxProc::Unwrap, &arg) {
        Ok(r) => r,
        Err(e) => return (consts::GSS_S_FAILURE, e.errno() as u32, None, false, 0),
    };
    if res.status.major_status != 0 {
        save_status(&res.status);
        return (
            res.status.major_status as u32,
            res.status.minor_status as u32,
            None,
            false,
            0,
        );
    }
    (
        GSS_S_COMPLETE,
        0,
        res.message_buffer.into_iter().next().map(|t| t.0),
        res.conf_state.unwrap_or(false),
        res.qop_state.unwrap_or(0) as u32,
    )
}

/// `gpm_get_mic`: GSSX_GET_MIC.
pub fn get_mic(ctx: &GssxCtx, qop: u32, message: &[u8]) -> (u32, u32, Option<Vec<u8>>) {
    let arg = ArgGetMic {
        context_handle: ctx.clone(),
        qop_req: qop as u64,
        message_buffer: Opaque::new(message.to_vec()),
        ..Default::default()
    };
    let res: ResGetMic = match make_call(GssxProc::GetMic, &arg) {
        Ok(r) => r,
        Err(e) => return (consts::GSS_S_FAILURE, e.errno() as u32, None),
    };
    if res.status.major_status != 0 {
        save_status(&res.status);
        return (
            res.status.major_status as u32,
            res.status.minor_status as u32,
            None,
        );
    }
    (GSS_S_COMPLETE, 0, Some(res.token_buffer.0))
}

/// `gpm_verify_mic`: GSSX_VERIFY.
pub fn verify_mic(ctx: &GssxCtx, message: &[u8], token: &[u8]) -> (u32, u32, u32) {
    let arg = ArgVerifyMic {
        context_handle: ctx.clone(),
        message_buffer: Opaque::new(message.to_vec()),
        token_buffer: Opaque::new(token.to_vec()),
        ..Default::default()
    };
    let res: ResVerifyMic = match make_call(GssxProc::VerifyMic, &arg) {
        Ok(r) => r,
        Err(e) => return (consts::GSS_S_FAILURE, e.errno() as u32, 0),
    };
    if res.status.major_status != 0 {
        save_status(&res.status);
        return (
            res.status.major_status as u32,
            res.status.minor_status as u32,
            0,
        );
    }
    (GSS_S_COMPLETE, 0, res.qop_state.unwrap_or(0) as u32)
}

/// `gpm_wrap_size_limit`: GSSX_WRAP_SIZE_LIMIT.
pub fn wrap_size_limit(
    ctx: &GssxCtx,
    conf_req: bool,
    qop: u32,
    req_output_size: u32,
) -> (u32, u32, u32) {
    let arg = ArgWrapSizeLimit {
        context_handle: ctx.clone(),
        conf_req,
        qop_state: qop as u64,
        req_output_size: req_output_size as u64,
        ..Default::default()
    };
    let res: ResWrapSizeLimit = match make_call(GssxProc::WrapSizeLimit, &arg) {
        Ok(r) => r,
        Err(e) => return (consts::GSS_S_FAILURE, e.errno() as u32, 0),
    };
    if res.status.major_status != 0 {
        save_status(&res.status);
        return (
            res.status.major_status as u32,
            res.status.minor_status as u32,
            0,
        );
    }
    (GSS_S_COMPLETE, 0, res.max_input_size as u32)
}

/// Encode a `gssx_cred` to its XDR bytes (used to stash a cred in a ccache).
pub fn encode_cred(cred: &GssxCred) -> Vec<u8> {
    let mut e = XdrEncoder::new();
    cred.encode(&mut e);
    e.into_bytes()
}

/// Decode a `gssx_cred` from its XDR bytes (the ccache `ticket` blob).
pub fn decode_cred(bytes: &[u8]) -> Option<GssxCred> {
    let mut d = XdrDecoder::new(bytes);
    GssxCred::decode(&mut d).ok()
}
