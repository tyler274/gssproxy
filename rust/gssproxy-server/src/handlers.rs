//! Per-procedure handlers. Each takes the decoded `gssx_arg_*` and returns the
//! `gssx_res_*`, mirroring the `gp_rpc_*` functions in `src/`.
//!
//! Implemented so far: `indicate_mechs` (1) and `import_and_canon_name` (3).
//! The remaining procedures return a faithful failure result (correct result
//! shape, `GSS_S_FAILURE` status) until they are ported.

use gssapi_sys::consts;
use gssapi_sys::wrap::{self, GssError};
use gssproxy_proto::gssx::*;
use gssproxy_proto::proc::*;

use crate::call::CallContext;
use crate::conv;

/// The `localname` special option key, matched/emitted exactly as the C daemon
/// does: `sizeof("localname")` includes the trailing NUL, so the wire key is
/// the 10-byte `b"localname\0"`.
const LOCALNAME_OPTION: &[u8] = b"localname\0";

const EINVAL: u32 = 22;

fn success(mech: Option<&[u8]>) -> GssxStatus {
    conv::status_to_gssx(0, 0, mech)
}

fn failure() -> GssxStatus {
    conv::status_to_gssx(consts::GSS_S_FAILURE, 0, None)
}

fn oids_to_gssx(oids: &[Vec<u8>]) -> GssxOidSet {
    oids.iter().map(|o| Opaque::new(o.clone())).collect()
}

fn find_option<'a>(options: &'a [GssxOption], key: &[u8]) -> Option<&'a GssxOption> {
    options.iter().find(|o| o.option.as_slice() == key)
}

// ---- indicate_mechs (1) ----

pub fn indicate_mechs(_ctx: &CallContext, _arg: ArgIndicateMechs) -> ResIndicateMechs {
    let mut res = ResIndicateMechs::default();
    res.status = match build_indicate_mechs(&mut res) {
        Ok(()) => success(None),
        Err(e) => conv::status_to_gssx(e.major, e.minor, None),
    };
    res
}

fn build_indicate_mechs(res: &mut ResIndicateMechs) -> wrap::Result<()> {
    let mechs = wrap::indicate_mechs()?;
    // Accumulate the union of all mechanisms' attributes, in first-seen order,
    // matching the attr_set the C handler builds with gss_add_oid_set_member.
    let mut attr_set: Vec<Vec<u8>> = Vec::new();

    for mech in &mechs {
        // A mechanism whose name-types can't be inquired is skipped (the C code
        // logs the offender and drops it from the list).
        let name_types = match wrap::inquire_names_for_mech(mech) {
            Ok(nt) => nt,
            Err(_) => continue,
        };
        let (mech_attrs, known_mech_attrs) = wrap::inquire_attrs_for_mech(mech)?;
        for a in mech_attrs.iter().chain(known_mech_attrs.iter()) {
            if !attr_set.contains(a) {
                attr_set.push(a.clone());
            }
        }
        let (sasl, mech_name, mech_desc) = wrap::inquire_saslname_for_mech(mech)?;

        res.mechs.push(GssxMechInfo {
            mech: Opaque::new(mech.clone()),
            name_types: oids_to_gssx(&name_types),
            mech_attrs: oids_to_gssx(&mech_attrs),
            known_mech_attrs: oids_to_gssx(&known_mech_attrs),
            saslname_sasl_mech_name: Opaque::new(sasl),
            saslname_mech_name: Opaque::new(mech_name),
            saslname_mech_desc: Opaque::new(mech_desc),
            ..Default::default()
        });
    }

    for attr in &attr_set {
        let (name, short_desc, long_desc) = wrap::display_mech_attr(attr)?;
        res.mech_attr_descs.push(GssxMechAttr {
            attr: Opaque::new(attr.clone()),
            name: Opaque::new(name),
            short_desc: Opaque::new(short_desc),
            long_desc: Opaque::new(long_desc),
            ..Default::default()
        });
    }
    Ok(())
}

// ---- import_and_canon_name (3) ----

pub fn import_and_canon_name(
    _ctx: &CallContext,
    arg: ArgImportAndCanonName,
) -> ResImportAndCanonName {
    let mut res = ResImportAndCanonName::default();
    let mech = if arg.mech.is_empty() {
        None
    } else {
        Some(arg.mech.as_slice())
    };
    res.status = match build_import_and_canon_name(&arg, &mut res) {
        Ok(()) => success(mech),
        Err(e) => conv::status_to_gssx(e.major, e.minor, mech),
    };
    res
}

fn build_import_and_canon_name(
    arg: &ArgImportAndCanonName,
    res: &mut ResImportAndCanonName,
) -> wrap::Result<()> {
    if arg.input_name.display_name.is_empty() && arg.input_name.exported_name.is_empty() {
        return Err(GssError {
            major: consts::GSS_S_FAILURE,
            minor: EINVAL,
            messages: Vec::new(),
        });
    }

    let import_name = conv::gssx_to_name(&arg.input_name)?;
    let mech = if arg.mech.is_empty() {
        None
    } else {
        Some(arg.mech.as_slice())
    };

    // gss_localname is exposed via the special "localname" option.
    if find_option(&arg.options, LOCALNAME_OPTION).is_some() {
        let localname = import_name.localname(mech)?;
        res.options.push(GssxOption {
            option: Opaque::new(LOCALNAME_OPTION.to_vec()),
            value: Opaque::new(localname),
        });
        return Ok(());
    }

    let output_name = match mech {
        Some(m) => import_name.canonicalize(m)?,
        None => import_name,
    };
    res.output_name = Some(conv::name_to_gssx(&output_name)?);
    Ok(())
}

// ---- not-yet-implemented procedures ----
//
// These return the correct result shape with a GSS_S_FAILURE status so the
// daemon stays wire-valid while the remaining handlers are ported.

// `get_call_context`, `export_cred`, `import_cred` and `store_cred` are
// `GP_EXEC_UNUSED_FUNC` stubs in the C daemon (`src/gp_rpc_process.c`): they
// return RPC success with a zero-initialized result, i.e. `GSS_S_COMPLETE` and
// an empty body. We return the same default-zeroed result so the bytes on the
// wire match the C oracle exactly (a `GSS_S_FAILURE` here would not).

pub fn get_call_context(_ctx: &CallContext, _arg: ArgGetCallContext) -> ResGetCallContext {
    ResGetCallContext::default()
}

pub fn export_cred(_ctx: &CallContext, _arg: ArgExportCred) -> ResExportCred {
    ResExportCred::default()
}

pub fn import_cred(_ctx: &CallContext, _arg: ArgImportCred) -> ResImportCred {
    ResImportCred::default()
}

pub fn store_cred(_ctx: &CallContext, _arg: ArgStoreCred) -> ResStoreCred {
    ResStoreCred::default()
}

// acquire_cred is genuinely implemented in the C daemon; this remains a
// wire-valid placeholder (GSS_S_FAILURE) until the credential acquisition path
// is ported.
pub fn acquire_cred(_ctx: &CallContext, _arg: ArgAcquireCred) -> ResAcquireCred {
    ResAcquireCred {
        status: failure(),
        ..Default::default()
    }
}

pub fn init_sec_context(_ctx: &CallContext, _arg: ArgInitSecContext) -> ResInitSecContext {
    ResInitSecContext {
        status: failure(),
        ..Default::default()
    }
}

pub fn accept_sec_context(_ctx: &CallContext, _arg: ArgAcceptSecContext) -> ResAcceptSecContext {
    ResAcceptSecContext {
        status: failure(),
        ..Default::default()
    }
}

/// The daemon is stateless (every handle is returned with `needs_release =
/// false`), so a client should never need to release anything. Mirror the C
/// handler: `GSS_S_UNAVAILABLE` for the known handle types, and
/// `GSS_S_CALL_BAD_STRUCTURE` for anything else.
pub fn release_handle(_ctx: &CallContext, arg: ArgReleaseHandle) -> ResReleaseHandle {
    let major = match arg.cred_handle {
        GssxHandle::SecCtx(_) | GssxHandle::Cred(_) => consts::GSS_S_UNAVAILABLE,
        GssxHandle::Extensions { .. } => consts::GSS_S_CALL_BAD_STRUCTURE,
    };
    ResReleaseHandle {
        status: conv::status_to_gssx(major, 0, None),
    }
}

pub fn get_mic(_ctx: &CallContext, _arg: ArgGetMic) -> ResGetMic {
    ResGetMic {
        status: failure(),
        ..Default::default()
    }
}

pub fn verify_mic(_ctx: &CallContext, _arg: ArgVerifyMic) -> ResVerifyMic {
    ResVerifyMic {
        status: failure(),
        ..Default::default()
    }
}

pub fn wrap_msg(_ctx: &CallContext, _arg: ArgWrap) -> ResWrap {
    ResWrap {
        status: failure(),
        ..Default::default()
    }
}

pub fn unwrap_msg(_ctx: &CallContext, _arg: ArgUnwrap) -> ResUnwrap {
    ResUnwrap {
        status: failure(),
        ..Default::default()
    }
}

pub fn wrap_size_limit(_ctx: &CallContext, _arg: ArgWrapSizeLimit) -> ResWrapSizeLimit {
    ResWrapSizeLimit {
        status: failure(),
        ..Default::default()
    }
}
