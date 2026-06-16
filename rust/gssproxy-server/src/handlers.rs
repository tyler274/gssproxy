//! Per-procedure handlers. Each takes the decoded `gssx_arg_*` and returns the
//! `gssx_res_*`, mirroring the `gp_rpc_*` functions in `src/`.
//!
//! Implemented so far: `indicate_mechs` (1) and `import_and_canon_name` (3).
//! The remaining procedures return a faithful failure result (correct result
//! shape, `GSS_S_FAILURE` status) until they are ported.

use gssapi_sys::consts;
use gssapi_sys::wrap::{self, Cred, GssError};
use gssproxy_proto::gssx::*;
use gssproxy_proto::proc::*;

use crate::call::CallContext;
use crate::config::Service;
use crate::conv::{self, ExpCtxType};
use crate::creds::{self, AcquireType};

// GSS_C_* credential usage values (gssapi.h).
const GSS_C_INITIATE: i32 = 1;
const GSS_C_ACCEPT: i32 = 2;
/// `GSS_C_DELEG_FLAG`.
const GSS_C_DELEG_FLAG: u32 = 1;

/// `gp_filter_flags`: apply the service's enforced/filtered request flags.
fn filter_flags(svc: &Service, mut flags: u32) -> u32 {
    flags |= svc.enforce_flags;
    flags &= !svc.filter_flags;
    flags
}

/// Borrow a `gssx_cb` as [`wrap::ChannelBindings`].
fn to_cb(c: &GssxCb) -> wrap::ChannelBindings<'_> {
    wrap::ChannelBindings {
        initiator_addrtype: c.initiator_addrtype as u32,
        initiator_address: c.initiator_address.as_slice(),
        acceptor_addrtype: c.acceptor_addrtype as u32,
        acceptor_address: c.acceptor_address.as_slice(),
        application_data: c.application_data.as_slice(),
    }
}

fn status_err(e: &GssError) -> GssxStatus {
    conv::status_to_gssx(e.major, e.minor, None)
}

/// `GSS_S_FAILURE` / `EINVAL`, used when required call context is missing.
fn invalid() -> GssError {
    GssError {
        major: consts::GSS_S_FAILURE,
        minor: EINVAL,
        messages: Vec::new(),
    }
}

/// The `localname` special option key, matched/emitted exactly as the C daemon
/// does: `sizeof("localname")` includes the trailing NUL, so the wire key is
/// the 10-byte `b"localname\0"`.
const LOCALNAME_OPTION: &[u8] = b"localname\0";

const EINVAL: u32 = 22;

fn success(mech: Option<&[u8]>) -> GssxStatus {
    conv::status_to_gssx(0, 0, mech)
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

// `gp_export_cred`, `gp_import_cred`, and `gp_store_cred` are `GP_EXEC_UNUSED_FUNC`
// in the C daemon: they leave the (zero-initialized) result untouched and return
// success. A defaulted result encodes byte-identically (COMPLETE status, no
// handle, empty option/oid sets).

pub fn export_cred(_ctx: &CallContext, _arg: ArgExportCred) -> ResExportCred {
    ResExportCred::default()
}

pub fn import_cred(_ctx: &CallContext, _arg: ArgImportCred) -> ResImportCred {
    ResImportCred::default()
}

pub fn store_cred(_ctx: &CallContext, _arg: ArgStoreCred) -> ResStoreCred {
    ResStoreCred::default()
}

/// `gp_acquire_cred`: acquire a krb5 credential for the matched service.
///
/// Only the non-impersonation `ACQ_NORMAL` (and trivial `ACQ_IMPNAME` without
/// impersonation) paths are supported; impersonating acquisitions return
/// `GSS_S_FAILURE` from [`creds::add_krb5_creds`].
pub fn acquire_cred(ctx: &CallContext, arg: ArgAcquireCred) -> ResAcquireCred {
    let (major, minor, output, mech) = acquire_cred_inner(ctx, &arg);
    ResAcquireCred {
        status: conv::status_to_gssx(major, minor, mech.as_deref()),
        output_cred_handle: output,
        options: Vec::new(),
    }
}

/// `gp_get_acquire_type`: inspect the `acquire_type` option. `None` mirrors the
/// C `-1` ("invalid") return.
fn get_acquire_type(arg: &ArgAcquireCred) -> Option<AcquireType> {
    // sizeof() in the C macros includes the trailing NUL.
    const KEY: &[u8] = b"acquire_type\0";
    const IMPERSONATE: &[u8] = b"impersonate_name\0";
    for opt in &arg.options {
        if opt.option.as_slice() == KEY {
            return if opt.value.as_slice() == IMPERSONATE {
                Some(AcquireType::ImpName)
            } else {
                None
            };
        }
    }
    Some(AcquireType::Normal)
}

fn acquire_cred_inner(
    ctx: &CallContext,
    arg: &ArgAcquireCred,
) -> (u32, u32, Option<GssxCred>, Option<Vec<u8>>) {
    let Some(svc) = &ctx.service else {
        return (consts::GSS_S_FAILURE, EINVAL, None, None);
    };
    let Some(handle) = ctx.creds.as_deref() else {
        return (consts::GSS_S_FAILURE, EINVAL, None, None);
    };

    let mut in_cred: Option<Cred> = None;
    let mut acquire_type = AcquireType::Normal;
    if let Some(ic) = &arg.input_cred_handle {
        match conv::import_gssx_cred(handle, ic) {
            Ok(c) => in_cred = c,
            Err(e) => return (e.major, e.minor, None, None),
        }
        match get_acquire_type(arg) {
            Some(t) => acquire_type = t,
            None => return (consts::GSS_S_FAILURE, EINVAL, None, None),
        }
    }

    // A specified mech list must include an allowed (krb5) mech; otherwise an
    // empty desired_mechs falls back to the supported set (krb5).
    if !arg.desired_mechs.is_empty()
        && !arg
            .desired_mechs
            .iter()
            .any(|m| creds::allowed_mech(svc, m.as_slice()))
    {
        return (consts::GSS_S_NO_CRED, 0, None, None);
    }

    let mech = Some(consts::KRB5_MECH_OID.to_vec());
    let cred_usage = conv::gssx_to_cred_usage(arg.cred_usage);

    let acquired = match creds::add_krb5_creds(
        ctx,
        svc,
        acquire_type,
        in_cred.as_ref(),
        arg.desired_name.as_ref(),
        cred_usage,
    ) {
        Ok(a) => a,
        Err(e) => return (e.major, e.minor, None, mech),
    };

    // Reproduce the C pointer dance: when adding to the input handle, or when
    // no separate cred was acquired, reuse the input handle bytes verbatim.
    let (reuse_input, final_cred): (bool, Option<Cred>) = if arg.add_cred_to_input_handle {
        if in_cred.is_some() || acquired.is_some() {
            (true, None)
        } else {
            return (consts::GSS_S_NO_CRED, 0, None, mech);
        }
    } else if let Some(c) = acquired {
        (false, Some(c))
    } else if in_cred.is_some() {
        (true, None)
    } else {
        return (consts::GSS_S_NO_CRED, 0, None, mech);
    };

    if reuse_input {
        return (0, 0, arg.input_cred_handle.clone(), mech);
    }

    match conv::export_gssx_cred(handle, final_cred.expect("acquired cred")) {
        Ok(g) => (0, 0, Some(g), mech),
        Err(e) => (e.major, e.minor, None, mech),
    }
}

/// `gp_init_sec_context`. The cc-sync (`gp_check_sync_creds`) path is omitted;
/// services without `allow_client_ccache_sync` never trigger it.
pub fn init_sec_context(ctx: &CallContext, arg: ArgInitSecContext) -> ResInitSecContext {
    let mut res = ResInitSecContext::default();
    let mech = arg.mech_type.as_slice().to_vec();
    let status_mech = if mech.is_empty() { None } else { Some(mech.as_slice()) };
    match init_inner(ctx, &arg) {
        Ok((continue_needed, handle, token)) => {
            let major = if continue_needed {
                gssapi_sys::sys::GSS_S_CONTINUE_NEEDED
            } else {
                0
            };
            res.status = conv::status_to_gssx(major, 0, status_mech);
            res.context_handle = Some(handle);
            res.output_token = token;
        }
        Err(e) => res.status = conv::status_to_gssx(e.major, e.minor, status_mech),
    }
    res
}

fn init_inner(
    ctx: &CallContext,
    arg: &ArgInitSecContext,
) -> Result<(bool, GssxCtx, Option<GssxBuffer>), GssError> {
    let svc = ctx.service.as_ref().ok_or_else(invalid)?;
    let handle = ctx.creds.as_deref().ok_or_else(invalid)?;

    let mut exp_type = conv::exported_context_type(&arg.call_ctx.options);

    let existing = match &arg.context_handle {
        Some(g) => Some(conv::import_gssx_ctx(g)?),
        None => None,
    };

    let mut cred = match &arg.cred_handle {
        Some(g) => conv::import_gssx_cred(handle, g)?,
        None => None,
    };

    let target = match &arg.target_name {
        Some(g) => conv::gssx_to_name(g)?,
        None => return Err(invalid()),
    };

    let mech = arg.mech_type.as_slice();

    if cred.is_none() {
        if mech == consts::KRB5_MECH_OID {
            cred = creds::add_krb5_creds(ctx, svc, AcquireType::Normal, None, None, GSS_C_INITIATE)
                .map_err(|e| GssError {
                    major: e.major,
                    minor: e.minor,
                    messages: Vec::new(),
                })?;
        } else {
            return Err(GssError {
                major: consts::GSS_S_NO_CRED,
                minor: 0,
                messages: Vec::new(),
            });
        }
    }

    if let Err(major) = creds::cred_allowed(svc, cred.as_ref(), &target) {
        return Err(GssError {
            major,
            minor: 0,
            messages: Vec::new(),
        });
    }

    let req_flags = filter_flags(svc, arg.req_flags as u32);
    let cb = arg.input_cb.as_ref().map(to_cb);
    let input = arg.input_token.as_ref().map(|b| b.as_slice()).unwrap_or(&[]);

    let r = wrap::init_sec_context(
        cred.as_ref(),
        existing,
        &target,
        mech,
        req_flags,
        arg.time_req as u32,
        cb.as_ref(),
        input,
    )?;

    if r.continue_needed {
        exp_type = ExpCtxType::Partial;
    }

    let handle_out = conv::export_gssx_ctx(r.context, exp_type, Some(mech))?;
    let token = if r.output.is_empty() {
        None
    } else {
        Some(Opaque::new(r.output))
    };
    Ok((r.continue_needed, handle_out, token))
}

/// `gp_accept_sec_context`. The cc-sync and `linux_creds_v1` export paths are
/// omitted (default `EXP_CREDS_NO_CREDS`, no `allow_client_ccache_sync`).
pub fn accept_sec_context(ctx: &CallContext, arg: ArgAcceptSecContext) -> ResAcceptSecContext {
    let mut res = ResAcceptSecContext::default();
    match accept_inner(ctx, &arg) {
        Ok((continue_needed, handle, token, deleg, mech)) => {
            let major = if continue_needed {
                gssapi_sys::sys::GSS_S_CONTINUE_NEEDED
            } else {
                0
            };
            let status_mech = if mech.is_empty() { None } else { Some(mech.as_slice()) };
            res.status = conv::status_to_gssx(major, 0, status_mech);
            res.context_handle = Some(handle);
            res.output_token = Some(token);
            res.delegated_cred_handle = deleg;
        }
        Err(e) => res.status = conv::status_to_gssx(e.major, e.minor, None),
    }
    res
}

#[allow(clippy::type_complexity)]
fn accept_inner(
    ctx: &CallContext,
    arg: &ArgAcceptSecContext,
) -> Result<(bool, GssxCtx, GssxBuffer, Option<GssxCred>, Vec<u8>), GssError> {
    let svc = ctx.service.as_ref().ok_or_else(invalid)?;
    let handle = ctx.creds.as_deref().ok_or_else(invalid)?;

    let mut exp_type = conv::exported_context_type(&arg.call_ctx.options);

    let existing = match &arg.context_handle {
        Some(g) => Some(conv::import_gssx_ctx(g)?),
        None => None,
    };

    let mut cred = match &arg.cred_handle {
        Some(g) => conv::import_gssx_cred(handle, g)?,
        None => None,
    };

    if cred.is_none() {
        cred = creds::add_krb5_creds(ctx, svc, AcquireType::Normal, None, None, GSS_C_ACCEPT)
            .map_err(|e| GssError {
                major: e.major,
                minor: e.minor,
                messages: Vec::new(),
            })?;
    }

    let cb = arg.input_cb.as_ref().map(to_cb);
    let r = wrap::accept_sec_context(
        existing,
        cred.as_ref(),
        arg.input_token.as_slice(),
        cb.as_ref(),
        arg.ret_deleg_cred,
    )?;

    if r.continue_needed {
        exp_type = ExpCtxType::Partial;
    }

    let mech = r.mech.clone();
    let output = r.output.clone();
    let ret_flags = r.ret_flags;
    let delegated = r.delegated_cred;

    let handle_out = conv::export_gssx_ctx(r.context, exp_type, Some(&mech))?;

    let deleg = if ret_flags & GSS_C_DELEG_FLAG != 0 && arg.ret_deleg_cred {
        match delegated {
            Some(dch) => Some(conv::export_gssx_cred(handle, dch)?),
            None => None,
        }
    } else {
        None
    };

    Ok((r.continue_needed, handle_out, Opaque::new(output), deleg, mech))
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

/// `gp_get_mic`.
pub fn get_mic(_ctx: &CallContext, arg: ArgGetMic) -> ResGetMic {
    let mut res = ResGetMic::default();
    let exp_type = conv::exported_context_type(&arg.call_ctx.options);
    let inner = || -> Result<(GssxCtx, Vec<u8>), GssError> {
        let context = conv::import_gssx_ctx(&arg.context_handle)?;
        let token = context.get_mic(arg.qop_req as u32, arg.message_buffer.as_slice())?;
        let handle = conv::export_gssx_ctx(context, exp_type, None)?;
        Ok((handle, token))
    };
    match inner() {
        Ok((handle, token)) => {
            res.status = success(None);
            res.context_handle = Some(handle);
            res.token_buffer = Opaque::new(token);
            res.qop_state = Some(arg.qop_req);
        }
        Err(e) => res.status = status_err(&e),
    }
    res
}

/// `gp_verify_mic`.
pub fn verify_mic(_ctx: &CallContext, arg: ArgVerifyMic) -> ResVerifyMic {
    let mut res = ResVerifyMic::default();
    let exp_type = conv::exported_context_type(&arg.call_ctx.options);
    let inner = || -> Result<(GssxCtx, u32), GssError> {
        let context = conv::import_gssx_ctx(&arg.context_handle)?;
        let qop = context.verify_mic(arg.message_buffer.as_slice(), arg.token_buffer.as_slice())?;
        let handle = conv::export_gssx_ctx(context, exp_type, None)?;
        Ok((handle, qop))
    };
    match inner() {
        Ok((handle, qop)) => {
            res.status = success(None);
            res.context_handle = Some(handle);
            res.qop_state = Some(qop as u64);
        }
        Err(e) => res.status = status_err(&e),
    }
    res
}

/// `gp_wrap`.
pub fn wrap_msg(_ctx: &CallContext, arg: ArgWrap) -> ResWrap {
    let mut res = ResWrap::default();
    let exp_type = conv::exported_context_type(&arg.call_ctx.options);
    let inner = || -> Result<(GssxCtx, Vec<u8>, bool), GssError> {
        let context = conv::import_gssx_ctx(&arg.context_handle)?;
        let input = arg.message_buffer.first().map(|b| b.as_slice()).unwrap_or(&[]);
        let (token, conf) = context.wrap(arg.conf_req, arg.qop_state as u32, input)?;
        let handle = conv::export_gssx_ctx(context, exp_type, None)?;
        Ok((handle, token, conf))
    };
    match inner() {
        Ok((handle, token, conf)) => {
            res.status = success(None);
            res.context_handle = Some(handle);
            // The C handler echoes back the *input* qop_state.
            res.qop_state = Some(arg.qop_state);
            res.conf_state = Some(conf);
            res.token_buffer = vec![Opaque::new(token)];
        }
        Err(e) => res.status = status_err(&e),
    }
    res
}

/// `gp_unwrap`.
pub fn unwrap_msg(_ctx: &CallContext, arg: ArgUnwrap) -> ResUnwrap {
    let mut res = ResUnwrap::default();
    let exp_type = conv::exported_context_type(&arg.call_ctx.options);
    let inner = || -> Result<(GssxCtx, Vec<u8>, bool), GssError> {
        let context = conv::import_gssx_ctx(&arg.context_handle)?;
        let input = arg.token_buffer.first().map(|b| b.as_slice()).unwrap_or(&[]);
        let (message, conf, _qop) = context.unwrap(input)?;
        let handle = conv::export_gssx_ctx(context, exp_type, None)?;
        Ok((handle, message, conf))
    };
    match inner() {
        Ok((handle, message, conf)) => {
            res.status = success(None);
            res.context_handle = Some(handle);
            // The C handler echoes back the *input* qop_state.
            res.qop_state = Some(arg.qop_state);
            res.conf_state = Some(conf);
            res.message_buffer = vec![Opaque::new(message)];
        }
        Err(e) => res.status = status_err(&e),
    }
    res
}

/// `gp_wrap_size_limit`.
pub fn wrap_size_limit(_ctx: &CallContext, arg: ArgWrapSizeLimit) -> ResWrapSizeLimit {
    let mut res = ResWrapSizeLimit::default();
    let inner = || -> Result<u32, GssError> {
        let context = conv::import_gssx_ctx(&arg.context_handle)?;
        context.wrap_size_limit(arg.conf_req, arg.qop_state as u32, arg.req_output_size as u32)
    };
    match inner() {
        Ok(max) => {
            res.status = success(None);
            res.max_input_size = max as u64;
        }
        Err(e) => res.status = status_err(&e),
    }
    res
}
