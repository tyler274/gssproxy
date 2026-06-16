//! Conversions between the gssx wire types (`gssproxy-proto`) and live GSSAPI
//! handles/values (`gssapi-sys`). Ported from `src/gp_conv.c`.

use gssapi_sys::seal::CredHandle;
use gssapi_sys::sys;
use gssapi_sys::wrap::{self, Context, Cred, Name};
use gssapi_sys::{consts, wrap::GssError};
use gssproxy_proto::gssx::{GssxCred, GssxCredElement, GssxCtx, GssxName, GssxStatus, Opaque};

/// Exported-context representation, mirroring `enum exp_ctx_types` in
/// `gp_export.c`. The Linux lucid (kernel) form is not yet implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpCtxType {
    Default,
    Partial,
    Lucid,
}

/// `gp_get_exported_context_type`: inspect the `exported_context_type` option.
pub fn exported_context_type(options: &[gssproxy_proto::gssx::GssxOption]) -> ExpCtxType {
    // sizeof() in the C macros includes the trailing NUL.
    const KEY: &[u8] = b"exported_context_type\0";
    const LUCID: &[u8] = b"linux_lucid_v1\0";
    for opt in options {
        if opt.option.as_slice() == KEY {
            return if opt.value.as_slice() == LUCID {
                ExpCtxType::Lucid
            } else {
                ExpCtxType::Partial
            };
        }
    }
    ExpCtxType::Default
}

/// `gssx_cred_usage` enum values (see `x-files/gss_proxy.x`). Note these differ
/// from the GSS_C_* usage values.
pub const GSSX_C_INITIATE: i32 = 1;
pub const GSSX_C_ACCEPT: i32 = 2;
pub const GSSX_C_BOTH: i32 = 3;

// GSS_C_* credential usage values (gssapi.h).
const GSS_C_BOTH: i32 = 0;
const GSS_C_INITIATE: i32 = 1;
const GSS_C_ACCEPT: i32 = 2;

/// `gp_conv_cred_usage_to_gssx`.
pub fn cred_usage_to_gssx(usage: i32) -> i32 {
    match usage {
        GSS_C_BOTH => GSSX_C_BOTH,
        GSS_C_INITIATE => GSSX_C_INITIATE,
        GSS_C_ACCEPT => GSSX_C_ACCEPT,
        _ => 0,
    }
}

/// `gp_conv_gssx_to_cred_usage`.
pub fn gssx_to_cred_usage(usage: i32) -> i32 {
    match usage {
        GSSX_C_BOTH => GSS_C_BOTH,
        GSSX_C_INITIATE => GSS_C_INITIATE,
        GSSX_C_ACCEPT => GSS_C_ACCEPT,
        _ => 0,
    }
}

/// `gp_conv_name_to_gssx`: serialize a live name into its wire form.
pub fn name_to_gssx(name: &Name) -> wrap::Result<GssxName> {
    let (display, name_type) = name.display()?;
    let mut out = GssxName {
        display_name: Opaque::new(display),
        name_type: Opaque::new(name_type),
        ..Default::default()
    };
    if let Some(exported) = name.export()? {
        out.exported_name = Opaque::new(exported);
    }
    if let Some(composite) = name.export_composite()? {
        out.exported_composite_name = Opaque::new(composite);
    }
    Ok(out)
}

/// `gp_conv_gssx_to_name`: reconstruct a live name from its wire form.
///
/// When a display name is present we (re-)import it so the original form is
/// preserved; otherwise we import the exported (mechanism) name blob.
pub fn gssx_to_name(g: &GssxName) -> wrap::Result<Name> {
    if !g.display_name.is_empty() {
        let name_type = if g.name_type.is_empty() {
            None
        } else {
            Some(g.name_type.as_slice())
        };
        Name::import(g.display_name.as_slice(), name_type)
    } else {
        Name::import_exported(g.exported_name.as_slice())
    }
}

/// `gp_export_gssx_cred`: serialize a live credential into its wire form,
/// sealing the opaque `cred_handle_reference` with the per-service key.
///
/// Consumes `cred` (the C daemon releases it once serialized, staying
/// stateless). Mechanisms that fail `inquire_cred_by_mech` are skipped, exactly
/// like the C "skip any offender" loop.
pub fn export_gssx_cred(handle: &CredHandle, cred: Cred) -> wrap::Result<GssxCred> {
    let info = cred.inquire()?;

    let desired_name = match &info.name {
        Some(n) => name_to_gssx(n)?,
        None => GssxName::default(),
    };

    let mut elements = Vec::with_capacity(info.mechs.len());
    for mech in &info.mechs {
        let by = match cred.inquire_by_mech(mech) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mn = match &by.name {
            Some(n) => name_to_gssx(n)?,
            None => GssxName::default(),
        };
        elements.push(GssxCredElement {
            mn,
            mech: Opaque::new(mech.clone()),
            cred_usage: cred_usage_to_gssx(by.usage),
            initiator_time_rec: by.initiator_lifetime as u64,
            acceptor_time_rec: by.acceptor_lifetime as u64,
            options: Vec::new(),
        });
    }

    let token = cred.export_token()?;
    let sealed = handle.seal(&token).map_err(seal_error)?;

    Ok(GssxCred {
        desired_name,
        elements,
        cred_handle_reference: Opaque::new(sealed),
        needs_release: false,
    })
}

/// `gp_import_gssx_cred`: reconstruct a live credential from its wire form by
/// unsealing the opaque handle reference. A decrypt failure is treated as "no
/// credential" (`Ok(None)`), mirroring the C "allow re-issuance" behavior.
pub fn import_gssx_cred(handle: &CredHandle, cred: &GssxCred) -> wrap::Result<Option<Cred>> {
    let sealed = cred.cred_handle_reference.as_slice();
    if sealed.is_empty() {
        return Ok(None);
    }
    let token = match handle.unseal(sealed) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    Ok(Some(Cred::import_token(&token)?))
}

/// `gp_export_ctx_id_to_gssx`: serialize a (possibly partial) security context.
///
/// Consumes `ctx` (`gss_export_sec_context` invalidates the handle). For
/// `Partial`, `partial_mech` overrides the inquired mech and the context is
/// flagged locally-initiated/not-open, matching the C `EXP_CTX_PARTIAL` path.
/// The `Lucid` (kernel) form is not implemented.
pub fn export_gssx_ctx(
    ctx: Context,
    exp_type: ExpCtxType,
    partial_mech: Option<&[u8]>,
) -> wrap::Result<GssxCtx> {
    let mut out = GssxCtx {
        needs_release: false,
        ..Default::default()
    };

    match ctx.inquire() {
        Ok(info) => {
            out.mech = Opaque::new(info.mech);
            if let Some(n) = &info.src_name {
                out.src_name = name_to_gssx(n)?;
            }
            if let Some(n) = &info.targ_name {
                out.targ_name = name_to_gssx(n)?;
            }
            out.lifetime = info.lifetime as u64;
            out.ctx_flags = info.flags as u64;
            out.locally_initiated = info.locally_initiated;
            out.open = info.open;
        }
        Err(e) => {
            // A partial (continue-needed) context may not inquire; carry on.
            if exp_type != ExpCtxType::Partial {
                return Err(e);
            }
        }
    }

    match exp_type {
        ExpCtxType::Partial => {
            out.mech = partial_mech
                .map(|m| Opaque::new(m.to_vec()))
                .unwrap_or_default();
            out.locally_initiated = true;
            out.open = false;
            out.exported_context_token = Opaque::new(ctx.export()?);
        }
        ExpCtxType::Default => {
            out.exported_context_token = Opaque::new(ctx.export()?);
        }
        ExpCtxType::Lucid => {
            return Err(GssError {
                major: consts::GSS_S_FAILURE,
                minor: libc::ENOSYS as u32,
                messages: vec!["linux_lucid_v1 context export is not implemented".to_string()],
            });
        }
    }

    Ok(out)
}

/// `gp_import_gssx_to_ctx_id` (DEFAULT type): reconstruct a live context from
/// its exported token.
pub fn import_gssx_ctx(ctx: &GssxCtx) -> wrap::Result<Context> {
    Context::import(ctx.exported_context_token.as_slice())
}

fn seal_error(e: gssapi_sys::seal::SealError) -> GssError {
    GssError {
        major: consts::GSS_S_FAILURE,
        minor: 0,
        messages: vec![format!("cred handle sealing failed: {e}")],
    }
}

/// `gp_conv_status_to_gssx`: render a major/minor status pair (for an optional
/// mechanism OID) into a `gssx_status`.
pub fn status_to_gssx(major: u32, minor: u32, mech: Option<&[u8]>) -> GssxStatus {
    let mut status = GssxStatus {
        major_status: major as u64,
        minor_status: minor as u64,
        ..Default::default()
    };
    if let Some(m) = mech
        && !m.is_empty()
    {
        status.mech = Opaque::new(m.to_vec());
    }
    if major != 0 {
        status.major_status_string = status_string(major, sys::GSS_C_GSS_CODE as i32, mech);
    }
    if minor != 0 {
        status.minor_status_string = status_string(minor, sys::GSS_C_MECH_CODE as i32, mech);
    }
    status
}

/// Render a status code into a NUL-terminated utf8string buffer, matching the
/// `len = strlen + 1` convention `gp_conv.c` uses on the wire.
fn status_string(code: u32, code_type: i32, mech: Option<&[u8]>) -> Opaque {
    let parts = wrap::display_status(code, code_type, mech);
    if parts.is_empty() {
        return Opaque::default();
    }
    let mut bytes = parts.join(", ").into_bytes();
    bytes.push(0);
    Opaque::new(bytes)
}
