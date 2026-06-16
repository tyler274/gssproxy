//! Conversions between the gssx wire types (`gssproxy-proto`) and live GSSAPI
//! handles/values (`gssapi-sys`). Ported from `src/gp_conv.c`.

use gssapi_sys::sys;
use gssapi_sys::wrap::{self, Name};
use gssproxy_proto::gssx::{GssxName, GssxStatus, Opaque};

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

/// `gp_conv_status_to_gssx`: render a major/minor status pair (for an optional
/// mechanism OID) into a `gssx_status`.
pub fn status_to_gssx(major: u32, minor: u32, mech: Option<&[u8]>) -> GssxStatus {
    let mut status = GssxStatus {
        major_status: major as u64,
        minor_status: minor as u64,
        ..Default::default()
    };
    if let Some(m) = mech {
        if !m.is_empty() {
            status.mech = Opaque::new(m.to_vec());
        }
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
