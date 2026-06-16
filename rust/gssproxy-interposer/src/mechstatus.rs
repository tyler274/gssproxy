//! Mechanism inquiry and status entry points. Port of `gpp_indicate_mechs.c`,
//! `gpp_display_status.c`, and `gssi_mech_invoke` from `gpp_misc.c`.
//!
//! The `gpm_inquire_*` helpers in the C client operate against a process-global
//! mech table populated once via `GSSX_INDICATE_MECHS`. We mirror that with a
//! lazily-initialised cache here.

use std::sync::OnceLock;

use gssapi_sys::consts;
use gssapi_sys::sys::{self, gss_OID, gss_OID_set, gss_buffer_t, OM_uint32};
use gssproxy_client::gpm;

use crate::behavior::{self, Behavior};
use crate::convert;
use crate::error::{map_error, unmap_error};
use crate::special;

const COMPLETE: u32 = 0;
const GSS_C_MECH_CODE: i32 = 2;

unsafe extern "C" {
    /// SPI entry point not bound by `libgssapi-sys` (its allowlist only covers
    /// `gss_*`). Declared here for `gssi_mech_invoke`.
    fn gssspi_mech_invoke(
        minor_status: *mut OM_uint32,
        desired_mech: gss_OID,
        desired_object: gss_OID,
        value: gss_buffer_t,
    ) -> OM_uint32;
}

// ===========================================================================
// Global mech cache (gpmint_indicate_mechs / global_mechs)
// ===========================================================================

struct MechInfo {
    mech: Vec<u8>,
    name_types: Vec<Vec<u8>>,
    mech_attrs: Vec<Vec<u8>>,
    known_mech_attrs: Vec<Vec<u8>>,
    saslname_sasl_mech_name: Vec<u8>,
    saslname_mech_name: Vec<u8>,
    saslname_mech_desc: Vec<u8>,
}

struct MechCache {
    ok: bool,
    info: Vec<MechInfo>,
}

static CACHE: OnceLock<MechCache> = OnceLock::new();

fn cache() -> &'static MechCache {
    CACHE.get_or_init(|| {
        let (maj, _, res) = gpm::indicate_mechs();
        if maj != COMPLETE {
            return MechCache { ok: false, info: Vec::new() };
        }
        let info = res
            .mechs
            .into_iter()
            .map(|m| MechInfo {
                mech: m.mech.as_slice().to_vec(),
                name_types: m.name_types.iter().map(|o| o.as_slice().to_vec()).collect(),
                mech_attrs: m.mech_attrs.iter().map(|o| o.as_slice().to_vec()).collect(),
                known_mech_attrs: m
                    .known_mech_attrs
                    .iter()
                    .map(|o| o.as_slice().to_vec())
                    .collect(),
                saslname_sasl_mech_name: m.saslname_sasl_mech_name.as_slice().to_vec(),
                saslname_mech_name: m.saslname_mech_name.as_slice().to_vec(),
                saslname_mech_desc: m.saslname_mech_desc.as_slice().to_vec(),
            })
            .collect();
        MechCache { ok: true, info }
    })
}

/// Look up a mech in the cache. Mirrors `gpmint_init_global_mechs` +
/// per-mech search: `Err((GSS_S_FAILURE, EIO))` if the cache could not be
/// built, `Err((GSS_S_BAD_MECH, 0))` if the mech is unknown.
unsafe fn find_mech(mech_type: gss_OID) -> Result<&'static MechInfo, (u32, u32)> {
    let c = cache();
    if !c.ok {
        return Err((consts::GSS_S_FAILURE, libc::EIO as u32));
    }
    let bytes = match convert::oid_bytes(mech_type) {
        Some(b) => b,
        None => return Err((consts::GSS_S_BAD_MECH, 0)),
    };
    c.info
        .iter()
        .find(|m| m.mech.as_slice() == bytes)
        .ok_or((consts::GSS_S_BAD_MECH, 0))
}

// ===========================================================================
// gssi_* entry points
// ===========================================================================

/// `gssi_indicate_mechs`: never actually called; present for completeness.
#[no_mangle]
pub unsafe extern "C" fn gssi_indicate_mechs(
    minor_status: *mut OM_uint32,
    _mech_set: *mut gss_OID_set,
) -> OM_uint32 {
    if !minor_status.is_null() {
        *minor_status = 0;
    }
    consts::GSS_S_FAILURE
}

/// `gssi_inquire_names_for_mech`.
#[no_mangle]
pub unsafe extern "C" fn gssi_inquire_names_for_mech(
    minor_status: *mut OM_uint32,
    mech_type: gss_OID,
    mech_names: *mut gss_OID_set,
) -> OM_uint32 {
    let behavior = behavior::get();
    let mut tmaj = COMPLETE;
    let mut tmin = 0u32;
    let mut maj;
    let mut min;

    if behavior == Behavior::LocalOnly || behavior == Behavior::LocalFirst {
        let sp = special::special_mech(mech_type as *const _);
        let mut m: OM_uint32 = 0;
        maj = sys::gss_inquire_names_for_mech(&mut m, sp, mech_names);
        min = m;
        if maj == COMPLETE || behavior == Behavior::LocalOnly {
            set_min(minor_status, min);
            return maj;
        }
        tmaj = maj;
        tmin = min;
    }

    // Remote: served from the cached mech table.
    let (rmaj, rmin) = match find_mech(mech_type) {
        Ok(info) => {
            *mech_names = convert::build_oid_set(&info.name_types);
            (COMPLETE, 0)
        }
        Err(e) => e,
    };
    maj = rmaj;
    min = rmin;
    if maj == COMPLETE || behavior == Behavior::RemoteOnly {
        if maj != COMPLETE && tmaj != COMPLETE {
            maj = tmaj;
            min = tmin;
        }
        set_min(minor_status, min);
        return maj;
    }

    let sp = special::special_mech(mech_type as *const _);
    let mut m: OM_uint32 = 0;
    maj = sys::gss_inquire_names_for_mech(&mut m, sp, mech_names);
    min = m;
    if maj != COMPLETE && tmaj != COMPLETE {
        maj = tmaj;
        min = tmin;
    }
    set_min(minor_status, min);
    maj
}

/// `gssi_inquire_attrs_for_mech`.
#[no_mangle]
pub unsafe extern "C" fn gssi_inquire_attrs_for_mech(
    minor_status: *mut OM_uint32,
    mech: gss_OID,
    mech_attrs: *mut gss_OID_set,
    known_mech_attrs: *mut gss_OID_set,
) -> OM_uint32 {
    let behavior = behavior::get();
    let mut tmaj = COMPLETE;
    let mut tmin = 0u32;
    let mut maj;
    let mut min;

    if behavior == Behavior::LocalOnly || behavior == Behavior::LocalFirst {
        let sp = special::special_mech(mech as *const _);
        let mut m: OM_uint32 = 0;
        maj = sys::gss_inquire_attrs_for_mech(&mut m, sp, mech_attrs, known_mech_attrs);
        min = m;
        if maj == COMPLETE || behavior == Behavior::LocalOnly {
            set_min(minor_status, min);
            return maj;
        }
        tmaj = maj;
        tmin = min;
    }

    let (rmaj, rmin) = match find_mech(mech) {
        Ok(info) => {
            if !mech_attrs.is_null() {
                *mech_attrs = convert::build_oid_set(&info.mech_attrs);
            }
            if !known_mech_attrs.is_null() {
                *known_mech_attrs = convert::build_oid_set(&info.known_mech_attrs);
            }
            (COMPLETE, 0)
        }
        Err(e) => e,
    };
    maj = rmaj;
    min = rmin;
    if maj == COMPLETE || behavior == Behavior::RemoteOnly {
        if maj != COMPLETE && tmaj != COMPLETE {
            maj = tmaj;
            min = tmin;
        }
        set_min(minor_status, min);
        return maj;
    }

    let sp = special::special_mech(mech as *const _);
    let mut m: OM_uint32 = 0;
    maj = sys::gss_inquire_attrs_for_mech(&mut m, sp, mech_attrs, known_mech_attrs);
    min = m;
    if maj != COMPLETE && tmaj != COMPLETE {
        maj = tmaj;
        min = tmin;
    }
    set_min(minor_status, min);
    maj
}

/// `gssi_inquire_saslname_for_mech`.
#[no_mangle]
pub unsafe extern "C" fn gssi_inquire_saslname_for_mech(
    minor_status: *mut OM_uint32,
    desired_mech: gss_OID,
    sasl_mech_name: gss_buffer_t,
    mech_name: gss_buffer_t,
    mech_description: gss_buffer_t,
) -> OM_uint32 {
    let behavior = behavior::get();
    let mut tmaj = COMPLETE;
    let mut tmin = 0u32;
    let mut maj;
    let mut min;

    if behavior == Behavior::LocalOnly || behavior == Behavior::LocalFirst {
        let sp = special::special_mech(desired_mech as *const _);
        let mut m: OM_uint32 = 0;
        maj = sys::gss_inquire_saslname_for_mech(
            &mut m,
            sp,
            sasl_mech_name,
            mech_name,
            mech_description,
        );
        min = m;
        if maj == COMPLETE || behavior == Behavior::LocalOnly {
            set_min(minor_status, min);
            return maj;
        }
        tmaj = maj;
        tmin = min;
    }

    let (rmaj, rmin) = match find_mech(desired_mech) {
        Ok(info) => {
            convert::write_buffer(sasl_mech_name, &info.saslname_sasl_mech_name);
            convert::write_buffer(mech_name, &info.saslname_mech_name);
            convert::write_buffer(mech_description, &info.saslname_mech_desc);
            (COMPLETE, 0)
        }
        Err(e) => e,
    };
    maj = rmaj;
    min = rmin;
    if maj == COMPLETE || behavior == Behavior::RemoteOnly {
        if maj != COMPLETE && tmaj != COMPLETE {
            maj = tmaj;
            min = tmin;
        }
        set_min(minor_status, min);
        return maj;
    }

    let sp = special::special_mech(desired_mech as *const _);
    let mut m: OM_uint32 = 0;
    maj = sys::gss_inquire_saslname_for_mech(
        &mut m,
        sp,
        sasl_mech_name,
        mech_name,
        mech_description,
    );
    min = m;
    if maj != COMPLETE && tmaj != COMPLETE {
        maj = tmaj;
        min = tmin;
    }
    set_min(minor_status, min);
    maj
}

/// `gssi_inquire_mech_for_saslname`: not supported.
#[no_mangle]
pub unsafe extern "C" fn gssi_inquire_mech_for_saslname(
    _minor_status: *mut OM_uint32,
    _sasl_mech_name: gss_buffer_t,
    _mech_type: *mut gss_OID,
) -> OM_uint32 {
    consts::GSS_S_UNAVAILABLE
}

/// `gssi_display_status`: only minor (mech-code) statuses are handled.
#[no_mangle]
pub unsafe extern "C" fn gssi_display_status(
    minor_status: *mut OM_uint32,
    status_value: OM_uint32,
    status_type: i32,
    _mech_type: gss_OID,
    message_context: *mut OM_uint32,
    status_string: gss_buffer_t,
) -> OM_uint32 {
    if status_type != GSS_C_MECH_CODE {
        return consts::GSS_S_BAD_STATUS;
    }

    let val = unmap_error(status_value);
    let mctx = if message_context.is_null() { 0 } else { *message_context };
    let (maj, min, text) = gpm::display_status(val, GSS_C_MECH_CODE, mctx);

    if maj == consts::GSS_S_UNAVAILABLE {
        // Fall back to the local mechglue (no mech specified, as in C).
        return sys::gss_display_status(
            minor_status,
            val,
            GSS_C_MECH_CODE,
            std::ptr::null_mut(),
            message_context,
            status_string,
        );
    }

    if maj == COMPLETE {
        convert::write_buffer(status_string, &text);
        if !message_context.is_null() {
            *message_context = 0;
        }
    }
    if !minor_status.is_null() {
        *minor_status = min;
    }
    maj
}

/// `gssi_mech_invoke`: always bridged to the local mechanism.
#[no_mangle]
pub unsafe extern "C" fn gssi_mech_invoke(
    minor_status: *mut OM_uint32,
    desired_mech: gss_OID,
    desired_object: gss_OID,
    value: gss_buffer_t,
) -> OM_uint32 {
    let sp = special::special_mech(desired_mech as *const _);
    let mut min: OM_uint32 = 0;
    let maj = gssspi_mech_invoke(&mut min, sp, desired_object, value);
    if !minor_status.is_null() {
        *minor_status = map_error(min);
    }
    maj
}

unsafe fn set_min(minor_status: *mut OM_uint32, min: u32) {
    if !minor_status.is_null() {
        *minor_status = map_error(min);
    }
}
