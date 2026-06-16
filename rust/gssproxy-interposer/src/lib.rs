//! `proxymech.so`: a GSSAPI mechanism interposer plugin that proxies krb5/IAKERB
//! operations to the gssproxy daemon.
//!
//! This is the Rust port of `src/mechglue/*.c`. The MIT krb5 mechglue loads an
//! interposer by calling [`gss_mech_interposer`] (which returns the set of mech
//! OIDs we take over) and then resolves the per-operation `gssi_*` symbols we
//! export here by name. Each `gssi_*` entry point converts the GSSAPI call into
//! the gssx wire form and dispatches it to the daemon via `gssproxy-client`
//! (and/or performs it locally against the real mechanism, depending on the
//! configured [`behavior`]).
//!
//! Implemented so far:
//!   - plugin entry/OID machinery: [`gss_mech_interposer`],
//!     [`gssi_internal_release_oid`], the special-mech OID registry
//!     ([`special`]), behavior/env handling ([`behavior`], [`env`]), and minor
//!     status mapping ([`error`]).
//!
//! The per-operation `gssi_*` data path (init/accept/wrap/unwrap/mic/name/cred)
//! is being filled in incrementally.

mod behavior;
mod context;
mod convert;
mod creds;
mod ctxlife;
mod env;
mod error;
mod handle;
mod logging;
mod mechstatus;
mod msgprot;
mod names;
mod oids;
mod special;

use gssapi_sys::sys::{
    self, OM_uint32, gss_OID, gss_OID_set, gss_create_empty_oid_set, gss_release_oid_set,
};

// Re-export the foundation pieces so the (forthcoming) gssi_* handler modules
// and tests can use them via crate paths without `pub mod` churn later.
pub use behavior::Behavior;

/// `GSS_S_COMPLETE`.
const GSS_S_COMPLETE: OM_uint32 = 0;

/// Add one of our base OIDs to `set`, returning false on allocation failure.
unsafe fn add_member(set: *mut gss_OID_set, member: gss_OID) -> bool {
    let mut minor: OM_uint32 = 0;
    let maj = unsafe { sys::gss_add_oid_set_member(&mut minor, member, set) };
    maj == GSS_S_COMPLETE
}

/// Entry point invoked by the mechglue to discover which mechanisms this
/// interposer takes over (C: `gss_mech_interposer`).
///
/// Returns the krb5 family + IAKERB OIDs when (a) interposition is enabled and
/// (b) `mech_type` is the gssproxy interposer OID; otherwise `GSS_C_NO_OID_SET`.
///
/// # Safety
/// Called by the C mechglue with a valid `gss_OID` (or null). Exported with C
/// ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gss_mech_interposer(mech_type: gss_OID) -> gss_OID_set {
    unsafe {
        if !behavior::enabled() {
            return std::ptr::null_mut();
        }
        logging::init();
        if !oids::oid_equal(oids::interposer(), mech_type) {
            tracing::trace!("gss_mech_interposer called for a non-gssproxy OID");
            return std::ptr::null_mut();
        }
        tracing::debug!(behavior = ?behavior::get(), "interposer enabled; claiming krb5/IAKERB mechs");

        let mut minor: OM_uint32 = 0;
        let mut set: gss_OID_set = std::ptr::null_mut();
        if gss_create_empty_oid_set(&mut minor, &mut set) != GSS_S_COMPLETE {
            return std::ptr::null_mut();
        }

        let base = oids::base();
        let ok = add_member(&mut set, &base.krb5 as *const _ as gss_OID)
            && add_member(&mut set, &base.krb5_old as *const _ as gss_OID)
            && add_member(&mut set, &base.krb5_wrong as *const _ as gss_OID)
            && add_member(&mut set, &base.iakerb as *const _ as gss_OID);

        if !ok {
            let mut min2: OM_uint32 = 0;
            gss_release_oid_set(&mut min2, &mut set);
            return std::ptr::null_mut();
        }

        // While we are here, seed the special-mech list from the mechs we proxy
        // (C: gpp_init_special_available_mechs).
        special::init_special_available_mechs(set);

        set
    }
}

/// `gssi_internal_release_oid`: claim ownership (and suppress release) of OIDs
/// that belong to us - the interposer OID itself and any registered
/// regular/special OID - so the mechglue does not try to free them.
///
/// Returns `GSS_S_COMPLETE` (and nulls `*oid`) when the OID is ours, otherwise
/// `GSS_S_CONTINUE_NEEDED` so the mechglue keeps looking.
///
/// # Safety
/// `minor_status` and `oid` must be valid pointers; `*oid` must be null or a
/// valid `gss_OID`. Exported with C ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_internal_release_oid(
    minor_status: *mut OM_uint32,
    oid: *mut gss_OID,
) -> OM_uint32 {
    unsafe {
        if !minor_status.is_null() {
            *minor_status = 0;
        }
        if oid.is_null() {
            return sys::GSS_S_CONTINUE_NEEDED;
        }

        let cur = *oid as *const sys::gss_OID_desc;

        // The static interposer OID (compared by identity, as in C).
        if std::ptr::eq(cur, oids::interposer()) {
            *oid = std::ptr::null_mut();
            return GSS_S_COMPLETE;
        }

        if special::is_registered_ptr(cur) {
            *oid = std::ptr::null_mut();
            return GSS_S_COMPLETE;
        }

        // Not ours: let the mechglue continue (gpm_mech_is_static is handled by the
        // real mechglue once the data path forwards static mech OIDs).
        sys::GSS_S_CONTINUE_NEEDED
    }
}
