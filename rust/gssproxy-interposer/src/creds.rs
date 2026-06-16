//! `gssi_*` credential operations. Port of `gpp_acquire_cred.c` and
//! `gpp_creds.c`.

use std::ptr;

use gssapi_sys::consts;
use gssapi_sys::sys::{
    self, gss_OID, gss_OID_set, gss_buffer_set_t, gss_buffer_t, gss_const_key_value_set_t,
    gss_cred_id_t, gss_name_t, OM_uint32,
};
use gssproxy_client::gpm;

use crate::behavior::{self, Behavior};
use crate::convert;
use crate::error::map_error;
use crate::handle::{name_to_local, store_remote_creds, CredHandle, NameHandle};
use crate::{handle, special};

const COMPLETE: u32 = 0;
const CONTINUE: u32 = sys::GSS_S_CONTINUE_NEEDED;
const GSS_C_ACCEPT: i32 = 2;
const GSS_C_INITIATE: i32 = 1;
const GSS_C_BOTH: i32 = 0;

unsafe fn set_min(minor_status: *mut OM_uint32, min: u32) {
    if !minor_status.is_null() {
        *minor_status = map_error(min);
    }
}

/// `acquire_local`: acquire local creds (optionally impersonating) using the
/// special form of `desired_mechs`.
#[allow(clippy::too_many_arguments)]
unsafe fn acquire_local(
    imp_cred: Option<&CredHandle>,
    name: Option<&mut NameHandle>,
    time_req: u32,
    desired_mechs: gss_OID_set,
    cred_usage: i32,
    cred_store: gss_const_key_value_set_t,
    out: &mut CredHandle,
    actual_mechs: *mut gss_OID_set,
    time_rec: *mut OM_uint32,
) -> handle::Status {
    let mut special = special::special_available_mechs(desired_mechs);
    if special.is_null() {
        return (consts::GSS_S_BAD_MECH, 0);
    }

    let name_local = match name {
        Some(n) => {
            if n.local.is_null() {
                let mech = n.mech_ptr();
                if let Some(r) = n.remote.as_mut() {
                    let (maj, min, local) = name_to_local(r, mech);
                    if maj != COMPLETE {
                        let mut m: OM_uint32 = 0;
                        sys::gss_release_oid_set(&mut m, &mut special);
                        return (maj, min);
                    }
                    n.local = local;
                }
            }
            n.local
        }
        None => ptr::null_mut(),
    };

    let mut min: OM_uint32 = 0;
    let maj = if let Some(ic) = imp_cred {
        sys::gss_acquire_cred_impersonate_name(
            &mut min,
            ic.local,
            name_local,
            time_req,
            special,
            cred_usage,
            &mut out.local,
            actual_mechs,
            time_rec,
        )
    } else {
        sys::gss_acquire_cred_from(
            &mut min,
            name_local,
            time_req,
            special,
            cred_usage,
            cred_store,
            &mut out.local,
            actual_mechs,
            time_rec,
        )
    };

    let mut m: OM_uint32 = 0;
    sys::gss_release_oid_set(&mut m, &mut special);
    (maj, min)
}

/// `gssi_acquire_cred`.
#[no_mangle]
pub unsafe extern "C" fn gssi_acquire_cred(
    minor_status: *mut OM_uint32,
    desired_name: gss_name_t,
    time_req: OM_uint32,
    desired_mechs: gss_OID_set,
    cred_usage: i32,
    output_cred_handle: *mut gss_cred_id_t,
    actual_mechs: *mut gss_OID_set,
    time_rec: *mut OM_uint32,
) -> OM_uint32 {
    gssi_acquire_cred_from(
        minor_status,
        desired_name,
        time_req,
        desired_mechs,
        cred_usage,
        ptr::null(),
        output_cred_handle,
        actual_mechs,
        time_rec,
    )
}

/// `gssi_acquire_cred_from`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_acquire_cred_from(
    minor_status: *mut OM_uint32,
    desired_name: gss_name_t,
    time_req: OM_uint32,
    desired_mechs: gss_OID_set,
    cred_usage: i32,
    cred_store: gss_const_key_value_set_t,
    output_cred_handle: *mut gss_cred_id_t,
    actual_mechs: *mut gss_OID_set,
    time_rec: *mut OM_uint32,
) -> OM_uint32 {
    if output_cred_handle.is_null() {
        set_min(minor_status, libc::EINVAL as u32);
        return consts::GSS_S_FAILURE;
    }

    let mut tmaj = COMPLETE;
    let mut tmin = 0u32;
    let mut behavior = behavior::get();

    let ccache_name = convert::ccache_from_store(cred_store);
    let mut out = CredHandle::new(ccache_name.is_none(), ccache_name.as_deref());

    // Always check whether we have remote creds in the local ccache.
    let mut in_cred_remote = None;
    if behavior != Behavior::LocalOnly {
        let (rmaj, _, remote) = handle::retrieve_remote_creds(ccache_name.as_deref(), None);
        if rmaj == COMPLETE {
            in_cred_remote = remote;
            behavior = Behavior::RemoteFirst;
        } else if ccache_name.is_some() {
            behavior = Behavior::LocalFirst;
        }
    }

    let name = NameHandle::as_mut(desired_name);
    let mut maj;
    let mut min;

    // Local first.
    if behavior == Behavior::LocalOnly || behavior == Behavior::LocalFirst {
        let nref = NameHandle::as_mut(desired_name);
        let (m, mi) = acquire_local(
            None,
            nref,
            time_req,
            desired_mechs,
            cred_usage,
            cred_store,
            &mut out,
            actual_mechs,
            time_rec,
        );
        maj = m;
        min = mi;
        if maj == COMPLETE || behavior == Behavior::LocalOnly {
            return finish_acquire(minor_status, output_cred_handle, out, maj, min, tmaj, tmin);
        }
        tmaj = maj;
        tmin = min;
    }

    // Remote.
    if let Some(n) = name {
        if !n.local.is_null() && n.remote.is_none() {
            let (m, mi, rn) = handle::local_to_name(n.local);
            if m != COMPLETE {
                return finish_acquire(minor_status, output_cred_handle, out, m, mi, tmaj, tmin);
            }
            n.remote = rn;
        }
    }

    let desired = convert::oidset_to_vecs(desired_mechs);
    let name_remote = NameHandle::as_mut(desired_name).and_then(|n| n.remote.clone());
    let acq = gpm::acquire_cred(
        in_cred_remote.as_ref(),
        name_remote.as_ref(),
        time_req,
        &desired,
        cred_usage,
        false,
    );
    maj = acq.major;
    min = acq.minor;
    if maj == COMPLETE {
        out.remote = acq.cred;
        if !actual_mechs.is_null() {
            let mechs = out
                .remote
                .as_ref()
                .map(|c| {
                    c.elements
                        .iter()
                        .map(|e| e.mech.as_slice().to_vec())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            convert::write_actual_mechs(actual_mechs, &mechs);
        }
        if !time_rec.is_null() {
            *time_rec = acq.time_rec;
        }
        if let Some(rc) = &out.remote {
            if !handle::creds_are_equal(in_cred_remote.as_ref(), Some(rc)) {
                let (sm, _) = store_remote_creds(out.default_creds, &out.store, rc);
                if sm != COMPLETE {
                    maj = sm;
                }
            }
        }
        return finish_acquire(minor_status, output_cred_handle, out, maj, min, tmaj, tmin);
    }

    if behavior == Behavior::RemoteFirst {
        tmaj = maj;
        tmin = min;
        let nref = NameHandle::as_mut(desired_name);
        let (m, mi) = acquire_local(
            None,
            nref,
            time_req,
            desired_mechs,
            cred_usage,
            cred_store,
            &mut out,
            actual_mechs,
            time_rec,
        );
        maj = m;
        min = mi;
    }

    finish_acquire(minor_status, output_cred_handle, out, maj, min, tmaj, tmin)
}

unsafe fn finish_acquire(
    minor_status: *mut OM_uint32,
    output_cred_handle: *mut gss_cred_id_t,
    out: Box<CredHandle>,
    mut maj: u32,
    mut min: u32,
    tmaj: u32,
    tmin: u32,
) -> OM_uint32 {
    if maj != COMPLETE && maj != CONTINUE && tmaj != COMPLETE {
        maj = tmaj;
        min = tmin;
    }
    if maj == COMPLETE {
        *output_cred_handle = CredHandle::into_raw(out);
    } else {
        drop(out);
    }
    set_min(minor_status, min);
    maj
}

/// `gssi_add_cred`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_add_cred(
    minor_status: *mut OM_uint32,
    input_cred_handle: gss_cred_id_t,
    desired_name: gss_name_t,
    desired_mech: gss_OID,
    cred_usage: i32,
    initiator_time_req: OM_uint32,
    acceptor_time_req: OM_uint32,
    output_cred_handle: *mut gss_cred_id_t,
    actual_mechs: *mut gss_OID_set,
    initiator_time_rec: *mut OM_uint32,
    acceptor_time_rec: *mut OM_uint32,
) -> OM_uint32 {
    gssi_add_cred_from(
        minor_status,
        input_cred_handle,
        desired_name,
        desired_mech,
        cred_usage,
        initiator_time_req,
        acceptor_time_req,
        ptr::null(),
        output_cred_handle,
        actual_mechs,
        initiator_time_rec,
        acceptor_time_rec,
    )
}

/// `gssi_add_cred_from`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_add_cred_from(
    minor_status: *mut OM_uint32,
    _input_cred_handle: gss_cred_id_t,
    desired_name: gss_name_t,
    desired_mech: gss_OID,
    cred_usage: i32,
    initiator_time_req: OM_uint32,
    acceptor_time_req: OM_uint32,
    _cred_store: gss_const_key_value_set_t,
    output_cred_handle: *mut gss_cred_id_t,
    actual_mechs: *mut gss_OID_set,
    initiator_time_rec: *mut OM_uint32,
    acceptor_time_rec: *mut OM_uint32,
) -> OM_uint32 {
    if output_cred_handle.is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    let mut desired_mechs: gss_OID_set = ptr::null_mut();
    if !desired_mech.is_null() {
        let mut min: OM_uint32 = 0;
        if sys::gss_create_empty_oid_set(&mut min, &mut desired_mechs) != COMPLETE {
            set_min(minor_status, min);
            return consts::GSS_S_FAILURE;
        }
        if sys::gss_add_oid_set_member(&mut min, desired_mech, &mut desired_mechs) != COMPLETE {
            sys::gss_release_oid_set(&mut min, &mut desired_mechs);
            set_min(minor_status, min);
            return consts::GSS_S_FAILURE;
        }
    }

    let time_req = match cred_usage {
        GSS_C_ACCEPT => acceptor_time_req,
        GSS_C_INITIATE => initiator_time_req,
        GSS_C_BOTH => acceptor_time_req.max(initiator_time_req),
        _ => 0,
    };

    let mut time_rec: OM_uint32 = 0;
    let maj = gssi_acquire_cred_from(
        minor_status,
        desired_name,
        time_req,
        desired_mechs,
        cred_usage,
        ptr::null(),
        output_cred_handle,
        actual_mechs,
        &mut time_rec,
    );
    if maj == COMPLETE {
        if !acceptor_time_rec.is_null() && (cred_usage == GSS_C_ACCEPT || cred_usage == GSS_C_BOTH)
        {
            *acceptor_time_rec = time_rec;
        }
        if !initiator_time_rec.is_null()
            && (cred_usage == GSS_C_INITIATE || cred_usage == GSS_C_BOTH)
        {
            *initiator_time_rec = time_rec;
        }
    }

    let mut min: OM_uint32 = 0;
    sys::gss_release_oid_set(&mut min, &mut desired_mechs);
    maj
}

/// `gssi_acquire_cred_with_password`: local-only (REMOTE_ONLY unsupported).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_acquire_cred_with_password(
    minor_status: *mut OM_uint32,
    desired_name: gss_name_t,
    password: gss_buffer_t,
    time_req: OM_uint32,
    desired_mechs: gss_OID_set,
    cred_usage: i32,
    output_cred_handle: *mut gss_cred_id_t,
    actual_mechs: *mut gss_OID_set,
    time_rec: *mut OM_uint32,
) -> OM_uint32 {
    let name = match NameHandle::as_mut(desired_name) {
        Some(n) => n,
        None => {
            set_min(minor_status, libc::EINVAL as u32);
            return consts::GSS_S_BAD_NAME;
        }
    };
    if output_cred_handle.is_null() {
        set_min(minor_status, libc::EINVAL as u32);
        return consts::GSS_S_FAILURE;
    }
    if desired_mechs.is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }

    let behavior = behavior::get();
    let mut out = CredHandle::new(false, None);

    let (maj, min) = match behavior {
        Behavior::LocalOnly | Behavior::LocalFirst | Behavior::RemoteFirst => {
            let mut special = special::special_available_mechs(desired_mechs);
            if special.is_null() {
                (consts::GSS_S_FAILURE, libc::EINVAL as u32)
            } else {
                if name.local.is_null() {
                    let mech = name.mech_ptr();
                    if let Some(r) = name.remote.as_mut() {
                        let (m, mi, local) = name_to_local(r, mech);
                        if m != COMPLETE {
                            let mut z: OM_uint32 = 0;
                            sys::gss_release_oid_set(&mut z, &mut special);
                            set_min(minor_status, mi);
                            return m;
                        }
                        name.local = local;
                    }
                }
                let mut min: OM_uint32 = 0;
                let maj = sys::gss_acquire_cred_with_password(
                    &mut min,
                    name.local,
                    password,
                    time_req,
                    special,
                    cred_usage,
                    &mut out.local,
                    actual_mechs,
                    time_rec,
                );
                let mut z: OM_uint32 = 0;
                sys::gss_release_oid_set(&mut z, &mut special);
                (maj, min)
            }
        }
        Behavior::RemoteOnly => (consts::GSS_S_FAILURE, libc::EINVAL as u32),
    };

    if maj == COMPLETE {
        *output_cred_handle = CredHandle::into_raw(out);
    } else {
        drop(out);
    }
    set_min(minor_status, min);
    maj
}

/// `gssi_acquire_cred_impersonate_name`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_acquire_cred_impersonate_name(
    minor_status: *mut OM_uint32,
    imp_cred_handle: gss_cred_id_t,
    desired_name: gss_name_t,
    time_req: OM_uint32,
    desired_mechs: gss_OID_set,
    cred_usage: i32,
    output_cred_handle: *mut gss_cred_id_t,
    actual_mechs: *mut gss_OID_set,
    time_rec: *mut OM_uint32,
) -> OM_uint32 {
    // NOTE: the GSSAPI SPI passes the impersonator credential *by value*
    // (`gss_cred_id_t`), even though gssproxy's C prototype spells it
    // `gss_cred_id_t *`. The handle pointer is used directly, not dereferenced.
    if imp_cred_handle.is_null() {
        set_min(minor_status, libc::EINVAL as u32);
        return consts::GSS_S_NO_CRED;
    }
    let imp = match CredHandle::as_mut(imp_cred_handle) {
        Some(c) => c,
        None => {
            set_min(minor_status, libc::EINVAL as u32);
            return consts::GSS_S_NO_CRED;
        }
    };
    if output_cred_handle.is_null() {
        set_min(minor_status, libc::EINVAL as u32);
        return consts::GSS_S_FAILURE;
    }

    let mut tmaj = COMPLETE;
    let mut tmin = 0u32;
    let mut out = CredHandle::new(false, None);
    let behavior = behavior::get();

    let mut maj;
    let mut min;

    if behavior == Behavior::LocalOnly || behavior == Behavior::LocalFirst {
        let nref = NameHandle::as_mut(desired_name);
        let (m, mi) = acquire_local(
            Some(&*imp),
            nref,
            time_req,
            desired_mechs,
            cred_usage,
            ptr::null(),
            &mut out,
            actual_mechs,
            time_rec,
        );
        maj = m;
        min = mi;
        if maj == COMPLETE || behavior == Behavior::LocalOnly {
            return finish_acquire(minor_status, output_cred_handle, out, maj, min, tmaj, tmin);
        }
        tmaj = maj;
        tmin = min;
    }

    if let Some(n) = NameHandle::as_mut(desired_name) {
        if !n.local.is_null() && n.remote.is_none() {
            let (m, mi, rn) = handle::local_to_name(n.local);
            if m != COMPLETE {
                return finish_acquire(minor_status, output_cred_handle, out, m, mi, tmaj, tmin);
            }
            n.remote = rn;
        }
    }

    let desired = convert::oidset_to_vecs(desired_mechs);
    let name_remote = NameHandle::as_mut(desired_name).and_then(|n| n.remote.clone());
    let acq = gpm::acquire_cred(
        imp.remote.as_ref(),
        name_remote.as_ref(),
        time_req,
        &desired,
        cred_usage,
        true,
    );
    maj = acq.major;
    min = acq.minor;
    if maj == COMPLETE {
        out.remote = acq.cred;
        if !actual_mechs.is_null() {
            let mechs = out
                .remote
                .as_ref()
                .map(|c| {
                    c.elements
                        .iter()
                        .map(|e| e.mech.as_slice().to_vec())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            convert::write_actual_mechs(actual_mechs, &mechs);
        }
        if !time_rec.is_null() {
            *time_rec = acq.time_rec;
        }
        return finish_acquire(minor_status, output_cred_handle, out, maj, min, tmaj, tmin);
    }
    if behavior == Behavior::RemoteOnly {
        return finish_acquire(minor_status, output_cred_handle, out, maj, min, tmaj, tmin);
    }

    if behavior == Behavior::RemoteFirst {
        let nref = NameHandle::as_mut(desired_name);
        let (m, mi) = acquire_local(
            Some(&*imp),
            nref,
            time_req,
            desired_mechs,
            cred_usage,
            ptr::null(),
            &mut out,
            actual_mechs,
            time_rec,
        );
        maj = m;
        min = mi;
    }

    finish_acquire(minor_status, output_cred_handle, out, maj, min, tmaj, tmin)
}

/// `gssi_inquire_cred`.
#[no_mangle]
pub unsafe extern "C" fn gssi_inquire_cred(
    minor_status: *mut OM_uint32,
    cred_handle: gss_cred_id_t,
    name: *mut gss_name_t,
    lifetime: *mut OM_uint32,
    cred_usage: *mut i32,
    mechanisms: *mut gss_OID_set,
) -> OM_uint32 {
    // Default-cred case: build a temporary handle.
    let mut owned: Option<Box<CredHandle>> = None;
    let no_cred = cred_handle.is_null();
    if no_cred {
        let (maj, min) = handle::get_def_creds(behavior::get(), None, GSS_C_INITIATE, &mut owned);
        if maj != COMPLETE {
            set_min(minor_status, min);
            return maj;
        }
    }
    let cred: &CredHandle = if no_cred {
        owned.as_ref().unwrap()
    } else {
        match CredHandle::as_mut(cred_handle) {
            Some(c) => c,
            None => return consts::GSS_S_FAILURE,
        }
    };

    let mut gpname = NameHandle::empty();
    let (maj, min) = if !cred.local.is_null() {
        let mut min: OM_uint32 = 0;
        let m = sys::gss_inquire_cred(
            &mut min,
            cred.local,
            if name.is_null() {
                ptr::null_mut()
            } else {
                &mut gpname.local
            },
            lifetime,
            cred_usage,
            mechanisms,
        );
        (m, min)
    } else if cred.remote.is_some() {
        let info = gpm::inquire_cred(cred.remote.as_ref().unwrap());
        if info.major == COMPLETE {
            if !lifetime.is_null() {
                *lifetime = info.lifetime;
            }
            if !cred_usage.is_null() {
                *cred_usage = info.usage;
            }
            if !mechanisms.is_null() {
                *mechanisms = convert::build_oid_set(&info.mechs);
            }
            gpname.remote = info.name;
        }
        (info.major, info.minor)
    } else {
        (consts::GSS_S_FAILURE, 0)
    };

    set_min(minor_status, min);
    if !name.is_null() && maj == COMPLETE {
        *name = NameHandle::into_raw(gpname);
    }
    maj
}

/// `gssi_inquire_cred_by_mech`.
#[no_mangle]
pub unsafe extern "C" fn gssi_inquire_cred_by_mech(
    minor_status: *mut OM_uint32,
    cred_handle: gss_cred_id_t,
    mech_type: gss_OID,
    name: *mut gss_name_t,
    initiator_lifetime: *mut OM_uint32,
    acceptor_lifetime: *mut OM_uint32,
    cred_usage: *mut i32,
) -> OM_uint32 {
    let mut owned: Option<Box<CredHandle>> = None;
    let no_cred = cred_handle.is_null();
    if no_cred {
        let (maj, min) = handle::get_def_creds(behavior::get(), None, GSS_C_INITIATE, &mut owned);
        if maj != COMPLETE {
            set_min(minor_status, min);
            return maj;
        }
    }
    let cred: &CredHandle = if no_cred {
        owned.as_ref().unwrap()
    } else {
        match CredHandle::as_mut(cred_handle) {
            Some(c) => c,
            None => return consts::GSS_S_FAILURE,
        }
    };

    let mut gpname = NameHandle::empty();
    let (maj, min) = if !cred.local.is_null() {
        let mut min: OM_uint32 = 0;
        let m = sys::gss_inquire_cred_by_mech(
            &mut min,
            cred.local,
            special::special_mech(mech_type as *const _),
            if name.is_null() {
                ptr::null_mut()
            } else {
                &mut gpname.local
            },
            initiator_lifetime,
            acceptor_lifetime,
            cred_usage,
        );
        (m, min)
    } else if cred.remote.is_some() {
        let unspec = special::unspecial_mech(mech_type as *const _);
        let mech_bytes = convert::oid_bytes(unspec).unwrap_or(&[]).to_vec();
        let info = gpm::inquire_cred_by_mech(cred.remote.as_ref().unwrap(), &mech_bytes);
        if info.major == COMPLETE {
            if !initiator_lifetime.is_null() {
                *initiator_lifetime = info.initiator_lifetime;
            }
            if !acceptor_lifetime.is_null() {
                *acceptor_lifetime = info.acceptor_lifetime;
            }
            if !cred_usage.is_null() {
                *cred_usage = info.usage;
            }
            gpname.remote = info.name;
        }
        (info.major, info.minor)
    } else {
        (consts::GSS_S_FAILURE, 0)
    };

    set_min(minor_status, min);
    if !name.is_null() && maj == COMPLETE {
        *name = NameHandle::into_raw(gpname);
    }
    maj
}

/// `gssi_inquire_cred_by_oid`: local only.
#[no_mangle]
pub unsafe extern "C" fn gssi_inquire_cred_by_oid(
    minor_status: *mut OM_uint32,
    cred_handle: gss_cred_id_t,
    desired_object: gss_OID,
    data_set: *mut gss_buffer_set_t,
) -> OM_uint32 {
    if !minor_status.is_null() {
        *minor_status = 0;
    }
    if cred_handle.is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }
    let cred = match CredHandle::as_mut(cred_handle) {
        Some(c) => c,
        None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
    };
    if cred.local.is_null() {
        return consts::GSS_S_UNAVAILABLE;
    }
    let mut min: OM_uint32 = 0;
    let maj = sys::gss_inquire_cred_by_oid(&mut min, cred.local, desired_object, data_set);
    set_min(minor_status, min);
    maj
}

/// `gssi_set_cred_option`.
#[no_mangle]
pub unsafe extern "C" fn gssi_set_cred_option(
    minor_status: *mut OM_uint32,
    cred_handle: *mut gss_cred_id_t,
    desired_object: gss_OID,
    value: gss_buffer_t,
) -> OM_uint32 {
    if !minor_status.is_null() {
        *minor_status = 0;
    }
    if cred_handle.is_null() || (*cred_handle).is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }
    let cred = match CredHandle::as_mut(*cred_handle) {
        Some(c) => c,
        None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
    };
    // NOTE: remote cred options (allowable enctypes / no_ci_flags) are not yet
    // wired; only local creds are handled, matching the practical test surface.
    if cred.remote.is_some() {
        return consts::GSS_S_UNAVAILABLE;
    }
    if cred.local.is_null() {
        return consts::GSS_S_UNAVAILABLE;
    }
    let mut min: OM_uint32 = 0;
    let maj = sys::gss_set_cred_option(&mut min, &mut cred.local, desired_object, value);
    set_min(minor_status, min);
    maj
}

/// `gssi_store_cred`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_store_cred(
    minor_status: *mut OM_uint32,
    input_cred_handle: gss_cred_id_t,
    input_usage: i32,
    desired_mech: gss_OID,
    overwrite_cred: OM_uint32,
    default_cred: OM_uint32,
    elements_stored: *mut gss_OID_set,
    cred_usage_stored: *mut i32,
) -> OM_uint32 {
    gssi_store_cred_into(
        minor_status,
        input_cred_handle,
        input_usage,
        desired_mech,
        overwrite_cred,
        default_cred,
        ptr::null(),
        elements_stored,
        cred_usage_stored,
    )
}

/// `gssi_store_cred_into`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_store_cred_into(
    minor_status: *mut OM_uint32,
    input_cred_handle: gss_cred_id_t,
    input_usage: i32,
    desired_mech: gss_OID,
    overwrite_cred: OM_uint32,
    default_cred: OM_uint32,
    cred_store: gss_const_key_value_set_t,
    elements_stored: *mut gss_OID_set,
    cred_usage_stored: *mut i32,
) -> OM_uint32 {
    if !minor_status.is_null() {
        *minor_status = 0;
    }
    if input_cred_handle.is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }
    let cred = match CredHandle::as_mut(input_cred_handle) {
        Some(c) => c,
        None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
    };

    let (maj, min) = if let Some(rc) = &cred.remote {
        let store = convert::kvset_to_vec(cred_store);
        store_remote_creds(default_cred != 0, &store, rc)
    } else {
        let mut min: OM_uint32 = 0;
        let m = sys::gss_store_cred_into(
            &mut min,
            cred.local,
            input_usage,
            special::special_mech(desired_mech as *const _),
            overwrite_cred,
            default_cred,
            cred_store,
            elements_stored,
            cred_usage_stored,
        );
        (m, min)
    };
    set_min(minor_status, min);
    maj
}

/// `gssi_release_cred`.
#[no_mangle]
pub unsafe extern "C" fn gssi_release_cred(
    minor_status: *mut OM_uint32,
    cred_handle: *mut gss_cred_id_t,
) -> OM_uint32 {
    if cred_handle.is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }
    if (*cred_handle).is_null() {
        if !minor_status.is_null() {
            *minor_status = 0;
        }
        return COMPLETE;
    }
    let handle = CredHandle::from_raw(*cred_handle);
    let (tmaj, tmin) = match &handle.remote {
        Some(r) => gpm::release_cred(r),
        None => (COMPLETE, 0),
    };
    // Drop releases the local credential (gpp_cred_handle_free).
    drop(handle);
    *cred_handle = ptr::null_mut();

    let (maj, min) = if tmaj != COMPLETE {
        (tmaj, tmin)
    } else {
        (COMPLETE, 0)
    };
    if !minor_status.is_null() {
        *minor_status = min;
    }
    maj
}

/// `gssi_export_cred`: local only.
#[no_mangle]
pub unsafe extern "C" fn gssi_export_cred(
    minor_status: *mut OM_uint32,
    cred_handle: gss_cred_id_t,
    token: gss_buffer_t,
) -> OM_uint32 {
    let cred = match CredHandle::as_mut(cred_handle) {
        Some(c) => c,
        None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
    };
    if cred.local.is_null() {
        return consts::GSS_S_CRED_UNAVAIL;
    }
    sys::gss_export_cred(minor_status, cred.local, token)
}

/// `gssi_import_cred`: not supported (UNAVAILABLE).
#[no_mangle]
pub unsafe extern "C" fn gssi_import_cred(
    _minor_status: *mut OM_uint32,
    _token: gss_buffer_t,
    _cred_handle: *mut gss_cred_id_t,
) -> OM_uint32 {
    consts::GSS_S_UNAVAILABLE
}

/// `gssi_import_cred_by_mech`: local only, wrapping the token with the special
/// mech so the real mechglue imports it.
#[no_mangle]
pub unsafe extern "C" fn gssi_import_cred_by_mech(
    minor_status: *mut OM_uint32,
    mech_type: gss_OID,
    token: gss_buffer_t,
    cred_handle: *mut gss_cred_id_t,
) -> OM_uint32 {
    let mut cred = CredHandle::new(false, None);

    let spmech = special::special_mech(mech_type as *const _);
    let sp_bytes = match convert::oid_bytes(spmech) {
        Some(b) => b.to_vec(),
        None => {
            set_min(minor_status, 0);
            return consts::GSS_S_FAILURE;
        }
    };
    let inner = convert::read_buffer(token);
    let total = 4 + sp_bytes.len() + inner.len();
    let mut wrap = Vec::with_capacity(total);
    // gssi_import_cred_by_mech prepends the *total* length (not the mech len).
    wrap.extend_from_slice(&(total as u32).to_be_bytes());
    wrap.extend_from_slice(&sp_bytes);
    wrap.extend_from_slice(inner);

    let wrapbuf = convert::TmpBuf::new(&wrap);
    let mut min: OM_uint32 = 0;
    let maj = sys::gss_import_cred(&mut min, wrapbuf.as_ptr(), &mut cred.local);

    set_min(minor_status, min);
    if maj == COMPLETE {
        *cred_handle = CredHandle::into_raw(cred);
    } else {
        drop(cred);
    }
    maj
}
