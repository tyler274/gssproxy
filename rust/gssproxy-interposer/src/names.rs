//! `gssi_*` name operations. Port of `gpp_import_and_canon_name.c` (and the
//! name-related entries of `gpp_misc.c`).

use std::ptr;

use gssapi_sys::consts;
use gssapi_sys::sys::{self, OM_uint32, gss_OID, gss_buffer_set_t, gss_buffer_t, gss_name_t};
use gssproxy_client::gpm;

use crate::convert;
use crate::error::map_error;
use crate::handle::{NameHandle, OwnedOid, name_to_local};
use crate::{logging, special};

const COMPLETE: u32 = 0;

unsafe fn set_min(minor_status: *mut OM_uint32, min: u32) {
    unsafe {
        if !minor_status.is_null() {
            *minor_status = map_error(min);
        }
    }
}

/// `gssi_display_name`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_display_name(
    minor_status: *mut OM_uint32,
    input_name: gss_name_t,
    output_name_buffer: gss_buffer_t,
    output_name_type: *mut gss_OID,
) -> OM_uint32 {
    unsafe {
        logging::init();
        tracing::trace!("display_name");
        if !output_name_buffer.is_null() {
            (*output_name_buffer).length = 0;
            (*output_name_buffer).value = ptr::null_mut();
        }
        if !output_name_type.is_null() {
            *output_name_type = ptr::null_mut();
        }

        let name = match NameHandle::as_mut(input_name) {
            Some(n) if !n.local.is_null() || n.remote.is_some() => n,
            _ => return consts::GSS_S_BAD_NAME,
        };

        if !name.local.is_null() {
            let mut min: OM_uint32 = 0;
            let maj =
                sys::gss_display_name(&mut min, name.local, output_name_buffer, output_name_type);
            set_min(minor_status, min);
            return maj;
        }

        let remote = name.remote.as_mut().unwrap();
        let (maj, min, disp, ntype) = gpm::display_name(remote);
        if maj != COMPLETE {
            set_min(minor_status, min);
            return maj;
        }
        if !output_name_buffer.is_null() {
            convert::write_buffer(output_name_buffer, &disp);
        }
        if !output_name_type.is_null() {
            match convert::name_type_static(&ntype) {
                Some(o) => *output_name_type = o,
                None => {
                    if !output_name_buffer.is_null() {
                        convert::release_buffer(output_name_buffer);
                    }
                    set_min(minor_status, libc::ENOENT as u32);
                    return consts::GSS_S_FAILURE;
                }
            }
        }
        set_min(minor_status, 0);
        COMPLETE
    }
}

/// `gssi_display_name_ext`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_display_name_ext(
    minor_status: *mut OM_uint32,
    input_name: gss_name_t,
    display_as_name_type: gss_OID,
    display_name: gss_buffer_t,
) -> OM_uint32 {
    unsafe {
        let name = match NameHandle::as_mut(input_name) {
            Some(n) if !n.local.is_null() || n.remote.is_some() => n,
            _ => return consts::GSS_S_BAD_NAME,
        };
        if name.local.is_null() {
            set_min(minor_status, 0);
            return consts::GSS_S_UNAVAILABLE;
        }
        let mut min: OM_uint32 = 0;
        let maj =
            sys::gss_display_name_ext(&mut min, name.local, display_as_name_type, display_name);
        set_min(minor_status, min);
        maj
    }
}

/// `gssi_import_name`: not supported by the interposer (always UNAVAILABLE).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_import_name(
    _minor_status: *mut OM_uint32,
    _input_name_buffer: gss_buffer_t,
    _input_name_type: gss_OID,
    _output_name: *mut gss_name_t,
) -> OM_uint32 {
    consts::GSS_S_UNAVAILABLE
}

/// `gssi_import_name_by_mech`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_import_name_by_mech(
    minor_status: *mut OM_uint32,
    mech_type: gss_OID,
    input_name_buffer: gss_buffer_t,
    input_name_type: gss_OID,
    output_name: *mut gss_name_t,
) -> OM_uint32 {
    unsafe {
        logging::init();
        tracing::debug!("import_name_by_mech");
        if mech_type.is_null() {
            return consts::GSS_S_CALL_INACCESSIBLE_READ;
        }
        // gpm_import_name requires a buffer and a name type.
        if input_name_buffer.is_null() || input_name_type.is_null() {
            set_min(minor_status, 0);
            return consts::GSS_S_CALL_INACCESSIBLE_READ;
        }

        let mut name = NameHandle::empty();
        name.mech_type = match OwnedOid::from_oid(mech_type) {
            Some(o) => Some(o),
            None => {
                set_min(minor_status, libc::ENOMEM as u32);
                return consts::GSS_S_FAILURE;
            }
        };
        let value = convert::read_buffer(input_name_buffer);
        let ntype = convert::oid_bytes(input_name_type).unwrap_or(&[]);
        name.remote = Some(gpm::import_name(value, ntype));

        set_min(minor_status, 0);
        *output_name = NameHandle::into_raw(name);
        COMPLETE
    }
}

/// `gssi_duplicate_name`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_duplicate_name(
    minor_status: *mut OM_uint32,
    input_name: gss_name_t,
    dest_name: *mut gss_name_t,
) -> OM_uint32 {
    unsafe {
        let in_name = match NameHandle::as_mut(input_name) {
            Some(n) if !n.local.is_null() || n.remote.is_some() => n,
            _ => return consts::GSS_S_BAD_NAME,
        };

        let mut out = NameHandle::empty();
        if let Some(o) = &in_name.mech_type {
            out.mech_type = Some(OwnedOid::new(
                convert::oid_bytes(o.as_ptr()).unwrap_or(&[]).to_vec(),
            ));
        }

        if let Some(r) = &in_name.remote {
            out.remote = Some(r.clone());
        } else {
            let mut min: OM_uint32 = 0;
            let maj = sys::gss_duplicate_name(&mut min, in_name.local, &mut out.local);
            if maj != COMPLETE {
                set_min(minor_status, min);
                return maj;
            }
        }

        set_min(minor_status, 0);
        *dest_name = NameHandle::into_raw(out);
        COMPLETE
    }
}

/// `gssi_inquire_name`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_inquire_name(
    minor_status: *mut OM_uint32,
    input_name: gss_name_t,
    name_is_nm: *mut i32,
    nm_mech: *mut gss_OID,
    attrs: *mut gss_buffer_set_t,
) -> OM_uint32 {
    unsafe {
        let name = match NameHandle::as_mut(input_name) {
            Some(n) if !n.local.is_null() || n.remote.is_some() => n,
            _ => return consts::GSS_S_BAD_NAME,
        };

        if !name.local.is_null() {
            let mut min: OM_uint32 = 0;
            let maj = sys::gss_inquire_name(&mut min, name.local, name_is_nm, nm_mech, attrs);
            set_min(minor_status, min);
            return maj;
        }

        let info = gpm::inquire_name(name.remote.as_ref().unwrap());
        set_min(minor_status, 0);
        if !name_is_nm.is_null() && info.name_is_mn {
            *name_is_nm = 1;
        }
        if !nm_mech.is_null() {
            match convert::name_type_static(&info.name_type) {
                Some(o) => *nm_mech = o,
                None => {
                    set_min(minor_status, libc::ENOENT as u32);
                    return consts::GSS_S_FAILURE;
                }
            }
        }
        if !attrs.is_null() {
            if info.attrs.is_empty() {
                *attrs = ptr::null_mut();
            } else {
                let mut min: OM_uint32 = 0;
                let mut set: gss_buffer_set_t = ptr::null_mut();
                if sys::gss_create_empty_buffer_set(&mut min, &mut set) != COMPLETE {
                    set_min(minor_status, libc::ENOMEM as u32);
                    return consts::GSS_S_FAILURE;
                }
                for a in &info.attrs {
                    let tb = convert::TmpBuf::new(a);
                    sys::gss_add_buffer_set_member(&mut min, tb.as_ptr(), &mut set);
                }
                *attrs = set;
            }
        }
        COMPLETE
    }
}

/// `gssi_release_name`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_release_name(
    minor_status: *mut OM_uint32,
    input_name: *mut gss_name_t,
) -> OM_uint32 {
    unsafe {
        if input_name.is_null() {
            return consts::GSS_S_BAD_NAME;
        }
        match NameHandle::as_mut(*input_name) {
            Some(n) if !n.local.is_null() || n.remote.is_some() => {}
            _ => return consts::GSS_S_BAD_NAME,
        }
        // Drop releases the local name, the owned mech OID, and the remote name.
        drop(NameHandle::from_raw(*input_name));
        *input_name = ptr::null_mut();
        set_min(minor_status, 0);
        COMPLETE
    }
}

/// `gssi_compare_name`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_compare_name(
    minor_status: *mut OM_uint32,
    name1: gss_name_t,
    name2: gss_name_t,
    name_equal: *mut i32,
) -> OM_uint32 {
    unsafe {
        let gp1 = match NameHandle::as_mut(name1) {
            Some(n) => n,
            None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
        };
        let gp2 = match NameHandle::as_mut(name2) {
            Some(n) => n,
            None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
        };

        if !gp1.local.is_null() || !gp2.local.is_null() {
            if gp1.local.is_null() {
                let mech = gp1.mech_ptr();
                let remote = match gp1.remote.as_mut() {
                    Some(r) => r,
                    None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
                };
                let (maj, min, local) = name_to_local(remote, mech);
                if maj != COMPLETE {
                    set_min(minor_status, min);
                    return maj;
                }
                gp1.local = local;
            }
            if gp2.local.is_null() {
                let mech = gp2.mech_ptr();
                let remote = match gp2.remote.as_mut() {
                    Some(r) => r,
                    None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
                };
                let (maj, min, local) = name_to_local(remote, mech);
                if maj != COMPLETE {
                    set_min(minor_status, min);
                    return maj;
                }
                gp2.local = local;
            }
            let mut min: OM_uint32 = 0;
            let maj = sys::gss_compare_name(&mut min, gp1.local, gp2.local, name_equal);
            set_min(minor_status, min);
            return maj;
        }

        if gp1.remote.is_none() && gp2.remote.is_none() {
            return consts::GSS_S_CALL_INACCESSIBLE_READ;
        }
        let (maj, min, equal) =
            gpm::compare_name(gp1.remote.as_ref().unwrap(), gp2.remote.as_ref().unwrap());
        if !name_equal.is_null() {
            *name_equal = if equal { 1 } else { 0 };
        }
        set_min(minor_status, min);
        maj
    }
}

/// `gssi_get_name_attribute`: local only.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_get_name_attribute(
    minor_status: *mut OM_uint32,
    input_name: gss_name_t,
    attr: gss_buffer_t,
    authenticated: *mut i32,
    complete: *mut i32,
    value: gss_buffer_t,
    display_value: gss_buffer_t,
    more: *mut i32,
) -> OM_uint32 {
    unsafe {
        let name = match NameHandle::as_mut(input_name) {
            Some(n) if !n.local.is_null() || n.remote.is_some() => n,
            _ => return consts::GSS_S_BAD_NAME,
        };
        if name.local.is_null() {
            set_min(minor_status, 0);
            return consts::GSS_S_UNAVAILABLE;
        }
        let mut min: OM_uint32 = 0;
        let maj = sys::gss_get_name_attribute(
            &mut min,
            name.local,
            attr,
            authenticated,
            complete,
            value,
            display_value,
            more,
        );
        set_min(minor_status, min);
        maj
    }
}

/// `gssi_set_name_attribute`: local only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_set_name_attribute(
    minor_status: *mut OM_uint32,
    input_name: gss_name_t,
    complete: i32,
    attr: gss_buffer_t,
    value: gss_buffer_t,
) -> OM_uint32 {
    unsafe {
        let name = match NameHandle::as_mut(input_name) {
            Some(n) if !n.local.is_null() || n.remote.is_some() => n,
            _ => return consts::GSS_S_BAD_NAME,
        };
        if name.local.is_null() {
            set_min(minor_status, 0);
            return consts::GSS_S_UNAVAILABLE;
        }
        let mut min: OM_uint32 = 0;
        let maj = sys::gss_set_name_attribute(&mut min, name.local, complete, attr, value);
        set_min(minor_status, min);
        maj
    }
}

/// `gssi_delete_name_attribute`: local only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_delete_name_attribute(
    minor_status: *mut OM_uint32,
    input_name: gss_name_t,
    attr: gss_buffer_t,
) -> OM_uint32 {
    unsafe {
        let name = match NameHandle::as_mut(input_name) {
            Some(n) if !n.local.is_null() || n.remote.is_some() => n,
            _ => return consts::GSS_S_BAD_NAME,
        };
        if name.local.is_null() {
            set_min(minor_status, 0);
            return consts::GSS_S_UNAVAILABLE;
        }
        let mut min: OM_uint32 = 0;
        let maj = sys::gss_delete_name_attribute(&mut min, name.local, attr);
        set_min(minor_status, min);
        maj
    }
}

/// `gssi_localname`: port of `gpp_misc.c`. Tries the daemon first (falling back
/// to local on `ENOTSUP`), otherwise the real local mechanism.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_localname(
    minor_status: *mut OM_uint32,
    name: gss_name_t,
    mech_type: gss_OID,
    localname: gss_buffer_t,
) -> OM_uint32 {
    unsafe {
        if !minor_status.is_null() {
            *minor_status = 0;
        }
        if name.is_null() {
            return consts::GSS_S_CALL_INACCESSIBLE_READ;
        }
        let gpname = match NameHandle::as_mut(name) {
            Some(n) if !n.local.is_null() || n.remote.is_some() => n,
            _ => return consts::GSS_S_CALL_INACCESSIBLE_READ,
        };

        let mut maj = COMPLETE;
        let mut min = 0u32;

        if let Some(remote) = gpname.remote.as_ref() {
            let mech_bytes = convert::oid_bytes(mech_type).unwrap_or(&[]).to_vec();
            let (m, mi, out) = gpm::localname(remote, &mech_bytes);
            if m == COMPLETE {
                if let Some(buf) = out {
                    convert::write_buffer(localname, &buf);
                }
                set_min(minor_status, mi);
                return m;
            } else if m != consts::GSS_S_FAILURE || mi != libc::ENOTSUP as u32 {
                set_min(minor_status, mi);
                return m;
            }
            // ENOTSUP: the daemon can't map it; fall back to a local conversion.
        }

        if gpname.local.is_null()
            && let Some(r) = gpname.remote.as_mut()
        {
            let (nm, nmi, local) = name_to_local(r, mech_type);
            if nm != COMPLETE {
                set_min(minor_status, nmi);
                return nm;
            }
            gpname.local = local;
        }

        if !gpname.local.is_null() {
            let sp = special::special_mech(mech_type as *const _);
            maj = sys::gss_localname(&mut min, gpname.local, sp, localname);
        }

        set_min(minor_status, min);
        maj
    }
}

/// `gssi_authorize_localname`: local only (with remote->local conversion).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_authorize_localname(
    minor_status: *mut OM_uint32,
    name: gss_name_t,
    local_user: gss_buffer_t,
    local_nametype: gss_OID,
) -> OM_uint32 {
    unsafe {
        if !minor_status.is_null() {
            *minor_status = 0;
        }
        if name.is_null() {
            return consts::GSS_S_CALL_INACCESSIBLE_READ;
        }
        let gpname = match NameHandle::as_mut(name) {
            Some(n) => n,
            None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
        };

        if gpname.local.is_null() {
            let mech = gpname.mech_ptr();
            if let Some(r) = gpname.remote.as_mut() {
                let (m, mi, local) = name_to_local(r, mech);
                if m != COMPLETE {
                    set_min(minor_status, mi);
                    return m;
                }
                gpname.local = local;
            }
        }

        let mut min: OM_uint32 = 0;
        let mut username: gss_name_t = ptr::null_mut();
        let maj = sys::gss_import_name(&mut min, local_user, local_nametype, &mut username);
        if maj != COMPLETE {
            set_min(minor_status, min);
            return maj;
        }
        let maj = sys::gss_authorize_localname(&mut min, gpname.local, username);
        set_min(minor_status, min);
        let mut m: OM_uint32 = 0;
        sys::gss_release_name(&mut m, &mut username);
        maj
    }
}

/// `gssi_map_name_to_any`: local only (with remote->local conversion).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_map_name_to_any(
    minor_status: *mut OM_uint32,
    name: gss_name_t,
    authenticated: i32,
    type_id: gss_buffer_t,
    output: *mut sys::gss_any_t,
) -> OM_uint32 {
    unsafe {
        if !minor_status.is_null() {
            *minor_status = 0;
        }
        if name.is_null() {
            return consts::GSS_S_CALL_INACCESSIBLE_READ;
        }
        let gpname = match NameHandle::as_mut(name) {
            Some(n) => n,
            None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
        };

        if gpname.local.is_null() {
            let mech = gpname.mech_ptr();
            if let Some(r) = gpname.remote.as_mut() {
                let (m, mi, local) = name_to_local(r, mech);
                if m != COMPLETE {
                    set_min(minor_status, mi);
                    return m;
                }
                gpname.local = local;
            }
        }

        let mut min: OM_uint32 = 0;
        let maj = sys::gss_map_name_to_any(&mut min, gpname.local, authenticated, type_id, output);
        set_min(minor_status, min);
        maj
    }
}

/// `gssi_release_any_name_mapping`: local only.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gssi_release_any_name_mapping(
    minor_status: *mut OM_uint32,
    name: gss_name_t,
    type_id: gss_buffer_t,
    input: *mut sys::gss_any_t,
) -> OM_uint32 {
    unsafe {
        if !minor_status.is_null() {
            *minor_status = 0;
        }
        if name.is_null() {
            return consts::GSS_S_CALL_INACCESSIBLE_READ;
        }
        let gpname = match NameHandle::as_mut(name) {
            Some(n) => n,
            None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
        };
        if gpname.local.is_null() {
            return consts::GSS_S_UNAVAILABLE;
        }
        let mut min: OM_uint32 = 0;
        let maj = sys::gss_release_any_name_mapping(&mut min, gpname.local, type_id, input);
        set_min(minor_status, min);
        maj
    }
}
