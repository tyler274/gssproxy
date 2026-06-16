//! Context lifecycle: export/import, delete, inquire, context_time,
//! process_context_token, inquire_by_oid, set_sec_context_option,
//! pseudo_random. Port of `gpp_context.c`.

use std::ptr;

use gssapi_sys::consts;
use gssapi_sys::sys::{
    self, gss_OID, gss_buffer_set_t, gss_buffer_t, gss_ctx_id_t, gss_name_t, OM_uint32,
};
use gssproxy_client::gpm;

use crate::convert;
use crate::error::map_error;
use crate::handle::{self, CtxHandle, NameHandle, OwnedOid};

const COMPLETE: u32 = 0;

unsafe fn set_min(minor_status: *mut OM_uint32, min: u32) {
    if !minor_status.is_null() {
        *minor_status = map_error(min);
    }
}

/// `gssi_export_sec_context`.
#[no_mangle]
pub unsafe extern "C" fn gssi_export_sec_context(
    minor_status: *mut OM_uint32,
    context_handle: *mut gss_ctx_id_t,
    interprocess_token: gss_buffer_t,
) -> OM_uint32 {
    if context_handle.is_null() || (*context_handle).is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }
    let local = match handle::ensure_local_ctx(*context_handle) {
        Ok(l) => l,
        Err((maj, min)) => {
            set_min(minor_status, min);
            return maj;
        }
    };
    let ctx = CtxHandle::as_mut(*context_handle).unwrap();
    ctx.local = local;

    let maj = sys::gss_export_sec_context(minor_status, &mut ctx.local, interprocess_token);
    if maj == COMPLETE {
        if let Some(r) = &ctx.remote {
            let _ = gpm::delete_sec_context(r);
            ctx.remote = None;
        }
    }
    maj
}

/// `gssi_import_sec_context`: not supported.
#[no_mangle]
pub unsafe extern "C" fn gssi_import_sec_context(
    _minor_status: *mut OM_uint32,
    _interprocess_token: gss_buffer_t,
    _context_handle: *mut gss_ctx_id_t,
) -> OM_uint32 {
    consts::GSS_S_UNAVAILABLE
}

/// `gssi_import_sec_context_by_mech`: local only.
#[no_mangle]
pub unsafe extern "C" fn gssi_import_sec_context_by_mech(
    minor_status: *mut OM_uint32,
    mech_type: gss_OID,
    interprocess_token: gss_buffer_t,
    context_handle: *mut gss_ctx_id_t,
) -> OM_uint32 {
    let mut ctx = CtxHandle::empty();

    let inner = convert::read_buffer(interprocess_token);
    let wrapped = match handle::wrap_sec_ctx_token(mech_type, inner) {
        Some(w) => w,
        None => {
            set_min(minor_status, 0);
            return consts::GSS_S_FAILURE;
        }
    };
    let wrapbuf = convert::TmpBuf::new(&wrapped);
    let mut min: OM_uint32 = 0;
    let maj = sys::gss_import_sec_context(&mut min, wrapbuf.as_ptr(), &mut ctx.local);

    set_min(minor_status, min);
    if maj == COMPLETE {
        *context_handle = CtxHandle::into_raw(ctx);
    } else {
        drop(ctx);
    }
    maj
}

/// `gssi_process_context_token`.
#[no_mangle]
pub unsafe extern "C" fn gssi_process_context_token(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    token_buffer: gss_buffer_t,
) -> OM_uint32 {
    let local = match handle::ensure_local_ctx(context_handle) {
        Ok(l) => l,
        Err((maj, min)) => {
            set_min(minor_status, min);
            return maj;
        }
    };
    sys::gss_process_context_token(minor_status, local, token_buffer)
}

/// `gssi_context_time`.
#[no_mangle]
pub unsafe extern "C" fn gssi_context_time(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    time_rec: *mut OM_uint32,
) -> OM_uint32 {
    if !minor_status.is_null() {
        *minor_status = 0;
    }
    let ctx = match CtxHandle::as_mut(context_handle) {
        Some(c) => c,
        None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
    };
    if let Some(r) = &ctx.remote {
        let info = gpm::inquire_context(r);
        if info.lifetime > 0 {
            if !time_rec.is_null() {
                *time_rec = info.lifetime;
            }
            COMPLETE
        } else {
            if !time_rec.is_null() {
                *time_rec = 0;
            }
            consts::GSS_S_CONTEXT_EXPIRED
        }
    } else if !ctx.local.is_null() {
        sys::gss_context_time(minor_status, ctx.local, time_rec)
    } else {
        consts::GSS_S_NO_CONTEXT
    }
}

/// `gssi_inquire_context`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_inquire_context(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    src_name: *mut gss_name_t,
    targ_name: *mut gss_name_t,
    lifetime_rec: *mut OM_uint32,
    mech_type: *mut gss_OID,
    ctx_flags: *mut OM_uint32,
    locally_initiated: *mut i32,
    open: *mut i32,
) -> OM_uint32 {
    if context_handle.is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }
    let ctx = match CtxHandle::as_mut(context_handle) {
        Some(c) => c,
        None => return consts::GSS_S_CALL_INACCESSIBLE_READ,
    };
    if ctx.local.is_null() && ctx.remote.is_none() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }

    let mut s_name: Option<Box<NameHandle>> = if !src_name.is_null() {
        Some(NameHandle::empty())
    } else {
        None
    };
    let mut t_name: Option<Box<NameHandle>> = if !targ_name.is_null() {
        Some(NameHandle::empty())
    } else {
        None
    };

    let mut mech_bytes: Vec<u8> = Vec::new();
    let mut mech_oid_local: gss_OID = ptr::null_mut();

    let (maj, min) = if !ctx.local.is_null() {
        let s_ptr = s_name
            .as_mut()
            .map(|n| &mut n.local as *mut gss_name_t)
            .unwrap_or(ptr::null_mut());
        let t_ptr = t_name
            .as_mut()
            .map(|n| &mut n.local as *mut gss_name_t)
            .unwrap_or(ptr::null_mut());
        let mut min: OM_uint32 = 0;
        let m = sys::gss_inquire_context(
            &mut min,
            ctx.local,
            s_ptr,
            t_ptr,
            lifetime_rec,
            &mut mech_oid_local,
            ctx_flags,
            locally_initiated,
            open,
        );
        if m == COMPLETE {
            mech_bytes = convert::oid_bytes(mech_oid_local).unwrap_or(&[]).to_vec();
        }
        (m, min)
    } else {
        let info = gpm::inquire_context(ctx.remote.as_ref().unwrap());
        if !lifetime_rec.is_null() {
            *lifetime_rec = info.lifetime;
        }
        if !ctx_flags.is_null() {
            *ctx_flags = info.ctx_flags;
        }
        if !locally_initiated.is_null() {
            *locally_initiated = info.locally_initiated as i32;
        }
        if !open.is_null() {
            *open = info.open as i32;
        }
        if let Some(n) = s_name.as_mut() {
            n.remote = Some(info.src_name.clone());
        }
        if let Some(n) = t_name.as_mut() {
            n.remote = Some(info.targ_name.clone());
        }
        mech_bytes = info.mech.clone();
        (COMPLETE, 0)
    };

    if maj != COMPLETE {
        set_min(minor_status, min);
        if !mech_oid_local.is_null() {
            let mut m: OM_uint32 = 0;
            sys::gss_release_oid(&mut m, &mut mech_oid_local);
        }
        return maj;
    }

    if let Some(n) = s_name.as_mut() {
        n.mech_type = Some(OwnedOid::new(mech_bytes.clone()));
    }
    if let Some(n) = t_name.as_mut() {
        n.mech_type = Some(OwnedOid::new(mech_bytes.clone()));
    }

    set_min(minor_status, 0);

    if !mech_type.is_null() {
        // Hand back a stable OID pointer (interned for the remote path, or the
        // mechglue's own OID for the local path).
        if !mech_oid_local.is_null() {
            *mech_type = mech_oid_local;
        } else {
            *mech_type = convert::intern_oid(&mech_bytes);
        }
    } else if !mech_oid_local.is_null() {
        let mut m: OM_uint32 = 0;
        sys::gss_release_oid(&mut m, &mut mech_oid_local);
    }

    if !src_name.is_null() {
        *src_name = match s_name.take() {
            Some(n) => NameHandle::into_raw(n),
            None => ptr::null_mut(),
        };
    }
    if !targ_name.is_null() {
        *targ_name = match t_name.take() {
            Some(n) => NameHandle::into_raw(n),
            None => ptr::null_mut(),
        };
    }
    COMPLETE
}

/// `gssi_inquire_sec_context_by_oid`: local only.
#[no_mangle]
pub unsafe extern "C" fn gssi_inquire_sec_context_by_oid(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    desired_object: gss_OID,
    data_set: *mut gss_buffer_set_t,
) -> OM_uint32 {
    let local = match handle::ensure_local_ctx(context_handle) {
        Ok(l) => l,
        Err((maj, min)) => {
            set_min(minor_status, min);
            return maj;
        }
    };
    sys::gss_inquire_sec_context_by_oid(minor_status, local, desired_object, data_set)
}

/// `gssi_set_sec_context_option`.
#[no_mangle]
pub unsafe extern "C" fn gssi_set_sec_context_option(
    minor_status: *mut OM_uint32,
    context_handle: *mut gss_ctx_id_t,
    desired_object: gss_OID,
    value: gss_buffer_t,
) -> OM_uint32 {
    if context_handle.is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }
    let ctx_ptr: *mut CtxHandle = if !(*context_handle).is_null() {
        *context_handle as *mut CtxHandle
    } else {
        CtxHandle::into_raw(CtxHandle::empty()) as *mut CtxHandle
    };

    let ctx = &mut *ctx_ptr;
    if ctx.remote.is_some() && ctx.local.is_null() {
        let (maj, min) = handle::remote_to_local_ctx(&mut ctx.remote, &mut ctx.local);
        if maj != COMPLETE {
            set_min(minor_status, min);
            *context_handle = ctx_ptr as gss_ctx_id_t;
            let mut m: OM_uint32 = 0;
            gssi_delete_sec_context(&mut m, context_handle, ptr::null_mut());
            return maj;
        }
    }

    let maj = sys::gss_set_sec_context_option(minor_status, &mut ctx.local, desired_object, value);
    *context_handle = ctx_ptr as gss_ctx_id_t;
    if maj != COMPLETE {
        let mut m: OM_uint32 = 0;
        gssi_delete_sec_context(&mut m, context_handle, ptr::null_mut());
    }
    maj
}

/// `gssi_delete_sec_context`.
#[no_mangle]
pub unsafe extern "C" fn gssi_delete_sec_context(
    minor_status: *mut OM_uint32,
    context_handle: *mut gss_ctx_id_t,
    output_token: gss_buffer_t,
) -> OM_uint32 {
    if context_handle.is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }
    let ptr_val = *context_handle;
    *context_handle = ptr::null_mut();
    if ptr_val.is_null() {
        if !minor_status.is_null() {
            *minor_status = 0;
        }
        return COMPLETE;
    }

    let mut ctx = CtxHandle::from_raw(ptr_val);
    let mut rmaj = COMPLETE;

    if !ctx.local.is_null() {
        let mut min: OM_uint32 = 0;
        let maj = sys::gss_delete_sec_context(&mut min, &mut ctx.local, output_token);
        if maj != COMPLETE {
            rmaj = maj;
            set_min(minor_status, min);
        }
    }
    if let Some(r) = &ctx.remote {
        let (maj, min) = gpm::delete_sec_context(r);
        if maj != COMPLETE && rmaj == COMPLETE {
            rmaj = maj;
            set_min(minor_status, min);
        }
    }
    // The local cred has already been released above; avoid the Drop double
    // release by clearing it before the box is dropped.
    ctx.local = ptr::null_mut();
    ctx.remote = None;
    drop(ctx);

    rmaj
}

/// `gssi_pseudo_random`.
#[no_mangle]
pub unsafe extern "C" fn gssi_pseudo_random(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    prf_key: i32,
    prf_in: gss_buffer_t,
    desired_output_len: isize,
    prf_out: gss_buffer_t,
) -> OM_uint32 {
    let local = match handle::ensure_local_ctx(context_handle) {
        Ok(l) => l,
        Err((maj, min)) => {
            set_min(minor_status, min);
            return maj;
        }
    };
    sys::gss_pseudo_random(
        minor_status,
        local,
        prf_key,
        prf_in,
        desired_output_len,
        prf_out,
    )
}
