//! `gssi_init_sec_context` and `gssi_accept_sec_context`. Port of
//! `gpp_init_sec_context.c` and `gpp_accept_sec_context.c`.

use std::ptr;

use gssapi_sys::consts;
use gssapi_sys::sys::{
    self, gss_OID, gss_buffer_t, gss_channel_bindings_t, gss_cred_id_t, gss_ctx_id_t, gss_name_t,
    OM_uint32,
};
use gssproxy_client::gpm;

use crate::behavior::{self, Behavior};
use crate::convert;
use crate::error::map_error;
use crate::handle::{
    local_to_name, name_to_local, store_remote_creds, CredHandle, CtxHandle, NameHandle,
};
use crate::{handle, special};

const COMPLETE: u32 = 0;
const CONTINUE: u32 = sys::GSS_S_CONTINUE_NEEDED;

fn keep(maj: u32) -> bool {
    maj == COMPLETE || maj == CONTINUE
}

/// `init_ctx_local`: establish via the real local mechanism.
#[allow(clippy::too_many_arguments)]
unsafe fn init_ctx_local(
    cred: &CredHandle,
    ctx: &mut CtxHandle,
    name: &mut NameHandle,
    mech_type: gss_OID,
    req_flags: OM_uint32,
    time_req: OM_uint32,
    input_cb: gss_channel_bindings_t,
    input_token: gss_buffer_t,
    actual_mech_type: *mut gss_OID,
    output_token: gss_buffer_t,
    ret_flags: *mut OM_uint32,
    time_rec: *mut OM_uint32,
) -> (u32, u32) {
    if name.local.is_null() {
        if let Some(r) = name.remote.as_mut() {
            let (maj, min, local) = name_to_local(r, mech_type);
            if maj != COMPLETE {
                return (maj, min);
            }
            name.local = local;
        }
    }
    let sp = special::special_mech(mech_type as *const _);
    let mut min: OM_uint32 = 0;
    let maj = sys::gss_init_sec_context(
        &mut min,
        cred.local,
        &mut ctx.local,
        name.local,
        sp,
        req_flags,
        time_req,
        input_cb,
        input_token,
        actual_mech_type,
        output_token,
        ret_flags,
        time_rec,
    );
    (maj, min)
}

/// `gssi_init_sec_context`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_init_sec_context(
    minor_status: *mut OM_uint32,
    claimant_cred_handle: gss_cred_id_t,
    context_handle: *mut gss_ctx_id_t,
    target_name: gss_name_t,
    mech_type: gss_OID,
    req_flags: OM_uint32,
    time_req: OM_uint32,
    input_cb: gss_channel_bindings_t,
    input_token: gss_buffer_t,
    actual_mech_type: *mut gss_OID,
    output_token: gss_buffer_t,
    ret_flags: *mut OM_uint32,
    time_rec: *mut OM_uint32,
) -> OM_uint32 {
    if !minor_status.is_null() {
        *minor_status = 0;
    }
    if target_name.is_null() {
        return consts::GSS_S_CALL_INACCESSIBLE_READ;
    }
    if mech_type.is_null() || special::is_special_oid(mech_type as *const _) {
        return consts::GSS_S_BAD_MECH;
    }

    let mut tmaj = COMPLETE;
    let mut tmin = 0u32;
    let mut local_only = false;

    // Context handle: reuse the existing one or allocate a fresh payload.
    let ctx_ptr: *mut CtxHandle = if !(*context_handle).is_null() {
        let p = *context_handle as *mut CtxHandle;
        if !(*p).local.is_null() {
            local_only = true;
        }
        p
    } else {
        CtxHandle::into_raw(CtxHandle::empty()) as *mut CtxHandle
    };

    // Credential handle.
    let mut owned_cred: Option<Box<CredHandle>> = None;
    let cred_ptr: *mut CredHandle;
    let mut early: Option<(u32, u32)> = None;
    if !claimant_cred_handle.is_null() {
        cred_ptr = claimant_cred_handle as *mut CredHandle;
        if !(*cred_ptr).local.is_null() {
            local_only = true;
        } else if local_only {
            early = Some((consts::GSS_S_DEFECTIVE_CREDENTIAL, 0));
        }
    } else {
        owned_cred = Some(CredHandle::new(true, None));
        cred_ptr = owned_cred.as_mut().unwrap().as_mut() as *mut CredHandle;
    }

    let behavior = if local_only {
        Behavior::LocalOnly
    } else {
        behavior::get()
    };
    let name_ptr = target_name as *mut NameHandle;

    let (mut maj, mut min) = 'done: {
        if let Some(e) = early {
            break 'done e;
        }
        let cred = &mut *cred_ptr;
        let ctx = &mut *ctx_ptr;
        let name = &mut *name_ptr;

        // Local first.
        if behavior == Behavior::LocalOnly || behavior == Behavior::LocalFirst {
            let (m, mi) = init_ctx_local(
                cred,
                ctx,
                name,
                mech_type,
                req_flags,
                time_req,
                input_cb,
                input_token,
                actual_mech_type,
                output_token,
                ret_flags,
                time_rec,
            );
            if keep(m) || behavior == Behavior::LocalOnly {
                break 'done (m, mi);
            }
            tmaj = m;
            tmin = mi;
        }

        // Remote.
        if behavior != Behavior::LocalOnly {
            if !name.local.is_null() && name.remote.is_none() {
                let (m, mi, rn) = local_to_name(name.local);
                if m != COMPLETE {
                    break 'done (m, mi);
                }
                name.remote = rn;
            }

            if cred.remote.is_none() {
                let mut slot: Option<Box<CredHandle>> = None;
                let _ = handle::get_def_creds(Behavior::RemoteOnly, None, 1, &mut slot);
                if let Some(s) = slot {
                    cred.remote = s.remote.clone();
                }
            }

            let mech_bytes = convert::oid_bytes(mech_type).unwrap_or(&[]).to_vec();
            let cb = convert::cb_to_gssx(input_cb);
            let in_tok = if input_token.is_null() {
                None
            } else {
                Some(convert::read_buffer(input_token).to_vec())
            };
            let res = gpm::init_sec_context(
                cred.remote.as_ref(),
                ctx.remote.as_ref(),
                name.remote.as_ref(),
                &mech_bytes,
                req_flags,
                time_req,
                cb.as_ref(),
                in_tok.as_deref(),
            );

            if keep(res.major) {
                ctx.remote = res.context;
                if !actual_mech_type.is_null() {
                    *actual_mech_type = convert::intern_oid(&res.actual_mech);
                }
                if let Some(tok) = &res.output_token {
                    convert::write_buffer(output_token, tok);
                }
                if let Some(c) = &ctx.remote {
                    if !ret_flags.is_null() {
                        *ret_flags = c.ctx_flags as OM_uint32;
                    }
                    if !time_rec.is_null() {
                        *time_rec = c.lifetime as OM_uint32;
                    }
                }
                if let Some(oc) = res.out_cred {
                    cred.remote = Some(oc);
                    if let Some(rc) = &cred.remote {
                        let _ = store_remote_creds(cred.default_creds, &cred.store, rc);
                    }
                }
                break 'done (res.major, res.minor);
            }

            if behavior == Behavior::RemoteFirst {
                let (m, mi) = init_ctx_local(
                    cred,
                    ctx,
                    name,
                    mech_type,
                    req_flags,
                    time_req,
                    input_cb,
                    input_token,
                    actual_mech_type,
                    output_token,
                    ret_flags,
                    time_rec,
                );
                break 'done (m, mi);
            }

            break 'done (res.major, res.minor);
        }

        (consts::GSS_S_FAILURE, 0)
    };

    // done:
    if !keep(maj) && tmaj != COMPLETE {
        maj = tmaj;
        min = tmin;
    }

    let ctx_local = (*ctx_ptr).local;
    let ctx_remote_some = (*ctx_ptr).remote.is_some();
    if !keep(maj) {
        if ctx_local.is_null() && !ctx_remote_some {
            // Free the (empty) context payload.
            drop(CtxHandle::from_raw(ctx_ptr as gss_ctx_id_t));
            *context_handle = ptr::null_mut();
        } else {
            *context_handle = ctx_ptr as gss_ctx_id_t;
        }
        if !minor_status.is_null() {
            *minor_status = map_error(min);
        }
    } else {
        *context_handle = ctx_ptr as gss_ctx_id_t;
    }

    drop(owned_cred);
    maj
}

/// `gssi_accept_sec_context`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn gssi_accept_sec_context(
    minor_status: *mut OM_uint32,
    context_handle: *mut gss_ctx_id_t,
    acceptor_cred_handle: gss_cred_id_t,
    input_token_buffer: gss_buffer_t,
    input_chan_bindings: gss_channel_bindings_t,
    src_name: *mut gss_name_t,
    mech_type: *mut gss_OID,
    output_token: gss_buffer_t,
    ret_flags: *mut OM_uint32,
    time_rec: *mut OM_uint32,
    delegated_cred_handle: *mut gss_cred_id_t,
) -> OM_uint32 {
    let mut behavior = behavior::get();

    let ctx_ptr: *mut CtxHandle = if !(*context_handle).is_null() {
        let p = *context_handle as *mut CtxHandle;
        if !(*p).local.is_null() {
            behavior = Behavior::LocalOnly;
        } else if (*p).remote.is_some() {
            behavior = Behavior::RemoteOnly;
        }
        p
    } else {
        CtxHandle::into_raw(CtxHandle::empty()) as *mut CtxHandle
    };

    let mut owned_cred: Option<Box<CredHandle>> = None;
    let cred_ptr: *mut CredHandle;
    let mut early: Option<(u32, u32)> = None;
    if !acceptor_cred_handle.is_null() {
        cred_ptr = acceptor_cred_handle as *mut CredHandle;
    } else {
        let mut slot: Option<Box<CredHandle>> = None;
        let (m, mi) = handle::get_def_creds(behavior, None, 2, &mut slot);
        if m != COMPLETE {
            early = Some((m, mi));
        }
        owned_cred = slot;
        cred_ptr = match owned_cred.as_mut() {
            Some(c) => c.as_mut() as *mut CredHandle,
            None => ptr::null_mut(),
        };
    }

    if early.is_none() && !cred_ptr.is_null() {
        let cred = &*cred_ptr;
        if !cred.local.is_null() {
            if behavior == Behavior::RemoteOnly {
                early = Some((consts::GSS_S_DEFECTIVE_CREDENTIAL, 0));
            } else {
                behavior = Behavior::LocalOnly;
            }
        } else if cred.remote.is_some() {
            if behavior == Behavior::LocalOnly {
                early = Some((consts::GSS_S_DEFECTIVE_CREDENTIAL, 0));
            } else {
                behavior = Behavior::RemoteOnly;
            }
        }
    }

    let mut name: Option<Box<NameHandle>> = if !src_name.is_null() {
        Some(NameHandle::empty())
    } else {
        None
    };
    let mut deleg: Option<Box<CredHandle>> = if !delegated_cred_handle.is_null() {
        Some(CredHandle::new(false, None))
    } else {
        None
    };

    let (maj, min) = 'done: {
        if let Some(e) = early {
            break 'done e;
        }
        let cred = &*cred_ptr;
        let ctx = &mut *ctx_ptr;

        match behavior {
            Behavior::LocalOnly => {
                let mut min: OM_uint32 = 0;
                let name_local = name
                    .as_mut()
                    .map(|n| &mut n.local as *mut gss_name_t)
                    .unwrap_or(ptr::null_mut());
                let deleg_local = deleg
                    .as_mut()
                    .map(|d| &mut d.local as *mut gss_cred_id_t)
                    .unwrap_or(ptr::null_mut());
                let m = sys::gss_accept_sec_context(
                    &mut min,
                    &mut ctx.local,
                    cred.local,
                    input_token_buffer,
                    input_chan_bindings,
                    name_local,
                    mech_type,
                    output_token,
                    ret_flags,
                    time_rec,
                    deleg_local,
                );
                (m, min)
            }
            Behavior::RemoteOnly => {
                let cb = convert::cb_to_gssx(input_chan_bindings);
                let in_tok = if input_token_buffer.is_null() {
                    Vec::new()
                } else {
                    convert::read_buffer(input_token_buffer).to_vec()
                };
                let res = gpm::accept_sec_context(
                    ctx.remote.as_ref(),
                    cred.remote.as_ref(),
                    &in_tok,
                    cb.as_ref(),
                    !delegated_cred_handle.is_null(),
                );
                if keep(res.major) {
                    ctx.remote = res.context;
                    if let Some(n) = name.as_mut() {
                        n.remote = res.src_name;
                    }
                    if let Some(tok) = &res.output_token {
                        convert::write_buffer(output_token, tok);
                    }
                    if !mech_type.is_null() {
                        *mech_type = convert::intern_oid(&res.actual_mech);
                    }
                    if let Some(c) = &ctx.remote {
                        if !ret_flags.is_null() {
                            *ret_flags = c.ctx_flags as OM_uint32;
                        }
                        if !time_rec.is_null() {
                            *time_rec = c.lifetime as OM_uint32;
                        }
                    }
                    if let Some(d) = deleg.as_mut() {
                        d.remote = res.delegated_cred;
                    }
                }
                (res.major, res.minor)
            }
            _ => (consts::GSS_S_FAILURE, 0),
        }
    };

    if !minor_status.is_null() {
        *minor_status = map_error(min);
    }

    if !keep(maj) {
        let ctx_local = (*ctx_ptr).local;
        let ctx_remote_some = (*ctx_ptr).remote.is_some();
        if ctx_local.is_null() && !ctx_remote_some {
            drop(CtxHandle::from_raw(ctx_ptr as gss_ctx_id_t));
            *context_handle = ptr::null_mut();
        } else {
            *context_handle = ctx_ptr as gss_ctx_id_t;
        }
        drop(name);
        drop(deleg);
    } else {
        *context_handle = ctx_ptr as gss_ctx_id_t;
        if !src_name.is_null() {
            *src_name = match name.take() {
                Some(n) => NameHandle::into_raw(n),
                None => ptr::null_mut(),
            };
        }
        if !delegated_cred_handle.is_null() {
            *delegated_cred_handle = match deleg.take() {
                Some(d) => CredHandle::into_raw(d),
                None => ptr::null_mut(),
            };
        }
    }

    // gpp: when we synthesised a default cred, release it like
    // `gssi_release_cred` does (remote daemon release + local release on drop).
    if let Some(c) = &owned_cred {
        if let Some(r) = &c.remote {
            let _ = gpm::release_cred(r);
        }
    }
    drop(owned_cred);
    maj
}
