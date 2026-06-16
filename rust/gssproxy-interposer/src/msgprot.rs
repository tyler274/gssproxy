//! Message protection: `gssi_wrap` / `gssi_unwrap` / `gssi_get_mic` /
//! `gssi_verify_mic` and the iov/aead/size-limit variants. Port of
//! `gpp_priv_integ.c`.
//!
//! These are always handled locally: if the context lives only on the daemon,
//! it is first materialised into a real local context via
//! `gpp_remote_to_local_ctx`, then the real `gss_*` routine runs.

use gssapi_sys::sys::{
    self, gss_buffer_t, gss_ctx_id_t, gss_iov_buffer_desc, gss_qop_t, OM_uint32,
};

use crate::error::map_error;
use crate::handle;

/// Ensure the context has a usable local handle, importing the remote one if
/// needed. Returns the resolved local `gss_ctx_id_t` or an error major status
/// (with `minor_status` already set).
unsafe fn ensure_local(
    context_handle: gss_ctx_id_t,
    minor_status: *mut OM_uint32,
) -> Result<gss_ctx_id_t, OM_uint32> {
    match handle::ensure_local_ctx(context_handle) {
        Ok(l) => Ok(l),
        Err((maj, min)) => {
            if min != 0 && !minor_status.is_null() {
                *minor_status = map_error(min);
            }
            Err(maj)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn gssi_wrap(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    conf_req_flag: i32,
    qop_req: gss_qop_t,
    input_message_buffer: gss_buffer_t,
    conf_state: *mut i32,
    output_message_buffer: gss_buffer_t,
) -> OM_uint32 {
    let local = match ensure_local(context_handle, minor_status) {
        Ok(l) => l,
        Err(maj) => return maj,
    };
    sys::gss_wrap(
        minor_status,
        local,
        conf_req_flag,
        qop_req,
        input_message_buffer,
        conf_state,
        output_message_buffer,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gssi_wrap_size_limit(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    conf_req_flag: i32,
    qop_req: gss_qop_t,
    req_output_size: OM_uint32,
    max_input_size: *mut OM_uint32,
) -> OM_uint32 {
    let local = match ensure_local(context_handle, minor_status) {
        Ok(l) => l,
        Err(maj) => return maj,
    };
    sys::gss_wrap_size_limit(
        minor_status,
        local,
        conf_req_flag,
        qop_req,
        req_output_size,
        max_input_size,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gssi_wrap_iov(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    conf_req_flag: i32,
    qop_req: gss_qop_t,
    conf_state: *mut i32,
    iov: *mut gss_iov_buffer_desc,
    iov_count: i32,
) -> OM_uint32 {
    let local = match ensure_local(context_handle, minor_status) {
        Ok(l) => l,
        Err(maj) => return maj,
    };
    sys::gss_wrap_iov(
        minor_status,
        local,
        conf_req_flag,
        qop_req,
        conf_state,
        iov,
        iov_count,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gssi_wrap_iov_length(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    conf_req_flag: i32,
    qop_req: gss_qop_t,
    conf_state: *mut i32,
    iov: *mut gss_iov_buffer_desc,
    iov_count: i32,
) -> OM_uint32 {
    let local = match ensure_local(context_handle, minor_status) {
        Ok(l) => l,
        Err(maj) => return maj,
    };
    sys::gss_wrap_iov_length(
        minor_status,
        local,
        conf_req_flag,
        qop_req,
        conf_state,
        iov,
        iov_count,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gssi_wrap_aead(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    conf_req_flag: i32,
    qop_req: gss_qop_t,
    input_assoc_buffer: gss_buffer_t,
    input_payload_buffer: gss_buffer_t,
    conf_state: *mut i32,
    output_message_buffer: gss_buffer_t,
) -> OM_uint32 {
    let local = match ensure_local(context_handle, minor_status) {
        Ok(l) => l,
        Err(maj) => return maj,
    };
    sys::gss_wrap_aead(
        minor_status,
        local,
        conf_req_flag,
        qop_req,
        input_assoc_buffer,
        input_payload_buffer,
        conf_state,
        output_message_buffer,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gssi_unwrap(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    input_message_buffer: gss_buffer_t,
    output_message_buffer: gss_buffer_t,
    conf_state: *mut i32,
    qop_state: *mut gss_qop_t,
) -> OM_uint32 {
    let local = match ensure_local(context_handle, minor_status) {
        Ok(l) => l,
        Err(maj) => return maj,
    };
    sys::gss_unwrap(
        minor_status,
        local,
        input_message_buffer,
        output_message_buffer,
        conf_state,
        qop_state,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gssi_unwrap_iov(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    conf_state: *mut i32,
    qop_state: *mut gss_qop_t,
    iov: *mut gss_iov_buffer_desc,
    iov_count: i32,
) -> OM_uint32 {
    let local = match ensure_local(context_handle, minor_status) {
        Ok(l) => l,
        Err(maj) => return maj,
    };
    sys::gss_unwrap_iov(minor_status, local, conf_state, qop_state, iov, iov_count)
}

#[no_mangle]
pub unsafe extern "C" fn gssi_unwrap_aead(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    input_message_buffer: gss_buffer_t,
    input_assoc_buffer: gss_buffer_t,
    output_payload_buffer: gss_buffer_t,
    conf_state: *mut i32,
    qop_state: *mut gss_qop_t,
) -> OM_uint32 {
    let local = match ensure_local(context_handle, minor_status) {
        Ok(l) => l,
        Err(maj) => return maj,
    };
    sys::gss_unwrap_aead(
        minor_status,
        local,
        input_message_buffer,
        input_assoc_buffer,
        output_payload_buffer,
        conf_state,
        qop_state,
    )
}

#[no_mangle]
pub unsafe extern "C" fn gssi_get_mic(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    qop_req: gss_qop_t,
    message_buffer: gss_buffer_t,
    message_token: gss_buffer_t,
) -> OM_uint32 {
    let local = match ensure_local(context_handle, minor_status) {
        Ok(l) => l,
        Err(maj) => return maj,
    };
    sys::gss_get_mic(minor_status, local, qop_req, message_buffer, message_token)
}

#[no_mangle]
pub unsafe extern "C" fn gssi_verify_mic(
    minor_status: *mut OM_uint32,
    context_handle: gss_ctx_id_t,
    message_buffer: gss_buffer_t,
    message_token: gss_buffer_t,
    qop_state: *mut gss_qop_t,
) -> OM_uint32 {
    let local = match ensure_local(context_handle, minor_status) {
        Ok(l) => l,
        Err(maj) => return maj,
    };
    sys::gss_verify_mic(minor_status, local, message_buffer, message_token, qop_state)
}
