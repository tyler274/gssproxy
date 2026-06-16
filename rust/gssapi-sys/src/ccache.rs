//! krb5 credential-cache helpers for the interposer's cred-sync path.
//!
//! Port of the ccache machinery in `src/mechglue/gpp_creds.c`
//! (`gpp_store_remote_creds` / `gppint_retrieve_remote_creds`). gssproxy stashes
//! a remote `gssx_cred` in a local krb5 ccache as the `ticket` blob of a krb5
//! credential whose server principal is the well-known [`GPKRB_SRV_NAME`], keyed
//! by the credential's client (display) name.
//!
//! These helpers operate on the already-XDR-encoded `gssx_cred` bytes so this
//! crate stays free of a `gssproxy-proto` dependency; the interposer does the
//! `gssx_cred` <-> bytes conversion.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use crate::krb5;

/// The well-known server principal under which a sealed `gssx_cred` blob is
/// stashed (`GPKRB_SRV_NAME` in `src/gp_common.h`).
const GPKRB_SRV_NAME: &str = "Encrypted/Credentials/v1@X-GSSPROXY:";

/// Maximum size of the encoded credential blob (`GPKRB_MAX_CRED_SIZE`).
const GPKRB_MAX_CRED_SIZE: usize = 1024 * 512;

/// A krb5 error code (or a synthetic errno) describing a ccache failure.
pub type CcResult<T> = std::result::Result<T, i32>;

/// Run `f` with an initialised krb5 context, freeing it afterwards.
unsafe fn with_context<T>(f: impl FnOnce(krb5::krb5_context) -> CcResult<T>) -> CcResult<T> {
    unsafe {
        let mut ctx: krb5::krb5_context = ptr::null_mut();
        let ret = krb5::krb5_init_context(&mut ctx);
        if ret != 0 {
            return Err(ret as i32);
        }
        let out = f(ctx);
        krb5::krb5_free_context(ctx);
        out
    }
}

/// `gpp_store_remote_creds`: persist the encoded `gssx_cred` blob `ticket` into
/// a local krb5 ccache, keyed by the client principal `client_name`.
///
/// `cred_store` mirrors the `gss_key_value_set` the caller configured (only the
/// `ccache` entry is honoured, as in C). When `store_as_default` is set the
/// resulting ccache is switched to be the collection default.
pub fn store_remote_cred(
    cred_store: &[(String, String)],
    client_name: &[u8],
    ticket: &[u8],
    store_as_default: bool,
) -> CcResult<()> {
    if ticket.len() > GPKRB_MAX_CRED_SIZE {
        return Err(libc::ENOSPC);
    }
    let client_c = CString::new(client_name).map_err(|_| libc::EINVAL)?;
    let server_c = CString::new(GPKRB_SRV_NAME).unwrap();

    unsafe {
        with_context(|ctx| {
            let mut ccache: krb5::krb5_ccache = ptr::null_mut();
            // Build the krb5_creds carrying our blob (gpp_construct_cred).
            let mut cred: krb5::krb5_creds = std::mem::zeroed();
            let mut ret = krb5::krb5_parse_name(ctx, client_c.as_ptr(), &mut cred.client);
            if ret == 0 {
                ret = krb5::krb5_parse_name(ctx, server_c.as_ptr(), &mut cred.server);
            }
            if ret == 0 {
                // ticket.data must be malloc'd so krb5_free_cred_contents frees it.
                let data = libc::malloc(ticket.len().max(1)) as *mut c_char;
                if data.is_null() {
                    ret = libc::ENOMEM;
                } else {
                    ptr::copy_nonoverlapping(ticket.as_ptr(), data as *mut u8, ticket.len());
                    cred.ticket.data = data;
                    cred.ticket.length = ticket.len() as _;
                }
            }

            if ret == 0 {
                // Point the context's default ccache name at the configured store.
                for (k, v) in cred_store {
                    if k == "ccache" {
                        if let Ok(cv) = CString::new(v.as_bytes()) {
                            ret = krb5::krb5_cc_set_default_name(ctx, cv.as_ptr());
                        } else {
                            ret = libc::EINVAL;
                        }
                        break;
                    }
                }
            }

            if ret == 0 {
                ret = store_into_ccache(ctx, &mut cred, &mut ccache, store_as_default);
            }

            krb5::krb5_free_cred_contents(ctx, &mut cred);
            if !ccache.is_null() {
                krb5::krb5_cc_close(ctx, ccache);
            }
            if ret == 0 { Ok(()) } else { Err(ret as i32) }
        })
    }
}

/// The collection-vs-FILE store logic factored out of [`store_remote_cred`].
unsafe fn store_into_ccache(
    ctx: krb5::krb5_context,
    cred: &mut krb5::krb5_creds,
    ccache: &mut krb5::krb5_ccache,
    store_as_default: bool,
) -> krb5::krb5_error_code {
    unsafe {
        let cc_name_ptr = krb5::krb5_cc_default_name(ctx);
        if cc_name_ptr.is_null() {
            return libc::ENOMEM as krb5::krb5_error_code;
        }
        let cc_name = CStr::from_ptr(cc_name_ptr).to_bytes().to_vec();

        let is_file = cc_name.starts_with(b"FILE:") || !cc_name.contains(&b':');
        if is_file {
            // FILE ccaches blackhole same-principal updates: reinitialise.
            let mut ret = krb5::krb5_cc_default(ctx, ccache);
            if ret == 0 {
                ret = krb5::krb5_cc_initialize(ctx, *ccache, cred.client);
            }
            if ret == 0 {
                ret = krb5::krb5_cc_store_cred(ctx, *ccache, cred);
            }
            return ret;
        }

        let mut ret = krb5::krb5_cc_cache_match(ctx, cred.client, ccache);
        if ret == krb5::KRB5_CC_NOTFOUND as krb5::krb5_error_code {
            // New ccache in the collection; krb5_cc_new_unique takes only the type.
            let colon = cc_name
                .iter()
                .position(|&b| b == b':')
                .unwrap_or(cc_name.len());
            let cc_type = match CString::new(&cc_name[..colon]) {
                Ok(t) => t,
                Err(_) => return libc::ENOMEM as krb5::krb5_error_code,
            };
            ret = krb5::krb5_cc_new_unique(ctx, cc_type.as_ptr(), ptr::null(), ccache);
            if ret == 0 {
                ret = krb5::krb5_cc_initialize(ctx, *ccache, cred.client);
            }
        }
        if ret != 0 {
            return ret;
        }

        ret = krb5::krb5_cc_store_cred(ctx, *ccache, cred);
        if ret != 0 {
            return ret;
        }

        if store_as_default {
            ret = krb5::krb5_cc_switch(ctx, *ccache);
        }
        ret
    }
}

/// `gppint_retrieve_remote_creds`: fetch the encoded `gssx_cred` blob stashed
/// under [`GPKRB_SRV_NAME`] for `client_name` (or the ccache's default
/// principal when `None`). Returns the raw ticket bytes (the XDR `gssx_cred`).
pub fn retrieve_remote_cred(
    ccache_name: Option<&str>,
    client_name: Option<&[u8]>,
) -> CcResult<Vec<u8>> {
    let server_c = CString::new(GPKRB_SRV_NAME).unwrap();
    let ccache_c = match ccache_name {
        Some(n) => Some(CString::new(n).map_err(|_| libc::EINVAL)?),
        None => None,
    };
    let client_c = match client_name {
        Some(n) => Some(CString::new(n).map_err(|_| libc::EINVAL)?),
        None => None,
    };

    unsafe {
        with_context(|ctx| {
            let mut ccache: krb5::krb5_ccache = ptr::null_mut();
            let mut cred: krb5::krb5_creds = std::mem::zeroed();
            let mut icred: krb5::krb5_creds = std::mem::zeroed();

            let mut ret = match &ccache_c {
                Some(c) => krb5::krb5_cc_resolve(ctx, c.as_ptr(), &mut ccache),
                None => krb5::krb5_cc_default(ctx, &mut ccache),
            };

            if ret == 0 {
                ret = match &client_c {
                    Some(c) => krb5::krb5_parse_name(ctx, c.as_ptr(), &mut icred.client),
                    None => krb5::krb5_cc_get_principal(ctx, ccache, &mut icred.client),
                };
            }
            if ret == 0 {
                ret = krb5::krb5_parse_name(ctx, server_c.as_ptr(), &mut icred.server);
            }
            if ret == 0 {
                ret = krb5::krb5_cc_retrieve_cred(ctx, ccache, 0, &mut icred, &mut cred);
            }

            let out = if ret == 0 {
                let len = cred.ticket.length as usize;
                if cred.ticket.data.is_null() || len == 0 {
                    Err(libc::EIO)
                } else {
                    Ok(std::slice::from_raw_parts(cred.ticket.data as *const u8, len).to_vec())
                }
            } else {
                Err(ret as i32)
            };

            krb5::krb5_free_cred_contents(ctx, &mut cred);
            krb5::krb5_free_cred_contents(ctx, &mut icred);
            if !ccache.is_null() {
                krb5::krb5_cc_close(ctx, ccache);
            }
            out
        })
    }
}
