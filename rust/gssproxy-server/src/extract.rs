//! `--extract-ccache`: decrypt a gssproxy-sealed credential stashed in a krb5
//! ccache and store it as a usable credential. Port of `src/extract_ccache.c`.
//!
//! gssproxy stores the encrypted credential blob as the "ticket" of a credential
//! whose server principal is the well-known [`GPKRB_SRV_NAME`]. The blob is an
//! XDR-encoded `gssx_cred` whose `cred_handle_reference` is the per-service
//! sealed `gss_export_cred` token. We decode it, unseal it with the default
//! keytab's sealing key, re-import the credential, and store it (into `dest` or
//! the default ccache).

use std::ffi::CString;
use std::ptr;

use gssapi_sys::krb5;
use gssapi_sys::seal::CredHandle;
use gssapi_sys::wrap::{self, Cred};
use gssproxy_proto::gssx::GssxCred;
use gssproxy_proto::{Xdr, XdrDecoder};

/// The special server principal under which gssproxy stores the encrypted
/// credential in a ccache (`GPKRB_SRV_NAME` in `src/gp_common.h`).
const GPKRB_SRV_NAME: &str = "Encrypted/Credentials/v1@X-GSSPROXY:";

/// Extract the gssproxy-encrypted credential from `ccache_name` and store it in
/// `dest` (or the default ccache when `None`).
pub fn extract_ccache(ccache_name: &str, dest: Option<&str>) -> Result<(), String> {
    let blob = read_sealed_blob(ccache_name)?;

    let mut d = XdrDecoder::new(&blob);
    let xcred = GssxCred::decode(&mut d).map_err(|e| format!("decoding gssx_cred: {e:?}"))?;

    let handle = CredHandle::new(None).map_err(|e| format!("deriving sealing key: {e}"))?;
    let token = handle
        .unseal(xcred.cred_handle_reference.as_slice())
        .map_err(|e| format!("decrypting credential handle: {e}"))?;

    let cred = Cred::import_token(&token).map_err(|e| format!("importing credential: {e}"))?;
    wrap::store_cred_into(&cred, dest).map_err(|e| format!("storing credential: {e}"))?;
    Ok(())
}

/// Read the XDR-encoded `gssx_cred` blob gssproxy stashes in the ccache as the
/// ticket of a credential for the [`GPKRB_SRV_NAME`] server principal.
fn read_sealed_blob(ccache_name: &str) -> Result<Vec<u8>, String> {
    unsafe {
        let mut ctx: krb5::krb5_context = ptr::null_mut();
        if krb5::krb5_init_context(&mut ctx) != 0 {
            return Err("krb5_init_context failed".into());
        }
        let r = read_sealed_blob_inner(ctx, ccache_name);
        krb5::krb5_free_context(ctx);
        r
    }
}

unsafe fn read_sealed_blob_inner(
    ctx: krb5::krb5_context,
    ccache_name: &str,
) -> Result<Vec<u8>, String> {
    let cc_cname = CString::new(ccache_name).map_err(|_| "invalid ccache name".to_string())?;
    let srv_cname = CString::new(GPKRB_SRV_NAME).unwrap();

    let mut ccache: krb5::krb5_ccache = ptr::null_mut();
    if krb5::krb5_cc_resolve(ctx, cc_cname.as_ptr(), &mut ccache) != 0 {
        return Err(format!("cannot resolve ccache {ccache_name}"));
    }

    let mut mcreds: krb5::krb5_creds = std::mem::zeroed();
    let mut creds: krb5::krb5_creds = std::mem::zeroed();

    let result: Result<Vec<u8>, String> = 'work: {
        if krb5::krb5_cc_get_principal(ctx, ccache, &mut mcreds.client) != 0 {
            break 'work Err("cannot read ccache principal".into());
        }
        if krb5::krb5_parse_name(ctx, srv_cname.as_ptr(), &mut mcreds.server) != 0 {
            break 'work Err("cannot parse gssproxy server principal".into());
        }
        if krb5::krb5_cc_retrieve_cred(ctx, ccache, 0, &mut mcreds, &mut creds) != 0 {
            break 'work Err("no gssproxy credential in ccache".into());
        }
        let t = &creds.ticket;
        if t.data.is_null() || t.length == 0 {
            break 'work Err("empty gssproxy credential ticket".into());
        }
        Ok(std::slice::from_raw_parts(t.data as *const u8, t.length as usize).to_vec())
    };

    krb5::krb5_free_cred_contents(ctx, &mut creds);
    krb5::krb5_free_cred_contents(ctx, &mut mcreds);
    krb5::krb5_cc_close(ctx, ccache);

    result
}
