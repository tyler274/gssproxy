//! The opaque interposer handle payloads and the `gpp_*` helper functions that
//! convert between local (real-mech) and remote (gssx/daemon) representations.
//!
//! Mirrors the `struct gpp_cred_handle` / `gpp_context_handle` /
//! `gpp_name_handle` definitions in `gss_plugin.h` and the helper functions in
//! `gss_plugin.c` / `gpp_creds.c`. The mechglue treats these as opaque
//! `gss_cred_id_t` / `gss_ctx_id_t` / `gss_name_t` pointers; we move them across
//! the C ABI with `Box::into_raw` / `Box::from_raw`.

use std::os::raw::c_void;
use std::ptr;

use gssapi_sys::sys::{
    self, OM_uint32, gss_OID, gss_OID_desc, gss_buffer_desc, gss_cred_id_t, gss_ctx_id_t,
    gss_name_t,
};
use gssapi_sys::{ccache, consts};
use gssproxy_client::gpm;
use gssproxy_proto::gssx::{GssxCred, GssxCtx, GssxName};

use crate::behavior::Behavior;
use crate::{convert, oids, special};

/// `(major, minor)` status pair.
pub type Status = (u32, u32);

const COMPLETE: u32 = 0;

// ===========================================================================
// Owned OID (gpp_copy_oid)
// ===========================================================================

/// A heap-owned `gss_OID` with stable address, like `gpp_copy_oid`'s malloc'd
/// descriptor. The `desc.elements` pointer references `bytes`, which never moves
/// while boxed.
pub struct OwnedOid {
    bytes: Vec<u8>,
    desc: gss_OID_desc,
}

impl OwnedOid {
    pub fn new(bytes: Vec<u8>) -> Box<OwnedOid> {
        let mut b = Box::new(OwnedOid {
            desc: gss_OID_desc {
                length: bytes.len() as OM_uint32,
                elements: ptr::null_mut(),
            },
            bytes,
        });
        b.desc.elements = b.bytes.as_ptr() as *mut c_void;
        b
    }

    /// `gpp_copy_oid`: clone the bytes behind a C `gss_OID`.
    ///
    /// # Safety
    /// `oid` must be null or a valid `gss_OID`.
    pub unsafe fn from_oid(oid: gss_OID) -> Option<Box<OwnedOid>> {
        unsafe { convert::oid_bytes(oid).map(|b| OwnedOid::new(b.to_vec())) }
    }

    pub fn as_ptr(&self) -> gss_OID {
        &self.desc as *const _ as gss_OID
    }
}

// ===========================================================================
// Credential handle
// ===========================================================================

pub struct CredHandle {
    pub remote: Option<GssxCred>,
    /// gss_key_value_set: only the `ccache` entry is used (as in C).
    pub store: Vec<(String, String)>,
    pub default_creds: bool,
    pub local: gss_cred_id_t,
}

impl CredHandle {
    /// `gpp_cred_handle_init`.
    pub fn new(defcred: bool, ccache_name: Option<&str>) -> Box<CredHandle> {
        let store = match ccache_name {
            Some(c) => vec![("ccache".to_string(), c.to_string())],
            None => Vec::new(),
        };
        Box::new(CredHandle {
            remote: None,
            store,
            default_creds: defcred,
            local: ptr::null_mut(),
        })
    }

    pub fn into_raw(b: Box<CredHandle>) -> gss_cred_id_t {
        Box::into_raw(b) as gss_cred_id_t
    }

    /// # Safety
    /// `p` must be null or a pointer previously produced by [`into_raw`].
    pub unsafe fn as_mut<'a>(p: gss_cred_id_t) -> Option<&'a mut CredHandle> {
        unsafe { (p as *mut CredHandle).as_mut() }
    }

    /// # Safety
    /// `p` must be a pointer previously produced by [`into_raw`] and not freed.
    pub unsafe fn from_raw(p: gss_cred_id_t) -> Box<CredHandle> {
        unsafe { Box::from_raw(p as *mut CredHandle) }
    }
}

impl Drop for CredHandle {
    /// `gpp_cred_handle_free`: release the local cred; the remote `gssx_cred` is
    /// just dropped (the daemon-side release is the explicit `gssi_release_cred`
    /// path, which calls `gpm_release_cred` first).
    fn drop(&mut self) {
        if !self.local.is_null() {
            let mut min: OM_uint32 = 0;
            unsafe { sys::gss_release_cred(&mut min, &mut self.local) };
        }
    }
}

// ===========================================================================
// Context handle
// ===========================================================================

pub struct CtxHandle {
    pub remote: Option<GssxCtx>,
    pub local: gss_ctx_id_t,
}

impl CtxHandle {
    pub fn empty() -> Box<CtxHandle> {
        Box::new(CtxHandle {
            remote: None,
            local: ptr::null_mut(),
        })
    }

    pub fn into_raw(b: Box<CtxHandle>) -> gss_ctx_id_t {
        Box::into_raw(b) as gss_ctx_id_t
    }

    /// # Safety
    /// `p` must be null or a pointer previously produced by [`into_raw`].
    pub unsafe fn as_mut<'a>(p: gss_ctx_id_t) -> Option<&'a mut CtxHandle> {
        unsafe { (p as *mut CtxHandle).as_mut() }
    }

    /// # Safety
    /// `p` must be a pointer previously produced by [`into_raw`] and not freed.
    pub unsafe fn from_raw(p: gss_ctx_id_t) -> Box<CtxHandle> {
        unsafe { Box::from_raw(p as *mut CtxHandle) }
    }
}

impl Drop for CtxHandle {
    /// Safety net: release a local context if one is still held. The remote
    /// context's daemon-side release is the explicit `gssi_delete_sec_context`
    /// path.
    fn drop(&mut self) {
        if !self.local.is_null() {
            let mut min: OM_uint32 = 0;
            unsafe { sys::gss_delete_sec_context(&mut min, &mut self.local, ptr::null_mut()) };
        }
    }
}

// ===========================================================================
// Name handle
// ===========================================================================

pub struct NameHandle {
    pub mech_type: Option<Box<OwnedOid>>,
    pub remote: Option<GssxName>,
    pub local: gss_name_t,
}

impl NameHandle {
    pub fn empty() -> Box<NameHandle> {
        Box::new(NameHandle {
            mech_type: None,
            remote: None,
            local: ptr::null_mut(),
        })
    }

    pub fn into_raw(b: Box<NameHandle>) -> gss_name_t {
        Box::into_raw(b) as gss_name_t
    }

    /// # Safety
    /// `p` must be null or a pointer previously produced by [`into_raw`].
    pub unsafe fn as_mut<'a>(p: gss_name_t) -> Option<&'a mut NameHandle> {
        unsafe { (p as *mut NameHandle).as_mut() }
    }

    /// # Safety
    /// `p` must be a pointer previously produced by [`into_raw`] and not freed.
    pub unsafe fn from_raw(p: gss_name_t) -> Box<NameHandle> {
        unsafe { Box::from_raw(p as *mut NameHandle) }
    }

    pub fn mech_ptr(&self) -> gss_OID {
        match &self.mech_type {
            Some(o) => o.as_ptr(),
            None => ptr::null_mut(),
        }
    }
}

impl Drop for NameHandle {
    fn drop(&mut self) {
        if !self.local.is_null() {
            let mut min: OM_uint32 = 0;
            unsafe { sys::gss_release_name(&mut min, &mut self.local) };
        }
    }
}

// ===========================================================================
// gpp_* helpers
// ===========================================================================

/// `gpp_wrap_sec_ctx_token`: prepend `htobe32(spmech.len) || spmech` to `token`
/// using the special form of `mech_type`.
///
/// # Safety
/// `mech_type` must be null or a valid `gss_OID`.
pub unsafe fn wrap_sec_ctx_token(mech_type: gss_OID, token: &[u8]) -> Option<Vec<u8>> {
    unsafe {
        let sp = special::special_mech(mech_type as *const gss_OID_desc);
        let sp_bytes = convert::oid_bytes(sp)?;
        let mut out = Vec::with_capacity(4 + sp_bytes.len() + token.len());
        out.extend_from_slice(&(sp_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(sp_bytes);
        out.extend_from_slice(token);
        Some(out)
    }
}

/// `gpp_remote_to_local_ctx`: import the remote context's exported token into a
/// real local context (consuming the remote one on success).
///
/// # Safety
/// `local` must point to a writable `gss_ctx_id_t`.
pub unsafe fn remote_to_local_ctx(
    remote: &mut Option<GssxCtx>,
    local: &mut gss_ctx_id_t,
) -> Status {
    unsafe {
        let token = match remote {
            Some(c) => c.exported_context_token.as_slice().to_vec(),
            None => return (consts::GSS_S_FAILURE, 0),
        };
        if token.len() <= 4 {
            return (consts::GSS_S_FAILURE, 0);
        }
        let mech_len = u32::from_be_bytes([token[0], token[1], token[2], token[3]]) as usize;
        let hlen = 4 + mech_len;
        if token.len() <= hlen {
            return (consts::GSS_S_FAILURE, 0);
        }
        let mech_oid = convert::TmpOid::new(&token[4..hlen]);
        let inner = &token[hlen..];

        let wrapped = match wrap_sec_ctx_token(mech_oid.as_ptr(), inner) {
            Some(w) => w,
            None => return (consts::GSS_S_FAILURE, 0),
        };
        let wrapbuf = convert::TmpBuf::new(&wrapped);
        let mut min: OM_uint32 = 0;
        let maj = sys::gss_import_sec_context(&mut min, wrapbuf.as_ptr(), local);
        *remote = None;
        (maj, min)
    }
}

/// Resolve a context payload to a usable local `gss_ctx_id_t`, importing the
/// remote context when only a daemon-side context exists. Used by the message
/// protection and context-lifecycle entry points. On failure, returns the
/// major status and the (unmapped) minor.
///
/// # Safety
/// `context_handle` must be null or a pointer produced by [`CtxHandle::into_raw`].
pub unsafe fn ensure_local_ctx(context_handle: gss_ctx_id_t) -> Result<gss_ctx_id_t, Status> {
    unsafe {
        if context_handle.is_null() {
            return Err((consts::GSS_S_CALL_INACCESSIBLE_READ, 0));
        }
        let ctx = match CtxHandle::as_mut(context_handle) {
            Some(c) => c,
            None => return Err((consts::GSS_S_CALL_INACCESSIBLE_READ, 0)),
        };
        if ctx.remote.is_some() && ctx.local.is_null() {
            let (maj, min) = remote_to_local_ctx(&mut ctx.remote, &mut ctx.local);
            if maj != COMPLETE {
                return Err((maj, min));
            }
        }
        Ok(ctx.local)
    }
}

/// `gpp_name_to_local`: turn a remote `gssx_name` into a real local
/// `gss_name_t`, canonicalising for `mech_type` when one is given. Returns the
/// new name on success.
///
/// # Safety
/// `mech_type` must be null or a valid `gss_OID`.
pub unsafe fn name_to_local(remote: &mut GssxName, mech_type: gss_OID) -> (u32, u32, gss_name_t) {
    unsafe {
        let (maj, min, disp, ntype) = gpm::display_name(remote);
        if maj != COMPLETE {
            return (maj, min, ptr::null_mut());
        }
        let ntype_oid = match convert::name_type_static(&ntype) {
            Some(o) => o,
            None => return (consts::GSS_S_FAILURE, libc::ENOENT as u32, ptr::null_mut()),
        };

        let inbuf = convert::TmpBuf::new(&disp);
        let mut tmpname: gss_name_t = ptr::null_mut();
        let mut min2: OM_uint32 = 0;
        let maj2 = sys::gss_import_name(&mut min2, inbuf.as_ptr(), ntype_oid, &mut tmpname);
        if maj2 != COMPLETE {
            return (maj2, min2, ptr::null_mut());
        }

        let mut maj3 = COMPLETE;
        let mut min3: OM_uint32 = 0;
        if !mech_type.is_null() {
            let sp = special::special_mech(mech_type as *const gss_OID_desc);
            maj3 = sys::gss_canonicalize_name(&mut min3, tmpname, sp, ptr::null_mut());
        }
        (maj3, min3, tmpname)
    }
}

/// `gpp_local_to_name`: turn a real local `gss_name_t` into a `gssx_name`.
///
/// # Safety
/// `local` must be a valid `gss_name_t`.
pub unsafe fn local_to_name(local: gss_name_t) -> (u32, u32, Option<GssxName>) {
    unsafe {
        let mut buf = gss_buffer_desc {
            length: 0,
            value: ptr::null_mut(),
        };
        let mut ntype: gss_OID = ptr::null_mut();
        let mut min: OM_uint32 = 0;
        let maj = sys::gss_display_name(&mut min, local, &mut buf, &mut ntype);
        if maj != COMPLETE {
            return (maj, min, None);
        }
        let disp = convert::read_buffer(&mut buf as *mut _).to_vec();
        let nt = convert::oid_bytes(ntype)
            .map(|b| b.to_vec())
            .unwrap_or_default();
        convert::release_buffer(&mut buf as *mut _);
        let name = gpm::import_name(&disp, &nt);
        (COMPLETE, 0, Some(name))
    }
}

/// `gpp_creds_are_equal`: compare two `gssx_cred`s by desired name, element
/// count, and cred-handle reference (the only fields C checks).
pub fn creds_are_equal(a: Option<&GssxCred>, b: Option<&GssxCred>) -> bool {
    match (a, b) {
        (None, None) => return true,
        (None, _) | (_, None) => return false,
        _ => {}
    }
    let a = a.unwrap();
    let b = b.unwrap();
    if a.desired_name.display_name.as_slice() != b.desired_name.display_name.as_slice() {
        return false;
    }
    if a.elements.len() != b.elements.len() {
        return false;
    }
    a.cred_handle_reference.as_slice() == b.cred_handle_reference.as_slice()
}

/// `gpp_store_remote_creds`: stash a remote cred in the local ccache.
pub fn store_remote_creds(
    default_cred: bool,
    store: &[(String, String)],
    creds: &GssxCred,
) -> Status {
    let ticket = gpm::encode_cred(creds);
    let client = creds.desired_name.display_name.as_slice();
    match ccache::store_remote_cred(store, client, &ticket, default_cred) {
        Ok(()) => (COMPLETE, 0),
        Err(e) => (consts::GSS_S_FAILURE, e as u32),
    }
}

/// `gppint_retrieve_remote_creds`: fetch a stashed remote cred from the ccache.
pub fn retrieve_remote_creds(
    ccache_name: Option<&str>,
    name: Option<&GssxName>,
) -> (u32, u32, Option<GssxCred>) {
    let client = name.map(|n| n.display_name.as_slice());
    match ccache::retrieve_remote_cred(ccache_name, client) {
        Ok(bytes) => match gpm::decode_cred(&bytes) {
            Some(c) => (COMPLETE, 0, Some(c)),
            None => (consts::GSS_S_FAILURE, libc::EIO as u32, None),
        },
        Err(e) => (consts::GSS_S_FAILURE, e as u32, None),
    }
}

/// `get_local_def_creds`: acquire default local creds for the interposed mechs.
unsafe fn get_local_def_creds(
    name_local: gss_name_t,
    cred_usage: i32,
    out_local: &mut gss_cred_id_t,
) -> Status {
    unsafe {
        let mut interposed = crate::gss_mech_interposer(oids::interposer() as gss_OID);
        if interposed.is_null() {
            return (consts::GSS_S_FAILURE, 0);
        }
        let mut special = special::special_available_mechs(interposed);
        let mut min: OM_uint32 = 0;
        if special.is_null() {
            sys::gss_release_oid_set(&mut min, &mut interposed);
            return (consts::GSS_S_FAILURE, 0);
        }
        let mut min2: OM_uint32 = 0;
        let maj = sys::gss_acquire_cred(
            &mut min2,
            name_local,
            0,
            special,
            cred_usage,
            out_local,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        let mut m: OM_uint32 = 0;
        sys::gss_release_oid_set(&mut m, &mut special);
        sys::gss_release_oid_set(&mut m, &mut interposed);
        (maj, min2)
    }
}

/// `gppint_get_def_creds`: obtain default creds honouring the behavior matrix,
/// reusing the cred handle in `slot` or creating a new one.
///
/// # Safety
/// Calls into the real mechglue and the daemon.
pub unsafe fn get_def_creds(
    behavior: Behavior,
    name: Option<&mut NameHandle>,
    cred_usage: i32,
    slot: &mut Option<Box<CredHandle>>,
) -> Status {
    unsafe {
        if slot.is_none() {
            *slot = Some(CredHandle::new(true, None));
        }
        let name_local = name.as_ref().map(|n| n.local).unwrap_or(ptr::null_mut());
        let name_remote = name.and_then(|n| n.remote.as_ref());

        let cred = slot.as_mut().unwrap();
        let mut tmaj = COMPLETE;
        let mut tmin = 0u32;
        let mut maj = consts::GSS_S_FAILURE;
        let mut min = 0u32;

        if behavior == Behavior::LocalOnly || behavior == Behavior::LocalFirst {
            let (m, mi) = get_local_def_creds(name_local, cred_usage, &mut cred.local);
            maj = m;
            min = mi;
            if maj == COMPLETE || behavior == Behavior::LocalOnly {
                return finish_def_creds(maj, min, tmaj, tmin);
            }
            tmaj = maj;
            tmin = min;
        }

        if behavior != Behavior::LocalOnly {
            let (rmaj, _, remote) = retrieve_remote_creds(None, name_remote);
            let premote = if rmaj == COMPLETE { remote } else { None };

            let acq = gpm::acquire_cred(premote.as_ref(), None, 0, &[], cred_usage, false);
            maj = acq.major;
            min = acq.minor;
            if maj == COMPLETE {
                cred.remote = acq.cred;
                if let Some(p) = &premote
                    && !creds_are_equal(Some(p), cred.remote.as_ref())
                    && let Some(rc) = &cred.remote
                {
                    let (sm, smi) = store_remote_creds(cred.default_creds, &cred.store, rc);
                    maj = sm;
                    min = smi;
                }
            }

            if maj == COMPLETE {
                return finish_def_creds(maj, min, tmaj, tmin);
            }

            if behavior == Behavior::RemoteFirst {
                let (m, mi) = get_local_def_creds(name_local, cred_usage, &mut cred.local);
                maj = m;
                min = mi;
            }
        }

        finish_def_creds(maj, min, tmaj, tmin)
    }
}

fn finish_def_creds(maj: u32, min: u32, tmaj: u32, tmin: u32) -> Status {
    if maj != COMPLETE && tmaj != COMPLETE {
        (tmaj, tmin)
    } else {
        (maj, min)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gssproxy_proto::gssx::{GssxCredElement, Opaque};

    fn cred(name: &[u8], elements: usize, href: &[u8]) -> GssxCred {
        let mut c = GssxCred::default();
        c.desired_name.display_name = Opaque::new(name.to_vec());
        c.elements = vec![GssxCredElement::default(); elements];
        c.cred_handle_reference = Opaque::new(href.to_vec());
        c
    }

    #[test]
    fn creds_are_equal_matches_c_fields() {
        // None/None is equal; None/Some is not.
        assert!(creds_are_equal(None, None));
        let a = cred(b"alice", 1, b"ref");
        assert!(!creds_are_equal(None, Some(&a)));
        assert!(!creds_are_equal(Some(&a), None));

        // Equal across the three compared fields.
        let b = cred(b"alice", 1, b"ref");
        assert!(creds_are_equal(Some(&a), Some(&b)));

        // Differ in display name / element count / handle reference.
        assert!(!creds_are_equal(Some(&a), Some(&cred(b"bob", 1, b"ref"))));
        assert!(!creds_are_equal(Some(&a), Some(&cred(b"alice", 2, b"ref"))));
        assert!(!creds_are_equal(
            Some(&a),
            Some(&cred(b"alice", 1, b"other"))
        ));
    }

    #[test]
    fn wrap_sec_ctx_token_layout() {
        // Use a real (non-special) krb5 OID so special_mech produces a prefixed
        // special OID; the wrapper must be htobe32(len) || special_oid || token.
        let real = gssapi_sys::consts::KRB5_MECH_OID;
        let token = b"\x01\x02\x03\x04payload";
        let out = unsafe {
            let t = convert::TmpOid::new(real);
            wrap_sec_ctx_token(t.as_ptr(), token).expect("wrap")
        };
        assert!(out.len() > 4 + token.len());
        let mech_len = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
        assert_eq!(out.len(), 4 + mech_len + token.len());
        // The special mech embeds the real OID bytes as its suffix.
        let sp = &out[4..4 + mech_len];
        assert!(sp.ends_with(real));
        assert_eq!(&out[4 + mech_len..], token);
    }
}
