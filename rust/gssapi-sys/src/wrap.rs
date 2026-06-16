//! Thin, safe-ish RAII wrappers over the raw `libgssapi_sys` bindings.
//!
//! These exist because the high-level `libgssapi` crate deliberately hides the
//! raw handles, but gssproxy is a *proxy*: it must export/import security
//! contexts and credentials and reach the MIT SPIs. So we keep ownership of the
//! raw `gss_*_t` handles (Drop releases them) while still being able to hand the
//! raw pointer to any `sys::gss_*` call the daemon needs.

use std::os::raw::{c_int, c_void};
use std::ptr;
use std::slice;

use libgssapi_sys as sys;
use sys::{OM_uint32, gss_OID_desc, gss_buffer_desc, gss_cred_id_t, gss_ctx_id_t, gss_name_t};

use crate::consts;
use crate::krb5;

/// A captured GSSAPI status (major/minor) plus the human-readable messages
/// rendered from `gss_display_status`.
#[derive(Debug, Clone)]
pub struct GssError {
    pub major: OM_uint32,
    pub minor: OM_uint32,
    pub messages: Vec<String>,
}

impl std::fmt::Display for GssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "gssapi error (major={:#010x} minor={}): {}",
            self.major,
            self.minor,
            self.messages.join(", ")
        )
    }
}

impl std::error::Error for GssError {}

pub type Result<T> = std::result::Result<T, GssError>;

/// True when the calling-error or routine-error bits are set in a major status.
#[inline]
pub fn is_error(major: OM_uint32) -> bool {
    (major & 0xffff_0000) != 0
}

/// Turn a major/minor pair into `Ok`/`Err`, rendering the messages on error.
pub fn check(major: OM_uint32, minor: OM_uint32) -> Result<()> {
    if is_error(major) {
        Err(make_error(major, minor))
    } else {
        Ok(())
    }
}

fn make_error(major: OM_uint32, minor: OM_uint32) -> GssError {
    let mut messages = display_status(major, sys::GSS_C_GSS_CODE as c_int, None);
    messages.extend(display_status(minor, sys::GSS_C_MECH_CODE as c_int, None));
    GssError {
        major,
        minor,
        messages,
    }
}

/// Render a status code into its (possibly multi-part) message strings, mirroring
/// the `do { gss_display_status } while (msg_ctx)` loop in `gp_conv.c`.
pub fn display_status(code: OM_uint32, code_type: c_int, mech: Option<&[u8]>) -> Vec<String> {
    let mut out = Vec::new();
    let mut msg_ctx: OM_uint32 = 0;
    let mut mech_oid = mech.map(oid_desc);
    let mech_ptr = mech_oid
        .as_mut()
        .map(|o| o as *mut gss_OID_desc)
        .unwrap_or(ptr::null_mut());

    loop {
        let mut minor: OM_uint32 = 0;
        let mut buf = OutputBuffer::empty();
        let major = unsafe {
            sys::gss_display_status(
                &mut minor,
                code,
                code_type,
                mech_ptr,
                &mut msg_ctx,
                buf.as_mut_ptr(),
            )
        };
        if is_error(major) {
            break;
        }
        out.push(String::from_utf8_lossy(buf.as_bytes()).into_owned());
        if msg_ctx == 0 {
            break;
        }
    }
    out
}

/// Build a borrowed input `gss_buffer_desc` over `data`. The descriptor borrows
/// `data`, so it must not outlive it; only pass it to calls that read the input.
fn input_buffer(data: &[u8]) -> gss_buffer_desc {
    gss_buffer_desc {
        length: data.len() as _,
        value: data.as_ptr() as *mut c_void,
    }
}

/// Build a borrowed `gss_OID_desc` over `oid`'s DER bytes.
fn oid_desc(oid: &[u8]) -> gss_OID_desc {
    gss_OID_desc {
        length: oid.len() as OM_uint32,
        elements: oid.as_ptr() as *mut c_void,
    }
}

/// Owns a `gss_buffer_desc` that GSSAPI allocated; releases it on drop.
pub struct OutputBuffer(gss_buffer_desc);

impl OutputBuffer {
    pub fn empty() -> Self {
        OutputBuffer(gss_buffer_desc {
            length: 0,
            value: ptr::null_mut(),
        })
    }

    fn as_mut_ptr(&mut self) -> *mut gss_buffer_desc {
        &mut self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        if self.0.value.is_null() || self.0.length == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.0.value as *const u8, self.0.length) }
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Drop for OutputBuffer {
    fn drop(&mut self) {
        if !self.0.value.is_null() {
            let mut minor: OM_uint32 = 0;
            unsafe {
                sys::gss_release_buffer(&mut minor, &mut self.0);
            }
        }
    }
}

/// Owns a `gss_name_t`; releases it on drop.
pub struct Name(gss_name_t);

impl Name {
    /// Import a name (`gss_import_name`). `name_type` of `None` passes
    /// `GSS_C_NO_OID`, matching the `len == 0` handling in `gp_conv.c`.
    pub fn import(value: &[u8], name_type: Option<&[u8]>) -> Result<Name> {
        let mut buf = input_buffer(value);
        let mut oid_storage;
        let oid_ptr = match name_type {
            Some(nt) => {
                oid_storage = oid_desc(nt);
                &mut oid_storage as *mut gss_OID_desc
            }
            None => ptr::null_mut(),
        };
        let mut out: gss_name_t = ptr::null_mut();
        let mut minor: OM_uint32 = 0;
        let major = unsafe { sys::gss_import_name(&mut minor, &mut buf, oid_ptr, &mut out) };
        check(major, minor)?;
        Ok(Name(out))
    }

    /// Import a previously exported (GSS_C_NT_EXPORT_NAME) name blob.
    pub fn import_exported(value: &[u8]) -> Result<Name> {
        Name::import(value, Some(consts::NT_EXPORT_NAME_OID))
    }

    /// Export the (canonicalized) name to its wire form (`gss_export_name`).
    /// Returns `Ok(None)` when the name is not a mechanism name
    /// (`GSS_S_NAME_NOT_MN`), which `gp_conv.c` treats as "simply do not export".
    pub fn export(&self) -> Result<Option<Vec<u8>>> {
        let mut out = OutputBuffer::empty();
        let mut minor: OM_uint32 = 0;
        let major = unsafe { sys::gss_export_name(&mut minor, self.0, out.as_mut_ptr()) };
        if major == consts::GSS_S_NAME_NOT_MN {
            return Ok(None);
        }
        check(major, minor)?;
        Ok(Some(out.to_vec()))
    }

    /// Export the composite (attribute-carrying) name (`gss_export_name_composite`).
    /// Tolerates `GSS_S_NAME_NOT_MN`/`GSS_S_UNAVAILABLE` like `gp_conv.c`.
    pub fn export_composite(&self) -> Result<Option<Vec<u8>>> {
        let mut out = OutputBuffer::empty();
        let mut minor: OM_uint32 = 0;
        let major = unsafe { sys::gss_export_name_composite(&mut minor, self.0, out.as_mut_ptr()) };
        if major == consts::GSS_S_NAME_NOT_MN || major == consts::GSS_S_UNAVAILABLE {
            return Ok(None);
        }
        check(major, minor)?;
        Ok(Some(out.to_vec()))
    }

    /// Display the name, returning `(display_bytes, name_type_oid_bytes)`.
    pub fn display(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut out = OutputBuffer::empty();
        let mut name_type: sys::gss_OID = ptr::null_mut();
        let mut minor: OM_uint32 = 0;
        let major =
            unsafe { sys::gss_display_name(&mut minor, self.0, out.as_mut_ptr(), &mut name_type) };
        check(major, minor)?;
        let oid_bytes = unsafe { oid_to_vec(name_type) };
        Ok((out.to_vec(), oid_bytes))
    }

    /// Canonicalize the name to a mechanism name (`gss_canonicalize_name`).
    pub fn canonicalize(&self, mech: &[u8]) -> Result<Name> {
        let mut oid = oid_desc(mech);
        let mut out: gss_name_t = ptr::null_mut();
        let mut minor: OM_uint32 = 0;
        let major = unsafe { sys::gss_canonicalize_name(&mut minor, self.0, &mut oid, &mut out) };
        check(major, minor)?;
        Ok(Name(out))
    }

    /// Map the name to a local (POSIX) name for `mech` (`gss_localname`). A
    /// `mech` of `None` passes `GSS_C_NO_OID`.
    pub fn localname(&self, mech: Option<&[u8]>) -> Result<Vec<u8>> {
        let oid_storage;
        let oid_ptr: sys::gss_const_OID = match mech {
            Some(m) => {
                oid_storage = oid_desc(m);
                &oid_storage as *const gss_OID_desc
            }
            None => ptr::null(),
        };
        let mut out = OutputBuffer::empty();
        let mut minor: OM_uint32 = 0;
        let major = unsafe { sys::gss_localname(&mut minor, self.0, oid_ptr, out.as_mut_ptr()) };
        check(major, minor)?;
        Ok(out.to_vec())
    }

    /// `gss_compare_name`: whether two names denote the same entity.
    pub fn compare(&self, other: &Name) -> Result<bool> {
        let mut equal: c_int = 0;
        let mut minor: OM_uint32 = 0;
        let major = unsafe { sys::gss_compare_name(&mut minor, self.0, other.0, &mut equal) };
        check(major, minor)?;
        Ok(equal != 0)
    }

    pub fn as_raw(&self) -> gss_name_t {
        self.0
    }

    /// Take ownership of a raw handle (caller must transfer sole ownership).
    ///
    /// # Safety
    /// `name` must be a valid `gss_name_t` (or null) whose ownership is
    /// transferred to the returned `Name`; it must not be used or freed
    /// elsewhere afterwards.
    pub unsafe fn from_raw(name: gss_name_t) -> Name {
        Name(name)
    }

    /// Relinquish ownership of the raw handle without releasing it.
    pub fn into_raw(self) -> gss_name_t {
        let p = self.0;
        std::mem::forget(self);
        p
    }
}

impl Drop for Name {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut minor: OM_uint32 = 0;
            unsafe {
                sys::gss_release_name(&mut minor, &mut self.0);
            }
        }
    }
}

/// Result of `gss_inquire_cred`: the cred's overall name, remaining lifetime,
/// usage, and the mechanisms it covers.
pub struct CredInfo {
    pub name: Option<Name>,
    pub lifetime: OM_uint32,
    pub usage: c_int,
    pub mechs: Vec<Vec<u8>>,
}

/// Result of `gss_inquire_cred_by_mech` for a single mechanism.
pub struct CredByMech {
    pub name: Option<Name>,
    pub initiator_lifetime: OM_uint32,
    pub acceptor_lifetime: OM_uint32,
    pub usage: c_int,
}

/// Owns a `gss_cred_id_t`; releases it on drop.
pub struct Cred(gss_cred_id_t);

impl Cred {
    pub fn as_raw(&self) -> gss_cred_id_t {
        self.0
    }

    /// # Safety
    /// `cred` must be a valid `gss_cred_id_t` (or null) whose ownership is
    /// transferred to the returned `Cred`; it must not be used or freed
    /// elsewhere afterwards.
    pub unsafe fn from_raw(cred: gss_cred_id_t) -> Cred {
        Cred(cred)
    }

    pub fn into_raw(self) -> gss_cred_id_t {
        let p = self.0;
        std::mem::forget(self);
        p
    }

    /// `gss_inquire_cred`: the credential's name, lifetime, usage and mechs.
    pub fn inquire(&self) -> Result<CredInfo> {
        let mut name: gss_name_t = ptr::null_mut();
        let mut lifetime: OM_uint32 = 0;
        let mut usage: c_int = 0;
        let mut set: sys::gss_OID_set = ptr::null_mut();
        let mut minor: OM_uint32 = 0;
        let major = unsafe {
            sys::gss_inquire_cred(
                &mut minor,
                self.0,
                &mut name,
                &mut lifetime,
                &mut usage,
                &mut set,
            )
        };
        check(major, minor)?;
        let mechs = unsafe { oid_set_drain(&mut set) };
        Ok(CredInfo {
            name: if name.is_null() {
                None
            } else {
                Some(Name(name))
            },
            lifetime,
            usage,
            mechs,
        })
    }

    /// `gss_inquire_cred_by_mech`: per-mechanism name/lifetimes/usage.
    pub fn inquire_by_mech(&self, mech: &[u8]) -> Result<CredByMech> {
        let mut oid = oid_desc(mech);
        let mut name: gss_name_t = ptr::null_mut();
        let mut initiator_lifetime: OM_uint32 = 0;
        let mut acceptor_lifetime: OM_uint32 = 0;
        let mut usage: c_int = 0;
        let mut minor: OM_uint32 = 0;
        let major = unsafe {
            sys::gss_inquire_cred_by_mech(
                &mut minor,
                self.0,
                &mut oid,
                &mut name,
                &mut initiator_lifetime,
                &mut acceptor_lifetime,
                &mut usage,
            )
        };
        check(major, minor)?;
        Ok(CredByMech {
            name: if name.is_null() {
                None
            } else {
                Some(Name(name))
            },
            initiator_lifetime,
            acceptor_lifetime,
            usage,
        })
    }

    /// `gss_inquire_cred_by_oid`: return the data buffers a mechanism associates
    /// with `oid` for this credential. Used with
    /// [`consts::KRB5_GET_CRED_IMPERSONATOR_OID`] to detect constrained-delegation
    /// (proxy) credentials. A `GSS_S_UNAVAILABLE` major (the SPI/OID is not
    /// supported by the installed mechanism) is reported as an empty result; the
    /// C daemon's raw-krb5 `proxy_impersonator` ccache fallback is not ported,
    /// since modern MIT krb5 supports this SPI directly.
    pub fn inquire_by_oid(&self, oid: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut desired = oid_desc(oid);
        let mut set: sys::gss_buffer_set_t = ptr::null_mut();
        let mut minor: OM_uint32 = 0;
        let major =
            unsafe { sys::gss_inquire_cred_by_oid(&mut minor, self.0, &mut desired, &mut set) };
        if major == consts::GSS_S_UNAVAILABLE {
            return Ok(Vec::new());
        }
        check(major, minor)?;
        Ok(unsafe { buffer_set_drain(&mut set) })
    }

    /// `gss_export_cred`: serialize the credential to an opaque token.
    pub fn export_token(&self) -> Result<Vec<u8>> {
        let mut out = OutputBuffer::empty();
        let mut minor: OM_uint32 = 0;
        let major = unsafe { sys::gss_export_cred(&mut minor, self.0, out.as_mut_ptr()) };
        check(major, minor)?;
        Ok(out.to_vec())
    }

    /// `gss_import_cred`: reconstruct a credential from an exported token.
    pub fn import_token(token: &[u8]) -> Result<Cred> {
        let mut buf = input_buffer(token);
        let mut out: gss_cred_id_t = ptr::null_mut();
        let mut minor: OM_uint32 = 0;
        let major = unsafe { sys::gss_import_cred(&mut minor, &mut buf, &mut out) };
        check(major, minor)?;
        Ok(Cred(out))
    }
}

/// `gss_acquire_cred_from`: acquire a credential for `name` (or the default
/// principal when `None`) over the given mechanisms and credential store.
pub fn acquire_cred_from(
    name: Option<&Name>,
    time_req: OM_uint32,
    mechs: &[&[u8]],
    usage: c_int,
    cred_store: &[(String, String)],
) -> Result<Cred> {
    // The mech OID set borrows these descs, which borrow the caller's slices.
    let mut oid_descs: Vec<gss_OID_desc> = mechs.iter().map(|m| oid_desc(m)).collect();
    let mut mech_set = sys::gss_OID_set_desc {
        count: oid_descs.len() as _,
        elements: oid_descs.as_mut_ptr(),
    };

    // Hold the CStrings alive for the duration of the call; the element descs
    // borrow their pointers.
    let cstrings: Vec<(std::ffi::CString, std::ffi::CString)> = cred_store
        .iter()
        .map(|(k, v)| {
            (
                std::ffi::CString::new(k.as_bytes()).unwrap_or_default(),
                std::ffi::CString::new(v.as_bytes()).unwrap_or_default(),
            )
        })
        .collect();
    let mut elements: Vec<sys::gss_key_value_element_desc> = cstrings
        .iter()
        .map(|(k, v)| sys::gss_key_value_element_desc {
            key: k.as_ptr(),
            value: v.as_ptr(),
        })
        .collect();
    let store = sys::gss_key_value_set_desc {
        count: elements.len() as _,
        elements: elements.as_mut_ptr(),
    };
    let store_ptr: sys::gss_const_key_value_set_t = if elements.is_empty() {
        ptr::null()
    } else {
        &store
    };

    let name_raw = name.map(|n| n.0).unwrap_or(ptr::null_mut());
    let mut out: gss_cred_id_t = ptr::null_mut();
    let mut minor: OM_uint32 = 0;
    let major = unsafe {
        sys::gss_acquire_cred_from(
            &mut minor,
            name_raw,
            time_req,
            &mut mech_set,
            usage,
            store_ptr,
            &mut out,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    check(major, minor)?;
    Ok(Cred(out))
}

/// `gss_store_cred_into`: persist `cred` to a credential store. Mirrors the call
/// in `extract_ccache` (`GSS_C_BOTH`, default mech, `overwrite` + `default` both
/// set). When `ccache` is `None` the default ccache is used.
pub fn store_cred_into(cred: &Cred, ccache: Option<&str>) -> Result<()> {
    let cstrings: Vec<(std::ffi::CString, std::ffi::CString)> = match ccache {
        Some(c) => vec![(
            std::ffi::CString::new("ccache").unwrap_or_default(),
            std::ffi::CString::new(c).unwrap_or_default(),
        )],
        None => Vec::new(),
    };
    let mut elements: Vec<sys::gss_key_value_element_desc> = cstrings
        .iter()
        .map(|(k, v)| sys::gss_key_value_element_desc {
            key: k.as_ptr(),
            value: v.as_ptr(),
        })
        .collect();
    let store = sys::gss_key_value_set_desc {
        count: elements.len() as _,
        elements: elements.as_mut_ptr(),
    };
    let store_ptr: sys::gss_const_key_value_set_t = if elements.is_empty() {
        ptr::null()
    } else {
        &store
    };

    let mut minor: OM_uint32 = 0;
    let major = unsafe {
        sys::gss_store_cred_into(
            &mut minor,
            cred.0,
            0, // GSS_C_BOTH
            ptr::null_mut(),
            1, // overwrite_cred
            1, // default_cred
            store_ptr,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    check(major, minor)
}

/// `gss_acquire_cred_impersonate_name`: obtain, via S4U2Self, a credential for
/// `desired_name` (the impersonated user) backed by `impersonator`'s ticket.
/// `mechs` and `usage` mirror the C call; `actual_mechs`/`time_rec` are not
/// surfaced (the daemon does not use them on this path).
pub fn acquire_cred_impersonate_name(
    impersonator: &Cred,
    desired_name: Option<&Name>,
    time_req: OM_uint32,
    mechs: &[&[u8]],
    usage: c_int,
) -> Result<Cred> {
    let mut oid_descs: Vec<gss_OID_desc> = mechs.iter().map(|m| oid_desc(m)).collect();
    let mut mech_set = sys::gss_OID_set_desc {
        count: oid_descs.len() as _,
        elements: oid_descs.as_mut_ptr(),
    };
    let name_raw = desired_name.map(|n| n.0).unwrap_or(ptr::null_mut());
    let mut out: gss_cred_id_t = ptr::null_mut();
    let mut minor: OM_uint32 = 0;
    let major = unsafe {
        sys::gss_acquire_cred_impersonate_name(
            &mut minor,
            impersonator.0,
            name_raw,
            time_req,
            &mut mech_set,
            usage,
            &mut out,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    check(major, minor)?;
    Ok(Cred(out))
}

/// Destroy a credential cache by name (a port of `safe_free_mem_ccache` in
/// `gp_creds.c`). Used to tear down the per-request `MEMORY:` ccache the
/// acquisition layer hands to MIT so that a later acquisition reusing the same
/// (thread-keyed) ccache name does not observe a stale, mismatched principal
/// (`KG_CCACHE_NOMATCH`). Best-effort: errors are swallowed, matching the C
/// daemon's cleanup callback.
pub fn destroy_ccache(name: &str) {
    let cname = match std::ffi::CString::new(name) {
        Ok(c) => c,
        Err(_) => return,
    };
    unsafe {
        let mut ctx: krb5::krb5_context = ptr::null_mut();
        if krb5::krb5_init_context(&mut ctx) != 0 {
            return;
        }
        let mut cc: krb5::krb5_ccache = ptr::null_mut();
        if krb5::krb5_cc_resolve(ctx, cname.as_ptr(), &mut cc) == 0 {
            // krb5_cc_destroy also closes the handle.
            krb5::krb5_cc_destroy(ctx, cc);
        }
        krb5::krb5_free_context(ctx);
    }
}

impl Drop for Cred {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut minor: OM_uint32 = 0;
            unsafe {
                sys::gss_release_cred(&mut minor, &mut self.0);
            }
        }
    }
}

/// Owns a `gss_ctx_id_t`; deletes it on drop.
pub struct Context(gss_ctx_id_t);

impl Context {
    pub fn as_raw(&self) -> gss_ctx_id_t {
        self.0
    }

    /// # Safety
    /// `ctx` must be a valid `gss_ctx_id_t` (or null) whose ownership is
    /// transferred to the returned `Context`; it must not be used or freed
    /// elsewhere afterwards.
    pub unsafe fn from_raw(ctx: gss_ctx_id_t) -> Context {
        Context(ctx)
    }

    pub fn into_raw(self) -> gss_ctx_id_t {
        let p = self.0;
        std::mem::forget(self);
        p
    }

    /// Serialize an established context (`gss_export_sec_context`). This consumes
    /// the underlying handle (GSSAPI invalidates it), so the wrapper is taken by
    /// value.
    pub fn export(mut self) -> Result<Vec<u8>> {
        let mut out = OutputBuffer::empty();
        let mut minor: OM_uint32 = 0;
        let major =
            unsafe { sys::gss_export_sec_context(&mut minor, &mut self.0, out.as_mut_ptr()) };
        // The handle is consumed regardless; forget so Drop doesn't double-delete.
        self.0 = ptr::null_mut();
        check(major, minor)?;
        Ok(out.to_vec())
    }

    /// Reconstruct a context from an interprocess token (`gss_import_sec_context`).
    pub fn import(token: &[u8]) -> Result<Context> {
        let mut buf = input_buffer(token);
        let mut out: gss_ctx_id_t = ptr::null_mut();
        let mut minor: OM_uint32 = 0;
        let major = unsafe { sys::gss_import_sec_context(&mut minor, &mut buf, &mut out) };
        check(major, minor)?;
        Ok(Context(out))
    }

    /// `gss_inquire_context`: the context's names, lifetime, mech, flags, and
    /// initiator/open state. The mechanism OID is copied (it is owned by GSSAPI).
    pub fn inquire(&self) -> Result<ContextInfo> {
        let mut src: gss_name_t = ptr::null_mut();
        let mut targ: gss_name_t = ptr::null_mut();
        let mut lifetime: OM_uint32 = 0;
        let mut mech: sys::gss_OID = ptr::null_mut();
        let mut flags: OM_uint32 = 0;
        let mut locally: c_int = 0;
        let mut open: c_int = 0;
        let mut minor: OM_uint32 = 0;
        let major = unsafe {
            sys::gss_inquire_context(
                &mut minor,
                self.0,
                &mut src,
                &mut targ,
                &mut lifetime,
                &mut mech,
                &mut flags,
                &mut locally,
                &mut open,
            )
        };
        check(major, minor)?;
        Ok(ContextInfo {
            src_name: if src.is_null() { None } else { Some(Name(src)) },
            targ_name: if targ.is_null() {
                None
            } else {
                Some(Name(targ))
            },
            lifetime,
            mech: unsafe { oid_to_vec(mech) },
            flags,
            locally_initiated: locally != 0,
            open: open != 0,
        })
    }

    /// `gss_get_mic`.
    pub fn get_mic(&self, qop: OM_uint32, message: &[u8]) -> Result<Vec<u8>> {
        let mut msg = input_buffer(message);
        let mut token = OutputBuffer::empty();
        let mut minor: OM_uint32 = 0;
        let major =
            unsafe { sys::gss_get_mic(&mut minor, self.0, qop, &mut msg, token.as_mut_ptr()) };
        check(major, minor)?;
        Ok(token.to_vec())
    }

    /// `gss_verify_mic`, returning the resulting QOP state.
    pub fn verify_mic(&self, message: &[u8], token: &[u8]) -> Result<OM_uint32> {
        let mut msg = input_buffer(message);
        let mut tok = input_buffer(token);
        let mut qop: sys::gss_qop_t = 0;
        let mut minor: OM_uint32 = 0;
        let major =
            unsafe { sys::gss_verify_mic(&mut minor, self.0, &mut msg, &mut tok, &mut qop) };
        check(major, minor)?;
        Ok(qop)
    }

    /// `gss_wrap`, returning `(token, conf_state)`.
    pub fn wrap(&self, conf_req: bool, qop: OM_uint32, message: &[u8]) -> Result<(Vec<u8>, bool)> {
        let mut msg = input_buffer(message);
        let mut conf: c_int = 0;
        let mut out = OutputBuffer::empty();
        let mut minor: OM_uint32 = 0;
        let major = unsafe {
            sys::gss_wrap(
                &mut minor,
                self.0,
                conf_req as c_int,
                qop,
                &mut msg,
                &mut conf,
                out.as_mut_ptr(),
            )
        };
        check(major, minor)?;
        Ok((out.to_vec(), conf != 0))
    }

    /// `gss_unwrap`, returning `(message, conf_state, qop_state)`.
    pub fn unwrap(&self, token: &[u8]) -> Result<(Vec<u8>, bool, OM_uint32)> {
        let mut tok = input_buffer(token);
        let mut conf: c_int = 0;
        let mut qop: sys::gss_qop_t = 0;
        let mut out = OutputBuffer::empty();
        let mut minor: OM_uint32 = 0;
        let major = unsafe {
            sys::gss_unwrap(
                &mut minor,
                self.0,
                &mut tok,
                out.as_mut_ptr(),
                &mut conf,
                &mut qop,
            )
        };
        check(major, minor)?;
        Ok((out.to_vec(), conf != 0, qop))
    }

    /// `gss_wrap_size_limit`: the largest message that wraps within `req_output_size`.
    pub fn wrap_size_limit(
        &self,
        conf_req: bool,
        qop: OM_uint32,
        req_output_size: OM_uint32,
    ) -> Result<OM_uint32> {
        let mut max: OM_uint32 = 0;
        let mut minor: OM_uint32 = 0;
        let major = unsafe {
            sys::gss_wrap_size_limit(
                &mut minor,
                self.0,
                conf_req as c_int,
                qop,
                req_output_size,
                &mut max,
            )
        };
        check(major, minor)?;
        Ok(max)
    }
}

/// Result of [`Context::inquire`].
pub struct ContextInfo {
    pub src_name: Option<Name>,
    pub targ_name: Option<Name>,
    pub lifetime: OM_uint32,
    pub mech: Vec<u8>,
    pub flags: OM_uint32,
    pub locally_initiated: bool,
    pub open: bool,
}

/// Borrowed channel-bindings for init/accept (`gss_channel_bindings_struct`).
pub struct ChannelBindings<'a> {
    pub initiator_addrtype: OM_uint32,
    pub initiator_address: &'a [u8],
    pub acceptor_addrtype: OM_uint32,
    pub acceptor_address: &'a [u8],
    pub application_data: &'a [u8],
}

impl ChannelBindings<'_> {
    fn to_raw(&self) -> sys::gss_channel_bindings_struct {
        sys::gss_channel_bindings_struct {
            initiator_addrtype: self.initiator_addrtype,
            initiator_address: input_buffer(self.initiator_address),
            acceptor_addrtype: self.acceptor_addrtype,
            acceptor_address: input_buffer(self.acceptor_address),
            application_data: input_buffer(self.application_data),
        }
    }
}

/// Result of [`init_sec_context`].
pub struct InitResult {
    pub context: Context,
    pub actual_mech: Vec<u8>,
    pub output: Vec<u8>,
    pub continue_needed: bool,
}

/// `gss_init_sec_context`. `existing` is the context handle from a previous step
/// (consumed). On a GSSAPI error the partial context is released automatically.
#[allow(clippy::too_many_arguments)]
pub fn init_sec_context(
    cred: Option<&Cred>,
    existing: Option<Context>,
    target: &Name,
    mech: &[u8],
    req_flags: OM_uint32,
    time_req: OM_uint32,
    cb: Option<&ChannelBindings>,
    input: &[u8],
) -> Result<InitResult> {
    let mut ctx_raw = existing.map(Context::into_raw).unwrap_or(ptr::null_mut());
    let mut oid = oid_desc(mech);
    let mut input_buf = input_buffer(input);
    let mut actual: sys::gss_OID = ptr::null_mut();
    let mut out = OutputBuffer::empty();
    let mut minor: OM_uint32 = 0;
    let cred_raw = cred.map(Cred::as_raw).unwrap_or(ptr::null_mut());
    let mut cb_storage;
    let cb_ptr = match cb {
        Some(c) => {
            cb_storage = c.to_raw();
            &mut cb_storage as *mut sys::gss_channel_bindings_struct
        }
        None => ptr::null_mut(),
    };
    let major = unsafe {
        sys::gss_init_sec_context(
            &mut minor,
            cred_raw,
            &mut ctx_raw,
            target.as_raw(),
            &mut oid,
            req_flags,
            time_req,
            cb_ptr,
            &mut input_buf,
            &mut actual,
            out.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    // Own the (possibly partial) context so it is released on the error path.
    let context = Context(ctx_raw);
    if is_error(major) {
        return Err(make_error(major, minor));
    }
    Ok(InitResult {
        context,
        actual_mech: unsafe { oid_to_vec(actual) },
        output: out.to_vec(),
        continue_needed: major == sys::GSS_S_CONTINUE_NEEDED,
    })
}

/// Result of [`accept_sec_context`].
pub struct AcceptResult {
    pub context: Context,
    pub src_name: Option<Name>,
    pub mech: Vec<u8>,
    pub output: Vec<u8>,
    pub ret_flags: OM_uint32,
    pub delegated_cred: Option<Cred>,
    pub continue_needed: bool,
}

/// `gss_accept_sec_context`. `existing` is the context handle from a previous
/// step (consumed). On a GSSAPI error the partial context is released.
pub fn accept_sec_context(
    existing: Option<Context>,
    cred: Option<&Cred>,
    input: &[u8],
    cb: Option<&ChannelBindings>,
    ret_deleg: bool,
) -> Result<AcceptResult> {
    let mut ctx_raw = existing.map(Context::into_raw).unwrap_or(ptr::null_mut());
    let cred_raw = cred.map(Cred::as_raw).unwrap_or(ptr::null_mut());
    let mut input_buf = input_buffer(input);
    let mut src: gss_name_t = ptr::null_mut();
    let mut mech: sys::gss_OID = ptr::null_mut();
    let mut out = OutputBuffer::empty();
    let mut ret_flags: OM_uint32 = 0;
    let mut deleg: gss_cred_id_t = ptr::null_mut();
    let mut minor: OM_uint32 = 0;
    let mut cb_storage;
    let cb_ptr = match cb {
        Some(c) => {
            cb_storage = c.to_raw();
            &mut cb_storage as *mut sys::gss_channel_bindings_struct
        }
        None => ptr::null_mut(),
    };
    let deleg_ptr = if ret_deleg {
        &mut deleg as *mut gss_cred_id_t
    } else {
        ptr::null_mut()
    };
    let major = unsafe {
        sys::gss_accept_sec_context(
            &mut minor,
            &mut ctx_raw,
            cred_raw,
            &mut input_buf,
            cb_ptr,
            &mut src,
            &mut mech,
            out.as_mut_ptr(),
            &mut ret_flags,
            ptr::null_mut(),
            deleg_ptr,
        )
    };
    let context = Context(ctx_raw);
    let delegated_cred = if deleg.is_null() {
        None
    } else {
        Some(Cred(deleg))
    };
    if is_error(major) {
        return Err(make_error(major, minor));
    }
    Ok(AcceptResult {
        context,
        src_name: if src.is_null() { None } else { Some(Name(src)) },
        mech: unsafe { oid_to_vec(mech) },
        output: out.to_vec(),
        ret_flags,
        delegated_cred,
        continue_needed: major == sys::GSS_S_CONTINUE_NEEDED,
    })
}

impl Drop for Context {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let mut minor: OM_uint32 = 0;
            unsafe {
                sys::gss_delete_sec_context(&mut minor, &mut self.0, ptr::null_mut());
            }
        }
    }
}

/// Enumerate the mechanisms the local GSSAPI supports (`gss_indicate_mechs`),
/// returning each mechanism OID's DER bytes.
pub fn indicate_mechs() -> Result<Vec<Vec<u8>>> {
    let mut set: sys::gss_OID_set = ptr::null_mut();
    let mut minor: OM_uint32 = 0;
    let major = unsafe { sys::gss_indicate_mechs(&mut minor, &mut set) };
    check(major, minor)?;

    let mut out = Vec::new();
    if !set.is_null() {
        unsafe {
            let count = (*set).count as usize;
            for i in 0..count {
                let elem = (*set).elements.add(i);
                out.push(oid_to_vec(elem));
            }
            sys::gss_release_oid_set(&mut minor, &mut set);
        }
    }
    Ok(out)
}

/// Copy a (non-owning) `gss_OID`'s DER bytes into a `Vec`. Returns empty for a
/// null OID.
unsafe fn oid_to_vec(oid: sys::gss_OID) -> Vec<u8> {
    unsafe {
        if oid.is_null() || (*oid).elements.is_null() {
            Vec::new()
        } else {
            slice::from_raw_parts((*oid).elements as *const u8, (*oid).length as usize).to_vec()
        }
    }
}

/// Drain a `gss_OID_set` into owned DER byte vectors and release the set.
unsafe fn oid_set_drain(set: &mut sys::gss_OID_set) -> Vec<Vec<u8>> {
    unsafe {
        let mut out = Vec::new();
        if !set.is_null() {
            let count = (**set).count;
            for i in 0..count {
                out.push(oid_to_vec((**set).elements.add(i)));
            }
            let mut minor: OM_uint32 = 0;
            sys::gss_release_oid_set(&mut minor, set);
        }
        out
    }
}

/// Drain a `gss_buffer_set` into owned byte vectors and release the set.
unsafe fn buffer_set_drain(set: &mut sys::gss_buffer_set_t) -> Vec<Vec<u8>> {
    unsafe {
        let mut out = Vec::new();
        if !set.is_null() {
            let count = (**set).count;
            for i in 0..count {
                let elem = (**set).elements.add(i);
                let bytes = if (*elem).value.is_null() || (*elem).length == 0 {
                    Vec::new()
                } else {
                    slice::from_raw_parts((*elem).value as *const u8, (*elem).length).to_vec()
                };
                out.push(bytes);
            }
            let mut minor: OM_uint32 = 0;
            sys::gss_release_buffer_set(&mut minor, set);
        }
        out
    }
}

/// `gss_inquire_names_for_mech`: the name-types a mechanism supports.
pub fn inquire_names_for_mech(mech: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut oid = oid_desc(mech);
    let mut set: sys::gss_OID_set = ptr::null_mut();
    let mut minor: OM_uint32 = 0;
    let major = unsafe { sys::gss_inquire_names_for_mech(&mut minor, &mut oid, &mut set) };
    check(major, minor)?;
    Ok(unsafe { oid_set_drain(&mut set) })
}

/// A pair of OID-set members: `(mech_attrs, known_mech_attrs)`.
pub type MechAttrSets = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// `gss_inquire_attrs_for_mech`: returns `(mech_attrs, known_mech_attrs)`.
pub fn inquire_attrs_for_mech(mech: &[u8]) -> Result<MechAttrSets> {
    let oid = oid_desc(mech);
    let mut mech_attrs: sys::gss_OID_set = ptr::null_mut();
    let mut known: sys::gss_OID_set = ptr::null_mut();
    let mut minor: OM_uint32 = 0;
    let major = unsafe {
        sys::gss_inquire_attrs_for_mech(
            &mut minor,
            &oid as *const gss_OID_desc,
            &mut mech_attrs,
            &mut known,
        )
    };
    check(major, minor)?;
    let a = unsafe { oid_set_drain(&mut mech_attrs) };
    let k = unsafe { oid_set_drain(&mut known) };
    Ok((a, k))
}

/// `gss_inquire_saslname_for_mech`: `(sasl_mech_name, mech_name, mech_desc)`.
pub fn inquire_saslname_for_mech(mech: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut oid = oid_desc(mech);
    let mut sasl = OutputBuffer::empty();
    let mut name = OutputBuffer::empty();
    let mut desc = OutputBuffer::empty();
    let mut minor: OM_uint32 = 0;
    let major = unsafe {
        sys::gss_inquire_saslname_for_mech(
            &mut minor,
            &mut oid,
            sasl.as_mut_ptr(),
            name.as_mut_ptr(),
            desc.as_mut_ptr(),
        )
    };
    check(major, minor)?;
    Ok((sasl.to_vec(), name.to_vec(), desc.to_vec()))
}

/// `gss_display_mech_attr`: `(name, short_desc, long_desc)` for an attribute OID.
pub fn display_mech_attr(attr: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let oid = oid_desc(attr);
    let mut name = OutputBuffer::empty();
    let mut short = OutputBuffer::empty();
    let mut long = OutputBuffer::empty();
    let mut minor: OM_uint32 = 0;
    let major = unsafe {
        sys::gss_display_mech_attr(
            &mut minor,
            &oid as *const gss_OID_desc,
            name.as_mut_ptr(),
            short.as_mut_ptr(),
            long.as_mut_ptr(),
        )
    };
    check(major, minor)?;
    Ok((name.to_vec(), short.to_vec(), long.to_vec()))
}
