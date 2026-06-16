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
use sys::{
    gss_OID_desc, gss_buffer_desc, gss_cred_id_t, gss_ctx_id_t, gss_name_t, OM_uint32,
};

use crate::consts;

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
            unsafe { slice::from_raw_parts(self.0.value as *const u8, self.0.length as usize) }
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
        let major =
            unsafe { sys::gss_export_name_composite(&mut minor, self.0, out.as_mut_ptr()) };
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

    pub fn as_raw(&self) -> gss_name_t {
        self.0
    }

    /// Take ownership of a raw handle (caller must transfer sole ownership).
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

/// Owns a `gss_cred_id_t`; releases it on drop.
pub struct Cred(gss_cred_id_t);

impl Cred {
    pub fn as_raw(&self) -> gss_cred_id_t {
        self.0
    }

    pub unsafe fn from_raw(cred: gss_cred_id_t) -> Cred {
        Cred(cred)
    }

    pub fn into_raw(self) -> gss_cred_id_t {
        let p = self.0;
        std::mem::forget(self);
        p
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
        let major = unsafe { sys::gss_export_sec_context(&mut minor, &mut self.0, out.as_mut_ptr()) };
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
    if oid.is_null() || (*oid).elements.is_null() {
        Vec::new()
    } else {
        slice::from_raw_parts((*oid).elements as *const u8, (*oid).length as usize).to_vec()
    }
}

/// Drain a `gss_OID_set` into owned DER byte vectors and release the set.
unsafe fn oid_set_drain(set: &mut sys::gss_OID_set) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if !set.is_null() {
        let count = (**set).count as usize;
        for i in 0..count {
            out.push(oid_to_vec((**set).elements.add(i)));
        }
        let mut minor: OM_uint32 = 0;
        sys::gss_release_oid_set(&mut minor, set);
    }
    out
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

/// `gss_inquire_attrs_for_mech`: returns `(mech_attrs, known_mech_attrs)`.
pub fn inquire_attrs_for_mech(mech: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
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
