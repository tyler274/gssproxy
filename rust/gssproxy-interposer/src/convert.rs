//! Conversions between the GSSAPI C ABI and the `gssx`/Rust values used by the
//! `gpm` layer. The mirror of the daemon-side `gp_conv.c`, but in the
//! client/interposer direction.

use std::os::raw::c_void;
use std::ptr;

use gssapi_sys::sys::{
    self, gss_OID, gss_OID_desc, gss_buffer_desc, gss_buffer_t, gss_channel_bindings_t, OM_uint32,
};
use gssproxy_proto::gssx::{GssxCb, Opaque};

/// Read an input `gss_buffer_t` as a byte slice (empty when null/empty).
///
/// # Safety
/// `buf` must be null or point to a valid `gss_buffer_desc`.
pub unsafe fn read_buffer<'a>(buf: gss_buffer_t) -> &'a [u8] {
    if buf.is_null() {
        return &[];
    }
    let b = &*buf;
    if b.value.is_null() || b.length == 0 {
        return &[];
    }
    std::slice::from_raw_parts(b.value as *const u8, b.length)
}

/// Write `data` into an output `gss_buffer_t`, allocating with `malloc` so the
/// generic `gss_release_buffer` (which calls `free`) can release it.
///
/// Returns false on allocation failure.
///
/// # Safety
/// `out` must be null or point to a writable `gss_buffer_desc`.
pub unsafe fn write_buffer(out: gss_buffer_t, data: &[u8]) -> bool {
    if out.is_null() {
        return true;
    }
    let b = &mut *out;
    if data.is_empty() {
        b.length = 0;
        b.value = ptr::null_mut();
        return true;
    }
    let p = libc::malloc(data.len()) as *mut u8;
    if p.is_null() {
        b.length = 0;
        b.value = ptr::null_mut();
        return false;
    }
    ptr::copy_nonoverlapping(data.as_ptr(), p, data.len());
    b.length = data.len() as _;
    b.value = p as *mut c_void;
    true
}

/// Borrow the DER bytes behind a `gss_OID` (None when null).
///
/// # Safety
/// `oid` must be null or a valid `gss_OID`.
pub unsafe fn oid_bytes<'a>(oid: gss_OID) -> Option<&'a [u8]> {
    crate::oids::oid_bytes(oid as *const gss_OID_desc)
}

/// Build an owned `gss_OID_desc` over leaked bytes for a returned static OID
/// pointer. Used where C hands back a stable `gss_OID` the caller must not free.
pub fn leak_oid(bytes: &[u8]) -> gss_OID {
    let boxed: Box<[u8]> = bytes.to_vec().into_boxed_slice();
    let len = boxed.len();
    let elements = Box::into_raw(boxed) as *mut c_void;
    let desc = Box::new(gss_OID_desc {
        length: len as OM_uint32,
        elements,
    });
    Box::into_raw(desc) as gss_OID
}

/// Convert GSSAPI channel bindings into the `gssx` form.
///
/// # Safety
/// `cb` must be null or point to a valid `gss_channel_bindings_struct`.
pub unsafe fn cb_to_gssx(cb: gss_channel_bindings_t) -> Option<GssxCb> {
    if cb.is_null() {
        return None;
    }
    let c = &*cb;
    let read = |b: &gss_buffer_desc| -> Opaque {
        if b.value.is_null() || b.length == 0 {
            Opaque::new(Vec::new())
        } else {
            Opaque::new(std::slice::from_raw_parts(b.value as *const u8, b.length).to_vec())
        }
    };
    Some(GssxCb {
        initiator_addrtype: c.initiator_addrtype as u64,
        initiator_address: read(&c.initiator_address),
        acceptor_addrtype: c.acceptor_addrtype as u64,
        acceptor_address: read(&c.acceptor_address),
        application_data: read(&c.application_data),
    })
}

/// A transient `gss_OID_desc` over borrowed bytes, for passing to `sys::gss_*`.
pub struct TmpOid {
    desc: gss_OID_desc,
    _bytes: Vec<u8>,
}

impl TmpOid {
    pub fn new(bytes: &[u8]) -> Self {
        let b = bytes.to_vec();
        let desc = gss_OID_desc {
            length: b.len() as OM_uint32,
            elements: b.as_ptr() as *mut c_void,
        };
        TmpOid { desc, _bytes: b }
    }
    pub fn as_ptr(&self) -> gss_OID {
        &self.desc as *const _ as gss_OID
    }
}

/// A transient input `gss_buffer_desc` over borrowed bytes.
pub struct TmpBuf {
    desc: gss_buffer_desc,
    _bytes: Vec<u8>,
}

impl TmpBuf {
    pub fn new(bytes: &[u8]) -> Self {
        let b = bytes.to_vec();
        let desc = gss_buffer_desc {
            length: b.len() as _,
            value: b.as_ptr() as *mut c_void,
        };
        TmpBuf { desc, _bytes: b }
    }
    pub fn as_ptr(&self) -> gss_buffer_t {
        &self.desc as *const _ as gss_buffer_t
    }
}

use std::collections::HashMap;
use std::sync::Mutex;

static OID_INTERN: Mutex<Option<HashMap<Vec<u8>, usize>>> = Mutex::new(None);

/// Return a process-stable `gss_OID` for `bytes`, leaking it on first use and
/// reusing the same pointer thereafter. Used for "static" mech/name-type OIDs
/// the mechglue hands back and callers must not free (C: `gpm_*_to_static`).
pub fn intern_oid(bytes: &[u8]) -> gss_OID {
    let mut guard = OID_INTERN.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(&p) = map.get(bytes) {
        return p as gss_OID;
    }
    let p = leak_oid(bytes);
    map.insert(bytes.to_vec(), p as usize);
    p
}

/// `gpm_name_oid_to_static`: map name-type OID bytes to a recognised static
/// OID pointer, or None (ENOENT) when not one of the known name types.
pub fn name_type_static(bytes: &[u8]) -> Option<gss_OID> {
    use gssapi_sys::consts::*;
    const KNOWN: &[&[u8]] = &[
        NT_USER_NAME_OID,
        NT_MACHINE_UID_NAME_OID,
        NT_STRING_UID_NAME_OID,
        NT_HOSTBASED_SERVICE_X_OID,
        NT_HOSTBASED_SERVICE_OID,
        NT_ANONYMOUS_OID,
        NT_EXPORT_NAME_OID,
        NT_COMPOSITE_EXPORT_OID,
        KRB5_NT_PRINCIPAL_NAME_OID,
    ];
    if KNOWN.contains(&bytes) {
        Some(intern_oid(bytes))
    } else {
        None
    }
}

/// Release a `gss_buffer_desc` produced by a real `gss_*` call.
///
/// # Safety
/// `buf` must point to a valid `gss_buffer_desc`.
pub unsafe fn release_buffer(buf: *mut gss_buffer_desc) {
    let mut min: OM_uint32 = 0;
    sys::gss_release_buffer(&mut min, buf);
}

/// Collect the member OIDs of a `gss_OID_set` as byte vectors.
///
/// # Safety
/// `set` must be null or a valid `gss_OID_set`.
pub unsafe fn oidset_to_vecs(set: sys::gss_OID_set) -> Vec<Vec<u8>> {
    if set.is_null() {
        return Vec::new();
    }
    let s = &*set;
    let mut out = Vec::with_capacity(s.count);
    for i in 0..s.count {
        let m = s.elements.add(i) as gss_OID;
        out.push(oid_bytes(m).unwrap_or(&[]).to_vec());
    }
    out
}

/// Build a freshly-allocated `gss_OID_set` from byte-vector OIDs. Returns null
/// on allocation failure.
pub unsafe fn build_oid_set(mechs: &[Vec<u8>]) -> sys::gss_OID_set {
    let mut min: OM_uint32 = 0;
    let mut set: sys::gss_OID_set = ptr::null_mut();
    if sys::gss_create_empty_oid_set(&mut min, &mut set) != 0 {
        return ptr::null_mut();
    }
    for m in mechs {
        let t = TmpOid::new(m);
        sys::gss_add_oid_set_member(&mut min, t.as_ptr(), &mut set);
    }
    set
}

/// `gpmint_cred_to_actual_mechs`: write a remote cred's element mechs into
/// `*out` (left as `GSS_C_NO_OID_SET` when the cred has no elements).
///
/// # Safety
/// `out` must be null or point to a writable `gss_OID_set`.
pub unsafe fn write_actual_mechs(out: *mut sys::gss_OID_set, mechs: &[Vec<u8>]) -> bool {
    if out.is_null() {
        return true;
    }
    if mechs.is_empty() {
        *out = ptr::null_mut();
        return true;
    }
    let set = build_oid_set(mechs);
    if set.is_null() {
        return false;
    }
    *out = set;
    true
}

/// Read the `ccache` entry from a `gss_const_key_value_set_t`, if present.
///
/// # Safety
/// `store` must be null or a valid `gss_key_value_set_desc`.
pub unsafe fn ccache_from_store(store: sys::gss_const_key_value_set_t) -> Option<String> {
    let kv = kvset_to_vec(store);
    kv.into_iter().find(|(k, _)| k == "ccache").map(|(_, v)| v)
}

/// Convert a `gss_const_key_value_set_t` into owned key/value pairs.
///
/// # Safety
/// `store` must be null or a valid `gss_key_value_set_desc`.
pub unsafe fn kvset_to_vec(store: sys::gss_const_key_value_set_t) -> Vec<(String, String)> {
    if store.is_null() {
        return Vec::new();
    }
    let s = &*store;
    let mut out = Vec::with_capacity(s.count as usize);
    for i in 0..s.count {
        let e = &*s.elements.add(i as usize);
        let key = cstr_to_string(e.key);
        let value = cstr_to_string(e.value);
        if let (Some(k), Some(v)) = (key, value) {
            out.push((k, v));
        }
    }
    out
}

unsafe fn cstr_to_string(p: *const std::os::raw::c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(p)
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intern_oid_is_stable_and_round_trips() {
        let a = intern_oid(b"\x2a\x86\x48");
        let b = intern_oid(b"\x2a\x86\x48");
        // Same bytes => identical stable pointer (mechglue compares by identity).
        assert_eq!(a as *const _, b as *const _);
        let bytes = unsafe { oid_bytes(a) }.unwrap();
        assert_eq!(bytes, b"\x2a\x86\x48");

        // Distinct bytes => distinct interned pointer.
        let c = intern_oid(b"\x2a\x86\x49");
        assert_ne!(a as *const _, c as *const _);
    }

    #[test]
    fn name_type_static_maps_known_only() {
        use gssapi_sys::consts::NT_USER_NAME_OID;
        assert!(name_type_static(NT_USER_NAME_OID).is_some());
        assert!(name_type_static(b"\x99\x99\x99").is_none());
    }

    #[test]
    fn oid_set_round_trips_through_bytes() {
        let mechs = vec![b"\x2a\x86\x48".to_vec(), b"\x2b\x06\x01".to_vec()];
        unsafe {
            let set = build_oid_set(&mechs);
            assert!(!set.is_null());
            let back = oidset_to_vecs(set);
            assert_eq!(back, mechs);
            let mut min: OM_uint32 = 0;
            sys::gss_release_oid_set(&mut min, &mut (set as sys::gss_OID_set));
        }
    }
}
