//! The "special" mechanism OID machinery from `src/mechglue/gss_plugin.c`.
//!
//! gssproxy hides interposed mechanisms from the local mechglue by prefixing
//! each real mech OID with the interposer OID. These prefixed OIDs are the
//! "special" mechs; a real mech is recovered by stripping the prefix. The C
//! code keeps a process-global, add-only linked list of `(regular, special)`
//! pairs whose pointers are handed out to the mechglue and must stay valid for
//! the life of the process.
//!
//! We mirror that with a `Mutex`-guarded `Vec` of leaked entries: each entry's
//! `gss_OID_desc`s (and their element buffers) are intentionally leaked so the
//! pointers we return remain valid forever, just like the never-freed C list.

use std::os::raw::c_void;
use std::ptr;
use std::sync::Mutex;

use gssapi_sys::sys::{OM_uint32, gss_OID, gss_OID_desc};

use crate::oids;

/// A leaked `(regular, special)` OID pair. The descriptors live at stable
/// heap addresses for the process lifetime.
struct SpecialEntry {
    regular: *const gss_OID_desc,
    special: *const gss_OID_desc,
}

// SAFETY: entries are immutable after creation; the pointers reference leaked,
// never-mutated heap allocations.
unsafe impl Send for SpecialEntry {}

static REGISTRY: Mutex<Vec<SpecialEntry>> = Mutex::new(Vec::new());

/// Leak `bytes` plus a `gss_OID_desc` describing them, returning a stable
/// pointer to the descriptor.
fn leak_oid(bytes: &[u8]) -> *const gss_OID_desc {
    let boxed: Box<[u8]> = bytes.to_vec().into_boxed_slice();
    let len = boxed.len();
    let elements = Box::into_raw(boxed) as *mut c_void; // leak element bytes
    let desc = Box::new(gss_OID_desc {
        length: len as OM_uint32,
        elements,
    });
    Box::into_raw(desc) as *const gss_OID_desc // leak descriptor
}

/// `gpp_is_special_oid`: true if `mech` begins with the interposer OID prefix.
///
/// # Safety
/// `mech` must satisfy the contract of [`oids::oid_bytes`].
pub unsafe fn is_special_oid(mech: *const gss_OID_desc) -> bool {
    unsafe {
        let prefix = match oids::oid_bytes(oids::interposer()) {
            Some(p) => p,
            None => return false,
        };
        match oids::oid_bytes(mech) {
            Some(b) => b.len() >= prefix.len() && &b[..prefix.len()] == prefix,
            None => false,
        }
    }
}

/// `gpp_special_equal`: true if special OID `s` is `n` with the interposer
/// prefix stripped (i.e. `s == interposer ++ n`).
///
/// # Safety
/// Both pointers must satisfy the contract of [`oids::oid_bytes`].
unsafe fn special_equal(s: *const gss_OID_desc, n: *const gss_OID_desc) -> bool {
    unsafe {
        let base = match oids::oid_bytes(oids::interposer()) {
            Some(p) => p.len(),
            None => return false,
        };
        let (sb, nb) = match (oids::oid_bytes(s), oids::oid_bytes(n)) {
            (Some(sb), Some(nb)) => (sb, nb),
            _ => return false,
        };
        sb.len() >= base && sb.len() - base == nb.len() && &sb[base..] == nb
    }
}

/// `gpp_new_special_mech`: build a new special OID for the regular mech bytes
/// `nb` and append it to the registry, returning the stable special-OID
/// pointer. The caller must already hold the registry lock so that the
/// search-then-insert in [`special_mech`] is atomic — see the note there.
fn register_locked(reg: &mut Vec<SpecialEntry>, nb: &[u8]) -> *const gss_OID_desc {
    // SAFETY: the interposer descriptor is a valid 'static OID.
    let prefix = unsafe { oids::oid_bytes(oids::interposer()) }.unwrap_or(&[]);

    let regular = leak_oid(nb);
    let mut special_bytes = Vec::with_capacity(prefix.len() + nb.len());
    special_bytes.extend_from_slice(prefix);
    special_bytes.extend_from_slice(nb);
    let special = leak_oid(&special_bytes);

    reg.push(SpecialEntry { regular, special });
    special
}

/// `gpp_special_mech`: map a real mech OID to its special form, registering a
/// new one if needed. `GSS_C_NO_OID` (null) returns the first known special
/// mech, or null if none exist yet.
///
/// Unlike the C `gpp_special_mech` — which walks a lock-free list and may, when
/// two threads race on the same new mech, append two equivalent entries — we
/// hold the registry lock across the search and the insert so a given mech maps
/// to exactly one stable special pointer. This is purely internal mechglue
/// bookkeeping (special OIDs never reach the wire), so the stricter dedup has no
/// byte/ABI effect; it only avoids redundant leaked allocations under load.
///
/// # Safety
/// `mech_type` must be null or satisfy the contract of [`oids::oid_bytes`].
pub unsafe fn special_mech(mech_type: *const gss_OID_desc) -> gss_OID {
    unsafe {
        if is_special_oid(mech_type) {
            return mech_type as gss_OID;
        }

        let mut reg = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());

        if mech_type.is_null() {
            return reg
                .first()
                .map(|e| e.special as gss_OID)
                .unwrap_or(ptr::null_mut());
        }

        for e in reg.iter() {
            if special_equal(e.special, mech_type) {
                return e.special as gss_OID;
            }
        }

        match oids::oid_bytes(mech_type) {
            Some(nb) => register_locked(&mut reg, nb) as gss_OID,
            None => ptr::null_mut(),
        }
    }
}

/// `gpp_unspecial_mech`: map a special mech OID back to its real form. If
/// `mech_type` is not special, or not known, it is returned unchanged.
///
/// # Safety
/// `mech_type` must be null or satisfy the contract of [`oids::oid_bytes`].
pub unsafe fn unspecial_mech(mech_type: *const gss_OID_desc) -> gss_OID {
    unsafe {
        if !is_special_oid(mech_type) {
            return mech_type as gss_OID;
        }
        let reg = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        for e in reg.iter() {
            if oids::oid_equal(e.special, mech_type) {
                return e.regular as gss_OID;
            }
        }
        mech_type as gss_OID
    }
}

/// `gpp_init_special_available_mechs`: pre-register special OIDs for every mech
/// in `mechs` that we do not already track.
///
/// # Safety
/// `mechs` must point to a valid `gss_OID_set_desc` for reads, or be null.
pub unsafe fn init_special_available_mechs(mechs: gssapi_sys::sys::gss_OID_set) {
    unsafe {
        if mechs.is_null() {
            return;
        }
        let set = &*mechs;
        // Hold the lock across the whole loop so the check-then-insert per mech is
        // atomic (matching special_mech's stricter dedup).
        let mut reg = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        for i in 0..set.count {
            let m = set.elements.add(i) as *const gss_OID_desc;
            if is_special_oid(m) {
                continue;
            }
            if reg.iter().any(|e| special_equal(e.special, m)) {
                continue;
            }
            if let Some(nb) = oids::oid_bytes(m) {
                register_locked(&mut reg, nb);
            }
        }
    }
}

/// `gpp_special_available_mechs`: build a freshly-allocated `gss_OID_set` of
/// the special OIDs corresponding to every mech in `mechs`, registering new
/// special OIDs as needed. Returns `GSS_C_NO_OID_SET` (null) on failure or when
/// the resulting set would be empty (matching the C behaviour).
///
/// # Safety
/// `mechs` must be null or point to a valid `gss_OID_set_desc`.
pub unsafe fn special_available_mechs(
    mechs: gssapi_sys::sys::gss_OID_set,
) -> gssapi_sys::sys::gss_OID_set {
    unsafe {
        use gssapi_sys::sys;
        let mut amechs: sys::gss_OID_set = ptr::null_mut();
        let mut min: OM_uint32 = 0;
        if sys::gss_create_empty_oid_set(&mut min, &mut amechs) != 0 {
            return ptr::null_mut();
        }
        let mut ok = true;
        if !mechs.is_null() {
            let set = &*mechs;
            for i in 0..set.count {
                let m = set.elements.add(i) as *const gss_OID_desc;
                // special_mech() returns m unchanged if it is already special, the
                // existing matching special OID, or a freshly registered one —
                // exactly the three cases in the C loop.
                let sp = special_mech(m);
                if sp.is_null() {
                    ok = false;
                    break;
                }
                if sys::gss_add_oid_set_member(&mut min, sp, &mut amechs) != 0 {
                    ok = false;
                    break;
                }
            }
        }
        let empty = amechs.is_null() || (*amechs).count == 0;
        if !ok || empty {
            let mut m2: OM_uint32 = 0;
            sys::gss_release_oid_set(&mut m2, &mut amechs);
            return ptr::null_mut();
        }
        amechs
    }
}

/// True if `oid` is one of our registered regular/special OID descriptor
/// pointers (compared by identity, as in `gssi_internal_release_oid`).
pub fn is_registered_ptr(oid: *const gss_OID_desc) -> bool {
    let reg = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    reg.iter().any(|e| e.regular == oid || e.special == oid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gssapi_sys::sys::gss_OID_desc;
    use std::os::raw::c_void;

    fn make_oid(bytes: &'static [u8]) -> gss_OID_desc {
        gss_OID_desc {
            length: bytes.len() as OM_uint32,
            elements: bytes.as_ptr() as *mut c_void,
        }
    }

    #[test]
    fn special_round_trip() {
        // 1.2.840.113554.1.2.2 (krb5) DER body.
        let krb5 = make_oid(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");
        unsafe {
            assert!(!is_special_oid(&krb5));
            let sp = special_mech(&krb5);
            assert!(!sp.is_null());
            assert!(is_special_oid(sp));
            // Idempotent: same mech maps to the same special OID pointer.
            let sp2 = special_mech(&krb5);
            assert_eq!(sp, sp2);
            // And we can strip back to the original bytes.
            let back = unspecial_mech(sp);
            assert_eq!(
                oids::oid_bytes(back).unwrap(),
                oids::oid_bytes(&krb5).unwrap()
            );
            // Passing an already-special OID returns it unchanged.
            assert_eq!(special_mech(sp), sp);
            assert!(is_registered_ptr(sp));
        }
    }

    #[test]
    fn distinct_mechs_get_distinct_special_oids() {
        let krb5 = make_oid(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");
        let iakerb = make_oid(b"\x2b\x06\x01\x05\x02\x05");
        unsafe {
            let sp_krb5 = special_mech(&krb5);
            let sp_iakerb = special_mech(&iakerb);
            assert_ne!(sp_krb5, sp_iakerb);
            // Each special OID strips back to its own original mech.
            assert_eq!(
                oids::oid_bytes(unspecial_mech(sp_krb5)).unwrap(),
                oids::oid_bytes(&krb5).unwrap()
            );
            assert_eq!(
                oids::oid_bytes(unspecial_mech(sp_iakerb)).unwrap(),
                oids::oid_bytes(&iakerb).unwrap()
            );
        }
    }

    #[test]
    fn special_prefix_is_the_interposer_oid() {
        let krb5 = make_oid(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");
        unsafe {
            let sp = special_mech(&krb5);
            let prefix = oids::oid_bytes(oids::interposer()).unwrap();
            let sp_bytes = oids::oid_bytes(sp).unwrap();
            assert!(sp_bytes.starts_with(prefix));
            assert_eq!(&sp_bytes[prefix.len()..], oids::oid_bytes(&krb5).unwrap());
        }
    }

    #[test]
    fn unspecial_of_unknown_returns_input() {
        // A non-special, unregistered OID passes through unchanged.
        let krb5 = make_oid(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02");
        unsafe {
            let p = &krb5 as *const gss_OID_desc;
            assert_eq!(unspecial_mech(p), p as gss_OID);
            assert!(!is_special_oid(p));
        }
    }

    #[test]
    fn null_oid_is_not_special() {
        unsafe {
            assert!(!is_special_oid(std::ptr::null()));
        }
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::thread;

    /// The interposer OID prefix, duplicated here so the strategy can exclude
    /// inputs that would already look "special".
    const INTERPOSER_PREFIX: &[u8] = b"\x60\x86\x48\x01\x86\xf8\x42\x03\x08\x0f\x01";

    /// Build a stack `gss_OID_desc` over `bytes` and run `f` with a pointer to
    /// it. The descriptor (and `bytes`) outlive the call, which is all the
    /// `special.rs` functions require — they copy bytes when registering.
    fn with_oid<R>(bytes: &[u8], f: impl FnOnce(*const gss_OID_desc) -> R) -> R {
        let desc = gss_OID_desc {
            length: bytes.len() as OM_uint32,
            elements: bytes.as_ptr() as *mut c_void,
        };
        f(&desc as *const gss_OID_desc)
    }

    fn current_len() -> usize {
        REGISTRY.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    fn non_special_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 1..24)
            .prop_filter("input must not already carry the interposer prefix", |b| {
                !b.starts_with(INTERPOSER_PREFIX)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 200,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// A regular mech round-trips through special/unspecial: the special OID
        /// is prefixed, registered, stable, and strips back to the input bytes.
        #[test]
        fn special_round_trip_arbitrary(bytes in non_special_bytes()) {
            with_oid(&bytes, |oid| -> std::result::Result<(), TestCaseError> {
                unsafe {
                    prop_assert!(!is_special_oid(oid));
                    let sp = special_mech(oid);
                    prop_assert!(!sp.is_null());
                    prop_assert!(is_special_oid(sp));
                    prop_assert!(is_registered_ptr(sp));

                    // Idempotent: same bytes -> same stable special pointer.
                    let sp2 = special_mech(oid);
                    prop_assert_eq!(sp, sp2);

                    // Layout: special == interposer-prefix ++ regular bytes.
                    let sp_bytes = oids::oid_bytes(sp).unwrap();
                    let prefix = oids::oid_bytes(oids::interposer()).unwrap();
                    prop_assert!(sp_bytes.starts_with(prefix));
                    prop_assert_eq!(&sp_bytes[prefix.len()..], &bytes[..]);

                    // Strips back to the original mech bytes.
                    let back = unspecial_mech(sp);
                    prop_assert_eq!(oids::oid_bytes(back).unwrap(), &bytes[..]);
                }
                Ok(())
            })?;
        }

        /// For ANY non-null OID (special-looking or not), the bytes survive a
        /// special->unspecial trip, and no input ever panics.
        #[test]
        fn unspecial_of_special_preserves_bytes(bytes in prop::collection::vec(any::<u8>(), 1..24)) {
            with_oid(&bytes, |oid| -> std::result::Result<(), TestCaseError> {
                unsafe {
                    let sp = special_mech(oid);
                    prop_assert!(is_special_oid(sp));
                    let back = unspecial_mech(sp);
                    prop_assert_eq!(oids::oid_bytes(back).unwrap(), &bytes[..]);
                }
                Ok(())
            })?;
        }

        /// Distinct regular mechs map to distinct special OIDs, each stripping
        /// back to its own bytes.
        #[test]
        fn distinct_inputs_get_distinct_specials(a in non_special_bytes(), b in non_special_bytes()) {
            prop_assume!(a != b);
            with_oid(&a, |oa| with_oid(&b, |ob| -> std::result::Result<(), TestCaseError> {
                unsafe {
                    let sa = special_mech(oa);
                    let sb = special_mech(ob);
                    prop_assert_ne!(sa, sb);
                    prop_assert_eq!(oids::oid_bytes(unspecial_mech(sa)).unwrap(), &a[..]);
                    prop_assert_eq!(oids::oid_bytes(unspecial_mech(sb)).unwrap(), &b[..]);
                }
                Ok(())
            }))?;
        }
    }

    /// Stress the add-only registry from many threads at once (the C code uses a
    /// lock-free, never-freed singly linked list). Invariants under contention:
    ///   - the registry only ever grows (add-only);
    ///   - a given mech always resolves to the same stable special pointer,
    ///     regardless of which thread first registered it (dedup);
    ///   - distinct mechs get distinct special pointers;
    ///   - every special pointer still strips back to its mech afterwards.
    #[test]
    fn concurrent_registration_is_consistent() {
        let mechs: Arc<Vec<Vec<u8>>> = Arc::new(
            (0..24u8)
                .map(|i| vec![0x77, 0x10, i, 0x42, i.wrapping_mul(13).wrapping_add(1)])
                .collect(),
        );
        let before = current_len();

        let mut handles = Vec::new();
        for t in 0..8usize {
            let mechs = mechs.clone();
            handles.push(thread::spawn(move || {
                let mut seen: Vec<(usize, usize)> = Vec::new();
                for round in 0..64usize {
                    let idx = (t.wrapping_mul(7).wrapping_add(round)) % mechs.len();
                    let sp = with_oid(&mechs[idx], |oid| unsafe { special_mech(oid) });
                    assert!(!sp.is_null(), "special_mech returned null under load");
                    seen.push((idx, sp as usize));
                }
                seen
            }));
        }

        let mut by_idx: HashMap<usize, usize> = HashMap::new();
        for h in handles {
            for (idx, sp) in h.join().unwrap() {
                match by_idx.get(&idx) {
                    Some(&prev) => assert_eq!(prev, sp, "mech {idx} got two special pointers"),
                    None => {
                        by_idx.insert(idx, sp);
                    }
                }
            }
        }

        // Add-only: never shrinks.
        assert!(current_len() >= before, "registry must be add-only");
        // Every mech was observed and each got a unique pointer.
        assert_eq!(by_idx.len(), mechs.len());
        let unique: HashSet<usize> = by_idx.values().copied().collect();
        assert_eq!(
            unique.len(),
            mechs.len(),
            "distinct mechs must have distinct specials"
        );

        // Strips back correctly after the concurrent churn.
        for (i, bytes) in mechs.iter().enumerate() {
            let sp = *by_idx.get(&i).unwrap() as *const gss_OID_desc;
            let back = unsafe { unspecial_mech(sp) };
            assert_eq!(unsafe { oids::oid_bytes(back).unwrap() }, &bytes[..]);
        }
    }
}
