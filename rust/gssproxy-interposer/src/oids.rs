//! Well-known and gssproxy-specific GSSAPI mechanism OIDs.
//!
//! Port of the OID `gss_OID_desc` constants at the top of
//! `src/mechglue/gss_plugin.c`. The descriptors are created once and stored in
//! a process-global `OnceLock` so their addresses are stable for the lifetime
//! of the process: the mechglue and our own `gssi_internal_release_oid` compare
//! some OIDs by pointer identity, exactly like the C code.

use std::os::raw::c_void;
use std::sync::OnceLock;

use gssapi_sys::sys::{gss_OID_desc, OM_uint32};

// DER element bytes for each mechanism OID (see gss_plugin.c).

/// krb5 mech: 1.2.840.113554.1.2.2
const KRB5: &[u8] = b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
/// Old krb5 mech: 1.3.5.1.5.2
const KRB5_OLD: &[u8] = b"\x2b\x05\x01\x05\x02";
/// Incorrect krb5 mech OID emitted by MS: 1.2.840.48018.1.2.2
const KRB5_WRONG: &[u8] = b"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02";
/// IAKERB mech: 1.3.6.1.5.2.5
const IAKERB: &[u8] = b"\x2b\x06\x01\x05\x02\x05";
/// gssproxy interposer mech: 2.16.840.1.113730.3.8.15.1
const INTERPOSER: &[u8] = b"\x60\x86\x48\x01\x86\xf8\x42\x03\x08\x0f\x01";

/// The set of stable base OID descriptors. Raw pointers inside `gss_OID_desc`
/// are immutable after construction, so sharing across threads is sound.
pub struct BaseOids {
    pub interposer: gss_OID_desc,
    pub krb5: gss_OID_desc,
    pub krb5_old: gss_OID_desc,
    pub krb5_wrong: gss_OID_desc,
    pub iakerb: gss_OID_desc,
}

// SAFETY: the descriptors only ever point at `'static` const byte slices and
// are never mutated after initialisation.
unsafe impl Sync for BaseOids {}
unsafe impl Send for BaseOids {}

static BASE: OnceLock<BaseOids> = OnceLock::new();

fn desc(bytes: &'static [u8]) -> gss_OID_desc {
    gss_OID_desc {
        length: bytes.len() as OM_uint32,
        elements: bytes.as_ptr() as *mut c_void,
    }
}

/// Accessor for the process-global base OID descriptors.
pub fn base() -> &'static BaseOids {
    BASE.get_or_init(|| BaseOids {
        interposer: desc(INTERPOSER),
        krb5: desc(KRB5),
        krb5_old: desc(KRB5_OLD),
        krb5_wrong: desc(KRB5_WRONG),
        iakerb: desc(IAKERB),
    })
}

/// Pointer to the stable interposer OID descriptor (`gssproxy_mech_interposer`).
pub fn interposer() -> *const gss_OID_desc {
    &base().interposer
}

/// Borrow the DER bytes behind an OID descriptor pointer.
///
/// # Safety
/// `oid` must be null or point to a valid `gss_OID_desc` whose `elements`
/// buffer is at least `length` bytes.
pub unsafe fn oid_bytes<'a>(oid: *const gss_OID_desc) -> Option<&'a [u8]> {
    if oid.is_null() {
        return None;
    }
    let d = &*oid;
    if d.elements.is_null() {
        return Some(&[]);
    }
    Some(std::slice::from_raw_parts(
        d.elements as *const u8,
        d.length as usize,
    ))
}

/// `gss_oid_equal` equivalent: compare two OIDs by length and bytes.
///
/// # Safety
/// Both pointers must satisfy the contract of [`oid_bytes`].
pub unsafe fn oid_equal(a: *const gss_OID_desc, b: *const gss_OID_desc) -> bool {
    match (oid_bytes(a), oid_bytes(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// `gpp_is_krb5_oid`: true for any of the krb5/iakerb mech OIDs we proxy.
///
/// Kept for parity with the C helper of the same name; not yet referenced by
/// the Rust data path.
///
/// # Safety
/// `mech` must satisfy the contract of [`oid_bytes`].
#[allow(dead_code)]
pub unsafe fn is_krb5_oid(mech: *const gss_OID_desc) -> bool {
    let b = base();
    oid_equal(mech, &b.krb5)
        || oid_equal(mech, &b.krb5_old)
        || oid_equal(mech, &b.krb5_wrong)
        || oid_equal(mech, &b.iakerb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_oids_have_stable_addresses() {
        let a = interposer();
        let b = interposer();
        assert_eq!(a, b, "interposer OID address must be stable");
    }

    #[test]
    fn krb5_oid_recognised() {
        let b = base();
        unsafe {
            assert!(is_krb5_oid(&b.krb5));
            assert!(is_krb5_oid(&b.iakerb));
            assert!(!is_krb5_oid(&b.interposer));
            assert!(!is_krb5_oid(std::ptr::null()));
        }
    }

    #[test]
    fn oid_bytes_match_der() {
        let b = base();
        unsafe {
            assert_eq!(oid_bytes(&b.krb5).unwrap(), KRB5);
            assert_eq!(oid_bytes(&b.interposer).unwrap().len(), 11);
        }
    }

    /// Cross-check every OID against the independently-defined, C-derived
    /// constants in `gssapi-sys` (which mirror `src/mechglue/gss_plugin.c` and
    /// the upstream OID registry). Any divergence here is a wire/ABI bug.
    #[test]
    fn oids_match_gssapi_sys_constants() {
        use gssapi_sys::consts;
        let b = base();
        unsafe {
            assert_eq!(oid_bytes(&b.krb5).unwrap(), consts::KRB5_MECH_OID);
            assert_eq!(oid_bytes(&b.krb5_old).unwrap(), consts::KRB5_OLD_MECH_OID);
            assert_eq!(
                oid_bytes(&b.krb5_wrong).unwrap(),
                consts::KRB5_WRONG_MECH_OID
            );
            assert_eq!(oid_bytes(&b.iakerb).unwrap(), consts::IAKERB_MECH_OID);
            assert_eq!(
                oid_bytes(&b.interposer).unwrap(),
                consts::GSSPROXY_INTERPOSER_OID
            );
        }
    }

    #[test]
    fn distinct_oids_are_not_equal() {
        let b = base();
        unsafe {
            assert!(!oid_equal(&b.krb5, &b.krb5_old));
            assert!(!oid_equal(&b.krb5, &b.krb5_wrong));
            assert!(oid_equal(&b.krb5, &b.krb5));
        }
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    fn with_oid<R>(bytes: &[u8], f: impl FnOnce(*const gss_OID_desc) -> R) -> R {
        let desc = gss_OID_desc {
            length: bytes.len() as OM_uint32,
            elements: if bytes.is_empty() {
                std::ptr::null_mut()
            } else {
                bytes.as_ptr() as *mut c_void
            },
        };
        f(&desc as *const gss_OID_desc)
    }

    // Known mech OIDs, so the strategy can assert is_krb5_oid is *exactly* this
    // set and nothing else.
    const KNOWN_KRB5: &[&[u8]] = &[KRB5, KRB5_OLD, KRB5_WRONG, IAKERB];

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// `oid_bytes` returns exactly the backing bytes for any length.
        #[test]
        fn oid_bytes_returns_input(bytes in prop::collection::vec(any::<u8>(), 0..40)) {
            with_oid(&bytes, |oid| -> std::result::Result<(), TestCaseError> {
                let got = unsafe { oids_oid_bytes_or_empty(oid) };
                prop_assert_eq!(got, &bytes[..]);
                Ok(())
            })?;
        }

        /// `oid_equal` is exactly byte-equality, and reflexive, for any inputs.
        #[test]
        fn oid_equal_is_byte_equality(a in prop::collection::vec(any::<u8>(), 0..32),
                                      b in prop::collection::vec(any::<u8>(), 0..32)) {
            with_oid(&a, |oa| with_oid(&b, |ob| -> std::result::Result<(), TestCaseError> {
                unsafe {
                    prop_assert_eq!(oid_equal(oa, ob), a == b);
                    prop_assert!(oid_equal(oa, oa));
                    prop_assert!(oid_equal(ob, ob));
                }
                Ok(())
            }))?;
        }

        /// `is_krb5_oid` is true for an arbitrary OID iff its bytes are one of
        /// the four known krb5/iakerb OIDs.
        #[test]
        fn is_krb5_oid_matches_known_set(bytes in prop::collection::vec(any::<u8>(), 0..32)) {
            with_oid(&bytes, |oid| -> std::result::Result<(), TestCaseError> {
                let expected = KNOWN_KRB5.contains(&bytes.as_slice());
                prop_assert_eq!(unsafe { is_krb5_oid(oid) }, expected);
                Ok(())
            })?;
        }
    }

    // Helper that treats a null-elements descriptor as the empty slice (matching
    // oid_bytes), so the property test can compare against the original Vec.
    unsafe fn oids_oid_bytes_or_empty<'a>(oid: *const gss_OID_desc) -> &'a [u8] {
        oid_bytes(oid).unwrap_or(&[])
    }
}
