//! gssproxy-specific GSSAPI constants that `libgssapi-sys` does not provide.
//!
//! Everything `libgssapi-sys` already exports as a proper bindgen item — the
//! request/return flag bits (`GSS_C_DELEG_FLAG`…), credential usage
//! (`GSS_C_BOTH/INITIATE/ACCEPT`), status selectors (`GSS_C_GSS_CODE`,
//! `GSS_C_MECH_CODE`), the error/supplementary offsets, `GSS_S_COMPLETE`, the
//! supplementary token bits, `GSS_C_INDEFINITE`, `GSS_C_QOP_DEFAULT` — should be
//! used directly via [`crate::sys`]. This module adds only what bindgen cannot
//! emit: the computed shifted routine-error codes, and the well-known OID byte
//! strings (which the sys crate exposes as runtime symbols, not byte arrays).

#![allow(non_upper_case_globals)]

use libgssapi_sys::{OM_uint32, GSS_C_CALLING_ERROR_OFFSET, GSS_C_ROUTINE_ERROR_OFFSET};

// bindgen does not expand the computed `GSS_S_*` routine-error macros (only the
// raw `_GSS_S_*` bases), so we recompute the ones gssproxy synthesizes itself.
const fn routine_error(n: OM_uint32) -> OM_uint32 {
    n << GSS_C_ROUTINE_ERROR_OFFSET
}

const fn calling_error(n: OM_uint32) -> OM_uint32 {
    n << GSS_C_CALLING_ERROR_OFFSET
}

pub const GSS_S_CALL_INACCESSIBLE_READ: OM_uint32 = calling_error(1);
pub const GSS_S_CALL_INACCESSIBLE_WRITE: OM_uint32 = calling_error(2);
pub const GSS_S_CALL_BAD_STRUCTURE: OM_uint32 = calling_error(3);

pub const GSS_S_BAD_NAME: OM_uint32 = routine_error(2);
pub const GSS_S_BAD_STATUS: OM_uint32 = routine_error(5);

pub const GSS_S_FAILURE: OM_uint32 = routine_error(13);
/// MIT defines `GSS_S_CRED_UNAVAIL` as `GSS_S_FAILURE`.
pub const GSS_S_CRED_UNAVAIL: OM_uint32 = GSS_S_FAILURE;
pub const GSS_S_NO_CRED: OM_uint32 = routine_error(7);
pub const GSS_S_DEFECTIVE_CREDENTIAL: OM_uint32 = routine_error(10);
pub const GSS_S_CREDENTIALS_EXPIRED: OM_uint32 = routine_error(11);
pub const GSS_S_CONTEXT_EXPIRED: OM_uint32 = routine_error(12);
pub const GSS_S_NO_CONTEXT: OM_uint32 = routine_error(8);
pub const GSS_S_DEFECTIVE_TOKEN: OM_uint32 = routine_error(9);
pub const GSS_S_BAD_MECH: OM_uint32 = routine_error(1);
pub const GSS_S_UNAVAILABLE: OM_uint32 = routine_error(16);
pub const GSS_S_NAME_NOT_MN: OM_uint32 = routine_error(18);
pub const GSS_S_UNAUTHORIZED: OM_uint32 = routine_error(15);

/// The krb5 mechanism OID: 1.2.840.113554.1.2.2
pub const KRB5_MECH_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// The deprecated/old krb5 mech OID: 1.3.5.1.5.2
pub const KRB5_OLD_MECH_OID: &[u8] = &[0x2b, 0x05, 0x01, 0x05, 0x02];

/// Microsoft's incorrectly emitted krb5 OID.
pub const KRB5_WRONG_MECH_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];

/// IAKERB OID: 1.3.6.1.5.2.5
pub const IAKERB_MECH_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x05];

/// The gssproxy interposer mech OID 2.16.840.1.113730.3.8.15.1.
pub const GSSPROXY_INTERPOSER_OID: &[u8] = &[
    0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x03, 0x08, 0x0f, 0x01,
];

/// `GSS_C_NT_USER_NAME` OID: 1.2.840.113554.1.2.1.1
pub const NT_USER_NAME_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01];

/// `GSS_C_NT_HOSTBASED_SERVICE` OID: 1.2.840.113554.1.2.1.4
pub const NT_HOSTBASED_SERVICE_OID: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04];

/// `GSS_C_NT_EXPORT_NAME` OID: 1.3.6.1.5.6.4
pub const NT_EXPORT_NAME_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x06, 0x04];

/// `GSS_C_NT_HOSTBASED_SERVICE_X` OID: 1.3.6.1.5.6.2
pub const NT_HOSTBASED_SERVICE_X_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x06, 0x02];

/// `GSS_C_NT_ANONYMOUS` OID: 1.3.6.1.5.6.3
pub const NT_ANONYMOUS_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x06, 0x03];

/// `GSS_C_NT_COMPOSITE_EXPORT` OID: 1.3.6.1.5.6.6
pub const NT_COMPOSITE_EXPORT_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x06, 0x06];

/// `GSS_C_NT_MACHINE_UID_NAME` OID: 1.2.840.113554.1.2.1.2
pub const NT_MACHINE_UID_NAME_OID: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x02];

/// `GSS_C_NT_STRING_UID_NAME` OID: 1.2.840.113554.1.2.1.3
pub const NT_STRING_UID_NAME_OID: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x03];

/// `GSS_KRB5_NT_PRINCIPAL_NAME` OID: 1.2.840.113554.1.2.2.1
pub const KRB5_NT_PRINCIPAL_NAME_OID: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01];

/// `GSS_KRB5_GET_CRED_IMPERSONATOR` OID: 1.2.840.113554.1.2.2.5.14.
///
/// Passed to `gss_inquire_cred_by_oid` to retrieve the principal that
/// impersonated the credential (constrained-delegation marker), matching the
/// hard-coded `impersonator_oid` fallback in `gp_creds.c`.
pub const KRB5_GET_CRED_IMPERSONATOR_OID: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x05, 0x0e,
];
