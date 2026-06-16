//! Credential acquisition, ported from `src/gp_creds.c` and the krb5 paths of
//! `gp_add_krb5_creds` / `gp_get_cred_environment` / `gp_check_cred`.
//!
//! Only the krb5 mechanism and the non-impersonation `ACQ_NORMAL` path are
//! implemented; the s4u2self impersonation dance (`impersonate = yes` services
//! and `ACQ_IMPNAME` acquisitions) is rejected with `GSS_S_FAILURE`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gssapi_sys::seal::CredHandle;
use gssapi_sys::wrap::{self, Cred, Name};
use gssapi_sys::consts;
use gssproxy_proto::gssx::GssxName;

/// `GSS_C_INDEFINITE` (`gssapi.h`); bindgen emits this macro as the unused
/// `_GSS_C_INDEFINITE`, so we restate the value here.
const GSS_C_INDEFINITE: u32 = 0xffff_ffff;

use crate::call::CallContext;
use crate::config::{Service, GP_CRED_KRB5};
use crate::conv;

// GSS_C_* credential usage values (gssapi.h).
const GSS_C_BOTH: i32 = 0;
const GSS_C_INITIATE: i32 = 1;
const GSS_C_ACCEPT: i32 = 2;

/// Acquisition type, mirroring `enum gp_aqcuire_cred_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireType {
    Normal,
    ImpName,
}

/// A GSSAPI major/minor pair for failed acquisitions.
#[derive(Debug, Clone)]
pub struct AcqError {
    pub major: u32,
    pub minor: u32,
}

impl AcqError {
    fn new(major: u32, minor: u32) -> AcqError {
        AcqError { major, minor }
    }
}

/// Per-service sealing-key registry. Handles are derived lazily on first use and
/// cached for the daemon's lifetime (keyed by service name), matching the C
/// daemon's one-shot `gp_service_get_creds_handle`.
#[derive(Default)]
pub struct CredsRegistry {
    handles: Mutex<HashMap<String, Arc<CredHandle>>>,
}

impl CredsRegistry {
    pub fn new() -> CredsRegistry {
        CredsRegistry::default()
    }

    /// Return (deriving + caching if necessary) the sealing handle for a service.
    pub fn get_or_init(&self, svc: &Service) -> Option<Arc<CredHandle>> {
        let mut map = self.handles.lock().unwrap();
        if let Some(h) = map.get(&svc.name) {
            return Some(h.clone());
        }
        let keytab = svc
            .krb5_store
            .iter()
            .find(|(k, _)| k == "keytab")
            .map(|(_, v)| v.as_str());
        let handle = Arc::new(CredHandle::new(keytab).ok()?);
        map.insert(svc.name.clone(), handle.clone());
        Some(handle)
    }
}

/// `gp_creds_allowed_mech`: whether the service permits `mech` (only krb5 is
/// supported).
pub fn allowed_mech(svc: &Service, mech: &[u8]) -> bool {
    (svc.mechs & GP_CRED_KRB5) != 0 && mech == consts::KRB5_MECH_OID
}

/// `try_impersonate`: whether this acquisition would require impersonation
/// (s4u2self), which this port does not implement.
fn try_impersonate(svc: &Service, cred_usage: i32, acquire_type: AcquireType) -> bool {
    if acquire_type == AcquireType::ImpName && (svc.allow_proto_trans || svc.trusted) {
        return true;
    }
    if svc.impersonate && (cred_usage == GSS_C_INITIATE || cred_usage == GSS_C_BOTH) {
        return true;
    }
    false
}

/// `get_formatted_string`: expand `%U` (target uid), `%u` (target username) and
/// `%%` in a cred_store value.
fn get_formatted_string(orig: &str, target_uid: u32) -> Option<String> {
    let mut out = String::with_capacity(orig.len());
    let mut chars = orig.chars().peekable();
    let mut username: Option<String> = None;
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('U') => out.push_str(&target_uid.to_string()),
            Some('u') => {
                let u = match &username {
                    Some(u) => u.clone(),
                    None => {
                        let u = uid_to_name(target_uid)?;
                        username = Some(u.clone());
                        u
                    }
                };
                out.push_str(&u);
            }
            _ => return None,
        }
    }
    Some(out)
}

fn uid_to_name(uid: u32) -> Option<String> {
    unsafe {
        let pw = libc::getpwuid(uid as libc::uid_t);
        if pw.is_null() {
            return None;
        }
        let name = (*pw).pw_name;
        if name.is_null() {
            return None;
        }
        Some(std::ffi::CStr::from_ptr(name).to_string_lossy().into_owned())
    }
}

/// `atol`-style leading-integer parse of a uid display name.
fn parse_leading_uid(s: &[u8]) -> u32 {
    let mut v: u32 = 0;
    for &b in s {
        if b.is_ascii_digit() {
            v = v.wrapping_mul(10).wrapping_add((b - b'0') as u32);
        } else if v == 0 && (b == b' ' || b == b'\t') {
            continue;
        } else {
            break;
        }
    }
    v
}

struct CredEnv {
    requested_name: Option<Name>,
    cred_usage: i32,
    cred_store: Vec<(String, String)>,
}

/// `gp_get_cred_environment` (krb5 path, impersonation sub-block omitted). On
/// error returns the C errno value, which the caller maps to `GSS_S_FAILURE`.
fn get_cred_environment(
    ctx: &CallContext,
    svc: &Service,
    desired_name: Option<&GssxName>,
    cred_usage: i32,
) -> Result<CredEnv, i32> {
    let mut target_uid = ctx.uid;
    let mut usage = cred_usage;
    let mut user_requested = false;
    let mut use_service_keytab = false;
    let mut requested_name: Option<Name> = None;

    if svc.cred_usage != GSS_C_BOTH {
        if usage == GSS_C_BOTH {
            usage = svc.cred_usage;
        } else if svc.cred_usage != usage {
            return Err(libc::EACCES);
        }
    }

    if let Some(dn) = desired_name {
        let name_type = dn.name_type.as_slice();
        if svc.trusted
            && svc.euid == target_uid
            && (name_type == consts::NT_STRING_UID_NAME_OID
                || name_type == consts::NT_MACHINE_UID_NAME_OID)
        {
            target_uid = parse_leading_uid(dn.display_name.as_slice());
            user_requested = true;
        } else {
            if svc.euid != target_uid {
                user_requested = true;
            } else {
                use_service_keytab = true;
            }
            requested_name = Some(conv::gssx_to_name(dn).map_err(|_| libc::EINVAL)?);
        }
    } else if svc.trusted && svc.euid == target_uid {
        use_service_keytab = true;
    } else if svc.euid != target_uid {
        user_requested = true;
    }

    // The impersonation sub-block of the C function is intentionally omitted:
    // callers reject impersonation before reaching acquisition.
    let _ = user_requested;

    if use_service_keytab && requested_name.is_none() {
        if let Some(principal) = &svc.krb5_principal {
            // The C daemon imports with length strlen+1 (trailing NUL included).
            let mut bytes = principal.clone().into_bytes();
            bytes.push(0);
            requested_name = Some(
                Name::import(&bytes, Some(consts::KRB5_NT_PRINCIPAL_NAME_OID))
                    .map_err(|_| libc::EINVAL)?,
            );
        }
    }

    if svc.krb5_store.is_empty() {
        return Ok(CredEnv {
            requested_name,
            cred_usage: usage,
            cred_store: Vec::new(),
        });
    }

    let mut store: Vec<(String, String)> = Vec::with_capacity(svc.krb5_store.len() + 2);
    let mut k_idx: Option<usize> = None;
    let mut ck_idx: Option<usize> = None;
    let mut cc_idx: Option<usize> = None;
    for (key, value) in &svc.krb5_store {
        let formatted = get_formatted_string(value, target_uid).ok_or(libc::ENOMEM)?;
        match key.as_str() {
            "client_keytab" => ck_idx = Some(store.len()),
            "keytab" => k_idx = Some(store.len()),
            "ccache" => cc_idx = Some(store.len()),
            _ => {}
        }
        store.push((key.clone(), formatted));
    }

    if use_service_keytab {
        match k_idx {
            None => {
                // A service may legitimately define only the client keytab.
                if ck_idx.is_some() {
                    return Ok(CredEnv {
                        requested_name,
                        cred_usage: usage,
                        cred_store: store,
                    });
                }
                return Err(libc::EINVAL);
            }
            Some(k) => {
                let keytab_value = store[k].1.clone();
                match ck_idx {
                    Some(ck) => store[ck].1 = keytab_value,
                    None => store.push(("client_keytab".to_string(), keytab_value)),
                }
            }
        }
    }

    ensure_segregated_ccache(&mut store, cc_idx);

    Ok(CredEnv {
        requested_name,
        cred_usage: usage,
        cred_store: store,
    })
}

/// `ensure_segregated_ccache`: when no ccache was configured, add a private
/// in-memory one so concurrent acquisitions do not collide.
fn ensure_segregated_ccache(store: &mut Vec<(String, String)>, cc_idx: Option<usize>) {
    if cc_idx.is_some() {
        return;
    }
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    store.push(("ccache".to_string(), format!("MEMORY:internal_{tid}")));
}

/// `gp_check_cred`: validate an input credential. `Ok(())` means reuse it.
fn check_cred(
    svc: &Service,
    in_cred: &Cred,
    desired_name: Option<&GssxName>,
    cred_usage: i32,
) -> Result<(), u32> {
    let info = in_cred.inquire().map_err(|e| e.major)?;

    let present = info.mechs.iter().any(|m| m.as_slice() == consts::KRB5_MECH_OID);
    if !present {
        return Err(consts::GSS_S_CRED_UNAVAIL);
    }

    if let Some(dn) = desired_name {
        let req = conv::gssx_to_name(dn).map_err(|e| e.major)?;
        let check = info.name.as_ref().ok_or(consts::GSS_S_CRED_UNAVAIL)?;
        if !req.compare(check).map_err(|e| e.major)? {
            return Err(consts::GSS_S_CRED_UNAVAIL);
        }
    }

    match cred_usage {
        GSS_C_ACCEPT if info.usage == GSS_C_INITIATE => return Err(consts::GSS_S_NO_CRED),
        GSS_C_INITIATE if info.usage == GSS_C_ACCEPT => return Err(consts::GSS_S_NO_CRED),
        GSS_C_BOTH if info.usage != GSS_C_BOTH => return Err(consts::GSS_S_NO_CRED),
        _ => {}
    }

    if info.lifetime == 0 {
        return Err(consts::GSS_S_CREDENTIALS_EXPIRED);
    }
    if svc.min_lifetime != 0 && info.lifetime < svc.min_lifetime {
        return Err(consts::GSS_S_CREDENTIALS_EXPIRED);
    }
    Ok(())
}

/// `gp_add_krb5_creds` (krb5, non-impersonation). Returns `Ok(Some(cred))` for a
/// freshly acquired credential, `Ok(None)` when the (valid) input credential
/// should be reused as-is.
pub fn add_krb5_creds(
    ctx: &CallContext,
    svc: &Service,
    acquire_type: AcquireType,
    in_cred: Option<&Cred>,
    desired_name: Option<&GssxName>,
    cred_usage: i32,
) -> Result<Option<Cred>, AcqError> {
    if try_impersonate(svc, cred_usage, acquire_type) {
        // Impersonation (s4u2self) is not implemented in this port.
        return Err(AcqError::new(consts::GSS_S_FAILURE, libc::ENOSYS as u32));
    }

    if let Some(inc) = in_cred {
        if acquire_type != AcquireType::ImpName {
            match check_cred(svc, inc, desired_name, cred_usage) {
                Ok(()) => return Ok(None),
                Err(maj)
                    if maj == consts::GSS_S_CREDENTIALS_EXPIRED
                        || maj == consts::GSS_S_NO_CRED
                        || maj == consts::GSS_S_DEFECTIVE_CREDENTIAL => {}
                Err(_) => return Err(AcqError::new(consts::GSS_S_CRED_UNAVAIL, 0)),
            }
        }
    }

    let env = if acquire_type == AcquireType::Normal {
        get_cred_environment(ctx, svc, desired_name, cred_usage)
            .map_err(|e| AcqError::new(consts::GSS_S_CRED_UNAVAIL, e as u32))?
    } else {
        // ACQ_IMPNAME without impersonation: just resolve the requested name.
        let requested_name = match desired_name {
            Some(dn) => Some(conv::gssx_to_name(dn).map_err(|e| AcqError::new(e.major, e.minor))?),
            None => None,
        };
        CredEnv {
            requested_name,
            cred_usage,
            cred_store: Vec::new(),
        }
    };

    let mechs: [&[u8]; 1] = [consts::KRB5_MECH_OID];
    let cred = wrap::acquire_cred_from(
        env.requested_name.as_ref(),
        GSS_C_INDEFINITE,
        &mechs,
        env.cred_usage,
        &env.cred_store,
    )
    .map_err(|e| AcqError::new(e.major, e.minor))?;
    Ok(Some(cred))
}
