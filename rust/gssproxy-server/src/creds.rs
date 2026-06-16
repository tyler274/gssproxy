//! Credential acquisition, ported from `src/gp_creds.c` and the krb5 paths of
//! `gp_add_krb5_creds` / `gp_get_cred_environment` / `gp_check_cred`.
//!
//! Only the krb5 mechanism is supported. Both the non-impersonation `ACQ_NORMAL`
//! path and the s4u2self impersonation / constrained-delegation paths
//! (`impersonate = yes` services and `ACQ_IMPNAME` acquisitions) are
//! implemented, mirroring the impersonation sub-blocks of `gp_add_krb5_creds`
//! and `gp_cred_allowed`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gssapi_sys::seal::CredHandle;
use gssapi_sys::wrap::{self, Cred, Name};
use gssapi_sys::{consts, sys};
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
    /// Name of the private `MEMORY:` ccache this environment created (if any),
    /// so the caller can destroy it once the acquired credential is no longer
    /// needed. Mirrors the C daemon's per-request `destroy_callback`.
    mem_ccache: Option<String>,
}

/// RAII guard that destroys a per-request `MEMORY:` credential cache on drop,
/// mirroring `safe_free_mem_ccache` in `gp_creds.c`. Without this, a later
/// acquisition reusing the same thread-keyed ccache name would observe a stale
/// principal and fail with `KG_CCACHE_NOMATCH`.
pub struct MemCcacheGuard(String);

impl Drop for MemCcacheGuard {
    fn drop(&mut self) {
        wrap::destroy_ccache(&self.0);
    }
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

    // Impersonation case (only for initiation): use the service keytab to
    // acquire the initial credential, then make the s4u2self dance toward the
    // target user, identified by uid. Mirrors the `user_requested` block in
    // `gp_get_cred_environment`.
    if user_requested && try_impersonate(svc, usage, AcquireType::Normal) {
        use_service_keytab = true;
        let username = uid_to_name(target_uid).ok_or(libc::ENOENT)?;
        // C imports with GSS_C_NT_USER_NAME and length == strlen(str) (no NUL).
        requested_name = Some(
            Name::import(username.as_bytes(), Some(consts::NT_USER_NAME_OID))
                .map_err(|_| libc::ENOMEM)?,
        );
    }

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
            mem_ccache: None,
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
                        mem_ccache: None,
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

    let mem_ccache = ensure_segregated_ccache(&mut store, cc_idx);

    Ok(CredEnv {
        requested_name,
        cred_usage: usage,
        cred_store: store,
        mem_ccache,
    })
}

/// `ensure_segregated_ccache`: when no ccache was configured, add a private
/// in-memory one so concurrent acquisitions do not collide. Returns the ccache
/// name when one was created, so the caller can destroy it after use (the C
/// daemon registers a per-request `destroy_callback` for the same reason).
fn ensure_segregated_ccache(
    store: &mut Vec<(String, String)>,
    cc_idx: Option<usize>,
) -> Option<String> {
    if cc_idx.is_some() {
        return None;
    }
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    let name = format!("MEMORY:internal_{tid}");
    store.push(("ccache".to_string(), name.clone()));
    Some(name)
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

/// `gp_cred_allowed`: decide whether `cred` may be used against `target`.
///
/// Trusted / impersonate / const-deleg services are always allowed. For other
/// services we inspect the credential for an impersonator entry (constrained
/// delegation) via `gss_inquire_cred_by_oid`; if one is present we reject the
/// use unless the target *is* the impersonator itself (the "self" case).
pub fn cred_allowed(svc: &Service, cred: Option<&Cred>, target: &Name) -> Result<(), u32> {
    let Some(cred) = cred else {
        return Err(consts::GSS_S_CRED_UNAVAIL);
    };
    if svc.trusted || svc.impersonate || svc.allow_const_deleg {
        return Ok(());
    }

    let impersonator = match get_impersonator_name(cred) {
        Ok(i) => i,
        Err(major) => return Err(major),
    };

    // No impersonator entry: a normal credential, always allowed.
    let Some(impersonator) = impersonator else {
        return Ok(());
    };

    // An impersonator entry is present: only allowed when the target is the
    // impersonator itself (otherwise it is unauthorized constrained delegation).
    check_impersonator_name(target, &impersonator)
}

/// `get_impersonator_name`: return the impersonator principal recorded on a
/// (constrained-delegation) credential, or `None` for a normal credential.
fn get_impersonator_name(cred: &Cred) -> Result<Option<Vec<u8>>, u32> {
    let bufs = cred
        .inquire_by_oid(consts::KRB5_GET_CRED_IMPERSONATOR_OID)
        .map_err(|e| e.major)?;
    match bufs.into_iter().next() {
        Some(b) if !b.is_empty() => Ok(Some(b)),
        _ => Ok(None),
    }
}

/// `check_impersonator_name`: canonicalize `target` to krb5, render its display
/// name, and compare it byte-for-byte against `impersonator`. Returns `Ok(())`
/// on a match ("self"), `GSS_S_UNAUTHORIZED` otherwise.
fn check_impersonator_name(target: &Name, impersonator: &[u8]) -> Result<(), u32> {
    let canon = target.canonicalize(consts::KRB5_MECH_OID).map_err(|e| e.major)?;
    let (display, _name_type) = canon.display().map_err(|e| e.major)?;
    if display == impersonator {
        Ok(())
    } else {
        Err(consts::GSS_S_UNAUTHORIZED)
    }
}

/// `gp_add_krb5_creds` (krb5, non-impersonation). Returns the freshly acquired
/// credential (or `None` when the valid input credential should be reused
/// as-is) together with a guard that destroys the private per-request `MEMORY:`
/// ccache once dropped. The caller must hold the guard until the credential has
/// finished being used (e.g. through `init`/`accept_sec_context` or the cred
/// export), then drop it.
pub fn add_krb5_creds(
    ctx: &CallContext,
    svc: &Service,
    acquire_type: AcquireType,
    in_cred: Option<&Cred>,
    desired_name: Option<&GssxName>,
    cred_usage: i32,
) -> Result<(Option<Cred>, Option<MemCcacheGuard>), AcqError> {
    if let Some(inc) = in_cred {
        if acquire_type != AcquireType::ImpName {
            match check_cred(svc, inc, desired_name, cred_usage) {
                Ok(()) => return Ok((None, None)),
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
        // ACQ_IMPNAME: just resolve the requested name; the cred store is unused.
        let requested_name = match desired_name {
            Some(dn) => Some(conv::gssx_to_name(dn).map_err(|e| AcqError::new(e.major, e.minor))?),
            None => None,
        };
        CredEnv {
            requested_name,
            cred_usage,
            cred_store: Vec::new(),
            mem_ccache: None,
        }
    };

    // The private MEMORY ccache (if any) must live until the acquired
    // credential has finished being used; hand a guard back to the caller.
    let guard = env.mem_ccache.map(MemCcacheGuard);
    let usage = env.cred_usage;
    let mechs: [&[u8]; 1] = [consts::KRB5_MECH_OID];

    if !try_impersonate(svc, usage, acquire_type) {
        let cred = wrap::acquire_cred_from(
            env.requested_name.as_ref(),
            GSS_C_INDEFINITE,
            &mechs,
            usage,
            &env.cred_store,
        )
        .map_err(|e| AcqError::new(e.major, e.minor))?;
        return Ok((Some(cred), guard));
    }

    let cred = impersonate_acquire(
        svc,
        acquire_type,
        in_cred,
        env.requested_name.as_ref(),
        usage,
        &env.cred_store,
        &mechs,
    )?;
    Ok((Some(cred), guard))
}

/// The s4u2self / constrained-delegation acquisition, ported from the
/// `impersonation` branch of `gp_add_krb5_creds`. Returns the credential to use
/// for the impersonated user.
#[allow(clippy::too_many_arguments)]
fn impersonate_acquire(
    svc: &Service,
    acquire_type: AcquireType,
    in_cred: Option<&Cred>,
    req_name: Option<&Name>,
    cred_usage: i32,
    cred_store: &[(String, String)],
    mechs: &[&[u8]],
) -> Result<Cred, AcqError> {
    // `input_cred` is the credential we impersonate *with*: for ACQ_NORMAL the
    // service ("impersonator") credential we acquire here, for ACQ_IMPNAME the
    // caller-supplied credential. `impersonator_owned` keeps the ACQ_NORMAL
    // credential alive for the rest of the function.
    let impersonator_owned: Option<Cred>;
    let input_cred: &Cred = match acquire_type {
        AcquireType::Normal => {
            let host_principal = match &svc.krb5_principal {
                Some(p) => {
                    // C imports with length strlen+1 (trailing NUL included).
                    let mut bytes = p.clone().into_bytes();
                    bytes.push(0);
                    Some(
                        Name::import(&bytes, Some(consts::KRB5_NT_PRINCIPAL_NAME_OID))
                            .map_err(|e| AcqError::new(e.major, e.minor))?,
                    )
                }
                None => None,
            };

            let impersonator = wrap::acquire_cred_from(
                host_principal.as_ref(),
                GSS_C_INDEFINITE,
                mechs,
                GSS_C_BOTH,
                cred_store,
            )
            .map_err(|e| AcqError::new(e.major, e.minor))?;

            // If the impersonator credential already names the requested client,
            // we do not need to impersonate (and MIT errors on self-S4U2Self):
            // acquire the client credential directly and return it.
            if let Some(req) = req_name {
                if let Ok(info) = impersonator.inquire() {
                    if let Some(comp) = &info.name {
                        if req.compare(comp).unwrap_or(false) {
                            if let Ok(user_cred) = wrap::acquire_cred_from(
                                Some(req),
                                GSS_C_INDEFINITE,
                                mechs,
                                cred_usage,
                                cred_store,
                            ) {
                                return Ok(user_cred);
                            }
                            // Fall through on failure, matching the C daemon.
                        }
                    }
                }
            }

            impersonator_owned = Some(impersonator);
            impersonator_owned.as_ref().unwrap()
        }
        AcquireType::ImpName => {
            // No impersonator credential is acquired on this path.
            in_cred.ok_or_else(|| AcqError::new(consts::GSS_S_FAILURE, libc::EFAULT as u32))?
        }
    };

    // The S4U2Self target is the impersonator/input credential's own name.
    let target_name = input_cred
        .inquire()
        .map_err(|e| AcqError::new(e.major, e.minor))?
        .name
        .ok_or_else(|| AcqError::new(consts::GSS_S_FAILURE, 0))?;

    // S4U2Self: obtain a credential for the requested user.
    let user_cred = wrap::acquire_cred_impersonate_name(
        input_cred,
        req_name,
        GSS_C_INDEFINITE,
        mechs,
        GSS_C_INITIATE,
    )
    .map_err(|e| AcqError::new(e.major, e.minor))?;

    if acquire_type == AcquireType::ImpName {
        // For ACQ_IMPNAME we are done: hand back the impersonated credential.
        return Ok(user_cred);
    }

    // Acquire credentials for the impersonated user "to self": initiate a
    // context with the impersonated credential toward the impersonator, then
    // accept it to extract the (constrained-delegation) credential.
    let init = wrap::init_sec_context(
        Some(&user_cred),
        None,
        &target_name,
        consts::KRB5_MECH_OID,
        sys::GSS_C_REPLAY_FLAG | sys::GSS_C_SEQUENCE_FLAG,
        GSS_C_INDEFINITE,
        None,
        &[],
    )
    .map_err(|e| AcqError::new(e.major, e.minor))?;

    let accept = wrap::accept_sec_context(None, Some(input_cred), &init.output, None, true)
        .map_err(|e| AcqError::new(e.major, e.minor))?;

    accept
        .delegated_cred
        .ok_or_else(|| AcqError::new(consts::GSS_S_FAILURE, 0))
}
