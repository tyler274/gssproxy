//! `secure_getenv`-based environment access (C: `gp_getenv`).
//!
//! The interposer is loaded into arbitrary, possibly setuid, programs, so it
//! must consult the environment through `secure_getenv` to avoid honouring
//! attacker-controlled variables across a privilege boundary.

use std::ffi::{CStr, CString};

extern "C" {
    fn secure_getenv(name: *const libc::c_char) -> *mut libc::c_char;
}

/// Return the value of environment variable `name` via `secure_getenv`, or
/// `None` when unset (or suppressed in a setuid/setgid context).
pub fn get(name: &str) -> Option<String> {
    let cname = CString::new(name).ok()?;
    // SAFETY: `cname` is a valid NUL-terminated C string; the returned pointer
    // (if non-null) references the process environment and is copied at once.
    let ptr = unsafe { secure_getenv(cname.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// `gp_boolean_is_true`: true for `1`/`on`/`true`/`yes` (case-insensitive).
pub fn boolean_is_true(s: &str) -> bool {
    let s = s.trim();
    s.eq_ignore_ascii_case("1")
        || s.eq_ignore_ascii_case("on")
        || s.eq_ignore_ascii_case("true")
        || s.eq_ignore_ascii_case("yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boolean_is_true_matches_c_semantics() {
        for t in ["1", "on", "true", "yes", "YES", "  TrUe  ", "On"] {
            assert!(boolean_is_true(t), "{t:?} should be true");
        }
        for f in ["0", "off", "false", "no", "", "2", "enable"] {
            assert!(!boolean_is_true(f), "{f:?} should be false");
        }
    }
}
