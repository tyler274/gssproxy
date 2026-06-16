//! Interposer behavior selection and the global enable check.
//!
//! Port of `gpp_get_behavior` and `enabled()` from `src/mechglue/gss_plugin.c`.

use std::sync::OnceLock;

use crate::env;

/// `enum gpp_behavior`. The wire/daemon split decides whether each operation
/// is attempted locally (real mech), remotely (via gssproxy), or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    LocalOnly,
    LocalFirst,
    RemoteFirst,
    RemoteOnly,
}

/// Compile-time default (autotools `--with-gpp-default-behavior`, default
/// `LOCAL_FIRST`).
const DEFAULT_BEHAVIOR: Behavior = Behavior::LocalFirst;

/// Compile-time default for `GSS_ALWAYS_INTERPOSE` (autotools
/// `--enable-always-interpose`, default `false`).
const GSS_ALWAYS_INTERPOSE: bool = false;

// Consumed by the forthcoming gssi_* data path (gpp_get_behavior call sites).
#[allow(dead_code)]
static BEHAVIOR: OnceLock<Behavior> = OnceLock::new();

/// Pure mapping of a `GSSPROXY_BEHAVIOR` value to a [`Behavior`] (unknown or
/// absent values fall back to the compiled-in default). Factored out so it can
/// be unit tested without the process-global `OnceLock` cache.
pub fn parse_behavior(value: Option<&str>) -> Behavior {
    match value {
        Some("LOCAL_ONLY") => Behavior::LocalOnly,
        Some("LOCAL_FIRST") => Behavior::LocalFirst,
        Some("REMOTE_FIRST") => Behavior::RemoteFirst,
        Some("REMOTE_ONLY") => Behavior::RemoteOnly,
        _ => DEFAULT_BEHAVIOR,
    }
}

/// `gpp_get_behavior`: resolve (once) the interposer behavior from
/// `GSSPROXY_BEHAVIOR`, falling back to the compiled-in default.
#[allow(dead_code)]
pub fn get() -> Behavior {
    *BEHAVIOR.get_or_init(|| parse_behavior(env::get("GSSPROXY_BEHAVIOR").as_deref()))
}

/// Pure form of [`enabled`]: resolve the `GSS_USE_PROXY` value to whether the
/// interposer is active, defaulting to `GSS_ALWAYS_INTERPOSE` when unset.
pub fn enabled_from(value: Option<&str>) -> bool {
    match value {
        Some(v) => env::boolean_is_true(v),
        None => GSS_ALWAYS_INTERPOSE,
    }
}

/// `enabled()`: whether interposition is active at all. Defaults to
/// `GSS_ALWAYS_INTERPOSE`, overridden by `GSS_USE_PROXY`. This is what prevents
/// the gssproxy daemon itself from looping back into the interposer.
pub fn enabled() -> bool {
    enabled_from(env::get("GSS_USE_PROXY").as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behavior_parsing_matches_c_names() {
        assert_eq!(parse_behavior(Some("LOCAL_ONLY")), Behavior::LocalOnly);
        assert_eq!(parse_behavior(Some("LOCAL_FIRST")), Behavior::LocalFirst);
        assert_eq!(parse_behavior(Some("REMOTE_FIRST")), Behavior::RemoteFirst);
        assert_eq!(parse_behavior(Some("REMOTE_ONLY")), Behavior::RemoteOnly);
    }

    #[test]
    fn unknown_or_absent_behavior_uses_default() {
        // Default is LOCAL_FIRST (autotools --with-gpp-default-behavior).
        assert_eq!(parse_behavior(None), Behavior::LocalFirst);
        assert_eq!(parse_behavior(Some("garbage")), Behavior::LocalFirst);
        assert_eq!(parse_behavior(Some("")), Behavior::LocalFirst);
    }

    #[test]
    fn enabled_follows_gss_use_proxy() {
        // GSS_ALWAYS_INTERPOSE defaults to false, so absence disables.
        assert!(!enabled_from(None));
        for truthy in ["1", "on", "true", "yes", "YES", "True"] {
            assert!(enabled_from(Some(truthy)), "{truthy:?} should enable");
        }
        for falsy in ["0", "off", "false", "no", "nonsense", ""] {
            assert!(!enabled_from(Some(falsy)), "{falsy:?} should disable");
        }
    }
}
