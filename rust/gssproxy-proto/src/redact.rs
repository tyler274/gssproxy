//! Helpers for logging secret-bearing data safely.
//!
//! The gssx wire protocol carries credentials, GSS tokens, exported context
//! state, keytab-derived key material, channel bindings, and passwords. None of
//! that may ever reach a log sink in cleartext. These helpers let call sites
//! record the *shape* of a secret (its length) without its contents, so that
//! `tracing` fields stay useful for debugging while never leaking key material.
//!
//! This module is intentionally dependency-free (no `tracing`): `gssproxy-proto`
//! is the byte-exact, dependency-free codec crate, so it only provides the
//! formatting primitives and the consuming crates pass them to `tracing`.
//!
//! Usage in a `tracing` field:
//! ```ignore
//! tracing::debug!(token = %redact::len(&output_token), "init_sec_context done");
//! // logs: token=<48 bytes>
//! ```

use core::fmt;

/// A [`fmt::Display`]/[`fmt::Debug`] wrapper that renders only a byte length,
/// never the bytes themselves. Construct it with [`len`]/[`opt_len`].
#[derive(Clone, Copy)]
pub struct Len(usize);

impl fmt::Display for Len {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

impl fmt::Debug for Len {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Summarise a secret-bearing byte slice as `<N bytes>` for logging.
pub fn len(bytes: &[u8]) -> Len {
    Len(bytes.len())
}

/// Summarise an optional secret-bearing byte slice; absent renders as
/// `<0 bytes>`, matching an empty buffer.
pub fn opt_len(bytes: Option<&[u8]>) -> Len {
    Len(bytes.map_or(0, <[u8]>::len))
}

/// Whether a secret is present (non-empty), for a boolean `present=` field that
/// reveals nothing about the contents.
pub fn present(bytes: &[u8]) -> bool {
    !bytes.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_only_length() {
        assert_eq!(len(b"super-secret-token").to_string(), "<18 bytes>");
        assert_eq!(format!("{:?}", len(&[])), "<0 bytes>");
        assert_eq!(opt_len(None).to_string(), "<0 bytes>");
        assert_eq!(opt_len(Some(b"abcd")).to_string(), "<4 bytes>");
    }

    #[test]
    fn never_contains_payload() {
        let secret = b"AKIA-pretend-this-is-a-key";
        let rendered = format!("{} {:?}", len(secret), opt_len(Some(secret)));
        assert!(!rendered.contains("AKIA"));
        assert!(rendered.contains("26 bytes"));
    }

    #[test]
    fn present_reports_emptiness_only() {
        assert!(present(b"x"));
        assert!(!present(b""));
    }
}
