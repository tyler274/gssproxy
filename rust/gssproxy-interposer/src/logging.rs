//! Tracing initialisation for the interposer.
//!
//! `proxymech.so` is loaded into arbitrary, possibly privileged, host processes.
//! Two rules follow from that:
//!
//!   1. **Off by default.** We never install a global subscriber unless the
//!      operator explicitly opts in via the `GSSPROXY_LOG` environment variable
//!      (read through `secure_getenv`, so it is ignored across a setuid/setgid
//!      boundary). When unset, our `tracing` events are near-zero-cost no-ops
//!      (or flow to the host's own subscriber, if it installed one).
//!
//!   2. **Install at most once, never panic.** Initialisation is guarded by a
//!      `Once` and uses `try_init`, so repeated `gssi_*` entry points and a
//!      host that already configured `tracing` are both handled gracefully.
//!
//! `GSSPROXY_LOG` takes an `EnvFilter` directive, e.g. `GSSPROXY_LOG=debug` or
//! `GSSPROXY_LOG=proxymech=trace`.

use std::sync::Once;

use gssapi_sys::sys::gss_buffer_t;

use crate::env;

static INIT: Once = Once::new();

/// Byte length of a `gss_buffer_t`, for logging GSS tokens by size only (never
/// their contents). Returns 0 for `GSS_C_NO_BUFFER` (null).
///
/// # Safety
/// `buf` must be null or point to a valid `gss_buffer_desc`.
pub unsafe fn buf_len(buf: gss_buffer_t) -> usize {
    if buf.is_null() {
        0
    } else {
        unsafe { (*buf).length }
    }
}

/// Install the interposer's `tracing` subscriber if `GSSPROXY_LOG` is set.
/// Idempotent and cheap to call from every entry point.
pub fn init() {
    INIT.call_once(|| {
        let Some(directive) = env::get("GSSPROXY_LOG") else {
            return;
        };
        if directive.trim().is_empty() {
            return;
        }

        use tracing_subscriber::EnvFilter;
        // ANSI colour is disabled: interposer logs commonly land in a host's
        // journal/file rather than an interactive terminal.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(directive))
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .try_init();
    });
}
