//! GSSAPI/krb5 FFI surface used by gssproxy.
//!
//! The raw bindings come from the maintained, bindgen-generated `libgssapi-sys`
//! crate (re-exported here as [`sys`]), so we don't hand-maintain hundreds of
//! `extern "C"` declarations and C struct layouts. This crate adds only what
//! that crate cannot provide:
//!
//!   * gssproxy-specific and well-known OID byte strings ([`consts`]),
//!   * the computed `GSS_S_*` / `GSS_C_*` values bindgen omits (it does not
//!     expand computed `#define` macros),
//!   * thin safe wrappers we layer on top as the daemon/interposer need them.

pub use libgssapi_sys as sys;

pub mod consts;
pub mod wrap;
