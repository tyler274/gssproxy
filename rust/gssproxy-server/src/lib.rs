//! The gssproxy daemon (Rust port), exposed as a library so the binary and the
//! integration tests share the same modules.
//!
//! Layers:
//!   - [`config`]: `gssproxy.conf` parsing and service/euid matching.
//!   - [`conv`]: conversions between the gssx wire types and live GSSAPI handles.
//!   - [`handlers`]: per-procedure GSSAPI logic (`gp_rpc_*` ports).
//!   - [`dispatch`]: RPC envelope validation and per-procedure routing.
//!   - [`server`]: the Unix-socket listener and SunRPC record-marking loop.

pub mod call;
pub mod config;
pub mod conv;
pub mod creds;
pub mod dispatch;
pub mod handlers;
pub mod server;
