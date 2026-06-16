//! Per-connection call context: the peer's credentials (from `SO_PEERCRED`),
//! the socket it connected on, the resolved program path, and the matched
//! service. Mirrors `struct gp_call_ctx` / `gp_creds_match_conn` in
//! `src/gp_creds.c`.

use crate::config::{Config, Service};

/// Everything a handler needs to know about the connection making a request.
#[derive(Debug, Clone)]
pub struct CallContext {
    /// Peer uid from `SO_PEERCRED`.
    pub uid: u32,
    /// Peer gid from `SO_PEERCRED`.
    pub gid: u32,
    /// Peer pid from `SO_PEERCRED` (`None` if the OS did not provide it).
    pub pid: Option<i32>,
    /// The socket path the peer connected on.
    pub socket: String,
    /// The peer's executable path (`/proc/<pid>/exe`), used for `program`
    /// matching. `None` if it could not be resolved.
    pub program: Option<String>,
    /// The matched service, if any.
    pub service: Option<Service>,
}

impl CallContext {
    /// Resolve the service for a connection, mirroring `gp_creds_match_conn`.
    pub fn resolve(
        config: &Config,
        socket: &str,
        uid: u32,
        gid: u32,
        pid: Option<i32>,
    ) -> CallContext {
        let program = pid.and_then(program_for_pid);
        let service = config
            .match_service(uid, socket, program.as_deref())
            .cloned();
        CallContext {
            uid,
            gid,
            pid,
            socket: socket.to_string(),
            program,
            service,
        }
    }

    /// A context with no resolved peer/service, used where peer credentials are
    /// unavailable (e.g. tests).
    pub fn anonymous(socket: &str) -> CallContext {
        CallContext {
            uid: u32::MAX,
            gid: u32::MAX,
            pid: None,
            socket: socket.to_string(),
            program: None,
            service: None,
        }
    }
}

/// Resolve the executable backing a pid via `/proc/<pid>/exe`, matching
/// `get_program()` in `src/gp_socket.c`.
fn program_for_pid(pid: i32) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_service(socket: &str, euid: u32) -> Config {
        let text = format!(
            "[gssproxy]\n[service/test]\n  mechs = krb5\n  euid = {euid}\n  cred_store = keytab:/tmp/x\n"
        );
        Config::parse_str(&text, socket).expect("parse config")
    }

    #[test]
    fn resolves_matching_service_by_uid() {
        let cfg = config_with_service("/run/gp.sock", 1000);
        let ctx = CallContext::resolve(&cfg, "/run/gp.sock", 1000, 1000, None);
        assert!(ctx.service.is_some(), "service should match euid 1000");
        assert_eq!(ctx.service.unwrap().name, "test");
    }

    #[test]
    fn no_service_for_other_uid() {
        let cfg = config_with_service("/run/gp.sock", 1000);
        let ctx = CallContext::resolve(&cfg, "/run/gp.sock", 4242, 4242, None);
        assert!(ctx.service.is_none(), "no service should match a foreign uid");
    }

    #[test]
    fn no_service_on_wrong_socket() {
        let cfg = config_with_service("/run/gp.sock", 1000);
        let ctx = CallContext::resolve(&cfg, "/run/other.sock", 1000, 1000, None);
        assert!(ctx.service.is_none(), "default-socket service must not match a different socket");
    }
}
