//! `gssproxy.conf` parser and service/euid matching, ported from
//! `src/gp_config.c`.
//!
//! Parsing uses the `rust-ini` crate (which preserves key order and supports
//! repeated keys via `get_all`, needed for `cred_store`); the schema, defaults,
//! and validation rules mirror the C loader.

use ini::Ini;

/// Compiled-in default socket path (autotools `GP_SOCKET_NAME`).
pub const GP_SOCKET_NAME: &str = "/var/lib/gssproxy/default.sock";

/// `gp_service.mechs` bitmask bit for krb5 (`GP_CRED_KRB5`).
pub const GP_CRED_KRB5: u32 = 0x01;

// GSS_C_* credential usage values (gssapi.h).
pub const GSS_C_BOTH: i32 = 0;
pub const GSS_C_INITIATE: i32 = 1;
pub const GSS_C_ACCEPT: i32 = 2;

// Request/return flag bits, used by filter_flags/enforce_flags.
const GSS_C_DELEG_FLAG: u32 = 1;

const DEFAULT_FILTERED_FLAGS: u32 = GSS_C_DELEG_FLAG;
const DEFAULT_ENFORCED_FLAGS: u32 = 0;
const DEFAULT_MIN_LIFETIME: u32 = 15;

/// Flag names accepted in `filter_flags`/`enforce_flags`. The `INTEGRITIY`
/// spelling is intentionally preserved from the C table for compatibility.
const FLAG_NAMES: &[(&str, u32)] = &[
    ("DELEGATE", 0x01),
    ("MUTUAL_AUTH", 0x02),
    ("REPLAY_DETECT", 0x04),
    ("SEQUENCE", 0x08),
    ("CONFIDENTIALITY", 0x10),
    ("INTEGRITIY", 0x20),
    ("ANONYMOUS", 0x40),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Parse(String),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Parse(m) => write!(f, "config parse error: {m}"),
            ConfigError::Invalid(m) => write!(f, "invalid config: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

type Result<T> = std::result::Result<T, ConfigError>;

/// A single `[service/...]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub euid: u32,
    pub any_uid: bool,
    pub allow_proto_trans: bool,
    pub allow_const_deleg: bool,
    pub allow_cc_sync: bool,
    pub trusted: bool,
    pub kernel_nfsd: bool,
    pub impersonate: bool,
    pub socket: Option<String>,
    pub selinux_context: Option<String>,
    pub cred_usage: i32,
    pub filter_flags: u32,
    pub enforce_flags: u32,
    pub min_lifetime: u32,
    pub program: Option<String>,
    pub mechs: u32,
    pub krb5_principal: Option<String>,
    /// `cred_store` entries as `(key, value)`, split on the first `:`.
    pub krb5_store: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub socket_name: String,
    pub num_workers: i32,
    pub proxy_user: Option<String>,
    pub debug_level: i32,
    pub services: Vec<Service>,
}

impl Config {
    /// A configuration with no services, listening on `socket_name`. Used as a
    /// fallback where no config is available (e.g. tests); `match_service`
    /// always returns `None`.
    pub fn empty(socket_name: &str) -> Config {
        Config {
            socket_name: socket_name.to_string(),
            num_workers: 0,
            proxy_user: None,
            debug_level: 0,
            services: Vec::new(),
        }
    }

    /// Load and parse a configuration file, using `socket_name` as the default
    /// socket for services that do not set their own.
    pub fn parse_file(path: &std::path::Path, socket_name: &str) -> Result<Config> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Parse(format!("{}: {e}", path.display())))?;
        Config::parse_str(&content, socket_name)
    }

    /// Parse a configuration from INI text, using `socket_name` as the default
    /// socket for services that do not set their own.
    pub fn parse_str(content: &str, socket_name: &str) -> Result<Config> {
        let ini = Ini::load_from_str(content).map_err(|e| ConfigError::Parse(e.to_string()))?;

        let mut cfg = Config {
            socket_name: socket_name.to_string(),
            num_workers: 0,
            proxy_user: None,
            debug_level: 0,
            services: Vec::new(),
        };

        // Global [gssproxy] section.
        if let Some(g) = ini.section(Some("gssproxy")) {
            if let Some(v) = g.get("debug") {
                if gp_boolean_is_true(v) && cfg.debug_level == 0 {
                    cfg.debug_level = 1;
                }
            }
            if let Some(v) = g.get("debug_level") {
                if let Ok(n) = v.trim().parse::<i32>() {
                    cfg.debug_level = n;
                }
            }
            if let Some(v) = g.get("run_as_user") {
                cfg.proxy_user = Some(v.to_string());
            }
            if let Some(v) = g.get("worker threads") {
                if let Ok(n) = v.trim().parse::<i32>() {
                    cfg.num_workers = n;
                }
            }
        }

        // Service sections, in file order.
        for sec in ini.sections().flatten() {
            let Some(name) = sec.strip_prefix("service/") else {
                continue;
            };
            if let Some(props) = ini.section(Some(sec)) {
                if let Some(svc) = parse_service(name, props)? {
                    cfg.services.push(svc);
                }
            }
        }

        if cfg.services.is_empty() {
            return Err(ConfigError::Invalid(
                "No service sections configured!".to_string(),
            ));
        }

        check_services(&cfg)?;
        Ok(cfg)
    }

    /// Match a connection to a service, mirroring `gp_creds_match_conn`: first
    /// service whose euid (or `any_uid`), program, and socket all match wins.
    ///
    /// SELinux context matching is not yet plumbed through and is treated as
    /// always-matching here.
    pub fn match_service(&self, uid: u32, socket: &str, program: Option<&str>) -> Option<&Service> {
        self.services.iter().find(|svc| {
            if !svc.any_uid && svc.euid != uid {
                return false;
            }
            if let Some(p) = &svc.program {
                if program != Some(p.as_str()) {
                    return false;
                }
            }
            match &svc.socket {
                Some(s) => socket == s,
                None => socket == self.socket_name,
            }
        })
    }
}

/// Parse one service section. Returns `Ok(None)` when the service should be
/// silently ignored (no usable mechs), matching the C loader.
fn parse_service(name: &str, props: &ini::Properties) -> Result<Option<Service>> {
    let mut svc = Service {
        name: name.to_string(),
        euid: 0,
        any_uid: false,
        allow_proto_trans: false,
        allow_const_deleg: false,
        allow_cc_sync: false,
        trusted: false,
        kernel_nfsd: false,
        impersonate: false,
        socket: None,
        selinux_context: None,
        cred_usage: GSS_C_BOTH,
        filter_flags: DEFAULT_FILTERED_FLAGS,
        enforce_flags: DEFAULT_ENFORCED_FLAGS,
        min_lifetime: DEFAULT_MIN_LIFETIME,
        program: None,
        mechs: 0,
        krb5_principal: None,
        krb5_store: Vec::new(),
    };

    // euid: integer, or a username resolved via getpwnam. Mandatory.
    match props.get("euid") {
        None => {
            return Err(ConfigError::Invalid(format!(
                "Option 'euid' is missing from [service/{name}]."
            )))
        }
        Some(v) => {
            let v = v.trim();
            svc.euid = match v.parse::<u32>() {
                Ok(n) => n,
                Err(_) => lookup_uid(v).ok_or_else(|| {
                    ConfigError::Invalid(format!("Unknown euid user '{v}' in [service/{name}]."))
                })?,
            };
        }
    }

    svc.any_uid = bool_opt(props, "allow_any_uid");
    svc.allow_proto_trans = bool_opt(props, "allow_protocol_transition");
    svc.allow_const_deleg = bool_opt(props, "allow_constrained_delegation");
    svc.allow_cc_sync = bool_opt(props, "allow_client_ccache_sync");
    svc.trusted = bool_opt(props, "trusted");
    svc.kernel_nfsd = bool_opt(props, "kernel_nfsd");
    svc.impersonate = bool_opt(props, "impersonate");

    if let Some(v) = props.get("socket") {
        svc.socket = Some(v.to_string());
    }

    // mechs: mandatory; only krb5 is supported.
    let mechs = props.get("mechs").ok_or_else(|| {
        ConfigError::Invalid(format!("Option 'mechs' is missing from [service/{name}]."))
    })?;
    for token in mechs.split([',', ' ']).filter(|t| !t.is_empty()) {
        if token == "krb5" {
            parse_krb5_cfg(&mut svc, props)?;
            svc.mechs |= GP_CRED_KRB5;
        }
        // Unknown mechs are ignored (logged in the C daemon).
    }
    if svc.mechs == 0 {
        // No usable mechs: ignore this service.
        return Ok(None);
    }

    if let Some(v) = props.get("selinux_context") {
        svc.selinux_context = Some(v.to_string());
    }

    if let Some(v) = props.get("cred_usage") {
        svc.cred_usage = match v.to_ascii_lowercase().as_str() {
            "initiate" => GSS_C_INITIATE,
            "accept" => GSS_C_ACCEPT,
            "both" => GSS_C_BOTH,
            _ => {
                return Err(ConfigError::Invalid(format!(
                    "Invalid value '{v}' for cred_usage in [service/{name}]."
                )))
            }
        };
    }

    if let Some(v) = props.get("filter_flags") {
        parse_flags(v, &mut svc.filter_flags)?;
    }
    if let Some(v) = props.get("enforce_flags") {
        parse_flags(v, &mut svc.enforce_flags)?;
    }

    if let Some(v) = props.get("program") {
        svc.program = Some(v.to_string());
    }

    if let Some(v) = props.get("min_lifetime") {
        if let Ok(n) = v.trim().parse::<i64>() {
            if n >= 0 {
                svc.min_lifetime = n as u32;
            }
        }
    }

    Ok(Some(svc))
}

fn parse_krb5_cfg(svc: &mut Service, props: &ini::Properties) -> Result<()> {
    if let Some(v) = props.get("krb5_principal") {
        svc.krb5_principal = Some(v.to_string());
    }

    // Reject the long-deprecated standalone keytab/ccache options.
    for dep in ["krb5_keytab", "krb5_ccache", "krb5_client_keytab"] {
        if props.get(dep).is_some() {
            return Err(ConfigError::Invalid(format!(
                "\"{dep}\" is deprecated, please use \"cred_store\"."
            )));
        }
    }

    for entry in props.get_all("cred_store").flat_map(|v| v.split(',')) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((key, value)) = entry.split_once(':') else {
            return Err(ConfigError::Invalid(format!(
                "Invalid cred_store value, no ':' separator found in [{entry}]."
            )));
        };
        svc.krb5_store.push((key.to_string(), value.to_string()));
    }
    Ok(())
}

/// Port of `check_services`: program paths must be absolute and free of `|`,
/// and no two services may collide on (socket, program, selinux, euid/any_uid).
fn check_services(cfg: &Config) -> Result<()> {
    let sock_of = |svc: &Service| -> String {
        svc.socket
            .clone()
            .unwrap_or_else(|| cfg.socket_name.clone())
    };

    for (i, isvc) in cfg.services.iter().enumerate() {
        if let Some(prog) = &isvc.program {
            if !prog.starts_with('/') {
                return Err(ConfigError::Invalid("Program paths must be absolute!".to_string()));
            }
            if prog.contains('|') {
                return Err(ConfigError::Invalid(
                    "The character '|' is invalid in program paths!".to_string(),
                ));
            }
        }

        for jsvc in &cfg.services[..i] {
            if sock_of(isvc) != sock_of(jsvc)
                || isvc.program != jsvc.program
                || isvc.selinux_context != jsvc.selinux_context
            {
                continue;
            }
            if jsvc.any_uid {
                return Err(ConfigError::Invalid(format!(
                    "{} sets allow_any_uid with the same socket, selinux_context, and program as {}!",
                    jsvc.name, isvc.name
                )));
            } else if jsvc.euid == isvc.euid {
                return Err(ConfigError::Invalid(format!(
                    "socket, selinux_context, euid, and program for {} and {} should not match!",
                    isvc.name, jsvc.name
                )));
            }
        }
    }
    Ok(())
}

/// `parse_flags`: tokens are `+NAME`/`-NAME` (names from `FLAG_NAMES`, or a
/// numeric value); a token without a `+`/`-` qualifier is ignored.
fn parse_flags(value: &str, storage: &mut u32) -> Result<()> {
    for token in value.split([',', ' ']).filter(|t| !t.is_empty()) {
        let (add, name) = match token.as_bytes()[0] {
            b'+' => (true, &token[1..]),
            b'-' => (false, &token[1..]),
            _ => continue,
        };
        let flagval = FLAG_NAMES
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
            .or_else(|| parse_numeric_flag(name));
        let Some(flagval) = flagval else {
            continue;
        };
        if add {
            *storage |= flagval;
        } else {
            *storage &= !flagval;
        }
    }
    Ok(())
}

fn parse_numeric_flag(s: &str) -> Option<u32> {
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    };
    match parsed {
        Ok(v) if v != 0 && v != u32::MAX => Some(v),
        _ => None,
    }
}

fn bool_opt(props: &ini::Properties, key: &str) -> bool {
    props.get(key).map(gp_boolean_is_true).unwrap_or(false)
}

/// `gp_boolean_is_true`: true for `1`/`on`/`true`/`yes` (case-insensitive).
fn gp_boolean_is_true(s: &str) -> bool {
    let s = s.trim();
    s.eq_ignore_ascii_case("1")
        || s.eq_ignore_ascii_case("on")
        || s.eq_ignore_ascii_case("true")
        || s.eq_ignore_ascii_case("yes")
}

fn lookup_uid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some((*pw).pw_uid as u32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOCK: &str = GP_SOCKET_NAME;

    #[test]
    fn parses_basic_service() {
        let cfg = Config::parse_str(
            "[gssproxy]\n\
             debug_level = 2\n\
             [service/nfs-server]\n\
             mechs = krb5\n\
             euid = 0\n\
             cred_store = keytab:/etc/krb5.keytab\n\
             cred_store = ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U\n\
             trusted = yes\n\
             kernel_nfsd = yes\n",
            SOCK,
        )
        .unwrap();

        assert_eq!(cfg.debug_level, 2);
        assert_eq!(cfg.services.len(), 1);
        let svc = &cfg.services[0];
        assert_eq!(svc.name, "nfs-server");
        assert_eq!(svc.euid, 0);
        assert!(svc.trusted);
        assert!(svc.kernel_nfsd);
        assert_eq!(svc.mechs, GP_CRED_KRB5);
        assert_eq!(svc.cred_usage, GSS_C_BOTH);
        assert_eq!(
            svc.krb5_store,
            vec![
                ("keytab".to_string(), "/etc/krb5.keytab".to_string()),
                (
                    "ccache".to_string(),
                    "FILE:/var/lib/gssproxy/clients/krb5cc_%U".to_string()
                ),
            ]
        );
    }

    #[test]
    fn cred_store_value_keeps_colons() {
        // The first colon splits key from value; later colons stay in the value.
        let cfg = Config::parse_str(
            "[service/x]\nmechs = krb5\neuid = 5\ncred_store = ccache:FILE:/tmp/cc\n",
            SOCK,
        )
        .unwrap();
        assert_eq!(
            cfg.services[0].krb5_store,
            vec![("ccache".to_string(), "FILE:/tmp/cc".to_string())]
        );
    }

    #[test]
    fn missing_euid_is_fatal() {
        let err = Config::parse_str("[service/x]\nmechs = krb5\n", SOCK).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn missing_mechs_is_fatal() {
        let err = Config::parse_str("[service/x]\neuid = 0\n", SOCK).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn no_services_is_fatal() {
        let err = Config::parse_str("[gssproxy]\ndebug = true\n", SOCK).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn cred_usage_and_flags() {
        let cfg = Config::parse_str(
            "[service/x]\n\
             mechs = krb5\n\
             euid = 1000\n\
             cred_usage = initiate\n\
             filter_flags = +MUTUAL_AUTH, -DELEGATE\n\
             enforce_flags = +CONFIDENTIALITY\n",
            SOCK,
        )
        .unwrap();
        let svc = &cfg.services[0];
        assert_eq!(svc.cred_usage, GSS_C_INITIATE);
        // default DELEG removed, MUTUAL added.
        assert_eq!(svc.filter_flags, 0x02);
        assert_eq!(svc.enforce_flags, 0x10);
    }

    #[test]
    fn duplicate_euid_socket_program_is_fatal() {
        let err = Config::parse_str(
            "[service/a]\nmechs = krb5\neuid = 0\n\
             [service/b]\nmechs = krb5\neuid = 0\n",
            SOCK,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn distinct_euid_ok_and_matches() {
        let cfg = Config::parse_str(
            "[service/a]\nmechs = krb5\neuid = 0\n\
             [service/b]\nmechs = krb5\neuid = 1000\n",
            SOCK,
        )
        .unwrap();
        assert_eq!(cfg.services.len(), 2);
        assert_eq!(cfg.match_service(1000, SOCK, None).unwrap().name, "b");
        assert_eq!(cfg.match_service(0, SOCK, None).unwrap().name, "a");
        assert!(cfg.match_service(42, SOCK, None).is_none());
    }

    #[test]
    fn any_uid_matches_anyone() {
        let cfg = Config::parse_str(
            "[service/any]\nmechs = krb5\neuid = 0\nallow_any_uid = yes\n",
            SOCK,
        )
        .unwrap();
        assert_eq!(cfg.match_service(12345, SOCK, None).unwrap().name, "any");
    }

    #[test]
    fn service_without_mechs_token_is_ignored() {
        // A mechs value with no recognized token yields no services -> fatal.
        let err = Config::parse_str("[service/x]\neuid = 0\nmechs = bogus\n", SOCK).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[test]
    fn relative_program_is_fatal() {
        let err = Config::parse_str(
            "[service/x]\nmechs = krb5\neuid = 0\nprogram = relative/path\n",
            SOCK,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }
}
