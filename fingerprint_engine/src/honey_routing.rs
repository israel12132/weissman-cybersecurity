//! Honey-routing fabric — classify inbound probes and extract MITRE TTPs.
//!
//! Dedicated decoy paths always enter Deception-Active Mode. Unauthenticated
//! lure/scanner probes are diverted instead of a standard 401. Legitimate JWT
//! sessions and public routes are never trapped.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const ENGINE_ID: &str = "honey_routing_gateway";
pub const FAIR_ARO_FLOOR: f64 = 3.0;
pub const SOAR_COOLDOWN_SECS: i64 = 3600;
/// CVSS 7.2 / 10 — typical “worked for it” chain, not a golden 0.15 path.
pub const HONEY_CVSS_EQUIV: f64 = 7.2;
pub const CONF_PASSIVE: u8 = 40;
pub const CONF_ENUMERATION: u8 = 75;
pub const CONF_ACTIVE: u8 = 100;

/// High-fidelity decoy surfaces (architecture §3).
pub const DECOY_ADMIN: &str = "/api/v1/auth/admin";
pub const DECOY_SHELL: &str = "/api/v1/debug/shell";
pub const DECOY_CONSOLE: &str = "/api/v1/internal/console";
pub const DECOY_VIP: &str = "/api/v1/internal/vip";
pub const DECOY_FINGERPRINT: &str = "/api/v1/auth/admin/fingerprint";

const DECOY_EXACT: &[&str] = &[
    DECOY_ADMIN,
    DECOY_SHELL,
    DECOY_CONSOLE,
    DECOY_VIP,
    DECOY_FINGERPRINT,
];

const LURE_PREFIXES: &[&str] = &[
    "/admin",
    "/administrator",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/console",
    "/debug",
    "/internal",
    "/.git",
    "/.env",
    "/actuator",
    "/cgi-bin",
    "/manager/html",
    "/server-status",
    "/xmlrpc.php",
];

const SCANNER_UA: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "nuclei",
    "dirbuster",
    "gobuster",
    "feroxbuster",
    "ffuf",
    "wfuzz",
    "wpscan",
    "nessus",
    "openvas",
    "burpsuite",
    "burp",
    "zgrab",
    "httpx",
    "acunetix",
    "appscan",
    "w3af",
    "havij",
    "sqlninja",
    "metasploit",
    "libwww-perl",
    "python-requests",
    "go-http-client",
    "java/",
    "zaproxy",
    "nessus",
];

const EXPLOIT_NEEDLES: &[&str] = &[
    "../",
    "..\\",
    "%2e%2e",
    "/etc/passwd",
    "/etc/shadow",
    "wp-config",
    "php://",
    "union select",
    "' or",
    "or 1=1",
    "or '1'='1",
    "<script",
    "${jndi",
    "/proc/self",
    "win.ini",
    "boot.ini",
    "%00",
    "cmd.exe",
    "powershell",
    "/bin/sh",
    "wget ",
    "curl ",
    "{{",
    "${7*7}",
];

const LATERAL_NEEDLES: &[&str] = &[
    "psexec",
    "wmiexec",
    "smbexec",
    "atexec",
    "crackmapexec",
    "impacket",
    "evil-winrm",
    "winrm",
    "xfreerdp",
    "chisel",
    "ligolo",
    "proxychains",
    "/dev/tcp",
    "bash -i",
    "nc -e",
    "ncat -e",
    "socat tcp",
    "masscan",
    "rustscan",
    "bloodhound",
    "mimikatz",
    "secretsdump",
];

/// Paths that must never enter the honeynet (real product surface).
pub fn is_honey_bypass_path(method: &str, path: &str) -> bool {
    let p = normalize_path(path);
    if p.starts_with("/command-center")
        || p.starts_with("/ws/")
        || p.starts_with("/api/honey-routing")
        || p.starts_with("/api/auth/")
        || p.starts_with("/api/v1/alerts/")
    {
        return true;
    }
    matches!(
        (method.to_ascii_uppercase().as_str(), p.as_str()),
        ("GET", "/api/health")
            | ("GET", "/api/metrics")
            | ("GET", "/status")
            | ("POST", "/api/login")
            | ("POST", "/api/logout")
            | ("POST", "/api/auth/refresh")
            | ("OPTIONS", _)
    )
}

#[must_use]
pub fn is_decoy_path(path: &str) -> bool {
    let p = normalize_path(path);
    DECOY_EXACT
        .iter()
        .any(|d| p == *d || p.starts_with(&format!("{d}/")))
}

#[must_use]
pub fn is_lure_path(path: &str) -> bool {
    if is_decoy_path(path) {
        return true;
    }
    let p = normalize_path(path);
    if p.starts_with("/api/v1/") && !p.starts_with("/api/v1/alerts/") {
        return true;
    }
    LURE_PREFIXES.iter().any(|pfx| {
        p == *pfx || p.starts_with(&format!("{pfx}/")) || p.starts_with(&format!("{pfx}?"))
    })
}

#[must_use]
pub fn decoy_kind(path: &str) -> &'static str {
    let p = normalize_path(path);
    if p.starts_with(DECOY_SHELL) {
        "debug_shell"
    } else if p.starts_with(DECOY_FINGERPRINT) {
        "browser_profile"
    } else if p.starts_with(DECOY_ADMIN)
        || p.starts_with(DECOY_CONSOLE)
        || p.starts_with(DECOY_VIP)
        || is_lure_path(&p)
    {
        "admin_portal"
    } else {
        "http"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneyHit {
    pub method: String,
    pub path: String,
    pub query: String,
    pub source_ip: String,
    pub user_agent: String,
    pub host: String,
    pub body: String,
    pub headers: Value,
    #[serde(default = "empty_json_object")]
    pub tls: Value,
}

fn empty_json_object() -> Value {
    json!({})
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneyDecision {
    pub intercept: bool,
    pub confidence: u8,
    pub high_confidence: bool,
    pub lateral_attempt: bool,
    pub scanner_signals: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub decoy_kind: String,
    pub session_fp: String,
}

impl HoneyDecision {
    #[must_use]
    pub fn should_intercept_unauthenticated(&self) -> bool {
        self.intercept
    }
}

/// Classify a request. `authenticated` true means a valid user JWT — never trap
/// those except on dedicated decoy paths (those URLs are not real APIs).
#[must_use]
pub fn classify(hit: &HoneyHit, authenticated: bool) -> HoneyDecision {
    let mut signals = Vec::new();
    let mut techniques = Vec::new();

    let decoy = is_decoy_path(&hit.path);
    let lure = is_lure_path(&hit.path);
    let ua_l = hit.user_agent.to_ascii_lowercase();
    let hay = format!(
        "{} {} {} {}",
        hit.path,
        hit.query,
        hit.body.to_ascii_lowercase(),
        ua_l
    );

    if decoy {
        signals.push("decoy_path".into());
        techniques.push("T1190".into());
    } else if lure {
        signals.push("lure_path".into());
        techniques.push("T1190".into());
    }

    for needle in SCANNER_UA {
        if ua_l.contains(needle) {
            signals.push(format!("scanner_ua:{needle}"));
            techniques.push("T1595".into());
            break;
        }
    }

    let mut exploit = false;
    for needle in EXPLOIT_NEEDLES {
        if hay.to_ascii_lowercase().contains(needle) {
            exploit = true;
            signals.push(format!("exploit:{needle}"));
            techniques.push("T1190".into());
            techniques.push("T1059".into());
            break;
        }
    }

    let shell_cmd = extract_shell_command(hit);
    let lateral = shell_cmd
        .as_deref()
        .map(is_lateral_movement)
        .unwrap_or(false);
    if shell_cmd.is_some() {
        signals.push("debug_shell_command".into());
        techniques.push("T1059".into());
        techniques.push("T1059.004".into());
    }
    if lateral {
        signals.push("lateral_movement".into());
        techniques.push("T1021".into());
        techniques.push("T1021.002".into());
    }

    if hit.path.starts_with(DECOY_ADMIN) && hit.method.eq_ignore_ascii_case("POST") {
        signals.push("admin_credential_probe".into());
        techniques.push("T1110".into());
        techniques.push("T1078".into());
    }

    if decoy && hit.method.eq_ignore_ascii_case("GET") {
        techniques.push("T1595.002".into());
    }

    techniques.sort();
    techniques.dedup();
    signals.sort();
    signals.dedup();

    let active_payload = exploit || shell_cmd.is_some();
    let confidence = if active_payload {
        CONF_ACTIVE
    } else {
        CONF_PASSIVE
    };
    let intercept = if authenticated { decoy } else { decoy || lure };

    HoneyDecision {
        intercept,
        confidence,
        high_confidence: confidence >= CONF_ACTIVE,
        lateral_attempt: lateral,
        scanner_signals: signals,
        mitre_techniques: techniques,
        decoy_kind: decoy_kind(&hit.path).to_string(),
        session_fp: session_fingerprint(&hit.source_ip, &hit.user_agent),
    }
}

#[must_use]
pub fn extract_shell_command(hit: &HoneyHit) -> Option<String> {
    if !normalize_path(&hit.path).starts_with(DECOY_SHELL) {
        return None;
    }
    if hit.method.eq_ignore_ascii_case("GET") && hit.body.trim().is_empty() {
        return None;
    }
    if let Ok(v) = serde_json::from_str::<Value>(&hit.body) {
        for key in ["cmd", "command", "exec", "input", "shell"] {
            if let Some(s) = v.get(key).and_then(Value::as_str) {
                let t = s.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
    }
    let t = hit.body.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.chars().take(512).collect())
    }
}

#[must_use]
pub fn is_lateral_movement(cmd: &str) -> bool {
    let c = cmd.to_ascii_lowercase();
    if LATERAL_NEEDLES.iter().any(|k| c.contains(k)) {
        return true;
    }
    let sshish =
        c.contains("ssh ") || c.starts_with("ssh") || c.contains(" scp ") || c.contains("nmap ");
    let rfc1918 = c.contains("10.")
        || c.contains("192.168.")
        || c.contains("172.16.")
        || c.contains("172.17.")
        || c.contains("172.18.")
        || c.contains("172.19.")
        || c.contains("172.20.");
    sshish && rfc1918
}

#[must_use]
pub fn session_fingerprint(ip: &str, ua: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ip.trim().as_bytes());
    h.update(b"|");
    h.update(ua.trim().as_bytes());
    hex::encode(h.finalize())
}

#[must_use]
pub fn normalize_path(path: &str) -> String {
    let p = path.split('?').next().unwrap_or(path).trim();
    let p = p.trim_end_matches('/');
    if p.is_empty() {
        "/".to_string()
    } else {
        p.to_string()
    }
}

#[must_use]
pub fn truncate_body(body: &str, max: usize) -> String {
    if body.len() <= max {
        body.to_string()
    } else {
        let mut s: String = body.chars().take(max).collect();
        s.push('…');
        s
    }
}

#[must_use]
pub fn honey_edge_weight(confidence: u8) -> f64 {
    // CVSS 7.2-shaped cost: slightly easier than a clean edge, never a 0.15 golden path.
    let base = HONEY_CVSS_EQUIV / 10.0;
    let spread = (f64::from(confidence) - 50.0) * 0.0008;
    (base + spread).clamp(0.64, 0.80)
}

#[must_use]
pub fn escalate_confidence(current: u8, distinct_paths: i64) -> u8 {
    if current >= CONF_ACTIVE {
        CONF_ACTIVE
    } else if distinct_paths >= 3 {
        current.max(CONF_ENUMERATION)
    } else {
        current
    }
}

/// Fair ARO used when a live honey-route session is open for the client.
#[must_use]
pub fn fair_aro_floor() -> f64 {
    std::env::var("WEISSMAN_HONEY_ROUTE_FAIR_ARO_FLOOR")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(FAIR_ARO_FLOOR)
}

#[must_use]
pub fn auto_soar_enabled() -> bool {
    if weissman_core::tls_policy::is_production_environment() {
        return false;
    }
    matches!(
        std::env::var("WEISSMAN_HONEY_ROUTE_AUTO_SOAR").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

pub fn decision_metadata(hit: &HoneyHit, decision: &HoneyDecision) -> Value {
    json!({
        "engine": ENGINE_ID,
        "decoy_kind": decision.decoy_kind,
        "host": hit.host,
        "method": hit.method,
        "path": hit.path,
        "confidence": decision.confidence,
        "high_confidence": decision.high_confidence,
        "lateral_attempt": decision.lateral_attempt,
        "scanner_signals": decision.scanner_signals,
        "mitre_techniques": decision.mitre_techniques,
        "tls": hit.tls,
        "honey_weight": honey_edge_weight(decision.confidence),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(method: &str, path: &str, ua: &str, body: &str) -> HoneyHit {
        HoneyHit {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            source_ip: "198.51.100.44".into(),
            user_agent: ua.into(),
            host: "gateway.example".into(),
            body: body.into(),
            headers: json!({}),
            tls: json!({}),
        }
    }

    #[test]
    fn legitimate_api_is_not_a_lure() {
        assert!(!is_lure_path("/api/findings"));
        assert!(!is_lure_path("/api/clients"));
        assert!(!is_decoy_path("/api/login"));
        assert!(is_honey_bypass_path("POST", "/api/login"));
        assert!(is_honey_bypass_path("GET", "/api/v1/alerts/aws-canary"));
    }

    #[test]
    fn decoy_paths_are_intercepted() {
        assert!(is_decoy_path("/api/v1/auth/admin"));
        assert!(is_decoy_path("/api/v1/debug/shell/"));
        let d = classify(&hit("GET", "/api/v1/auth/admin", "Mozilla/5.0", ""), false);
        assert!(d.intercept);
        assert_eq!(d.confidence, CONF_PASSIVE);
        assert!(!d.high_confidence);
    }

    #[test]
    fn authenticated_users_are_not_trapped_on_real_apis() {
        let d = classify(&hit("GET", "/api/findings", "Mozilla/5.0", ""), true);
        assert!(!d.intercept);
    }

    #[test]
    fn sqlmap_on_lure_is_high_signal() {
        let d = classify(&hit("GET", "/admin", "sqlmap/1.7.2", "' OR 1=1--"), false);
        assert!(d.intercept);
        assert!(d.scanner_signals.iter().any(|s| s.contains("sqlmap")));
        assert_eq!(d.confidence, CONF_ACTIVE);
        assert!(d.high_confidence);
        assert!(d.mitre_techniques.iter().any(|t| t.starts_with('T')));
    }

    #[test]
    fn shell_lateral_ssh_is_detected() {
        let body = r#"{"cmd":"ssh root@10.0.0.12"}"#;
        let d = classify(
            &hit("POST", "/api/v1/debug/shell", "curl/8.5.0", body),
            false,
        );
        assert!(d.intercept);
        assert!(d.lateral_attempt);
        assert!(d.high_confidence);
        assert!(d.mitre_techniques.iter().any(|t| t == "T1021"));
    }

    #[test]
    fn session_fingerprint_is_stable() {
        assert_eq!(
            session_fingerprint("1.2.3.4", "ua"),
            session_fingerprint("1.2.3.4", "ua")
        );
        assert_ne!(
            session_fingerprint("1.2.3.4", "ua"),
            session_fingerprint("1.2.3.5", "ua")
        );
    }

    #[test]
    fn enumeration_escalates_to_75_not_100() {
        assert_eq!(escalate_confidence(40, 1), 40);
        assert_eq!(escalate_confidence(40, 3), 75);
        assert_eq!(escalate_confidence(100, 1), 100);
    }

    #[test]
    fn honey_weight_is_cvss72_not_golden() {
        let w = honey_edge_weight(40);
        assert!(w > 0.60 && w < 0.85);
        assert!(w > 0.15);
        assert!((w - 0.72).abs() < 0.03);
        let hot = honey_edge_weight(100);
        assert!((0.64..=0.80).contains(&hot));
    }
}
