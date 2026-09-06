//! Honey-routing fabric — classify inbound probes and extract MITRE TTPs.
//!
//! Dedicated decoy paths always enter Deception-Active Mode. Unauthenticated
//! lure/scanner probes are diverted instead of a standard 401. Legitimate JWT
//! sessions and public routes are never trapped.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

pub const ENGINE_ID: &str = "honey_routing_gateway";
pub const FAIR_ARO_FLOOR: f64 = 3.0;
pub const SOAR_COOLDOWN_SECS: i64 = 3600;
/// Prior mean CVSS when the client has no live KEV/EPSS yet (not a clamp band).
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

/// Live CISA KEV + EPSS moments from the client's real findings (same tenant subnet).
#[derive(Debug, Clone)]
pub struct LiveKevEpssStats {
    pub n: usize,
    pub severity_mean: f64,
    pub severity_std: f64,
    pub cost_mean: f64,
    pub cost_std: f64,
    pub source: &'static str,
}

impl Default for LiveKevEpssStats {
    fn default() -> Self {
        // Wide enterprise prior (CVSS ~N(5.8, 2.4) → costs spanning ~0.15–2.0), never a 0.72 band.
        Self {
            n: 0,
            severity_mean: 5.8,
            severity_std: 2.4,
            cost_mean: 0.85,
            cost_std: 0.45,
            source: "wide_prior",
        }
    }
}

/// Map a live finding to the same pivot **cost** Dijkstra uses (`1 / score`).
#[must_use]
pub fn pivot_cost_from_intel(cvss: f64, epss: f64, kev: bool) -> f64 {
    let mut score: f64 = 0.5 + (cvss.clamp(0.0, 10.0) / 10.0);
    score *= 1.0 + epss.clamp(0.0, 1.0) * 1.5;
    if kev {
        score *= 2.0;
    }
    1.0 / score.max(0.05)
}

#[must_use]
pub fn severity_from_intel(cvss: f64, epss: f64, kev: bool) -> f64 {
    let mut s = cvss.clamp(0.0, 10.0);
    s *= 1.0 + epss.clamp(0.0, 1.0) * 0.5;
    if kev {
        s = (s * 1.15).max(8.5).min(10.0);
    }
    s.clamp(1.0, 10.0)
}

fn moments(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    if xs.len() < 2 {
        return (mean, 0.0);
    }
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    (mean, var.sqrt())
}

fn stats_from_rows(rows: &[(f64, f64, bool)], source: &'static str) -> LiveKevEpssStats {
    let costs: Vec<f64> = rows
        .iter()
        .map(|(c, e, k)| pivot_cost_from_intel(*c, *e, *k))
        .collect();
    let sevs: Vec<f64> = rows
        .iter()
        .map(|(c, e, k)| severity_from_intel(*c, *e, *k))
        .collect();
    let (cost_mean, cost_std) = moments(&costs);
    let (severity_mean, severity_std) = moments(&sevs);
    LiveKevEpssStats {
        n: rows.len(),
        severity_mean,
        severity_std: severity_std.max(0.4),
        cost_mean,
        cost_std: cost_std.max(0.05),
        source,
    }
}

/// Load live KEV/EPSS of the client's findings. Catalog intel is the fallback when
/// the subnet has no scored vulns yet — never a hardcoded 0.64–0.80 band.
pub async fn load_live_kev_epss_stats(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    source_ip: &str,
) -> LiveKevEpssStats {
    let prefix = v4_slash24_prefix(source_ip);
    if let Ok(rows) = fetch_client_intel(pool, tenant_id, client_id, prefix.as_deref()).await {
        if rows.len() >= 8 {
            return stats_from_rows(&rows, "client_subnet_kev_epss");
        }
        if !rows.is_empty() {
            if let Ok(all) = fetch_client_intel(pool, tenant_id, client_id, None).await {
                if all.len() >= rows.len() {
                    return stats_from_rows(&all, "client_kev_epss");
                }
            }
            return stats_from_rows(&rows, "client_kev_epss");
        }
    }
    if let Ok(cat) = fetch_catalog_intel(pool).await {
        if cat.len() >= 8 {
            return stats_from_rows(&cat, "catalog_kev_epss");
        }
    }
    LiveKevEpssStats::default()
}

fn v4_slash24_prefix(ip: &str) -> Option<String> {
    let ip = ip.split('%').next().unwrap_or(ip).trim();
    let ip = ip.split(':').next().unwrap_or(ip);
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    if parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        Some(format!("{}.{}.{}.", parts[0], parts[1], parts[2]))
    } else {
        None
    }
}

async fn fetch_client_intel(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    subnet_prefix: Option<&str>,
) -> Result<Vec<(f64, f64, bool)>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let prefix = subnet_prefix.unwrap_or("");
    let rows = sqlx::query(
        r#"SELECT
                COALESCE(
                    NULLIF((raw_data->>'cvss_score')::float, 0),
                    CASE lower(severity)
                        WHEN 'critical' THEN 9.5
                        WHEN 'high' THEN 7.5
                        WHEN 'medium' THEN 5.5
                        WHEN 'low' THEN 3.0
                        ELSE 5.0
                    END
                ) AS cvss,
                COALESCE(epss_score, 0)::float8 AS epss,
                COALESCE(kev_listed, false) AS kev
           FROM vulnerabilities
          WHERE tenant_id = $1 AND client_id = $2
            AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE')
            AND (
                $3 = ''
                OR COALESCE(raw_data->>'ip', raw_data->>'host', raw_data->>'target', '')
                   LIKE $3 || '%'
            )
          ORDER BY discovered_at DESC NULLS LAST
          LIMIT 800"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(prefix)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                f64_col(&r, "cvss").unwrap_or(5.0),
                f64_col(&r, "epss").unwrap_or(0.0),
                r.try_get::<bool, _>("kev").unwrap_or(false),
            )
        })
        .collect())
}

fn f64_col(r: &sqlx::postgres::PgRow, name: &str) -> Option<f64> {
    r.try_get::<f64, _>(name)
        .ok()
        .or_else(|| r.try_get::<f32, _>(name).ok().map(|v| f64::from(v)))
}

async fn fetch_catalog_intel(pool: &sqlx::PgPool) -> Result<Vec<(f64, f64, bool)>, sqlx::Error> {
    // Live CISA KEV + FIRST EPSS mirrors — not invented scores.
    let rows = sqlx::query(
        r#"SELECT e.score::float8 AS epss,
                  (k.cve IS NOT NULL) AS kev
             FROM epss_intel e
             LEFT JOIN kev_intel k ON k.cve = e.cve
            ORDER BY e.refreshed_at DESC NULLS LAST
            LIMIT 2000"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let epss = f64_col(&r, "epss").unwrap_or(0.0);
            let kev = r.try_get::<bool, _>("kev").unwrap_or(false);
            let cvss = if kev { 9.0 } else { 4.0 + epss * 6.0 };
            (cvss, epss, kev)
        })
        .collect())
}

#[derive(Debug, Clone)]
pub struct HoneyWeightSample {
    pub honey_weight: f64,
    pub honey_edge_cost: f64,
    pub cvss_equivalent: f64,
    pub source: &'static str,
    pub live_n: usize,
}

/// Sample Dijkstra cost from the live KEV/EPSS Gaussian (wide spectrum, no 0.64–0.80 clamp).
#[must_use]
pub fn sample_honey_weight(
    confidence: u8,
    stats: &LiveKevEpssStats,
    session_fp: &str,
    decoy_kind: &str,
) -> HoneyWeightSample {
    let seed = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(session_fp.as_bytes());
        h.update(b"|");
        h.update(decoy_kind.as_bytes());
        h.update(b"|");
        h.update([confidence]);
        u64::from_le_bytes(h.finalize()[..8].try_into().unwrap_or([0; 8]))
    };
    let sev = crate::gaussian::sample_normal_seeded(
        stats.severity_mean,
        stats.severity_std.max(0.4),
        seed,
    )
    .clamp(1.0, 10.0);
    let cost = crate::gaussian::sample_normal_seeded(
        stats.cost_mean,
        stats.cost_std.max(0.05),
        seed ^ 0xA5A5_A5A5_A5A5_A5A5,
    )
    .clamp(0.05, 10.0);
    // Multiplier vs a clean edge (~cost 1.0): spread across real enterprise graphs.
    let honey_weight = (cost / stats.cost_mean.max(0.2)).clamp(0.05, 10.0);
    HoneyWeightSample {
        honey_weight,
        honey_edge_cost: cost,
        cvss_equivalent: sev,
        source: stats.source,
        live_n: stats.n,
    }
}

/// Unseeded sample for dashboards / tests (wide prior, not a 0.72 fingerprint).
#[must_use]
pub fn honey_edge_weight(confidence: u8) -> f64 {
    sample_honey_weight(confidence, &LiveKevEpssStats::default(), "dash", "decoy").honey_weight
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
    fn honey_weight_is_not_a_homogeneous_band() {
        let stats = LiveKevEpssStats {
            n: 40,
            severity_mean: 6.1,
            severity_std: 2.2,
            cost_mean: 0.9,
            cost_std: 0.5,
            source: "test",
        };
        let mut weights = Vec::new();
        for i in 0..40 {
            let s = sample_honey_weight(40, &stats, &format!("fp-{i}"), "admin_portal");
            weights.push(s.honey_edge_cost);
            assert!(s.honey_edge_cost >= 0.05 && s.honey_edge_cost <= 10.0);
            assert!(s.cvss_equivalent >= 1.0 && s.cvss_equivalent <= 10.0);
        }
        let min = weights.iter().copied().fold(f64::INFINITY, f64::min);
        let max = weights.iter().copied().fold(0.0_f64, f64::max);
        assert!(
            (max - min) > 0.15,
            "costs still clustered: min={min} max={max}"
        );
        let in_old_band = weights
            .iter()
            .filter(|w| **w >= 0.64 && **w <= 0.80)
            .count();
        assert!(
            in_old_band < weights.len(),
            "all samples fell in the old 0.64–0.80 fingerprint band"
        );
        // Same attacker+decoy is stable (no per-hit jitter fingerprint).
        let a = sample_honey_weight(100, &stats, "same", "shell");
        let b = sample_honey_weight(100, &stats, "same", "shell");
        assert!((a.honey_edge_cost - b.honey_edge_cost).abs() < 1e-12);
    }
}
