//! Stable finding identity — hard de-duplication for SOC alert-fatigue control.
//!
//! Every persist path (worker + in-process) must hash the **same normalised
//! invariants**. Volatile fields (timestamps, evidence bodies, ephemeral ports,
//! query-string session tokens, UUID path segments) are stripped so an identical
//! vulnerability re-detected on a rescan lands on the same `finding_id` /
//! `cluster_key` instead of minting a duplicate ticket.
//!
//! Cluster identity intentionally **excludes** `engine` so network and agent
//! planes that fire on the same (target, signature, CWE) collapse into one card.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use regex::Regex;
use weissman_core::models::engine::resolve_engine_id;
use weissman_core::models::engine_agent::is_agent_required_engine;

/// IANA / Linux ephemeral port range. Service ports below this (8080, 8443, 3000)
/// identify a real listener and MUST stay in the identity.
const EPHEMERAL_PORT_MIN: u16 = 32768;

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").expect("uuid")
});
static ISO_TS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\d{4}-\d{2}-\d{2}[tT ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|Z|[+-]\d{2}:?\d{2})?")
        .expect("ts")
});
static LONG_HEX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{16,}\b").expect("hex"));
static MATRIX_PARAM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r";[a-zA-Z][\w-]*=[^;/?#]*").expect("matrix"));
static SESSION_KV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:jsessionid|session(?:id)?|sid|token|nonce|request[_-]?id|trace[_-]?id|span[_-]?id)\s*[:=]\s*\S+")
        .expect("sess")
});
static PORT_WORD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bport\s+(\d{4,5})\b").expect("port-word"));

/// True when `port` is an OS-allocated ephemeral / dynamic port, not a service port.
#[must_use]
pub fn is_ephemeral_port(port: u16) -> bool {
    port >= EPHEMERAL_PORT_MIN
}

/// Lower-case host, strip query / fragment / userinfo / default + ephemeral ports,
/// replace UUID / long-hex / numeric id path segments with `{id}`.
#[must_use]
pub fn normalize_target(raw: &str) -> String {
    let mut s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return s;
    }
    if let Some(i) = s.find('#') {
        s.truncate(i);
    }
    if let Some(i) = s.find('?') {
        s.truncate(i);
    }
    s = MATRIX_PARAM_RE.replace_all(&s, "").into_owned();

    let (scheme, rest) = split_scheme(&s);
    let rest = strip_userinfo(rest);
    let (authority, path) = split_authority_path(rest);
    let authority = strip_target_port(authority, scheme);
    let path = normalize_path_ids(path);
    let path = path.trim_end_matches('/');

    let mut out = String::new();
    if !scheme.is_empty() {
        out.push_str(scheme);
        out.push_str("://");
    }
    out.push_str(&authority);
    if !path.is_empty() {
        if !path.starts_with('/') && !authority.is_empty() {
            out.push('/');
        }
        out.push_str(path);
    }
    out.trim_end_matches('/').to_string()
}

fn split_scheme(s: &str) -> (&str, &str) {
    if let Some(i) = s.find("://") {
        (&s[..i], &s[i + 3..])
    } else {
        ("", s)
    }
}

fn strip_userinfo(rest: &str) -> &str {
    // user:pass@host — only when @ sits in the authority (before first /).
    let auth_end = rest.find('/').unwrap_or(rest.len());
    let auth = &rest[..auth_end];
    if let Some(at) = auth.rfind('@') {
        &rest[at + 1..]
    } else {
        rest
    }
}

fn split_authority_path(rest: &str) -> (&str, &str) {
    if rest.starts_with('[') {
        // IPv6 literal
        if let Some(end) = rest.find(']') {
            let after = end + 1;
            if after < rest.len() && rest.as_bytes()[after] == b':' {
                // [v6]:port/path
                let port_end = rest[after + 1..]
                    .find('/')
                    .map(|i| after + 1 + i)
                    .unwrap_or(rest.len());
                return (&rest[..port_end], &rest[port_end..]);
            }
            return (&rest[..after], &rest[after..]);
        }
    }
    match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    }
}

fn strip_target_port(authority: &str, scheme: &str) -> String {
    let (host, port) = split_host_port(authority);
    let Some(p) = port else {
        return host.to_string();
    };
    let default = matches!(
        (scheme, p),
        ("https", 443) | ("http", 80) | ("wss", 443) | ("ws", 80)
    );
    if default || is_ephemeral_port(p) {
        host.to_string()
    } else {
        format!("{host}:{p}")
    }
}

fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    if authority.starts_with('[') {
        if let Some(end) = authority.find(']') {
            let host = &authority[..=end];
            let rest = &authority[end + 1..];
            if let Some(p) = rest.strip_prefix(':') {
                return (host, p.parse().ok());
            }
            return (host, None);
        }
    }
    if let Some(colon) = authority.rfind(':') {
        // Avoid treating the colon in an unbracketed IPv6 as a port.
        if authority.matches(':').count() == 1 {
            let host = &authority[..colon];
            let port = authority[colon + 1..].parse().ok();
            return (host, port);
        }
    }
    (authority, None)
}

fn normalize_path_ids(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let s = UUID_RE.replace_all(path, "{id}");
    let s = LONG_HEX_RE.replace_all(&s, "{id}");
    // Replace numeric path segments of 4+ digits (`/orders/12345` → `/orders/{id}`).
    // The `regex` crate has no look-around, so we split on `/` instead of a lookahead.
    let mut out = String::with_capacity(s.len());
    for (i, seg) in s.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if seg.len() >= 4 && seg.bytes().all(|b| b.is_ascii_digit()) {
            out.push_str("{id}");
        } else {
            out.push_str(seg);
        }
    }
    out
}

/// Uniform, filtered signature: lowercase, strip query/fragment, ephemeral ports,
/// session tokens, UUIDs, timestamps. Two probes of the same vuln with different
/// `?sid=` or `:54321` must hash identically.
#[must_use]
pub fn normalize_signature(raw: &str) -> String {
    let mut s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return s;
    }
    if let Some(i) = s.find('#') {
        s.truncate(i);
    }
    if let Some(i) = s.find('?') {
        s.truncate(i);
    }
    s = MATRIX_PARAM_RE.replace_all(&s, "").into_owned();
    s = SESSION_KV_RE.replace_all(&s, "").into_owned();
    s = UUID_RE.replace_all(&s, "{id}").into_owned();
    s = ISO_TS_RE.replace_all(&s, "{ts}").into_owned();
    s = LONG_HEX_RE.replace_all(&s, "{id}").into_owned();
    s = PORT_WORD_RE
        .replace_all(&s, |caps: &regex::Captures| {
            let p: u16 = caps
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            if is_ephemeral_port(p) {
                "port {ephemeral}".to_string()
            } else {
                caps.get(0)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default()
            }
        })
        .into_owned();
    s = strip_colon_ephemeral_ports(&s);
    collapse_ws(&s)
}

fn strip_colon_ephemeral_ports(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let num = &s[i + 1..j];
            if let Ok(p) = num.parse::<u16>() {
                if is_ephemeral_port(p) {
                    i = j;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[must_use]
pub fn normalize_cwe(raw: &str) -> String {
    let s = raw.trim().to_ascii_uppercase().replace(' ', "");
    if s.is_empty() {
        return s;
    }
    if let Some(rest) = s.strip_prefix("CWE-") {
        return format!("CWE-{rest}");
    }
    if let Some(rest) = s.strip_prefix("CWE") {
        if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return format!("CWE-{rest}");
        }
    }
    if s.chars().all(|c| c.is_ascii_digit() || c == '-') {
        let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            return format!("CWE-{digits}");
        }
    }
    s
}

#[must_use]
pub fn normalize_cve(raw: &str) -> String {
    raw.trim().to_ascii_uppercase()
}

#[must_use]
pub fn normalize_mitre(raw: &str) -> String {
    raw.trim().to_ascii_uppercase().replace(' ', "")
}

/// "What" of the issue — NOT the "where" (target stays a separate identity field).
///
/// Priority: explicit signature / rule_id / vuln_signature / rule → type → CVE → title.
#[must_use]
pub fn derive_vuln_signature(finding: &Value, fallback_title: &str) -> String {
    for k in ["signature", "rule_id", "vuln_signature", "rule"] {
        if let Some(s) = finding.get(k).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return normalize_signature(t);
            }
        }
    }
    if let Some(t) = finding.get("type").and_then(Value::as_str) {
        let s = t.trim();
        if !s.is_empty() {
            return normalize_signature(s);
        }
    }
    for k in ["cve", "cve_id"] {
        if let Some(c) = finding.get(k).and_then(Value::as_str) {
            let s = c.trim();
            if !s.is_empty() {
                return normalize_cve(s);
            }
        }
    }
    let title: String = fallback_title.chars().take(80).collect();
    normalize_signature(&title)
}

/// Cluster identity: sha256(normalised_target | normalised_signature | normalised_cwe).
/// Engine is excluded so independent detectors of the same vuln share one cluster.
#[must_use]
pub fn build_cluster_key(target: &str, vuln_signature: &str, cwe: &str) -> String {
    let target_norm = normalize_target(target);
    let sig_norm = normalize_signature(vuln_signature);
    let cwe_norm = normalize_cwe(cwe);
    let mut h = Sha256::new();
    h.update(target_norm.as_bytes());
    h.update(b"|");
    h.update(sig_norm.as_bytes());
    h.update(b"|");
    h.update(cwe_norm.as_bytes());
    hex::encode(h.finalize())
}

/// Stable `vulnerabilities.finding_id`: `{engine}-{sha256[:12]}` of
/// `engine | target | cve | cwe | mitre | signature` (title only when signature is empty).
#[must_use]
pub fn build_stable_finding_id(engine: &str, target: &str, finding: &Value) -> String {
    let cve = crate::intel_findings_backfill::extract_cve_from_value(finding).unwrap_or_default();
    let cwe = finding
        .get("cwe")
        .or_else(|| finding.get("cwe_id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let mitre = finding
        .get("mitre_attack")
        .or_else(|| finding.get("mitre"))
        .or_else(|| finding.get("attack_id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let title = extract_title(finding, engine);
    let signature = derive_vuln_signature(finding, &title);

    let mut hasher = Sha256::new();
    hasher.update(engine.trim().as_bytes());
    hasher.update(b"|");
    hasher.update(normalize_target(target).as_bytes());
    hasher.update(b"|");
    hasher.update(normalize_cve(&cve).as_bytes());
    hasher.update(b"|");
    hasher.update(normalize_cwe(cwe).as_bytes());
    hasher.update(b"|");
    hasher.update(normalize_mitre(mitre).as_bytes());
    hasher.update(b"|");
    hasher.update(signature.as_bytes());
    if signature.is_empty() {
        hasher.update(b"|");
        hasher.update(normalize_signature(&title).as_bytes());
    }
    let digest = hasher.finalize();
    let short: String = digest.iter().take(12).map(|b| format!("{b:02x}")).collect();
    format!("{engine}-{short}")
}

fn extract_title(f: &Value, engine: &str) -> String {
    for key in [
        "title", "name", "summary", "rule", "finding", "issue", "asset", "type",
    ] {
        if let Some(s) = f.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.chars().take(240).collect();
            }
        }
    }
    format!("{engine} finding")
}

/// Detection plane: host-resident agent vs remote/network probe.
#[must_use]
pub fn engine_plane(engine_id: &str) -> &'static str {
    let id = engine_id.trim();
    let canonical = resolve_engine_id(id);
    if is_agent_required_engine(id) || is_agent_required_engine(canonical) {
        "agent"
    } else {
        "network"
    }
}

/// Auto-suppressed / analyst FALSE_POSITIVE findings must not fire SOAR playbooks.
#[must_use]
pub fn should_dispatch_soar_playbooks(status: &str) -> bool {
    !status.trim().eq_ignore_ascii_case("FALSE_POSITIVE")
}

/// Result of multi-engine corroboration applied on top of native (member-max) severity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Corroboration {
    pub severity: String,
    pub native_severity: String,
    pub boost: String,
    pub engine_planes: Vec<String>,
}

/// Dynamic cluster severity:
/// * network + agent on the same (target, signature, CWE) → **critical**
/// * 3+ distinct engines → at least **high**, bumped one extra level
/// * 2 engines, same plane → bump one level
#[must_use]
pub fn corroborate_cluster_severity(native: &str, engines: &[String]) -> Corroboration {
    let native_w = sev_weight(native);
    let mut planes = std::collections::BTreeSet::<&'static str>::new();
    let mut distinct = std::collections::BTreeSet::<String>::new();
    for e in engines {
        let id = e.trim();
        if id.is_empty() {
            continue;
        }
        distinct.insert(id.to_ascii_lowercase());
        planes.insert(engine_plane(id));
    }
    let n = distinct.len();
    let has_agent = planes.contains("agent");
    let has_network = planes.contains("network");

    let (boost, boosted_w) = if has_agent && has_network {
        ("cross_plane", 5)
    } else if n >= 3 {
        ("multi_engine", native_w.max(4).min(5))
    } else if n >= 2 {
        ("multi_engine", (native_w + 1).min(5))
    } else {
        ("none", native_w)
    };
    let final_w = boosted_w.max(native_w);
    Corroboration {
        severity: weight_to_sev(final_w).to_string(),
        native_severity: canonical_sev(native).to_string(),
        boost: boost.to_string(),
        engine_planes: planes.into_iter().map(|p| p.to_string()).collect(),
    }
}

/// CVSS floor applied when corroboration raises severity (keeps inbox sort honest).
#[must_use]
pub fn corroboration_cvss_floor(boost: &str, severity: &str) -> f64 {
    match (boost, canonical_sev(severity)) {
        ("cross_plane", _) | (_, "critical") if boost != "none" => 9.0,
        ("multi_engine", "high") => 7.0,
        ("multi_engine", "medium") => 5.0,
        _ => 0.0,
    }
}

#[must_use]
pub fn sev_weight(s: &str) -> i32 {
    match canonical_sev(s) {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

#[must_use]
pub fn weight_to_sev(w: i32) -> &'static str {
    match w {
        5 => "critical",
        4 => "high",
        3 => "medium",
        2 => "low",
        1 => "info",
        _ => "info",
    }
}

fn canonical_sev(s: &str) -> &'static str {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" | "informational" => "info",
        _ => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn target_strips_query_fragment_slash_and_case() {
        let a = normalize_target("https://EXAMPLE.com/foo/");
        let b = normalize_target("https://example.com/foo?x=1");
        let c = normalize_target("https://example.com/foo#frag");
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a, "https://example.com/foo");
    }

    #[test]
    fn target_strips_ephemeral_and_default_ports_keeps_service_ports() {
        assert_eq!(
            normalize_target("https://api.example.com:443/login"),
            normalize_target("https://api.example.com/login")
        );
        assert_eq!(
            normalize_target("https://api.example.com:54321/login"),
            normalize_target("https://api.example.com/login")
        );
        assert_eq!(
            normalize_target("https://api.example.com:49152/login"),
            "https://api.example.com/login"
        );
        // 8443 is a real TLS listener — must remain distinct.
        assert_ne!(
            normalize_target("https://api.example.com:8443/login"),
            normalize_target("https://api.example.com/login")
        );
    }

    #[test]
    fn target_replaces_uuid_and_numeric_ids() {
        let a = normalize_target(
            "https://app.example.com/users/550e8400-e29b-41d4-a716-446655440000/profile",
        );
        let b = normalize_target(
            "https://app.example.com/users/99aa88bb-e29b-41d4-a716-446655440000/profile",
        );
        assert_eq!(a, b);
        assert!(a.contains("/users/{id}/profile"));
        let n = normalize_target("https://app.example.com/orders/12345");
        assert_eq!(n, "https://app.example.com/orders/{id}");
    }

    #[test]
    fn signature_strips_query_session_and_ephemeral_port() {
        let a = normalize_signature("XSS in /foo?id=1&sid=deadbeef");
        let b = normalize_signature("xss in /foo");
        assert_eq!(a, b);

        let p1 = normalize_signature("sqli /login:54321");
        let p2 = normalize_signature("SQLi /login");
        assert_eq!(p1, p2);

        let w1 = normalize_signature("open port 49152 on ssh");
        let w2 = normalize_signature("open port {ephemeral} on ssh");
        assert_eq!(w1, w2);
    }

    #[test]
    fn cluster_key_stable_across_volatile_url_and_signature() {
        let a = build_cluster_key(
            "https://EXAMPLE.com:54321/foo/?session=abc",
            "xss_reflected?token=1",
            "cwe-79",
        );
        let b = build_cluster_key("https://example.com/foo", "XSS_Reflected", "CWE-79");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn distinct_targets_or_cwes_distinct_clusters() {
        let a = build_cluster_key("https://x.com/foo", "xss_reflected", "CWE-79");
        let b = build_cluster_key("https://y.com/foo", "xss_reflected", "CWE-79");
        let c = build_cluster_key("https://x.com/foo", "xss_reflected", "CWE-89");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn finding_id_stable_across_ports_query_and_evidence() {
        let first = json!({
            "title": "SQL Injection in /login",
            "signature": "sqli?sid=aaa",
            "cve": "CVE-2021-1234",
            "cwe": "cwe-89",
            "evidence": "body A",
            "discovered_at": "2026-01-01T00:00:00Z"
        });
        let rescan = json!({
            "title": "SQL Injection in /login",
            "signature": "sqli",
            "cve": "cve-2021-1234",
            "cwe": "CWE-89",
            "evidence": "body Z",
            "discovered_at": "2026-08-27T00:00:00Z"
        });
        let id1 =
            build_stable_finding_id("sqli_engine", "https://Example.com:49152/login?x=1", &first);
        let id2 = build_stable_finding_id("sqli_engine", "https://example.com/login", &rescan);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("sqli_engine-"));
    }

    #[test]
    fn finding_id_changes_with_signature() {
        let a = json!({"title": "Issue", "signature": "sqli", "cve": "CVE-2021-1234"});
        let b = json!({"title": "Issue", "signature": "xss", "cve": "CVE-2021-1234"});
        let target = "https://example.com/login";
        assert_ne!(
            build_stable_finding_id("eng", target, &a),
            build_stable_finding_id("eng", target, &b)
        );
    }

    #[test]
    fn cwe_normalizes_forms() {
        assert_eq!(normalize_cwe("cwe-79"), "CWE-79");
        assert_eq!(normalize_cwe("CWE 79"), "CWE-79");
        assert_eq!(normalize_cwe("79"), "CWE-79");
    }

    #[test]
    fn plane_classifies_agent_vs_network() {
        assert_eq!(engine_plane("process_inventory"), "agent");
        assert_eq!(engine_plane("usb_enumeration"), "agent");
        assert_eq!(engine_plane("asm"), "network");
        assert_eq!(engine_plane("leak_hunter"), "network");
    }

    #[test]
    fn cross_plane_jumps_to_critical() {
        let c = corroborate_cluster_severity("medium", &["asm".into(), "process_inventory".into()]);
        assert_eq!(c.severity, "critical");
        assert_eq!(c.boost, "cross_plane");
        assert!(c.engine_planes.contains(&"agent".to_string()));
        assert!(c.engine_planes.contains(&"network".to_string()));
        assert_eq!(c.native_severity, "medium");
        assert_eq!(corroboration_cvss_floor(&c.boost, &c.severity), 9.0);
    }

    #[test]
    fn two_network_engines_bump_one_level() {
        let c = corroborate_cluster_severity("medium", &["asm".into(), "leak_hunter".into()]);
        assert_eq!(c.severity, "high");
        assert_eq!(c.boost, "multi_engine");
        assert_eq!(c.engine_planes, vec!["network".to_string()]);
    }

    #[test]
    fn three_engines_at_least_high() {
        let c = corroborate_cluster_severity(
            "low",
            &["asm".into(), "leak_hunter".into(), "bola_idor".into()],
        );
        assert_eq!(c.severity, "high");
        assert_eq!(c.boost, "multi_engine");
    }

    #[test]
    fn single_engine_no_boost() {
        let c = corroborate_cluster_severity("high", &["asm".into()]);
        assert_eq!(c.severity, "high");
        assert_eq!(c.boost, "none");
    }

    #[test]
    fn soar_skipped_only_for_false_positive() {
        assert!(!should_dispatch_soar_playbooks("FALSE_POSITIVE"));
        assert!(!should_dispatch_soar_playbooks("false_positive"));
        assert!(should_dispatch_soar_playbooks("OPEN"));
        assert!(should_dispatch_soar_playbooks("ACKNOWLEDGED"));
    }
}
