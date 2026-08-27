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

/// IANA Dynamic/Private Ports (RFC 6335) and Windows Vista+ default.
/// Used when the OS is unknown so we do **not** merge Kubernetes NodePorts
/// (30000–32767) or Linux high-but-static listeners (32768–49151) into one id.
pub const IANA_DYNAMIC_PORT_MIN: u16 = 49152;
pub const LINUX_EPHEMERAL_PORT_MIN: u16 = 32768;
pub const WINDOWS_EPHEMERAL_PORT_MIN: u16 = 49152;
pub const K8S_NODEPORT_MIN: u16 = 30000;
pub const K8S_NODEPORT_MAX: u16 = 32767;

/// Host OS family for ephemeral-port classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OsFamily {
    Linux,
    Windows,
    #[default]
    Unknown,
}

/// Extra identity context from the engine — service fingerprint / NodePort /
/// declared listener must never be treated as an ephemeral client port.
#[derive(Debug, Clone, Default)]
pub struct IdentityHint {
    pub os: OsFamily,
    pub keep_port: bool,
}

impl IdentityHint {
    #[must_use]
    pub fn from_finding(finding: &Value) -> Self {
        identity_hint_from_finding(finding)
    }
}

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

/// Conservative default (OS unknown): only IANA dynamic ports (≥49152).
#[must_use]
pub fn is_ephemeral_port(port: u16) -> bool {
    is_ephemeral_port_hinted(port, &IdentityHint::default())
}

/// OS-aware / fingerprint-aware ephemeral check.
///
/// * Kubernetes NodePort range is **never** ephemeral (service ports).
/// * Engine-declared listener / banner / `service` / `node_port` keeps the port.
/// * Windows → 49152+; Linux → 32768+; unknown → 49152+ (false-dedup safe).
#[must_use]
pub fn is_ephemeral_port_hinted(port: u16, hint: &IdentityHint) -> bool {
    if hint.keep_port {
        return false;
    }
    if (K8S_NODEPORT_MIN..=K8S_NODEPORT_MAX).contains(&port) {
        return false;
    }
    let min = match hint.os {
        OsFamily::Linux => LINUX_EPHEMERAL_PORT_MIN,
        OsFamily::Windows | OsFamily::Unknown => IANA_DYNAMIC_PORT_MIN,
    };
    port >= min
}

#[must_use]
pub fn identity_hint_from_finding(finding: &Value) -> IdentityHint {
    let os = detect_os_family(finding);
    let keep_port = service_fingerprint_keep_port(finding);
    IdentityHint { os, keep_port }
}

fn detect_os_family(finding: &Value) -> OsFamily {
    for key in ["os", "os_family", "platform", "host_os", "guest_os"] {
        if let Some(s) = finding.get(key).and_then(Value::as_str) {
            if let Some(os) = parse_os_family(s) {
                return os;
            }
        }
    }
    if let Some(agent) = finding.get("agent") {
        for key in ["os", "os_family", "platform"] {
            if let Some(s) = agent.get(key).and_then(Value::as_str) {
                if let Some(os) = parse_os_family(s) {
                    return os;
                }
            }
        }
    }
    OsFamily::Unknown
}

fn parse_os_family(raw: &str) -> Option<OsFamily> {
    let s = raw.trim().to_ascii_lowercase();
    if s.contains("win") {
        return Some(OsFamily::Windows);
    }
    if s.contains("linux")
        || s.contains("ubuntu")
        || s.contains("debian")
        || s.contains("rhel")
        || s.contains("centos")
        || s.contains("alpine")
    {
        return Some(OsFamily::Linux);
    }
    None
}

fn service_fingerprint_keep_port(finding: &Value) -> bool {
    // Service / agent / proxy metadata wins over IANA/OS ranges. A reverse
    // proxy or internal LB that publishes a high mapped port is a listener,
    // not an ephemeral client source — stripping it would merge backends
    // that share the same gateway host.
    if keep_port_flags(finding) || keep_port_strings(finding) {
        return true;
    }
    for nest in [
        "agent",
        "client",
        "proxy",
        "http",
        "metadata",
        "k8s",
        "service_info",
        "upstream",
        "backend",
    ] {
        if let Some(obj) = finding.get(nest) {
            if keep_port_flags(obj) || keep_port_strings(obj) {
                return true;
            }
        }
    }
    false
}

fn keep_port_flags(v: &Value) -> bool {
    for key in [
        "node_port",
        "k8s_node_port",
        "listener",
        "keep_port",
        "port_mapped",
        "mapped_port",
        "reverse_proxy",
    ] {
        if v.get(key).and_then(Value::as_bool).unwrap_or(false) {
            return true;
        }
    }
    if v.get("port_role").and_then(Value::as_str).is_some_and(|s| {
        matches!(
            s.to_ascii_lowercase().as_str(),
            "service" | "listener" | "proxy" | "upstream" | "backend" | "mapped"
        )
    }) {
        return true;
    }
    false
}

fn keep_port_strings(v: &Value) -> bool {
    for key in [
        "service",
        "service_name",
        "banner",
        "product",
        "fingerprint",
        "detected_service",
        "upstream",
        "backend",
        "backend_service",
        "proxy",
        "via",
        "nginx",
        "haproxy",
        "envoy",
        "listen_port",
        "published_port",
        "container_port",
        "target_port",
        "x_forwarded_port",
    ] {
        match v.get(key) {
            Some(Value::String(s)) if !s.trim().is_empty() => return true,
            Some(Value::Number(_)) => return true,
            Some(Value::Bool(true)) => return true,
            _ => {}
        }
    }
    false
}

/// Lower-case host, strip query / fragment / userinfo / default + ephemeral ports,
/// replace **variable** path segments only (UUID / hex id / numeric id) with `{id}`.
/// Static route tokens (`admin`, `billing`, `public`, `image`, `v1`) are kept so
/// `/api/v1/public/image/{id}` never collides with `/api/v1/admin/billing/{id}`.
#[must_use]
pub fn normalize_target(raw: &str) -> String {
    normalize_target_hinted(raw, &IdentityHint::default())
}

#[must_use]
pub fn normalize_target_hinted(raw: &str, hint: &IdentityHint) -> String {
    normalize_target_ctx(raw, hint, None)
}

/// Same as [`normalize_target_hinted`] plus a tenant structural template index.
#[must_use]
pub fn normalize_target_ctx(
    raw: &str,
    hint: &IdentityHint,
    templates: Option<&crate::path_templates::PathTemplateIndex>,
) -> String {
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
    let authority = strip_target_port(authority, scheme, hint);
    let path = match templates {
        Some(idx) => {
            let segs: Vec<&str> = path.split('/').collect();
            idx.apply_segments(&segs)
        }
        None => normalize_route_template(path),
    };
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

fn strip_target_port(authority: &str, scheme: &str, hint: &IdentityHint) -> String {
    let (host, port) = split_host_port(authority);
    let Some(p) = port else {
        return host.to_string();
    };
    let default = matches!(
        (scheme, p),
        ("https", 443) | ("http", 80) | ("wss", 443) | ("ws", 80)
    );
    if default || is_ephemeral_port_hinted(p, hint) {
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

/// Preserve the full application route template. Only **variable edge values**
/// (a whole path segment that is a UUID, hex id, or numeric id) become `{id}`.
/// Static tokens — `admin`, `billing`, `public`, `image`, `v1`, years — stay.
fn normalize_route_template(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let segs: Vec<&str> = path.split('/').collect();
    let last = segs.len().saturating_sub(1);
    let mut out = String::with_capacity(path.len());
    for (i, seg) in segs.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        if is_variable_path_segment(seg, i == last) {
            out.push_str("{id}");
        } else {
            out.push_str(seg);
        }
    }
    out
}

/// REST / framework tokens that must never become `{id}` — they distinguish
/// products (public image vs admin billing) even when a sibling position fans out.
#[must_use]
pub fn is_reserved_route_token(seg: &str) -> bool {
    matches!(
        seg,
        "api"
            | "v1"
            | "v2"
            | "v3"
            | "v4"
            | "admin"
            | "public"
            | "private"
            | "internal"
            | "external"
            | "billing"
            | "image"
            | "images"
            | "img"
            | "static"
            | "assets"
            | "media"
            | "users"
            | "user"
            | "settings"
            | "profile"
            | "login"
            | "logout"
            | "auth"
            | "oauth"
            | "well-known"
            | "health"
            | "healthz"
            | "ready"
            | "livez"
            | "status"
            | "metrics"
            | "graphql"
            | "swagger"
            | "docs"
            | "openapi"
            | "webhook"
            | "webhooks"
            | "callback"
            | "files"
            | "file"
            | "download"
            | "upload"
            | "search"
            | "reports"
            | "report"
            | "invoices"
            | "invoice"
            | "orders"
            | "order"
            | "checkout"
            | "cart"
            | "q1"
            | "q2"
            | "q3"
            | "q4"
            | "rest"
            | "rpc"
            | "grpc"
    )
}

/// True when `seg` is a variable identifier, never a static route token.
#[must_use]
pub fn is_variable_path_segment(seg: &str, is_last: bool) -> bool {
    if seg.is_empty() || seg == "{id}" {
        return false;
    }
    if is_reserved_route_token(seg) {
        return false;
    }
    let s = seg;
    if UUID_RE.is_match(s) && s.len() >= 36 {
        return true;
    }
    if s.len() >= 16 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    if is_hyphenated_hex_id(s) {
        return true;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        // Intermediate 4-digit tokens are often years / versions — keep them.
        // Leaf 4+ digits (`/orders/1234`) and any 5+ digit token are ids.
        if s.len() >= 5 {
            return true;
        }
        if is_last && s.len() >= 4 {
            return true;
        }
        return false;
    }
    if is_email_segment(s) || is_filename_segment(s) || is_opaque_resource_segment(s) {
        return true;
    }
    false
}

fn is_email_segment(s: &str) -> bool {
    let Some(at) = s.find('@') else {
        return false;
    };
    at > 0 && s[at + 1..].contains('.')
}

fn is_filename_segment(s: &str) -> bool {
    let Some(dot) = s.rfind('.') else {
        return false;
    };
    if dot == 0 || dot + 1 >= s.len() {
        return false;
    }
    let ext = &s[dot + 1..];
    if ext.len() < 2 || ext.len() > 5 || !ext.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return false;
    }
    let stem = &s[..dot];
    stem.bytes()
        .any(|b| b == b'_' || b == b'-' || b.is_ascii_digit())
}

/// `invoice_august_2026`, `report_q3_final`, `user-john-doe-123` (non-hex).
fn is_opaque_resource_segment(s: &str) -> bool {
    let underscores = s.bytes().filter(|b| *b == b'_').count();
    let hyphens = s.bytes().filter(|b| *b == b'-').count();
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    if underscores >= 1 && has_digit && s.len() >= 8 {
        return true;
    }
    if underscores >= 2 && s.len() >= 10 {
        return true;
    }
    if hyphens >= 2 && has_digit && !s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return true;
    }
    false
}

fn is_hyphenated_hex_id(seg: &str) -> bool {
    if !seg.contains('-') {
        return false;
    }
    if !seg.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return false;
    }
    let hex_len = seg.bytes().filter(|b| b.is_ascii_hexdigit()).count();
    hex_len >= 12
}

/// Uniform, filtered signature: lowercase, strip query/fragment, ephemeral ports,
/// session tokens, UUIDs, timestamps. Two probes of the same vuln with different
/// `?sid=` or `:54321` must hash identically.
#[must_use]
pub fn normalize_signature(raw: &str) -> String {
    normalize_signature_hinted(raw, &IdentityHint::default())
}

#[must_use]
pub fn normalize_signature_hinted(raw: &str, hint: &IdentityHint) -> String {
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
            if is_ephemeral_port_hinted(p, hint) {
                "port {ephemeral}".to_string()
            } else {
                caps.get(0)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default()
            }
        })
        .into_owned();
    s = strip_colon_ephemeral_ports(&s, hint);
    collapse_ws(&s)
}

fn strip_colon_ephemeral_ports(s: &str, hint: &IdentityHint) -> String {
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
                if is_ephemeral_port_hinted(p, hint) {
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
    build_cluster_key_hinted(target, vuln_signature, cwe, &IdentityHint::default())
}

#[must_use]
pub fn build_cluster_key_hinted(
    target: &str,
    vuln_signature: &str,
    cwe: &str,
    hint: &IdentityHint,
) -> String {
    build_cluster_key_ctx(target, vuln_signature, cwe, hint, None)
}

#[must_use]
pub fn build_cluster_key_ctx(
    target: &str,
    vuln_signature: &str,
    cwe: &str,
    hint: &IdentityHint,
    templates: Option<&crate::path_templates::PathTemplateIndex>,
) -> String {
    let target_norm = normalize_target_ctx(target, hint, templates);
    let sig_norm = normalize_signature_hinted(vuln_signature, hint);
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
    build_stable_finding_id_ctx(engine, target, finding, None)
}

#[must_use]
pub fn build_stable_finding_id_ctx(
    engine: &str,
    target: &str,
    finding: &Value,
    templates: Option<&crate::path_templates::PathTemplateIndex>,
) -> String {
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
    let hint = identity_hint_from_finding(finding);
    let signature = derive_vuln_signature(finding, &title);

    let mut hasher = Sha256::new();
    hasher.update(engine.trim().as_bytes());
    hasher.update(b"|");
    hasher.update(normalize_target_ctx(target, &hint, templates).as_bytes());
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
        hasher.update(normalize_signature_hinted(&title, &hint).as_bytes());
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

/// Watermark after HFV closes the vulnerability. A later regression starts clean.
#[must_use]
pub fn watermark_after_verified_fixed() -> &'static str {
    "info"
}

/// First severity of a new lifecycle after [`watermark_after_verified_fixed`].
#[must_use]
pub fn watermark_on_regression(native: &str) -> String {
    canonical_sev(native).to_string()
}

/// High-watermark: cluster severity used for inbox / SOAR / audit never drops.
#[must_use]
pub fn monotonic_severity(watermark: &str, computed: &str) -> String {
    if sev_weight(computed) > sev_weight(watermark) {
        canonical_sev(computed).to_string()
    } else {
        canonical_sev(watermark).to_string()
    }
}

/// `cross_plane` > `multi_engine` > `none` — boost reason is also monotonic.
#[must_use]
pub fn monotonic_boost(watermark: &str, computed: &str) -> String {
    if boost_rank(computed) > boost_rank(watermark) {
        computed.to_string()
    } else if watermark.trim().is_empty() {
        "none".to_string()
    } else {
        watermark.to_string()
    }
}

#[must_use]
pub fn boost_rank(boost: &str) -> i32 {
    match boost.trim() {
        "cross_plane" => 2,
        "multi_engine" => 1,
        _ => 0,
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
    fn route_template_keeps_static_tokens_public_vs_admin() {
        let public = normalize_target("https://api.corp/api/v1/public/image/6c084089-0aec");
        let admin = normalize_target("https://api.corp/api/v1/admin/billing/6c084089-0aec");
        assert_eq!(public, "https://api.corp/api/v1/public/image/{id}");
        assert_eq!(admin, "https://api.corp/api/v1/admin/billing/{id}");
        assert_ne!(
            build_cluster_key(&public, "xss", "CWE-79"),
            build_cluster_key(&admin, "xss", "CWE-79"),
            "public image and admin billing must never share a cluster_key"
        );
        // Year-like intermediate 4-digit tokens stay (not collapsed to /api/{id}/...).
        assert_eq!(
            normalize_target("https://api.corp/reports/2024/q1"),
            "https://api.corp/reports/2024/q1"
        );
    }

    #[test]
    fn conservative_ephemeral_keeps_nodeport_and_linux_high_static() {
        assert_eq!(
            normalize_target("https://svc.internal:30000/health"),
            "https://svc.internal:30000/health"
        );
        assert_eq!(
            normalize_target("https://cache.internal:33791/"),
            "https://cache.internal:33791"
        );
        let linux = IdentityHint {
            os: OsFamily::Linux,
            keep_port: false,
        };
        assert_eq!(
            normalize_target_hinted("https://cache.internal:33791/", &linux),
            "https://cache.internal"
        );
        let fingerprinted = IdentityHint {
            os: OsFamily::Unknown,
            keep_port: true,
        };
        assert_eq!(
            normalize_target_hinted("https://redis.internal:50100/", &fingerprinted),
            "https://redis.internal:50100"
        );
    }

    #[test]
    fn watermark_severity_never_drops() {
        assert_eq!(monotonic_severity("critical", "medium"), "critical");
        assert_eq!(monotonic_severity("medium", "critical"), "critical");
        assert_eq!(monotonic_boost("cross_plane", "none"), "cross_plane");
        assert_eq!(monotonic_boost("none", "multi_engine"), "multi_engine");
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

    #[test]
    fn high_cardinality_email_file_and_slug_collapse() {
        assert_eq!(
            normalize_target("https://api.corp/files/alice@corp.com"),
            normalize_target("https://api.corp/files/bob@corp.com")
        );
        assert_eq!(
            normalize_target("https://api.corp/files/alice@corp.com"),
            "https://api.corp/files/{id}"
        );
        assert_eq!(
            normalize_target("https://api.corp/docs/invoice_august_2026.pdf"),
            normalize_target("https://api.corp/docs/invoice_july_2026.pdf")
        );
        assert_eq!(
            normalize_target("https://api.corp/docs/invoice_august_2026.pdf"),
            "https://api.corp/docs/{id}"
        );
        assert_eq!(
            normalize_target("https://api.corp/people/user-john-doe-99"),
            "https://api.corp/people/{id}"
        );
        assert_eq!(
            normalize_target("https://api.corp/reports/report_q3_final"),
            "https://api.corp/reports/{id}"
        );
        // Static product tokens still distinguish planes.
        assert_ne!(
            normalize_target("https://api.corp/api/v1/public/image/alice@corp.com"),
            normalize_target("https://api.corp/api/v1/admin/billing/alice@corp.com")
        );
    }

    #[test]
    fn static_filenames_and_reserved_tokens_stay() {
        assert_eq!(
            normalize_target("https://api.corp/.well-known/openid-configuration"),
            "https://api.corp/.well-known/openid-configuration"
        );
        assert_eq!(
            normalize_target("https://api.corp/static/index.html"),
            "https://api.corp/static/index.html"
        );
    }

    #[test]
    fn proxy_or_banner_metadata_keeps_high_port() {
        let via_proxy = json!({"proxy": {"via": "nginx"}, "banner": ""});
        let hint = identity_hint_from_finding(&via_proxy);
        assert!(hint.keep_port);
        assert_eq!(
            normalize_target_hinted("https://gw.internal:50100/app", &hint),
            "https://gw.internal:50100/app"
        );
        let agent = json!({"agent": {"service": "redis-exporter", "os": "linux"}});
        let h2 = identity_hint_from_finding(&agent);
        assert!(h2.keep_port);
        assert_eq!(
            normalize_target_hinted("https://gw.internal:32768/metrics", &h2),
            "https://gw.internal:32768/metrics"
        );
        let bare = json!({"title": "open port"});
        let h3 = identity_hint_from_finding(&bare);
        assert!(!h3.keep_port);
        assert_eq!(
            normalize_target_hinted("https://gw.internal:50100/app", &h3),
            "https://gw.internal/app"
        );
    }

    #[test]
    fn verified_fixed_resets_watermark_lifecycle() {
        assert_eq!(watermark_after_verified_fixed(), "info");
        assert_eq!(watermark_on_regression("low"), "low");
        assert_eq!(
            monotonic_severity(watermark_after_verified_fixed(), "low"),
            "low"
        );
    }
}
