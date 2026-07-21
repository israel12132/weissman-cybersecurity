//! Adversarial hardening: validate outbound-destructive inputs (Auto-Heal → GitHub, PoE URLs, containment).
//! Human-in-the-loop: optional `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET`; caller must send matching `X-Weissman-Destructive-Confirm`.

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use subtle::ConstantTimeEq;
use tokio::net::lookup_host;
use url::Url;

const MAX_PATCH_BYTES: usize = 512 * 1024;
const MAX_URL_BYTES: usize = 2048;
const MAX_FINDING_ID_LEN: usize = 128;
const SCAN_SCOPE_BLOCKLIST: &[&str] = &[
    "localhost",
    "metadata.google.internal",
    "metadata.goog",
    "169.254.169.254",
    "fd00:ec2::254",
    "100.100.100.200",
];

/// When `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET` is non-empty, the header must match exactly (constant-time on equal lengths).
/// In production, an empty secret denies all destructive actions (fail-closed).
pub fn destructive_action_authorized(headers: &HeaderMap) -> bool {
    let secret = std::env::var("WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET").unwrap_or_default();
    if secret.is_empty() {
        return !weissman_core::tls_policy::is_production_environment();
    }
    let Some(hv) = headers
        .get("x-weissman-destructive-confirm")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    header_secret_matches(hv, &secret)
}

/// Dual approval: second operator must send `X-Weissman-Dual-Approve` matching
/// `WEISSMAN_DUAL_APPROVAL_SECRET` (independent from primary destructive confirm).
pub fn dual_approval_authorized(headers: &HeaderMap) -> bool {
    let secret = std::env::var("WEISSMAN_DUAL_APPROVAL_SECRET").unwrap_or_default();
    if secret.is_empty() {
        return !weissman_core::tls_policy::is_production_environment();
    }
    let Some(hv) = headers
        .get("x-weissman-dual-approve")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    header_secret_matches(hv, &secret)
}

fn header_secret_matches(provided: &str, expected: &str) -> bool {
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Destructive SOAR / containment paths: admin role + primary + dual approval headers.
pub fn destructive_admin_dual_authorized(
    headers: &HeaderMap,
    auth: &crate::auth_jwt::AuthContext,
) -> Result<(), Response> {
    if let Err(r) = crate::rbac::require_admin(auth) {
        return Err(r);
    }
    if !destructive_action_authorized(headers) {
        return Err(destructive_denied_response(
            "Missing or invalid X-Weissman-Destructive-Confirm header",
        ));
    }
    if !dual_approval_authorized(headers) {
        return Err(destructive_denied_response(
            "Missing or invalid X-Weissman-Dual-Approve header (dual approval required)",
        ));
    }
    Ok(())
}

fn destructive_denied_response(detail: &str) -> Response {
    (
        axum::http::StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({
            "ok": false,
            "code": "destructive_approval_required",
            "detail": detail,
        })),
    )
        .into_response()
}

/// Constant-time compare of raw HMAC/digest bytes against a hex signature (optional `sha256=` prefix).
pub fn constant_time_hmac_hex_eq(expected_bytes: &[u8], provided_hex: &str) -> bool {
    let provided = provided_hex.trim();
    let provided = provided
        .strip_prefix("sha256=")
        .or_else(|| provided.strip_prefix("SHA256="))
        .unwrap_or(provided);
    let Ok(provided_bytes) = hex::decode(provided) else {
        return false;
    };
    if expected_bytes.len() != provided_bytes.len() {
        return false;
    }
    bool::from(expected_bytes.ct_eq(&provided_bytes))
}

/// `owner/repo` only; GitHub slug rules (no traversal, no URL injection).
pub fn validate_github_repo_slug(slug: &str) -> Result<(), &'static str> {
    let s = slug.trim();
    if s.is_empty() || s.len() > 200 {
        return Err("invalid repo slug length");
    }
    if s.contains("..") || s.contains('/') && s.matches('/').count() != 1 {
        return Err("invalid repo slug format");
    }
    let (owner, repo) = s.split_once('/').ok_or("repo must be owner/name")?;
    if owner.is_empty() || repo.is_empty() {
        return Err("empty owner or repo");
    }
    let ok_part = |p: &str| {
        p.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    };
    if !ok_part(owner) || !ok_part(repo) {
        return Err("owner/repo must be alphanumeric with - _ . only");
    }
    Ok(())
}

/// Reject binary / embedded NUL; cap size. Unified-diff blobs get extra script heuristics (poisoned “patch” → code exec).
pub fn validate_remediation_patch(patch: &str) -> Result<(), &'static str> {
    if patch.len() > MAX_PATCH_BYTES {
        return Err("patch exceeds maximum size");
    }
    if patch.as_bytes().contains(&0) {
        return Err("patch contains NUL bytes");
    }
    let looks_diff = patch.lines().take(20).any(|l| {
        let t = l.trim_start();
        t.starts_with("diff ")
            || t.starts_with("--- ")
            || t.starts_with("+++ ")
            || t.starts_with("@@ ")
            || t.starts_with("index ")
    });
    if !looks_diff {
        return Ok(());
    }
    let lower = patch.to_ascii_lowercase();
    if lower.contains("#!/bin/bash")
        || lower.contains("#!/bin/sh")
        || lower.contains("\neval(")
        || lower.contains("base64 -d")
    {
        return Err("patch rejected: suspicious script-like content in diff");
    }
    Ok(())
}

/// PoE / scanner targets: HTTP(S) only, bounded length, block obvious SSRF to cloud metadata.
pub fn validate_poe_target_url(raw: &str) -> Result<(), &'static str> {
    let u = raw.trim();
    if u.is_empty() || u.len() > MAX_URL_BYTES {
        return Err("invalid target url length");
    }
    let parsed = Url::parse(u).map_err(|_| "invalid URL")?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("only http and https targets are allowed");
    }
    let host = parsed
        .host_str()
        .ok_or("missing host")?
        .to_ascii_lowercase();
    if host == "169.254.169.254"
        || host == "metadata.google.internal"
        || host == "metadata"
        || host.ends_with(".internal")
    {
        return Err("cloud metadata endpoints are blocked");
    }
    if std::env::var("WEISSMAN_ALLOW_PRIVATE_SCAN_TARGETS")
        .map(|v| v != "1" && !v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
    {
        if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            return Err("loopback targets blocked unless WEISSMAN_ALLOW_PRIVATE_SCAN_TARGETS=1");
        }
    }
    Ok(())
}

fn allow_private_scan_targets() -> bool {
    std::env::var("WEISSMAN_ALLOW_PRIVATE_SCAN_TARGETS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn extract_target_host(raw: &str) -> Result<String, &'static str> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("target must not be empty");
    }
    let parsed = if t.contains("://") {
        Url::parse(t).map_err(|_| "invalid target URL")?
    } else {
        Url::parse(&format!("https://{t}")).map_err(|_| "invalid target host")?
    };
    let host = parsed.host_str().ok_or("missing target host")?;
    Ok(host.to_ascii_lowercase())
}

fn is_private_or_reserved_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || (o[0] == 10)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 169 && o[1] == 254)
                || *v4 == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

fn normalize_scope_domain(s: &str) -> Option<String> {
    let raw = s.trim().trim_matches('.').trim_start_matches("*.").trim();
    if raw.is_empty() {
        return None;
    }
    let candidate = if raw.contains("://") {
        Url::parse(raw)
            .ok()
            .and_then(|u| u.host_str().map(ToString::to_string))
    } else {
        Url::parse(&format!("https://{raw}"))
            .ok()
            .and_then(|u| u.host_str().map(ToString::to_string))
    };
    candidate.map(|h| h.to_ascii_lowercase())
}

fn parse_approved_domains_blob(raw: &str) -> Vec<String> {
    let t = raw.trim();
    if t.is_empty() {
        return Vec::new();
    }
    if t.starts_with('[') {
        if let Ok(arr) = serde_json::from_str::<Vec<String>>(t) {
            return arr
                .into_iter()
                .filter_map(|x| normalize_scope_domain(&x))
                .collect();
        }
    }
    t.split(',').filter_map(normalize_scope_domain).collect()
}

fn target_matches_approved(host: &str, approved: &HashSet<String>) -> bool {
    approved.iter().any(|d| {
        if host == d {
            return true;
        }
        host.strip_suffix(d)
            .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

async fn load_tenant_approved_domains(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<HashSet<String>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows: Vec<String> = if let Some(cid) = client_id {
        sqlx::query_scalar(
            "SELECT COALESCE(domains, '[]') FROM clients WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(cid)
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query_scalar("SELECT COALESCE(domains, '[]') FROM clients WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&mut *tx)
            .await?
    };
    tx.commit().await?;
    let mut approved = HashSet::new();
    for raw in rows {
        for d in parse_approved_domains_blob(&raw) {
            approved.insert(d);
        }
    }
    Ok(approved)
}

#[derive(Debug, Clone)]
pub struct ScopeValidationOutcome {
    pub normalized_host: String,
    pub resolved_ips: Vec<String>,
}

pub async fn validate_scan_target_in_scope(
    pool: &PgPool,
    tenant_id: i64,
    target: &str,
    client_id: Option<i64>,
) -> Result<ScopeValidationOutcome, String> {
    let host = extract_target_host(target).map_err(ToString::to_string)?;
    let host_trimmed_dot = host.trim_end_matches('.');

    if SCAN_SCOPE_BLOCKLIST.iter().any(|h| *h == host_trimmed_dot) {
        return Err(format!("target host '{host_trimmed_dot}' is blocked"));
    }

    let allow_private = allow_private_scan_targets();
    let mut resolved_ips: Vec<String> = Vec::new();
    if let Ok(ip) = host_trimmed_dot.parse::<IpAddr>() {
        if !allow_private && is_private_or_reserved_ip(&ip) {
            return Err(format!(
                "target host '{host_trimmed_dot}' resolves to a private/reserved address and is not allowed"
            ));
        }
        resolved_ips.push(ip.to_string());
    } else {
        let resolved = lookup_host((host_trimmed_dot, 80))
            .await
            .map_err(|_| format!("failed to resolve target host '{host_trimmed_dot}'"))?;
        let mut saw_addr = false;
        let mut seen = HashSet::new();
        for addr in resolved {
            saw_addr = true;
            let ip = addr.ip();
            if !allow_private && is_private_or_reserved_ip(&ip) {
                return Err(format!(
                    "target host '{host_trimmed_dot}' resolved to blocked address {ip}"
                ));
            }
            let s = ip.to_string();
            if seen.insert(s.clone()) {
                resolved_ips.push(s);
            }
        }
        if !saw_addr {
            return Err(format!(
                "failed to resolve target host '{host_trimmed_dot}'"
            ));
        }
    }

    let approved = load_tenant_approved_domains(pool, tenant_id, client_id)
        .await
        .map_err(|e| format!("failed loading approved tenant domains: {e}"))?;
    if approved.is_empty() {
        return Err(
            "no approved client domains found for tenant; define at least one client domain"
                .to_string(),
        );
    }
    if !target_matches_approved(host_trimmed_dot, &approved) {
        return Err(format!(
            "target host '{host_trimmed_dot}' is outside approved tenant scope"
        ));
    }
    Ok(ScopeValidationOutcome {
        normalized_host: host_trimmed_dot.to_string(),
        resolved_ips,
    })
}

/// Validate a tenant-configured OUTBOUND URL (webhook / Slack / integration target)
/// against SSRF. Unlike scan targets these legitimately point at arbitrary third-party
/// domains, so there is no tenant-scope allow-list — but the destination must be a
/// public http(s) endpoint: cloud-metadata/internal hosts are blocked, and every
/// resolved address is rejected if it is private/reserved (unless the operator sets
/// `WEISSMAN_ALLOW_PRIVATE_WEBHOOKS=1` for on-prem integrations).
pub async fn validate_outbound_url(raw: &str) -> Result<(), String> {
    let u = raw.trim();
    if u.is_empty() || u.len() > MAX_URL_BYTES {
        return Err("invalid webhook url length".to_string());
    }
    let parsed = Url::parse(u).map_err(|_| "invalid webhook URL".to_string())?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("only http and https webhook URLs are allowed".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "missing webhook host".to_string())?
        .to_ascii_lowercase();
    let host_trimmed_dot = host.trim_end_matches('.');
    if SCAN_SCOPE_BLOCKLIST.iter().any(|h| *h == host_trimmed_dot)
        || host_trimmed_dot == "metadata"
        || host_trimmed_dot == "metadata.google.internal"
        || host_trimmed_dot.ends_with(".internal")
    {
        return Err(format!("webhook host '{host_trimmed_dot}' is blocked"));
    }
    let allow_private = std::env::var("WEISSMAN_ALLOW_PRIVATE_WEBHOOKS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if allow_private {
        return Ok(());
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    if let Ok(ip) = host_trimmed_dot.parse::<IpAddr>() {
        if is_private_or_reserved_ip(&ip) {
            return Err(format!(
                "webhook host '{host_trimmed_dot}' is a private/reserved address"
            ));
        }
    } else {
        let resolved = lookup_host((host_trimmed_dot, port))
            .await
            .map_err(|_| format!("failed to resolve webhook host '{host_trimmed_dot}'"))?;
        let mut saw = false;
        for addr in resolved {
            saw = true;
            if is_private_or_reserved_ip(&addr.ip()) {
                return Err(format!(
                    "webhook host '{host_trimmed_dot}' resolved to blocked address {}",
                    addr.ip()
                ));
            }
        }
        if !saw {
            return Err(format!(
                "failed to resolve webhook host '{host_trimmed_dot}'"
            ));
        }
    }
    Ok(())
}

pub async fn enforce_execution_scope_pin(
    target: &str,
    validated_scope: &Value,
) -> Result<(), String> {
    let pinned_host = validated_scope
        .get("host")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "validated_scope.host missing".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();

    let pinned_ips: HashSet<String> = validated_scope
        .get("resolved_ips")
        .and_then(Value::as_array)
        .ok_or_else(|| "validated_scope.resolved_ips missing".to_string())?
        .iter()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    if pinned_ips.is_empty() {
        return Err("validated_scope.resolved_ips empty".to_string());
    }

    let target_host = extract_target_host(target)
        .map_err(ToString::to_string)?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if target_host != pinned_host {
        return Err(format!(
            "validated_scope host mismatch: target '{target_host}' != pinned '{pinned_host}'"
        ));
    }

    let current_ips: HashSet<String> = if let Ok(ip) = target_host.parse::<IpAddr>() {
        std::iter::once(ip.to_string()).collect()
    } else {
        lookup_host((target_host.as_str(), 80))
            .await
            .map_err(|_| format!("failed to resolve target host '{target_host}'"))?
            .map(|sa| sa.ip().to_string())
            .collect()
    };
    if current_ips.is_empty() {
        return Err(format!("failed to resolve target host '{target_host}'"));
    }

    if current_ips.iter().all(|ip| pinned_ips.contains(ip)) {
        return Ok(());
    }

    // The exact pin no longer matches. This is legitimate for round-robin / rotating hosts —
    // e.g. github.com hands out a *different single A-record per lookup* (140.82.113.x today,
    // 140.82.114.x on the next query), so two consecutive resolutions rarely agree and an
    // exact-IP match cannot be required without permanently breaking real public targets
    // (supply-chain scans of GitHub repos, CDN-fronted sites, anycast hosts). The security
    // property we MUST still enforce is anti-rebinding into INTERNAL space (SSRF): a host that
    // was public at submission must not resolve to a private/reserved address at execution.
    // Re-resolve and reject only on that condition; rotation among public addresses of the same
    // (name-matched) host is allowed. `allow_private_scan_targets()` (operator opt-in) keeps the
    // escape hatch consistent with submission-time validation.
    let fresh_ips: HashSet<String> = lookup_host((target_host.as_str(), 80))
        .await
        .map_err(|_| format!("failed to re-resolve target host '{target_host}'"))?
        .map(|sa| sa.ip().to_string())
        .collect();
    if fresh_ips.is_empty() {
        return Err(format!("failed to re-resolve target host '{target_host}'"));
    }
    if !allow_private_scan_targets() {
        for ip_s in current_ips.iter().chain(fresh_ips.iter()) {
            if let Ok(ip) = ip_s.parse::<IpAddr>() {
                if is_private_or_reserved_ip(&ip) {
                    return Err(format!(
                        "validated_scope pin mismatch: host '{target_host}' now resolves to a \
                         private/reserved address ({ip_s}) — possible DNS rebind"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Finding IDs become Git branch suffixes — restrict charset.
pub fn validate_git_branch_name(branch: &str) -> Result<(), &'static str> {
    let s = branch.trim();
    if s.is_empty() || s.len() > 255 {
        return Err("invalid branch length");
    }
    if s.contains("..") || s.starts_with('/') || s.ends_with('/') {
        return Err("invalid branch path");
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/')
    {
        return Err("invalid branch characters");
    }
    Ok(())
}

pub fn validate_finding_id_token(id: &str) -> Result<(), &'static str> {
    let s = id.trim();
    if s.is_empty() || s.len() > MAX_FINDING_ID_LEN {
        return Err("invalid finding_id length");
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err("finding_id has invalid characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_slug_accepts_normal() {
        assert!(validate_github_repo_slug("acme/corp-app").is_ok());
    }

    #[test]
    fn repo_slug_rejects_traversal() {
        assert!(validate_github_repo_slug("evil/../other").is_err());
    }

    #[test]
    fn patch_rejects_nul() {
        assert!(validate_remediation_patch("hello\0world").is_err());
    }

    #[test]
    fn poe_blocks_metadata() {
        assert!(validate_poe_target_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(validate_poe_target_url("https://example.com/").is_ok());
    }

    #[test]
    fn scope_normalize_domain() {
        assert_eq!(
            normalize_scope_domain("*.Example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_scope_domain("https://api.example.com/path"),
            Some("api.example.com".to_string())
        );
    }

    #[test]
    fn scope_target_matches_subdomain() {
        let mut approved = HashSet::new();
        approved.insert("example.com".to_string());
        assert!(target_matches_approved("example.com", &approved));
        assert!(target_matches_approved("api.example.com", &approved));
        assert!(!target_matches_approved("evil-example.com", &approved));
        assert!(!target_matches_approved("evilexample.com", &approved));
    }

    #[test]
    fn scope_private_ip_blocking() {
        assert!(is_private_or_reserved_ip(
            &"127.0.0.1".parse::<IpAddr>().expect("ip parse")
        ));
        assert!(is_private_or_reserved_ip(
            &"169.254.169.254".parse::<IpAddr>().expect("ip parse")
        ));
        assert!(is_private_or_reserved_ip(
            &"10.1.2.3".parse::<IpAddr>().expect("ip parse")
        ));
        assert!(!is_private_or_reserved_ip(
            &"8.8.8.8".parse::<IpAddr>().expect("ip parse")
        ));
    }

    #[test]
    fn scope_extract_target_host() {
        assert_eq!(
            extract_target_host("https://api.example.com/path").expect("host"),
            "api.example.com".to_string()
        );
        assert_eq!(
            extract_target_host("example.com:443").expect("host"),
            "example.com".to_string()
        );
    }

    #[tokio::test]
    async fn execution_scope_pin_accepts_matching_ip_literal() {
        let scope = serde_json::json!({
            "host": "1.1.1.1",
            "resolved_ips": ["1.1.1.1"]
        });
        let ok = enforce_execution_scope_pin("https://1.1.1.1/login", &scope).await;
        assert!(ok.is_ok());
    }

    #[tokio::test]
    async fn execution_scope_pin_rejects_host_mismatch() {
        let scope = serde_json::json!({
            "host": "1.1.1.1",
            "resolved_ips": ["1.1.1.1"]
        });
        let err = enforce_execution_scope_pin("https://8.8.8.8", &scope).await;
        assert!(err.is_err());
    }

    // Round-robin tolerance: a target that still resolves to a PUBLIC address is accepted even
    // when that address is not in the submission-time pin set. Rotating/anycast/CDN hosts
    // (github.com, Cloudflare-fronted sites) hand out different public A-records per lookup, so
    // requiring an exact pin match would permanently break legitimate public scans. The pin's
    // job is anti-rebinding into internal space — enforced by the test below — not freezing a
    // single public IP.
    #[tokio::test]
    async fn execution_scope_pin_allows_unpinned_public_ip() {
        let scope = serde_json::json!({
            "host": "1.1.1.1",
            "resolved_ips": ["8.8.8.8"]
        });
        let ok = enforce_execution_scope_pin("https://1.1.1.1", &scope).await;
        assert!(
            ok.is_ok(),
            "a public address outside the pin set must be tolerated (round-robin), got {ok:?}"
        );
    }

    // Retained SSRF property: if the (name-matched) host resolves to a private/reserved address
    // at execution while the pin was public, reject it as a possible DNS rebind.
    #[tokio::test]
    async fn execution_scope_pin_rejects_rebind_to_private_ip() {
        let scope = serde_json::json!({
            "host": "10.0.0.1",
            "resolved_ips": ["8.8.8.8"]
        });
        let err = enforce_execution_scope_pin("https://10.0.0.1", &scope).await;
        assert!(
            err.is_err(),
            "a host resolving into private/reserved space must be rejected (rebind), got {err:?}"
        );
    }
}
