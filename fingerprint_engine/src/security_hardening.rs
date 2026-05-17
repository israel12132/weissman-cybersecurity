//! Adversarial hardening: validate outbound-destructive inputs (Auto-Heal → GitHub, PoE URLs, containment).
//! Human-in-the-loop: optional `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET`; caller must send matching `X-Weissman-Destructive-Confirm`.

use axum::http::HeaderMap;
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
pub fn destructive_action_authorized(headers: &HeaderMap) -> bool {
    let secret = std::env::var("WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET").unwrap_or_default();
    if secret.is_empty() {
        return true;
    }
    let Some(hv) = headers
        .get("x-weissman-destructive-confirm")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let a = hv.as_bytes();
    let b = secret.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
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

fn bypass_ssrf_scope_check() -> bool {
    std::env::var("BYPASS_SSRF_CHECK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
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
    if approved.contains(host) {
        return true;
    }
    approved.iter().any(|d| host.ends_with(&format!(".{d}")))
}

async fn load_tenant_approved_domains(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<HashSet<String>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT COALESCE(domains, '[]') FROM clients WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&mut *tx)
            .await?;
    let _ = tx.commit().await;
    let mut approved = HashSet::new();
    for raw in rows {
        for d in parse_approved_domains_blob(&raw) {
            approved.insert(d);
        }
    }
    Ok(approved)
}

pub async fn validate_scan_target_in_scope(
    pool: &PgPool,
    tenant_id: i64,
    target: &str,
) -> Result<(), String> {
    if bypass_ssrf_scope_check() {
        tracing::warn!(
            target: "security_hardening",
            tenant_id,
            "BYPASS_SSRF_CHECK active: scan target scope checks disabled"
        );
        return Ok(());
    }

    let host = extract_target_host(target).map_err(ToString::to_string)?;
    let host_trimmed_dot = host.trim_end_matches('.');

    if SCAN_SCOPE_BLOCKLIST.iter().any(|h| *h == host_trimmed_dot) {
        return Err(format!("target host '{host_trimmed_dot}' is blocked"));
    }

    let allow_private = allow_private_scan_targets();
    if let Ok(ip) = host_trimmed_dot.parse::<IpAddr>() {
        if !allow_private && is_private_or_reserved_ip(&ip) {
            return Err(format!(
                "target host '{host_trimmed_dot}' resolves to a private/reserved address and is not allowed"
            ));
        }
    } else {
        let resolved = lookup_host((host_trimmed_dot, 80))
            .await
            .map_err(|_| format!("failed to resolve target host '{host_trimmed_dot}'"))?;
        let mut saw_addr = false;
        for addr in resolved {
            saw_addr = true;
            let ip = addr.ip();
            if !allow_private && is_private_or_reserved_ip(&ip) {
                return Err(format!(
                    "target host '{host_trimmed_dot}' resolved to blocked address {ip}"
                ));
            }
        }
        if !saw_addr {
            return Err(format!(
                "failed to resolve target host '{host_trimmed_dot}'"
            ));
        }
    }

    let approved = load_tenant_approved_domains(pool, tenant_id)
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
}
