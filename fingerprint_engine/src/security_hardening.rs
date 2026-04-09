//! Adversarial hardening: validate outbound-destructive inputs (Auto-Heal → GitHub, PoE URLs, containment).
//! Human-in-the-loop: optional `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET`; caller must send matching `X-Weissman-Destructive-Confirm`.

use axum::http::HeaderMap;
use subtle::ConstantTimeEq;
use url::Url;

const MAX_PATCH_BYTES: usize = 512 * 1024;
const MAX_URL_BYTES: usize = 2048;
const MAX_FINDING_ID_LEN: usize = 128;

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
}
