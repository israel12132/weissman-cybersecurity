//! Phase 6: CI/CD webhooks — GitHub / GitLab / Bitbucket / generic file bundle; AST+regex gate returns 403 on critical.

use crate::cicd_ast_scan::{self, CicdFinding};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::PgPool;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

fn verify_github_signature(secret: &str, signature_256: Option<&str>, body: &[u8]) -> bool {
    let Some(sig_raw) = signature_256 else {
        return false;
    };
    let sig = sig_raw.trim().strip_prefix("sha256=").unwrap_or(sig_raw);
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());
    expected.eq_ignore_ascii_case(sig)
}

fn verify_gitlab_token(headers: &HeaderMap, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    let t = headers
        .get("x-gitlab-token")
        .or_else(|| headers.get("X-Gitlab-Token"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    t == expected
}

fn verify_bitbucket_secret(headers: &HeaderMap, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    let t = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    t == format!("Bearer {}", expected)
}

async fn log_cicd_event(
    pool: Option<&PgPool>,
    provider: &str,
    ref_name: &str,
    sha: &str,
    blocked: bool,
    findings: &[CicdFinding],
) {
    let Some(p) = pool else { return };
    let fj = serde_json::to_string(findings).unwrap_or_else(|_| "[]".into());
    let _ = sqlx::query(
        r#"INSERT INTO cicd_scan_events (provider, ref_name, commit_sha, blocked, findings_json) VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(provider)
    .bind(ref_name)
    .bind(sha)
    .bind(blocked)
    .bind(&fj)
    .execute(p)
    .await;
}

fn gate_response(blocked: bool, findings: &[CicdFinding]) -> Response {
    let body = json!({
        "ok": !blocked,
        "blocked": blocked,
        "findings": findings,
        "weissman_gate": "phase6_cicd_ast",
    });
    if blocked {
        (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
    } else {
        (StatusCode::OK, axum::Json(body)).into_response()
    }
}

/// GitHub `push` webhook: scans changed paths (raw.githubusercontent.com).
pub async fn github_push_hook(
    pool: Option<Arc<PgPool>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let secret = std::env::var("WEISSMAN_CICD_WEBHOOK_SECRET").unwrap_or_default();
    if secret.trim().is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "WEISSMAN_CICD_WEBHOOK_SECRET not configured"})),
        )
            .into_response();
    }
    let sig = headers
        .get("x-hub-signature-256")
        .and_then(|h| h.to_str().ok());
    if !verify_github_signature(&secret, sig, &body) {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "bad signature"})),
        )
            .into_response();
    }
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": "invalid json"})),
            )
                .into_response();
        }
    };
    let event = headers
        .get("x-github-event")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if event != "push" {
        return (
            StatusCode::OK,
            axum::Json(json!({"ok": true, "ignored": event})),
        )
            .into_response();
    }
    let full_name = payload
        .get("repository")
        .and_then(|r| r.get("full_name"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let sha = payload
        .get("after")
        .and_then(|x| x.as_str())
        .or_else(|| {
            payload
                .get("head_commit")
                .and_then(|h| h.get("id"))
                .and_then(|x| x.as_str())
        })
        .unwrap_or("");
    let ref_name = payload.get("ref").and_then(|x| x.as_str()).unwrap_or("");
    if full_name.is_empty() || sha.is_empty() {
        return (
            StatusCode::OK,
            axum::Json(json!({"ok": true, "detail": "no repo/sha"})),
        )
            .into_response();
    }
    let token = std::env::var("WEISSMAN_GITHUB_TOKEN").unwrap_or_default();
    let mut paths: Vec<String> = Vec::new();
    if let Some(commits) = payload.get("commits").and_then(|c| c.as_array()) {
        for c in commits {
            for k in ["added", "modified"] {
                if let Some(arr) = c.get(k).and_then(|x| x.as_array()) {
                    for p in arr {
                        if let Some(s) = p.as_str() {
                            if !s.is_empty() {
                                paths.push(s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths.truncate(25);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("Weissman-CICD-Gate/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut files: Vec<(String, String)> = Vec::new();
    for p in paths {
        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}",
            full_name, sha, p
        );
        let mut req = client.get(&url);
        if !token.trim().is_empty() {
            req = req.header("Authorization", format!("Bearer {}", token.trim()));
        }
        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                if let Ok(txt) = resp.text().await {
                    files.push((p, txt));
                }
            }
        }
    }

    let findings = cicd_ast_scan::scan_many_files(&files);
    let blocked = cicd_ast_scan::has_critical(&findings);
    log_cicd_event(pool.as_deref(), "github", ref_name, sha, blocked, &findings).await;
    gate_response(blocked, &findings)
}

/// GitLab `Push Hook` — expects `X-Gitlab-Token`; uses project path + checkout ref to fetch raw files from list in payload.
pub async fn gitlab_push_hook(
    pool: Option<Arc<PgPool>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let tok = std::env::var("WEISSMAN_GITLAB_WEBHOOK_SECRET").unwrap_or_default();
    if !verify_gitlab_token(&headers, tok.trim()) {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "bad token"})),
        )
            .into_response();
    }
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": "invalid json"})),
            )
                .into_response();
        }
    };
    let ref_name = payload.get("ref").and_then(|x| x.as_str()).unwrap_or("");
    let sha = payload
        .get("checkout_sha")
        .and_then(|x| x.as_str())
        .or_else(|| payload.get("after").and_then(|x| x.as_str()))
        .unwrap_or("");
    let path_ns = payload
        .get("project")
        .and_then(|p| p.get("path_with_namespace"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let host =
        std::env::var("WEISSMAN_GITLAB_BASE_URL").unwrap_or_else(|_| "https://gitlab.com".into());
    let host = host.trim_end_matches('/');
    let pat = std::env::var("WEISSMAN_GITLAB_TOKEN").unwrap_or_default();
    let mut paths: Vec<String> = Vec::new();
    if let Some(commits) = payload.get("commits").and_then(|c| c.as_array()) {
        for c in commits {
            for k in ["added", "modified"] {
                if let Some(arr) = c.get(k).and_then(|x| x.as_array()) {
                    for p in arr {
                        if let Some(s) = p.as_str() {
                            paths.push(s.to_string());
                        }
                    }
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths.truncate(25);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let pid = payload
        .get("project")
        .and_then(|pr| pr.get("id"))
        .and_then(|x| x.as_i64())
        .unwrap_or(0);
    let mut files: Vec<(String, String)> = Vec::new();
    for p in paths {
        let enc_path = urlencoding::encode(&p);
        let url2 = if pid > 0 {
            format!(
                "{}/api/v4/projects/{}/repository/files/{}/raw?ref={}",
                host,
                pid,
                enc_path,
                urlencoding::encode(sha)
            )
        } else {
            format!(
                "{}/api/v4/projects/{}/repository/files/{}/raw?ref={}",
                host,
                urlencoding::encode(path_ns),
                enc_path,
                urlencoding::encode(sha)
            )
        };
        let mut req = client.get(&url2);
        if !pat.is_empty() {
            req = req.header("PRIVATE-TOKEN", pat.trim());
        }
        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                if let Ok(txt) = resp.text().await {
                    files.push((p, txt));
                }
            }
        }
    }
    let findings = cicd_ast_scan::scan_many_files(&files);
    let blocked = cicd_ast_scan::has_critical(&findings);
    log_cicd_event(pool.as_deref(), "gitlab", ref_name, sha, blocked, &findings).await;
    gate_response(blocked, &findings)
}

/// Bitbucket `repo:push` — bearer `WEISSMAN_BITBUCKET_WEBHOOK_SECRET`; fetch changed files via raw URLs if token present.
pub async fn bitbucket_push_hook(
    pool: Option<Arc<PgPool>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let sec = std::env::var("WEISSMAN_BITBUCKET_WEBHOOK_SECRET").unwrap_or_default();
    if !verify_bitbucket_secret(&headers, sec.trim()) {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "bad auth"})),
        )
            .into_response();
    }
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": "invalid json"})),
            )
                .into_response();
        }
    };
    let mut paths: Vec<String> = Vec::new();
    let mut sha = String::new();
    let mut ref_name = String::new();
    if let Some(changes) = payload
        .get("push")
        .and_then(|p| p.get("changes"))
        .and_then(|c| c.as_array())
    {
        for ch in changes {
            ref_name = ch
                .get("new")
                .and_then(|n| n.get("name"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            sha = ch
                .get("new")
                .and_then(|n| n.get("target"))
                .and_then(|t| t.get("hash"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if let Some(commits) = ch.get("commits").and_then(|c| c.as_array()) {
                for c in commits {
                    if let Some(h) = c.get("hash").and_then(|x| x.as_str()) {
                        sha = h.into();
                    }
                }
            }
        }
    }
    if let Some(chg) = payload
        .get("push")
        .and_then(|p| p.get("changes"))
        .and_then(|c| c.get(0))
    {
        if let Some(commits) = chg.get("commits").and_then(|c| c.as_array()) {
            for c in commits {
                for k in ["added", "modified"] {
                    if let Some(files) = c.get(k).and_then(|x| x.as_array()) {
                        for f in files {
                            if let Some(s) = f.get("path").and_then(|x| x.as_str()) {
                                paths.push(s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths.truncate(25);
    let workspace = payload
        .get("repository")
        .and_then(|r| r.get("full_name"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let bb_user = std::env::var("WEISSMAN_BITBUCKET_USER").unwrap_or_default();
    let bb_app = std::env::var("WEISSMAN_BITBUCKET_APP_PASSWORD").unwrap_or_default();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let mut files: Vec<(String, String)> = Vec::new();
    for p in paths {
        let url = format!(
            "https://api.bitbucket.org/2.0/repositories/{}/src/{}/{}",
            workspace, sha, p
        );
        let mut req = client.get(&url);
        if !bb_user.is_empty() && !bb_app.is_empty() {
            req = req.basic_auth(bb_user.trim(), Some(bb_app.trim()));
        }
        if let Ok(resp) = req.send().await {
            if resp.status().is_success() {
                if let Ok(txt) = resp.text().await {
                    files.push((p, txt));
                }
            }
        }
    }
    let findings = cicd_ast_scan::scan_many_files(&files);
    let blocked = cicd_ast_scan::has_critical(&findings);
    log_cicd_event(
        pool.as_deref(),
        "bitbucket",
        &ref_name,
        &sha,
        blocked,
        &findings,
    )
    .await;
    gate_response(blocked, &findings)
}

#[derive(Deserialize)]
pub struct GenericFile {
    pub path: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct GenericScanBody {
    pub files: Vec<GenericFile>,
    #[serde(default)]
    pub r#ref: String,
    #[serde(default)]
    pub commit_sha: String,
}

/// Universal CI: POST JSON `{ "files": [{"path":"...","content":"..."}], "ref": "", "commit_sha": "" }` with `Authorization: Bearer <WEISSMAN_CICD_BEARER_TOKEN>`.
pub async fn generic_cicd_scan(
    pool: Option<Arc<PgPool>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let expected = std::env::var("WEISSMAN_CICD_BEARER_TOKEN").unwrap_or_default();
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let ok = format!("Bearer {}", expected.trim());
    if expected.trim().is_empty() || auth != ok {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    let req: GenericScanBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": format!("json: {}", e)})),
            )
                .into_response();
        }
    };
    let pairs: Vec<(String, String)> = req
        .files
        .into_iter()
        .map(|f| (f.path, f.content))
        .take(100)
        .collect();
    let findings = cicd_ast_scan::scan_many_files(&pairs);
    let blocked = cicd_ast_scan::has_critical(&findings);
    log_cicd_event(
        pool.as_deref(),
        "generic",
        &req.r#ref,
        &req.commit_sha,
        blocked,
        &findings,
    )
    .await;
    gate_response(blocked, &findings)
}
