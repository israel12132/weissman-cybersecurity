//! Bitbucket Cloud delivery for auto-heal: create a heal branch + commit the applied files via the
//! `/src` endpoint, then open a Pull Request (REST v2). Mirrors `gitlab_heal`'s resilience harness
//! (shared pooled client + retry/backoff), authenticating with a Bitbucket **access token**
//! (`Authorization: Bearer`). Reuses the single verified `changed_files` artifact, so the PR is a real
//! applied fix. The slug is `workspace/repo`.

use reqwest::header::HeaderMap;
use reqwest::{Response, StatusCode};
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;

const API_BASE: &str = "https://api.bitbucket.org/2.0";
const TIMEOUT_SECS: u64 = 30;
const MAX_ATTEMPTS: u32 = 6;
const INITIAL_BACKOFF_MS: u64 = 400;
const MAX_BACKOFF_MS: u64 = 30_000;

static BB_HTTP: OnceLock<reqwest::Client> = OnceLock::new();

fn bb_client() -> &'static reqwest::Client {
    BB_HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .pool_max_idle_per_host(16)
            .user_agent("Weissman-CNAPP-AutoHeal/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Split a `workspace/repo` slug into its two parts. A slug that isn't exactly two non-empty
/// segments is rejected (`None`) rather than guessed, so a misconfigured 3-part slug can't
/// silently target the wrong repo.
#[must_use]
pub fn split_workspace_repo(slug: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = slug
        .trim()
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.trim().is_empty())
        .collect();
    if parts.len() != 2 {
        return None;
    }
    Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
}

/// Percent-encode a single URL path/query segment (everything but RFC 3986 unreserved), so a branch
/// or path containing `/`, `#`, `?`, space, `&`, etc. stays one segment instead of injecting routing.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

fn backoff(attempt: u32) -> Duration {
    let exp = INITIAL_BACKOFF_MS.saturating_mul(1u64 << attempt.saturating_sub(1).min(12));
    let ms = exp.min(MAX_BACKOFF_MS);
    let jitter = rand::random::<u64>() % ms.min(500).max(1);
    Duration::from_millis(ms.saturating_add(jitter))
}

fn transient(status: StatusCode, headers: &HeaderMap) -> bool {
    let c = status.as_u16();
    if matches!(c, 408 | 429 | 500 | 502 | 503 | 504) {
        return true;
    }
    if status == StatusCode::FORBIDDEN {
        if let Some(v) = headers.get("x-ratelimit-remaining") {
            if v.to_str().ok() == Some("0") {
                return true;
            }
        }
    }
    false
}

/// Statuses safe to retry for a NON-idempotent write — the request was definitely not applied.
fn write_retryable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429)
}

/// `idempotent` requests retry on any transient status AND network error; writes retry only on
/// 429/408 and never on a network error, so a retry can't duplicate a `/src` commit or a PR.
async fn send_with_retry(
    idempotent: bool,
    mut make: impl FnMut() -> reqwest::RequestBuilder,
) -> Result<Response, String> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match make().send().await {
            Ok(r) => {
                if r.status().is_success() {
                    return Ok(r);
                }
                let status = r.status();
                let headers = r.headers().clone();
                let body = r.text().await.unwrap_or_default();
                let retryable = if idempotent {
                    transient(status, &headers)
                } else {
                    write_retryable(status)
                };
                if retryable && attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(backoff(attempt)).await;
                    continue;
                }
                return Err(format!("Bitbucket API {}: {}", status, body.chars().take(400).collect::<String>()));
            }
            Err(e) => {
                if idempotent && attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(backoff(attempt)).await;
                    continue;
                }
                return Err(format!("Bitbucket network error after {attempt}: {e}"));
            }
        }
    }
}

async fn json_body(resp: Response, ctx: &str) -> Result<Value, String> {
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("{ctx}: read body: {e}"))?;
    if !status.is_success() {
        return Err(format!("{ctx}: Bitbucket {} {}", status, text.chars().take(400).collect::<String>()));
    }
    serde_json::from_str(&text).map_err(|e| format!("{ctx}: invalid JSON: {e}"))
}

/// Current head commit of `base` branch (the `parents` for the new branch's commit), if resolvable.
async fn base_branch_head(ws: &str, repo: &str, base: &str, token: &str) -> Option<String> {
    let url = format!(
        "{API_BASE}/repositories/{}/{}/refs/branches/{}",
        pct(ws),
        pct(repo),
        pct(base)
    );
    let resp = bb_client()
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let j: Value = resp.json().await.ok()?;
    j.get("target")
        .and_then(|t| t.get("hash"))
        .and_then(|h| h.as_str())
        .map(String::from)
}

/// Result of a Bitbucket heal PR attempt.
pub struct BitbucketPrOutcome {
    pub branch_name: String,
    pub pr_url: Option<String>,
    pub pr_id: Option<i64>,
    pub error: Option<String>,
}

fn err(branch_name: String, msg: impl Into<String>) -> BitbucketPrOutcome {
    BitbucketPrOutcome { branch_name, pr_url: None, pr_id: None, error: Some(msg.into()) }
}

/// Create a heal branch, commit `files` in one commit (`/src`), then open a Pull Request.
pub async fn create_branch_commit_and_pr(
    token: &str,
    repo_slug: &str,
    base_branch: &str,
    finding_id: &str,
    files: Vec<(String, String)>,
    title: &str,
    description: &str,
) -> BitbucketPrOutcome {
    let branch_name = format!(
        "weissman-heal-{}",
        crate::heal_channels::safe_branch_suffix(finding_id)
    );
    let Some((ws, repo)) = split_workspace_repo(repo_slug) else {
        return err(branch_name, "invalid Bitbucket slug (expected workspace/repo)");
    };
    if files.is_empty() {
        return err(branch_name, "no files to commit");
    }
    for (path, _) in &files {
        let p = path.trim_start_matches('/');
        if p.is_empty() || p.contains("..") {
            return err(branch_name, format!("invalid file path: {path:?}"));
        }
    }

    // Commit via the /src endpoint (multipart/form). File fields are `path=content`; the heal branch
    // is cut from `parents` (the base head). Resolving the base head is REQUIRED — proceeding without
    // it would commit against the default branch and produce a whole-tree PR, so treat it as an error.
    let Some(parent) = base_branch_head(&ws, &repo, base_branch, token).await else {
        return err(
            branch_name,
            format!("could not resolve base branch head for '{base_branch}'"),
        );
    };
    let src_url = format!("{API_BASE}/repositories/{}/{}/src", pct(&ws), pct(&repo));
    let mut form: Vec<(String, String)> = Vec::with_capacity(files.len() + 3);
    form.push(("branch".to_string(), branch_name.clone()));
    form.push(("parents".to_string(), parent));
    form.push((
        "message".to_string(),
        format!("Security remediation from Weissman CNAPP ({finding_id})"),
    ));
    for (path, content) in &files {
        form.push((path.trim_start_matches('/').to_string(), content.clone()));
    }
    if let Err(e) = send_with_retry(false, || {
        bb_client()
            .post(&src_url)
            .header("Authorization", format!("Bearer {token}"))
            .form(&form)
    })
    .await
    {
        return err(branch_name, format!("commit: {e}"));
    }

    // Open the pull request.
    let pr_url = format!("{API_BASE}/repositories/{}/{}/pullrequests", pct(&ws), pct(&repo));
    let pr_body = serde_json::json!({
        "title": title,
        "description": description,
        "source": { "branch": { "name": branch_name } },
        "destination": { "branch": { "name": base_branch } },
        "close_source_branch": true,
    });
    match send_with_retry(false, || {
        bb_client()
            .post(&pr_url)
            .header("Authorization", format!("Bearer {token}"))
            .json(&pr_body)
    })
    .await
    {
        Ok(resp) => match json_body(resp, "open PR").await {
            Ok(j) => BitbucketPrOutcome {
                branch_name,
                pr_url: j
                    .get("links")
                    .and_then(|l| l.get("html"))
                    .and_then(|h| h.get("href"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                pr_id: j.get("id").and_then(|v| v.as_i64()),
                error: None,
            },
            Err(e) => err(branch_name, e),
        },
        Err(e) => err(branch_name, format!("open PR: {e}")),
    }
}

/// Decline an auto-opened Bitbucket PR (revert).
pub async fn decline_pull_request(
    token: &str,
    repo_slug: &str,
    pr_id: i64,
) -> Result<(), String> {
    let (ws, repo) = split_workspace_repo(repo_slug)
        .ok_or_else(|| "invalid Bitbucket slug".to_string())?;
    let url = format!(
        "{API_BASE}/repositories/{}/{}/pullrequests/{pr_id}/decline",
        pct(&ws),
        pct(&repo)
    );
    let resp = send_with_retry(true, || {
        bb_client()
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
    })
    .await?;
    let _ = resp.bytes().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_split() {
        assert_eq!(split_workspace_repo("acme/api"), Some(("acme".into(), "api".into())));
        assert_eq!(split_workspace_repo("/acme/api/"), Some(("acme".into(), "api".into())));
        assert_eq!(split_workspace_repo("noslash"), None);
        assert_eq!(split_workspace_repo(""), None);
        // A 3-part slug is rejected, not silently mis-parsed into ("ws","proj/repo").
        assert_eq!(split_workspace_repo("ws/proj/repo"), None);
    }

    #[test]
    fn pct_encodes_ref_and_path_segments() {
        assert_eq!(pct("release/2.0"), "release%2F2.0");
        assert_eq!(pct("feat#1"), "feat%231");
        assert_eq!(pct("a b"), "a%20b");
        assert_eq!(pct("src/app.js"), "src%2Fapp.js");
        // Unreserved chars pass through untouched.
        assert_eq!(pct("safe-name.1_x~"), "safe-name.1_x~");
    }
}
