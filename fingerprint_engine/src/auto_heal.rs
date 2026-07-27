//! CNAPP Layer 3: Autonomous remediation. Creates branch + PR via GitHub API from generated patches.
//! 200% verification opens the PR only after Docker sandbox proves the exploit no longer succeeds.

use reqwest::header::HeaderMap;
use reqwest::{Response, StatusCode};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::Duration;

const GITHUB_API: &str = "https://api.github.com";
const TIMEOUT_SECS: u64 = 30;
const MAX_GITHUB_ATTEMPTS: u32 = 8;
const INITIAL_BACKOFF_MS: u64 = 400;
const MAX_BACKOFF_MS: u64 = 60_000;
const ERROR_BODY_MAX_CHARS: usize = 12_000;

/// Shared HTTP client for all GitHub API traffic (connection reuse, bounded idle pool).
static GITHUB_HTTP: OnceLock<reqwest::Client> = OnceLock::new();

fn github_client() -> &'static reqwest::Client {
    GITHUB_HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .pool_max_idle_per_host(32)
            .user_agent("Weissman-CNAPP-AutoHeal/1.0")
            .build()
            .unwrap_or_else(|e| {
                tracing::error!(target: "auto_heal", error = %e, "GitHub reqwest client build failed; using default client");
                reqwest::Client::new()
            })
    })
}

fn backoff_with_jitter(attempt: u32) -> Duration {
    let exp = INITIAL_BACKOFF_MS.saturating_mul(1u64 << attempt.saturating_sub(1).min(12));
    let ms = exp.min(MAX_BACKOFF_MS);
    let jitter_cap = ms.min(500).max(1);
    let jitter = rand::random::<u64>() % jitter_cap;
    Duration::from_millis(ms.saturating_add(jitter))
}

fn retry_after_from_headers(headers: &HeaderMap) -> Option<Duration> {
    if let Some(v) = headers.get(reqwest::header::RETRY_AFTER) {
        if let Ok(s) = v.to_str() {
            if let Ok(secs) = s.parse::<u64>() {
                return Some(Duration::from_secs(secs.min(3600).max(1)));
            }
        }
    }
    if let Some(v) = headers.get("x-ratelimit-reset") {
        if let Ok(s) = v.to_str() {
            if let Ok(reset) = s.parse::<i64>() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?
                    .as_secs() as i64;
                let wait = reset.saturating_sub(now).max(1).min(3600);
                return Some(Duration::from_secs(wait as u64));
            }
        }
    }
    None
}

fn github_transient_status(status: StatusCode, body_lower: &str, headers: &HeaderMap) -> bool {
    let code = status.as_u16();
    if matches!(code, 408 | 429 | 500 | 502 | 503 | 504) {
        return true;
    }
    if status == StatusCode::FORBIDDEN {
        if body_lower.contains("rate limit")
            || body_lower.contains("abuse detection")
            || body_lower.contains("secondary rate")
        {
            return true;
        }
        if let Some(remaining) = headers.get("x-ratelimit-remaining") {
            if remaining.to_str().ok() == Some("0") {
                return true;
            }
        }
    }
    false
}

fn format_github_api_error(status: StatusCode, body: &str) -> String {
    let trimmed = truncate_for_error(body);
    format!("GitHub API {}: {}", status, trimmed)
}

fn truncate_for_error(s: &str) -> String {
    if s.len() <= ERROR_BODY_MAX_CHARS {
        return s.to_string();
    }
    format!(
        "{}… (truncated, {} bytes total)",
        &s[..ERROR_BODY_MAX_CHARS],
        s.len()
    )
}

/// Sends a request built by `make` on each attempt; retries rate limits and transient failures.
async fn github_send_with_retry(
    mut make: impl FnMut() -> reqwest::RequestBuilder,
) -> Result<Response, String> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let resp = match make().send().await {
            Ok(r) => r,
            Err(e) => {
                if attempt >= MAX_GITHUB_ATTEMPTS {
                    return Err(format!(
                        "GitHub network error after {attempt} attempts: {e}"
                    ));
                }
                tokio::time::sleep(backoff_with_jitter(attempt)).await;
                continue;
            }
        };

        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }

        let headers = resp.headers().clone();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|e| format!("(failed to read error body: {e})"));
        let body_lower = body.to_ascii_lowercase();

        let transient = github_transient_status(status, &body_lower, &headers);
        if transient && attempt < MAX_GITHUB_ATTEMPTS {
            let sleep_d =
                retry_after_from_headers(&headers).unwrap_or_else(|| backoff_with_jitter(attempt));
            tokio::time::sleep(sleep_d).await;
            continue;
        }

        return Err(format_github_api_error(status, &body));
    }
}

async fn github_json_value(resp: Response, context: &str) -> Result<Value, String> {
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("{context}: read body: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "{context}: {}",
            format_github_api_error(status, &text)
        ));
    }
    serde_json::from_str(&text).map_err(|e| {
        format!(
            "{context}: invalid JSON ({}): {}",
            e,
            truncate_for_error(&text)
        )
    })
}

/// Result of create-pr attempt.
pub struct HealRequestResult {
    pub branch_name: String,
    pub pr_url: Option<String>,
    pub pr_number: Option<i64>,
    pub diff_summary: String,
    pub error: Option<String>,
}

/// Branch updated on GitHub with one or more file blobs; PR not opened yet.
pub struct HealCommitOutcome {
    pub branch_name: String,
    pub commit_sha: String,
    pub diff_summary: String,
    pub error: Option<String>,
}

fn validate_heal_files(files: &[(String, String)]) -> Result<(), String> {
    if files.is_empty() {
        return Err("no files supplied for heal commit".into());
    }
    let mut seen = HashSet::new();
    for (path, _content) in files {
        let p = path.trim();
        if p.is_empty() || p.contains("..") {
            return Err(format!("invalid heal file path: {path:?}"));
        }
        if !seen.insert(p.to_string()) {
            return Err(format!("duplicate heal file path: {p}"));
        }
    }
    Ok(())
}

fn diff_summary_from_files(files: &[(String, String)]) -> String {
    let mut parts = Vec::new();
    let mut budget = 500usize;
    for (path, content) in files {
        if budget == 0 {
            break;
        }
        let header = format!("{}:", path);
        let take = budget.saturating_sub(header.len()).min(200).max(0);
        let snippet: String = content.chars().take(take).collect();
        let piece = format!("{header}\n{snippet}");
        budget = budget.saturating_sub(piece.len().min(budget));
        parts.push(piece);
    }
    parts.join("\n---\n")
}

/// Create heal branch and commit one or more files in a single tree; does **not** open a pull request.
pub async fn create_branch_and_commit_only(
    token: &str,
    repo_slug: &str,
    base_branch: &str,
    finding_id: &str,
    files: Vec<(String, String)>,
    commit_message: Option<&str>,
) -> HealCommitOutcome {
    let branch_name = format!("weissman-heal-{}", finding_id.replace(['/', '\\'], "-"));
    let msg = commit_message.unwrap_or("Security remediation from Weissman CNAPP");
    let diff_summary = diff_summary_from_files(&files);

    if let Err(e) = validate_heal_files(&files) {
        return HealCommitOutcome {
            branch_name: branch_name.clone(),
            commit_sha: String::new(),
            diff_summary,
            error: Some(e),
        };
    }

    let client = github_client();
    let auth = format!("Bearer {}", token);

    let get_ref = format!(
        "{}/repos/{}/git/ref/heads/{}",
        GITHUB_API, repo_slug, base_branch
    );
    let ref_json = match github_send_with_retry(|| {
        client
            .get(&get_ref)
            .header("Authorization", &auth)
            .header("Accept", "application/vnd.github+json")
    })
    .await
    {
        Ok(r) => match github_json_value(r, "get ref").await {
            Ok(j) => j,
            Err(e) => {
                return HealCommitOutcome {
                    branch_name: branch_name.clone(),
                    commit_sha: String::new(),
                    diff_summary,
                    error: Some(e),
                };
            }
        },
        Err(e) => {
            return HealCommitOutcome {
                branch_name: branch_name.clone(),
                commit_sha: String::new(),
                diff_summary,
                error: Some(e),
            };
        }
    };

    let Some(sha) = ref_json
        .get("object")
        .and_then(|o| o.get("sha"))
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
    else {
        return HealCommitOutcome {
            branch_name: branch_name.clone(),
            commit_sha: String::new(),
            diff_summary,
            error: Some(format!(
                "get ref: missing object.sha in response: {}",
                truncate_for_error(&ref_json.to_string())
            )),
        };
    };
    let base_sha = sha.to_string();

    let create_ref_url = format!("{}/repos/{}/git/refs", GITHUB_API, repo_slug);
    let create_ref_body =
        serde_json::json!({ "ref": format!("refs/heads/{}", branch_name), "sha": base_sha });
    match github_send_with_retry(|| {
        client
            .post(&create_ref_url)
            .header("Authorization", &auth)
            .header("Accept", "application/vnd.github+json")
            .json(&create_ref_body)
    })
    .await
    {
        Ok(r) => {
            let _ = r.bytes().await;
        }
        Err(e) => {
            return HealCommitOutcome {
                branch_name: branch_name.clone(),
                commit_sha: String::new(),
                diff_summary,
                error: Some(format!("create ref (branch): {e}")),
            };
        }
    }

    let blob_url = format!("{}/repos/{}/git/blobs", GITHUB_API, repo_slug);
    let mut tree_entries = Vec::with_capacity(files.len());
    for (path, content) in &files {
        let blob_resp = match github_send_with_retry(|| {
            client
                .post(&blob_url)
                .header("Authorization", &auth)
                .header("Accept", "application/vnd.github+json")
                .json(&serde_json::json!({ "content": content, "encoding": "utf-8" }))
        })
        .await
        {
            Ok(r) => r,
            Err(e) => {
                return HealCommitOutcome {
                    branch_name: branch_name.clone(),
                    commit_sha: String::new(),
                    diff_summary,
                    error: Some(format!("create blob for {path:?}: {e}")),
                };
            }
        };
        let blob_json = match github_json_value(blob_resp, "create blob").await {
            Ok(j) => j,
            Err(e) => {
                return HealCommitOutcome {
                    branch_name: branch_name.clone(),
                    commit_sha: String::new(),
                    diff_summary,
                    error: Some(format!("{path}: {e}")),
                };
            }
        };
        let Some(blob_sha) = blob_json
            .get("sha")
            .and_then(|s| s.as_str())
            .filter(|s| !s.is_empty())
        else {
            return HealCommitOutcome {
                branch_name: branch_name.clone(),
                commit_sha: String::new(),
                diff_summary,
                error: Some(format!(
                    "{path}: create blob response missing sha: {}",
                    truncate_for_error(&blob_json.to_string())
                )),
            };
        };
        tree_entries.push(serde_json::json!({
            "path": path.trim_start_matches('/'),
            "mode": "100644",
            "type": "blob",
            "sha": blob_sha,
        }));
    }

    let tree_url = format!("{}/repos/{}/git/trees", GITHUB_API, repo_slug);
    let tree_body = serde_json::json!({
        "base_tree": base_sha,
        "tree": tree_entries,
    });
    let tree_resp = match github_send_with_retry(|| {
        client
            .post(&tree_url)
            .header("Authorization", &auth)
            .header("Accept", "application/vnd.github+json")
            .json(&tree_body)
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return HealCommitOutcome {
                branch_name: branch_name.clone(),
                commit_sha: String::new(),
                diff_summary,
                error: Some(format!("create tree: {e}")),
            };
        }
    };
    let tree_json = match github_json_value(tree_resp, "create tree").await {
        Ok(j) => j,
        Err(e) => {
            return HealCommitOutcome {
                branch_name: branch_name.clone(),
                commit_sha: String::new(),
                diff_summary,
                error: Some(e),
            };
        }
    };
    let Some(tree_sha) = tree_json
        .get("sha")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
    else {
        return HealCommitOutcome {
            branch_name: branch_name.clone(),
            commit_sha: String::new(),
            diff_summary,
            error: Some(format!(
                "create tree: missing sha: {}",
                truncate_for_error(&tree_json.to_string())
            )),
        };
    };

    let commit_url = format!("{}/repos/{}/git/commits", GITHUB_API, repo_slug);
    let commit_body = serde_json::json!({
        "message": msg,
        "tree": tree_sha,
        "parents": [base_sha],
    });
    let commit_resp = match github_send_with_retry(|| {
        client
            .post(&commit_url)
            .header("Authorization", &auth)
            .header("Accept", "application/vnd.github+json")
            .json(&commit_body)
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return HealCommitOutcome {
                branch_name: branch_name.clone(),
                commit_sha: String::new(),
                diff_summary,
                error: Some(format!("create commit: {e}")),
            };
        }
    };
    let commit_json = match github_json_value(commit_resp, "create commit").await {
        Ok(j) => j,
        Err(e) => {
            return HealCommitOutcome {
                branch_name: branch_name.clone(),
                commit_sha: String::new(),
                diff_summary,
                error: Some(e),
            };
        }
    };
    let Some(commit_sha) = commit_json
        .get("sha")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
    else {
        return HealCommitOutcome {
            branch_name: branch_name.clone(),
            commit_sha: String::new(),
            diff_summary,
            error: Some(format!(
                "create commit: missing sha: {}",
                truncate_for_error(&commit_json.to_string())
            )),
        };
    };
    let commit_sha = commit_sha.to_string();

    let update_ref_url = format!(
        "{}/repos/{}/git/refs/heads/{}",
        GITHUB_API, repo_slug, branch_name
    );
    match github_send_with_retry(|| {
        client
            .patch(&update_ref_url)
            .header("Authorization", &auth)
            .header("Accept", "application/vnd.github+json")
            .json(&serde_json::json!({ "sha": commit_sha }))
    })
    .await
    {
        Ok(r) => {
            let _ = r.bytes().await;
        }
        Err(e) => {
            return HealCommitOutcome {
                branch_name: branch_name.clone(),
                commit_sha,
                diff_summary,
                error: Some(format!("update ref: {e}")),
            };
        }
    }

    HealCommitOutcome {
        branch_name,
        commit_sha,
        diff_summary,
        error: None,
    }
}

/// Open a GitHub PR with a caller-supplied title + body. The title/body are built from the
/// real `VerificationResult` (see `auto_heal_job`) so the PR never over-claims: it states the
/// actual verdict, health, exploit before/after codes, and the files that changed.
pub async fn open_pull_request(
    token: &str,
    repo_slug: &str,
    base_branch: &str,
    head_branch: &str,
    title: &str,
    body: &str,
) -> Result<(Option<String>, Option<i64>), String> {
    let client = github_client();
    let auth = format!("Bearer {}", token);
    let pr_url_post = format!("{}/repos/{}/pulls", GITHUB_API, repo_slug);
    let pr_body = serde_json::json!({
        "title": title,
        "head": head_branch,
        "base": base_branch,
        "body": body,
    });

    let pr_resp = github_send_with_retry(|| {
        client
            .post(&pr_url_post)
            .header("Authorization", &auth)
            .header("Accept", "application/vnd.github+json")
            .json(&pr_body)
    })
    .await?;

    let p = github_json_value(pr_resp, "create pull").await?;
    Ok((
        p.get("html_url").and_then(|u| u.as_str()).map(String::from),
        p.get("number").and_then(|n| n.as_i64()),
    ))
}

/// Merge an auto-opened remediation PR (policy-driven auto-merge). Best-effort: returns `Ok(true)`
/// only when GitHub confirms `merged: true`. Uses the squash method for a clean single commit.
pub async fn merge_pull_request(
    token: &str,
    repo_slug: &str,
    pr_number: i64,
    commit_title: &str,
) -> Result<bool, String> {
    let client = github_client();
    let auth = format!("Bearer {}", token);
    let merge_url = format!(
        "{}/repos/{}/pulls/{}/merge",
        GITHUB_API, repo_slug, pr_number
    );
    let resp = github_send_with_retry(|| {
        client
            .put(&merge_url)
            .header("Authorization", &auth)
            .header("Accept", "application/vnd.github+json")
            .json(&serde_json::json!({ "merge_method": "squash", "commit_title": commit_title }))
    })
    .await?;
    let status = resp.status();
    let bytes = resp.bytes().await.unwrap_or_default();
    let merged = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("merged").and_then(|m| m.as_bool()))
        .unwrap_or(false);
    Ok(status.is_success() && merged)
}

/// Close an auto-opened remediation PR (revert). Optionally deletes the heal branch.
pub async fn close_pull_request(
    token: &str,
    repo_slug: &str,
    pr_number: i64,
    delete_branch: Option<&str>,
) -> Result<(), String> {
    let client = github_client();
    let auth = format!("Bearer {}", token);
    let patch_url = format!("{}/repos/{}/pulls/{}", GITHUB_API, repo_slug, pr_number);
    let resp = github_send_with_retry(|| {
        client
            .patch(&patch_url)
            .header("Authorization", &auth)
            .header("Accept", "application/vnd.github+json")
            .json(&serde_json::json!({ "state": "closed" }))
    })
    .await?;
    let _ = resp.bytes().await;

    if let Some(branch) = delete_branch.filter(|b| !b.trim().is_empty()) {
        let del_url = format!(
            "{}/repos/{}/git/refs/heads/{}",
            GITHUB_API, repo_slug, branch
        );
        // Best-effort branch cleanup — a failure here doesn't fail the revert.
        if let Ok(r) = github_send_with_retry(|| {
            client
                .delete(&del_url)
                .header("Authorization", &auth)
                .header("Accept", "application/vnd.github+json")
        })
        .await
        {
            let _ = r.bytes().await;
        }
    }
    Ok(())
}

/// Resolve the GitHub token for a tenant's PR automation without requiring it per request.
///
/// Precedence: the tenant's **GitHub integration** saved in the UI (Integration Manager →
/// "GitHub PR"), which lives encrypted in the `integrations_registry` (decrypted via the
/// integrations vault); then the deployment env (`WEISSMAN_GITHUB_TOKEN` / `GITHUB_TOKEN`).
/// Returns `None` when nothing is configured. The plaintext is only ever materialized here,
/// in-memory, to authenticate the GitHub API call — never logged or persisted.
pub async fn github_token_for_tenant(pool: &sqlx::PgPool, tenant_id: i64) -> Option<String> {
    if let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await {
        let raw: Option<String> = sqlx::query_scalar(
            "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'integrations_registry'",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
        let _ = tx.commit().await;
        if let Some(items) = raw.and_then(|s| serde_json::from_str::<Vec<Value>>(&s).ok()) {
            for item in &items {
                let id = item.get("id").and_then(Value::as_str).unwrap_or("");
                let category = item.get("category").and_then(Value::as_str).unwrap_or("");
                // The UI registers this integration as id "github" / "GitHub PR".
                if id == "github" || category.eq_ignore_ascii_case("source_control") {
                    if let Some(cfg) = item.get("config") {
                        let decrypted = crate::soar::integrations_vault::decrypt_config(cfg);
                        if let Some(tok) = decrypted.get("token").and_then(Value::as_str) {
                            let t = tok.trim();
                            if !t.is_empty() {
                                return Some(t.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    std::env::var("WEISSMAN_GITHUB_TOKEN")
        .ok()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Create a branch and PR from a single file (legacy); PR opened immediately after commit.
pub async fn create_branch_and_pr(
    token: &str,
    repo_slug: &str,
    base_branch: &str,
    finding_id: &str,
    patch_content: &str,
    file_path: Option<&str>,
    commit_message: Option<&str>,
) -> HealRequestResult {
    let path = file_path.unwrap_or("PATCH.txt").to_string();
    let c = create_branch_and_commit_only(
        token,
        repo_slug,
        base_branch,
        finding_id,
        vec![(path, patch_content.to_string())],
        commit_message,
    )
    .await;
    if let Some(e) = c.error {
        return HealRequestResult {
            branch_name: c.branch_name,
            pr_url: None,
            pr_number: None,
            diff_summary: c.diff_summary,
            error: Some(e),
        };
    }
    // Legacy / skip-sandbox path: the patch is committed as an advisory file and NOT proven,
    // so the PR text must not claim verification.
    let title = format!(
        "[Weissman CNAPP] Advisory remediation (sandbox skipped): {}",
        finding_id
    );
    let advisory_body = format!(
        "⚠️ Advisory patch for finding `{}`. The ephemeral-Docker verification was **skipped** \
         (`WEISSMAN_AUTOHEAL_SKIP_SANDBOX`), so this patch is **not proven** and is committed as an \
         advisory artifact rather than an applied fix. Review carefully before merging.",
        finding_id
    );
    match open_pull_request(
        token,
        repo_slug,
        base_branch,
        &c.branch_name,
        &title,
        &advisory_body,
    )
    .await
    {
        Ok((pr_url, pr_number)) => HealRequestResult {
            branch_name: c.branch_name,
            pr_url,
            pr_number,
            diff_summary: c.diff_summary,
            error: None,
        },
        Err(e) => HealRequestResult {
            branch_name: c.branch_name,
            pr_url: None,
            pr_number: None,
            diff_summary: c.diff_summary,
            error: Some(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};

    #[test]
    fn backoff_bounds_first_attempt() {
        // attempt=1: exp=400, ms=400, jitter_cap=400 => [400, 800)
        let ms = backoff_with_jitter(1).as_millis();
        assert!((400..800).contains(&ms), "attempt1 out of range: {ms}");
    }

    #[test]
    fn backoff_bounds_second_attempt() {
        // attempt=2: exp=800, ms=800, jitter_cap=500 => [800, 1300)
        let ms = backoff_with_jitter(2).as_millis();
        assert!((800..1300).contains(&ms), "attempt2 out of range: {ms}");
    }

    #[test]
    fn backoff_saturates_at_max() {
        // Large attempt saturates ms at MAX_BACKOFF_MS (60_000); jitter_cap=500 => [60000, 60500)
        let ms = backoff_with_jitter(20).as_millis();
        assert!(
            (60_000..60_500).contains(&ms),
            "saturated out of range: {ms}"
        );
    }

    #[test]
    fn retry_after_parses_seconds() {
        let mut h = HeaderMap::new();
        h.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(retry_after_from_headers(&h), Some(Duration::from_secs(120)));
    }

    #[test]
    fn retry_after_clamps_zero_to_one() {
        let mut h = HeaderMap::new();
        h.insert(RETRY_AFTER, HeaderValue::from_static("0"));
        assert_eq!(retry_after_from_headers(&h), Some(Duration::from_secs(1)));
    }

    #[test]
    fn retry_after_clamps_high_to_3600() {
        let mut h = HeaderMap::new();
        h.insert(RETRY_AFTER, HeaderValue::from_static("999999"));
        assert_eq!(
            retry_after_from_headers(&h),
            Some(Duration::from_secs(3600))
        );
    }

    #[test]
    fn retry_after_none_when_absent() {
        let h = HeaderMap::new();
        assert_eq!(retry_after_from_headers(&h), None);
    }

    #[test]
    fn transient_status_5xx_and_429() {
        let h = HeaderMap::new();
        for code in [408u16, 429, 500, 502, 503, 504] {
            let s = StatusCode::from_u16(code).unwrap();
            assert!(
                github_transient_status(s, "", &h),
                "code {code} should be transient"
            );
        }
    }

    #[test]
    fn transient_status_ok_is_not_transient() {
        let h = HeaderMap::new();
        assert!(!github_transient_status(StatusCode::OK, "", &h));
        assert!(!github_transient_status(StatusCode::NOT_FOUND, "", &h));
    }

    #[test]
    fn transient_status_forbidden_rate_limit_body() {
        let h = HeaderMap::new();
        assert!(github_transient_status(
            StatusCode::FORBIDDEN,
            "you have exceeded a secondary rate limit",
            &h
        ));
        // Plain forbidden with no rate-limit signal is terminal.
        assert!(!github_transient_status(
            StatusCode::FORBIDDEN,
            "forbidden",
            &h
        ));
    }

    #[test]
    fn transient_status_forbidden_remaining_zero() {
        let mut h = HeaderMap::new();
        h.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        assert!(github_transient_status(StatusCode::FORBIDDEN, "", &h));
    }

    #[test]
    fn truncate_short_unchanged() {
        assert_eq!(truncate_for_error("hello"), "hello");
    }

    #[test]
    fn truncate_long_appends_marker() {
        let s = "a".repeat(ERROR_BODY_MAX_CHARS + 1);
        let out = truncate_for_error(&s);
        assert!(out.starts_with(&"a".repeat(ERROR_BODY_MAX_CHARS)));
        assert!(out.ends_with(&format!(
            "… (truncated, {} bytes total)",
            ERROR_BODY_MAX_CHARS + 1
        )));
    }

    #[test]
    fn format_error_includes_status_and_body() {
        let out = format_github_api_error(StatusCode::NOT_FOUND, "oops");
        assert!(out.starts_with("GitHub API 404"));
        assert!(out.ends_with("oops"));
    }

    #[test]
    fn validate_rejects_empty_list() {
        let err = validate_heal_files(&[]).unwrap_err();
        assert!(err.contains("no files"));
    }

    #[test]
    fn validate_rejects_dotdot_path() {
        let files = vec![("../etc/passwd".to_string(), "x".to_string())];
        assert!(validate_heal_files(&files)
            .unwrap_err()
            .contains("invalid heal file path"));
    }

    #[test]
    fn validate_rejects_empty_path() {
        let files = vec![("   ".to_string(), "x".to_string())];
        assert!(validate_heal_files(&files)
            .unwrap_err()
            .contains("invalid heal file path"));
    }

    #[test]
    fn validate_rejects_duplicate_paths() {
        let files = vec![
            ("a.txt".to_string(), "1".to_string()),
            ("a.txt".to_string(), "2".to_string()),
        ];
        assert!(validate_heal_files(&files)
            .unwrap_err()
            .contains("duplicate"));
    }

    #[test]
    fn validate_accepts_distinct_paths() {
        let files = vec![
            ("a.txt".to_string(), "1".to_string()),
            ("b.txt".to_string(), "2".to_string()),
        ];
        assert!(validate_heal_files(&files).is_ok());
    }

    #[test]
    fn diff_summary_single_file() {
        let files = vec![("a.txt".to_string(), "hello".to_string())];
        assert_eq!(diff_summary_from_files(&files), "a.txt:\nhello");
    }

    #[test]
    fn diff_summary_joins_with_separator() {
        let files = vec![
            ("a".to_string(), "x".to_string()),
            ("b".to_string(), "y".to_string()),
        ];
        assert_eq!(diff_summary_from_files(&files), "a:\nx\n---\nb:\ny");
    }

    #[test]
    fn diff_summary_truncates_content_to_200_chars() {
        let files = vec![("f".to_string(), "z".repeat(500))];
        let out = diff_summary_from_files(&files);
        // header "f:\n" (3 chars) + 200 content chars
        assert_eq!(out, format!("f:\n{}", "z".repeat(200)));
    }
}
