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
                    return Err(format!("GitHub network error after {attempt} attempts: {e}"));
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
            let sleep_d = retry_after_from_headers(&headers)
                .unwrap_or_else(|| backoff_with_jitter(attempt));
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

/// Open GitHub PR after sandbox verification succeeded.
pub async fn open_pull_request(
    token: &str,
    repo_slug: &str,
    base_branch: &str,
    head_branch: &str,
    finding_id: &str,
) -> Result<(Option<String>, Option<i64>), String> {
    let client = github_client();
    let auth = format!("Bearer {}", token);
    let pr_url_post = format!("{}/repos/{}/pulls", GITHUB_API, repo_slug);
    let pr_body = serde_json::json!({
        "title": format!("[Weissman CNAPP] Auto-Heal (200% verified): {}", finding_id),
        "head": head_branch,
        "base": base_branch,
        "body": "Autonomous remediation verified in ephemeral Docker: exploit re-run no longer succeeds. Please review and merge."
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
    match open_pull_request(token, repo_slug, base_branch, &c.branch_name, finding_id).await {
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
