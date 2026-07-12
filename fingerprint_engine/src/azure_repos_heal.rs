//! Azure DevOps (Azure Repos) delivery for auto-heal: push the applied files as one commit on a new
//! heal branch, then open a Pull Request (REST v7). Mirrors `gitlab_heal`'s resilience harness
//! (shared pooled client + retry/backoff), authenticating with a Personal Access Token via HTTP Basic
//! (`Authorization: Basic base64(":" + pat)`). The slug is `org/project/repo`.

use base64::Engine;
use reqwest::header::HeaderMap;
use reqwest::{Response, StatusCode};
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;

const API_VER: &str = "7.0";
const TIMEOUT_SECS: u64 = 30;
const MAX_ATTEMPTS: u32 = 6;
const INITIAL_BACKOFF_MS: u64 = 400;
const MAX_BACKOFF_MS: u64 = 30_000;

static ADO_HTTP: OnceLock<reqwest::Client> = OnceLock::new();

fn ado_client() -> &'static reqwest::Client {
    ADO_HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .pool_max_idle_per_host(16)
            .user_agent("Weissman-CNAPP-AutoHeal/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Split an `org/project/repo` slug into its three parts.
#[must_use]
pub fn split_org_project_repo(slug: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = slug
        .trim()
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.trim().is_empty())
        .collect();
    if parts.len() < 3 {
        return None;
    }
    Some((parts[0].to_string(), parts[1].to_string(), parts[2].to_string()))
}

/// HTTP Basic header for a PAT (empty username).
#[must_use]
pub fn basic_auth_header(pat: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(format!(":{}", pat.trim()));
    format!("Basic {b64}")
}

/// `https://dev.azure.com/{org}/{project}` base for the Git REST endpoints.
#[must_use]
pub fn org_base(org: &str, project: &str) -> String {
    format!("https://dev.azure.com/{}/{}", pct(org.trim()), pct(project.trim()))
}

/// Percent-encode a single URL path/query value (everything but RFC 3986 unreserved), so a branch,
/// ref filter, or file path containing `&`, `#`, `?`, space, `/`, `=` can't inject query parameters
/// or break routing.
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

fn transient(status: StatusCode, _headers: &HeaderMap) -> bool {
    matches!(status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504)
}

/// Statuses safe to retry for a NON-idempotent write — the request was definitely not applied.
fn write_retryable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429)
}

/// `idempotent` requests retry on any transient status AND network error; writes retry only on
/// 429/408 and never on a network error, so a retry can't duplicate a push or a pull request (and,
/// for Azure specifically, a retried push would otherwise fail on an `oldObjectId` mismatch).
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
                return Err(format!("Azure DevOps API {}: {}", status, body.chars().take(400).collect::<String>()));
            }
            Err(e) => {
                if idempotent && attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(backoff(attempt)).await;
                    continue;
                }
                return Err(format!("Azure DevOps network error after {attempt}: {e}"));
            }
        }
    }
}

async fn json_body(resp: Response, ctx: &str) -> Result<Value, String> {
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("{ctx}: read body: {e}"))?;
    if !status.is_success() {
        return Err(format!("{ctx}: Azure DevOps {} {}", status, text.chars().take(400).collect::<String>()));
    }
    serde_json::from_str(&text).map_err(|e| format!("{ctx}: invalid JSON: {e}"))
}

/// Resolve the base branch head commit id (`oldObjectId` for the push refUpdate).
async fn base_ref_object_id(base_url: &str, repo: &str, base: &str, auth: &str) -> Option<String> {
    let url = format!(
        "{base_url}/_apis/git/repositories/{}/refs?filter=heads/{}&api-version={API_VER}",
        pct(repo),
        pct(base),
    );
    let resp = ado_client().get(&url).header("Authorization", auth).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let j: Value = resp.json().await.ok()?;
    // `filter=heads/{base}` is a PREFIX match, so `main` also returns `maintenance`, `main-2`, … —
    // require an EXACT `refs/heads/{base}` match rather than falling back to the first ref, which
    // would cut the heal branch off the wrong commit.
    let want = format!("refs/heads/{base}");
    j.get("value")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.iter().find(|r| r.get("name").and_then(|n| n.as_str()) == Some(want.as_str())))
        .and_then(|r| r.get("objectId"))
        .and_then(|o| o.as_str())
        .map(String::from)
}

/// Resolve whether `path` exists on `base` to pick `edit` vs `add`. Returns `Some(true)` (exists),
/// `Some(false)` (a definitive 404 → absent), or `None` (indeterminate after retrying transient
/// failures) — the caller must NOT guess a change type on `None`, since a wrong `add`/`edit` gets the
/// whole push rejected.
async fn file_state(base_url: &str, repo: &str, path: &str, base: &str, auth: &str) -> Option<bool> {
    let url = format!(
        "{base_url}/_apis/git/repositories/{}/items?path={}&versionDescriptor.version={}&api-version={API_VER}",
        pct(repo),
        pct(path),
        pct(base),
    );
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match ado_client().get(&url).header("Authorization", auth).send().await {
            Ok(r) => {
                let status = r.status();
                if status.is_success() {
                    return Some(true);
                }
                if status == StatusCode::NOT_FOUND {
                    return Some(false);
                }
                if transient(status, r.headers()) && attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(backoff(attempt)).await;
                    continue;
                }
                return None; // auth/other error → indeterminate, do not guess
            }
            Err(_) => {
                if attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(backoff(attempt)).await;
                    continue;
                }
                return None;
            }
        }
    }
}

/// Result of an Azure Repos heal PR attempt.
pub struct AzurePrOutcome {
    pub branch_name: String,
    pub pr_url: Option<String>,
    pub pr_id: Option<i64>,
    pub error: Option<String>,
}

fn err(branch_name: String, msg: impl Into<String>) -> AzurePrOutcome {
    AzurePrOutcome { branch_name, pr_url: None, pr_id: None, error: Some(msg.into()) }
}

/// Push `files` as one commit on a new heal branch, then open a Pull Request.
pub async fn create_push_and_pr(
    pat: &str,
    repo_slug: &str,
    base_branch: &str,
    finding_id: &str,
    files: Vec<(String, String)>,
    title: &str,
    description: &str,
) -> AzurePrOutcome {
    let branch_name = format!(
        "weissman-heal-{}",
        crate::heal_channels::safe_branch_suffix(finding_id)
    );
    let Some((org, project, repo)) = split_org_project_repo(repo_slug) else {
        return err(branch_name, "invalid Azure DevOps slug (expected org/project/repo)");
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

    let base_url = org_base(&org, &project);
    let auth = basic_auth_header(pat);

    // The push must supply the current base head as oldObjectId.
    let Some(old_object_id) = base_ref_object_id(&base_url, &repo, base_branch, &auth).await else {
        return err(branch_name, format!("could not resolve base branch head for '{base_branch}'"));
    };

    // Build the change set (add vs edit per file).
    let mut changes = Vec::with_capacity(files.len());
    for (path, content) in &files {
        let p = if path.starts_with('/') {
            path.clone()
        } else {
            format!("/{}", path.trim_start_matches('/'))
        };
        let change_type = match file_state(&base_url, &repo, &p, base_branch, &auth).await {
            Some(true) => "edit",
            Some(false) => "add",
            None => {
                return err(
                    branch_name,
                    format!("could not determine repository state of '{p}'; not pushing to avoid a wrong change type"),
                )
            }
        };
        changes.push(serde_json::json!({
            "changeType": change_type,
            "item": { "path": p },
            "newContent": { "content": content, "contentType": "rawtext" },
        }));
    }

    // Single push creating the heal branch off the base head.
    let push_url = format!(
        "{base_url}/_apis/git/repositories/{}/pushes?api-version={API_VER}",
        pct(&repo)
    );
    let push_body = serde_json::json!({
        "refUpdates": [ { "name": format!("refs/heads/{branch_name}"), "oldObjectId": old_object_id } ],
        "commits": [ {
            "comment": format!("Security remediation from Weissman CNAPP ({finding_id})"),
            "changes": changes,
        } ],
    });
    if let Err(e) = send_with_retry(false, || {
        ado_client()
            .post(&push_url)
            .header("Authorization", &auth)
            .json(&push_body)
    })
    .await
    {
        return err(branch_name, format!("push: {e}"));
    }

    // Open the pull request.
    let pr_ep = format!(
        "{base_url}/_apis/git/repositories/{}/pullrequests?api-version={API_VER}",
        pct(&repo)
    );
    let pr_body = serde_json::json!({
        "sourceRefName": format!("refs/heads/{branch_name}"),
        "targetRefName": format!("refs/heads/{base_branch}"),
        "title": title,
        "description": description,
    });
    match send_with_retry(false, || {
        ado_client()
            .post(&pr_ep)
            .header("Authorization", &auth)
            .json(&pr_body)
    })
    .await
    {
        Ok(resp) => match json_body(resp, "open PR").await {
            Ok(j) => {
                let pr_id = j.get("pullRequestId").and_then(|v| v.as_i64());
                let pr_url = pr_id.map(|id| {
                    format!("{base_url}/_git/{repo}/pullrequest/{id}")
                });
                AzurePrOutcome { branch_name, pr_url, pr_id, error: None }
            }
            Err(e) => err(branch_name, e),
        },
        Err(e) => err(branch_name, format!("open PR: {e}")),
    }
}

/// Abandon an auto-opened Azure Repos PR (revert).
pub async fn abandon_pull_request(
    pat: &str,
    repo_slug: &str,
    pr_id: i64,
) -> Result<(), String> {
    let (org, project, repo) =
        split_org_project_repo(repo_slug).ok_or_else(|| "invalid Azure DevOps slug".to_string())?;
    let base_url = org_base(&org, &project);
    let auth = basic_auth_header(pat);
    let url = format!(
        "{base_url}/_apis/git/repositories/{}/pullrequests/{pr_id}?api-version={API_VER}",
        pct(&repo)
    );
    let resp = send_with_retry(true, || {
        ado_client()
            .patch(&url)
            .header("Authorization", &auth)
            .json(&serde_json::json!({ "status": "abandoned" }))
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
        assert_eq!(
            split_org_project_repo("myorg/myproj/myrepo"),
            Some(("myorg".into(), "myproj".into(), "myrepo".into()))
        );
        assert_eq!(
            split_org_project_repo("/a/b/c/"),
            Some(("a".into(), "b".into(), "c".into()))
        );
        assert_eq!(split_org_project_repo("a/b"), None);
        assert_eq!(split_org_project_repo(""), None);
    }

    #[test]
    fn basic_auth_is_base64_of_colon_pat() {
        // ":pat" base64 == "OnBhdA=="
        assert_eq!(basic_auth_header("pat"), "Basic OnBhdA==");
    }

    #[test]
    fn org_base_builds_dev_azure_url() {
        assert_eq!(org_base("o", "p"), "https://dev.azure.com/o/p");
    }

    #[test]
    fn pct_encodes_query_values_preventing_injection() {
        // '&' must not survive raw (it would inject a query parameter).
        assert_eq!(pct("/a&evil=1"), "%2Fa%26evil%3D1");
        assert_eq!(pct("feat/x"), "feat%2Fx");
        assert_eq!(pct("notes#1.md"), "notes%231.md");
        assert_eq!(pct("a b"), "a%20b");
        assert_eq!(pct("safe-1.2_x~"), "safe-1.2_x~");
    }
}
