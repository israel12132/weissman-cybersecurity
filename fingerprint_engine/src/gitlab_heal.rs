//! GitLab delivery for auto-heal: branch → commit the applied files → open a Merge Request,
//! via the GitLab REST v4 API. Mirrors `auto_heal.rs` (shared pooled client + retry/backoff) but
//! authenticates with the `PRIVATE-TOKEN` header (glpat) and uses v4 endpoints. Reuses the single
//! verified `changed_files` artifact produced by the sandbox, so the MR is a real applied fix.

use reqwest::header::HeaderMap;
use reqwest::{Response, StatusCode};
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;

const TIMEOUT_SECS: u64 = 30;
const MAX_ATTEMPTS: u32 = 6;
const INITIAL_BACKOFF_MS: u64 = 400;
const MAX_BACKOFF_MS: u64 = 30_000;

static GITLAB_HTTP: OnceLock<reqwest::Client> = OnceLock::new();

fn gitlab_client() -> &'static reqwest::Client {
    GITLAB_HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .pool_max_idle_per_host(16)
            .user_agent("Weissman-CNAPP-AutoHeal/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Build the v4 API base for gitlab.com or a self-managed host. `host` may be empty (⇒ gitlab.com),
/// a bare host, or a full URL.
#[must_use]
pub fn v4_base(host: &str) -> String {
    let h = host.trim().trim_end_matches('/');
    if h.is_empty() || h.eq_ignore_ascii_case("gitlab.com") {
        return "https://gitlab.com/api/v4".to_string();
    }
    if let Some(rest) = h.strip_prefix("https://").or_else(|| h.strip_prefix("http://")) {
        return format!("https://{}/api/v4", rest.trim_end_matches('/'));
    }
    format!("https://{}/api/v4", h)
}

/// URL-encode a project path (`owner/repo` → `owner%2Frepo`) for the `:id` path segment.
fn enc_project(project_path: &str) -> String {
    project_path
        .trim()
        .trim_matches('/')
        .replace('/', "%2F")
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
    // GitLab secondary rate limit surfaces 403 with RateLimit-Remaining: 0.
    if status == StatusCode::FORBIDDEN {
        if let Some(v) = headers.get("ratelimit-remaining") {
            if v.to_str().ok() == Some("0") {
                return true;
            }
        }
    }
    false
}

async fn send_with_retry(
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
                if transient(status, &headers) && attempt < MAX_ATTEMPTS {
                    tokio::time::sleep(backoff(attempt)).await;
                    continue;
                }
                return Err(format!(
                    "GitLab API {}: {}",
                    status,
                    body.chars().take(500).collect::<String>()
                ));
            }
            Err(e) => {
                if attempt >= MAX_ATTEMPTS {
                    return Err(format!("GitLab network error after {attempt}: {e}"));
                }
                tokio::time::sleep(backoff(attempt)).await;
            }
        }
    }
}

async fn json_body(resp: Response, ctx: &str) -> Result<Value, String> {
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("{ctx}: read body: {e}"))?;
    if !status.is_success() {
        return Err(format!("{ctx}: GitLab {} {}", status, text.chars().take(400).collect::<String>()));
    }
    serde_json::from_str(&text).map_err(|e| format!("{ctx}: invalid JSON: {e}"))
}

/// Does `path` exist on `git_ref`? Determines create vs update action for the commit.
async fn file_exists(api_base: &str, project: &str, path: &str, git_ref: &str, token: &str) -> bool {
    let url = format!(
        "{}/projects/{}/repository/files/{}?ref={}",
        api_base,
        project,
        urlencoding_min(path),
        urlencoding_min(git_ref)
    );
    matches!(
        gitlab_client()
            .get(&url)
            .header("PRIVATE-TOKEN", token)
            .send()
            .await
            .map(|r| r.status().is_success()),
        Ok(true)
    )
}

/// Minimal percent-encoding for a single path/ref segment (encodes `/`, space, `?`, `#`, `%`).
fn urlencoding_min(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for b in s.bytes() {
        match b {
            b'/' => out.push_str("%2F"),
            b' ' => out.push_str("%20"),
            b'?' => out.push_str("%3F"),
            b'#' => out.push_str("%23"),
            b'%' => out.push_str("%25"),
            _ => out.push(b as char),
        }
    }
    out
}

/// Result of a GitLab heal MR attempt.
pub struct GitlabMrOutcome {
    pub branch_name: String,
    pub mr_url: Option<String>,
    pub mr_iid: Option<i64>,
    pub error: Option<String>,
}

/// Create a heal branch from `base_branch`, commit `files` in one commit, then open a Merge Request.
pub async fn create_branch_commit_and_mr(
    token: &str,
    gitlab_host: &str,
    project_path: &str,
    base_branch: &str,
    finding_id: &str,
    files: Vec<(String, String)>,
    title: &str,
    description: &str,
) -> GitlabMrOutcome {
    let branch_name = format!("weissman-heal-{}", finding_id.replace(['/', '\\'], "-"));
    if files.is_empty() {
        return GitlabMrOutcome {
            branch_name,
            mr_url: None,
            mr_iid: None,
            error: Some("no files to commit".into()),
        };
    }
    let api_base = v4_base(gitlab_host);
    let project = enc_project(project_path);
    let client = gitlab_client();

    // Build actions (create vs update per file existence on the base branch).
    let mut actions = Vec::with_capacity(files.len());
    for (path, content) in &files {
        let p = path.trim_start_matches('/');
        if p.is_empty() || p.contains("..") {
            return GitlabMrOutcome {
                branch_name,
                mr_url: None,
                mr_iid: None,
                error: Some(format!("invalid file path: {path:?}")),
            };
        }
        let action = if file_exists(&api_base, &project, p, base_branch, token).await {
            "update"
        } else {
            "create"
        };
        actions.push(serde_json::json!({ "action": action, "file_path": p, "content": content }));
    }

    // Single commit that also creates the branch (start_branch).
    let commit_url = format!("{}/projects/{}/repository/commits", api_base, project);
    let commit_body = serde_json::json!({
        "branch": branch_name,
        "start_branch": base_branch,
        "commit_message": format!("Security remediation from Weissman CNAPP ({finding_id})"),
        "actions": actions,
    });
    if let Err(e) = send_with_retry(|| {
        client
            .post(&commit_url)
            .header("PRIVATE-TOKEN", token)
            .json(&commit_body)
    })
    .await
    {
        return GitlabMrOutcome {
            branch_name,
            mr_url: None,
            mr_iid: None,
            error: Some(format!("commit: {e}")),
        };
    }

    // Open the merge request.
    let mr_url = format!("{}/projects/{}/merge_requests", api_base, project);
    let mr_body = serde_json::json!({
        "source_branch": branch_name,
        "target_branch": base_branch,
        "title": title,
        "description": description,
        "remove_source_branch": true,
    });
    match send_with_retry(|| {
        client
            .post(&mr_url)
            .header("PRIVATE-TOKEN", token)
            .json(&mr_body)
    })
    .await
    {
        Ok(resp) => match json_body(resp, "open MR").await {
            Ok(j) => GitlabMrOutcome {
                branch_name,
                mr_url: j.get("web_url").and_then(|v| v.as_str()).map(String::from),
                mr_iid: j.get("iid").and_then(|v| v.as_i64()),
                error: None,
            },
            Err(e) => GitlabMrOutcome {
                branch_name,
                mr_url: None,
                mr_iid: None,
                error: Some(e),
            },
        },
        Err(e) => GitlabMrOutcome {
            branch_name,
            mr_url: None,
            mr_iid: None,
            error: Some(format!("open MR: {e}")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_base_variants() {
        assert_eq!(v4_base(""), "https://gitlab.com/api/v4");
        assert_eq!(v4_base("gitlab.com"), "https://gitlab.com/api/v4");
        assert_eq!(v4_base("gitlab.example.com"), "https://gitlab.example.com/api/v4");
        assert_eq!(v4_base("https://gl.corp.io/"), "https://gl.corp.io/api/v4");
    }

    #[test]
    fn project_encoding() {
        assert_eq!(enc_project("acme/api"), "acme%2Fapi");
        assert_eq!(enc_project("/group/sub/repo/"), "group%2Fsub%2Frepo");
    }

    #[test]
    fn path_encoding_min() {
        assert_eq!(urlencoding_min("src/app.js"), "src%2Fapp.js");
        assert_eq!(urlencoding_min("a b"), "a%20b");
    }
}
