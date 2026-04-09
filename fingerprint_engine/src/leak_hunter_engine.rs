//! LeakHunter: Deep Leak Discovery — .git, .env, .aws/credentials, open S3/Azure, GitHub API key search.

use crate::engine_result::EngineResult;
use crate::stealth_engine;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::time::Duration;

const TIMEOUT_SECS: u64 = 8;
/// Concurrent HTTP probes per LeakHunter run (bounded; scales on multi-core + connection pool).
const LEAK_PROBE_CONCURRENCY: usize = 64;

/// Paths to probe for exposed secrets / config.
const LEAK_PATHS: &[&str] = &[
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.staging",
    "/.aws/credentials",
    "/config",
    "/config.json",
    "/config.yaml",
    "/.htpasswd",
    "/web.config",
    "/.docker/config.json",
    "/.npmrc",
    "/.pypirc",
    "/package.json",
    "/composer.json",
    "/.kube/config",
    "/server-status",
    "/actuator/env",
    "/.well-known/security.txt",
];

fn client(stealth: Option<&stealth_engine::StealthConfig>) -> reqwest::Client {
    match stealth {
        Some(s) => stealth_engine::build_client(s, TIMEOUT_SECS),
        None => reqwest::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
            .user_agent("Weissman-LeakHunter/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
    }
}

/// Probe a single URL; returns (status, body_preview) if success.
async fn probe_url(
    c: &reqwest::Client,
    url: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> Option<(u16, String)> {
    let req = match stealth {
        Some(s) => {
            stealth_engine::apply_jitter(s);
            c.get(url).headers(stealth_engine::random_morph_headers(s))
        }
        None => c.get(url),
    };
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.ok().unwrap_or_default();
    let preview = body.chars().take(500).collect::<String>();
    Some((status, preview))
}

/// Check if body looks like a secret file (not a 404 page).
fn looks_like_leak(path: &str, status: u16, body: &str) -> bool {
    if status != 200 && status != 206 {
        return false;
    }
    let body_lower = body.to_lowercase();
    if path.contains(".git") {
        return body_lower.contains("[core]")
            || body_lower.contains("ref: refs/heads")
            || body.trim().len() < 200;
    }
    if path.contains(".env") || path.contains("credentials") || path.contains("config") {
        return body.contains("=")
            && (body.contains("key")
                || body.contains("secret")
                || body.contains("password")
                || body.contains("token")
                || body.len() < 2000);
    }
    !body.is_empty() && body.len() < 10000
}

/// Run leak probes on base URLs. Returns findings for exposed .git, .env, .aws, etc.
pub async fn run_leak_hunter(
    base_urls: &[String],
    stealth: Option<&stealth_engine::StealthConfig>,
) -> EngineResult {
    let c = Arc::new(client(stealth));
    let st = stealth.cloned();
    let mut tasks = Vec::new();
    for base in base_urls.iter().take(20) {
        let base = base.trim_end_matches('/').to_string();
        for path in LEAK_PATHS {
            let base = base.clone();
            let path_s = (*path).to_string();
            let c = Arc::clone(&c);
            let st = st.clone();
            tasks.push(async move {
                let url = format!("{}{}", base, path_s.trim_start_matches('/'));
                if let Some((status, preview)) = probe_url(c.as_ref(), &url, st.as_ref()).await {
                    if looks_like_leak(&path_s, status, &preview) {
                        return Some(serde_json::json!({
                            "type": "leak_hunter",
                            "subtype": "exposed_secret",
                            "path": path_s,
                            "url": url,
                            "status": status,
                            "preview_len": preview.len(),
                            "severity": "critical",
                            "title": format!("Exposed sensitive path: {}", path_s)
                        }));
                    }
                }
                None
            });
        }
    }
    let rows: Vec<Option<serde_json::Value>> = stream::iter(tasks)
        .map(|fut| fut)
        .buffer_unordered(LEAK_PROBE_CONCURRENCY)
        .collect()
        .await;
    let findings: Vec<serde_json::Value> = rows.into_iter().flatten().collect();
    let msg = format!(
        "LeakHunter: {} base URLs probed, {} potential leaks",
        base_urls.len().min(20),
        findings.len()
    );
    EngineResult::ok(findings, msg)
}

/// Query GitHub API for repos/code containing domain or org name (optional; requires token).
pub async fn github_leak_search(
    domain_or_org: &str,
    github_token: Option<&str>,
) -> Vec<serde_json::Value> {
    let token = match github_token {
        Some(t) if !t.is_empty() => t,
        _ => return vec![],
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("Weissman-Security-Scanner")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let query = format!("{} .env OR api_key OR password", domain_or_org);
    let url = "https://api.github.com/search/code";
    let resp = client
        .get(url)
        .query(&[("q", query.as_str())])
        .header("Authorization", format!("Bearer {}", token))
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    if !resp.status().is_success() {
        return vec![];
    }
    let data: serde_json::Value = match resp.json().await {
        Ok(d) => d,
        Err(_) => return vec![],
    };
    let empty: Vec<serde_json::Value> = vec![];
    let items = data
        .get("items")
        .and_then(|i| i.as_array())
        .unwrap_or(&empty);
    let mut out = Vec::new();
    for item in items.iter().take(10) {
        let path = item.get("path").and_then(|p| p.as_str()).unwrap_or("");
        let html_url = item.get("html_url").and_then(|u| u.as_str()).unwrap_or("");
        out.push(serde_json::json!({
            "type": "leak_hunter",
            "subtype": "github_possible_leak",
            "path": path,
            "url": html_url,
            "severity": "high",
            "title": format!("Possible leaked secret in repo: {}", path)
        }));
    }
    out
}
