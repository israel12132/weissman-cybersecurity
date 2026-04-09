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
    // Git / VCS
    "/.git/HEAD",
    "/.git/config",
    "/.git/COMMIT_EDITMSG",
    "/.git/logs/HEAD",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/hgrc",
    // Env / credentials
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.staging",
    "/.env.development",
    "/.env.backup",
    "/.env.bak",
    "/.envrc",
    "/.aws/credentials",
    "/.aws/config",
    "/.gcloud/application_default_credentials.json",
    // Config files
    "/config",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/config.php",
    "/configuration.json",
    "/configuration.yaml",
    "/settings.json",
    "/settings.yaml",
    "/application.properties",
    "/application.yml",
    "/.htpasswd",
    "/web.config",
    "/.docker/config.json",
    "/.npmrc",
    "/.pypirc",
    "/.pip/pip.conf",
    "/package.json",
    "/composer.json",
    "/.kube/config",
    "/kubeconfig",
    // Database dumps / backups
    "/backup.sql",
    "/backup.zip",
    "/backup.tar.gz",
    "/dump.sql",
    "/db.sql",
    "/database.sql",
    "/data.sql",
    // SSH keys
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.ssh/id_ecdsa",
    "/.ssh/authorized_keys",
    "/.ssh/known_hosts",
    "/id_rsa",
    "/id_rsa.pub",
    // WordPress / CMS
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config-sample.php",
    "/sites/default/settings.php",
    "/sites/default/default.settings.php",
    "/user/login",
    // macOS metadata (may contain directory structure)
    "/.DS_Store",
    // CI/CD & infrastructure
    "/.travis.yml",
    "/.github/workflows/ci.yml",
    "/Jenkinsfile",
    "/jenkins.yml",
    "/docker-compose.yml",
    "/docker-compose.override.yml",
    "/Dockerfile",
    "/.dockerignore",
    "/helm/values.yaml",
    "/values.yaml",
    "/terraform.tfvars",
    "/terraform.tfstate",
    "/.terraform/terraform.tfstate",
    "/ansible.cfg",
    "/inventory",
    // API docs / schema (may expose endpoints)
    "/api/swagger-ui.html",
    "/swagger-ui/",
    "/swagger-ui.html",
    "/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphql",
    "/graphql/console",
    // Debug / diagnostics pages
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/debug",
    "/debug.php",
    "/server-status",
    "/server-info",
    "/actuator/env",
    "/actuator/health",
    "/actuator/info",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/configprops",
    "/metrics",
    "/health",
    "/_ah/admin",
    // Shell / command history
    "/.bash_history",
    "/.zsh_history",
    "/.profile",
    "/.bashrc",
    // Nginx / Apache leaks
    "/nginx.conf",
    "/nginx/nginx.conf",
    "/.htaccess",
    // Misc
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
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
    // Git: HEAD file or config
    if path.contains(".git") || path.contains(".svn") || path.contains(".hg") {
        return body_lower.contains("[core]")
            || body_lower.contains("ref: refs/heads")
            || body_lower.contains("repositoryformatversion")
            || body_lower.contains("xmlns:svn")
            || body_lower.contains("[paths]")
            || body.trim().len() < 300;
    }
    // SSH keys
    if path.contains("id_rsa") || path.contains("id_ed25519") || path.contains("id_ecdsa") {
        return body_lower.contains("-----begin")
            || body_lower.contains("openssh private key")
            || body_lower.contains("rsa private key");
    }
    // Env / credentials
    if path.contains(".env") || path.contains("credentials") {
        return body.contains("=")
            && (body.contains("key")
                || body.contains("secret")
                || body.contains("password")
                || body.contains("token")
                || body.len() < 4000);
    }
    // Config files
    if path.contains("config") || path.contains("settings") || path.contains(".npmrc") || path.contains(".pypirc") || path.contains("application.properties") || path.contains("application.yml") {
        return (body.contains("=") || body.contains(":"))
            && (body.contains("key")
                || body.contains("secret")
                || body.contains("password")
                || body.contains("token")
                || body.contains("database")
                || body.contains("host")
                || body.len() < 5000);
    }
    // Kubernetes / Docker config (JSON format)
    if path.contains(".kube") || path.contains(".docker") || path.contains("kubeconfig") {
        return body_lower.contains("certificate")
            || body_lower.contains("apiserver")
            || body_lower.contains("cluster")
            || body_lower.contains("auths");
    }
    // Database backups
    if path.ends_with(".sql") || path.ends_with(".zip") || path.ends_with(".tar.gz") {
        return !body.is_empty() && (body_lower.contains("create table") || body_lower.contains("insert into") || body_lower.contains("pk\x03\x04"));
    }
    // Spring Boot actuator / env
    if path.contains("actuator") {
        return body_lower.contains("propertysources")
            || body_lower.contains("systemproperties")
            || body_lower.contains("applicationconfig")
            || (body_lower.contains("{") && body_lower.contains("value"));
    }
    // PHP info pages
    if path.contains("phpinfo") || path.contains("info.php") {
        return body_lower.contains("php version") || body_lower.contains("phpinfo()");
    }
    // GraphQL introspection
    if path.contains("graphql") {
        return body_lower.contains("\"__schema\"")
            || body_lower.contains("\"types\"")
            || body_lower.contains("introspection");
    }
    // API docs that expose internals
    if path.contains("swagger") || path.contains("openapi") || path.contains("api-docs") {
        return body_lower.contains("\"paths\"") || body_lower.contains("\"openapi\"") || body_lower.contains("swagger");
    }
    // Apache server-status
    if path.contains("server-status") || path.contains("server-info") {
        return body_lower.contains("apache") || body_lower.contains("server version");
    }
    // Shell history / profile files
    if path.contains("history") || path.contains(".profile") || path.contains(".bashrc") {
        return !body.is_empty() && body.len() > 5;
    }
    // Terraform state (contains cloud credentials/resource details)
    if path.contains("terraform") || path.contains(".tfstate") {
        return body_lower.contains("\"version\"") && (body_lower.contains("\"resources\"") || body_lower.contains("\"terraform_version\""));
    }
    // CI/CD configs
    if path.contains(".travis") || path.contains("Jenkinsfile") || path.contains("docker-compose") || path.contains("Dockerfile") {
        return !body.is_empty() && body.len() < 50000;
    }
    // WordPress config
    if path.contains("wp-config") {
        return body_lower.contains("db_name") || body_lower.contains("db_password") || body_lower.contains("define(");
    }
    // Generic: non-empty and reasonably short (not a CDN asset)
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
    let query = format!("{} .env OR api_key OR password OR secret OR token OR credential", domain_or_org);
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
