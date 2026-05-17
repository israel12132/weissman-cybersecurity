//! Supply chain audit: NPM search + OSV vuln check. Output JSON for Python.
//! Module 2: routes through StealthClientFactory + jitter + identity morphing when config provided.

use crate::engine_result::{print_result, EngineResult};
use crate::stealth_engine;
use futures::stream::{self, StreamExt};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

const TIMEOUT_SECS: u64 = 6;
/// Parallel OSV queries after registry metadata (registry rate limits; keep bounded).
const SUPPLY_OSV_CONCURRENCY: usize = 16;

async fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn apply_stealth_headers(
    req: reqwest::RequestBuilder,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> reqwest::RequestBuilder {
    match stealth {
        Some(s) => req.headers(stealth_engine::random_morph_headers(s)),
        None => req,
    }
}

/// Prefix derived from client target (used for PoC curl lines in orchestrator).
pub fn target_prefix_for_poc(target: &str) -> String {
    weissman_core::models::poc::client_target_search_prefix(target)
}

/// Detect potential typosquat: a package whose name is suspiciously close to a well-known package.
/// Returns the likely impersonated package name if risk is detected.
fn detect_typosquat(name: &str) -> Option<String> {
    // Well-known high-value npm packages commonly typosquatted
    const POPULAR_PACKAGES: &[&str] = &[
        "lodash", "express", "react", "vue", "angular", "axios", "moment",
        "chalk", "debug", "request", "underscore", "bluebird", "commander",
        "webpack", "babel", "eslint", "typescript", "jest", "mocha",
        "passport", "mongoose", "sequelize", "knex", "pg", "mysql",
        "redis", "socket.io", "ws", "node-fetch", "cross-fetch",
        "dotenv", "uuid", "path", "fs-extra", "glob", "rimraf",
        "semver", "minimist", "yargs", "inquirer", "ora", "cli-table",
        "jsonwebtoken", "bcrypt", "crypto-js", "helmet", "cors",
        "body-parser", "multer", "nodemailer", "aws-sdk", "azure",
    ];
    let name_lower = name.to_lowercase();
    for &popular in POPULAR_PACKAGES {
        // Skip exact matches
        if name_lower == popular {
            return None;
        }
        // Check edit distance ≤ 2 for short packages (≤ 8 chars) or ≤ 3 for longer ones
        let max_dist = if popular.len() <= 8 { 2 } else { 3 };
        if levenshtein_distance(&name_lower, popular) <= max_dist {
            return Some(popular.to_string());
        }
        // Also catch common patterns: prefixing/suffixing with common words
        if (name_lower.starts_with(popular) || name_lower.ends_with(popular))
            && name_lower != popular
            && name_lower.len() <= popular.len() + 5
        {
            return Some(popular.to_string());
        }
    }
    None
}

/// Simple Levenshtein distance (character edit distance) for typosquat detection.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len();
    let n = b.len();
    if m == 0 { return n; }
    if n == 0 { return m; }
    // Only compute if lengths are close enough to be typosquats
    if m.abs_diff(n) > 4 { return usize::MAX; }
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1])
            };
        }
    }
    dp[m][n]
}

pub async fn run_supply_chain_result(
    target: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> EngineResult {
    let prefix = weissman_core::models::poc::client_target_search_prefix(target);
    if prefix.is_empty() {
        return EngineResult::error("target required");
    }

    let c = match stealth {
        Some(s) => {
            stealth_engine::apply_jitter(s);
            stealth_engine::build_client(s, TIMEOUT_SECS)
        }
        None => default_client().await,
    };
    let c = Arc::new(c);
    let st: Option<stealth_engine::StealthConfig> = stealth.cloned();

    let npm_url = format!(
        "https://registry.npmjs.org/-/v1/search?text={}&size=50",
        urlencoding::encode(&prefix)
    );
    let pypi_name = prefix.replace(' ', "-");
    let pypi_url = format!("https://pypi.org/pypi/{}/json", pypi_name);

    let c_npm = Arc::clone(&c);
    let c_pypi = Arc::clone(&c);
    let npm_url_f = npm_url.clone();
    let pypi_url_f = pypi_url.clone();
    let st_npm = st.clone();
    let st_pypi = st.clone();
    let npm_fut = async move {
        let req = apply_stealth_headers(c_npm.get(&npm_url_f), st_npm.as_ref());
        req.send().await.ok()
    };
    let pypi_fut = async move {
        if let Some(ref s) = st_pypi {
            stealth_engine::apply_jitter(s);
        }
        let req = apply_stealth_headers(c_pypi.get(&pypi_url_f), st_pypi.as_ref());
        req.send().await.ok()
    };
    let (npm_resp, pypi_resp) = tokio::join!(npm_fut, pypi_fut);

    let mut npm_packages: Vec<(String, String)> = Vec::new();
    if let Some(r) = npm_resp {
        if r.status().is_success() {
            if let Ok(data) = r.json::<serde_json::Value>().await {
                let empty: Vec<serde_json::Value> = vec![];
                let objects = data
                    .get("objects")
                    .and_then(|o| o.as_array())
                    .unwrap_or(&empty);
                for obj in objects {
                    let pkg = obj.get("package").or(Some(obj)).and_then(|p| p.as_object());
                    if let Some(p) = pkg {
                        let name = p.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        if name.is_empty() {
                            continue;
                        }
                        let version = p.get("version").and_then(|v| v.as_str()).unwrap_or("");
                        npm_packages.push((name.to_string(), version.to_string()));
                    }
                }
            }
        }
    }

    let npm_findings: Vec<serde_json::Value> = stream::iter(npm_packages.into_iter().map(
        |(name, version)| {
            let c = Arc::clone(&c);
            let st = st.clone();
            let npm_url = npm_url.clone();
            async move {
                let osv = check_osv(c.as_ref(), "npm", &name, st.as_ref()).await;
                let osv_body = json!({ "package": { "name": name, "ecosystem": "npm" } });
                let osv_esc = serde_json::to_string(&osv_body).unwrap_or_default();
                let poc = format!(
                    "# Live reproducibility (same requests the engine executed)\n\
                     curl -sS '{}'\n\
                     curl -sS -X POST 'https://api.osv.dev/v1/query' -H 'Content-Type: application/json' -d '{}'",
                    npm_url, osv_esc
                );
                let typosquat = detect_typosquat(&name);
                let typosquat_risk = typosquat.is_some();
                let severity = if osv.vuln_count > 0 || typosquat_risk {
                    "high"
                } else {
                    "info"
                };
                json!({
                    "type": "supply_chain",
                    "package": name,
                    "ecosystem": "npm",
                    "version": version,
                    "vuln_count": osv.vuln_count,
                    "osv_ids": osv.ids,
                    "osv_summaries": osv.summaries,
                    "typosquat_risk": typosquat_risk,
                    "typosquat_similar_to": typosquat,
                    "severity": severity,
                    "poc_exploit": poc
                })
            }
        },
    ))
    .buffer_unordered(SUPPLY_OSV_CONCURRENCY)
    .collect()
    .await;

    let mut findings = npm_findings;

    if let Some(r) = pypi_resp {
        if r.status().is_success() {
            if let Ok(data) = r.json::<serde_json::Value>().await {
                let info = data.get("info").and_then(|i| i.as_object());
                if let Some(info) = info {
                    let name = info
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(pypi_name.as_str())
                        .to_string();
                    let version = info
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let osv = check_osv(c.as_ref(), "PyPI", &name, st.as_ref()).await;
                    let osv_body = json!({ "package": { "name": name, "ecosystem": "PyPI" } });
                    let osv_esc = serde_json::to_string(&osv_body).unwrap_or_default();
                    let poc = format!(
                        "# Live reproducibility (same requests the engine executed)\n\
                         curl -sS '{}'\n\
                         curl -sS -X POST 'https://api.osv.dev/v1/query' -H 'Content-Type: application/json' -d '{}'",
                        pypi_url, osv_esc
                    );
                    let typosquat = detect_typosquat(&name);
                    let typosquat_risk = typosquat.is_some();
                    let severity = if osv.vuln_count > 0 || typosquat_risk { "high" } else { "info" };
                    findings.push(json!({
                        "type": "supply_chain",
                        "package": name,
                        "ecosystem": "pypi",
                        "version": version,
                        "vuln_count": osv.vuln_count,
                        "osv_ids": osv.ids,
                        "osv_summaries": osv.summaries,
                        "typosquat_risk": typosquat_risk,
                        "typosquat_similar_to": typosquat,
                        "severity": severity,
                        "poc_exploit": poc
                    }));
                }
            }
        }
    }

    let msg = format!("Supply chain: {} packages audited", findings.len());
    EngineResult::ok(findings, msg)
}

pub async fn run_supply_chain(target: &str) {
    print_result(run_supply_chain_result(target, None).await);
}

#[derive(Default)]
struct OsvQueryResult {
    vuln_count: u32,
    ids: Vec<String>,
    summaries: Vec<String>,
}

async fn check_osv(
    c: &reqwest::Client,
    ecosystem: &str,
    name: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> OsvQueryResult {
    if let Some(s) = stealth {
        stealth_engine::apply_jitter(s);
    }
    let body = json!({ "package": { "name": name, "ecosystem": ecosystem } });
    let req = c.post("https://api.osv.dev/v1/query").json(&body);
    let req = apply_stealth_headers(req, stealth);
    let mut out = OsvQueryResult::default();
    if let Ok(r) = req.send().await {
        if r.status().is_success() {
            if let Ok(data) = r.json::<serde_json::Value>().await {
                let empty: Vec<serde_json::Value> = vec![];
                let vulns = data
                    .get("vulns")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&empty);
                out.vuln_count = vulns.len() as u32;
                for v in vulns.iter().take(24) {
                    if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
                        out.ids.push(id.to_string());
                    }
                    if let Some(s) = v.get("summary").and_then(|x| x.as_str()) {
                        let t = s.chars().take(280).collect::<String>();
                        if !t.is_empty() {
                            out.summaries.push(t);
                        }
                    }
                }
            }
        }
    }
    out
}
