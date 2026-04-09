//! crt.sh + HackerTarget hostsearch.

use async_trait::async_trait;
use serde_json::json;
use std::time::Duration;

use crate::context::{EngineRunOutcome, ScanContext};
use crate::engine_trait::CyberEngine;
use crate::result::{print_result, EngineResult};
use crate::stealth;

const TIMEOUT_SECS: u64 = 8;

async fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn target_to_domain(target: &str) -> String {
    let target = target.trim().to_lowercase();
    if target.is_empty() {
        return String::new();
    }
    if let Some(rest) = target.strip_prefix("http://") {
        return rest.split('/').next().unwrap_or(rest).to_string();
    }
    if let Some(rest) = target.strip_prefix("https://") {
        return rest.split('/').next().unwrap_or(rest).to_string();
    }
    target
}

fn apply_stealth_headers(
    req: reqwest::RequestBuilder,
    st: Option<&stealth::StealthConfig>,
) -> reqwest::RequestBuilder {
    match st {
        Some(s) => req.headers(stealth::random_morph_headers(s)),
        None => req,
    }
}

/// Run OSINT against a single primary target.
pub async fn run_osint_result(
    target: &str,
    st: Option<&stealth::StealthConfig>,
) -> EngineResult {
    let domain = target_to_domain(target);
    if domain.is_empty() {
        return EngineResult::error("target required");
    }

    let c = match st {
        Some(s) => {
            stealth::apply_jitter(s);
            stealth::build_client(s, TIMEOUT_SECS)
        }
        None => default_client().await,
    };

    let mut findings: Vec<serde_json::Value> = Vec::new();

    let ct_url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let whois_url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    let c2 = c.clone();
    let ct_fut = async {
        let req = apply_stealth_headers(c.get(&ct_url), st);
        req.send().await
    };
    let whois_fut = async {
        if let Some(s) = st {
            stealth::apply_jitter(s);
        }
        let req = apply_stealth_headers(c2.get(&whois_url), st);
        req.send().await
    };
    let (ct_resp, whois_resp) = tokio::join!(ct_fut, whois_fut);

    if let Ok(r) = ct_resp {
        if r.status().is_success() {
            let entries: Vec<serde_json::Value> = match r.json().await {
                Ok(serde_json::Value::Array(a)) => a,
                _ => vec![],
            };
            if !entries.is_empty() {
                let mut seen = std::collections::HashSet::new();
                for e in entries {
                    let name = e
                        .get("name_value")
                        .or(e.get("common_name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim()
                        .to_lowercase();
                    for part in name.split('\n') {
                        let part = part.trim().to_lowercase();
                        if part.is_empty() || part.len() < 2 {
                            continue;
                        }
                        if !part.ends_with(&domain) && part != domain {
                            continue;
                        }
                        if part.contains("*.") {
                            continue;
                        }
                        if seen.insert(part.clone()) {
                            findings.push(json!({
                                "type": "osint",
                                "source": "ct",
                                "asset_type": "subdomain",
                                "value": part,
                                "confidence": "high",
                                "risk_impact": "medium",
                                "severity": "medium"
                            }));
                        }
                    }
                }
            }
        }
    }

    if let Ok(r) = whois_resp {
        if r.status().is_success() {
            if let Ok(text) = r.text().await {
                let mut seen = std::collections::HashSet::new();
                for line in text.lines() {
                    let part = line.split(',').next().unwrap_or("").trim().to_lowercase();
                    if part.is_empty() || !part.ends_with(&domain) {
                        continue;
                    }
                    let part = part.replace("*.", "");
                    if part.len() < 2
                        || !part
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                    {
                        continue;
                    }
                    if seen.insert(part.clone()) {
                        findings.push(json!({
                            "type": "osint",
                            "source": "whois",
                            "asset_type": "subdomain",
                            "value": part,
                            "confidence": "medium",
                            "risk_impact": "medium",
                            "severity": "medium"
                        }));
                    }
                }
            }
        }
    }

    let msg = format!("OSINT: {} unique assets for {}", findings.len(), domain);
    EngineResult::ok(findings, msg)
}

/// CLI helper (prints JSON).
pub async fn run_osint(target: &str) {
    print_result(&run_osint_result(target, None).await);
}

/// Trait adapter for the engine factory.
pub struct OsintCyberEngine;

#[async_trait]
impl CyberEngine for OsintCyberEngine {
    fn engine_id(&self) -> &'static str {
        "osint"
    }

    fn display_label(&self) -> &'static str {
        "OSINT"
    }

    async fn execute(&self, ctx: &ScanContext) -> EngineRunOutcome {
        let r = run_osint_result(&ctx.primary_target, ctx.stealth.as_ref()).await;
        EngineRunOutcome::with_result(r)
    }
}
