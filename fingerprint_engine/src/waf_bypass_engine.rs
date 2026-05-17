//! WAF bypass detection via payload injection and header inspection.
use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn normalize_target(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") { t.to_string() } else { format!("https://{}", t) }
}

pub async fn run_waf_bypass_result(target: &str) -> EngineResult {
    if target.trim().is_empty() { return EngineResult::error("target required"); }
    let client = build_client().await;
    let base = normalize_target(target);
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Check for WAF headers
    if let Ok(resp) = client.get(&base).send().await {
        let headers = resp.headers();
        let waf_present = headers.contains_key("x-sucuri-id") || headers.contains_key("cf-ray") || headers.contains_key("x-fw-protect");
        if !waf_present {
            findings.push(json!({
                "type": "waf_bypass",
                "title": "No WAF headers detected",
                "severity": "medium",
                "mitre_attack": "T1027",
                "description": "No WAF protection headers (x-sucuri-id, cf-ray, x-fw-protect) found on base response."
            }));
        }
    }

    // Try bypass payloads
    let payloads = [
        ("?q=%3Cscript%3E", "URL-encoded XSS"),
        ("?q=%253Cscript%253E", "Double-encoded XSS"),
        ("?id=1%00", "Null byte injection"),
        ("?search=<script>", "Raw XSS"),
    ];
    for (payload, desc) in &payloads {
        let url = format!("{}{}", base, payload);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().as_u16() == 200 {
                findings.push(json!({
                    "type": "waf_bypass",
                    "title": format!("WAF bypass possible: {}", desc),
                    "severity": "high",
                    "mitre_attack": "T1027",
                    "description": format!("Payload {} returned 200 — WAF may not be blocking this pattern.", payload)
                }));
            }
        }
    }
    EngineResult::ok(findings.clone(), format!("WAF Bypass: {} findings", findings.len()))
}

pub async fn run_waf_bypass(target: &str) {
    print_result(run_waf_bypass_result(target).await);
}
