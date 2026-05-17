//! EDR/WAF evasion detection via header inspection and malicious UA probing.
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

pub async fn run_edr_evasion_result(target: &str) -> EngineResult {
    if target.trim().is_empty() { return EngineResult::error("target required"); }
    let client = build_client().await;
    let base = normalize_target(target);
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Check WAF/EDR headers on normal request
    if let Ok(resp) = client.get(&base).send().await {
        let headers = resp.headers();
        let waf_headers = ["cf-ray", "x-sucuri-id", "x-akamai-transformed", "x-imperva-waf"];
        let waf_found: Vec<&str> = waf_headers.iter().filter(|h| headers.contains_key(**h)).copied().collect();
        if !waf_found.is_empty() {
            findings.push(json!({
                "type": "edr_evasion",
                "title": "WAF/EDR protection headers detected",
                "severity": "info",
                "mitre_attack": "T1562",
                "description": format!("WAF/EDR headers present: {:?}", waf_found)
            }));
        }
    }

    // Probe with malicious UAs; if all succeed, flag missing protection
    let malicious_uas = ["sqlmap/1.0", "Nikto/2.1.6", "Mozilla/5.0 (compatible; Googlebot/2.1)"];
    let mut unblocked = 0usize;
    for ua in &malicious_uas {
        if let Ok(resp) = client.get(&base).header("User-Agent", *ua).send().await {
            if resp.status().as_u16() == 200 { unblocked += 1; }
        }
    }
    if unblocked == malicious_uas.len() {
        findings.push(json!({
            "type": "edr_evasion",
            "title": "No WAF/EDR blocking of malicious User-Agents",
            "severity": "high",
            "mitre_attack": "T1562",
            "description": format!("All {} malicious UA requests returned 200 — no blocking detected.", unblocked)
        }));
    }
    EngineResult::ok(findings.clone(), format!("EDR Evasion: {} findings", findings.len()))
}

pub async fn run_edr_evasion(target: &str) {
    print_result(run_edr_evasion_result(target).await);
}
