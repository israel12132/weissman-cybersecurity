//! PKI/TLS security header and certificate transparency inspection.
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

fn extract_domain(target: &str) -> String {
    let t = target.trim().trim_start_matches("http://").trim_start_matches("https://");
    let t = t.split('/').next().unwrap_or(t);
    t.split(':').next().unwrap_or(t).to_string()
}

fn normalize_target(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") { t.to_string() } else { format!("https://{}", t) }
}

pub async fn run_pki_tls_result(target: &str) -> EngineResult {
    if target.trim().is_empty() { return EngineResult::error("target required"); }
    let client = build_client().await;
    let base = normalize_target(target);
    let domain = extract_domain(target);
    let mut findings: Vec<serde_json::Value> = Vec::new();

    if let Ok(resp) = client.get(&base).send().await {
        let headers = resp.headers();
        if !headers.contains_key("strict-transport-security") {
            findings.push(json!({"type":"pki_tls","title":"Missing HSTS header","severity":"high","mitre_attack":"T1557","description":"Strict-Transport-Security header not present."}));
        }
        if !headers.contains_key("x-content-type-options") {
            findings.push(json!({"type":"pki_tls","title":"Missing X-Content-Type-Options","severity":"medium","mitre_attack":"T1557","description":"X-Content-Type-Options header not present."}));
        }
        if !headers.contains_key("x-frame-options") {
            findings.push(json!({"type":"pki_tls","title":"Missing X-Frame-Options","severity":"medium","mitre_attack":"T1557","description":"X-Frame-Options header not present."}));
        }
    }

    // Check HTTP -> HTTPS redirect
    let http_url = format!("http://{}", domain);
    if let Ok(resp) = client.get(&http_url).send().await {
        if resp.status().as_u16() == 200 {
            findings.push(json!({"type":"pki_tls","title":"HTTP served without HTTPS redirect","severity":"high","mitre_attack":"T1557","description":"HTTP endpoint returns 200 instead of redirecting to HTTPS."}));
        }
    }

    // Check crt.sh
    let crtsh_url = format!("https://crt.sh/?q={}&output=json", domain);
    if let Ok(resp) = client.get(&crtsh_url).send().await {
        if let Ok(text) = resp.text().await {
            if let Ok(arr) = serde_json::from_str::<serde_json::Value>(&text) {
                let count = arr.as_array().map(|a| a.len()).unwrap_or(0);
                findings.push(json!({"type":"pki_tls","title":format!("Certificate transparency: {} certs found",count),"severity":"info","mitre_attack":"T1557","description":format!("{} certificates found in crt.sh for domain {}",count,domain)}));
            }
        }
    }

    EngineResult::ok(findings.clone(), format!("PKI/TLS: {} findings", findings.len()))
}

pub async fn run_pki_tls(target: &str) {
    print_result(run_pki_tls_result(target).await);
}
