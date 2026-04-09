//! HTTP Request Smuggling Engine — CL.TE confusion, TE obfuscation, dual-header probing.
//! MITRE: T1190 (Exploit Public-Facing Application).

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

pub async fn run_http_smuggling_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    // Probe 1: CL.TE — send both Content-Length and Transfer-Encoding: chunked
    // The body is a valid chunked body but the Content-Length is intentionally wrong.
    let cl_te_body = "5\r\nSMUGG\r\n0\r\n\r\n";
    let cl_te_resp = client
        .post(&base)
        .header("Content-Length", "4")
        .header("Transfer-Encoding", "chunked")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(cl_te_body)
        .send()
        .await;

    match cl_te_resp {
        Ok(r) => {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            // Server accepted both headers without a 400 → potential smuggling surface
            if status != 400 && status != 501 {
                findings.push(json!({
                    "type": "http_smuggling",
                    "title": "Potential CL.TE HTTP Request Smuggling Surface",
                    "severity": "high",
                    "mitre_attack": "T1190",
                    "description": format!(
                        "Target {} accepted a request with conflicting Content-Length and Transfer-Encoding headers (HTTP {}). This may indicate CL.TE request smuggling is possible.",
                        base, status
                    ),
                    "value": base.clone()
                }));
            }
            // Check if SMUGG leaked into the response body
            if body.to_ascii_uppercase().contains("SMUGG") {
                findings.push(json!({
                    "type": "http_smuggling",
                    "title": "Request Smuggling Body Reflection Detected",
                    "severity": "critical",
                    "mitre_attack": "T1190",
                    "description": format!("Smuggled body segment was reflected in the response from {}. Request smuggling is likely exploitable.", base),
                    "value": base.clone()
                }));
            }
        }
        Err(_) => {}
    }

    // Probe 2: TE.CL — Transfer-Encoding: xchunked (obfuscated) with valid Content-Length
    let te_cl_body = "PROBE";
    let te_obfuscated_resp = client
        .post(&base)
        .header("Transfer-Encoding", "xchunked")
        .header("Content-Length", te_cl_body.len().to_string())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(te_cl_body)
        .send()
        .await;

    match te_obfuscated_resp {
        Ok(r) => {
            let status = r.status().as_u16();
            if status == 200 || status == 301 || status == 302 {
                findings.push(json!({
                    "type": "http_smuggling",
                    "title": "Obfuscated Transfer-Encoding Accepted (TE.CL Risk)",
                    "severity": "medium",
                    "mitre_attack": "T1190",
                    "description": format!(
                        "Target {} accepted 'Transfer-Encoding: xchunked' (non-standard, obfuscated). Front-end/back-end disagreement on TE parsing is a TE.CL smuggling indicator.",
                        base
                    ),
                    "value": base.clone()
                }));
            }
        }
        Err(_) => {}
    }

    // Probe 3: Check via OPTIONS if server advertises HTTP/1.1 (required for smuggling)
    if let Ok(r) = client.request(reqwest::Method::OPTIONS, &base).send().await {
        let version = format!("{:?}", r.version());
        if version.contains("HTTP/1") {
            findings.push(json!({
                "type": "http_smuggling",
                "title": "HTTP/1.1 Protocol in Use",
                "severity": "info",
                "mitre_attack": "T1190",
                "description": format!("Target {} uses HTTP/1.1 which is required for request smuggling attacks. Upgrading to HTTP/2 end-to-end eliminates the risk.", base),
                "value": version
            }));
        }
    }

    let message = if findings.is_empty() {
        "No HTTP request smuggling indicators detected".to_string()
    } else {
        format!("{} HTTP smuggling indicator(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_http_smuggling(target: &str) {
    print_result(run_http_smuggling_result(target).await);
}
