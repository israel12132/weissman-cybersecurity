//! SSTI Engine — template injection probing via URL params and form fields, arithmetic detection.
//! MITRE: T1059 (Command and Scripting Interpreter).

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

/// SSTI payloads and the expected output when evaluated (7*7 = 49).
const SSTI_PAYLOADS: &[(&str, &str)] = &[
    ("{{7*7}}", "49"),       // Jinja2, Twig, Pebble
    ("${7*7}", "49"),        // Freemarker, Spring EL
    ("<%= 7*7 %>", "49"),    // ERB (Ruby), EJS
    ("#{7*7}", "49"),        // Thymeleaf, Groovy
    ("{{7*'7'}}", "7777777"), // Jinja2 vs Twig differentiator
    ("%7B%7B7*7%7D%7D", "49"), // URL-encoded Jinja2
];

/// Common GET parameters that might be rendered in templates.
const PROBE_PARAMS: &[&str] = &["q", "search", "query", "name", "input", "msg", "message", "text", "value", "template", "page", "id", "title", "content", "data"];

/// Common endpoints that may render user input.
const PROBE_PATHS: &[&str] = &["/", "/search", "/index", "/home", "/api/render", "/template", "/render", "/preview", "/api/preview"];

pub async fn run_ssti_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    // Probe GET params across multiple paths
    'outer: for path in PROBE_PATHS {
        let url_base = format!("{}{}", base, path);
        for param in PROBE_PARAMS {
            for (payload, expected) in SSTI_PAYLOADS {
                let probe_url = format!("{}?{}={}", url_base, param, payload);
                if let Ok(resp) = client.get(&probe_url).send().await {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    if (status == 200 || status == 201) && body.contains(expected) {
                        let engine_type = if payload.starts_with("{{") {
                            "Jinja2/Twig/Pebble"
                        } else if payload.starts_with("${") {
                            "Freemarker/Spring EL"
                        } else if payload.starts_with("<%=") {
                            "ERB/EJS"
                        } else if payload.starts_with("#{") {
                            "Thymeleaf/Groovy"
                        } else {
                            "Unknown"
                        };
                        findings.push(json!({
                            "type": "ssti",
                            "title": format!("SSTI Confirmed ({} Template Engine)", engine_type),
                            "severity": "critical",
                            "mitre_attack": "T1059",
                            "description": format!(
                                "Server-side template injection confirmed at {} via parameter '{}'. Payload '{}' evaluated to '{}'. Remote code execution may be possible.",
                                probe_url, param, payload, expected
                            ),
                            "value": probe_url
                        }));
                        break 'outer;
                    }
                }
            }
        }
    }

    // Probe POST form fields if no GET hit
    if findings.is_empty() {
        for path in PROBE_PATHS {
            let url = format!("{}{}", base, path);
            for (payload, expected) in SSTI_PAYLOADS {
                for field in PROBE_PARAMS.iter().take(6) {
                    let form_data = format!("{}={}", field, payload);
                    if let Ok(resp) = client
                        .post(&url)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .body(form_data)
                        .send()
                        .await
                    {
                        let body = resp.text().await.unwrap_or_default();
                        if body.contains(expected) {
                            findings.push(json!({
                                "type": "ssti",
                                "title": "SSTI Confirmed via POST Form Field",
                                "severity": "critical",
                                "mitre_attack": "T1059",
                                "description": format!(
                                    "Server-side template injection confirmed at {} via POST field '{}'. Payload '{}' evaluated to '{}'.",
                                    url, field, payload, expected
                                ),
                                "value": url
                            }));
                            break;
                        }
                    }
                }
                if !findings.is_empty() {
                    break;
                }
            }
            if !findings.is_empty() {
                break;
            }
        }
    }

    let message = if findings.is_empty() {
        "No SSTI vulnerabilities detected".to_string()
    } else {
        format!("{} SSTI issue(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_ssti(target: &str) {
    print_result(run_ssti_result(target).await);
}
