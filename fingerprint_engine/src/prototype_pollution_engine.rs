//! Prototype Pollution Engine — JSON body probing, query param injection, error reflection check.
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

pub async fn run_prototype_pollution_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    let api_paths = ["/api", "/api/v1", "/api/v2", "/graphql", "/data", "/submit", "/"];

    // Payload 1: __proto__ pollution
    let proto_payload = json!({"__proto__": {"polluted": "weissman_pp_test"}});
    // Payload 2: constructor.prototype pollution
    let constructor_payload = json!({"constructor": {"prototype": {"polluted": "weissman_pp_test"}}});

    for path in &api_paths {
        let url = format!("{}{}", base, path);

        // Try __proto__ JSON body
        if let Ok(resp) = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&proto_payload)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if body.contains("weissman_pp_test") || body.contains("polluted") {
                findings.push(json!({
                    "type": "prototype_pollution",
                    "title": "Prototype Pollution: __proto__ Reflected in Response",
                    "severity": "critical",
                    "mitre_attack": "T1059",
                    "description": format!(
                        "Endpoint {} reflected the __proto__ pollution payload back in the response. Server-side prototype pollution is likely exploitable.",
                        url
                    ),
                    "value": url
                }));
            } else if status == 200 || status == 201 || status == 422 {
                // Endpoint accepts JSON — mark as candidate even without reflection
                findings.push(json!({
                    "type": "prototype_pollution",
                    "title": "JSON API Endpoint Accepts __proto__ Payload",
                    "severity": "medium",
                    "mitre_attack": "T1059",
                    "description": format!(
                        "Endpoint {} accepted a JSON body with __proto__ key (HTTP {}). Manual verification of server-side prototype pollution is recommended.",
                        url, status
                    ),
                    "value": url
                }));
                break; // One finding per endpoint type is enough
            }
        }

        // Try constructor.prototype JSON body
        if let Ok(resp) = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&constructor_payload)
            .send()
            .await
        {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("weissman_pp_test") || body.contains("polluted") {
                findings.push(json!({
                    "type": "prototype_pollution",
                    "title": "Prototype Pollution: constructor.prototype Reflected",
                    "severity": "critical",
                    "mitre_attack": "T1059",
                    "description": format!(
                        "Endpoint {} reflected the constructor.prototype pollution payload. Server-side prototype pollution confirmed.",
                        url
                    ),
                    "value": url
                }));
            }
        }
    }

    // Query parameter pollution probes
    let qp_urls = [
        format!("{}/?__proto__[polluted]=weissman_pp_test", base),
        format!("{}/?constructor[prototype][polluted]=weissman_pp_test", base),
    ];
    for url in &qp_urls {
        if let Ok(resp) = client.get(url).send().await {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("weissman_pp_test") || body.contains("polluted") {
                findings.push(json!({
                    "type": "prototype_pollution",
                    "title": "Prototype Pollution via Query Parameter Reflected",
                    "severity": "high",
                    "mitre_attack": "T1059",
                    "description": format!(
                        "Query parameter prototype pollution payload was reflected in the response from {}.",
                        url
                    ),
                    "value": url
                }));
            }
        }
    }

    let message = if findings.is_empty() {
        "No prototype pollution indicators detected".to_string()
    } else {
        format!("{} prototype pollution issue(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_prototype_pollution(target: &str) {
    print_result(run_prototype_pollution_result(target).await);
}
