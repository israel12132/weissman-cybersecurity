//! GraphQL Attack Engine — introspection detection, batching, field suggestions, multi-path probing.
//! MITRE: T1046 (Network Service Discovery).

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

pub async fn run_graphql_attack_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    let graphql_paths = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/query"];
    let introspection_query = json!({"query": "{__schema{types{name}}}"});

    for path in &graphql_paths {
        let url = format!("{}{}", base, path);
        let resp = client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&introspection_query)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();

                if (status == 200 || status == 201) && body.contains("__schema") {
                    findings.push(json!({
                        "type": "graphql_attack",
                        "title": "GraphQL Introspection Enabled",
                        "severity": "high",
                        "mitre_attack": "T1046",
                        "description": format!("GraphQL introspection is enabled at {}. Attackers can enumerate all types, queries, and mutations.", url),
                        "value": url
                    }));
                } else if status == 200 && body.contains("errors") && body.contains("suggestion") {
                    findings.push(json!({
                        "type": "graphql_attack",
                        "title": "GraphQL Field Suggestion Leak",
                        "severity": "medium",
                        "mitre_attack": "T1046",
                        "description": format!("GraphQL endpoint at {} leaks field suggestions in error messages, aiding enumeration.", url),
                        "value": url
                    }));
                }

                // Check batching: send an array of queries
                let batch_query = json!([
                    {"query": "{__typename}"},
                    {"query": "{__typename}"}
                ]);
                if let Ok(br) = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .json(&batch_query)
                    .send()
                    .await
                {
                    let bstatus = br.status().as_u16();
                    let bbody = br.text().await.unwrap_or_default();
                    if bstatus == 200 && bbody.starts_with('[') {
                        findings.push(json!({
                            "type": "graphql_attack",
                            "title": "GraphQL Batching Enabled",
                            "severity": "medium",
                            "mitre_attack": "T1046",
                            "description": format!("GraphQL endpoint at {} supports query batching, enabling brute-force and DoS amplification.", url),
                            "value": url
                        }));
                    }
                }
            }
            Err(_) => continue,
        }
    }

    let message = if findings.is_empty() {
        "No GraphQL vulnerabilities detected".to_string()
    } else {
        format!("{} GraphQL issue(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_graphql_attack(target: &str) {
    print_result(run_graphql_attack_result(target).await);
}
