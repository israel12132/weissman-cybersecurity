//! GraphQL Attack Engine — introspection, batching, depth-limit, and field-suggestion probes.
//! MITRE: T1046 (Network Service Discovery).

use crate::engine_probes::{
    empty_ok, finding_with_probe_depth, http_client, http_post_json, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

const GRAPHQL_PROBE_DEPTH: &str = "graphql_introspection_surface";

fn graphql_finding(title: &str, severity: &str, description: &str, target: &str, extra: Value) -> Value {
    let mut f = finding_with_probe_depth(
        "graphql_attack",
        title,
        severity,
        "T1046",
        description,
        target,
        GRAPHQL_PROBE_DEPTH,
    );
    if let Some(obj) = f.as_object_mut() {
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    f
}

pub async fn run_graphql_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    let graphql_paths = [
        "/graphql",
        "/api/graphql",
        "/graphql/v1",
        "/v1/graphql",
        "/query",
        "/api/v1/graphql",
    ];
    let introspection_query = json!({"query": "{__schema{types{name fields{name}}}}"});
    let suggestion_query = json!({"query": "{ nonExistentWeissmanField { id } }"});
    let depth_query = json!({"query": "{ a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename a6:__typename a7:__typename a8:__typename a9:__typename a10:__typename }"});
    let batch_query = json!([
        {"query": "{__typename}"},
        {"query": "{__typename}"}
    ]);

    for path in &graphql_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);

        if let Some(p) = http_post_json(&client, &url, &introspection_query).await {
            if p.status < 500
                && p.body.contains("__schema")
                && (p.body.contains("types") || p.body.contains("fields"))
            {
                findings.push(graphql_finding(
                    "GraphQL introspection enabled",
                    "high",
                    &format!(
                        "POST {} returned __schema types/fields (HTTP {}). Full schema enumeration is possible.",
                        p.final_url, p.status
                    ),
                    target,
                    json!({ "url": p.final_url }),
                ));
            }
        }

        if let Some(p) = http_post_json(&client, &url, &suggestion_query).await {
            let body_low = p.body.to_ascii_lowercase();
            if body_low.contains("did you mean")
                || body_low.contains("suggestion")
                || body_low.contains("cannot query field")
            {
                findings.push(graphql_finding(
                    "GraphQL field suggestions leak schema hints",
                    "medium",
                    &format!(
                        "Invalid field probe on {} returned suggestion-style errors (HTTP {}) — aids schema brute-force.",
                        p.final_url, p.status
                    ),
                    target,
                    json!({ "url": p.final_url }),
                ));
            }
        }

        if let Some(p) = http_post_json(&client, &url, &batch_query).await {
            if p.status >= 200
                && p.status < 300
                && p.body.trim_start().starts_with('[')
                && p.body.contains("__typename")
            {
                findings.push(graphql_finding(
                    "GraphQL query batching enabled",
                    "medium",
                    &format!(
                        "Endpoint {} accepted a JSON array of queries and returned a batched array response — enables brute-force amplification.",
                        p.final_url
                    ),
                    target,
                    json!({ "url": p.final_url }),
                ));
            }
        }

        if let Some(p) = http_post_json(&client, &url, &depth_query).await {
            if p.status >= 200 && p.status < 500 && !p.body.to_ascii_lowercase().contains("depth") {
                findings.push(graphql_finding(
                    "GraphQL depth/complexity limit not enforced",
                    "low",
                    &format!(
                        "Repeated __typename aliases on {} returned HTTP {} without a depth-limit error — verify query cost controls.",
                        p.final_url, p.status
                    ),
                    target,
                    json!({ "url": p.final_url }),
                ));
            }
        }
    }

    if findings.is_empty() {
        empty_ok("graphql_attack", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("graphql_attack: {} live finding(s)", n))
    }
}

pub async fn run_graphql_attack(target: &str) {
    print_result(run_graphql_attack_result(target).await);
}
