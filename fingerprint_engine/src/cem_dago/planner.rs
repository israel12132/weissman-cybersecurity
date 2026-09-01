//! Supreme Council / vLLM fallback planner.
//!
//! When deterministic engines and graph pivots are exhausted, collect blackboard
//! failures and ask the sovereign LLM for:
//! 1. An **OffensiveQueryPlan** — alternative live probes (validated against
//!    `PRODUCTION_ENGINE_IDS`; findings in the JSON are dropped — 0 fabricated).
//! 2. Optionally a classic Ask-Weissman [`crate::nl_query::QueryPlan`] executed
//!    **only** against `weissman_ro` (compile + SELECT-only on the 13-table
//!    allow-list). The application pool is never used for council SQL.
//!
//! If vLLM is unreachable, the planner degrades to a static graph fallback map
//! (does not freeze or drop the scan).

use super::blackboard::{FailureLog, ScanBlackboard};
use super::pivot::fallback_engine_ids;
use super::queryplan_sandbox::{
    execute_plan_under_ro_sandbox, failures_for_llm, probe_reason_allowed, probe_target_allowed,
    reject_query_plan_injection, sanitize_blackboard_text, signals_for_llm,
};
use crate::elite_hardening::nl_guard::ASK_WEISSMAN_TABLE_COUNT;
use crate::nl_query::{compile_plan, QueryPlan};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::HashSet;
use weissman_core::models::engine::{is_production_engine_id, resolve_engine_id};

const MAX_PROBES: usize = 8;
const PLANNER_TIMEOUT_SECS: u64 = 45;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OffensiveProbe {
    #[serde(default)]
    pub engine_id: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OffensiveQueryPlan {
    #[serde(default)]
    pub probes: Vec<OffensiveProbe>,
    #[serde(default)]
    pub rationale: String,
    /// Optional Ask-Weissman QueryPlan (table/select/filters) — never raw SQL.
    #[serde(default)]
    pub telemetry_query: Option<QueryPlan>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannerResult {
    pub invoked: bool,
    pub reachable: bool,
    pub degraded: bool,
    pub plan: Option<OffensiveQueryPlan>,
    pub telemetry_rows: usize,
    pub rejected_probes: Vec<String>,
    pub error: Option<String>,
}

impl Default for PlannerResult {
    fn default() -> Self {
        Self {
            invoked: false,
            reachable: false,
            degraded: false,
            plan: None,
            telemetry_rows: 0,
            rejected_probes: Vec::new(),
            error: None,
        }
    }
}

/// Owned planner inputs — no short lifetimes across the vLLM await.
#[derive(Clone)]
pub struct PlannerInput {
    pub target: String,
    pub llm_base_url: String,
    pub llm_model: String,
    pub tenant_id: i64,
    pub enabled: Vec<String>,
    pub already: HashSet<String>,
}

/// Validate probes: production engine ids only, non-empty target, cap length.
/// Any `findings` field the model invents is ignored.
#[must_use]
pub fn validate_offensive_plan(
    raw: &Value,
    fallback_target: &str,
) -> (OffensiveQueryPlan, Vec<String>) {
    let mut rejected = Vec::new();
    let rationale = sanitize_blackboard_text(
        raw.get("rationale").and_then(Value::as_str).unwrap_or(""),
        480,
    );
    let telemetry_query = raw
        .get("telemetry_query")
        .cloned()
        .and_then(|v| serde_json::from_value::<QueryPlan>(v).ok())
        .and_then(|qp| {
            if reject_query_plan_injection(&qp).is_err() {
                return None;
            }
            if compile_plan(&qp, 0).is_err() {
                None
            } else {
                Some(qp)
            }
        });

    let mut probes = Vec::new();
    if let Some(arr) = raw.get("probes").and_then(Value::as_array) {
        for p in arr {
            if probes.len() >= MAX_PROBES {
                rejected.push("probe_cap".into());
                break;
            }
            let engine_id = p
                .get("engine_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if engine_id.is_empty() || !is_production_engine_id(&engine_id) {
                rejected.push(format!("rejected_engine:{engine_id}"));
                continue;
            }
            let mut target = p
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if target.is_empty() {
                target = fallback_target.to_string();
            }
            if target.trim().is_empty() {
                rejected.push(format!("empty_target:{engine_id}"));
                continue;
            }
            if !probe_target_allowed(&target) {
                if probe_target_allowed(fallback_target) {
                    target = fallback_target.to_string();
                } else {
                    rejected.push(format!("unsafe_target:{engine_id}"));
                    continue;
                }
            }
            let mut reason = p
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if !probe_reason_allowed(&reason) {
                reason.clear();
            }
            let mitre = p
                .get("mitre_techniques")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            probes.push(OffensiveProbe {
                engine_id,
                target,
                reason,
                mitre_techniques: mitre,
            });
        }
    }
    (
        OffensiveQueryPlan {
            probes,
            rationale,
            telemetry_query,
        },
        rejected,
    )
}

/// Static fallback edges when a named engine fails (graph-shaped, not LLM).
#[must_use]
pub fn static_fallback_engine_ids(failed: &str) -> &'static [&'static str] {
    match resolve_engine_id(failed) {
        "scada_ics" | "ot_ics" | "modbus_tcp" => &["iot_firmware", "ble_rf", "ot_ics", "scada_ics"],
        "iot_firmware" => &["scada_ics", "ble_rf", "ot_ics"],
        "ble_rf" => &["iot_firmware", "scada_ics"],
        "graphql_attack" => &["waf_bypass", "http_smuggling", "websocket_attack"],
        "waf_bypass" => &["http_smuggling", "graphql_attack"],
        "http_smuggling" => &["waf_bypass", "websocket_attack"],
        "kerberoasting" => &["password_spray", "smb_netbios"],
        "password_spray" => &["kerberoasting", "smb_netbios"],
        "aws_attack" => &["cloud_posture", "azure_attack", "gcp_attack"],
        "azure_attack" => &["cloud_posture", "aws_attack", "gcp_attack"],
        "gcp_attack" => &["cloud_posture", "aws_attack"],
        "websocket_attack" => &["graphql_attack", "http_smuggling"],
        _ => &[],
    }
}

/// Build a live-probe plan from the static graph map + Dijkstra-style overlap.
/// Never invents findings.
#[must_use]
pub fn static_graph_fallback_plan(
    target: &str,
    failures: &[FailureLog],
    enabled: &[String],
    already: &HashSet<String>,
    route_signals: &[String],
) -> OffensiveQueryPlan {
    let mut probes = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for fail in failures {
        for id in static_fallback_engine_ids(&fail.engine_id) {
            push_probe(
                &mut probes,
                &mut seen,
                id,
                target,
                enabled,
                already,
                fail.engine_id.as_str(),
            );
            if probes.len() >= MAX_PROBES {
                break;
            }
        }
    }
    if probes.is_empty() {
        let failed = failures.last().map(|f| f.engine_id.as_str()).unwrap_or("");
        for id in fallback_engine_ids(failed, enabled, already, route_signals, MAX_PROBES) {
            push_probe(
                &mut probes,
                &mut seen,
                &id,
                target,
                enabled,
                already,
                "graph_overlap",
            );
        }
    }
    OffensiveQueryPlan {
        probes,
        rationale: "vLLM unreachable — static attack-graph fallback rules (no fabricated findings)"
            .into(),
        telemetry_query: None,
    }
}

fn push_probe(
    probes: &mut Vec<OffensiveProbe>,
    seen: &mut HashSet<String>,
    id: &str,
    target: &str,
    enabled: &[String],
    already: &HashSet<String>,
    because: &str,
) {
    if probes.len() >= MAX_PROBES {
        return;
    }
    if already.contains(id) || seen.contains(id) {
        return;
    }
    if !enabled.iter().any(|e| e == id) {
        return;
    }
    if !is_production_engine_id(id) {
        return;
    }
    seen.insert(id.to_string());
    probes.push(OffensiveProbe {
        engine_id: id.to_string(),
        target: target.to_string(),
        reason: format!("static graph fallback after {because}"),
        mitre_techniques: Vec::new(),
    });
}

pub async fn trigger_supreme_council_planner(
    blackboard: &ScanBlackboard,
    input: &PlannerInput,
    ro_pool: Option<&PgPool>,
) -> PlannerResult {
    tracing::info!(
        target: "cem_dago",
        scan_id = %blackboard.scan_id(),
        "classic engines exhausted — invoking Supreme Council planner"
    );
    metrics::counter!("weissman_cem_dago_council_invocations_total").increment(1);

    let failures = blackboard.list_failures().await.unwrap_or_default();
    let signals = blackboard.present_signals().await.unwrap_or_default();
    let fail_json = failures_for_llm(&failures);
    let signals_safe = signals_for_llm(&signals);

    if !super::council_enabled() {
        return degrade(
            &input.target,
            &failures,
            &input.enabled,
            &input.already,
            &signals,
            "council disabled",
        );
    }

    let llm = call_vllm(
        &input.llm_base_url,
        &input.llm_model,
        &input.target,
        &signals_safe,
        &fail_json,
    )
    .await;

    match llm {
        Ok(text) => {
            let parsed = parse_json_object(&text);
            let Some(raw) = parsed else {
                return degrade(
                    &input.target,
                    &failures,
                    &input.enabled,
                    &input.already,
                    &signals,
                    "planner output is not JSON",
                );
            };
            let (mut plan, rejected) = validate_offensive_plan(&raw, &input.target);
            let telemetry_rows =
                execute_telemetry_on_weissman_ro(&mut plan, ro_pool, input.tenant_id).await;
            PlannerResult {
                invoked: true,
                reachable: true,
                degraded: false,
                plan: Some(plan),
                telemetry_rows,
                rejected_probes: rejected,
                error: None,
            }
        }
        Err(e) => {
            tracing::warn!(target: "cem_dago", error = %e, "vLLM planner degraded to static graph rules");
            metrics::counter!("weissman_cem_dago_council_degraded_total").increment(1);
            degrade(
                &input.target,
                &failures,
                &input.enabled,
                &input.already,
                &signals,
                &e,
            )
        }
    }
}

fn degrade(
    target: &str,
    failures: &[FailureLog],
    enabled: &[String],
    already: &HashSet<String>,
    signals: &[String],
    why: &str,
) -> PlannerResult {
    let plan = static_graph_fallback_plan(target, failures, enabled, already, signals);
    PlannerResult {
        invoked: true,
        reachable: false,
        degraded: true,
        plan: Some(plan),
        telemetry_rows: 0,
        rejected_probes: Vec::new(),
        error: Some(why.to_string()),
    }
}

/// Council SQL runs only on the weissman_ro pool, after the hermetic QueryPlan
/// sandbox (identifier allow-list + injection needles + compiled-SQL guard).
/// The application pool is never used.
async fn execute_telemetry_on_weissman_ro(
    plan: &mut OffensiveQueryPlan,
    ro_pool: Option<&PgPool>,
    tenant_id: i64,
) -> usize {
    let Some(qp) = plan.telemetry_query.clone() else {
        return 0;
    };
    debug_assert_eq!(
        crate::nl_query::allowed_table_count(),
        ASK_WEISSMAN_TABLE_COUNT
    );
    match execute_plan_under_ro_sandbox(qp, ro_pool, tenant_id).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(target: "cem_dago", error = %e, "telemetry QueryPlan rejected by weissman_ro sandbox");
            plan.telemetry_query = None;
            0
        }
    }
}

async fn call_vllm(
    llm_base_url: &str,
    llm_model: &str,
    target: &str,
    signals: &[String],
    fail_json: &Value,
) -> Result<String, String> {
    let base = effective_llm_base(llm_base_url);
    let url = if base.ends_with("/chat/completions") {
        base
    } else {
        format!("{base}/chat/completions")
    };

    let target_safe = sanitize_blackboard_text(target, 200);
    let prompt = format!(
        "Analyze the following attack failures and current scan telemetry. \
         Generate a high-fidelity JSON object with keys: \
         probes (array of {{engine_id, target, reason, mitre_techniques}}), \
         rationale (string), \
         telemetry_query (optional QueryPlan with table/select/filters/limit for risk_graph_nodes or risk_graph_edges). \
         Use only real Weissman production engine_id values. Do not invent findings. \
         telemetry_query.table must be one of the 17 weissman_ro tables (never users). \
         telemetry_query must contain only allow-listed identifiers — never SQL, never pg_ catalog names.\n\
         Target: {target_safe}\nSignals: {signals:?}\nFailures: {fail_json}"
    );

    let client = crate::outbound_http::external_json_client().map_err(|e| e.to_string())?;
    let model = if llm_model.trim().is_empty() {
        "meta-llama/Meta-Llama-3.1-70B-Instruct"
    } else {
        llm_model.trim()
    };

    let body = json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are the Weissman Supreme Council Planner. Output ONLY valid JSON. \
    No fabricated vulnerabilities. probes[].engine_id must be a real production engine. \
    telemetry_query if present must be a QueryPlan (never raw SQL) against the 13-table weissman_ro allow-list."
            },
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
        "max_tokens": 2048
    });

    let response = tokio::time::timeout(
        std::time::Duration::from_secs(PLANNER_TIMEOUT_SECS),
        client.post(&url).json(&body).send(),
    )
    .await
    .map_err(|_| "vLLM planner timeout".to_string())?;

    let res = response.map_err(|e| format!("vLLM unreachable: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("vLLM HTTP {}", res.status()));
    }
    let v: Value = res.json().await.map_err(|e| e.to_string())?;
    let text = extract_content(&v).ok_or_else(|| "vLLM content missing".to_string())?;
    Ok(text)
}

fn effective_llm_base(explicit: &str) -> String {
    let t = explicit.trim().trim_end_matches('/');
    if !t.is_empty() {
        return t.to_string();
    }
    std::env::var("WEISSMAN_LLM_BASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .unwrap_or_else(|| {
            weissman_engines::openai_chat::DEFAULT_LLM_BASE_URL
                .trim_end_matches('/')
                .to_string()
        })
}

/// OpenAI-compatible `choices` is an **array**, never an object keyed by index.
/// `message.content` may be a string or an array of text parts.
pub(crate) fn extract_content(body: &Value) -> Option<String> {
    let content = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))?;
    match content {
        Value::String(s) => Some(s.clone()),
        Value::Array(parts) => {
            let text: String = parts
                .iter()
                .filter_map(|p| {
                    p.as_str()
                        .map(str::to_string)
                        .or_else(|| p.get("text").and_then(Value::as_str).map(str::to_string))
                })
                .collect();
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        }
        _ => None,
    }
}

fn parse_json_object(text: &str) -> Option<Value> {
    let t = text.trim();
    let t = t
        .strip_prefix("```json")
        .or_else(|| t.strip_prefix("```"))
        .unwrap_or(t)
        .trim_end_matches('`')
        .trim();
    if let Ok(v) = serde_json::from_str::<Value>(t) {
        if v.is_object() {
            return Some(v);
        }
    }
    let start = t.find('{')?;
    let end = t.rfind('}')?;
    serde_json::from_str(&t[start..=end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_engine_and_strips_fake_findings() {
        let raw = json!({
            "rationale": "try OT via firmware",
            "probes": [
                {
                    "engine_id": "not_a_real_engine",
                    "target": "10.0.0.1",
                    "findings": [{"title": "FAKE RCE"}]
                },
                {
                    "engine_id": "osint",
                    "target": "https://example.com",
                    "reason": "recon",
                    "findings": [{"title": "should be dropped"}]
                }
            ]
        });
        let (plan, rejected) = validate_offensive_plan(&raw, "https://fallback.example");
        assert!(rejected.iter().any(|r| r.contains("not_a_real_engine")));
        assert_eq!(plan.probes.len(), 1);
        assert_eq!(plan.probes[0].engine_id, "osint");
        assert!(plan.probes[0].reason.contains("recon"));
    }

    #[test]
    fn compile_rejects_unsafe_table() {
        let qp = QueryPlan {
            table: "pg_shadow".into(),
            select: vec!["passwd".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: Some(1),
            ..QueryPlan::default()
        };
        assert!(compile_plan(&qp, 1).is_err());
    }

    #[test]
    fn compile_rejects_users_table() {
        let qp = QueryPlan {
            table: "users".into(),
            select: vec!["id".into()],
            filters: vec![],
            order_by: None,
            order_desc: false,
            limit: Some(1),
            ..QueryPlan::default()
        };
        assert!(compile_plan(&qp, 1).is_err());
    }

    #[test]
    fn extract_openai_content_from_choices_array() {
        let body = json!({
            "choices": [{"message": {"content": "{\"probes\":[]}"}}]
        });
        assert!(extract_content(&body).unwrap().contains("probes"));

        let parts = json!({
            "choices": [{"message": {"content": [
                {"type": "text", "text": "{\"probes\":"},
                {"type": "text", "text": "[]}"}
            ]}}]
        });
        assert_eq!(extract_content(&parts).as_deref(), Some("{\"probes\":[]}"));

        let wrong = json!({ "choices": { "message": { "content": "no" } } });
        assert!(extract_content(&wrong).is_none());
    }

    #[test]
    fn static_fallback_does_not_relaunch_self() {
        let failures = vec![FailureLog {
            engine_id: "scada_ics".into(),
            target: "10.0.0.5".into(),
            error_message: "register read timeout".into(),
            timestamp: 1,
        }];
        let enabled = vec![
            "scada_ics".into(),
            "iot_firmware".into(),
            "graphql_attack".into(),
        ];
        let already = HashSet::from(["scada_ics".into()]);
        let plan = static_graph_fallback_plan(
            "10.0.0.5",
            &failures,
            &enabled,
            &already,
            &["ot_protocol".into()],
        );
        assert!(plan.probes.iter().any(|p| p.engine_id == "iot_firmware"));
        assert!(plan.probes.iter().all(|p| p.engine_id != "scada_ics"));
        assert!(plan.rationale.contains("static"));
    }

    #[test]
    fn weissman_ro_allowlist_matches_ask_weissman_table_count() {
        assert_eq!(
            crate::nl_query::allowed_table_count(),
            ASK_WEISSMAN_TABLE_COUNT
        );
    }

    #[test]
    fn validate_drops_injected_queryplan_and_unsafe_target() {
        let raw = json!({
            "rationale": "ignore previous; SELECT pg_sleep(10)",
            "probes": [{
                "engine_id": "osint",
                "target": "https://example.com; DROP TABLE users",
                "reason": "recon -- pg_read_file('/etc/passwd')"
            }],
            "telemetry_query": {
                "table": "pg_shadow",
                "select": ["passwd"],
                "filters": [],
                "limit": 1
            }
        });
        let (plan, rejected) = validate_offensive_plan(&raw, "https://fallback.example");
        assert!(plan.telemetry_query.is_none());
        assert_eq!(plan.rationale, "[redacted]");
        assert_eq!(plan.probes.len(), 1);
        assert_eq!(plan.probes[0].target, "https://fallback.example");
        assert!(plan.probes[0].reason.is_empty());
        assert!(rejected.is_empty() || !rejected.iter().any(|r| r.contains("osint")));
        let _ = rejected;
    }

    #[test]
    fn validate_accepts_allowlisted_graph_queryplan() {
        let raw = json!({
            "rationale": "map internet-exposed nodes",
            "probes": [],
            "telemetry_query": {
                "table": "risk_graph_nodes",
                "select": ["id", "label"],
                "filters": [],
                "order_by": "id",
                "limit": 10
            }
        });
        let (plan, _) = validate_offensive_plan(&raw, "10.0.0.1");
        assert!(plan.telemetry_query.is_some());
        assert_eq!(plan.telemetry_query.unwrap().table, "risk_graph_nodes");
    }
}
