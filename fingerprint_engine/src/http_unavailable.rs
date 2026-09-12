//! Store-down JSON for list APIs.
//!
//! A query failure must never look like a healthy empty tenant (`ok: true` + `[]`).
//! Callers return HTTP 503 with these envelopes.

use serde_json::{json, Value};

fn list_envelope(collection: &'static str, detail: &str) -> Value {
    let mut v = json!({
        "ok": false,
        "unavailable": true,
        "detail": detail,
    });
    v[collection] = json!([]);
    v
}

/// `GET /api/playbooks`
pub fn playbook_list_unavailable_json(detail: &str) -> Value {
    list_envelope("playbooks", detail)
}

/// `GET /api/playbooks/:id/runs`
pub fn playbook_runs_unavailable_json(detail: &str) -> Value {
    list_envelope("runs", detail)
}

/// `GET /api/clients/:id/identity-contexts`
pub fn identity_contexts_unavailable_json(detail: &str) -> Value {
    list_envelope("contexts", detail)
}

/// `GET /api/clients/:id/privilege-escalation`
pub fn privilege_events_unavailable_json(detail: &str) -> Value {
    list_envelope("events", detail)
}

/// `GET /api/clients/:id/runtime-traces`
pub fn runtime_traces_unavailable_json(detail: &str) -> Value {
    list_envelope("traces", detail)
}

/// `GET /api/clients/:id/containment-rules`
pub fn containment_rules_unavailable_json(detail: &str) -> Value {
    list_envelope("rules", detail)
}

/// `GET /api/pipeline/state`
pub fn pipeline_state_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "run_id": null,
        "states": [],
        "stage_labels": [],
        "detail": detail,
    })
}

/// `GET /api/oast/callbacks` health object when the hit table cannot be read.
/// `callback_count` stays null — never a live `0` on store-down.
pub fn oast_callbacks_store_down_health() -> Value {
    json!({
        "configured": crate::fuzz_oob::oast_correlation_enabled(),
        "domain": crate::fuzz_oob::oast_hook_domain().unwrap_or_default(),
        "last_callback_at": Value::Null,
        "callback_count": Value::Null,
    })
}

/// `GET /api/oast/callbacks`
pub fn oast_callbacks_unavailable_json(detail: &str, health: Value) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "callbacks": [],
        "health": health,
        "detail": detail,
    })
}

/// `GET /api/clients/:id/llm-fuzz/events`
pub fn llm_fuzz_events_unavailable_json(detail: &str) -> Value {
    list_envelope("events", detail)
}

/// `GET /api/clients/:id/llm-fuzz/summary`
pub fn llm_fuzz_summary_unavailable_json(detail: &str) -> Value {
    list_envelope("vectors", detail)
}

/// `GET /api/edge-swarm/nodes`
pub fn edge_swarm_nodes_unavailable_json(detail: &str) -> Value {
    list_envelope("nodes", detail)
}

/// `GET /api/clients/:id/ot-ics/fingerprints`
pub fn ot_ics_fingerprints_unavailable_json(detail: &str) -> Value {
    list_envelope("fingerprints", detail)
}

/// `GET /api/clients/:id/engagements`
pub fn engagements_unavailable_json(detail: &str) -> Value {
    list_envelope("engagements", detail)
}

/// `GET /api/clients/:id/evidence`
pub fn evidence_unavailable_json(detail: &str) -> Value {
    list_envelope("evidence", detail)
}

/// `GET /api/sovereign-defense/:id/chronos/events`
pub fn chronos_events_unavailable_json(detail: &str) -> Value {
    list_envelope("events", detail)
}

/// `GET /api/sovereign-defense/:id/cognitive/sessions`
pub fn cognitive_sessions_unavailable_json(detail: &str) -> Value {
    list_envelope("sessions", detail)
}

/// `GET /api/alerts/rules`
pub fn alert_rules_unavailable_json(detail: &str) -> Value {
    list_envelope("rules", detail)
}

/// `GET /api/enterprise/settings` — never confirm safe-mode off on store-down
pub fn enterprise_settings_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "global_safe_mode": Value::Null,
        "alert_webhook_url": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/audit/logs`
pub fn audit_logs_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "entries": [],
        "total": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/clients/:id/sbom`
pub fn sbom_components_unavailable_json(detail: &str) -> Value {
    list_envelope("components", detail)
}

/// `GET /api/verify-audit/:hash`
pub fn audit_verify_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "verified": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/clients/:id/config`
pub fn client_config_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "config": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/clients/:id/heal-requests`
pub fn heal_requests_unavailable_json(detail: &str) -> Value {
    list_envelope("requests", detail)
}

/// `GET /api/clients/:id/risk-graph`
pub fn risk_graph_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "nodes": [],
        "edges": [],
        "detail": detail,
    })
}

/// `GET /api/baseline/summary`
pub fn baseline_summary_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "total_assets": Value::Null,
        "drift_score": Value::Null,
        "last_updated": Value::Null,
        "sample_count": Value::Null,
        "baseline_rows": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/baseline/drift`
pub fn baseline_drift_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "data": [],
        "detail": detail,
    })
}

/// `GET /api/baseline/anomalies`
pub fn baseline_anomalies_unavailable_json(detail: &str) -> Value {
    list_envelope("anomalies", detail)
}

/// `GET /api/roe/override-requests`
pub fn roe_override_requests_unavailable_json(detail: &str) -> Value {
    list_envelope("requests", detail)
}

/// `GET /api/clients` when the tenant client list cannot be read
pub fn clients_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "clients": [],
        "detail": detail,
    })
}

/// `POST /api/cnapp/refresh` when the client fan-out query fails
pub fn cnapp_refresh_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "jobs": [],
        "jobs_queued": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/cnapp/status`
pub fn cnapp_jobs_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "jobs": [],
        "running": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/soar` execution index
pub fn soar_executions_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "executions": [],
        "detail": detail,
    })
}

/// `GET /api/agents/isolate` status list
pub fn isolate_agents_unavailable_json(detail: &str) -> Value {
    list_envelope("agents", detail)
}

/// `GET /api/heal/stats` tenant aggregates
pub fn heal_stats_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "total": Value::Null,
        "fixed": Value::Null,
        "broke_app": Value::Null,
        "still_vulnerable": Value::Null,
        "delivered": Value::Null,
        "attested": Value::Null,
        "success_rate": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/evidence/:id/download` — never 404 a SQL error, never serve an empty blob as success
pub fn evidence_download_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "detail": detail,
    })
}

/// `GET /api/clients/:id/attack-chain`
pub fn attack_chain_unavailable_json(detail: &str) -> Value {
    list_envelope("steps", detail)
}

/// `GET /api/clients/:id/attack-surface` graph
pub fn asm_graph_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "nodes": [],
        "edges": [],
        "run_id": Value::Null,
        "vuln_findings": [],
        "detail": detail,
    })
}

/// `GET /api/first-mover/nerve` when OAST hit aggregates cannot be read
pub fn first_mover_nerve_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "detail": detail,
        "oast": {
            "configured": Value::Null,
            "domain": Value::Null,
            "last_callback_at": Value::Null,
            "recent_callback_count": Value::Null,
        },
    })
}

/// `GET /api/clients/:id/semantic/state-machine`
pub fn semantic_logs_unavailable_json(detail: &str) -> Value {
    list_envelope("logs", detail)
}

/// `GET /api/clients/:id/semantic/reasoning`
pub fn semantic_reasoning_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "reasoning_text": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/system/configs`
pub fn system_configs_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "configs": [],
        "detail": detail,
    })
}

/// `GET /api/clients/:id/deception`
pub fn deception_assets_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "assets": [],
        "detail": detail,
    })
}

/// `POST /api/clients/:id/deception/generate`
pub fn deception_generate_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "inserted": Value::Null,
        "detail": detail,
    })
}

/// GitHub token registry cannot be read — never 400 "git_token required" on store-down
pub fn github_token_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "error": "git_token_unavailable",
        "detail": detail,
        "code": "db_unavailable",
    })
}

/// `POST /api/clients/:id/heal-batch` when findings or specs cannot be confirmed
pub fn heal_batch_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "enqueued": Value::Null,
        "skipped": Value::Null,
        "results": [],
        "detail": detail,
    })
}

/// `POST /api/sovereign/phantom-trap` when LLM config cannot be confirmed
pub fn phantom_trap_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "error": "DB unavailable",
        "detail": detail,
    })
}

/// `GET /api/command-center/ticker` — never a live-empty event wall on store-down
pub fn command_center_ticker_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "events": [],
        "detail": detail,
    })
}

/// ITDR connector save/pull persist when the store cannot be confirmed
pub fn itdr_connectors_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "connectors": {},
        "detail": detail,
    })
}

/// CEO strategy/HPC/vault/god-mode writes — never 400 + SQL on store-down
pub fn ceo_write_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "detail": detail,
        "code": "db_unavailable",
    })
}

/// Billing usage/checkout/sync when the subscription store cannot be read
pub fn billing_store_down_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "code": "db_unavailable",
        "subscription": Value::Null,
        "usage": Value::Null,
        "checkout_url": Value::Null,
        "detail": detail,
    })
}

/// God Mode snapshot when policy configs cannot be confirmed
pub fn god_mode_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "scan_interval_secs": Value::Null,
        "engine_matrix": Value::Null,
        "detail": detail,
    })
}

/// Sovereign Operator knowledge bus — never ok:true live:true empty theater
pub fn sovereign_operator_knowledge_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "knowledge": Value::Null,
        "detail": detail,
    })
}

/// Sovereign Operator chat when tenant LLM config cannot be confirmed
pub fn sovereign_operator_chat_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "session_id": Value::Null,
        "reply": Value::Null,
        "tools": [],
        "detail": detail,
    })
}

/// `GET /api/oast/verify/:token` when hit counts cannot be confirmed
pub fn oast_verify_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "oob_confirmed": Value::Null,
        "hit_count": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/clients/:id/first-seen-hits` — never advertise zero pre-NVD counts on store-down
pub fn first_seen_hits_unavailable_json(client_id: i64, detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "client_id": client_id,
        "hits": [],
        "first_seen_count": Value::Null,
        "listed_count": Value::Null,
        "skipped_count": Value::Null,
        "detail": detail,
    })
}

/// `POST /api/system/configs` when the store cannot take writes
pub fn system_configs_write_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "updated": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/clients/:id/cicd-findings` and `GET /api/clients/:id/poe-findings`
pub fn findings_unavailable_json(detail: &str) -> Value {
    list_envelope("findings", detail)
}

/// `GET /api/findings/clusters` when the cluster query cannot be read
pub fn findings_clusters_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "clusters": [],
        "total": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/intel/suppressions` when the suppression table cannot be read
pub fn intel_suppressions_unavailable_json(detail: &str) -> Value {
    list_envelope("suppressions", detail)
}

/// `GET /api/intel/status` when KEV/EPSS mirrors cannot be counted
pub fn intel_status_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "kev": { "rows": Value::Null, "last_refresh": Value::Null },
        "epss": { "rows": Value::Null, "last_refresh": Value::Null },
        "detail": detail,
    })
}

/// `GET /api/reports` when report_runs cannot be listed
pub fn reports_unavailable_json(detail: &str) -> Value {
    list_envelope("reports", detail)
}

/// `GET /api/onboarding/tenant-status` when tenant config cannot be confirmed
pub fn onboarding_tenant_status_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "llm_configured": Value::Null,
        "oast_configured": Value::Null,
        "ai_heavy_entitled": Value::Null,
        "oast_listener_url": Value::Null,
        "oast_domain": Value::Null,
        "oast_api_key_configured": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/clients/:id/readiness` when the client/agent/tenant facts cannot be read
pub fn client_readiness_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "readiness": Value::Null,
        "tenant": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/tenant/brand` when tenant_brand cannot be read
pub fn tenant_brand_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "brand": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/vngfw/status` and apply/put when policy cannot be confirmed
pub fn vngfw_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "applied": Value::Null,
        "policy": Value::Null,
        "detail": detail,
    })
}

/// Login / MFA policy when the identity store cannot be read
pub fn auth_degraded_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "code": "auth_degraded",
        "detail": detail,
    })
}

/// `GET /api/clients/:id/vulnerabilities/:id/sealed-poc`
pub fn sealed_poc_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "detail": detail,
    })
}

/// `POST /api/sovereign-defense/:id/liquid-matrix/rotate` when the pool UPDATE fails
pub fn sovereign_rotate_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "detail": detail,
    })
}

/// `GET /api/rate-limits/status` when Redis is enabled but unreadable
pub fn rate_limits_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "limits": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/rate-limits/analytics` when Redis is enabled but unreadable
pub fn rate_limits_analytics_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "current": Value::Null,
        "history": [],
        "violations": [],
        "endpoints": [],
        "detail": detail,
    })
}

/// `GET /api/dashboard/stats` when the store cannot be read
pub fn dashboard_stats_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "total_vulnerabilities": Value::Null,
        "active_scans": Value::Null,
        "security_score": Value::Null,
        "assets_monitored": Value::Null,
        "threats_mitigated": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/metrics/dashboard` when postgres or tenant aggregates fail
pub fn metrics_dashboard_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "postgres_ok": false,
        "active_scans": Value::Null,
        "findings_by_severity": Value::Null,
        "jobs": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/dashboard/exec-kpis` when a severity/trend/side-KPI query fails
pub fn exec_kpis_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "trend": Value::Null,
        "security_score": Value::Null,
        "severity": Value::Null,
        "severity_delta_24h": Value::Null,
        "open_vs_resolved": Value::Null,
        "assets": Value::Null,
        "agents": Value::Null,
        "jobs": Value::Null,
        "scan_velocity": Value::Null,
        "mttr_hours": Value::Null,
        "scoring": Value::Null,
        "mitre_top": Value::Null,
        "engines_top": Value::Null,
        "clients_top": Value::Null,
        "cves_top": Value::Null,
        "last_updated_unix": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/poe-scan/:id` when the job row cannot be read
pub fn poe_job_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "job": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/clients/:id` when the client row cannot be read — never 404 a SQL error
pub fn client_lookup_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "detail": detail,
        "code": "db_unavailable",
    })
}

/// Client PDF / executive board pack when findings cannot be read — never a 200 empty/zero pack
pub fn report_pdf_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "findings": [],
        "critical": Value::Null,
        "high": Value::Null,
        "medium": Value::Null,
        "low": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/compliance/posture` when mapped findings cannot be read
pub fn compliance_posture_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "frameworks": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/heal-verify/:job_id/steps` when verification steps cannot be read
pub fn heal_verify_steps_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "steps": [],
        "detail": detail,
    })
}

/// `GET /api/clients/:id/heal-trends` when heal_requests cannot be aggregated
pub fn heal_trends_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "trend": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/clients/:id/heal-priorities` when open findings cannot be ranked
pub fn heal_priorities_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "priorities": [],
        "count": Value::Null,
        "detail": detail,
    })
}

/// `POST /api/clients/:id/swarm/run` when client EXISTS cannot be confirmed
pub fn swarm_run_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "detail": detail,
        "code": "db_unavailable",
    })
}

/// `GET /api/heal-verify/:job_id` (status / patch / attestation) when the spec cannot be read
pub fn heal_verify_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "job": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/heal/readiness` when tenant config cannot be confirmed
pub fn heal_readiness_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "ready": Value::Null,
        "llm_configured": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/clients/:id/findings/:finding_id/channel-suggestion`
pub fn heal_channel_suggestion_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "channel": Value::Null,
        "detail": detail,
    })
}

/// `GET/POST /api/sso/idps` when `tenant_idps` cannot be read or committed
pub fn sso_idps_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "idps": [],
        "count": Value::Null,
        "detail": detail,
        "code": "db_unavailable",
    })
}

/// `GET/POST /api/admin/users` when the identity store cannot be confirmed
pub fn admin_users_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "users": [],
        "detail": detail,
        "code": "db_unavailable",
    })
}

/// `POST /api/findings/:id/verify` when the finding or client scope cannot be read
pub fn findings_verify_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "verdict": Value::Null,
        "checks": [],
        "detail": detail,
        "code": "db_unavailable",
    })
}

/// `POST /api/threat-ingest/run` when LLM config cannot be confirmed
pub fn threat_ingest_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "job_id": Value::Null,
        "detail": detail,
        "code": "db_unavailable",
    })
}

/// `GET /api/sovereign-defense/.../operator/logs` when the log store cannot be read
pub fn sovereign_operator_logs_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "events": [],
        "detail": detail,
    })
}

/// `GET /api/sovereign-defense/.../operator/windows` when live windows cannot be read
pub fn sovereign_operator_windows_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "windows": Value::Null,
        "detail": detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn never_ok_empty_success(v: &Value, key: &str) {
        assert_eq!(v["ok"], false, "store-down must not be ok");
        assert_eq!(v["unavailable"], true);
        assert_eq!(v[key], json!([]));
        assert!(v["detail"].as_str().unwrap().contains("store"));
    }

    #[test]
    fn playbook_list_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&playbook_list_unavailable_json("store down"), "playbooks");
    }

    #[test]
    fn playbook_runs_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&playbook_runs_unavailable_json("store down"), "runs");
    }

    #[test]
    fn identity_contexts_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(
            &identity_contexts_unavailable_json("store down"),
            "contexts",
        );
    }

    #[test]
    fn privilege_events_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&privilege_events_unavailable_json("store down"), "events");
    }

    #[test]
    fn runtime_traces_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&runtime_traces_unavailable_json("store down"), "traces");
    }

    #[test]
    fn containment_rules_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&containment_rules_unavailable_json("store down"), "rules");
    }

    #[test]
    fn pipeline_state_store_down_is_never_idle_success() {
        let v = pipeline_state_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["run_id"], Value::Null);
        assert_eq!(v["states"], json!([]));
    }

    #[test]
    fn oast_callbacks_store_down_is_never_ok_empty_success() {
        let v = oast_callbacks_unavailable_json("store down", oast_callbacks_store_down_health());
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["callbacks"], json!([]));
        assert!(v["health"]["callback_count"].is_null());
        assert_ne!(v["health"]["callback_count"], json!(0));
    }

    #[test]
    fn llm_fuzz_events_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&llm_fuzz_events_unavailable_json("store down"), "events");
    }

    #[test]
    fn llm_fuzz_summary_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&llm_fuzz_summary_unavailable_json("store down"), "vectors");
    }

    #[test]
    fn edge_swarm_nodes_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&edge_swarm_nodes_unavailable_json("store down"), "nodes");
    }

    #[test]
    fn ot_ics_fingerprints_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(
            &ot_ics_fingerprints_unavailable_json("store down"),
            "fingerprints",
        );
    }

    #[test]
    fn engagements_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&engagements_unavailable_json("store down"), "engagements");
    }

    #[test]
    fn evidence_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&evidence_unavailable_json("store down"), "evidence");
    }

    #[test]
    fn chronos_events_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&chronos_events_unavailable_json("store down"), "events");
    }

    #[test]
    fn cognitive_sessions_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(
            &cognitive_sessions_unavailable_json("store down"),
            "sessions",
        );
    }

    #[test]
    fn alert_rules_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&alert_rules_unavailable_json("store down"), "rules");
    }

    #[test]
    fn enterprise_settings_store_down_is_never_safe_mode_off() {
        let v = enterprise_settings_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["global_safe_mode"].is_null());
        assert_ne!(v["global_safe_mode"], json!(false));
    }

    #[test]
    fn audit_logs_store_down_is_never_ok_empty_trail() {
        let v = audit_logs_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["entries"], json!([]));
        assert!(v["total"].is_null());
        assert_ne!(v["total"], json!(0));
    }

    #[test]
    fn sbom_components_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&sbom_components_unavailable_json("store down"), "components");
    }

    #[test]
    fn audit_verify_store_down_is_never_verified_false() {
        let v = audit_verify_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert!(v["verified"].is_null());
        assert_ne!(v["verified"], json!(false));
    }

    #[test]
    fn client_config_store_down_is_never_empty_object() {
        let v = client_config_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert!(v["config"].is_null());
    }

    #[test]
    fn scan_all_engines_target_lookup_is_store_down_503_not_empty_400() {
        let src = include_str!("server_handlers_rest.inc");
        let start = src
            .find("async fn api_scan_all_engines")
            .expect("api_scan_all_engines");
        let rest = &src[start..];
        let end = rest.find("\nasync fn ").unwrap_or(rest.len());
        let fn_src = &rest[..end];
        assert!(fn_src.contains("SELECT domains FROM clients"));
        assert!(fn_src.contains("No scan target resolved for this client"));
        let domains_idx = fn_src
            .find("SELECT domains FROM clients")
            .expect("domains lookup");
        let after = &fn_src[domains_idx..];
        assert!(after.contains("SERVICE_UNAVAILABLE"));
        assert!(!after.contains(".ok().flatten()"));
    }

    #[test]
    fn clients_scan_run_all_domains_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_rest.inc");
        let start = src
            .find("async fn api_clients_scan_run_all")
            .expect("api_clients_scan_run_all");
        let rest = &src[start..];
        let end = rest.find("\nasync fn ").unwrap_or(rest.len());
        let fn_src = &rest[..end];
        assert!(fn_src.contains("SELECT domains FROM clients"));
        assert!(fn_src.contains("SERVICE_UNAVAILABLE"));
        assert!(fn_src.contains("Client not found"));
        assert!(fn_src.contains("no_domains"));
        let domains_idx = fn_src
            .find("SELECT domains FROM clients")
            .expect("domains lookup");
        let after = &fn_src[domains_idx..];
        assert!(!after.contains(".ok().flatten()"));
    }

    #[test]
    fn mfa_status_handler_is_store_down_503_not_ok_flatten() {
        let src = include_str!("server_handlers_mfa.inc");
        let start = src
            .find("async fn api_auth_mfa_status")
            .expect("api_auth_mfa_status");
        let rest = &src[start..];
        let end = rest.find("\nasync fn ").unwrap_or(rest.len());
        let fn_src = &rest[..end];
        assert!(fn_src.contains("auth_degraded_unavailable_json"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn scan_all_engines_does_not_widen_known_engine_ids_on_store_down() {
        let src = include_str!("server_handlers_rest.inc");
        let start = src
            .find("async fn api_scan_all_engines")
            .expect("api_scan_all_engines");
        let rest = &src[start..];
        let end = rest.find("\nasync fn ").unwrap_or(rest.len());
        let fn_src = &rest[..end];
        assert!(fn_src.contains("SERVICE_UNAVAILABLE"));
        assert!(fn_src.contains("No engines configured for this client"));
        assert!(!fn_src.contains("KNOWN_ENGINE_IDS.iter"));
        assert!(!fn_src.contains("&KNOWN_ENGINE_IDS"));
    }

    #[test]
    fn history_findings_count_pending_is_null_not_invented_zero() {
        let src = include_str!("server_handlers_sqlx.inc");
        assert!(src.contains("fn history_findings_count"));
        assert!(src.contains("\"pending\" | \"running\" | \"queued\" | \"held\""));
        assert!(src.contains("Value::Null"));
    }

    #[test]
    fn heal_requests_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&heal_requests_unavailable_json("store down"), "requests");
    }

    #[test]
    fn risk_graph_store_down_is_never_ok_empty_success() {
        let v = risk_graph_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["nodes"], json!([]));
        assert_eq!(v["edges"], json!([]));
        assert_ne!(v["truncated"], json!(true));
    }

    #[test]
    fn baseline_summary_store_down_is_never_zeroed_success() {
        let v = baseline_summary_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["total_assets"].is_null());
        assert!(v["drift_score"].is_null());
        assert_ne!(v["total_assets"], json!(0));
    }

    #[test]
    fn baseline_drift_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&baseline_drift_unavailable_json("store down"), "data");
    }

    #[test]
    fn baseline_anomalies_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(
            &baseline_anomalies_unavailable_json("store down"),
            "anomalies",
        );
    }

    #[test]
    fn roe_override_requests_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(
            &roe_override_requests_unavailable_json("store down"),
            "requests",
        );
    }

    #[test]
    fn cnapp_refresh_store_down_is_never_accepted_empty() {
        let v = cnapp_refresh_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["jobs"], json!([]));
        assert!(v["jobs_queued"].is_null());
    }

    #[test]
    fn clients_store_down_is_never_ok_empty_success() {
        let v = clients_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["clients"], json!([]));
    }

    #[test]
    fn cnapp_jobs_store_down_is_never_idle_success() {
        let v = cnapp_jobs_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["jobs"], json!([]));
        assert!(v["running"].is_null());
    }

    #[test]
    fn soar_executions_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&soar_executions_unavailable_json("store down"), "executions");
    }

    #[test]
    fn isolate_agents_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&isolate_agents_unavailable_json("store down"), "agents");
    }

    #[test]
    fn heal_stats_store_down_is_never_zero_success_rate() {
        let v = heal_stats_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["total"].is_null());
        assert!(v["success_rate"].is_null());
        assert_ne!(v["success_rate"], json!(0.0));
    }

    #[test]
    fn evidence_download_store_down_is_never_empty_blob_success() {
        let v = evidence_download_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v.get("blob").is_none());
    }

    #[test]
    fn findings_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&findings_unavailable_json("store down"), "findings");
    }

    #[test]
    fn findings_clusters_store_down_is_never_ok_empty_success() {
        let v = findings_clusters_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["clusters"], json!([]));
        assert!(v["total"].is_null());
        assert_ne!(v["total"], json!(0));
    }

    #[test]
    fn intel_suppressions_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(
            &intel_suppressions_unavailable_json("store down"),
            "suppressions",
        );
    }

    #[test]
    fn intel_status_store_down_is_never_zero_mirror_success() {
        let v = intel_status_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["kev"]["rows"].is_null());
        assert!(v["epss"]["rows"].is_null());
        assert_ne!(v["kev"]["rows"], json!(0));
        assert_ne!(v["epss"]["rows"], json!(0));
    }

    #[test]
    fn reports_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&reports_unavailable_json("store down"), "reports");
    }

    #[test]
    fn onboarding_tenant_status_store_down_is_never_entitled_success() {
        let v = onboarding_tenant_status_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["llm_configured"].is_null());
        assert!(v["ai_heavy_entitled"].is_null());
        assert_ne!(v["ai_heavy_entitled"], json!(true));
        assert_ne!(v["llm_configured"], json!(false));
    }

    #[test]
    fn client_readiness_store_down_is_never_zero_gap_success() {
        let v = client_readiness_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["readiness"].is_null());
        assert!(v["tenant"].is_null());
    }

    #[test]
    fn tenant_brand_store_down_is_never_empty_brand_success() {
        let v = tenant_brand_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["brand"].is_null());
        assert_ne!(v["brand"], json!({}));
    }

    #[test]
    fn vngfw_store_down_is_never_allow_all_success() {
        let v = vngfw_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["policy"].is_null());
        assert!(v["applied"].is_null());
        assert_ne!(v["policy"]["default_action"], json!("allow"));
    }

    #[test]
    fn auth_degraded_store_down_is_never_deny_success() {
        let v = auth_degraded_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["code"], "auth_degraded");
    }

    #[test]
    fn attack_chain_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&attack_chain_unavailable_json("store down"), "steps");
    }

    #[test]
    fn asm_graph_store_down_is_never_empty_surface_success() {
        let v = asm_graph_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["nodes"], json!([]));
        assert_ne!(v["message"], json!("No ASM graph yet."));
        assert_ne!(v["truncated"], json!(true));
    }

    #[test]
    fn first_mover_nerve_store_down_is_never_zero_callback_success() {
        let v = first_mover_nerve_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["oast"]["recent_callback_count"].is_null());
        assert_ne!(v["oast"]["recent_callback_count"], json!(0));
    }

    #[test]
    fn semantic_logs_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&semantic_logs_unavailable_json("store down"), "logs");
    }

    #[test]
    fn semantic_reasoning_store_down_is_never_empty_text_success() {
        let v = semantic_reasoning_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert!(v["reasoning_text"].is_null());
    }

    #[test]
    fn system_configs_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&system_configs_unavailable_json("store down"), "configs");
    }

    #[test]
    fn deception_assets_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&deception_assets_unavailable_json("store down"), "assets");
    }

    #[test]
    fn deception_generate_store_down_is_never_inserted_zero_success() {
        let v = deception_generate_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["inserted"].is_null());
        assert_ne!(v["inserted"], json!(0));
    }

    #[test]
    fn first_seen_hits_store_down_is_never_zero_pre_nvd_success() {
        let v = first_seen_hits_unavailable_json(3, "store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["hits"], json!([]));
        assert!(v["first_seen_count"].is_null());
        assert_ne!(v["first_seen_count"], json!(0));
        assert!(v["listed_count"].is_null());
    }

    #[test]
    fn system_configs_write_store_down_is_never_updated_zero_success() {
        let v = system_configs_write_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["updated"].is_null());
        assert_ne!(v["updated"], json!(0));
    }

    #[test]
    fn sealed_poc_store_down_is_never_not_found() {
        let v = sealed_poc_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v.get("poc").is_none());
        assert_ne!(v["detail"], json!("finding not found"));
    }

    #[test]
    fn sovereign_rotate_store_down_is_never_ok_true() {
        let v = sovereign_rotate_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_ne!(v["ok"], true);
    }

    #[test]
    fn rate_limits_store_down_is_never_ok_zero_counters() {
        let v = rate_limits_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["limits"], Value::Null);
        assert!(v.get("scans").is_none());
    }

    #[test]
    fn rate_limits_analytics_store_down_is_never_ok_zero_current() {
        let v = rate_limits_analytics_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["current"], Value::Null);
        assert_eq!(v["history"], json!([]));
    }

    #[test]
    fn exec_kpis_store_down_is_never_perfect_score() {
        let v = exec_kpis_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["trend"], Value::Null);
        assert_eq!(v["security_score"], Value::Null);
        assert!(v["severity"].is_null());
        assert!(v["assets"].is_null());
        assert!(v["agents"].is_null());
        assert!(v["jobs"].is_null());
        assert!(v["mttr_hours"].is_null());
        assert!(v["severity_delta_24h"].is_null());
        assert!(v["open_vs_resolved"].is_null());
        assert!(v["scan_velocity"].is_null());
        assert!(v["mitre_top"].is_null());
        assert!(v["engines_top"].is_null());
        assert!(v["clients_top"].is_null());
        assert!(v["cves_top"].is_null());
        assert!(v["scoring"].is_null());
        assert!(v["last_updated_unix"].is_null());
        assert_ne!(v["security_score"], json!(100));
        assert_ne!(v["trend"], json!([]));
        assert_ne!(v["mitre_top"], json!([]));
        assert_ne!(v["engines_top"], json!([]));
        assert_ne!(v["assets"], json!({"total_clients": 0, "with_findings": 0}));
        assert_ne!(v["jobs"], json!({"pending": 0, "running": 0}));
    }

    #[test]
    fn dashboard_stats_store_down_is_never_zeroed_score() {
        let v = dashboard_stats_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["security_score"].is_null());
        assert!(v["total_vulnerabilities"].is_null());
        assert_ne!(v["security_score"], json!(0));
        assert_ne!(v["security_score"], json!(100));
    }

    #[test]
    fn metrics_dashboard_store_down_is_never_zeroed_severity() {
        let v = metrics_dashboard_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["postgres_ok"], false);
        assert!(v["findings_by_severity"].is_null());
        assert!(v["jobs"].is_null());
        assert_ne!(v["findings_by_severity"], json!({"critical": 0, "high": 0}));
    }

    #[test]
    fn poe_job_store_down_is_never_not_found() {
        let v = poe_job_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["job"], Value::Null);
        assert_ne!(v["detail"], json!("job not found"));
    }

    fn named_fn_src<'a>(src: &'a str, sig: &str) -> &'a str {
        let start = src.find(sig).unwrap_or_else(|| panic!("missing {sig}"));
        let rest = &src[start..];
        let after = &rest[sig.len()..];
        let end_async = after.find("\nasync fn ").unwrap_or(usize::MAX);
        let end_fn = after.find("\nfn ").unwrap_or(usize::MAX);
        let rel = end_async.min(end_fn);
        if rel == usize::MAX {
            rest
        } else {
            &rest[..sig.len() + rel]
        }
    }

    #[test]
    fn client_lookup_store_down_is_never_not_found() {
        let v = client_lookup_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["code"], "db_unavailable");
        assert_ne!(v["detail"], json!("Client not found"));
    }

    #[test]
    fn report_pdf_store_down_is_never_zero_board_pack() {
        let v = report_pdf_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["critical"].is_null());
        assert!(v["high"].is_null());
        assert_ne!(v["critical"], json!(0));
        assert_ne!(v["high"], json!(0));
    }

    #[test]
    fn compliance_posture_store_down_is_never_empty_frameworks_success() {
        let v = compliance_posture_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["frameworks"].is_null());
        assert_ne!(v["frameworks"], json!([]));
    }

    #[test]
    fn heal_verify_steps_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&heal_verify_steps_unavailable_json("store down"), "steps");
    }

    #[test]
    fn heal_trends_store_down_is_never_empty_trend_success() {
        let v = heal_trends_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["trend"].is_null());
        assert_ne!(v["trend"], json!([]));
    }

    #[test]
    fn heal_priorities_store_down_is_never_ok_empty_queue() {
        let v = heal_priorities_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["priorities"], json!([]));
        assert!(v["count"].is_null());
        assert_ne!(v["count"], json!(0));
    }

    #[test]
    fn swarm_run_store_down_is_never_client_not_found() {
        let v = swarm_run_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["code"], "db_unavailable");
        assert_ne!(v["detail"], json!("client not found"));
    }

    #[test]
    fn clients_get_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_rest.inc");
        let fn_src = named_fn_src(src, "async fn api_clients_get");
        assert!(fn_src.contains("client_lookup_unavailable_json"));
        assert!(fn_src.contains("SERVICE_UNAVAILABLE"));
        assert!(fn_src.contains("Client not found"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn audit_export_is_store_down_503_not_500() {
        let src = include_str!("server_handlers_rest.inc");
        let fn_src = named_fn_src(src, "async fn api_audit_export");
        assert!(fn_src.contains("audit_logs_unavailable_json"));
        assert!(fn_src.contains("SERVICE_UNAVAILABLE"));
        assert!(!fn_src.contains("INTERNAL_SERVER_ERROR"));
        assert!(!fn_src.contains("let _ = tx.commit()"));
    }

    #[test]
    fn roe_override_reject_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_roe_approvals.inc");
        let fn_src = named_fn_src(src, "async fn api_roe_override_request_reject");
        assert!(fn_src.contains("roe_store_down()"));
        assert!(fn_src.contains("request not found"));
        assert!(!fn_src.contains(".ok().flatten()"));
        assert!(!fn_src.contains("let _ = tx.commit()"));
        let helper = named_fn_src(src, "fn roe_store_down");
        assert!(helper.contains("SERVICE_UNAVAILABLE"));
        assert!(helper.contains("roe_override_requests_unavailable_json"));
    }

    #[test]
    fn roe_override_approve_writes_are_commit_checked() {
        let src = include_str!("server_handlers_roe_approvals.inc");
        let fn_src = named_fn_src(src, "async fn api_roe_override_request_approve");
        assert!(fn_src.contains("roe_store_down()"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        assert!(!fn_src.contains(".ok().flatten()"));
        assert!(!fn_src.contains("let _ = tx.commit()"));
        let helper = named_fn_src(src, "fn roe_store_down");
        assert!(helper.contains("roe_override_requests_unavailable_json"));
    }

    #[test]
    fn containment_rules_patch_select_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase5.inc");
        let fn_src = named_fn_src(src, "async fn api_containment_rules_patch");
        assert!(fn_src.contains("containment_rules_unavailable_json"));
        assert!(fn_src.contains("SERVICE_UNAVAILABLE"));
        assert!(!fn_src.contains("let Ok(Some(row)) = existing"));
        assert!(!fn_src.contains("error\": e.to_string()"));
    }

    #[test]
    fn containment_execute_lookups_are_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase5.inc");
        let fn_src = named_fn_src(src, "async fn api_containment_execute");
        assert!(fn_src.contains("containment_rules_unavailable_json"));
        assert!(fn_src.contains("client_lookup_unavailable_json"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn swarm_run_exists_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase5.inc");
        let fn_src = named_fn_src(src, "async fn api_swarm_run");
        assert!(fn_src.contains("swarm_run_unavailable_json"));
        assert!(!fn_src.contains("unwrap_or(false)"));
    }

    #[test]
    fn client_report_pdf_lookups_are_store_down_503_not_empty_pdf() {
        let src = include_str!("server_handlers_rest2.inc");
        let fn_src = named_fn_src(src, "async fn api_client_report_pdf");
        assert!(fn_src.contains("client_lookup_unavailable_json"));
        assert!(fn_src.contains("report_pdf_unavailable_json"));
        assert!(!fn_src.contains(".ok().flatten()"));
        assert!(!fn_src.contains(".fetch_all(&mut *tx)\n    .await\n    .unwrap_or_default()"));
    }

    #[test]
    fn crypto_proof_config_is_fail_closed_on_store_down() {
        let src = include_str!("server_handlers_rest2.inc");
        let fn_src = named_fn_src(src, "async fn get_crypto_proof_for_client_tx");
        assert!(fn_src.contains("store_down"));
        assert!(fn_src.contains("map_err"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn reports_executive_is_store_down_503_not_zero_or_perfect() {
        let src = include_str!("server_handlers_phase3.inc");
        let fn_src = named_fn_src(src, "async fn api_reports_executive");
        assert!(fn_src.contains("report_pdf_unavailable_json"));
        assert!(fn_src.contains("SERVICE_UNAVAILABLE"));
        assert!(!fn_src.contains(".ok().flatten()"));
        assert!(!fn_src.contains(".fetch_all(&mut *tx)\n            .await\n            .unwrap_or_default()"));
        assert!(!fn_src.contains(".fetch_one(&mut *tx)\n            .await\n            .unwrap_or(0)"));
    }

    #[test]
    fn compliance_posture_fetch_is_store_down_503_not_empty_200() {
        let src = include_str!("server_handlers_phase3.inc");
        let fn_src = named_fn_src(src, "async fn api_compliance_posture");
        assert!(fn_src.contains("compliance_posture_unavailable_json"));
        assert!(!fn_src.contains(".unwrap_or_default()"));
        assert!(!fn_src.contains("{\"frameworks\": []}"));
    }

    #[test]
    fn load_compliance_evidence_is_err_on_store_down_not_empty_ok() {
        let src = include_str!("server_handlers_ui_aliases.inc");
        let fn_src = named_fn_src(src, "async fn load_compliance_evidence");
        assert!(!fn_src.contains("unwrap_or_default()"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn heal_verify_steps_is_store_down_503_not_empty_steps() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_verify_steps");
        assert!(fn_src.contains("heal_verify_steps_unavailable_json"));
        assert!(fn_src.contains("SERVICE_UNAVAILABLE"));
        assert!(!fn_src.contains(".fetch_all(&mut *tx)\n        .await\n        .unwrap_or_default()"));
    }

    #[test]
    fn heal_trends_is_store_down_503_not_empty_trend() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_trends");
        assert!(fn_src.contains("heal_trends_unavailable_json"));
        assert!(!fn_src.contains(".fetch_all(&mut *tx)\n        .await\n        .unwrap_or_default()"));
    }

    #[test]
    fn heal_priorities_is_store_down_503_not_empty_queue() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_priorities");
        assert!(fn_src.contains("heal_priorities_unavailable_json"));
        assert!(!fn_src.contains(".fetch_all(&mut *tx)\n        .await\n        .unwrap_or_default()"));
    }

    #[test]
    fn finding_brief_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_rest4.inc");
        let fn_src = named_fn_src(src, "async fn api_finding_brief");
        let lookup = fn_src
            .find("FROM vulnerabilities WHERE client_id")
            .expect("finding lookup");
        let after = &fn_src[lookup..];
        let serve_cache = after.find("Serve the cache").unwrap_or(after.len());
        let lookup_src = &after[..serve_cache];
        assert!(lookup_src.contains("findings_unavailable_json"));
        assert!(!lookup_src.contains(".ok().flatten()"));
    }

    #[test]
    fn heal_revert_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_rest4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_revert");
        let lookup = fn_src
            .find("FROM heal_requests")
            .expect("heal lookup");
        let after = &fn_src[lookup..];
        let github = after
            .find("no open heal PR/MR to revert")
            .unwrap_or(after.len());
        let lookup_src = &after[..github];
        assert!(lookup_src.contains("heal_requests_unavailable_json"));
        assert!(!lookup_src.contains(".ok().flatten()"));
    }

    #[test]
    fn heal_verify_store_down_is_never_job_not_found() {
        let v = heal_verify_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["job"].is_null());
        assert_ne!(v["detail"], json!("job not found"));
    }

    #[test]
    fn heal_readiness_store_down_is_never_not_configured() {
        let v = heal_readiness_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["ready"].is_null());
        assert!(v["llm_configured"].is_null());
        assert_ne!(v["llm_configured"], json!(false));
    }

    #[test]
    fn heal_channel_suggestion_store_down_is_never_empty_channel() {
        let v = heal_channel_suggestion_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert!(v["channel"].is_null());
    }

    #[test]
    fn client_integrations_get_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase3.inc");
        let fn_src = named_fn_src(src, "async fn api_client_integrations_get");
        assert!(fn_src.contains("client_lookup_unavailable_json"));
        assert!(fn_src.contains("client not found"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn client_integrations_patch_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase3.inc");
        let fn_src = named_fn_src(src, "async fn api_client_integrations_patch");
        assert!(fn_src.contains("client_lookup_unavailable_json"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn client_cloud_scan_run_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase3.inc");
        let fn_src = named_fn_src(src, "async fn api_client_cloud_scan_run");
        assert!(fn_src.contains("client_lookup_unavailable_json"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn saas_idp_discovery_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_saas_idp_discovery.inc");
        let fn_src = named_fn_src(src, "async fn api_client_saas_idp_discovery");
        assert!(fn_src.contains("client_lookup_unavailable_json"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn engagement_patch_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_engagements.inc");
        let fn_src = named_fn_src(src, "async fn api_engagement_patch");
        assert!(fn_src.contains("engagements_unavailable_json"));
        assert!(fn_src.contains("engagement not found"));
        assert!(!fn_src.contains(".ok().flatten()"));
        assert!(!fn_src.contains("let _ = tx.commit()"));
    }

    #[test]
    fn deception_deploy_cloud_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_deception_deploy_cloud");
        assert!(fn_src.contains("client_lookup_unavailable_json"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn heal_verify_status_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_verify_status");
        assert!(fn_src.contains("heal_verify_unavailable_json"));
        assert!(fn_src.contains("job not found"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn heal_verify_patch_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_verify_patch");
        assert!(fn_src.contains("heal_verify_unavailable_json"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn heal_verify_attestation_lookup_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_verify_attestation");
        assert!(fn_src.contains("heal_verify_unavailable_json"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn load_heal_report_data_spec_is_store_down_503_not_404() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn load_heal_report_data");
        assert!(fn_src.contains("SERVICE_UNAVAILABLE"));
        assert!(fn_src.contains("job not found"));
        let spec = fn_src
            .find("FROM auto_heal_job_specs")
            .expect("spec lookup");
        let after = &fn_src[spec..];
        let hr = after.find("FROM heal_requests").unwrap_or(after.len());
        assert!(!after[..hr].contains(".ok().flatten()"));
    }

    #[test]
    fn heal_readiness_is_store_down_503_not_not_configured() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_readiness");
        assert!(fn_src.contains("heal_readiness_unavailable_json"));
        assert!(!fn_src.contains("if let Ok(mut tx)"));
    }

    #[test]
    fn channel_suggestion_lookup_is_store_down_503_not_empty_live() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_channel_suggestion");
        assert!(fn_src.contains("heal_channel_suggestion_unavailable_json"));
        assert!(fn_src.contains("finding not found"));
        assert!(!fn_src.contains(".ok().flatten()"));
        assert!(!fn_src.contains("None => (String::new(), String::new())"));
    }

    #[test]
    fn health_safe_mode_query_err_is_null_not_off() {
        let src = include_str!("server_handlers_rest.inc");
        let fn_src = named_fn_src(src, "async fn api_health");
        assert!(fn_src.contains("global_safe_mode"));
        assert!(!fn_src.contains("let mut safe_mode = false"));
        assert!(fn_src.contains("Option<bool>"));
    }

    #[test]
    fn client_config_patch_roe_select_is_store_down_503_not_insert() {
        let src = include_str!("server_handlers_rest.inc");
        let fn_src = named_fn_src(src, "async fn api_client_config_patch");
        let roe = fn_src
            .find("FROM roe_override_requests")
            .expect("roe select");
        let after = &fn_src[roe..];
        let insert = after.find("INSERT INTO roe_override_requests").unwrap_or(after.len());
        let select_src = &after[..insert];
        assert!(select_src.contains("roe_override_requests_unavailable_json"));
        assert!(!select_src.contains(".ok().flatten()"));
    }

    #[test]
    fn alert_rules_test_is_store_down_503_not_ok_true() {
        let src = include_str!("server_handlers_alert_rules.inc");
        let fn_src = named_fn_src(src, "async fn api_alert_rules_test");
        assert!(fn_src.contains("alert_rules_unavailable_json"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        assert!(!fn_src.contains("let _ = tx.commit()"));
    }

    #[test]
    fn sso_idps_store_down_is_never_ok_empty_success() {
        let v = sso_idps_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["idps"], json!([]));
        assert!(v["count"].is_null());
        assert_ne!(v["count"], json!(0));
    }

    #[test]
    fn admin_users_store_down_is_never_ok_empty_success() {
        never_ok_empty_success(&admin_users_unavailable_json("store down"), "users");
    }

    #[test]
    fn findings_verify_store_down_is_never_400_db_leak() {
        let v = findings_verify_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["verdict"].is_null());
        assert_ne!(v["detail"].as_str().unwrap_or(""), "finding not found");
    }

    #[test]
    fn threat_ingest_store_down_is_never_accepted_job() {
        let v = threat_ingest_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["job_id"].is_null());
    }

    #[test]
    fn cloud_integration_patch_update_err_is_503_not_404() {
        let src = include_str!("server_handlers_phase3.inc");
        let fn_src = named_fn_src(src, "async fn api_client_cloud_integration_patch");
        assert!(fn_src.contains("client_lookup_unavailable_json"));
        assert!(!fn_src.contains("unwrap_or(0)"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
    }

    #[test]
    fn sso_idp_delete_lookup_is_store_down_503_not_404() {
        let src = include_str!("sso_management.rs");
        let fn_src = named_fn_src(src, "pub async fn api_sso_idp_delete");
        let del = fn_src
            .find("DELETE FROM tenant_idps")
            .expect("delete lookup");
        let after = &fn_src[del..];
        let next = after.find("\npub async fn").unwrap_or(after.len());
        let body = &after[..next];
        assert!(body.contains("sso_store_down"));
        assert!(!body.contains(".ok().flatten()"));
        assert!(body.contains("not_found"));
    }

    #[test]
    fn sso_idp_test_lookup_is_store_down_503_not_404() {
        let src = include_str!("sso_management.rs");
        let fn_src = named_fn_src(src, "pub async fn api_sso_idp_test");
        assert!(fn_src.contains("sso_store_down"));
        assert!(!fn_src.contains("let Ok(Some(row)) = row else"));
    }

    #[test]
    fn sso_idps_create_commit_before_ok_not_leak() {
        let src = include_str!("sso_management.rs");
        let fn_src = named_fn_src(src, "pub async fn api_sso_idps_create");
        assert!(fn_src.contains("sso_store_down"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        assert!(!fn_src.contains("e.to_string()"));
    }

    #[test]
    fn admin_users_create_exists_is_store_down_503_not_400() {
        let src = include_str!("admin_users.rs");
        let fn_src = named_fn_src(src, "pub async fn api_admin_users_create");
        assert!(fn_src.contains("admin_store_down"));
        let client = fn_src
            .find("assigned_client_id does not exist")
            .expect("client miss");
        let before = &fn_src[..client];
        assert!(!before.contains(".ok().flatten()"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
    }

    #[test]
    fn admin_users_deactivate_lookup_is_store_down_503_not_404() {
        let src = include_str!("admin_users.rs");
        let fn_src = named_fn_src(src, "pub async fn api_admin_users_deactivate");
        assert!(fn_src.contains("admin_store_down"));
        assert!(!fn_src.contains(".ok().flatten()"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
    }

    #[test]
    fn load_finding_store_down_is_never_db_prefix_leak() {
        let src = include_str!("finding_live_verify.rs");
        let fn_src = named_fn_src(src, "async fn load_finding");
        assert!(fn_src.contains("STORE_DOWN"));
        assert!(!fn_src.contains("format!(\"db: {e}\")"));
        assert!(fn_src.contains("finding not found"));
    }

    #[test]
    fn load_client_domains_store_down_is_never_empty_scope() {
        let src = include_str!("finding_live_verify.rs");
        let fn_src = named_fn_src(src, "async fn load_client_domains");
        assert!(fn_src.contains("Result<Vec<String>, String>"));
        assert!(fn_src.contains("STORE_DOWN"));
        assert!(!fn_src.contains("return Vec::new()"));
        assert!(!fn_src.contains(".ok().flatten()"));
    }

    #[test]
    fn findings_verify_live_maps_store_down_to_503() {
        let src = include_str!("server_handlers_rest2.inc");
        let fn_src = named_fn_src(src, "async fn api_findings_verify_live");
        assert!(fn_src.contains("findings_verify_unavailable_json"));
        assert!(fn_src.contains("STORE_DOWN"));
        assert!(fn_src.contains("finding not found"));
    }

    #[test]
    fn threat_ingest_config_err_is_503_not_env_default() {
        let src = include_str!("server_handlers_phase5.inc");
        let fn_src = named_fn_src(src, "async fn api_threat_ingest_run");
        assert!(fn_src.contains("threat_ingest_unavailable_json"));
        let llm = fn_src.find("llm_base_url").expect("llm key");
        let after = &fn_src[llm..];
        let env = after
            .find("WEISSMAN_LLM_BASE_URL")
            .expect("env fallback after successful miss");
        assert!(!after[..env].contains(".ok().flatten()"));
    }

    #[test]
    fn evidence_upload_insert_err_is_503_not_500() {
        let src = include_str!("server_handlers_evidence_vault.inc");
        let fn_src = named_fn_src(src, "async fn api_client_evidence_upload");
        assert!(fn_src.contains("evidence_unavailable_json"));
        let insert = fn_src.find("INSERT INTO evidence_items").expect("insert");
        assert!(!fn_src[insert..].contains(".ok().flatten()"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
    }

    #[test]
    fn sbom_post_insert_err_is_503_not_error_leak() {
        let src = include_str!("server_handlers_phase5.inc");
        let fn_src = named_fn_src(src, "async fn api_client_sbom_post");
        assert!(fn_src.contains("sbom_components_unavailable_json"));
        assert!(!fn_src.contains("e.to_string()"));
    }

    #[test]
    fn containment_rules_post_insert_err_is_503_not_error_leak() {
        let src = include_str!("server_handlers_phase5.inc");
        let fn_src = named_fn_src(src, "async fn api_containment_rules_post");
        assert!(fn_src.contains("containment_rules_unavailable_json"));
        assert!(!fn_src.contains("e.to_string()"));
    }

    #[test]
    fn oidc_begin_db_err_is_auth_degraded_not_leak() {
        let src = include_str!("oidc_auth.rs");
        let fn_src = named_fn_src(src, "pub async fn oidc_begin");
        assert!(fn_src.contains("auth_store_down"));
        assert!(!fn_src.contains("format!(\"db: {}\""));
    }

    #[test]
    fn saml_begin_db_err_is_auth_degraded_not_leak() {
        let src = include_str!("saml_auth.rs");
        let fn_src = named_fn_src(src, "pub async fn saml_begin");
        assert!(fn_src.contains("auth_store_down"));
        assert!(!fn_src.contains("format!(\"{}\""));
    }

    #[test]
    fn logout_revoke_fail_is_503_not_ok_true() {
        let src = include_str!("server_handlers_auth.inc");
        let fn_src = named_fn_src(src, "async fn api_logout");
        assert!(fn_src.contains("auth_degraded_unavailable_json"));
        assert!(fn_src.contains("revoke_failed"));
    }

    #[test]
    fn auth_refresh_jti_link_fail_is_503_not_ok_true() {
        let src = include_str!("server_handlers_auth.inc");
        let fn_src = named_fn_src(src, "async fn api_auth_refresh");
        assert!(fn_src.contains("auth_degraded_unavailable_json"));
        assert!(fn_src.contains("store_refresh_access_jti"));
        assert!(fn_src.contains("session link unavailable"));
    }

    #[test]
    fn ceo_telemetry_safe_mode_query_err_is_null_not_off() {
        let src = include_str!("ceo/ops_status.rs");
        let fn_src = named_fn_src(src, "pub async fn build_ceo_telemetry_json");
        assert!(fn_src.contains("Option<bool>"));
        assert!(!fn_src.contains("let mut global_safe = false"));
        assert!(!fn_src.contains("unwrap_or(0)"));
    }

    #[test]
    fn ceo_global_safe_patch_store_down_is_503_not_400_leak() {
        let src = include_str!("server_handlers_ceo.inc");
        let fn_src = named_fn_src(src, "async fn api_ceo_global_safe_patch");
        assert!(fn_src.contains("SERVICE_UNAVAILABLE"));
        assert!(!fn_src.contains("detail\": e"));
    }

    #[test]
    fn vngfw_save_policy_execute_is_database_unavailable_not_sql_leak() {
        let src = include_str!("vngfw_control.rs");
        let fn_src = named_fn_src(src, "pub async fn save_policy");
        assert!(fn_src.contains("database unavailable"));
        assert!(!fn_src.contains("e.to_string()"));
    }

    #[test]
    fn sovereign_operator_logs_err_is_503_not_error_leak() {
        let src = include_str!("server_handlers_sovereign_operator.inc");
        let fn_src = named_fn_src(src, "async fn api_sovereign_operator_logs_get");
        assert!(fn_src.contains("sovereign_operator_logs_unavailable_json"));
        assert!(!fn_src.contains("e.to_string()"));
    }

    #[test]
    fn github_token_store_down_is_never_git_token_required() {
        let v = github_token_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["error"], "git_token_unavailable");
        assert_eq!(v["code"], "db_unavailable");
        assert_ne!(v["error"], json!("git_token and repo_slug required"));
    }

    #[test]
    fn heal_batch_store_down_is_never_ok_true_accepted() {
        let v = heal_batch_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["enqueued"].is_null());
        assert!(v["skipped"].is_null());
        assert_eq!(v["results"], json!([]));
        assert_ne!(v["ok"], true);
        assert_ne!(v["enqueued"], json!(0));
    }

    #[test]
    fn phantom_trap_store_down_is_never_ok_bundle() {
        let v = phantom_trap_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["error"], "DB unavailable");
        assert_ne!(v["ok"], true);
    }

    #[test]
    fn github_token_for_tenant_registry_is_store_down_not_env_fallback() {
        let src = include_str!("auto_heal.rs");
        let start = src
            .find("pub async fn github_token_for_tenant")
            .expect("github_token_for_tenant");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn create_branch_and_pr")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(fn_src.contains("Result<Option<String>, &'static str>"));
        assert!(fn_src.contains("store_down"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        assert!(!fn_src.contains(".ok().flatten()"));
        assert!(!fn_src.contains("if let Ok(mut tx)"));
    }

    #[test]
    fn auto_heal_git_token_is_store_down_503_not_400() {
        let src = include_str!("server_handlers_rest4.inc");
        let fn_src = named_fn_src(src, "async fn api_auto_heal");
        let tok = fn_src
            .find("github_token_for_tenant")
            .expect("token resolve");
        let after = &fn_src[tok..];
        let req = after
            .find("git_token and repo_slug required")
            .unwrap_or(after.len());
        let resolve = &after[..req];
        assert!(resolve.contains("github_token_unavailable_json"));
        assert!(resolve.contains("Err(_)"));
        assert!(!resolve.contains(".await\n                .unwrap_or_default()"));
    }

    #[test]
    fn heal_revert_git_token_is_store_down_503_not_400() {
        let src = include_str!("server_handlers_rest4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_revert");
        let tok = fn_src
            .find("github_token_for_tenant")
            .expect("token resolve");
        let after = &fn_src[tok..];
        let req = after
            .find("git_token and repo_slug required")
            .unwrap_or(after.len());
        let resolve = &after[..req];
        assert!(resolve.contains("github_token_unavailable_json"));
        assert!(resolve.contains("Err(_)"));
        assert!(!resolve.contains(".await\n                .unwrap_or_default()"));
    }

    #[test]
    fn heal_batch_git_token_is_store_down_503_not_400() {
        let src = include_str!("server_handlers_rest4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_batch");
        let tok = fn_src
            .find("github_token_for_tenant")
            .expect("token resolve");
        let after = &fn_src[tok..];
        let req = after
            .find("git_token and repo_slug required")
            .unwrap_or(after.len());
        let resolve = &after[..req];
        assert!(resolve.contains("github_token_unavailable_json"));
        assert!(resolve.contains("Err(_)"));
        assert!(!resolve.contains(".await\n                .unwrap_or_default()"));
    }

    #[test]
    fn heal_batch_finding_store_down_is_503_not_ok_true() {
        let src = include_str!("server_handlers_rest4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_batch");
        assert!(fn_src.contains("heal_batch_unavailable_json"));
        assert!(!fn_src.contains("\"status\": \"db_error\""));
        assert!(!fn_src.contains("\"status\": \"insert_failed\""));
        assert!(!fn_src.contains("\"status\": \"persist_failed\""));
        assert!(fn_src.contains("enqueue_failed"));
        let enq = fn_src.find("enqueue_failed").expect("enqueue skip");
        let enq_src = &fn_src[enq..];
        assert!(!enq_src.contains("e.to_string()"));
        assert!(enq_src.contains("scrub_internal_error"));
    }

    #[test]
    fn heal_readiness_github_token_is_store_down_503_not_not_configured() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_heal_readiness");
        let tok = fn_src
            .find("github_token_for_tenant")
            .expect("token resolve");
        let after = &fn_src[tok..];
        assert!(after.contains("heal_readiness_unavailable_json"));
        assert!(!after.contains(".await\n        .is_some()"));
    }

    #[test]
    fn deception_generate_llm_is_store_down_503_not_empty_config() {
        let src = include_str!("server_handlers_rest4.inc");
        let fn_src = named_fn_src(src, "async fn api_deception_generate");
        let llm = fn_src.find("llm_base_url").expect("llm key");
        let after = &fn_src[llm..];
        let records = after
            .find("generate_deception_assets")
            .unwrap_or(after.len());
        let llm_src = &after[..records];
        assert!(llm_src.contains("deception_generate_unavailable_json"));
        assert!(!llm_src.contains(".ok().flatten()"));
    }

    #[test]
    fn phantom_trap_llm_is_store_down_503_not_empty_config() {
        let src = include_str!("server_handlers_rest4.inc");
        let fn_src = named_fn_src(src, "async fn api_sovereign_phantom_trap");
        assert!(fn_src.contains("phantom_trap_unavailable_json"));
        assert!(!fn_src.contains(".ok().flatten()"));
        let llm = fn_src.find("llm_base_url").expect("llm key");
        let after = &fn_src[llm..];
        let factory = after.find("build_phantom_bundle").unwrap_or(after.len());
        assert!(!after[..factory].contains(".ok().flatten()"));
    }

    #[test]
    fn identity_contexts_add_insert_err_is_503_not_sql_leak() {
        let src = include_str!("server_handlers_rest4.inc");
        let fn_src = named_fn_src(src, "async fn api_identity_contexts_add");
        assert!(fn_src.contains("identity_contexts_unavailable_json"));
        assert!(!fn_src.contains("e.to_string()"));
    }

    #[test]
    fn identity_contexts_delete_err_is_503_not_sql_leak() {
        let src = include_str!("server_handlers_rest4.inc");
        let fn_src = named_fn_src(src, "async fn api_identity_contexts_delete");
        assert!(fn_src.contains("identity_contexts_unavailable_json"));
        assert!(!fn_src.contains("e.to_string()"));
    }

    #[test]
    fn ticker_store_down_is_never_empty_ok() {
        let v = command_center_ticker_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["events"], json!([]));
        assert_ne!(v["ok"], true);
    }

    #[test]
    fn itdr_connectors_store_down_is_never_empty_ok() {
        let v = itdr_connectors_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["connectors"], json!({}));
        assert_ne!(v["ok"], true);
    }

    #[test]
    fn ceo_write_store_down_is_never_400() {
        let v = ceo_write_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["code"], "db_unavailable");
        assert_ne!(v["ok"], true);
    }

    #[test]
    fn billing_store_down_is_never_live_subscription() {
        let v = billing_store_down_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["subscription"].is_null());
        assert!(v["usage"].is_null());
        assert!(v["checkout_url"].is_null());
        assert_ne!(v["ok"], true);
    }

    #[test]
    fn god_mode_store_down_is_never_default_interval() {
        let v = god_mode_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["scan_interval_secs"].is_null());
        assert!(v["engine_matrix"].is_null());
        assert_ne!(v["scan_interval_secs"], json!(60));
    }

    #[test]
    fn knowledge_store_down_is_never_live_true() {
        let v = sovereign_operator_knowledge_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["knowledge"].is_null());
        assert_ne!(v["ok"], true);
    }

    #[test]
    fn chat_store_down_is_never_ok_session() {
        let v = sovereign_operator_chat_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["session_id"].is_null());
        assert!(v["reply"].is_null());
        assert_ne!(v["ok"], true);
    }

    #[test]
    fn oast_verify_store_down_is_never_zero_hits() {
        let v = oast_verify_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["oob_confirmed"].is_null());
        assert!(v["hit_count"].is_null());
        assert_ne!(v["hit_count"], json!(0));
        assert_ne!(v["oob_confirmed"], json!(false));
    }

    #[test]
    fn ticker_handler_begin_fail_is_503_not_empty_events() {
        let src = include_str!("http/serve.rs");
        let start = src
            .find("async fn api_command_center_ticker")
            .expect("ticker");
        let rest = &src[start..];
        let next = rest
            .find("\nstruct EnterpriseSettingsPatch")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(fn_src.contains("command_center_ticker_unavailable_json"));
        assert!(fn_src.contains("SERVICE_UNAVAILABLE"));
        assert!(!fn_src.contains("json!({ \"events\": [] })"));
        let begin = fn_src.find("begin_tenant_tx").expect("begin");
        let begin_src = &fn_src[begin..fn_src.find("let rows").expect("rows")];
        assert!(begin_src.contains("command_center_ticker_unavailable_json"));
    }

    #[test]
    fn dashboard_page_count_err_is_503_not_zero() {
        let src = include_str!("http/serve.rs");
        assert!(src.contains("Dashboard store unavailable"));
        let helper = named_fn_src(src, "fn dashboard_store_down_html");
        assert!(helper.contains("SERVICE_UNAVAILABLE"));
        assert!(helper.contains("Dashboard store unavailable"));
        let fn_src = named_fn_src(src, "async fn dashboard_page");
        assert!(fn_src.contains("dashboard_store_down_html"));
        let vuln = fn_src.find("FROM vulnerabilities").expect("vuln count");
        let clients = fn_src.find("FROM clients").expect("client count");
        let vuln_src = &fn_src[vuln..clients];
        assert!(vuln_src.contains("dashboard_store_down_html"));
        assert!(!vuln_src.contains("unwrap_or(0)"));
        let client_src = &fn_src[clients..fn_src.find("FROM report_runs").unwrap_or(fn_src.len())];
        assert!(client_src.contains("dashboard_store_down_html"));
        assert!(!client_src.contains("unwrap_or(0)"));
    }

    #[test]
    fn engagements_create_commit_err_is_503_not_ok_true() {
        let src = include_str!("server_handlers_engagements.inc");
        let fn_src = named_fn_src(src, "async fn api_client_engagements_create");
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        let commit = fn_src.find("tx.commit().await.is_err()").expect("commit");
        let after = &fn_src[commit..];
        assert!(after.contains("engagements_unavailable_json"));
        assert!(after.contains("\"ok\": true"));
        let unavail = after.find("engagements_unavailable_json").expect("503");
        let ok_true = after.find("\"ok\": true").expect("ok true");
        assert!(unavail < ok_true);
    }

    #[test]
    fn evidence_delete_commit_err_is_503_not_ok_true() {
        let src = include_str!("server_handlers_evidence_vault.inc");
        let fn_src = named_fn_src(src, "async fn api_evidence_delete");
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        let commit = fn_src.find("tx.commit().await.is_err()").expect("commit");
        let after = &fn_src[commit..];
        assert!(after.contains("evidence_unavailable_json"));
        let unavail = after.find("evidence_unavailable_json").expect("503");
        let ok_true = after.find("\"ok\": true").expect("ok true");
        assert!(unavail < ok_true);
    }

    #[test]
    fn decrypt_sealed_poc_commit_err_is_503_not_ok_true() {
        let src = include_str!("server_handlers_phase6.inc");
        let fn_src = named_fn_src(src, "async fn api_decrypt_sealed_poc");
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        let commit = fn_src.find("tx.commit().await.is_err()").expect("commit");
        let after = &fn_src[commit..];
        assert!(after.contains("sealed_poc_unavailable_json"));
        let unavail = after.find("sealed_poc_unavailable_json").expect("503");
        let ok_true = after.find("\"ok\": true").expect("ok true");
        assert!(unavail < ok_true);
    }

    #[test]
    fn itdr_put_pull_store_down_is_503_constructor() {
        let src = include_str!("server_handlers_supreme.inc");
        let put = named_fn_src(src, "async fn api_itdr_connectors_put");
        assert!(put.contains("itdr_connectors_unavailable_json"));
        let pull = named_fn_src(src, "async fn api_itdr_connectors_pull");
        assert!(pull.contains("itdr_connectors_unavailable_json"));
        let persist = named_fn_src(include_str!("itdr_connectors.rs"), "async fn persist_events");
        assert!(persist.contains("return Err(\"database unavailable\""));
        assert!(persist.contains("rollback"));
        assert!(!persist.contains("let _ = res"));
    }

    #[test]
    fn slack_heal_repo_select_err_is_store_down_not_env_default() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn enqueue_heal_from_slack");
        let repo = fn_src.find("auto_heal_repo_slug").expect("repo key");
        let repo_src = &fn_src[repo..fn_src.find("WEISSMAN_AUTOHEAL_REPO").expect("env")];
        assert!(repo_src.contains("store_down"));
        assert!(!repo_src.contains(".ok().flatten()"));
        assert!(fn_src.contains("map_err(|_| \"store_down\""));
        assert!(!fn_src.contains("map_err(|e| e.to_string())"));
    }

    #[test]
    fn ceo_write_err_maps_store_down_to_503() {
        let src = include_str!("server_handlers_ceo.inc");
        let helper = named_fn_src(src, "fn ceo_write_err");
        assert!(helper.contains("ceo_write_unavailable_json"));
        assert!(helper.contains("store_down"));
        for sig in [
            "async fn api_ceo_strategy_patch",
            "async fn api_ceo_hpc_policy_put",
            "async fn api_ceo_vault_match",
            "async fn api_ceo_sovereign_trigger_post",
            "async fn api_ceo_suspended_resume",
            "async fn api_ceo_god_mode_scan_interval_patch",
            "async fn api_ceo_tenant_engines_put",
        ] {
            let fn_src = named_fn_src(src, sig);
            assert!(fn_src.contains("ceo_write_err"), "{sig}");
        }
    }

    #[test]
    fn god_mode_config_reads_are_result_not_ok_flatten() {
        let src = include_str!("ceo/god_mode.rs");
        let start = src.find("async fn get_config_tx_str").expect("get_config");
        let rest = &src[start..];
        let next = rest
            .find("\nfn tenant_active_engine_set")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(fn_src.contains("Result<Option<String>, sqlx::Error>"));
        assert!(!fn_src.contains(".ok().flatten()"));
        let interval = src
            .find("pub async fn default_scan_interval_secs_get")
            .expect("interval get");
        let rest = &src[interval..];
        let next = rest
            .find("\npub async fn default_scan_interval_secs_set")
            .unwrap_or(rest.len());
        let get_src = &rest[..next];
        assert!(get_src.contains("Result<u64, sqlx::Error>"));
        assert!(get_src.contains(".await?"));
    }

    #[test]
    fn knowledge_snapshot_store_down_is_503_not_live_empty() {
        let src = include_str!("sovereign_operator/knowledge.rs");
        let start = src.find("pub async fn build_snapshot").expect("snapshot");
        let rest = &src[start..];
        let next = rest
            .find("\npub fn snapshot_prompt_text")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(!fn_src.contains("unwrap_or_default()"));
        assert!(fn_src.contains("store_down"));
        let clusters = named_fn_src(src, "async fn recent_clusters");
        assert!(!clusters.contains("return Ok(vec![])"));
        let handler = named_fn_src(
            include_str!("server_handlers_sovereign_operator.inc"),
            "async fn api_sovereign_operator_knowledge_get",
        );
        assert!(handler.contains("sovereign_operator_knowledge_unavailable_json"));
        assert!(!handler.contains("\"detail\": e"));
    }

    #[test]
    fn chat_llm_config_store_down_is_503_not_env_default() {
        let src = include_str!("sovereign_operator/chat.rs");
        let start = src.find("pub async fn load_llm_config").expect("load_llm");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn ensure_session")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(!fn_src.contains(".ok()\n        .flatten()"));
        assert!(fn_src.contains("store_down"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        let handler = named_fn_src(
            include_str!("server_handlers_sovereign_operator.inc"),
            "async fn api_sovereign_operator_chat",
        );
        assert!(handler.contains("sovereign_operator_chat_unavailable_json"));
        assert!(handler.contains("e == \"store_down\""));
    }

    #[test]
    fn oast_verify_count_err_is_503_not_zero_hits() {
        let src = include_str!("council_hitl.rs");
        let start = src.find("pub async fn poll_oast_token").expect("poll");
        let rest = &src[start..];
        let next = rest.find("\n#[cfg(test)]").unwrap_or(rest.len());
        let fn_src = &rest[..next];
        let count = fn_src.find("SELECT COUNT(*)").expect("count");
        let min = fn_src.find("SELECT MIN(").expect("min");
        let count_src = &fn_src[count..min];
        assert!(!count_src.contains("unwrap_or(0)"));
        assert!(count_src.contains(".await?"));
        let min_src = &fn_src[min..fn_src.find("prev_hit_count").expect("prev")];
        assert!(!min_src.contains(".ok()"));
        assert!(min_src.contains(".await?"));
        let handler = named_fn_src(
            include_str!("server_handlers_rest4.inc"),
            "async fn api_oast_probe_verify",
        );
        assert!(handler.contains("oast_verify_unavailable_json"));
        assert!(!handler.contains("e.to_string()"));
    }

    #[test]
    fn billing_usage_checkout_sync_store_down_is_503() {
        let src = include_str!("server_handlers_onboarding_billing.inc");
        let helper = named_fn_src(src, "fn billing_store_down");
        assert!(helper.contains("billing_store_down_unavailable_json"));
        for sig in [
            "async fn api_billing_usage",
            "async fn api_billing_checkout_session",
            "async fn api_billing_sync_paddle",
        ] {
            let fn_src = named_fn_src(src, sig);
            assert!(fn_src.contains("store_down"), "{sig}");
            assert!(fn_src.contains("billing_store_down"), "{sig}");
        }
    }
}
