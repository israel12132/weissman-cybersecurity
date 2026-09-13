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

/// `POST /api/agents/isolate` when the isolate task cannot be persisted
pub fn agents_isolate_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "task_id": Value::Null,
        "live_dispatched": Value::Null,
        "detail": detail,
    })
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

/// `POST /api/clients/:id/deception/deploy-cloud` when the deployment row cannot be confirmed
pub fn deception_deploy_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "deployment_id": Value::Null,
        "job_id": Value::Null,
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

/// `POST /api/oast/probe` mint when the probe row cannot be persisted
pub fn oast_mint_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "token": Value::Null,
        "callback_domain": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/scan/status` when running job counts cannot be confirmed
pub fn scan_status_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "scanning_active": Value::Null,
        "scanning_enabled": Value::Null,
        "scan_in_progress": Value::Null,
        "running_async_jobs": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/discovery/knowledge/stats` when the intel corpus cannot be read
pub fn discovery_knowledge_stats_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "stored_paths": Value::Null,
        "stored_subdomain_prefixes": Value::Null,
        "llm_learned": Value::Null,
        "confirmed_hits": Value::Null,
        "seed_rows": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/self-improve/status` and self-improve writes when the queue cannot be confirmed
pub fn self_improve_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "enabled": Value::Null,
        "counts": Value::Null,
        "item_id": Value::Null,
        "apply_job_id": Value::Null,
        "detail": detail,
    })
}

/// Council HITL propose/approve/reject when the queue cannot be confirmed
pub fn council_hitl_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "id": Value::Null,
        "job_id": Value::Null,
        "item_id": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/ceo/strategy` when tenant strategy configs cannot be confirmed
pub fn ceo_strategy_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "effective": Value::Null,
        "env_fallback_snapshot": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/ceo/hpc-policy` when running job splits cannot be confirmed
pub fn hpc_policy_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "desired": Value::Null,
        "effective_routing": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/sovereign-defense/:id/dashboard` when 24h counts cannot be confirmed
pub fn sovereign_defense_dashboard_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "chronos": Value::Null,
        "liquid_matrix": Value::Null,
        "detail": detail,
    })
}

/// `GET /api/ceo/supreme-nerve-center` when module counts cannot be confirmed
pub fn nerve_center_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "system_modules": [],
        "engines": [],
        "live_jobs": [],
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

/// `GET /api/sovereign-defense/:id/cognitive/poison-library` when the library cannot be read
pub fn poison_library_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "items": [],
        "detail": detail,
    })
}

/// Sovereign Operator memory / forge / scripts lists when the store cannot be read
pub fn sovereign_operator_memory_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "memory": [],
        "detail": detail,
    })
}

pub fn sovereign_operator_forge_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "forge": [],
        "detail": detail,
    })
}

pub fn sovereign_operator_scripts_unavailable_json(detail: &str) -> Value {
    json!({
        "ok": false,
        "unavailable": true,
        "scripts": [],
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
        let end_pub_async = after.find("\npub async fn ").unwrap_or(usize::MAX);
        let end_fn = after.find("\nfn ").unwrap_or(usize::MAX);
        let end_pub_fn = after.find("\npub fn ").unwrap_or(usize::MAX);
        let rel = end_async.min(end_pub_async).min(end_fn).min(end_pub_fn);
        if rel == usize::MAX {
            rest
        } else {
            &rest[..sig.len() + rel]
        }
    }

    fn compact_src(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
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

    #[test]
    fn deception_deploy_store_down_is_never_ok_queued() {
        let v = deception_deploy_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["deployment_id"].is_null());
        assert!(v["job_id"].is_null());
        assert_ne!(v["ok"], true);
    }

    #[test]
    fn agents_isolate_store_down_is_never_ok_task() {
        let v = agents_isolate_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert!(v["task_id"].is_null());
        assert!(v["live_dispatched"].is_null());
        assert_ne!(v["ok"], true);
    }

    #[test]
    fn deception_deploy_cloud_insert_commit_is_503_not_ok_true() {
        let src = include_str!("server_handlers_phase4.inc");
        let fn_src = named_fn_src(src, "async fn api_deception_deploy_cloud");
        let ins = fn_src
            .find("INSERT INTO deception_cloud_deployments")
            .expect("insert");
        let after = &fn_src[ins..];
        assert!(after.contains("deception_deploy_unavailable_json"));
        let commit = after.find("tx.commit().await.is_err()").expect("commit");
        let ok_true = after.find("\"ok\": true").expect("accepted");
        assert!(commit < ok_true);
    }

    #[test]
    fn client_config_patch_roe_create_commit_is_503_not_created() {
        let src = include_str!("server_handlers_rest.inc");
        let fn_src = named_fn_src(src, "async fn api_client_config_patch");
        let created = fn_src.find("A request was created").expect("created");
        let insert = fn_src[..created]
            .rfind("INSERT INTO roe_override_requests")
            .expect("insert");
        let create_src = &fn_src[insert..created];
        assert!(create_src.contains("tx.commit().await.is_err()"));
        assert!(create_src.contains("roe_override_requests_unavailable_json"));
        assert!(!create_src.contains("let _ = tx.commit()"));
    }

    #[test]
    fn agents_isolate_err_is_503_not_sql_leak() {
        let src = include_str!("server_handlers_supreme.inc");
        let fn_src = named_fn_src(src, "async fn api_agents_isolate");
        assert!(fn_src.contains("agents_isolate_unavailable_json"));
        assert!(!fn_src.contains("e.to_string()"));
    }

    #[test]
    fn war_room_sse_err_is_not_sql_leak() {
        let src = include_str!("ceo/war_room.rs");
        let start = src.find("pub fn sse_war_room_stream").expect("sse");
        let rest = &src[start..];
        let next = rest.find("\nasync fn fetch_events_since").unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(fn_src.contains("database unavailable"));
        assert!(fn_src.contains("unavailable"));
        assert!(!fn_src.contains("e.to_string()"));
    }

    #[test]
    fn sovereign_sse_err_is_not_sql_leak() {
        let src = include_str!("server_handlers_sovereign_operator.inc");
        let start = src
            .find("async fn api_sovereign_operator_stream(")
            .expect("stream");
        let rest = &src[start..];
        let next = rest
            .find("\nasync fn api_sovereign_operator_memory")
            .or_else(|| rest.find("\nasync fn api_sovereign_operator_forge"))
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(fn_src.contains("database unavailable"));
        assert!(!fn_src.contains("e.to_string()"));
    }

    #[test]
    fn ws_command_center_count_err_is_unavailable_not_init_zero() {
        let fn_src = named_fn_src(
            include_str!("http/serve.rs"),
            "async fn handle_ws_command_center",
        );
        assert!(fn_src.contains("ws_command_center_store_down"));
        let vuln = fn_src.find("FROM vulnerabilities").expect("vuln");
        let clients = fn_src.find("FROM clients").expect("clients");
        assert!(!&fn_src[vuln..clients].contains("unwrap_or(0)"));
        let reports = fn_src.find("FROM report_runs").expect("reports");
        let commit = fn_src.find("tx.commit().await.is_err()").expect("commit");
        let report_src = &fn_src[reports..commit];
        assert!(!report_src.contains(".flatten()"));
        assert!(report_src.contains("ws_command_center_store_down"));
        let init = fn_src.find("\"type\": \"init\"").expect("init");
        assert!(commit < init);
    }

    #[test]
    fn hpc_running_jobs_fetch_is_not_live_zero() {
        let src = include_str!("ceo/hpc.rs");
        let start = src.find("pub async fn get_hpc_policy").expect("hpc");
        let rest = &src[start..];
        let next = rest.find("\n#[derive(Deserialize)]").unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(fn_src.contains(".fetch_all(pool)\n    .await?"));
        assert!(!fn_src.contains(".await\n    .unwrap_or_default()"));
        let handler = named_fn_src(
            include_str!("server_handlers_ceo.inc"),
            "async fn api_ceo_hpc_policy_get",
        );
        assert!(handler.contains("hpc_policy_unavailable_json"));
        assert!(!handler.contains("INTERNAL_SERVER_ERROR"));
    }

    #[test]
    fn strategy_get_is_503_not_env_fallback() {
        let src = include_str!("ceo/strategy.rs");
        let start = src
            .find("pub async fn load_genesis_runtime_params")
            .expect("load");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn get_ceo_strategy_json")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(fn_src.contains("Result<GenesisRuntimeParams"));
        assert!(!fn_src.contains("load_env_fallback()"));
        let handler = named_fn_src(
            include_str!("server_handlers_ceo.inc"),
            "async fn api_ceo_strategy_get",
        );
        assert!(handler.contains("ceo_strategy_unavailable_json"));
        let exec = include_str!("async_job_executor.rs");
        assert!(exec.contains("Err(_) => crate::ceo::strategy::load_env_fallback()"));
        let telem = include_str!("ceo/ops_status.rs");
        assert!(telem.contains("\"unavailable\": true"));
        assert!(telem.contains("Value::Null"));
    }

    #[test]
    fn sovereign_defense_dashboard_counts_are_not_live_zeros() {
        let src = include_str!("sovereign_defense_store.rs");
        let start = src.find("pub async fn dashboard_snapshot").expect("dash");
        let rest = &src[start..];
        let next = rest.find("\n#[cfg(test)]").unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(!fn_src.contains("unwrap_or(0)"));
        assert!(!fn_src.contains("tenant tx:"));
        assert!(fn_src.contains("store_down"));
        let handler = named_fn_src(
            include_str!("server_handlers_sovereign_defense.inc"),
            "async fn api_sovereign_defense_dashboard",
        );
        assert!(handler.contains("sovereign_defense_dashboard_unavailable_json"));
        assert!(!handler.contains("\"error\": e"));
    }

    #[test]
    fn scan_status_job_count_err_is_503_not_zero() {
        let fn_src = named_fn_src(
            include_str!("server_handlers_rest.inc"),
            "async fn api_scan_status",
        );
        assert!(fn_src.contains("scan_status_unavailable_json"));
        assert!(!fn_src.contains("unwrap_or(0)"));
        let v = scan_status_unavailable_json("store down");
        assert_eq!(v["ok"], false);
        assert!(v["running_async_jobs"].is_null());
        assert_ne!(v["running_async_jobs"], json!(0));
    }

    #[test]
    fn discovery_knowledge_stats_err_is_not_default_zero() {
        let src = include_str!("discovery_knowledge.rs");
        let start = src.find("pub async fn stats").expect("stats");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn seed_public_knowledge")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(fn_src.contains("Result<CorpusStats"));
        assert!(!fn_src.contains("CorpusStats::default()"));
        let handler = named_fn_src(
            include_str!("server_handlers_rest4.inc"),
            "async fn api_discovery_knowledge_stats",
        );
        assert!(handler.contains("discovery_knowledge_stats_unavailable_json"));
        let v = discovery_knowledge_stats_unavailable_json("store down");
        assert!(v["confirmed_hits"].is_null());
        assert_ne!(v["confirmed_hits"], json!(0));
    }

    #[test]
    fn self_improve_status_is_503_not_zero_counts() {
        let src = include_str!("self_improve.rs");
        let start = src.find("pub async fn status_summary").expect("status");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn insert_proposals")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(fn_src.contains("Result<Value"));
        assert!(!fn_src.contains("unwrap_or(0)"));
        let handler = named_fn_src(
            include_str!("server_handlers_rest4.inc"),
            "async fn api_self_improve_status",
        );
        assert!(handler.contains("self_improve_unavailable_json"));
        let v = self_improve_unavailable_json("store down");
        assert!(v["counts"].is_null());
        assert!(v["enabled"].is_null());
    }

    #[test]
    fn compliance_frameworks_list_err_is_503_not_fallback() {
        let fn_src = named_fn_src(
            include_str!("server_handlers_ui_aliases.inc"),
            "async fn api_compliance_frameworks_list",
        );
        assert!(fn_src.contains("catalog_unavailable"));
        assert!(!fn_src.contains("FALLBACK_FRAMEWORKS"));
        let slugs = named_fn_src(
            include_str!("server_handlers_ui_aliases.inc"),
            "async fn listed_framework_slugs",
        );
        assert!(!slugs.contains("FALLBACK_FRAMEWORKS"));
        assert!(slugs.contains("catalog_unavailable"));
    }

    #[test]
    fn nerve_module_counts_are_not_healthy_on_store_down() {
        let fn_src = named_fn_src(
            include_str!("supreme_nerve_center.rs"),
            "async fn build_system_modules",
        );
        let pending = fn_src.find("status = 'pending'").expect("pending");
        let running = fn_src.find("status = 'running'").expect("running");
        assert!(!&fn_src[pending..running].contains("unwrap_or(0)"));
        assert!(fn_src.contains("Result<Vec<Value>"));
        let handler = named_fn_src(
            include_str!("server_handlers_ceo.inc"),
            "async fn api_ceo_supreme_nerve_center_get",
        );
        assert!(handler.contains("nerve_center_unavailable_json"));
        assert!(!handler.contains("INTERNAL_SERVER_ERROR"));
    }

    #[test]
    fn rest4_writes_are_503_not_sql_leak() {
        let src = include_str!("server_handlers_rest4.inc");
        for sig in [
            "async fn api_pipeline_state_patch",
            "async fn api_risk_graph_build",
            "async fn api_runtime_traces_ingest",
            "async fn api_deception_triggered",
            "async fn api_council_hitl_propose",
            "async fn api_council_hitl_approve",
            "async fn api_council_hitl_reject",
            "async fn api_self_improve_toggle",
            "async fn api_self_improve_approve",
            "async fn api_self_improve_reject",
            "async fn api_oast_probe_mint",
        ] {
            let fn_src = named_fn_src(src, sig);
            assert!(
                !fn_src.contains("e.to_string()") && !fn_src.contains("err.to_string()"),
                "{sig} still leaks Display"
            );
            assert!(
                fn_src.contains("SERVICE_UNAVAILABLE") || fn_src.contains("_unavailable_json"),
                "{sig} missing 503"
            );
        }
        let build = named_fn_src(src, "async fn api_risk_graph_build");
        assert!(!build.contains("unwrap_or(0)"));
        assert!(build.contains("risk_graph_unavailable_json"));
        let v = oast_mint_unavailable_json("store down");
        assert!(v["token"].is_null());
        assert_eq!(v["ok"], false);
        let hitl = council_hitl_unavailable_json("store down");
        assert!(hitl["job_id"].is_null());
        let hpc = hpc_policy_unavailable_json("store down");
        assert!(hpc["effective_routing"].is_null());
        let strat = ceo_strategy_unavailable_json("store down");
        assert!(strat["effective"].is_null());
    }

    #[test]
    fn sovereign_rotate_store_down_is_503_not_sql_or_ok_true() {
        let src = include_str!("sovereign_defense_store.rs");
        for sig in [
            "pub async fn ensure_routing_token",
            "pub async fn rotate_liquid_matrix",
        ] {
            let start = src.find(sig).unwrap_or_else(|| panic!("missing {sig}"));
            let rest = &src[start..];
            let next = rest.find("\npub async fn ").unwrap_or(rest.len());
            let fn_src = if next == 0 { rest } else { &rest[..next] };
            assert!(!fn_src.contains("e.to_string()"), "{sig}");
            assert!(!fn_src.contains("tenant tx:"));
            assert!(fn_src.contains("tx.commit().await.is_err()"), "{sig}");
            assert!(!fn_src.contains("let _ = tx.commit()"), "{sig}");
        }
        let handler = named_fn_src(
            include_str!("server_handlers_sovereign_defense.inc"),
            "async fn api_sovereign_defense_rotate",
        );
        assert!(handler.contains("sovereign_rotate_unavailable_json"));
        assert!(!handler.contains("\"error\": e"));
        assert!(!handler.contains("INTERNAL_SERVER_ERROR"));
    }

    #[test]
    fn risk_graph_build_optional_sources_are_not_empty_success() {
        let src = include_str!("risk_graph.rs");
        let start = src
            .find("pub async fn build_risk_graph_for_client")
            .expect("build");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn fusion_ot_it_graph_edges_llm")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(!fn_src.contains("fetch_all(&mut **tx)\n        .await\n        .unwrap_or_default()"));
        assert!(!fn_src.contains("fetch_all(&mut **tx)\n    .await\n    .unwrap_or_default()"));
        let nodes = fn_src.find("FROM risk_graph_nodes").expect("nodes count");
        let count_src = &fn_src[nodes..];
        assert!(!count_src.contains("unwrap_or(0)"));
        assert!(count_src.contains(".await?"));
    }

    #[test]
    fn chronos_cognitive_insert_commit_is_store_down() {
        let src = include_str!("sovereign_defense_store.rs");
        for sig in [
            "pub async fn insert_chronos_event",
            "pub async fn insert_cognitive_session",
        ] {
            let start = src.find(sig).unwrap_or_else(|| panic!("missing {sig}"));
            let rest = &src[start..];
            let next = rest.find("\npub async fn ").unwrap_or(rest.len());
            let fn_src = &rest[..next];
            assert!(!fn_src.contains("e.to_string()"), "{sig}");
            assert!(!fn_src.contains("tenant tx:"));
            assert!(fn_src.contains("tx.commit().await.is_err()"), "{sig}");
            assert!(!fn_src.contains("let _ = tx.commit()"), "{sig}");
        }
    }

    #[test]
    fn self_improve_gather_signals_and_run_now_are_not_zero_success() {
        let src = include_str!("self_improve.rs");
        let start = src.find("async fn gather_signals").expect("gather");
        let rest = &src[start..];
        let next = rest
            .find("\nfn deterministic_proposals")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        assert!(fn_src.contains("Result<Vec<(String, i64)>"));
        assert!(!fn_src.contains("unwrap_or(0)"));
        let handler = named_fn_src(
            include_str!("server_handlers_rest4.inc"),
            "async fn api_self_improve_run_now",
        );
        assert!(handler.contains("self_improve_unavailable_json"));
        assert!(!handler.contains("\"error\": e"));
    }

    #[test]
    fn llm_fuzz_and_cloud_scan_persist_commit_is_not_ok_true() {
        let src = include_str!("async_job_executor.rs");
        let fuzz = src.find("\"llm_fuzz_run\"").expect("fuzz");
        let cloud = src.find("\"cloud_scan_run\"").expect("cloud");
        let payload = src.find("\"payload_sync\"").expect("payload");
        let fuzz_src = &src[fuzz..cloud];
        assert!(fuzz_src.contains("tx.commit().await.is_err()"));
        assert!(!fuzz_src.contains("let _ = tx.commit()"));
        let cloud_src = &src[cloud..payload];
        assert!(cloud_src.contains("tx.commit().await.is_err()"));
        assert!(!cloud_src.contains("let _ = sqlx::query(\"DELETE FROM cloud_scan_findings"));
        let persist_commit = cloud_src
            .rfind("tx.commit().await.is_err()")
            .expect("persist commit");
        let ok_true = cloud_src.find("\"ok\": true").expect("ok");
        assert!(persist_commit < ok_true);
    }

    #[test]
    fn poison_library_and_operator_lists_are_503_not_sql() {
        let poison = named_fn_src(
            include_str!("server_handlers_sovereign_defense.inc"),
            "async fn api_sovereign_defense_poison_library",
        );
        assert!(poison.contains("poison_library_unavailable_json"));
        assert!(!poison.contains("\"error\": e"));
        let src = include_str!("sovereign_defense_store.rs");
        let start = src.find("pub async fn load_poison_library").expect("poison");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn dashboard_snapshot")
            .unwrap_or(rest.len());
        assert!(!&rest[..next].contains("e.to_string()"));
        let op = include_str!("server_handlers_sovereign_operator.inc");
        for (sig, ctor) in [
            (
                "async fn api_sovereign_operator_memory_get",
                "sovereign_operator_memory_unavailable_json",
            ),
            (
                "async fn api_sovereign_operator_forge_get",
                "sovereign_operator_forge_unavailable_json",
            ),
            (
                "async fn api_sovereign_operator_scripts_get",
                "sovereign_operator_scripts_unavailable_json",
            ),
        ] {
            let fn_src = named_fn_src(op, sig);
            assert!(fn_src.contains(ctor), "{sig}");
            assert!(!fn_src.contains("\"detail\": e"), "{sig}");
        }
        let exec = include_str!("async_job_executor.rs");
        for needle in ["\"swarm_run\" =>", "\"feedback_fuzz\" =>"] {
            let start = exec.find(needle).unwrap_or_else(|| panic!("missing {needle}"));
            let slice = &exec[start..start + 1800.min(exec.len() - start)];
            let exists = slice.find("SELECT EXISTS").expect("exists");
            assert!(
                !&slice[exists..exists + 350].contains("unwrap_or(false)"),
                "{needle}"
            );
            assert!(&slice[exists..exists + 350].contains("store_down"), "{needle}");
        }
    }

    #[test]
    fn chronos_live_reads_are_error_not_empty_ok_on_store_down() {
        let src = include_str!("chronos_engine.rs");
        let start = src
            .find("pub async fn run_chronos_result")
            .expect("run_chronos_result");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn run_chronos(")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        let compact = compact_src(fn_src);
        assert!(!fn_src.contains("format!(\"db: {e}\")"));
        assert!(!compact.contains("fetch_all(&mut*tx).await.unwrap_or_default()"));
        assert!(!fn_src.contains("let _ = tx.commit()"));
        assert!(fn_src.contains("EngineResult::error(\"store_down\")"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        assert!(fn_src.contains("empty_ok("));
        let last_store = fn_src
            .rfind("EngineResult::error(\"store_down\")")
            .expect("store_down return");
        let agent = fn_src
            .find("run_agent_required_engine")
            .expect("agent path");
        let empty = fn_src.find("empty_ok(").expect("empty_ok");
        assert!(last_store < agent, "store-down must not continue to agent");
        assert!(last_store < empty, "empty_ok must follow store-down returns");
    }

    #[test]
    fn defense_fusion_telemetry_counts_are_not_live_zeros_on_store_down() {
        let src = include_str!("sovereign_active_defense_fusion_engine.rs");
        let start = src
            .find("async fn load_defense_telemetry")
            .expect("load_defense_telemetry");
        let rest = &src[start..];
        let next = rest.find("\nfn maturity_grade").unwrap_or(rest.len());
        let fn_src = &rest[..next];
        let compact = compact_src(fn_src);
        assert!(fn_src.contains("Result<DefenseTelemetry, String>"));
        assert!(!fn_src.contains("return DefenseTelemetry::default()"));
        assert!(fn_src.contains("return Ok(DefenseTelemetry::default())"));
        assert!(!compact.contains("unwrap_or(0)"));
        assert!(!compact.contains("unwrap_or_default()"));
        assert!(!fn_src.contains("let Ok(mut tx)"));
        assert!(fn_src.contains("map_err(|_| \"store_down\".to_string())"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        let run_start = src
            .find("pub async fn run_sovereign_active_defense_fusion_result")
            .expect("run fusion");
        let run_rest = &src[run_start..];
        let run_next = run_rest
            .find("\npub async fn run_sovereign_active_defense_fusion(")
            .unwrap_or(run_rest.len());
        let run_src = &run_rest[..run_next];
        assert!(run_src.contains("Err(_) => return EngineResult::error(\"store_down\")"));
        assert!(run_src.contains("Ok(DefenseTelemetry::default())"));
    }

    #[test]
    fn identity_itdr_loader_is_not_empty_success_on_store_down() {
        let src = include_str!("identity_attack_chain_engine.rs");
        let start = src
            .find("async fn itdr_findings_from_db")
            .expect("itdr_findings_from_db");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn run_identity_attack_chain_result")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        let compact = compact_src(fn_src);
        assert!(fn_src.contains("Result<Vec<Value>, String>"));
        assert!(fn_src.contains("return Ok(Vec::new())"));
        assert!(!fn_src.contains("let Ok(mut tx)"));
        assert!(!compact.contains("fetch_all(&mut*tx).await.unwrap_or_default()"));
        assert!(fn_src.contains("map_err(|_| \"store_down\".to_string())"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        let run_start = src
            .find("pub async fn run_identity_attack_chain_result")
            .expect("run identity");
        let run_rest = &src[run_start..];
        let run_next = run_rest
            .find("\npub async fn run_identity_attack_chain(")
            .unwrap_or(run_rest.len());
        let run_src = &run_rest[..run_next];
        assert!(run_src.contains("Err(_) => return EngineResult::error(\"store_down\")"));
        assert!(run_src.contains("empty_ok("));
    }

    #[test]
    fn cognitive_poison_library_load_is_not_empty_ok_on_store_down() {
        let src = include_str!("cognitive_starvation_engine.rs");
        let start = src
            .find("pub async fn run_cognitive_starvation_result")
            .expect("cognitive");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn run_cognitive_starvation(")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        let compact = compact_src(fn_src);
        assert!(!compact.contains("load_poison_library(pool.as_ref(),20).await.unwrap_or_default()"));
        assert!(fn_src.contains("EngineResult::error(\"store_down\")"));
        assert!(fn_src.contains("empty_ok("));
        let store = fn_src
            .find("EngineResult::error(\"store_down\")")
            .expect("store_down");
        let empty = fn_src.find("empty_ok(").expect("empty_ok");
        assert!(store < empty);
    }

    #[test]
    fn orchestrator_cycle_reads_are_not_empty_success_on_store_down() {
        let src = include_str!("orchestrator/mod.rs");
        let ident_start = src
            .find("async fn load_identity_contexts")
            .expect("identity");
        let ident_rest = &src[ident_start..];
        let ident_next = ident_rest
            .find("\nfn client_auto_harvest_enabled")
            .unwrap_or(ident_rest.len());
        let ident = &ident_rest[..ident_next];
        let ident_c = compact_src(ident);
        assert!(ident.contains("Result<Vec<identity_engine::AuthContext>, sqlx::Error>"));
        assert!(!ident_c.contains("fetch_all(&mut**tx).await.unwrap_or_default()"));
        assert!(ident_c.contains("fetch_all(&mut**tx).await?"));
        assert!(src.contains("get_config_tx_strict"));
        let cycle_start = src
            .find("async fn run_cycle_for_tenant_inner")
            .expect("cycle");
        let cycle = &src[cycle_start..];
        assert!(cycle.contains("get_config_tx_strict(&mut tx, tenant_id, \"global_safe_mode\")"));
        assert!(!cycle.contains("get_config_tx(&mut tx, tenant_id, \"global_safe_mode\")"));
        let clients = cycle
            .find("SELECT id, name, domains")
            .expect("clients select");
        let clients_slice = &cycle[clients..clients + 280];
        assert!(clients_slice.contains(".await?"));
        assert!(!clients_slice.contains("unwrap_or_default()"));
        let audit = cycle
            .find("FROM vulnerabilities WHERE run_id")
            .expect("audit");
        let audit_slice = &cycle[audit..audit + 350];
        assert!(audit_slice.contains(".await?"));
        assert!(!audit_slice.contains("unwrap_or_default()"));
    }

    #[test]
    fn ueba_threat_intel_exists_is_not_false_on_store_down() {
        let src = include_str!("ueba_onboarding.rs");
        let start = src.find("pub async fn threat_intel_hit").expect("ti");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn fleet_consensus_hit")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        let compact = compact_src(fn_src);
        assert!(fn_src.contains("Result<bool, String>"));
        assert!(!compact.contains("fetch_one(&mut**tx).await.unwrap_or(false)"));
        assert!(fn_src.contains("map_err(|_| \"store_down\".to_string())"));
        let det = include_str!("ueba_detector.rs");
        let call = det
            .find("crate::ueba_onboarding::threat_intel_hit")
            .expect("caller");
        let call_src = &det[call..call + 280];
        assert!(call_src.contains("map_err(|_| \"store_down\".to_string())?"));
    }

    #[test]
    fn nexus_endpoint_agent_count_is_not_live_zero_on_store_down() {
        let src = include_str!("nexus_sovereign_swarm_engine.rs");
        let start = src.find("async fn count_endpoint_agents").expect("count");
        let rest = &src[start..];
        let next = rest.find("\nfn signal_to_finding").unwrap_or(rest.len());
        let fn_src = &rest[..next];
        let compact = compact_src(fn_src);
        assert!(fn_src.contains("Result<u32, String>"));
        assert!(fn_src.contains("return Ok(0)"));
        assert!(!fn_src.contains("return 0;"));
        assert!(!compact.contains("unwrap_or(0)"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        let run_hit = src
            .find("match count_endpoint_agents(ctx).await")
            .expect("caller");
        let caller = &src[run_hit..run_hit + 220];
        assert!(caller.contains("EngineResult::error(\"store_down\")"));
    }

    #[test]
    fn store_down_engine_error_is_fail_fast_not_waf_skip() {
        let src = include_str!("engine_resilience.rs");
        let classify = named_fn_src(src, "pub fn classify_failure");
        assert!(classify.contains("FailureClass::StoreDown"));
        assert!(classify.contains("store_down"));
        let store_idx = classify.find("store_down").expect("store_down token");
        let waf_503 = classify.find("contains(\"503\")").expect("waf 503");
        assert!(store_idx < waf_503, "StoreDown must be classified before WAF 503");
        let iff = named_fn_src(src, "pub fn is_fail_fast");
        assert!(iff.contains("StoreDown"));
        let as_str = named_fn_src(src, "pub fn as_str");
        assert!(as_str.contains("StoreDown => \"store_down\""));
    }

    #[test]
    fn persist_kev_and_exposure_are_not_confirmed_false_on_store_down() {
        let kev = include_str!("intel_kev.rs");
        let start = kev
            .find("pub async fn kev_listed_for_cves")
            .expect("kev_listed_for_cves");
        let rest = &kev[start..];
        let next = rest
            .find("\npub fn bootstrap_kev_catalog")
            .unwrap_or(rest.len());
        let fn_src = &rest[..next];
        let compact = compact_src(fn_src);
        assert!(fn_src.contains("Result<std::collections::HashMap<String, KevEntry>, String>"));
        assert!(!compact.contains("fetch_all(pool).await.unwrap_or_default()"));
        assert!(fn_src.contains("map_err(|_| \"store_down\".to_string())"));
        let persist = include_str!("findings_persist.rs");
        let exp_start = persist
            .find("async fn resolve_internet_exposed")
            .expect("exposed");
        let exp_rest = &persist[exp_start..];
        let exp_next = exp_rest.find("\nfn extract_array").unwrap_or(exp_rest.len());
        let exp = &exp_rest[..exp_next];
        let exp_c = compact_src(exp);
        assert!(exp.contains("Result<bool, String>"));
        assert!(!exp_c.contains("fetch_one(&mut*conn).await.unwrap_or(false)"));
        assert!(persist.contains(
            "intel_kev::kev_listed_for_cves(pool, &scan_cves)\n        .await\n        .map_err(|_| \"store_down\".to_string())?"
        ));
    }

    #[test]
    fn risk_superposition_raw_findings_are_not_empty_ok_on_store_down() {
        let src = include_str!("risk_superposition_collapse_engine.rs");
        let start = src
            .find("pub async fn run_risk_superposition_collapse_result")
            .expect("run");
        let rest = &src[start..];
        let next = rest
            .find("\npub async fn run_risk_superposition_collapse(")
            .unwrap_or(rest.len());
        let run_src = &rest[..next];
        assert!(!run_src.contains("unwrap_or_default()"));
        assert!(!run_src.contains("cluster load failed:"));
        assert!(run_src.contains("EngineResult::error(\"store_down\")"));
        let raw = src.find("async fn load_raw_findings").expect("raw");
        let raw_rest = &src[raw..];
        let raw_next = raw_rest.find("\nfn cluster_as_finding").unwrap_or(raw_rest.len());
        let raw_src = &raw_rest[..raw_next];
        assert!(!raw_src.contains("let _ = tx.commit()"));
        assert!(raw_src.contains("tx.commit().await.is_err()"));
        assert!(!raw_src.contains("format!(\"tenant tx: {e}\")"));
    }

    #[test]
    fn nexus_surface_extras_are_not_empty_ok_on_store_down() {
        let src = include_str!("nexus_sovereign_swarm_engine.rs");
        let start = src
            .find("async fn load_db_surface_extras")
            .expect("extras");
        let rest = &src[start..];
        let next = rest.find("\nfn assign_agents_cycle").unwrap_or(rest.len());
        let fn_src = &rest[..next];
        let compact = compact_src(fn_src);
        assert!(fn_src.contains("Result<(Vec<String>, Vec<String>), String>"));
        assert!(!compact.contains("fetch_all(&mut*tx).await.unwrap_or_default()"));
        assert!(fn_src.contains("tx.commit().await.is_err()"));
        assert!(src.contains("Err(_) => return EngineResult::error(\"store_down\")"));
    }

    #[test]
    fn billing_gates_store_down_is_503_not_quota_deny() {
        let billing = include_str!("billing/mod.rs");
        let impl_src = billing.split("#[cfg(test)]").next().expect("impl");
        let compact = compact_src(impl_src);
        assert!(impl_src.contains("map_err(|_| \"store_down\".into())"));
        assert!(impl_src.contains("Result<Option<String>, String>"));
        assert!(!compact.contains("ifletOk(Some(s))=sqlx::query_scalar"));
        let handlers = include_str!("server_handlers_onboarding_billing.inc");
        let pay = named_fn_src(handlers, "fn payment_or_store_down");
        assert!(pay.contains("detail == \"store_down\""));
        assert!(pay.contains("billing_store_down"));
        assert!(pay.contains("PAYMENT_REQUIRED"));
        let register = named_fn_src(handlers, "async fn api_onboarding_register");
        assert!(register.contains("e == \"store_down\""));
        assert!(register.contains("billing_store_down"));
        let rest = include_str!("server_handlers_rest.inc");
        assert!(rest.contains("payment_or_store_down(detail)"));
        assert!(!rest.contains("StatusCode::PAYMENT_REQUIRED"));
        let payload = named_fn_src(
            include_str!("server_handlers_rest4.inc"),
            "async fn api_payload_sync_run",
        );
        assert!(payload.contains("detail == \"store_down\""));
        assert!(payload.contains("billing_store_down"));
        let webhook = named_fn_src(handlers, "fn paddle_webhook_error_response");
        assert!(webhook.contains("msg == \"store_down\""));
        assert!(webhook.contains("PaddleWebhookError::Sql"));
        assert!(webhook.contains("billing_store_down"));
        for inc in [
            "server_handlers_phase3.inc",
            "server_handlers_phase5.inc",
            "server_handlers_phase6.inc",
            "server_handlers_sqlx.inc",
            "server_handlers_rest4.inc",
        ] {
            let src = match inc {
                "server_handlers_phase3.inc" => include_str!("server_handlers_phase3.inc"),
                "server_handlers_phase5.inc" => include_str!("server_handlers_phase5.inc"),
                "server_handlers_phase6.inc" => include_str!("server_handlers_phase6.inc"),
                "server_handlers_sqlx.inc" => include_str!("server_handlers_sqlx.inc"),
                _ => include_str!("server_handlers_rest4.inc"),
            };
            assert!(src.contains("payment_or_store_down(detail)"), "{inc}");
        }
        assert!(impl_src.contains(
            "bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| e.to_string())"
        ));
        assert!(impl_src.contains("Subscription not provisioned for tenant"));
        let paddle_wh = include_str!("billing/webhook.rs");
        assert!(paddle_wh.contains("Result<Option<i64>, String>"));
        assert!(!compact_src(paddle_wh).contains(".await.ok()?"));
        assert!(paddle_wh.contains("map_err(|_| \"store_down\".to_string())"));
    }

    #[test]
    fn fp_feedback_store_down_is_not_full_confidence_or_empty_cache() {
        let src = include_str!("fp_feedback.rs");
        let pool_fn = named_fn_src(src, "pub async fn confidence_multiplier(");
        assert!(pool_fn.contains("Result<f64, String>"));
        assert!(pool_fn.contains("return Ok(1.0)"));
        assert!(!pool_fn.contains("pub async fn confidence_multiplier_tx"));
        let tx_fn = named_fn_src(src, "pub async fn confidence_multiplier_tx");
        assert!(tx_fn.contains("Result<f64, String>"));
        assert!(tx_fn.contains("store_down"));
        assert!(!compact_src(tx_fn).contains(".ok().flatten()"));
        let batch = named_fn_src(src, "pub async fn confidence_multipliers_batch");
        assert!(batch.contains("Result<HashMap<(String, String), f64>, String>"));
        assert!(!compact_src(batch).contains("fetch_all(&mut*tx).await.unwrap_or_default()"));
        assert!(batch.contains("tx.commit().await.is_err()"));
        let load = named_fn_src(src, "async fn load_suppression_rules_from_db");
        assert!(load.contains("Result<Vec<SuppressionRule>, String>"));
        assert!(!compact_src(load).contains("unwrap_or_default()"));
        assert!(load.contains("Err(\"store_down\".to_string())"));
        let insert_idx = load.find("SUPPRESSION_CACHE.insert").expect("cache insert");
        let first_err = load.find("return Err(\"store_down\".to_string())").expect("err");
        assert!(first_err < insert_idx, "must not cache rules before store-down return");
        let persist = include_str!("findings_persist.rs");
        assert!(persist.contains(
            "fp_feedback::active_suppressions_for_engine(pool, tenant_id, engine)\n            .await\n            .map_err(|_| \"store_down\".to_string())?"
        ));
        assert!(persist.contains(
            "fp_feedback::confidence_multiplier_tx(&mut tx, tenant_id, engine, &signature_hash)\n                .await\n                .map_err(|_| \"store_down\".to_string())?"
        ));
        let findings = named_fn_src(
            include_str!("server_handlers_sqlx.inc"),
            "async fn api_findings(",
        );
        assert!(findings.contains("confidence_multipliers_batch"));
        assert!(findings.contains("match crate::fp_feedback::confidence_multipliers_batch"));
        assert!(findings.contains("findings_unavailable_json"));
    }

    #[test]
    fn auto_heal_running_dupe_count_store_down_is_not_zero() {
        let src = include_str!("auto_heal_job.rs");
        let start = src
            .find("SELECT count(*)::bigint FROM auto_heal_job_specs")
            .expect("dupe count");
        let slice = &src[start..start + 700];
        assert!(slice.contains("Err(_) => return Err(\"store_down\".into())"));
        assert!(!slice.contains("unwrap_or(0)"));
    }

    #[test]
    fn soar_blast_and_idempotency_store_down_is_not_live_zero() {
        let blast = include_str!("soar/blast_radius.rs");
        let eval = named_fn_src(blast, "pub async fn evaluate");
        assert!(!compact_src(eval).contains("fetch_all(&mut*tx).await.unwrap_or_default()"));
        assert!(eval.contains("unavailable_blast"));
        assert!(!eval.contains("apply_blast_decision") || eval.contains("unavailable_blast"));
        let apply_idx = eval.find("apply_blast_decision").expect("apply after live rows");
        let unavail = eval.find("unavailable_blast").expect("fail closed");
        assert!(unavail < apply_idx);
        let ublast_start = blast.find("fn unavailable_blast()").expect("unavailable_blast");
        let ublast_rest = &blast[ublast_start..];
        let ublast_next = ublast_rest
            .find("\npub fn apply_blast_decision")
            .unwrap_or(ublast_rest.len());
        let unavail_fn = &ublast_rest[..ublast_next];
        assert!(unavail_fn.contains("report.blocked = true"));
        assert!(!unavail_fn.contains("force_approved"));
        let engine = include_str!("soar/engine.rs");
        let find = named_fn_src(engine, "async fn find_existing_execution");
        assert!(find.contains("Result<Option<ExistingExecution>, String>"));
        assert!(!compact_src(find).contains(".ok().flatten()"));
        assert!(engine.contains("detail: \"database unavailable\".into()"));
        let insert = named_fn_src(engine, "async fn insert_execution");
        assert!(!insert.contains("let _ = tx.commit()"));
        assert!(insert.contains("tx.commit().await.is_err()"));
        assert!(insert.contains("duplicate_in_flight"));
        let exec = named_fn_src(engine, "pub async fn execute_armored_action");
        assert!(exec.contains("duplicate_skipped: in-flight execution"));
        assert!(exec.contains("duplicate_in_flight"));
        assert!(exec.contains("match load_integrations"));
        let lock = named_fn_src(
            include_str!("soar/idempotency.rs"),
            "pub async fn try_acquire_lock",
        );
        assert!(lock.contains("Result<Option<SoarLockGuard>, String>"));
        assert!(lock.contains("store_down"));
        assert!(!compact_src(lock).contains(".ok().unwrap_or(false)"));
        assert!(!lock.contains("pub async fn mark_completed"));
        let iso = named_fn_src(
            include_str!("soar/idempotency.rs"),
            "pub async fn try_acquire_isolate_lock",
        );
        assert!(iso.contains("Result<SoarLockGuard, String>"));
        assert!(!iso.contains("pub async fn try_acquire_lock"));
        assert!(!compact_src(iso).contains(".ok().unwrap_or(false)"));
        let integ = include_str!("soar/integrations.rs");
        let load = named_fn_src(integ, "pub async fn load_integrations");
        assert!(load.contains("Result<Vec<IntegrationRecord>, String>"));
        assert!(load.contains("store_down"));
        assert!(!compact_src(load).contains(".ok().flatten()"));
    }

    #[test]
    fn pipeline_pause_store_down_does_not_scan_as_unpaused() {
        let src = include_str!("orchestrator/mod.rs");
        let fn_src = named_fn_src(src, "async fn pipeline_get_state");
        assert!(fn_src.contains("Result<Option<(u8, bool, Option<u8>)>, sqlx::Error>"));
        assert!(!fn_src.contains(".ok()??"));
        assert!(fn_src.contains(".await?"));
        assert!(src.contains(
            "pipeline_get_state(&mut tx, tenant_id, run_id, &cid).await?"
        ));
        let persist_n = named_fn_src(src, "async fn persist_and_notify_findings");
        assert!(persist_n.contains("return 0;"));
        let failed = persist_n.find("findings_persist failed").expect("persist err");
        let bcast = persist_n.find("broadcast_finding_created").expect("broadcast");
        assert!(failed < bcast);
        let err_arm = &persist_n[failed..bcast];
        assert!(err_arm.contains("return 0"));
    }

    #[test]
    fn heal_recent_open_pr_store_down_is_not_confirmed_miss() {
        let src = include_str!("auto_heal_job.rs");
        let recent = named_fn_src(src, "async fn recent_open_pr");
        assert!(recent.contains("Result<Option<(String, Option<i64>, String)>, String>"));
        assert!(recent.contains("store_down"));
        assert!(!compact_src(recent).contains("begin_tenant_tx(pool, tenant_id).await.ok()?"));
        assert!(!compact_src(recent).contains("fetch_optional(&mut*tx).await.ok().flatten()"));
        assert!(src.contains("Err(_) => return Err(\"store_down\".to_string())"));
    }

    #[test]
    fn ueba_epss_fair_verify_heal_store_down_is_not_live_miss() {
        let ingest = named_fn_src(
            include_str!("ueba_detector.rs"),
            "pub async fn ingest_sample",
        );
        assert!(ingest.contains("SELECT enrolled_at FROM endpoint_agents"));
        assert!(!compact_src(ingest).contains("fetch_optional(&mut*tx).await.ok().flatten()"));
        assert!(ingest.contains("map_err(|_| \"store_down\".to_string())?"));
        let det = include_str!("ueba_detector.rs");
        let sov_call = det
            .find("crate::ueba_onboarding::on_sovereign_binary_allowlist_tx")
            .expect("sov caller");
        let sov_call_src = &det[sov_call..sov_call + 280];
        assert!(sov_call_src.contains("map_err(|_| \"store_down\".to_string())?"));

        let ueba = include_str!("ueba_onboarding.rs");
        let sov_start = ueba
            .find("pub async fn on_sovereign_binary_allowlist_tx")
            .expect("sov");
        let sov_rest = &ueba[sov_start..];
        let sov_next = sov_rest
            .find("\npub fn item_binary_hash")
            .unwrap_or(sov_rest.len());
        let sov = &sov_rest[..sov_next];
        assert!(sov.contains("Result<bool, String>"));
        assert!(!compact_src(sov).contains(".ok().flatten()"));
        assert!(sov.contains("map_err(|_| \"store_down\".to_string())?"));

        let epss = include_str!("intel_epss.rs");
        let epss_start = epss
            .find("pub async fn fetch_epss_for_cves")
            .expect("fetch_epss");
        let epss_rest = &epss[epss_start..];
        let epss_next = epss_rest.find("\nfn parse_score").unwrap_or(epss_rest.len());
        let epss_fn = &epss_rest[..epss_next];
        assert!(epss_fn.contains("Result<HashMap<String, EpssScore>, String>"));
        assert!(!compact_src(epss_fn).contains("fetch_all(pool).await.unwrap_or_default()"));
        assert!(epss_fn.contains("map_err(|_| \"store_down\".to_string())?"));
        let persist = include_str!("findings_persist.rs");
        assert!(persist.contains(
            "intel_epss::fetch_epss_for_cves(pool, &scan_cves)\n        .await\n        .map_err(|_| \"store_down\".to_string())?"
        ));

        let fair = include_str!("financial_risk.rs");
        let fair_start = fair
            .find("pub async fn compute_and_store")
            .expect("compute_and_store");
        let fair_rest = &fair[fair_start..];
        let fair_next = fair_rest
            .find("\npub async fn latest_snapshot")
            .unwrap_or(fair_rest.len());
        let fair_fn = &fair_rest[..fair_next];
        assert!(!compact_src(fair_fn).contains(".ok().flatten()"));
        assert!(fair_fn.contains("Err(_) => return Err(\"store_down\".to_string())"));

        let verify = include_str!("soar/verification.rs");
        let claim_start = verify
            .find("pub async fn claim_due_tasks")
            .expect("claim_due_tasks");
        let claim_rest = &verify[claim_start..];
        let claim_next = claim_rest
            .find("\npub async fn mark_verified")
            .unwrap_or(claim_rest.len());
        let claim = &claim_rest[..claim_next];
        assert!(claim.contains("Result<Vec<PendingVerifyTask>, String>"));
        assert!(!compact_src(claim).contains("fetch_all(&mut*tx).await.unwrap_or_default()"));
        assert!(claim.contains("store_down"));
        assert!(!claim.contains("return Vec::new()"));
        let cycle = named_fn_src(include_str!("soar/worker.rs"), "async fn run_cycle");
        assert!(cycle.contains("claim_due_tasks(app_pool, tenant_id, 8).await?"));
        assert!(!compact_src(cycle).contains("let tasks=claim_due_tasks(app_pool,tenant_id,8).await;"));

        let heal = include_str!("auto_heal_job.rs");
        let ctx = named_fn_src(heal, "async fn load_finding_context");
        assert!(ctx.contains("Result<Option<(String, String, String)>, String>"));
        assert!(ctx.contains("store_down"));
        assert!(!compact_src(ctx).contains(".ok().flatten()"));
        assert!(heal.contains(
            "load_finding_context(app_pool.as_ref(), tenant_id, client_id, &finding_id).await?"
        ));
    }

    #[test]
    fn soar_playbook_github_status_isolate_verify_are_not_ok_on_store_down() {
        let pb = include_str!("soar_playbook.rs");
        let cool = named_fn_src(pb, "async fn in_cooldown");
        assert!(cool.contains("Result<bool, String>"));
        assert!(!compact_src(cool).contains(".ok().flatten()"));
        assert!(cool.contains("store_down"));
        let rec = named_fn_src(pb, "async fn record_run");
        assert!(rec.contains("Result<(), String>"));
        assert!(!rec.contains("let _ = tx.commit()"));
        assert!(rec.contains("store_down"));
        let dispatch = named_fn_src(pb, "pub async fn dispatch_event");
        assert!(dispatch.contains("skipped_store_down"));
        assert!(dispatch.contains("record_run(pool, &pb, &event, &dedup, &actions, &status).await.is_err()"));

        let gh = include_str!("soar/adapters/github.rs");
        let open = named_fn_src(gh, "async fn open_pr");
        assert!(open.contains("if tx.commit().await.is_err()"));
        assert!(!compact_src(open).contains("let_=tx.commit().await"));
        let enqueue = open.find("enqueue_with_max_attempts").expect("enqueue after commit");
        let commit = open.find("if tx.commit().await.is_err()").expect("commit checked");
        assert!(commit < enqueue, "must not enqueue until spec commit succeeds");

        let engine = include_str!("soar/engine.rs");
        let upd = named_fn_src(engine, "async fn update_status");
        assert!(!upd.contains("let _ = tx.commit()"));
        assert!(upd.contains("store_down"));
        let ures = named_fn_src(engine, "async fn update_execution_result");
        assert!(!ures.contains("let _ = tx.commit()"));
        assert!(ures.contains("store_down"));
        let exec = named_fn_src(engine, "pub async fn execute_armored_action");
        assert!(!compact_src(exec).contains(
            "let_=update_status(pool,cmd.tenant_id,execution_id,ExecutionStatus::Executing"
        ));
        assert!(!compact_src(exec).contains("let_=update_execution_result"));
        let persist = exec
            .find("if update_execution_result")
            .expect("result persist checked");
        assert!(
            exec[persist..].contains("status: \"ok\".into()"),
            "ok only after execution result persist is checked"
        );

        let aws = include_str!("soar/adapters/aws_ec2.rs");
        let probe_start = aws
            .find("async fn tcp_probe_unreachable(")
            .expect("tcp_probe");
        let probe_rest = &aws[probe_start..];
        let probe_next = probe_rest
            .find("\npub async fn tcp_probe_unreachable_batch")
            .unwrap_or(probe_rest.len());
        let probe = &probe_rest[..probe_next];
        assert!(probe.contains("Result<bool, super::AdapterError>"));
        assert!(probe.contains("isolate probe timeout — not confirmed"));
        assert!(!probe.contains("return true;"));
        let agent = named_fn_src(
            include_str!("soar/adapters/weissman_agent.rs"),
            "async fn verify_isolated",
        );
        assert!(agent.contains("tcp_probe_unreachable_batch"));
        assert!(!agent.contains("tcp_open"));
    }

    #[test]
    fn worker_ingest_enqueue_leader_store_down_is_not_empty_ok() {
        let worker = include_str!("soar/worker.rs");
        let cycle = named_fn_src(worker, "async fn run_cycle");
        assert!(!compact_src(cycle).contains("fetch_all(auth_pool).await.unwrap_or_default()"));
        assert!(cycle.contains("map_err(|_| \"store_down\".to_string())?"));
        assert!(cycle.contains("verify_heal_job(app_pool, tenant_id, &task.target).await?"));
        let heal = named_fn_src(worker, "async fn verify_heal_job");
        assert!(heal.contains("Result<bool, String>"));
        assert!(!compact_src(heal).contains(".ok().flatten()"));
        assert!(heal.contains("store_down"));
        let leader = named_fn_src(worker, "async fn try_acquire_leader");
        assert!(leader.contains("Result<bool, String>"));
        assert!(!compact_src(leader).contains(".ok().unwrap_or(false)"));
        assert!(worker.contains("leader election store_down"));

        let ingest = named_fn_src(
            include_str!("endpoint_agents.rs"),
            "pub async fn store_finding_for_task",
        );
        assert!(!ingest.contains("let _ = crate::ueba_detector::ingest_sample"));
        assert!(ingest.contains("map_err(|e| sqlx::Error::Protocol(e))?"));

        let exec = named_fn_src(
            include_str!("soar/engine.rs"),
            "pub async fn execute_armored_action",
        );
        assert!(!compact_src(exec).contains("let_=enqueue_verification"));
        assert!(exec.contains("enqueue_verification(pool, cmd.tenant_id, execution_id, &probe)"));
        assert!(exec.contains("status: \"failed\".into()"));

        let merge = named_fn_src(include_str!("auto_heal_job.rs"), "async fn maybe_auto_merge_pr");
        assert!(!compact_src(merge).contains(".ok().flatten().unwrap_or_default()"));

        let persist_rb = named_fn_src(include_str!("soar/revert.rs"), "pub async fn persist_runbook");
        assert!(persist_rb.contains("Result<Uuid, String>"));
        assert!(!persist_rb.contains("let _ = tx.commit()"));
        assert!(persist_rb.contains("store_down"));

        assert!(!compact_src(exec).contains("let_=persist_runbook"));
        let persist_idx = exec
            .find("persist_runbook(")
            .expect("execute_armored_action must persist a runbook");
        let ok_idx = exec[persist_idx..]
            .find("status: \"ok\".into()")
            .expect("success arm should still exist after persist");
        assert!(
            exec[persist_idx..persist_idx + ok_idx].contains("store_down"),
            "persist_runbook Err must become failed/store_down before returning ok"
        );
    }

    #[test]
    fn execute_revert_commit_fail_is_store_down() {
        let src = named_fn_src(include_str!("soar/revert.rs"), "pub async fn execute_revert");
        assert!(src.contains("Result<String, String>"));
        let last = src
            .rfind("tx.commit()")
            .expect("execute_revert must commit the reverted UPDATE");
        assert!(
            src[last.saturating_sub(80)..].contains("is_err()"),
            "final revert commit fail must be checked"
        );
        assert!(
            src.contains("store_down"),
            "execute_revert commit fail must be store_down, not Ok(details)"
        );
    }

    #[test]
    fn claim_due_schedule_ids_store_down_not_empty_ok() {
        let src = named_fn_src(
            include_str!("scan_schedule_worker.rs"),
            "async fn claim_due_schedule_ids",
        );
        assert!(
            src.contains("Result<Vec<i64>, String>"),
            "claim_due_schedule_ids must return Result so tick cannot treat store-down as no due scans"
        );
        assert!(
            !src.contains("return Vec::new()"),
            "claim_due_schedule_ids must not empty-ok begin fail as a bare empty vec"
        );
        assert!(
            !compact_src(src).contains("fetch_all(&mut*tx).await.unwrap_or_default()"),
            "claim_due_schedule_ids must not unwrap_or_default a due-id SELECT as empty"
        );
        assert!(
            src.contains("store_down"),
            "claim_due_schedule_ids begin/fetch/commit fail must be store_down"
        );
        let tick = named_fn_src(include_str!("scan_schedule_worker.rs"), "async fn tick");
        assert!(
            !tick.contains("for schedule_id in claim_due_schedule_ids("),
            "tick must not iterate claim_due_schedule_ids as if it were Vec"
        );
        assert!(
            tick.contains("match claim_due_schedule_ids("),
            "tick must match claim_due_schedule_ids Err instead of treating it as no due work"
        );
    }

    #[test]
    fn stale_soar_begin_fail_is_store_down_not_ok_zero() {
        let exec = named_fn_src(
            include_str!("soar/stale.rs"),
            "async fn alert_stale_executions",
        );
        let ver = named_fn_src(
            include_str!("soar/stale.rs"),
            "async fn alert_stale_verifications",
        );
        for (name, src) in [
            ("alert_stale_executions", exec),
            ("alert_stale_verifications", ver),
        ] {
            assert!(
                !src.contains("return Ok(0)"),
                "{name} must not empty-ok begin fail as zero stale work"
            );
            assert!(
                src.contains("store_down"),
                "{name} begin/commit fail must be store_down"
            );
        }
    }

    #[test]
    fn pentest_memory_prior_winners_store_down_not_empty_ok() {
        let src = named_fn_src(include_str!("pentest_memory.rs"), "pub async fn prior_winners");
        assert!(
            src.contains("Result<Vec<WinningPath>, String>"),
            "prior_winners must return Result so store-down is not an empty winner list"
        );
        assert!(
            !compact_src(src).contains("fetch_all(&mut*tx).await.unwrap_or_default()"),
            "prior_winners must not unwrap_or_default a winner SELECT as empty"
        );
        assert!(
            src.contains("store_down"),
            "prior_winners begin/fetch/commit fail must be store_down"
        );
        let live = include_str!("engine_dispatch.rs");
        assert!(
            live.contains("EngineResult::error(\"store_down\")"),
            "live engine dispatch must fail closed when pentest memory store is down"
        );
    }
}
