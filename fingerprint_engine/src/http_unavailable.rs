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
        let v = oast_callbacks_unavailable_json("store down", json!({"configured": true}));
        assert_eq!(v["ok"], false);
        assert_eq!(v["unavailable"], true);
        assert_eq!(v["callbacks"], json!([]));
        assert_eq!(v["health"]["configured"], true);
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
}
