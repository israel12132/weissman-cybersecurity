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
}
