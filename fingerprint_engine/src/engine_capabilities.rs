//! Per-engine reality classification — the source of truth for the catalog's "indication on each
//! engine" badge. Every engine ID is classified, directly from the canonical registry, into exactly
//! one kind so the UI can show operators precisely what each engine is:
//!
//!   * `real_probe`     — canonical engine with a live dispatch arm (real network/host I/O)
//!   * `alias`          — a retag that resolves to another canonical engine (same detection logic)
//!   * `agent_required` — remote-impossible; returns an info finding until the endpoint agent runs
//!   * `special`        — reserved for async-only engines without a sync dispatch arm
//!
//! Mirrors `scripts/engine_reality_audit.mjs` exactly, but computed at runtime in Rust.

use serde::Serialize;
use weissman_core::models::engine::{production_engine_ids, resolve_engine_id};

/// Classify a single engine id (precedence: agent_required > alias > special > real_probe).
pub fn classify(id: &str) -> &'static str {
    if crate::engine_dispatch::AGENT_REQUIRED_ENGINES.contains(&id) {
        return "agent_required";
    }
    let canonical = resolve_engine_id(id);
    if canonical != id {
        return "alias";
    }
    if crate::critical_infra::is_critical_infra_engine(id) {
        return "real_probe";
    }
    "real_probe"
}

/// Whether a kind performs real detection from a remote scan without an agent.
pub fn detects_remotely(kind: &str, id: &str) -> bool {
    if kind == "agent_required" {
        return false;
    }
    if kind == "alias" {
        let canonical = resolve_engine_id(id);
        return !crate::engine_dispatch::AGENT_REQUIRED_ENGINES.contains(&canonical);
    }
    matches!(kind, "real_probe" | "special")
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineCapability {
    pub id: String,
    pub kind: String,
    /// The canonical engine this id resolves to (only meaningful for aliases).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical: Option<String>,
    /// True when the engine yields a real detection from a remote scan with no agent installed.
    pub remote_detection: bool,
}

/// Capability descriptor for every production engine id.
pub fn capabilities() -> Vec<EngineCapability> {
    production_engine_ids()
        .iter()
        .map(|&id| {
            let kind = classify(id);
            let canonical = if kind == "alias" {
                Some(resolve_engine_id(id).to_string())
            } else {
                None
            };
            EngineCapability {
                id: id.to_string(),
                kind: kind.to_string(),
                canonical,
                remote_detection: detects_remotely(kind, id),
            }
        })
        .collect()
}

/// JSON for the `/api/engines/capabilities` surface.
pub fn to_json() -> serde_json::Value {
    let caps = capabilities();
    let mut counts: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for c in &caps {
        *counts.entry(c.kind.clone()).or_insert(0) += 1;
    }
    let mut body = serde_json::json!({
        "total": caps.len(),
        "summary": counts,
        "engines": caps,
        "legend": {
            "real_probe": "Live probe — real network/host detection",
            "alias": "Alias — same detection as its canonical engine, different name",
            "agent_required": "Requires the endpoint agent; info-only from a remote scan",
            "special": "poe_synthesis — runs via the async-job path"
        },
    });
    if let Some(secret) = provenance_signing_secret() {
        if let Some(manifest) = weissman_ui_provenance::sign_capabilities_manifest(&body, &secret) {
            body["provenance"] = serde_json::to_value(manifest).unwrap_or(serde_json::Value::Null);
        }
    }
    body
}

pub fn provenance_signing_secret() -> Option<String> {
    std::env::var("WEISSMAN_UI_PROVENANCE_SECRET")
        .ok()
        .or_else(|| std::env::var("WEISSMAN_JWT_SECRET").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_kinds_classify_correctly() {
        assert_eq!(classify("poe_synthesis"), "real_probe");
        assert_eq!(classify("avionics_adsb_attack"), "real_probe");
        // wifi_attack_engine genuinely needs RF hardware via the agent.
        assert_eq!(classify("wifi_attack_engine"), "agent_required");
        // modbus_exploit was promoted to a real read-only probe (removed from agent-required).
        assert_eq!(classify("modbus_exploit"), "real_probe");
    }

    #[test]
    fn every_production_id_is_classified_consistently() {
        let caps = capabilities();
        assert!(caps.len() > 400, "should cover the full production catalog");
        let real = caps.iter().filter(|c| c.kind == "real_probe").count();
        let alias = caps.iter().filter(|c| c.kind == "alias").count();
        let agent = caps.iter().filter(|c| c.kind == "agent_required").count();
        let special = caps.iter().filter(|c| c.kind == "special").count();
        // Buckets must partition the catalog exactly (no id left unclassified).
        assert_eq!(real + alias + agent + special, caps.len());
        assert!(real > 0 && alias > 0 && agent > 0);
        assert_eq!(special, 0);
        // Aliases must carry a canonical target; real probes must not.
        for c in &caps {
            if c.kind == "alias" {
                assert!(c.canonical.is_some());
            } else {
                assert!(c.canonical.is_none());
            }
        }
    }

    #[test]
    fn alias_of_agent_required_is_not_remote() {
        let caps = capabilities();
        let alias = caps
            .iter()
            .find(|c| c.kind == "alias" && !c.remote_detection);
        assert!(
            alias.is_some(),
            "expected at least one alias whose canonical engine requires an agent"
        );
    }

    #[test]
    fn agent_required_never_remote() {
        for c in capabilities().iter().filter(|c| c.kind == "agent_required") {
            assert!(!c.remote_detection, "{} should not detect remotely", c.id);
        }
    }

    #[test]
    fn json_has_summary_and_legend() {
        let v = to_json();
        assert!(v["total"].as_u64().unwrap() > 400);
        assert!(v["summary"]["real_probe"].as_u64().is_some());
        assert!(v["legend"]["agent_required"].as_str().is_some());
    }
}
