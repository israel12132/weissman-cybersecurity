//! Canonical engine contract — probe, evidence, severity, remediation, MITRE.
//! Metadata drives UI drawers, compliance mapping, and SOAR triggers.

use serde::Serialize;
use serde_json::{json, Value};
use weissman_core::models::engine::{is_production_engine_id, resolve_engine_id};

/// MITRE ATT&CK technique or tactic identifier.
pub type MitreId = String;

/// Optional SOAR playbook hook.
pub type PlaybookId = String;

/// Runtime contract every production engine should satisfy (dispatch + persist path).
pub trait EngineContract {
    fn engine_id(&self) -> &'static str;

    /// Onboarding / integration requirements (from `engine_requirements.json` when available).
    fn requirements(&self) -> Value {
        crate::engine_requirements::catalog_json()
            .get("engines")
            .and_then(|e| e.get(self.engine_id()))
            .cloned()
            .unwrap_or_else(|| json!({ "engine_id": self.engine_id() }))
    }

    /// JSON Schema fragment for evidence drawer rendering.
    fn evidence_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["proof", "timestamp", "engine_id"],
            "properties": {
                "proof": { "type": "string", "description": "Live probe proof (HTTP excerpt, API response hash, OAST hit id, …)" },
                "timestamp": { "type": "string", "format": "date-time" },
                "engine_id": { "type": "string" },
                "method": { "type": "string" },
                "url": { "type": "string" },
                "status_code": { "type": "integer" },
                "oast_token": { "type": "string" }
            }
        })
    }

    fn mitre_mapping(&self) -> Vec<MitreId>;

    fn remediation_playbook(&self) -> Option<PlaybookId> {
        None
    }
}

/// Static contract descriptor for catalog / OpenAPI (no I/O).
#[derive(Debug, Clone, Serialize)]
pub struct EngineContractMeta {
    pub engine_id: String,
    pub requirements: Value,
    pub evidence_schema: Value,
    pub mitre_mapping: Vec<String>,
    pub remediation_playbook: Option<String>,
}

/// Resolve SOAR remediation playbook id for a production engine.
#[must_use]
pub fn remediation_playbook_for(engine_id: &str) -> Option<String> {
    if !is_production_engine_id(engine_id) {
        return None;
    }
    let kind = crate::engine_capabilities::classify(engine_id);
    if kind == "agent_required" {
        return Some(format!("agent-deploy-{engine_id}"));
    }
    if kind == "alias" {
        let canonical = resolve_engine_id(engine_id);
        return remediation_playbook_for(canonical);
    }
    Some(format!("remediate-{engine_id}"))
}

/// Build contract metadata for `/api/engines/:id/contract`.
#[must_use]
pub fn contract_meta_for_engine(engine_id: &str) -> EngineContractMeta {
    let catalog = crate::engine_requirements::catalog_json();
    let requirements = catalog
        .get("engines")
        .and_then(|e| e.get(engine_id))
        .cloned()
        .unwrap_or_else(|| json!({ "engine_id": engine_id }));
    let mitre_mapping: Vec<String> = requirements
        .get("mitre")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let evidence_schema = json!({
        "type": "object",
        "required": ["proof", "timestamp", "engine_id"],
        "properties": {
            "proof": { "type": "string" },
            "timestamp": { "type": "string", "format": "date-time" },
            "engine_id": { "type": "string" }
        }
    });
    EngineContractMeta {
        engine_id: engine_id.to_string(),
        requirements,
        evidence_schema,
        mitre_mapping,
        remediation_playbook: remediation_playbook_for(engine_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_meta_has_evidence_schema() {
        let m = contract_meta_for_engine("graphql_attack");
        assert!(m.evidence_schema.get("required").is_some());
        assert!(!m.engine_id.is_empty());
        assert!(m
            .remediation_playbook
            .as_deref()
            .is_some_and(|p| p.starts_with("remediate-")));
    }
}
