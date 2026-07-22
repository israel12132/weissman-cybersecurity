//! Battlespace topology API — risk graph + attack paths + STRIPS shadow planning for C2 UI.

use crate::attack_chain_planner::{self, AttackChain};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::collections::HashMap;

fn node_provenance_hash(graph_key: &str, node_type: &str, metadata: &str) -> String {
    let mut h = Sha256::new();
    h.update(graph_key.as_bytes());
    h.update(node_type.as_bytes());
    h.update(metadata.as_bytes());
    hex::encode(h.finalize())
}

/// Full battlespace bundle for the force-directed C2 surface.
pub async fn topology_bundle(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Value, String> {
    let graph = crate::risk_graph::export_risk_graph_json(pool, tenant_id, client_id)
        .await
        .map_err(|e| format!("graph export: {e}"))?;

    let attack_paths = crate::attack_path::latest_snapshot(pool, tenant_id, client_id)
        .await
        .map_err(|e| format!("attack paths: {e}"))?;

    let findings = load_open_findings(pool, tenant_id, client_id).await?;
    let strips_chain = attack_chain_planner::plan_from_findings(&findings, "impact:objective");

    let mut nodes = graph
        .pointer("/graph/nodes_flat")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let exposure = load_node_exposure(pool, tenant_id, client_id).await?;
    for n in &mut nodes {
        if let Some(obj) = n.as_object_mut() {
            let id = obj.get("id").and_then(Value::as_i64).unwrap_or(0);
            if let Some((internet, jewel)) = exposure.get(&id) {
                obj.insert("internet_exposed".into(), json!(*internet));
                obj.insert("crown_jewel".into(), json!(*jewel));
            }
            let gk = obj.get("graph_key").and_then(Value::as_str).unwrap_or("");
            let nt = obj.get("node_type").and_then(Value::as_str).unwrap_or("");
            let meta = obj
                .get("metadata")
                .map(|m| m.to_string())
                .unwrap_or_else(|| "{}".into());
            obj.insert(
                "provenance_sha256".into(),
                json!(node_provenance_hash(gk, nt, &meta)),
            );
        }
    }

    Ok(json!({
        "ok": true,
        "client_id": client_id,
        "graph": {
            "nodes": nodes,
            "edges": graph.pointer("/graph/edges_struct").cloned().unwrap_or(json!([])),
            "meta": graph.get("meta").cloned().unwrap_or(json!({})),
        },
        "attack_paths": attack_paths,
        "strips_chain": strips_chain.as_ref().map(AttackChain::to_json),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ShadowPreviewBody {
    pub client_id: i64,
    #[serde(default)]
    pub technique_id: Option<String>,
    #[serde(default = "default_goal")]
    pub goal: String,
}

fn default_goal() -> String {
    "impact:objective".into()
}

/// STRIPS shadow preview — productive technique step or full chain as shadow nodes.
pub async fn shadow_preview(
    pool: &PgPool,
    tenant_id: i64,
    body: &ShadowPreviewBody,
) -> Result<Value, String> {
    let findings = load_open_findings(pool, tenant_id, body.client_id).await?;
    let facts = attack_chain_planner::facts_from_findings(&findings);
    let techniques = attack_chain_planner::default_technique_library();

    let (step, gained) = if let Some(tid) = body.technique_id.as_deref() {
        let t = techniques
            .iter()
            .find(|x| x.id == tid)
            .ok_or_else(|| format!("unknown technique: {tid}"))?;
        let applicable = t.preconditions.iter().all(|p| facts.contains(p));
        if !applicable {
            return Err(format!("technique {tid} not applicable to observed state"));
        }
        let productive = t.effects.iter().any(|e| !facts.contains(e));
        if !productive {
            return Err(format!("technique {tid} would not change state"));
        }
        let mut next = facts.clone();
        let mut gained = Vec::new();
        for e in &t.effects {
            if next.insert(e.clone()) {
                gained.push(e.clone());
            }
        }
        (
            json!({
                "technique_id": t.id,
                "name": t.name,
                "mitre": t.mitre,
                "cost": t.cost,
                "gained": &gained,
            }),
            gained,
        )
    } else {
        let chain = attack_chain_planner::plan(&facts, &techniques, &body.goal, 50_000)
            .ok_or_else(|| "no STRIPS path from observed facts to goal".to_string())?;
        let last = chain.steps.last();
        let gained = last.map(|s| s.gained.clone()).unwrap_or_default();
        (chain.to_json(), gained)
    };

    let shadow_nodes: Vec<Value> = gained
        .iter()
        .enumerate()
        .map(|(i, fact)| {
            json!({
                "id": format!("shadow-{i}-{fact}"),
                "label": fact,
                "node_type": "shadow_state",
                "is_shadow": true,
                "fact": fact,
                "provenance_sha256": node_provenance_hash(fact, "shadow_state", "strips_planner"),
            })
        })
        .collect();

    let shadow_edges: Vec<Value> = gained
        .iter()
        .enumerate()
        .map(|(i, fact)| {
            json!({
                "id": format!("shadow-edge-{i}"),
                "source": "current_state",
                "target": format!("shadow-{i}-{fact}"),
                "edge_type": "strips_transition",
                "is_shadow": true,
            })
        })
        .collect();

    Ok(json!({
        "ok": true,
        "step": step,
        "shadow_nodes": shadow_nodes,
        "shadow_edges": shadow_edges,
    }))
}

async fn load_open_findings(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Vec<Value>, String> {
    // Pull the intel columns alongside raw_data and fold them into the finding JSON. These live in
    // dedicated table columns (not inside raw_data), so without this the STRIPS planner would never
    // see a finding's KEV status or EPSS/KEV-adjusted effective_risk when grounding its facts.
    let rows = sqlx::query(
        r#"SELECT raw_data, severity, effective_risk, kev_listed FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2
              AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE')
            ORDER BY id DESC LIMIT 500"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("findings: {e}"))?;

    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let mut v = r.try_get::<Value, _>("raw_data").ok()?;
            if let Some(obj) = v.as_object_mut() {
                // Prefer the authoritative column value; only fill when raw_data lacks the key.
                if let Ok(sev) = r.try_get::<String, _>("severity") {
                    obj.entry("severity").or_insert(Value::String(sev));
                }
                if let Ok(Some(eff)) = r.try_get::<Option<f64>, _>("effective_risk") {
                    obj.insert("effective_risk".into(), json!(eff));
                }
                if let Ok(kev) = r.try_get::<bool, _>("kev_listed") {
                    obj.insert("kev_listed".into(), json!(kev));
                }
            }
            Some(v)
        })
        .collect())
}

async fn load_node_exposure(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<HashMap<i64, (bool, bool)>, String> {
    let rows = sqlx::query(
        r#"SELECT id, internet_exposed, crown_jewel
             FROM risk_graph_nodes
            WHERE tenant_id = $1 AND client_id = $2"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("exposure: {e}"))?;

    let mut map = HashMap::new();
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let internet: bool = r.try_get("internet_exposed").unwrap_or(false);
        let jewel: bool = r.try_get("crown_jewel").unwrap_or(false);
        map.insert(id, (internet, jewel));
    }
    Ok(map)
}

pub fn techniques_json() -> Value {
    json!({
        "techniques": attack_chain_planner::default_technique_library()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_hash_matches_known_sha256_vectors() {
        // Concatenation of the three empty strings hashes to the SHA-256 of the empty input.
        assert_eq!(
            node_provenance_hash("", "", ""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // "a" || "b" || "c" == "abc", the canonical SHA-256 test vector.
        assert_eq!(
            node_provenance_hash("a", "b", "c"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn provenance_hash_is_deterministic_and_input_sensitive() {
        let a = node_provenance_hash("gk", "host", "{\"k\":1}");
        let b = node_provenance_hash("gk", "host", "{\"k\":1}");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        // Different content produces a different hash.
        assert_ne!(a, node_provenance_hash("gk", "host", "{\"k\":2}"));
        // Components are concatenated without a delimiter, so boundary shifts of
        // the same joined string collide (hash is SHA-256 of the concatenation).
        assert_eq!(
            node_provenance_hash("ab", "c", "d"),
            node_provenance_hash("a", "bc", "d")
        );
    }

    #[test]
    fn default_goal_is_impact_objective() {
        assert_eq!(default_goal(), "impact:objective");
    }

    #[test]
    fn techniques_json_wraps_library_in_array() {
        let v = techniques_json();
        assert!(v.get("techniques").is_some());
        assert!(v["techniques"].is_array());
    }

    #[test]
    fn shadow_preview_body_defaults() {
        let body: ShadowPreviewBody = serde_json::from_str(r#"{"client_id": 7}"#).unwrap();
        assert_eq!(body.client_id, 7);
        assert!(body.technique_id.is_none());
        // #[serde(default = "default_goal")] supplies the goal
        assert_eq!(body.goal, "impact:objective");
    }

    #[test]
    fn shadow_preview_body_full() {
        let body: ShadowPreviewBody =
            serde_json::from_str(r#"{"client_id": 3, "technique_id": "T1190", "goal": "lateral"}"#)
                .unwrap();
        assert_eq!(body.client_id, 3);
        assert_eq!(body.technique_id.as_deref(), Some("T1190"));
        assert_eq!(body.goal, "lateral");
    }
}
