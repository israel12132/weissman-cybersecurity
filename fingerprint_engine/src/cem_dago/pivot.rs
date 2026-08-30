//! Pivot: Dijkstra over live `risk_graph_nodes` / `risk_graph_edges` plus manifest overlap.
//!
//! Schema is `from_node_id` / `to_node_id` / `edge_type` (not the draft `source_node`/`cost`
//! columns). Edge cost follows the same inverse-CVSS/EPSS/KEV model as [`crate::attack_path`].

use super::manifest::EdgeKind;
use super::registry::manifest_for;
use petgraph::algo::dijkstra;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize)]
pub struct GraphHop {
    pub from_label: String,
    pub to_label: String,
    pub edge_type: String,
    pub cost: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlternativeRoute {
    pub signals: Vec<String>,
    pub hops: Vec<GraphHop>,
    pub start: String,
}

/// Load the client risk graph and return cheapest-path signals from internet-exposed nodes.
pub async fn alternative_signals_via_dijkstra(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<AlternativeRoute, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;

    let node_rows = sqlx::query(
        r#"SELECT n.id, n.label, n.node_type, n.graph_key, n.internet_exposed,
                  COALESCE(MAX((v.raw_data->>'cvss_score')::real), 0)::real AS max_cvss,
                  COALESCE(MAX(v.epss_score), 0)::real AS max_epss,
                  BOOL_OR(COALESCE(v.kev_listed, FALSE)) AS kev
             FROM risk_graph_nodes n
             LEFT JOIN vulnerabilities v
               ON v.risk_node_id = n.id
              AND COALESCE(v.status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE')
            WHERE n.tenant_id = $1 AND n.client_id = $2
            GROUP BY n.id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("load nodes: {e}"))?;

    let edge_rows = sqlx::query(
        r#"SELECT from_node_id, to_node_id, edge_type
             FROM risk_graph_edges
            WHERE tenant_id = $1 AND client_id = $2"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("load edges: {e}"))?;
    let _ = tx.rollback().await;

    let mut labels: HashMap<i64, (String, String, bool, f64)> = HashMap::new();
    for r in &node_rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let label: String = r.try_get("label").unwrap_or_default();
        let ntype: String = r.try_get("node_type").unwrap_or_default();
        let exposed: bool = r.try_get("internet_exposed").unwrap_or(false);
        let cvss: f32 = r.try_get("max_cvss").unwrap_or(0.0);
        let epss: f32 = r.try_get("max_epss").unwrap_or(0.0);
        let kev: bool = r.try_get("kev").unwrap_or(false);
        let mut score: f64 = 0.5 + f64::from(cvss) / 10.0;
        score *= 1.0 + f64::from(epss) * 1.5;
        if kev {
            score *= 2.0;
        }
        let cost = 1.0 / score.max(0.05);
        labels.insert(id, (label, ntype, exposed, cost));
    }

    let mut graph = DiGraph::<i64, (f64, String)>::new();
    let mut idx: HashMap<i64, NodeIndex> = HashMap::new();
    for id in labels.keys() {
        idx.insert(*id, graph.add_node(*id));
    }
    let mut hops_meta = Vec::new();
    for r in &edge_rows {
        let from: i64 = r.try_get("from_node_id").unwrap_or(0);
        let to: i64 = r.try_get("to_node_id").unwrap_or(0);
        let etype: String = r.try_get("edge_type").unwrap_or_default();
        let (Some(&u), Some(&v)) = (idx.get(&from), idx.get(&to)) else {
            continue;
        };
        let node_cost = labels.get(&to).map(|t| t.3).unwrap_or(1.0);
        graph.add_edge(u, v, (node_cost, etype.clone()));
        hops_meta.push((from, to, etype, node_cost));
    }

    let starts: Vec<i64> = labels
        .iter()
        .filter(|(_, t)| t.2)
        .map(|(id, _)| *id)
        .collect();

    let mut signals: HashSet<String> = HashSet::new();
    let mut hops: Vec<GraphHop> = Vec::new();
    let mut start_label = String::from("internet_exposed");

    if let Some(&sid) = starts.first() {
        start_label = labels.get(&sid).map(|t| t.0.clone()).unwrap_or(start_label);
        if let Some(&start_idx) = idx.get(&sid) {
            let costs = dijkstra(&graph, start_idx, None, |e| e.weight().0);
            let mut ranked: Vec<_> = costs.into_iter().collect();
            ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            for (nix, _) in ranked.into_iter().take(32) {
                let node_id = graph[nix];
                if let Some((label, ntype, _, _)) = labels.get(&node_id) {
                    push_signals(&mut signals, ntype);
                    push_signals(&mut signals, label);
                }
            }
        }
    }

    for (from, to, etype, cost) in hops_meta.into_iter().take(64) {
        push_signals(&mut signals, &etype);
        if let Some(k) = EdgeKind::from_graph_label(&etype) {
            signals.insert(k.signal().to_string());
        }
        hops.push(GraphHop {
            from_label: labels.get(&from).map(|t| t.0.clone()).unwrap_or_default(),
            to_label: labels.get(&to).map(|t| t.0.clone()).unwrap_or_default(),
            edge_type: etype,
            cost,
        });
    }

    if signals.is_empty() {
        signals.insert("internet_exposed".into());
        signals.insert("web_port_active".into());
    }

    let mut sigs: Vec<String> = signals.into_iter().collect();
    sigs.sort();
    Ok(AlternativeRoute {
        signals: sigs,
        hops,
        start: start_label,
    })
}

fn push_signals(set: &mut HashSet<String>, label: &str) {
    if let Some(k) = EdgeKind::from_graph_label(label) {
        set.insert(k.signal().to_string());
    }
}

/// Engines that can answer the failed engine's outputs **or** consume Dijkstra signals.
#[must_use]
pub fn fallback_engine_ids(
    failed_engine: &str,
    enabled: &[String],
    already_ran: &HashSet<String>,
    route_signals: &[String],
    cap: usize,
) -> Vec<String> {
    let failed = manifest_for(failed_engine);
    let mut scored: Vec<(i32, String)> = Vec::new();
    for id in enabled {
        if id == failed_engine || already_ran.contains(id) {
            continue;
        }
        let m = manifest_for(id);
        let mut score = 0i32;
        for s in &m.output_signals {
            if failed.output_signals.iter().any(|f| f == s) {
                score += 3;
            }
        }
        for s in &m.required_inputs {
            if route_signals.iter().any(|r| r == s) {
                score += 2;
            }
        }
        for k in &m.edge_kinds {
            if route_signals.iter().any(|r| r == k.signal()) {
                score += 2;
            }
        }
        if score > 0 {
            scored.push((score, id.clone()));
        }
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().take(cap).map(|(_, id)| id).collect()
}

/// In-memory Dijkstra used by unit tests (no Postgres).
#[must_use]
pub fn dijkstra_signals_in_memory(
    nodes: &[(String, bool)],
    edges: &[(usize, usize, &str, f64)],
) -> Vec<String> {
    let mut graph = DiGraph::<usize, f64>::new();
    let idxs: Vec<NodeIndex> = (0..nodes.len()).map(|i| graph.add_node(i)).collect();
    for (u, v, _, w) in edges {
        graph.add_edge(idxs[*u], idxs[*v], *w);
    }
    let start = nodes.iter().position(|n| n.1).unwrap_or(0);
    let costs = dijkstra(&graph, idxs[start], None, |e| *e.weight());
    let mut signals = HashSet::new();
    for (nix, _) in costs {
        let i = graph[nix];
        if let Some(k) = EdgeKind::from_graph_label(&nodes[i].0) {
            signals.insert(k.signal().to_string());
        }
    }
    for (_, _, etype, _) in edges {
        if let Some(k) = EdgeKind::from_graph_label(etype) {
            signals.insert(k.signal().to_string());
        }
    }
    let mut v: Vec<_> = signals.into_iter().collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_path_yields_web_and_ot_signals() {
        let nodes = vec![
            ("internet_exposed".into(), true),
            ("web_app".into(), false),
            ("modbus_plc".into(), false),
        ];
        let edges = vec![(0, 1, "exposes", 1.0), (1, 2, "leads_to_ot", 2.0)];
        let sigs = dijkstra_signals_in_memory(&nodes, &edges);
        assert!(sigs
            .iter()
            .any(|s| s == "web_port_active" || s == "ot_protocol"));
    }

    #[test]
    fn fallback_picks_overlap_not_self() {
        let enabled = vec![
            "scada_ics".into(),
            "iot_firmware".into(),
            "graphql_attack".into(),
        ];
        let ran = HashSet::from(["scada_ics".into()]);
        let ids = fallback_engine_ids("scada_ics", &enabled, &ran, &["ot_protocol".into()], 4);
        assert!(ids.contains(&"iot_firmware".to_string()));
        assert!(!ids.contains(&"scada_ics".to_string()));
    }
}
