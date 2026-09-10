//! Pivot: Dijkstra over a **live** copy of `risk_graph_nodes` / `risk_graph_edges`.
//!
//! The tenant graph is loaded at mesh start ([`load_risk_graph`]) into
//! [`ResidentRiskGraph`] (`Arc<ArcSwap<CachedRiskGraph>>`). Per-engine failures
//! recompute Dijkstra in RAM only — they must not re-query Postgres on every
//! timeout. After each wave, new blackboard signals are ingested with a CAS
//! (`rcu`) swap so Dijkstra sees mid-scan topology (asset discovery / lateral
//! movement) without an `RwLock` write that would stall the event loop.
//!
//! Schema is `from_node_id` / `to_node_id` / `edge_type` (not the draft `source_node`/`cost`
//! columns). Edge cost follows the same inverse-CVSS/EPSS/KEV model as [`crate::attack_path`].

use super::manifest::EdgeKind;
use super::registry::manifest_for;
use arc_swap::ArcSwap;
use petgraph::algo::dijkstra;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Scan-resident risk graph. [`ArcSwap`] so discovery engines can publish a new
/// snapshot without blocking Dijkstra readers on an `RwLock` write.
#[derive(Clone)]
pub struct CachedRiskGraph {
    labels: HashMap<i64, (String, String, bool, f64)>,
    graph: DiGraph<i64, (f64, String)>,
    idx: HashMap<i64, NodeIndex>,
    hops_meta: Vec<(i64, i64, String, f64)>,
}

impl CachedRiskGraph {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            labels: HashMap::new(),
            graph: DiGraph::new(),
            idx: HashMap::new(),
            hops_meta: Vec::new(),
        }
    }

    #[must_use]
    pub fn node_count(&self) -> usize {
        self.labels.len()
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.hops_meta.len()
    }

    #[must_use]
    pub fn has_label(&self, label: &str) -> bool {
        self.labels.values().any(|t| t.0 == label)
    }

    /// Copy-on-write: attach newly discovered blackboard signals as nodes linked
    /// from internet-exposed entry points so Dijkstra sees live topology.
    #[must_use]
    pub fn with_ingested_signals(&self, signals: &[String]) -> Self {
        let mut next = self.clone();
        let existing: HashSet<String> = next.labels.values().map(|t| t.0.clone()).collect();
        let mut next_id = next
            .labels
            .keys()
            .copied()
            .min()
            .unwrap_or(0)
            .min(0)
            .saturating_sub(1);
        if next_id >= 0 {
            next_id = -1;
        }
        if !next.labels.values().any(|t| t.2) {
            let id = next_id;
            next_id -= 1;
            let idx = next.graph.add_node(id);
            next.idx.insert(id, idx);
            next.labels
                .insert(id, ("internet_exposed".into(), "entry".into(), true, 1.0));
        }
        let starts: Vec<i64> = next
            .labels
            .iter()
            .filter(|(_, t)| t.2)
            .map(|(id, _)| *id)
            .collect();
        for sig in signals {
            if !ingestible_signal(sig) || existing.contains(sig) {
                continue;
            }
            let id = next_id;
            next_id -= 1;
            let gidx = next.graph.add_node(id);
            next.idx.insert(id, gidx);
            let ntype = EdgeKind::from_graph_label(sig)
                .map(|k| k.signal().to_string())
                .unwrap_or_else(|| "discovered".into());
            next.labels.insert(id, (sig.clone(), ntype, false, 0.4));
            for sid in &starts {
                let Some(&u) = next.idx.get(sid) else {
                    continue;
                };
                let etype = format!("live:{sig}");
                next.graph.add_edge(u, gidx, (0.4, etype.clone()));
                next.hops_meta.push((*sid, id, etype, 0.4));
            }
        }
        next
    }
}

fn ingestible_signal(sig: &str) -> bool {
    if sig.starts_with('_')
        || sig == "internet_exposed"
        || sig == "historical_payloads"
        || sig == "discovery_paths"
        || sig == "_failures"
    {
        return false;
    }
    EdgeKind::from_graph_label(sig).is_some()
}

/// Shared handle stored on the mesh executor for the lifetime of one scan.
pub type ResidentRiskGraph = Arc<ArcSwap<CachedRiskGraph>>;

#[must_use]
pub fn resident_graph(graph: CachedRiskGraph) -> ResidentRiskGraph {
    Arc::new(ArcSwap::from_pointee(graph))
}

/// Atomic snapshot replace (no blocking write lock).
pub fn store_graph(cache: &ResidentRiskGraph, graph: CachedRiskGraph) {
    cache.store(Arc::new(graph));
}

/// CAS / RCU ingest of live blackboard signals.
pub fn ingest_live_signals(cache: &ResidentRiskGraph, signals: &[String]) {
    cache.rcu(|cur| Arc::new((**cur).with_ingested_signals(signals)));
}

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

/// Pull the tenant risk graph from Postgres **once**. Callers cache the result.
pub async fn load_risk_graph(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<CachedRiskGraph, String> {
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

    Ok(CachedRiskGraph {
        labels,
        graph,
        idx,
        hops_meta,
    })
}

/// Cheapest-path signals from internet-exposed nodes. **No I/O.**
#[must_use]
pub fn alternative_signals_from_cached(cached: &CachedRiskGraph) -> AlternativeRoute {
    let starts: Vec<i64> = cached
        .labels
        .iter()
        .filter(|(_, t)| t.2)
        .map(|(id, _)| *id)
        .collect();

    let mut signals: HashSet<String> = HashSet::new();
    let mut hops: Vec<GraphHop> = Vec::new();
    let mut start_label = String::from("internet_exposed");

    if let Some(&sid) = starts.first() {
        start_label = cached
            .labels
            .get(&sid)
            .map(|t| t.0.clone())
            .unwrap_or(start_label);
        if let Some(&start_idx) = cached.idx.get(&sid) {
            let costs = dijkstra(&cached.graph, start_idx, None, |e| e.weight().0);
            let mut ranked: Vec<_> = costs.into_iter().collect();
            ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            for (nix, _) in ranked.into_iter().take(32) {
                let node_id = cached.graph[nix];
                if let Some((label, ntype, _, _)) = cached.labels.get(&node_id) {
                    push_signals(&mut signals, ntype);
                    push_signals(&mut signals, label);
                }
            }
        }
    }

    for (from, to, etype, cost) in cached.hops_meta.iter().take(64) {
        push_signals(&mut signals, etype);
        if let Some(k) = EdgeKind::from_graph_label(etype) {
            signals.insert(k.signal().to_string());
        }
        hops.push(GraphHop {
            from_label: cached
                .labels
                .get(from)
                .map(|t| t.0.clone())
                .unwrap_or_default(),
            to_label: cached
                .labels
                .get(to)
                .map(|t| t.0.clone())
                .unwrap_or_default(),
            edge_type: etype.clone(),
            cost: *cost,
        });
    }

    if signals.is_empty() {
        signals.insert("internet_exposed".into());
        signals.insert("web_port_active".into());
    }

    let mut sigs: Vec<String> = signals.into_iter().collect();
    sigs.sort();
    AlternativeRoute {
        signals: sigs,
        hops,
        start: start_label,
    }
}

/// Load-then-compute helper for callers that do not hold a scan-resident graph
/// (status probes, one-shot tools). The mesh path must use [`load_risk_graph`]
/// once and [`alternative_signals_from_cached`] thereafter.
pub async fn alternative_signals_via_dijkstra(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<AlternativeRoute, String> {
    let cached = load_risk_graph(pool, tenant_id, client_id).await?;
    Ok(alternative_signals_from_cached(&cached))
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
    fn cached_graph_dijkstra_is_ram_only() {
        let mut cached = CachedRiskGraph::empty();
        let a = cached.graph.add_node(1);
        let b = cached.graph.add_node(2);
        cached.idx.insert(1, a);
        cached.idx.insert(2, b);
        cached
            .labels
            .insert(1, ("internet_exposed".into(), "entry".into(), true, 1.0));
        cached
            .labels
            .insert(2, ("web_app".into(), "web".into(), false, 0.5));
        cached.graph.add_edge(a, b, (0.5, "exposes".into()));
        cached.hops_meta.push((1, 2, "exposes".into(), 0.5));
        let route = alternative_signals_from_cached(&cached);
        assert!(!route.signals.is_empty());
        assert!(route
            .signals
            .iter()
            .any(|s| s == "web_port_active" || s == "internet_exposed" || s == "web_app"));
    }

    #[test]
    fn empty_cached_graph_has_seed_signals() {
        let route = alternative_signals_from_cached(&CachedRiskGraph::empty());
        assert!(route.signals.contains(&"internet_exposed".to_string()));
        assert!(route.signals.contains(&"web_port_active".to_string()));
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

    #[test]
    fn ingest_signal_adds_live_hop_for_dijkstra() {
        let mut cached = CachedRiskGraph::empty();
        let a = cached.graph.add_node(1);
        cached.idx.insert(1, a);
        cached
            .labels
            .insert(1, ("internet_exposed".into(), "entry".into(), true, 1.0));
        let live = cached.with_ingested_signals(&["ot_protocol".into()]);
        assert!(live.has_label("ot_protocol"));
        assert!(live.edge_count() > cached.edge_count());
        let route = alternative_signals_from_cached(&live);
        assert!(
            route
                .hops
                .iter()
                .any(|h| h.to_label == "ot_protocol" || h.edge_type.contains("ot_protocol")),
            "live ingest must be visible to Dijkstra hops: {:?}",
            route.hops
        );
        let swapped = resident_graph(cached);
        ingest_live_signals(&swapped, &["web_port_active".into()]);
        let snap = swapped.load();
        assert!(snap.has_label("web_port_active"));
    }
}
