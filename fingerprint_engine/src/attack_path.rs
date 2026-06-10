//! Attack-path inference over the `risk_graph_nodes` / `risk_graph_edges`
//! topology built incrementally by every scan.
//!
//! Algorithm (Yen-style top-K shortest paths, simplified for our use case):
//!   1. Load all nodes + edges for `(tenant, client)` into memory once
//!      (typical client: tens to a few hundred nodes — well within memory).
//!   2. Seed nodes = `internet_exposed = TRUE`.
//!      Target nodes = `crown_jewel = TRUE`.
//!   3. Edge weight = `1.0 / max(0.01, severity_score(node) * (1 + epss))`.
//!      Cheaper edges represent EASIER attacker pivots — Dijkstra finds the
//!      *most likely* path, not the shortest hop count.
//!   4. For every (seed, target) pair, run Dijkstra. Collect path + total cost.
//!   5. Sort paths by ascending cost. Return top K (default 25).
//!   6. Identify **choke points**: nodes that appear in ≥ N/2 of the top
//!      paths. Patching one of these breaks many paths simultaneously —
//!      this is the highest-leverage remediation guidance the analyst gets.
//!
//! Output is also persisted to `attack_path_snapshots` so the cockpit can
//! render without rerunning BFS on every poll.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::{BinaryHeap, HashMap, HashSet};

const DEFAULT_TOP_K: usize = 25;
const MAX_PATH_HOPS: usize = 12;       // anything longer is hypothetical
const CHOKE_POINT_THRESHOLD: f64 = 0.5; // node appears in ≥50% of top paths

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: i64,
    pub graph_key: String,
    pub label: String,
    pub node_type: String,
    pub risk_score: i32,
    pub internet_exposed: bool,
    pub crown_jewel: bool,
    pub asset_value: f32,
    pub max_finding_cvss: f32,
    pub max_finding_epss: f32,
    pub kev_present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: i64,
    pub to: i64,
    pub edge_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStep {
    pub node_id: i64,
    pub graph_key: String,
    pub label: String,
    pub node_type: String,
    pub edge_type: String, // type of edge taken to reach this node ("" for seed)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub entry: i64,
    pub jewel: i64,
    pub hops: usize,
    pub cost: f64,                // sum of edge weights (lower = easier)
    pub risk: f64,                // 0..10 derived from path cost + asset value
    pub kev_hops: usize,          // number of hops with at least one KEV finding
    pub steps: Vec<PathStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathSnapshot {
    pub entry_count: usize,
    pub jewel_count: usize,
    pub paths: Vec<AttackPath>,
    pub choke_points: Vec<ChokePoint>,
    pub computed_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChokePoint {
    pub node_id: i64,
    pub graph_key: String,
    pub label: String,
    pub node_type: String,
    /// How many of the top paths flow through this node.
    pub coverage: usize,
    /// Coverage as a percentage of the top paths (0–100).
    pub coverage_pct: u8,
    pub max_finding_cvss: f32,
    pub max_finding_epss: f32,
    pub kev_present: bool,
}

/// Public entry point: compute (and persist) the top-K attack paths for a client.
pub async fn compute_and_store(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    top_k: Option<usize>,
) -> Result<AttackPathSnapshot, String> {
    let top_k = top_k.unwrap_or(DEFAULT_TOP_K).clamp(1, 200);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;

    // ── Load graph + finding-derived risk per node in TWO queries ───────────
    let node_rows = sqlx::query(
        r#"SELECT n.id, n.graph_key, n.label, n.node_type, n.risk_score,
                  n.internet_exposed, n.crown_jewel, n.asset_value,
                  COALESCE(MAX((v.raw_data->>'cvss_score')::real), 0)::real AS max_cvss,
                  COALESCE(MAX(v.epss_score), 0)::real                       AS max_epss,
                  BOOL_OR(COALESCE(v.kev_listed, FALSE))                     AS kev
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

    let nodes: HashMap<i64, GraphNode> = node_rows
        .into_iter()
        .map(|r| {
            let id: i64 = r.try_get("id").unwrap_or(0);
            let n = GraphNode {
                id,
                graph_key: r.try_get("graph_key").unwrap_or_default(),
                label: r.try_get("label").unwrap_or_default(),
                node_type: r.try_get("node_type").unwrap_or_default(),
                risk_score: r.try_get("risk_score").unwrap_or(0),
                internet_exposed: r.try_get("internet_exposed").unwrap_or(false),
                crown_jewel: r.try_get("crown_jewel").unwrap_or(false),
                asset_value: r.try_get("asset_value").unwrap_or(1.0),
                max_finding_cvss: r.try_get("max_cvss").unwrap_or(0.0),
                max_finding_epss: r.try_get("max_epss").unwrap_or(0.0),
                kev_present: r.try_get("kev").unwrap_or(false),
            };
            (id, n)
        })
        .collect();

    let mut adjacency: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
    let mut edges = Vec::with_capacity(edge_rows.len());
    for r in edge_rows {
        let from: i64 = r.try_get("from_node_id").unwrap_or(0);
        let to: i64 = r.try_get("to_node_id").unwrap_or(0);
        let etype: String = r.try_get("edge_type").unwrap_or_default();
        if from == 0 || to == 0 {
            continue;
        }
        adjacency.entry(from).or_default().push((to, etype.clone()));
        edges.push(GraphEdge { from, to, edge_type: etype });
    }

    let entries: Vec<&GraphNode> = nodes.values().filter(|n| n.internet_exposed).collect();
    let jewels: HashSet<i64> = nodes
        .values()
        .filter(|n| n.crown_jewel)
        .map(|n| n.id)
        .collect();

    let mut paths: Vec<AttackPath> = Vec::new();
    if !entries.is_empty() && !jewels.is_empty() {
        for entry in &entries {
            // Dijkstra from this entry → any crown jewel.
            for jewel_id in &jewels {
                if let Some(p) = dijkstra_path(
                    entry.id,
                    *jewel_id,
                    &nodes,
                    &adjacency,
                ) {
                    paths.push(p);
                }
            }
        }
    }

    paths.sort_by(|a, b| a.cost.partial_cmp(&b.cost).unwrap_or(std::cmp::Ordering::Equal));
    paths.truncate(top_k);

    // ── Choke points: nodes appearing in ≥ N/2 of the top paths ─────────────
    let mut counter: HashMap<i64, usize> = HashMap::new();
    for p in &paths {
        for s in &p.steps {
            *counter.entry(s.node_id).or_insert(0) += 1;
        }
    }
    let threshold = (paths.len() as f64 * CHOKE_POINT_THRESHOLD).ceil() as usize;
    let mut choke_points: Vec<ChokePoint> = counter
        .into_iter()
        .filter(|(_, c)| *c >= threshold.max(2))
        .filter_map(|(id, cov)| {
            nodes.get(&id).map(|n| ChokePoint {
                node_id: id,
                graph_key: n.graph_key.clone(),
                label: n.label.clone(),
                node_type: n.node_type.clone(),
                coverage: cov,
                coverage_pct: ((cov as f64 / paths.len().max(1) as f64) * 100.0).round() as u8,
                max_finding_cvss: n.max_finding_cvss,
                max_finding_epss: n.max_finding_epss,
                kev_present: n.kev_present,
            })
        })
        .collect();
    choke_points.sort_by(|a, b| b.coverage.cmp(&a.coverage));

    let snapshot = AttackPathSnapshot {
        entry_count: entries.len(),
        jewel_count: jewels.len(),
        paths: paths.clone(),
        choke_points: choke_points.clone(),
        computed_at_unix: chrono::Utc::now().timestamp(),
    };

    // ── Persist the snapshot so the cockpit can read instantly ──────────────
    let max_risk = snapshot
        .paths
        .iter()
        .map(|p| p.risk)
        .fold(0_f64, f64::max);
    let paths_json: Value = serde_json::to_value(&snapshot.paths).unwrap_or(json!([]));
    let chokes_json: Value = serde_json::to_value(&snapshot.choke_points).unwrap_or(json!([]));
    let _ = sqlx::query(
        r#"INSERT INTO attack_path_snapshots
                 (tenant_id, client_id, computed_at,
                  entry_count, jewel_count, path_count, max_risk,
                  paths_json, choke_points)
           VALUES ($1, $2, now(), $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(snapshot.entry_count as i32)
    .bind(snapshot.jewel_count as i32)
    .bind(snapshot.paths.len() as i32)
    .bind(max_risk as f32)
    .bind(&paths_json)
    .bind(&chokes_json)
    .execute(&mut *tx)
    .await;

    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(snapshot)
}

/// Read the latest snapshot for this client. Returns `None` if none was ever computed.
pub async fn latest_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Option<AttackPathSnapshot>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT entry_count, jewel_count, paths_json, choke_points, computed_at
             FROM attack_path_snapshots
            WHERE tenant_id = $1 AND client_id = $2
            ORDER BY computed_at DESC
            LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    let Some(r) = row else { return Ok(None) };
    let paths: Vec<AttackPath> = serde_json::from_value(
        r.try_get::<Value, _>("paths_json").unwrap_or(json!([])),
    )
    .unwrap_or_default();
    let choke: Vec<ChokePoint> = serde_json::from_value(
        r.try_get::<Value, _>("choke_points").unwrap_or(json!([])),
    )
    .unwrap_or_default();
    let computed_at: chrono::DateTime<chrono::Utc> = r.try_get("computed_at").unwrap_or_else(|_| chrono::Utc::now());
    Ok(Some(AttackPathSnapshot {
        entry_count: r.try_get::<i32, _>("entry_count").unwrap_or(0) as usize,
        jewel_count: r.try_get::<i32, _>("jewel_count").unwrap_or(0) as usize,
        paths,
        choke_points: choke,
        computed_at_unix: computed_at.timestamp(),
    }))
}

// ── Dijkstra over a min-heap of (cost, node, [path]) tuples ──────────────────

#[derive(Debug)]
struct HeapEntry {
    cost: f64,
    node: i64,
    path: Vec<PathStep>,
}
impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool { self.cost == other.cost }
}
impl Eq for HeapEntry {}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse so BinaryHeap acts as a *min*-heap on cost.
        other.cost.partial_cmp(&self.cost).unwrap_or(std::cmp::Ordering::Equal)
    }
}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn node_pivot_weight(n: &GraphNode) -> f64 {
    // Combined difficulty metric for a node:
    //   - high CVSS, high EPSS, KEV → low cost (easy attacker pivot)
    //   - clean node → high cost
    let mut score: f64 = 0.5 + (n.max_finding_cvss as f64 / 10.0); // 0.5..1.5
    score *= 1.0 + (n.max_finding_epss as f64) * 1.5;              // up to ~3.75
    if n.kev_present {
        score *= 2.0;
    }
    // Convert score-of-attack to cost (inverse) — easier = cheaper.
    1.0 / score.max(0.05)
}

fn dijkstra_path(
    entry: i64,
    target: i64,
    nodes: &HashMap<i64, GraphNode>,
    adjacency: &HashMap<i64, Vec<(i64, String)>>,
) -> Option<AttackPath> {
    let entry_node = nodes.get(&entry)?;
    let mut heap: BinaryHeap<HeapEntry> = BinaryHeap::new();
    heap.push(HeapEntry {
        cost: 0.0,
        node: entry,
        path: vec![PathStep {
            node_id: entry_node.id,
            graph_key: entry_node.graph_key.clone(),
            label: entry_node.label.clone(),
            node_type: entry_node.node_type.clone(),
            edge_type: String::new(),
        }],
    });
    let mut visited: HashMap<i64, f64> = HashMap::new();

    while let Some(HeapEntry { cost, node, path }) = heap.pop() {
        if node == target {
            // Compute risk score 0..10 from path cost + asset value of jewel.
            // Lower cost = higher likelihood = higher risk.
            let jewel_value = nodes.get(&target).map(|n| n.asset_value).unwrap_or(1.0) as f64;
            let likelihood = (1.0 / (1.0 + cost)).clamp(0.0, 1.0);
            let risk = (likelihood * 10.0 * jewel_value.clamp(0.5, 3.0)).min(10.0);
            let kev_hops = path
                .iter()
                .filter(|s| nodes.get(&s.node_id).map(|n| n.kev_present).unwrap_or(false))
                .count();
            return Some(AttackPath {
                entry,
                jewel: target,
                hops: path.len().saturating_sub(1),
                cost,
                risk: (risk * 10.0).round() / 10.0,
                kev_hops,
                steps: path,
            });
        }
        if path.len() > MAX_PATH_HOPS {
            continue;
        }
        if let Some(&best) = visited.get(&node) {
            if best <= cost {
                continue;
            }
        }
        visited.insert(node, cost);
        let Some(neighbours) = adjacency.get(&node) else { continue };
        for (next, etype) in neighbours {
            // Don't revisit a node already in this path (avoid cycles).
            if path.iter().any(|s| s.node_id == *next) {
                continue;
            }
            let Some(next_node) = nodes.get(next) else { continue };
            let edge_cost = node_pivot_weight(next_node);
            let mut new_path = path.clone();
            new_path.push(PathStep {
                node_id: next_node.id,
                graph_key: next_node.graph_key.clone(),
                label: next_node.label.clone(),
                node_type: next_node.node_type.clone(),
                edge_type: etype.clone(),
            });
            heap.push(HeapEntry { cost: cost + edge_cost, node: *next, path: new_path });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn n(id: i64, internet: bool, jewel: bool, cvss: f32) -> GraphNode {
        GraphNode {
            id,
            graph_key: format!("k{}", id),
            label: format!("n{}", id),
            node_type: "asset".into(),
            risk_score: 0,
            internet_exposed: internet,
            crown_jewel: jewel,
            asset_value: 1.0,
            max_finding_cvss: cvss,
            max_finding_epss: 0.0,
            kev_present: false,
        }
    }
    #[test]
    fn pivot_weight_is_lower_for_critical_kev() {
        let mut critical = n(1, false, false, 9.8);
        critical.kev_present = true;
        critical.max_finding_epss = 0.95;
        let clean = n(2, false, false, 0.0);
        assert!(node_pivot_weight(&critical) < node_pivot_weight(&clean));
    }
    #[test]
    fn dijkstra_finds_simple_path() {
        let mut nodes = HashMap::new();
        nodes.insert(1, n(1, true, false, 0.0));
        nodes.insert(2, n(2, false, false, 5.0));
        nodes.insert(3, n(3, false, true, 0.0));
        let mut adj: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
        adj.insert(1, vec![(2, "connects".into())]);
        adj.insert(2, vec![(3, "leads_to".into())]);
        let p = dijkstra_path(1, 3, &nodes, &adj).unwrap();
        assert_eq!(p.hops, 2);
        assert_eq!(p.steps.len(), 3);
        assert!(p.risk > 0.0);
    }
    #[test]
    fn dijkstra_returns_none_for_disconnected() {
        let mut nodes = HashMap::new();
        nodes.insert(1, n(1, true, false, 0.0));
        nodes.insert(2, n(2, false, true, 0.0));
        let adj: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
        assert!(dijkstra_path(1, 2, &nodes, &adj).is_none());
    }
}
