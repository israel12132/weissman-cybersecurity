//! Attack-path inference over `risk_graph_nodes` / `risk_graph_edges`.
//!
//! Dijkstra with a BinaryHeap min-queue (milli-cost fixed-point) from every
//! `internet_exposed` seed to every `crown_jewel`. Edge weights come from
//! [`crate::supreme_weights`] (KEV −0.8, EPSS linear, CVSS log, agent ×2.5).
//!
//! Output persists to `attack_path_snapshots` (including path ALE) so the
//! cockpit can render without rerunning the search.

use crate::supreme_weights::{
    self, evidence_confidence, is_cross_region, is_identity_edge, is_smb_or_port_edge,
    path_score_0_100, EdgeWeightInputs, MAX_PATH_DEPTH,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

const DEFAULT_TOP_K: usize = 25;
const CHOKE_POINT_THRESHOLD: f64 = 0.5;
const INFER_TIMEOUT: Duration = Duration::from_secs(15);
const TENANT_PATH_QUOTA: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetKind {
    Ot,
    Cloud,
    Network,
    Endpoint,
    Identity,
    Llm,
    K8s,
    Unknown,
}

impl AssetKind {
    pub fn from_node_type(t: &str) -> Self {
        match t {
            "physical_asset" | "ot" | "ics" => Self::Ot,
            "cloud_resource" | "cloud" => Self::Cloud,
            "network" => Self::Network,
            "identity" => Self::Identity,
            "k8s_cluster" | "k8s" => Self::K8s,
            "llm" | "model" => Self::Llm,
            "asset" | "endpoint" => Self::Endpoint,
            _ => Self::Unknown,
        }
    }
}

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
    #[serde(default)]
    pub agent_present: bool,
    #[serde(default)]
    pub honey_node: bool,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub age_days: f64,
    #[serde(default)]
    pub business_value_usd: i64,
    #[serde(default)]
    pub engine_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: i64,
    pub to: i64,
    pub edge_type: String,
    #[serde(default)]
    pub mitre_technique_id: String,
    #[serde(default)]
    pub age_days: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStep {
    pub node_id: i64,
    pub graph_key: String,
    pub label: String,
    pub node_type: String,
    pub edge_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub entry: i64,
    pub jewel: i64,
    pub hops: usize,
    pub cost: f64,
    pub risk: f64,
    pub kev_hops: usize,
    pub steps: Vec<PathStep>,
    #[serde(default)]
    pub path_score: u8,
    #[serde(default)]
    pub ale_usd: i64,
    #[serde(default)]
    pub root_cause: String,
    #[serde(default)]
    pub diversity: usize,
    #[serde(default)]
    pub mitre_technique_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathSnapshot {
    pub entry_count: usize,
    pub jewel_count: usize,
    pub paths: Vec<AttackPath>,
    pub choke_points: Vec<ChokePoint>,
    pub computed_at_unix: i64,
    #[serde(default)]
    pub total_path_ale_usd: i64,
    #[serde(default)]
    pub max_path_score: u8,
    #[serde(default)]
    pub graph_dirty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChokePoint {
    pub node_id: i64,
    pub graph_key: String,
    pub label: String,
    pub node_type: String,
    pub coverage: usize,
    pub coverage_pct: u8,
    pub max_finding_cvss: f32,
    pub max_finding_epss: f32,
    pub kev_present: bool,
    #[serde(default)]
    pub blast_radius_ale_usd: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WhatIfSpec {
    #[serde(default)]
    pub block_node_ids: Vec<i64>,
    #[serde(default)]
    pub block_edge_types: Vec<String>,
    #[serde(default)]
    pub block_ports: Vec<u16>,
}

struct LoadedGraph {
    nodes: HashMap<i64, GraphNode>,
    adjacency: HashMap<i64, Vec<(i64, String)>>,
    mitre: HashMap<(i64, i64), String>,
}

struct CachedGraph {
    loaded: Arc<LoadedGraph>,
    loaded_at: Instant,
    dirty: AtomicBool,
}

fn graph_cache() -> &'static DashMap<(i64, i64), Arc<RwLock<CachedGraph>>> {
    static S: OnceLock<DashMap<(i64, i64), Arc<RwLock<CachedGraph>>>> = OnceLock::new();
    S.get_or_init(DashMap::new)
}

fn path_counter() -> &'static AtomicU64 {
    static C: OnceLock<AtomicU64> = OnceLock::new();
    C.get_or_init(|| AtomicU64::new(0))
}

const GRAPH_CACHE_TTL: Duration = Duration::from_secs(30);

async fn cached_graph(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Arc<LoadedGraph>, String> {
    let key = (tenant_id, client_id);
    if let Some(entry) = graph_cache().get(&key) {
        if let Ok(g) = entry.read() {
            if !g.dirty.load(Ordering::Relaxed) && g.loaded_at.elapsed() < GRAPH_CACHE_TTL {
                return Ok(g.loaded.clone());
            }
        }
    }
    let (nodes, adjacency, mitre) = load_graph(pool, tenant_id, client_id).await?;
    let loaded = Arc::new(LoadedGraph {
        nodes,
        adjacency,
        mitre,
    });
    graph_cache().insert(
        key,
        Arc::new(RwLock::new(CachedGraph {
            loaded: loaded.clone(),
            loaded_at: Instant::now(),
            dirty: AtomicBool::new(false),
        })),
    );
    Ok(loaded)
}

/// Mark the in-memory graph dirty so the next inference reloads from Postgres.
pub fn mark_graph_dirty(tenant_id: i64, client_id: i64) {
    if let Some(entry) = graph_cache().get(&(tenant_id, client_id)) {
        if let Ok(g) = entry.read() {
            g.dirty.store(true, Ordering::Relaxed);
        }
    }
}

pub fn is_graph_dirty(tenant_id: i64, client_id: i64) -> bool {
    graph_cache()
        .get(&(tenant_id, client_id))
        .and_then(|e| e.read().ok().map(|g| g.dirty.load(Ordering::Relaxed)))
        .unwrap_or(true)
}

fn node_inputs(from: Option<&GraphNode>, to: &GraphNode, edge_type: &str) -> EdgeWeightInputs {
    let cross = match from {
        Some(f) => is_cross_region(&f.region, &to.region),
        None => false,
    };
    EdgeWeightInputs {
        cvss: to.max_finding_cvss,
        epss: to.max_finding_epss,
        kev: to.kev_present,
        agent_present: to.agent_present,
        honey_node: to.honey_node,
        age_days: to.age_days,
        cross_region: cross,
        identity_edge: is_identity_edge(edge_type),
        engine_confidence: if to.engine_confidence > 0.0 {
            to.engine_confidence
        } else {
            evidence_confidence(to.max_finding_cvss, to.max_finding_epss, to.kev_present)
        },
        ueba_zscore: 0.0,
        false_positive: false,
    }
}

fn path_ale(jewel: &GraphNode, steps: &[PathStep], nodes: &HashMap<i64, GraphNode>) -> i64 {
    let mut cvss = jewel.max_finding_cvss;
    let mut epss = jewel.max_finding_epss;
    let mut kev = jewel.kev_present;
    for s in steps {
        if let Some(n) = nodes.get(&s.node_id) {
            cvss = cvss.max(n.max_finding_cvss);
            epss = epss.max(n.max_finding_epss);
            kev = kev || n.kev_present;
        }
    }
    let value = if jewel.business_value_usd > 0 {
        jewel.business_value_usd
    } else {
        ((jewel.asset_value as f64) * 10_000.0).round() as i64
    };
    let sle = supreme_weights::single_loss_expectancy(value, cvss);
    supreme_weights::annual_loss_expectancy(
        sle,
        epss,
        kev,
        0.30,
        jewel.agent_present,
        supreme_weights::is_zero_day(cvss, epss, kev),
    )
}

fn root_cause(steps: &[PathStep], nodes: &HashMap<i64, GraphNode>) -> String {
    for s in steps {
        if let Some(n) = nodes.get(&s.node_id) {
            if n.kev_present {
                return format!("KEV on {} ({})", n.label, n.graph_key);
            }
        }
    }
    for s in steps {
        if let Some(n) = nodes.get(&s.node_id) {
            if n.max_finding_cvss >= 7.0 {
                return format!(
                    "CVSS {:.1} on {} ({})",
                    n.max_finding_cvss, n.label, n.graph_key
                );
            }
        }
    }
    steps
        .first()
        .map(|s| format!("entry {}", s.label))
        .unwrap_or_default()
}

fn first_mitre(steps: &[PathStep], edges: &HashMap<(i64, i64), String>) -> String {
    for w in steps.windows(2) {
        if let Some(m) = edges.get(&(w[0].node_id, w[1].node_id)) {
            if !m.is_empty() {
                return m.clone();
            }
        }
    }
    String::new()
}

fn finish_path(
    entry: i64,
    target: i64,
    cost_milli: i64,
    path: Vec<PathStep>,
    nodes: &HashMap<i64, GraphNode>,
    mitre_by_edge: &HashMap<(i64, i64), String>,
) -> AttackPath {
    let jewel_value = nodes.get(&target).map(|n| n.asset_value).unwrap_or(1.0) as f64;
    let cost = supreme_weights::milli_to_f64(cost_milli);
    let likelihood = (1.0 / (1.0 + cost)).clamp(0.0, 1.0);
    let risk = (likelihood * 10.0 * jewel_value.clamp(0.5, 3.0)).min(10.0);
    let kev_hops = path
        .iter()
        .filter(|s| nodes.get(&s.node_id).map(|n| n.kev_present).unwrap_or(false))
        .count();
    let jewel = nodes.get(&target);
    let score = path_score_0_100(cost, jewel.map(|n| n.asset_value).unwrap_or(1.0), kev_hops);
    let ale = jewel
        .map(|j| path_ale(j, &path, nodes))
        .unwrap_or(0);
    AttackPath {
        entry,
        jewel: target,
        hops: path.len().saturating_sub(1),
        cost,
        risk: (risk * 10.0).round() / 10.0,
        kev_hops,
        path_score: score,
        ale_usd: ale,
        root_cause: root_cause(&path, nodes),
        diversity: 0,
        mitre_technique_id: first_mitre(&path, mitre_by_edge),
        steps: path,
    }
}

/// Single-source Dijkstra from `entry` to every jewel. Milli-cost min-heap.
pub fn dijkstra_from_entry(
    entry: i64,
    jewels: &HashSet<i64>,
    nodes: &HashMap<i64, GraphNode>,
    adjacency: &HashMap<i64, Vec<(i64, String)>>,
    mitre_by_edge: &HashMap<(i64, i64), String>,
    what_if: Option<&WhatIfSpec>,
) -> Vec<AttackPath> {
    let Some(entry_node) = nodes.get(&entry) else {
        return Vec::new();
    };
    if what_if
        .map(|w| w.block_node_ids.contains(&entry))
        .unwrap_or(false)
    {
        return Vec::new();
    }
    let mut heap: BinaryHeap<Reverse<(i64, i64, usize)>> = BinaryHeap::new();
    heap.push(Reverse((0, entry, 0)));
    let mut best: HashMap<i64, i64> = HashMap::new();
    let mut prev: HashMap<i64, (i64, String)> = HashMap::new();
    best.insert(entry, 0);
    let mut remaining: HashSet<i64> = jewels.clone();
    remaining.remove(&entry);

    while let Some(Reverse((cost, node, depth))) = heap.pop() {
        if best.get(&node).is_some_and(|&b| b < cost) {
            continue;
        }
        if remaining.remove(&node) && remaining.is_empty() {
            break;
        }
        if depth >= MAX_PATH_DEPTH {
            continue;
        }
        let Some(neighbours) = adjacency.get(&node) else {
            continue;
        };
        let from = nodes.get(&node);
        for (next, etype) in neighbours {
            if what_if.map(|w| blocked(w, *next, etype)).unwrap_or(false) {
                continue;
            }
            if *next == entry {
                continue;
            }
            let Some(next_node) = nodes.get(next) else {
                continue;
            };
            if next_node.honey_node {
                continue;
            }
            let w = supreme_weights::edge_weight_milli(&node_inputs(from, next_node, etype));
            let nc = cost.saturating_add(w);
            if best.get(next).is_some_and(|&b| b <= nc) {
                continue;
            }
            best.insert(*next, nc);
            prev.insert(*next, (node, etype.clone()));
            heap.push(Reverse((nc, *next, depth + 1)));
        }
    }

    let mut out = Vec::new();
    for &jewel in jewels {
        if jewel == entry {
            continue;
        }
        let Some(&cost) = best.get(&jewel) else {
            continue;
        };
        let mut steps_rev = Vec::new();
        let mut cur = jewel;
        let mut guard = 0;
        loop {
            let n = match nodes.get(&cur) {
                Some(n) => n,
                None => break,
            };
            let etype = prev
                .get(&cur)
                .map(|(_, e)| e.clone())
                .unwrap_or_default();
            steps_rev.push(PathStep {
                node_id: n.id,
                graph_key: n.graph_key.clone(),
                label: n.label.clone(),
                node_type: n.node_type.clone(),
                edge_type: etype,
            });
            if cur == entry {
                break;
            }
            match prev.get(&cur) {
                Some((p, _)) => cur = *p,
                None => {
                    steps_rev.clear();
                    break;
                }
            }
            guard += 1;
            if guard > MAX_PATH_DEPTH + 2 {
                steps_rev.clear();
                break;
            }
        }
        if steps_rev.is_empty() {
            continue;
        }
        steps_rev.reverse();
        if steps_rev.first().map(|s| s.node_id) != Some(entry_node.id) {
            continue;
        }
        out.push(finish_path(entry, jewel, cost, steps_rev, nodes, mitre_by_edge));
    }
    out
}

fn blocked(spec: &WhatIfSpec, node_id: i64, edge_type: &str) -> bool {
    if spec.block_node_ids.contains(&node_id) {
        return true;
    }
    let et = edge_type.to_ascii_lowercase();
    if spec
        .block_edge_types
        .iter()
        .any(|b| et.contains(&b.to_ascii_lowercase()))
    {
        return true;
    }
    is_smb_or_port_edge(edge_type, &spec.block_ports)
}

fn infer_paths(
    nodes: &HashMap<i64, GraphNode>,
    adjacency: &HashMap<i64, Vec<(i64, String)>>,
    mitre_by_edge: &HashMap<(i64, i64), String>,
    top_k: usize,
    what_if: Option<&WhatIfSpec>,
) -> (Vec<AttackPath>, Vec<ChokePoint>, usize, usize) {
    let entries: Vec<i64> = nodes
        .values()
        .filter(|n| n.internet_exposed && !n.honey_node)
        .map(|n| n.id)
        .collect();
    let jewels: HashSet<i64> = nodes
        .values()
        .filter(|n| n.crown_jewel && !n.honey_node)
        .map(|n| n.id)
        .collect();
    let mut paths = Vec::new();
    if !entries.is_empty() && !jewels.is_empty() {
        for entry in &entries {
            paths.extend(dijkstra_from_entry(
                *entry,
                &jewels,
                nodes,
                adjacency,
                mitre_by_edge,
                what_if,
            ));
        }
    }
    paths.sort_by(|a, b| {
        a.cost
            .partial_cmp(&b.cost)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let quota = top_k.min(TENANT_PATH_QUOTA);
    paths.truncate(quota);
    path_counter().fetch_add(paths.len() as u64, Ordering::Relaxed);

    let mut jewel_counts: HashMap<i64, usize> = HashMap::new();
    for p in &paths {
        *jewel_counts.entry(p.jewel).or_insert(0) += 1;
    }
    for p in &mut paths {
        p.diversity = *jewel_counts.get(&p.jewel).unwrap_or(&1);
    }

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
            nodes.get(&id).map(|n| {
                let blast = blast_radius_ale(id, nodes, adjacency);
                ChokePoint {
                    node_id: id,
                    graph_key: n.graph_key.clone(),
                    label: n.label.clone(),
                    node_type: n.node_type.clone(),
                    coverage: cov,
                    coverage_pct: ((cov as f64 / paths.len().max(1) as f64) * 100.0).round() as u8,
                    max_finding_cvss: n.max_finding_cvss,
                    max_finding_epss: n.max_finding_epss,
                    kev_present: n.kev_present,
                    blast_radius_ale_usd: blast,
                }
            })
        })
        .collect();
    choke_points.sort_by(|a, b| b.coverage.cmp(&a.coverage));
    (paths, choke_points, entries.len(), jewels.len())
}

fn blast_radius_ale(
    start: i64,
    nodes: &HashMap<i64, GraphNode>,
    adjacency: &HashMap<i64, Vec<(i64, String)>>,
) -> i64 {
    let mut seen = HashSet::new();
    let mut q = vec![start];
    seen.insert(start);
    let mut hops = 0;
    while !q.is_empty() && hops < 6 {
        let mut next = Vec::new();
        for id in q {
            if let Some(nbrs) = adjacency.get(&id) {
                for (n, _) in nbrs {
                    if seen.insert(*n) {
                        next.push(*n);
                    }
                }
            }
        }
        q = next;
        hops += 1;
    }
    seen.iter()
        .filter_map(|id| nodes.get(id))
        .map(|n| {
            let v = if n.business_value_usd > 0 {
                n.business_value_usd
            } else {
                0
            };
            supreme_weights::annual_loss_expectancy(
                supreme_weights::single_loss_expectancy(v.max(1), n.max_finding_cvss),
                n.max_finding_epss,
                n.kev_present,
                0.30,
                n.agent_present,
                false,
            )
        })
        .sum()
}

fn build_snapshot(
    paths: Vec<AttackPath>,
    choke_points: Vec<ChokePoint>,
    entry_count: usize,
    jewel_count: usize,
    dirty: bool,
) -> AttackPathSnapshot {
    let total_path_ale_usd: i64 = paths.iter().map(|p| p.ale_usd).sum();
    let max_path_score = paths.iter().map(|p| p.path_score).max().unwrap_or(0);
    AttackPathSnapshot {
        entry_count,
        jewel_count,
        paths,
        choke_points,
        computed_at_unix: Utc::now().timestamp(),
        total_path_ale_usd,
        max_path_score,
        graph_dirty: dirty,
    }
}

async fn load_graph(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<(HashMap<i64, GraphNode>, HashMap<i64, Vec<(i64, String)>>, HashMap<(i64, i64), String>), String>
{
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let _ = sqlx::query("SET LOCAL statement_timeout = '15s'")
        .execute(&mut *tx)
        .await;

    let node_rows = sqlx::query(
        r#"SELECT n.id, n.graph_key, n.label, n.node_type, n.risk_score,
                  n.internet_exposed, n.crown_jewel, n.asset_value,
                  COALESCE(n.agent_present, FALSE)
                    OR EXISTS (
                        SELECT 1 FROM endpoint_agents a
                         WHERE a.tenant_id = n.tenant_id AND a.client_id = n.client_id
                           AND a.status IN ('online','enrolled')
                           AND a.revoked_at IS NULL
                           AND (lower(a.hostname) = lower(n.label)
                                OR a.hostname = COALESCE(n.external_id, ''))
                    ) AS agent_present,
                  COALESCE(n.honey_node, FALSE) AS honey_node,
                  COALESCE(n.region, '') AS region,
                  EXTRACT(EPOCH FROM (now() - COALESCE(n.last_seen, n.created_at))) / 86400.0 AS age_days,
                  COALESCE(n.business_value_usd, 0) AS business_value_usd,
                  COALESCE(n.criticality_override, n.asset_value) AS asset_value_eff,
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
        r#"SELECT from_node_id, to_node_id, edge_type,
                  COALESCE(mitre_technique_id, '') AS mitre,
                  EXTRACT(EPOCH FROM (now() - COALESCE(last_seen, created_at))) / 86400.0 AS age_days
             FROM risk_graph_edges
            WHERE tenant_id = $1 AND client_id = $2"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("load edges: {e}"))?;
    tx.commit().await.map_err(|e| format!("commit load: {e}"))?;

    let mut nodes: HashMap<i64, GraphNode> = HashMap::new();
    for r in node_rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let asset: f32 = r
            .try_get::<f32, _>("asset_value_eff")
            .or_else(|_| r.try_get("asset_value"))
            .unwrap_or(1.0);
        let n = GraphNode {
            id,
            graph_key: r.try_get("graph_key").unwrap_or_default(),
            label: r.try_get("label").unwrap_or_default(),
            node_type: r.try_get("node_type").unwrap_or_default(),
            risk_score: r.try_get("risk_score").unwrap_or(0),
            internet_exposed: r.try_get("internet_exposed").unwrap_or(false),
            crown_jewel: r.try_get("crown_jewel").unwrap_or(false),
            asset_value: asset,
            max_finding_cvss: r.try_get("max_cvss").unwrap_or(0.0),
            max_finding_epss: r.try_get("max_epss").unwrap_or(0.0),
            kev_present: r.try_get("kev").unwrap_or(false),
            agent_present: r.try_get("agent_present").unwrap_or(false),
            honey_node: r.try_get("honey_node").unwrap_or(false),
            region: r.try_get("region").unwrap_or_default(),
            age_days: r.try_get::<f64, _>("age_days").unwrap_or(0.0),
            business_value_usd: r.try_get("business_value_usd").unwrap_or(0),
            engine_confidence: 0.0,
        };
        let _ = AssetKind::from_node_type(&n.node_type);
        nodes.insert(id, n);
    }

    let mut adjacency: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
    let mut mitre_by_edge: HashMap<(i64, i64), String> = HashMap::new();
    for r in edge_rows {
        let from: i64 = r.try_get("from_node_id").unwrap_or(0);
        let to: i64 = r.try_get("to_node_id").unwrap_or(0);
        let etype: String = r.try_get("edge_type").unwrap_or_default();
        if from == 0 || to == 0 {
            continue;
        }
        if !nodes.contains_key(&from) || !nodes.contains_key(&to) {
            continue;
        }
        let age: f64 = r.try_get("age_days").unwrap_or(0.0);
        if let Some(n) = nodes.get_mut(&to) {
            n.age_days = n.age_days.max(age);
        }
        let mitre: String = r.try_get("mitre").unwrap_or_default();
        if !mitre.is_empty() {
            mitre_by_edge.insert((from, to), mitre);
        }
        adjacency.entry(from).or_default().push((to, etype));
    }
    Ok((nodes, adjacency, mitre_by_edge))
}

async fn persist_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    snapshot: &AttackPathSnapshot,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let _ = sqlx::query(
        r#"DELETE FROM attack_path_snapshots
            WHERE id IN (
                SELECT id FROM attack_path_snapshots
                 WHERE tenant_id = $1 AND client_id = $2
                   AND computed_at < now() - interval '90 days'
                 FOR UPDATE SKIP LOCKED
            )"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .execute(&mut *tx)
    .await;

    let max_risk = snapshot.paths.iter().map(|p| p.risk).fold(0_f64, f64::max);
    let paths_json: Value = serde_json::to_value(&snapshot.paths).unwrap_or(json!([]));
    let chokes_json: Value = serde_json::to_value(&snapshot.choke_points).unwrap_or(json!([]));
    sqlx::query(
        r#"INSERT INTO attack_path_snapshots
                 (tenant_id, client_id, computed_at,
                  entry_count, jewel_count, path_count, max_risk,
                  paths_json, choke_points,
                  total_path_ale_usd, max_path_score)
           VALUES ($1, $2, now(), $3, $4, $5, $6, $7, $8, $9, $10)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(snapshot.entry_count as i32)
    .bind(snapshot.jewel_count as i32)
    .bind(snapshot.paths.len() as i32)
    .bind(max_risk as f32)
    .bind(&paths_json)
    .bind(&chokes_json)
    .bind(snapshot.total_path_ale_usd)
    .bind(snapshot.max_path_score as f32)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert snapshot: {e}"))?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(())
}

/// Public entry point: compute (and persist) the top-K attack paths for a client.
pub async fn compute_and_store(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    top_k: Option<usize>,
) -> Result<AttackPathSnapshot, String> {
    let top_k = top_k.unwrap_or(DEFAULT_TOP_K).clamp(1, TENANT_PATH_QUOTA);
    let graph = cached_graph(pool, tenant_id, client_id).await?;
    let infer = tokio::task::spawn_blocking(move || {
        infer_paths(&graph.nodes, &graph.adjacency, &graph.mitre, top_k, None)
    });
    let (paths, choke, entries, jewels) = tokio::time::timeout(INFER_TIMEOUT, infer)
        .await
        .map_err(|_| "path inference timed out (15s)".to_string())?
        .map_err(|e| format!("infer join: {e}"))?;

    let snapshot = build_snapshot(paths, choke, entries, jewels, false);
    persist_snapshot(pool, tenant_id, client_id, &snapshot).await?;
    Ok(snapshot)
}

/// What-if: recompute paths with nodes / edge types / ports removed. Not persisted.
pub async fn compute_what_if(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    spec: WhatIfSpec,
    top_k: Option<usize>,
) -> Result<AttackPathSnapshot, String> {
    let top_k = top_k.unwrap_or(DEFAULT_TOP_K).clamp(1, TENANT_PATH_QUOTA);
    let graph = cached_graph(pool, tenant_id, client_id).await?;
    let infer = tokio::task::spawn_blocking(move || {
        infer_paths(
            &graph.nodes,
            &graph.adjacency,
            &graph.mitre,
            top_k,
            Some(&spec),
        )
    });
    let (paths, choke, entries, jewels) = tokio::time::timeout(INFER_TIMEOUT, infer)
        .await
        .map_err(|_| "what-if inference timed out (15s)".to_string())?
        .map_err(|e| format!("infer join: {e}"))?;
    Ok(build_snapshot(paths, choke, entries, jewels, is_graph_dirty(tenant_id, client_id)))
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
        r#"SELECT entry_count, jewel_count, paths_json, choke_points, computed_at,
                  COALESCE(total_path_ale_usd, 0) AS total_path_ale_usd,
                  COALESCE(max_path_score, 0) AS max_path_score
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
    let paths: Vec<AttackPath> =
        serde_json::from_value(r.try_get::<Value, _>("paths_json").unwrap_or(json!([])))
            .unwrap_or_default();
    let choke: Vec<ChokePoint> =
        serde_json::from_value(r.try_get::<Value, _>("choke_points").unwrap_or(json!([])))
            .unwrap_or_default();
    let computed_at: DateTime<Utc> = r
        .try_get("computed_at")
        .unwrap_or_else(|_| Utc::now());
    let total_path_ale_usd: i64 = r.try_get("total_path_ale_usd").unwrap_or(0);
    let max_path_score: f32 = r.try_get("max_path_score").unwrap_or(0.0);
    Ok(Some(AttackPathSnapshot {
        entry_count: r.try_get::<i32, _>("entry_count").unwrap_or(0) as usize,
        jewel_count: r.try_get::<i32, _>("jewel_count").unwrap_or(0) as usize,
        paths,
        choke_points: choke,
        computed_at_unix: computed_at.timestamp(),
        total_path_ale_usd,
        max_path_score: max_path_score.round() as u8,
        graph_dirty: is_graph_dirty(tenant_id, client_id),
    }))
}

/// Pairwise Dijkstra kept for unit tests / callers that want a single target.
pub fn dijkstra_path(
    entry: i64,
    target: i64,
    nodes: &HashMap<i64, GraphNode>,
    adjacency: &HashMap<i64, Vec<(i64, String)>>,
) -> Option<AttackPath> {
    let mut jewels = HashSet::new();
    jewels.insert(target);
    dijkstra_from_entry(entry, &jewels, nodes, adjacency, &HashMap::new(), None)
        .into_iter()
        .next()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(id: i64, internet: bool, jewel: bool, cvss: f32) -> GraphNode {
        GraphNode {
            id,
            graph_key: format!("k{id}"),
            label: format!("n{id}"),
            node_type: "asset".into(),
            risk_score: 0,
            internet_exposed: internet,
            crown_jewel: jewel,
            asset_value: 1.0,
            max_finding_cvss: cvss,
            max_finding_epss: 0.0,
            kev_present: false,
            agent_present: false,
            honey_node: false,
            region: String::new(),
            age_days: 0.0,
            business_value_usd: 10_000,
            engine_confidence: 1.0,
        }
    }

    #[test]
    fn pivot_weight_is_lower_for_critical_kev() {
        let mut critical = n(1, false, false, 9.8);
        critical.kev_present = true;
        critical.max_finding_epss = 0.95;
        let clean = n(2, false, false, 0.0);
        let w_crit = supreme_weights::edge_weight_milli(&node_inputs(None, &critical, "connects"));
        let w_clean = supreme_weights::edge_weight_milli(&node_inputs(None, &clean, "connects"));
        assert!(w_crit < w_clean);
    }

    #[test]
    fn agent_makes_pivot_harder() {
        let open = n(1, false, false, 7.0);
        let mut guarded = open.clone();
        guarded.agent_present = true;
        let a = supreme_weights::edge_weight_milli(&node_inputs(None, &open, "connects"));
        let b = supreme_weights::edge_weight_milli(&node_inputs(None, &guarded, "connects"));
        assert!(b > a);
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
        assert!(p.path_score > 0);
        assert!(!p.root_cause.is_empty());
    }

    #[test]
    fn dijkstra_returns_none_for_disconnected() {
        let mut nodes = HashMap::new();
        nodes.insert(1, n(1, true, false, 0.0));
        nodes.insert(2, n(2, false, true, 0.0));
        let adj: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
        assert!(dijkstra_path(1, 2, &nodes, &adj).is_none());
    }

    #[test]
    fn what_if_blocking_middle_kills_path() {
        let mut nodes = HashMap::new();
        nodes.insert(1, n(1, true, false, 0.0));
        nodes.insert(2, n(2, false, false, 5.0));
        nodes.insert(3, n(3, false, true, 0.0));
        let mut adj: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
        adj.insert(1, vec![(2, "connects".into())]);
        adj.insert(2, vec![(3, "leads_to".into())]);
        let mut jewels = HashSet::new();
        jewels.insert(3);
        let spec = WhatIfSpec {
            block_node_ids: vec![2],
            ..Default::default()
        };
        let paths = dijkstra_from_entry(1, &jewels, &nodes, &adj, &HashMap::new(), Some(&spec));
        assert!(paths.is_empty());
    }

    #[test]
    fn what_if_block_smb_port() {
        let mut nodes = HashMap::new();
        nodes.insert(1, n(1, true, false, 0.0));
        nodes.insert(2, n(2, false, true, 9.0));
        let mut adj: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
        adj.insert(1, vec![(2, "smb".into())]);
        let mut jewels = HashSet::new();
        jewels.insert(2);
        let spec = WhatIfSpec {
            block_ports: vec![445],
            ..Default::default()
        };
        let paths = dijkstra_from_entry(1, &jewels, &nodes, &adj, &HashMap::new(), Some(&spec));
        assert!(paths.is_empty());
        let open = dijkstra_from_entry(1, &jewels, &nodes, &adj, &HashMap::new(), None);
        assert_eq!(open.len(), 1);
    }

    #[test]
    fn honey_node_is_skipped_as_jewel() {
        let mut nodes = HashMap::new();
        nodes.insert(1, n(1, true, false, 0.0));
        let mut decoy = n(2, false, true, 9.0);
        decoy.honey_node = true;
        nodes.insert(2, decoy);
        let mut adj: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
        adj.insert(1, vec![(2, "connects".into())]);
        let (paths, _, _, jewels) = infer_paths(&nodes, &adj, &HashMap::new(), 10, None);
        assert_eq!(jewels, 0);
        assert!(paths.is_empty());
    }

    #[test]
    fn kev_path_outranks_clean_alternate() {
        let mut nodes = HashMap::new();
        nodes.insert(1, n(1, true, false, 0.0));
        let mut kev_hop = n(2, false, false, 9.8);
        kev_hop.kev_present = true;
        kev_hop.max_finding_epss = 0.9;
        nodes.insert(2, kev_hop);
        nodes.insert(3, n(3, false, false, 1.0));
        nodes.insert(4, n(4, false, true, 0.0));
        let mut adj: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
        adj.insert(1, vec![(2, "a".into()), (3, "b".into())]);
        adj.insert(2, vec![(4, "a".into())]);
        adj.insert(3, vec![(4, "b".into())]);
        let p = dijkstra_path(1, 4, &nodes, &adj).unwrap();
        assert_eq!(p.steps[1].node_id, 2, "KEV hop should be preferred");
        assert!(p.kev_hops >= 1);
    }

    #[test]
    fn choke_and_diversity() {
        let mut nodes = HashMap::new();
        nodes.insert(1, n(1, true, false, 0.0));
        nodes.insert(2, n(2, true, false, 0.0));
        nodes.insert(9, n(9, false, false, 5.0));
        nodes.insert(3, n(3, false, true, 0.0));
        let mut adj: HashMap<i64, Vec<(i64, String)>> = HashMap::new();
        adj.insert(1, vec![(9, "c".into())]);
        adj.insert(2, vec![(9, "c".into())]);
        adj.insert(9, vec![(3, "c".into())]);
        let (paths, choke, entries, jewels) = infer_paths(&nodes, &adj, &HashMap::new(), 10, None);
        assert_eq!(entries, 2);
        assert_eq!(jewels, 1);
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().all(|p| p.diversity == 2));
        assert!(choke.iter().any(|c| c.node_id == 9));
    }
}
