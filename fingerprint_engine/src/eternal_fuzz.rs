//! **Genesis — Eternal Fuzz**: lazy attack-graph DFS with RAM-based **Hibernation Protocol**
//! (state offload to `genesis_suspended_graphs`) and resumption.
//!
//! Depth / step caps are **unclamped** from env (`usize::MAX` allowed). Primary guard is RSS vs
//! `WEISSMAN_GENESIS_RAM_BUDGET_MB` (soft limit at 85%). Optional fuse: `WEISSMAN_GENESIS_DFS_MAX_STEPS`.
//!
//! The DFS itself does **not** call the LLM; it expands a synthetic attack graph from seeds.
//! The `genesis_eternal_fuzz` async job then optionally runs **council synthesis** ([`crate::council_synthesis::run_genesis_war_room`]),
//! which consults the tenant `llm_base_url` (OpenAI-compatible / local Qwen) and mirrors proposer/critic/bypass/vaccine JSON to the CEO war room.

use crate::ceo::strategy::GenesisRuntimeParams;
use petgraph::graph::Graph;
use petgraph::graph::NodeIndex;
use petgraph::Direction;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use tracing::warn;

#[must_use]
pub fn genesis_protocol_enabled() -> bool {
    matches!(
        std::env::var("WEISSMAN_GENESIS_PROTOCOL").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// No artificial upper bound; unset defaults to `8`. Parse `usize::MAX` from env if desired.
#[must_use]
pub fn genesis_dfs_max_depth() -> usize {
    std::env::var("WEISSMAN_GENESIS_DFS_MAX_DEPTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
}

/// Optional step fuse only (`usize::MAX` when unset — RAM hibernation is the main brake).
#[must_use]
pub fn genesis_dfs_max_steps_fuse() -> usize {
    std::env::var("WEISSMAN_GENESIS_DFS_MAX_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(usize::MAX)
}

/// RAM budget for this process (bytes). Default 4 GiB when unset.
#[must_use]
pub fn genesis_ram_budget_bytes() -> u64 {
    let mb = std::env::var("WEISSMAN_GENESIS_RAM_BUDGET_MB")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(4096)
        .max(64);
    mb.saturating_mul(1024 * 1024)
}

/// Soft limit: 85% of budget.
#[must_use]
pub fn genesis_ram_soft_limit_bytes() -> u64 {
    genesis_ram_budget_bytes().saturating_mul(85) / 100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimFeedbackStep {
    pub stage: String,
    pub outcome: String,
    pub pivot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GraphSnapshot {
    nodes: Vec<String>,
    edges: Vec<(usize, usize, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StackFrameSer {
    node_index: usize,
    path: Vec<String>,
}

fn load_seed_strings() -> Vec<String> {
    load_seed_strings_from_params(&crate::ceo::strategy::load_env_fallback())
}

/// Seeds from DB-backed CEO strategy (newline/comma separated per channel).
pub fn load_seed_strings_from_params(p: &GenesisRuntimeParams) -> Vec<String> {
    let mut out = Vec::new();
    for (key, raw) in [
        ("WEISSMAN_GENESIS_SEED_REPOS", p.seed_repos.as_str()),
        ("WEISSMAN_GENESIS_SEED_NPM", p.seed_npm.as_str()),
        ("WEISSMAN_GENESIS_SEED_CRATES", p.seed_crates.as_str()),
        ("WEISSMAN_GENESIS_SEED_PYPI", p.seed_pypi.as_str()),
        ("WEISSMAN_GENESIS_SEED_IMAGES", p.seed_images.as_str()),
    ] {
        for part in raw.split(|c| c == ',' || c == '\n') {
            let s = part.trim();
            if !s.is_empty() {
                out.push(format!("{key}:{s}"));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

const CHAIN_VECTORS: &[&str] = &[
    "memory_pressure",
    "memory_leak",
    "info_disclosure",
    "auth_weakness",
    "auth_bypass",
    "privilege_escalation",
    "rce_primitive",
];

const RAM_CHECK_INTERVAL: usize = 256;

pub fn build_roots_only(seeds: &[String]) -> (Graph<String, String>, Vec<NodeIndex>) {
    let mut g = Graph::new();
    let mut roots = Vec::new();
    for seed in seeds {
        let root = g.add_node(seed.clone());
        roots.push(root);
    }
    (g, roots)
}

fn ensure_single_child(
    g: &mut Graph<String, String>,
    parent: NodeIndex,
    depth: usize,
    max_depth: usize,
    seed_key: &str,
) -> Option<NodeIndex> {
    if depth >= max_depth {
        return None;
    }
    let outs: Vec<NodeIndex> = g.neighbors_directed(parent, Direction::Outgoing).collect();
    if let Some(c) = outs.first().copied() {
        return Some(c);
    }
    let v = CHAIN_VECTORS[depth % CHAIN_VECTORS.len()];
    let label = format!("{seed_key}>>{v}@d{depth}");
    let child = g.add_node(label);
    g.add_edge(parent, child, v.to_string());
    Some(child)
}

fn snapshot_graph(g: &Graph<String, String>) -> GraphSnapshot {
    let n = g.node_count();
    let mut nodes = vec![String::new(); n];
    for i in g.node_indices() {
        let idx = i.index();
        if idx < nodes.len() {
            nodes[idx] = g[i].clone();
        }
    }
    let mut edges = Vec::new();
    for e in g.edge_indices() {
        if let Some((a, b)) = g.edge_endpoints(e) {
            edges.push((a.index(), b.index(), g[e].clone()));
        }
    }
    GraphSnapshot { nodes, edges }
}

fn graph_from_snapshot(s: &GraphSnapshot) -> Result<Graph<String, String>, String> {
    let mut g = Graph::new();
    for node_label in &s.nodes {
        g.add_node(node_label.clone());
    }
    for (a, b, w) in &s.edges {
        let na = NodeIndex::new(*a);
        let nb = NodeIndex::new(*b);
        if na.index() >= g.node_count() || nb.index() >= g.node_count() {
            return Err("edge endpoint out of range".into());
        }
        g.add_edge(na, nb, w.clone());
    }
    Ok(g)
}

fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
                return Some(kb.saturating_mul(1024));
            }
        }
    }
    None
}

fn should_hibernate(soft_limit: u64) -> bool {
    process_rss_bytes()
        .map(|rss| rss >= soft_limit)
        .unwrap_or(false)
}

pub struct DfsRunOutcome {
    pub json: Value,
    pub suspended_id: Option<i64>,
}

/// Lazy DFS with RAM hibernation + optional resume row. Strategy comes from `params` (DB + env fallback).
pub async fn run_eternal_fuzz_cycle_with_hibernation(
    pool: &PgPool,
    tenant_id: i64,
    resume_suspended_id: Option<i64>,
    params: &GenesisRuntimeParams,
) -> Result<DfsRunOutcome, sqlx::Error> {
    if !params.protocol_enabled {
        return Ok(DfsRunOutcome {
            json: json!({ "enabled": false, "source": "genesis_protocol_disabled" }),
            suspended_id: None,
        });
    }

    let env_seeds = load_seed_strings_from_params(params);
    if env_seeds.is_empty() && resume_suspended_id.is_none() {
        return Ok(DfsRunOutcome {
            json: json!({
                "enabled": true,
                "seeds": 0,
                "message": "configure genesis_seed_* via PATCH /api/ceo/strategy or WEISSMAN_GENESIS_SEED_* env",
            }),
            suspended_id: None,
        });
    }

    let max_steps = params.dfs_max_steps;
    let soft_limit = params.ram_soft_limit_bytes();
    let budget = params.ram_budget_bytes();

    let suspended_row_id = resume_suspended_id;

    let (
        mut g,
        seeds_ref,
        mut root_index,
        mut stack,
        mut paths_found,
        mut visited,
        mut steps,
        max_depth,
    ) = if let Some(sid) = resume_suspended_id {
        let row = sqlx::query(
            r#"SELECT graph_snapshot, dfs_stack, visited_nodes, seeds_json, max_depth, root_index, paths_found_json
               FROM genesis_suspended_graphs
               WHERE id = $1 AND tenant_id = $2 AND status IN ('suspended', 'resumed')"#,
        )
        .bind(sid)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

        let Some(r) = row else {
            return Ok(DfsRunOutcome {
                json: json!({
                    "enabled": true,
                    "error": "resume row not found or not resumable",
                    "resume_suspended_id": sid,
                }),
                suspended_id: None,
            });
        };

        let snap_v: Value = r.try_get("graph_snapshot")?;
        let stack_v: Value = r.try_get("dfs_stack")?;
        let visited_v: Value = r.try_get("visited_nodes")?;
        let seeds_v: Value = r.try_get("seeds_json")?;
        let max_depth: usize = r
            .try_get::<i64, _>("max_depth")
            .ok()
            .map(|d| d.max(1) as usize)
            .unwrap_or(params.dfs_max_depth);
        let ri: i64 = r.try_get("root_index")?;
        let paths_v: Value = r.try_get("paths_found_json")?;

        let snap: GraphSnapshot = match serde_json::from_value(snap_v) {
            Ok(s) => s,
            Err(e) => {
                return Ok(DfsRunOutcome {
                    json: json!({ "enabled": true, "error": format!("graph_snapshot: {e}") }),
                    suspended_id: None,
                });
            }
        };
        let g = match graph_from_snapshot(&snap) {
            Ok(g) => g,
            Err(msg) => {
                return Ok(DfsRunOutcome {
                    json: json!({ "enabled": true, "error": msg }),
                    suspended_id: None,
                });
            }
        };
        let frames: Vec<StackFrameSer> = match serde_json::from_value(stack_v) {
            Ok(f) => f,
            Err(e) => {
                return Ok(DfsRunOutcome {
                    json: json!({ "enabled": true, "error": format!("dfs_stack: {e}") }),
                    suspended_id: None,
                });
            }
        };
        let mut stack = Vec::new();
        for f in frames {
            stack.push((NodeIndex::new(f.node_index), f.path));
        }
        let visited_list: Vec<usize> = serde_json::from_value(visited_v).unwrap_or_default();
        let visited: HashSet<usize> = visited_list.into_iter().collect();
        let mut loaded_seeds: Vec<String> = serde_json::from_value(seeds_v).unwrap_or_default();
        if loaded_seeds.is_empty() {
            loaded_seeds = env_seeds.clone();
        } else if !env_seeds.is_empty() && loaded_seeds != env_seeds {
            warn!(target: "eternal_fuzz", "resume seeds differ from env; using stored seeds");
        }
        let paths_found: Vec<Vec<String>> = serde_json::from_value(paths_v).unwrap_or_default();

        sqlx::query(
            "UPDATE genesis_suspended_graphs SET status = 'resumed', updated_at = now() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(sid)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        (
            g,
            loaded_seeds,
            ri as usize,
            stack,
            paths_found,
            visited,
            0usize,
            max_depth,
        )
    } else {
        let max_depth = params.dfs_max_depth;
        let (g, _) = build_roots_only(&env_seeds);
        (
            g,
            env_seeds.clone(),
            0usize,
            Vec::new(),
            Vec::<Vec<String>>::new(),
            HashSet::new(),
            0usize,
            max_depth,
        )
    };

    let nroots = seeds_ref.len();
    if nroots == 0 {
        return Ok(DfsRunOutcome {
            json: json!({ "enabled": true, "error": "no seeds" }),
            suspended_id: None,
        });
    }

    let roots: Vec<NodeIndex> = (0..nroots).map(NodeIndex::new).collect();
    for (i, &exp) in roots.iter().enumerate() {
        if exp.index() >= g.node_count() {
            return Ok(DfsRunOutcome {
                json: json!({
                    "enabled": true,
                    "error": format!("graph missing root node index {i}"),
                }),
                suspended_id: None,
            });
        }
    }

    if root_index >= nroots {
        let longest = paths_found.iter().max_by_key(|p| p.len()).cloned().unwrap_or_default();
        let fp = tech_fingerprint_for_chain(&longest);
        let feedback = synthesize_feedback_from_path(&longest);
        if let Some(sid) = suspended_row_id {
            sqlx::query(
                "UPDATE genesis_suspended_graphs SET status = 'completed', updated_at = now() WHERE id = $1 AND tenant_id = $2",
            )
            .bind(sid)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        }
        return Ok(DfsRunOutcome {
            json: json!({
                "enabled": true,
                "nodes": g.node_count(),
                "edges": g.edge_count(),
                "paths_found": paths_found.len(),
                "longest_chain": longest,
                "tech_fingerprint": fp,
                "simulation_feedback": serde_json::to_value(&feedback).unwrap_or(json!([])),
                "component_ref": seeds_ref.first().cloned().unwrap_or_default(),
                "hibernation": false,
                "completed": true,
                "rss_soft_limit_bytes": soft_limit,
                "ram_budget_bytes": budget,
            }),
            suspended_id: None,
        });
    }

    if stack.is_empty() {
        let r = roots[root_index];
        stack.push((r, vec![g[r].clone()]));
    }

    let mut ram_checks = 0usize;
    let mut pending_hibernate = false;

    'roots: while root_index < nroots {
        while let Some((node, path)) = stack.pop() {
            steps += 1;
            if steps > max_steps {
                pending_hibernate = true;
                stack.push((node, path));
                break 'roots;
            }

            ram_checks += 1;
            if ram_checks >= RAM_CHECK_INTERVAL {
                ram_checks = 0;
                if should_hibernate(soft_limit) {
                    pending_hibernate = true;
                    stack.push((node, path));
                    break 'roots;
                }
            }

            visited.insert(node.index());
            let depth = path.len().saturating_sub(1);
            let seed_key = seeds_ref.get(root_index).map(String::as_str).unwrap_or("");

            match ensure_single_child(&mut g, node, depth, max_depth, seed_key) {
                None => {
                    paths_found.push(path);
                }
                Some(child) => {
                    let Some(e) = g.find_edge(node, child) else {
                        continue;
                    };
                    let lbl = g[e].clone();
                    let mut p2 = path.clone();
                    p2.push(format!("{}→{}", lbl, g[child]));
                    stack.push((child, p2));
                }
            }
        }

        root_index += 1;
        if root_index < nroots {
            let r = roots[root_index];
            stack.push((r, vec![g[r].clone()]));
        }
    }

    if pending_hibernate {
        let snap = snapshot_graph(&g);
        let stack_ser: Vec<StackFrameSer> = stack
            .iter()
            .map(|(n, p)| StackFrameSer {
                node_index: n.index(),
                path: p.clone(),
            })
            .collect();
        let visited_v: Vec<usize> = visited.iter().copied().collect();

        let graph_json = serde_json::to_value(&snap).unwrap_or(json!({}));
        let stack_json = serde_json::to_value(&stack_ser).unwrap_or(json!([]));
        let visited_json = serde_json::to_value(&visited_v).unwrap_or(json!([]));
        let seeds_json = serde_json::to_value(&seeds_ref).unwrap_or(json!([]));
        let paths_json = serde_json::to_value(&paths_found).unwrap_or(json!([]));

        let sid = if let Some(existing) = suspended_row_id {
            sqlx::query(
                r#"UPDATE genesis_suspended_graphs SET
                    graph_snapshot = $1, dfs_stack = $2, visited_nodes = $3,
                    seeds_json = $4, max_depth = $5, root_index = $6, paths_found_json = $7,
                    ram_budget_bytes = $8, status = 'suspended', updated_at = now()
                   WHERE id = $9 AND tenant_id = $10"#,
            )
            .bind(&graph_json)
            .bind(&stack_json)
            .bind(&visited_json)
            .bind(&seeds_json)
            .bind(max_depth as i64)
            .bind(root_index as i64)
            .bind(&paths_json)
            .bind(budget as i64)
            .bind(existing)
            .bind(tenant_id)
            .execute(pool)
            .await?;
            existing
        } else {
            sqlx::query_scalar(
                r#"INSERT INTO genesis_suspended_graphs (
                    tenant_id, graph_snapshot, dfs_stack, visited_nodes, seeds_json,
                    max_depth, root_index, paths_found_json, ram_budget_bytes, status
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'suspended')
                RETURNING id"#,
            )
            .bind(tenant_id)
            .bind(&graph_json)
            .bind(&stack_json)
            .bind(&visited_json)
            .bind(&seeds_json)
            .bind(max_depth as i64)
            .bind(root_index as i64)
            .bind(&paths_json)
            .bind(budget as i64)
            .fetch_one(pool)
            .await?
        };

        let rss = process_rss_bytes();
        return Ok(DfsRunOutcome {
            json: json!({
                "enabled": true,
                "hibernation": true,
                "suspended_id": sid,
                "paths_found_partial": paths_found.len(),
                "nodes": g.node_count(),
                "edges": g.edge_count(),
                "root_index": root_index,
                "stack_depth": stack_ser.len(),
                "rss_bytes": rss,
                "rss_soft_limit_bytes": soft_limit,
                "ram_budget_bytes": budget,
                "steps_this_slice": steps,
                "message": "state offloaded to genesis_suspended_graphs; enqueue genesis_eternal_fuzz with resume_suspended_id",
            }),
            suspended_id: Some(sid),
        });
    }

    let longest = paths_found.iter().max_by_key(|p| p.len()).cloned().unwrap_or_default();
    let fp = tech_fingerprint_for_chain(&longest);
    let feedback = synthesize_feedback_from_path(&longest);

    if let Some(sid) = suspended_row_id {
        sqlx::query(
            "UPDATE genesis_suspended_graphs SET status = 'completed', updated_at = now() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(sid)
        .bind(tenant_id)
        .execute(pool)
        .await?;
    }

    Ok(DfsRunOutcome {
        json: json!({
            "enabled": true,
            "nodes": g.node_count(),
            "edges": g.edge_count(),
            "paths_found": paths_found.len(),
            "longest_chain": longest,
            "tech_fingerprint": fp,
            "simulation_feedback": serde_json::to_value(&feedback).unwrap_or(json!([])),
            "component_ref": seeds_ref.first().cloned().unwrap_or_default(),
            "hibernation": false,
            "completed": true,
            "rss_soft_limit_bytes": soft_limit,
            "ram_budget_bytes": budget,
            "steps_this_slice": steps,
        }),
        suspended_id: None,
    })
}

#[must_use]
pub fn tech_fingerprint_for_chain(path: &[String]) -> String {
    let joined = path.join("|");
    let h = Sha256::digest(joined.as_bytes());
    hex::encode(h)
}

pub fn synthesize_feedback_from_path(path: &[String]) -> Vec<SimFeedbackStep> {
    let mut fb = Vec::new();
    for (i, step) in path.iter().enumerate() {
        let failure_first = i % 3 != 0;
        fb.push(SimFeedbackStep {
            stage: step.chars().take(512).collect(),
            outcome: if failure_first {
                "simulated_failure".into()
            } else {
                "simulated_success".into()
            },
            pivot: if failure_first {
                "internal_simulation_retry_encoding".into()
            } else {
                "chain_advances".into()
            },
        });
    }
    fb
}

#[must_use]
pub fn run_eternal_fuzz_cycle_json() -> Value {
    if !genesis_protocol_enabled() {
        return json!({ "enabled": false });
    }
    let seeds = load_seed_strings();
    if seeds.is_empty() {
        return json!({
            "enabled": true,
            "seeds": 0,
            "message": "set WEISSMAN_GENESIS_SEED_REPOS or other WEISSMAN_GENESIS_SEED_* lists",
        });
    }
    let max_depth = genesis_dfs_max_depth();
    let max_steps = genesis_dfs_max_steps_fuse();
    let soft = genesis_ram_soft_limit_bytes();
    let (mut g, roots) = build_roots_only(&seeds);
    let mut paths_found = Vec::new();
    let mut visited = HashSet::new();
    let mut steps = 0usize;
    let mut root_index = 0usize;
    let mut stack: Vec<(NodeIndex, Vec<String>)> = Vec::new();
    if !roots.is_empty() {
        let r = roots[0];
        stack.push((r, vec![g[r].clone()]));
    }
    let nroots = roots.len();

    'roots: while root_index < nroots {
        while let Some((node, path)) = stack.pop() {
            steps += 1;
            if steps > max_steps {
                stack.push((node, path));
                break 'roots;
            }
            if steps % RAM_CHECK_INTERVAL == 0 && should_hibernate(soft) {
                stack.push((node, path));
                break 'roots;
            }
            visited.insert(node.index());
            let depth = path.len().saturating_sub(1);
            let seed_key = seeds.get(root_index).map(String::as_str).unwrap_or("");
            match ensure_single_child(&mut g, node, depth, max_depth, seed_key) {
                None => paths_found.push(path),
                Some(child) => {
                    let Some(e) = g.find_edge(node, child) else {
                        continue;
                    };
                    let lbl = g[e].clone();
                    let mut p2 = path.clone();
                    p2.push(format!("{}→{}", lbl, g[child]));
                    stack.push((child, p2));
                }
            }
        }
        root_index += 1;
        if root_index < nroots {
            let r = roots[root_index];
            stack.push((r, vec![g[r].clone()]));
        }
    }

    let longest = paths_found.iter().max_by_key(|p| p.len()).cloned().unwrap_or_default();
    let fp = tech_fingerprint_for_chain(&longest);
    let feedback = synthesize_feedback_from_path(&longest);
    let truncated = !stack.is_empty() || root_index < nroots;
    json!({
        "enabled": true,
        "nodes": g.node_count(),
        "edges": g.edge_count(),
        "paths_found": paths_found.len(),
        "longest_chain": longest,
        "tech_fingerprint": fp,
        "simulation_feedback": serde_json::to_value(&feedback).unwrap_or(json!([])),
        "component_ref": seeds.first().cloned().unwrap_or_default(),
        "sync_truncated": truncated,
        "note": "use async run_eternal_fuzz_cycle_with_hibernation for DB offload + resume",
    })
}

#[must_use]
pub fn unique_seed_targets() -> HashSet<String> {
    load_seed_strings().into_iter().collect()
}
