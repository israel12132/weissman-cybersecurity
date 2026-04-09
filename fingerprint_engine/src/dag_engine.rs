//! True concurrent DAG execution using petgraph. Nodes are engines; edges are dependencies.
//! Engines run the moment their prerequisites complete. No linear stages.

use petgraph::graph::DiGraph;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

pub type NodeId = String;
pub type EdgeList = Vec<(NodeId, NodeId)>;

/// Build the engine DAG: nodes = engine ids, edge A->B = B depends on A.
/// Discovery (osint, asm) has no deps; fuzzers depend on discovery; PoE depends on fuzzers; compliance last.
pub fn build_engine_dag() -> DiGraph<NodeId, ()> {
    let mut g: DiGraph<NodeId, ()> = DiGraph::new();
    let _zero_day = g.add_node("zero_day_radar".to_string());
    let osint = g.add_node("osint".to_string());
    let asm = g.add_node("asm".to_string());
    let supply = g.add_node("supply_chain".to_string());
    let leak = g.add_node("leak_hunter".to_string());
    let bola = g.add_node("bola_idor".to_string());
    let llm_path_fuzz = g.add_node("llm_path_fuzz".to_string());
    let semantic = g.add_node("semantic_ai_fuzz".to_string());
    let timing = g.add_node("microsecond_timing".to_string());
    let ai_red = g.add_node("ai_adversarial_redteam".to_string());
    let poe = g.add_node("poe_synthesis".to_string());
    let compliance = g.add_node("compliance".to_string());

    g.add_edge(osint, asm, ()); // asm can use osint subdomains
    g.add_edge(asm, supply, ());
    g.add_edge(asm, leak, ());
    g.add_edge(asm, bola, ());
    g.add_edge(asm, llm_path_fuzz, ());
    g.add_edge(asm, semantic, ());
    g.add_edge(asm, timing, ());
    g.add_edge(asm, ai_red, ());
    g.add_edge(supply, poe, ());
    g.add_edge(leak, poe, ());
    g.add_edge(bola, poe, ());
    g.add_edge(llm_path_fuzz, poe, ());
    g.add_edge(semantic, poe, ());
    g.add_edge(timing, poe, ());
    g.add_edge(ai_red, poe, ());
    g.add_edge(poe, compliance, ());
    g
}

/// Returns (nodes, edges) for UI: nodes have id and label; edges are (source_id, target_id).
pub fn dag_for_ui(g: &DiGraph<NodeId, ()>) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let nodes: Vec<(String, String)> = g.node_weights().map(|n| (n.clone(), n.clone())).collect();
    let edges: Vec<(String, String)> = g
        .edge_references()
        .map(|e| (g[e.source()].clone(), g[e.target()].clone()))
        .collect();
    (nodes, edges)
}

/// State of a single node in the DAG (for a given run_id + client_id).
#[derive(Clone, Debug, Default)]
pub struct NodeState {
    pub status: String, // "pending" | "running" | "done" | "skipped"
    pub started_at: Option<i64>,
    pub completed_at: Option<i64>,
}

/// Tracks which nodes are done so we can determine ready set. Thread-safe.
pub struct DagRunState {
    pub run_id: i64,
    pub client_id: String,
    done: Arc<RwLock<HashSet<NodeId>>>,
    running: Arc<RwLock<HashSet<NodeId>>>,
}

impl DagRunState {
    pub fn new(run_id: i64, client_id: String) -> Self {
        Self {
            run_id,
            client_id,
            done: Arc::new(RwLock::new(HashSet::new())),
            running: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub async fn mark_done(&self, node: &NodeId) {
        let mut d = self.done.write().await;
        d.insert(node.clone());
        let mut r = self.running.write().await;
        r.remove(node);
    }

    pub async fn mark_running(&self, node: &NodeId) {
        self.running.write().await.insert(node.clone());
    }

    pub async fn is_done(&self, node: &NodeId) -> bool {
        self.done.read().await.contains(node)
    }

    /// Nodes that are ready to run: all predecessors are done, self not done and not running.
    pub async fn ready_nodes(&self, g: &DiGraph<NodeId, ()>) -> Vec<NodeId> {
        let done = self.done.read().await.clone();
        let running = self.running.read().await.clone();
        let mut ready = Vec::new();
        for idx in g.node_indices() {
            let n = g[idx].clone();
            if done.contains(&n) || running.contains(&n) {
                continue;
            }
            let mut deps_done = true;
            for pred in g.neighbors_directed(idx, Direction::Incoming) {
                if !done.contains(&g[pred]) {
                    deps_done = false;
                    break;
                }
            }
            if deps_done {
                ready.push(n);
            }
        }
        ready
    }

    pub async fn all_done(&self, g: &DiGraph<NodeId, ()>) -> bool {
        let d = self.done.read().await;
        g.node_weights().all(|n| d.contains(n))
    }

    pub async fn snapshot(&self, g: &DiGraph<NodeId, ()>) -> HashMap<NodeId, NodeState> {
        let done = self.done.read().await.clone();
        let running = self.running.read().await.clone();
        g.node_weights()
            .map(|n| {
                let status = if done.contains(n) {
                    "done"
                } else if running.contains(n) {
                    "running"
                } else {
                    "pending"
                };
                (
                    n.clone(),
                    NodeState {
                        status: status.to_string(),
                        started_at: None,
                        completed_at: None,
                    },
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn dag_ready_order() {
        let g = build_engine_dag();
        let state = DagRunState::new(1, "c1".to_string());
        let ready0 = state.ready_nodes(&g).await;
        assert!(ready0.contains(&"zero_day_radar".to_string()));
        assert!(ready0.contains(&"osint".to_string()));
        state.mark_done(&"osint".to_string()).await;
        state.mark_done(&"zero_day_radar".to_string()).await;
        let ready1 = state.ready_nodes(&g).await;
        assert!(ready1.contains(&"asm".to_string()));
    }
}
