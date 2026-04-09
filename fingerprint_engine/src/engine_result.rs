//! Common JSON result type for all SOC engines. Output to stdout for Python to parse.
//! Module 3: optional graph_nodes/graph_edges for Attack Surface Graph.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EngineResult {
    pub status: String,
    pub findings: Vec<serde_json::Value>,
    pub message: String,
    /// Module 3: nodes for Attack Surface Graph (ASM/cloud_hunter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_nodes: Option<Vec<super::cloud_hunter::GraphNode>>,
    /// Module 3: edges for Attack Surface Graph.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_edges: Option<Vec<super::cloud_hunter::GraphEdge>>,
}

impl EngineResult {
    pub fn ok(findings: Vec<serde_json::Value>, message: impl Into<String>) -> Self {
        Self {
            status: "ok".to_string(),
            findings,
            message: message.into(),
            graph_nodes: None,
            graph_edges: None,
        }
    }
    pub fn ok_with_graph(
        findings: Vec<serde_json::Value>,
        message: impl Into<String>,
        graph_nodes: Vec<super::cloud_hunter::GraphNode>,
        graph_edges: Vec<super::cloud_hunter::GraphEdge>,
    ) -> Self {
        Self {
            status: "ok".to_string(),
            findings,
            message: message.into(),
            graph_nodes: Some(graph_nodes),
            graph_edges: Some(graph_edges),
        }
    }
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "error".to_string(),
            findings: vec![],
            message: message.into(),
            graph_nodes: None,
            graph_edges: None,
        }
    }
}

impl From<weissman_engines::EngineResult> for EngineResult {
    fn from(r: weissman_engines::EngineResult) -> Self {
        Self {
            status: r.status,
            findings: r.findings,
            message: r.message,
            graph_nodes: None,
            graph_edges: None,
        }
    }
}

pub fn print_result(r: EngineResult) {
    if let Ok(s) = serde_json::to_string(&r) {
        println!("{}", s);
    } else {
        println!("{{\"status\":\"error\",\"findings\":[],\"message\":\"serialize failed\"}}");
    }
}
