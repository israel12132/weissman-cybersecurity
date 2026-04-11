//! Common JSON result type for all SOC engines. Output to stdout for Python to parse.
//! Module 3: optional graph_nodes/graph_edges for Attack Surface Graph.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EngineResult {
    pub status: String,
    pub findings: Vec<serde_json::Value>,
    pub message: String,
    /// Helper for compatibility: indicates success based on status
    #[serde(skip_serializing)]
    pub success: bool,
    /// Helper for compatibility: summary string (same as message)
    #[serde(skip_serializing)]
    pub summary: String,
    /// Module 3: nodes for Attack Surface Graph (ASM/cloud_hunter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_nodes: Option<Vec<super::cloud_hunter::GraphNode>>,
    /// Module 3: edges for Attack Surface Graph.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_edges: Option<Vec<super::cloud_hunter::GraphEdge>>,
}

impl EngineResult {
    pub fn ok(findings: Vec<serde_json::Value>, message: impl Into<String>) -> Self {
        let msg = message.into();
        Self {
            status: "ok".to_string(),
            findings,
            message: msg.clone(),
            success: true,
            summary: msg,
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
        let msg = message.into();
        Self {
            status: "ok".to_string(),
            findings,
            message: msg.clone(),
            success: true,
            summary: msg,
            graph_nodes: Some(graph_nodes),
            graph_edges: Some(graph_edges),
        }
    }
    pub fn error(message: impl Into<String>) -> Self {
        let msg = message.into();
        Self {
            status: "error".to_string(),
            findings: vec![],
            message: msg.clone(),
            success: false,
            summary: msg,
            graph_nodes: None,
            graph_edges: None,
        }
    }
}

impl From<weissman_engines::EngineResult> for EngineResult {
    fn from(r: weissman_engines::EngineResult) -> Self {
        let is_ok = r.status == "ok";
        Self {
            status: r.status,
            findings: r.findings,
            message: r.message.clone(),
            success: is_ok,
            summary: r.message,
            graph_nodes: None,
            graph_edges: None,
        }
    }
}

impl From<Vec<serde_json::Value>> for EngineResult {
    fn from(findings: Vec<serde_json::Value>) -> Self {
        let msg = format!("Generated {} findings", findings.len());
        Self {
            status: "ok".to_string(),
            findings,
            message: msg.clone(),
            success: true,
            summary: msg,
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
