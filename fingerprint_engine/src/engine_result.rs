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
    /// Honest RoE fail-closed flag. Never set on a successful or empty-looking ICS scan.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub roe_blocked: bool,
    /// Structured RoE payload (`control`, `never_auto_enabled`, enable path). Absent when the engine ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roe: Option<serde_json::Value>,
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
            roe_blocked: false,
            roe: None,
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
            roe_blocked: false,
            roe: None,
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
            roe_blocked: false,
            roe: None,
        }
    }

    /// Structured RoE block: no findings, `status=roe_blocked`, never looks like a completed empty scan.
    pub fn roe_blocked(message: impl Into<String>, roe: serde_json::Value) -> Self {
        let msg = message.into();
        Self {
            status: "roe_blocked".to_string(),
            findings: vec![],
            message: msg.clone(),
            success: false,
            summary: msg,
            graph_nodes: None,
            graph_edges: None,
            roe_blocked: true,
            roe: Some(roe),
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
            roe_blocked: false,
            roe: None,
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
            roe_blocked: false,
            roe: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_result_sets_success_and_summary() {
        let r = EngineResult::ok(vec![serde_json::json!({"f": 1})], "done");
        assert_eq!(r.status, "ok");
        assert!(r.success);
        assert_eq!(r.summary, "done");
        assert_eq!(r.message, "done");
        assert_eq!(r.findings.len(), 1);
        assert!(r.graph_nodes.is_none());
        assert!(r.graph_edges.is_none());
    }

    #[test]
    fn error_result_has_no_findings_and_not_success() {
        let r = EngineResult::error("boom");
        assert_eq!(r.status, "error");
        assert!(!r.success);
        assert!(r.findings.is_empty());
        assert_eq!(r.summary, "boom");
    }

    #[test]
    fn from_findings_vec_reports_count() {
        let r: EngineResult = vec![serde_json::json!(1), serde_json::json!(2)].into();
        assert_eq!(r.status, "ok");
        assert!(r.success);
        assert_eq!(r.message, "Generated 2 findings");
    }

    #[test]
    fn from_engines_result_maps_status_to_success() {
        let ok: EngineResult = weissman_engines::EngineResult::ok(vec![], "hi").into();
        assert!(ok.success);
        assert_eq!(ok.status, "ok");
        let err: EngineResult = weissman_engines::EngineResult::error("nope").into();
        assert!(!err.success);
        assert_eq!(err.status, "error");
    }

    #[test]
    fn serialization_skips_helper_and_none_graph_fields() {
        let r = EngineResult::ok(vec![], "m");
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("status"));
        assert!(obj.contains_key("findings"));
        assert!(obj.contains_key("message"));
        // success/summary are #[serde(skip_serializing)]; graph_* skipped when None.
        assert!(!obj.contains_key("success"));
        assert!(!obj.contains_key("summary"));
        assert!(!obj.contains_key("graph_nodes"));
        assert!(!obj.contains_key("graph_edges"));
        assert!(!obj.contains_key("roe_blocked"));
        assert!(!obj.contains_key("roe"));
    }

    #[test]
    fn roe_blocked_serializes_control_payload_and_no_findings() {
        let r = EngineResult::roe_blocked(
            "RoE blocked: industrial_ot_enabled is false",
            serde_json::json!({
                "roe_blocked": true,
                "control": "industrial_ot_enabled",
                "control_value": false,
                "auto_enable": false,
                "never_auto_enabled": true,
            }),
        );
        assert_eq!(r.status, "roe_blocked");
        assert!(r.roe_blocked);
        assert!(!r.success);
        assert!(r.findings.is_empty());
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(v["status"], "roe_blocked");
        assert_eq!(v["roe_blocked"], true);
        assert_eq!(v["findings"], serde_json::json!([]));
        assert_eq!(v["roe"]["control"], "industrial_ot_enabled");
        assert_eq!(v["roe"]["auto_enable"], false);
    }
}
