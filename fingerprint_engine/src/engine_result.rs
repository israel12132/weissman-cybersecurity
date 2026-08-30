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
    /// First-class policy / RoE denial (never empty `ok`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// True when this result is a Rules-of-Engagement / policy block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_block: Option<bool>,
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
            error_code: None,
            policy_block: None,
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
            error_code: None,
            policy_block: None,
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
            error_code: None,
            policy_block: None,
        }
    }

    /// Policy / RoE denial: first-class `blocked` status with an explicit finding.
    /// Never `ok` with zero findings (that is read as "healthy").
    pub fn blocked(
        findings: Vec<serde_json::Value>,
        message: impl Into<String>,
        error_code: impl Into<String>,
    ) -> Self {
        let msg = message.into();
        Self {
            status: "blocked".to_string(),
            findings,
            message: msg.clone(),
            success: false,
            summary: msg,
            graph_nodes: None,
            graph_edges: None,
            error_code: Some(error_code.into()),
            policy_block: Some(true),
        }
    }

    #[must_use]
    pub fn is_policy_block(&self) -> bool {
        self.status.eq_ignore_ascii_case("blocked")
            || self.policy_block == Some(true)
            || self
                .error_code
                .as_deref()
                .is_some_and(|c| c.eq_ignore_ascii_case("roe_denied"))
    }
}

impl From<weissman_engines::EngineResult> for EngineResult {
    fn from(r: weissman_engines::EngineResult) -> Self {
        let is_ok = r.status == "ok";
        let is_block = r.status.eq_ignore_ascii_case("blocked");
        Self {
            status: r.status,
            findings: r.findings,
            message: r.message.clone(),
            success: is_ok,
            summary: r.message,
            graph_nodes: None,
            graph_edges: None,
            error_code: is_block.then(|| "roe_denied".to_string()),
            policy_block: is_block.then_some(true),
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
            error_code: None,
            policy_block: None,
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
        assert!(!obj.contains_key("error_code"));
        assert!(!obj.contains_key("policy_block"));
    }

    #[test]
    fn blocked_result_is_not_success_and_carries_policy_finding() {
        let r = EngineResult::blocked(
            vec![serde_json::json!({"type": "policy_block", "policy_block": true})],
            "RoE DENIED: industrial_ot_enabled is false",
            "roe_denied",
        );
        assert_eq!(r.status, "blocked");
        assert!(!r.success);
        assert!(r.is_policy_block());
        assert_eq!(r.error_code.as_deref(), Some("roe_denied"));
        assert_eq!(r.policy_block, Some(true));
        assert!(!r.findings.is_empty());
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(v["status"], "blocked");
        assert_eq!(v["error_code"], "roe_denied");
        assert_eq!(v["policy_block"], true);
        assert!(v["findings"].as_array().is_some_and(|a| !a.is_empty()));
    }
}
