//! Semantic / OpenAPI fuzzer — implemented in `weissman-engines` (`CyberEngine`: [`weissman_engines::fuzzer::SemanticAiFuzzCyberEngine`]).
//! When no OpenAPI is published, the engine runs a primary path wordlist and a **second wave** of
//! recursively derived paths under prefixes that returned a non-404 response (aggressive directory discovery).

pub use weissman_engines::fuzzer::preflight_semantic_probe_body;

use serde_json::Value;
pub use weissman_core::models::semantic::{SemanticConfig, StateEdge, StateNode};

use crate::engine_result::EngineResult;
use crate::stealth_engine;

/// Same shape as the engines crate, but [`EngineResult`] is the monolith type (ASM graph-capable).
pub struct SemanticFuzzResult {
    pub result: EngineResult,
    pub state_nodes: Vec<StateNode>,
    pub state_edges: Vec<StateEdge>,
    pub reasoning_log: String,
}

pub async fn get_state_machine(target: &str) -> Option<(Vec<StateNode>, Vec<StateEdge>)> {
    weissman_engines::fuzzer::get_state_machine(target).await
}

pub fn parse_state_machine(spec: &Value) -> (Vec<StateNode>, Vec<StateEdge>) {
    weissman_engines::fuzzer::parse_state_machine(spec)
}

pub async fn run_semantic_fuzz_result(
    target: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
    config: &SemanticConfig,
    discovered_paths: Option<&[String]>,
    llm_tenant_id: Option<i64>,
) -> SemanticFuzzResult {
    let inner = weissman_engines::fuzzer::run_semantic_fuzz_result(
        target,
        stealth,
        config,
        discovered_paths,
        llm_tenant_id,
    )
    .await;
    SemanticFuzzResult {
        result: inner.result.into(),
        state_nodes: inner.state_nodes,
        state_edges: inner.state_edges,
        reasoning_log: inner.reasoning_log,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_state_machine_via_monolith_wrapper() {
        let spec = json!({"paths": {"/login": {"post": {"summary": "auth"}}}});
        let (nodes, edges) = parse_state_machine(&spec);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "POST_login");
        assert_eq!(nodes[0].method, "POST");
        assert!(edges.is_empty());
    }

    #[test]
    fn preflight_probe_body_reexport_validates() {
        assert!(preflight_semantic_probe_body("{\"a\":1}", true).is_ok());
        assert!(preflight_semantic_probe_body("<r><a/></r>", true).is_ok());
        assert!(preflight_semantic_probe_body("", true).is_err());
        assert!(preflight_semantic_probe_body("{bad", true).is_err());
    }
}
