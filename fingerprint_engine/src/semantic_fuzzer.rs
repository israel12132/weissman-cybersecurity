//! Semantic / OpenAPI fuzzer — implemented in `weissman-engines` (`CyberEngine`: [`weissman_engines::fuzzer::SemanticAiFuzzCyberEngine`]).
//! When no OpenAPI is published, the engine runs a primary path wordlist and a **second wave** of
//! recursively derived paths under prefixes that returned a non-404 response (aggressive directory discovery).

pub use weissman_engines::fuzzer::preflight_semantic_probe_body;

pub use weissman_core::models::semantic::{SemanticConfig, StateEdge, StateNode};
use serde_json::Value;

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
