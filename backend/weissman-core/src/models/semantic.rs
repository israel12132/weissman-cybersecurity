//! Semantic / OpenAPI fuzzer configuration and state-machine view models.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct StateNode {
    pub id: String,
    pub path: String,
    pub method: String,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct StateEdge {
    pub id: String,
    pub from_id: String,
    pub to_id: String,
    pub edge_type: String,
}

/// Config for semantic fuzzer (from `system_configs` / tenant settings).
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct SemanticConfig {
    #[schema(example = "http://127.0.0.1:8000/v1")]
    pub llm_base_url: String,
    #[schema(example = 0.7)]
    pub llm_temperature: f64,
    #[schema(example = "meta-llama/Llama-3.2-3B-Instruct")]
    pub llm_model: String,
    #[schema(example = 5)]
    pub max_sequence_depth: usize,
}
