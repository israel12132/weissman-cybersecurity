//! Scan inputs passed from the orchestrator (no SQL, no Axum).

use crate::openai_chat::DEFAULT_LLM_BASE_URL;
use crate::result::EngineResult;
use crate::stealth::StealthConfig;
use weissman_core::models::semantic::SemanticConfig;

/// Tenant-agnostic snapshot for engine execution.
#[derive(Clone, Debug, Default)]
pub struct ScanContext {
    pub primary_target: String,
    pub target_list: Vec<String>,
    pub discovered_paths: Vec<String>,
    pub stealth: Option<StealthConfig>,
    pub semantic: SemanticConfig,
    /// OpenAI-compatible API base URL (vLLM), e.g. `http://127.0.0.1:8000/v1`.
    pub llm_base_url: String,
    /// When set, LLM token usage is attributed to this tenant (Postgres metering).
    pub llm_tenant_id: Option<i64>,
}

impl ScanContext {
    #[must_use]
    pub fn llm_base_resolved(&self) -> &str {
        let s = self.llm_base_url.trim();
        if s.is_empty() {
            DEFAULT_LLM_BASE_URL
        } else {
            s
        }
    }
}

/// Result of one engine pass; semantic fuzzer may attach a reasoning log for persistence.
#[derive(Debug, Clone)]
pub struct EngineRunOutcome {
    pub result: EngineResult,
    pub semantic_reasoning_log: Option<String>,
}

impl EngineRunOutcome {
    #[must_use]
    pub fn with_result(result: EngineResult) -> Self {
        Self {
            result,
            semantic_reasoning_log: None,
        }
    }
}
