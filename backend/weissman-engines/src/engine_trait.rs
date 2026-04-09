//! Pluggable scan engines (`CyberEngine`).

use async_trait::async_trait;

use crate::context::{EngineRunOutcome, ScanContext};

/// SOC engine contract: pure async execution from a [`ScanContext`]. No routing or persistence.
#[async_trait]
pub trait CyberEngine: Send + Sync {
    /// Stable id (`osint`, `llm_path_fuzz`, `semantic_ai_fuzz`, …).
    fn engine_id(&self) -> &'static str;

    /// Short label for telemetry / UI.
    fn display_label(&self) -> &'static str;

    async fn execute(&self, ctx: &ScanContext) -> EngineRunOutcome;
}
