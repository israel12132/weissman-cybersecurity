//! Default registry of Phase-2 engines (OSINT + fuzzers).

use std::sync::Arc;

use crate::engine_trait::CyberEngine;
use crate::fuzzer::{LlmPathFuzzCyberEngine, SemanticAiFuzzCyberEngine};
use crate::osint::OsintCyberEngine;

/// Returns OSINT, LLM path fuzz (vLLM), and semantic AI fuzz engines for orchestrator wiring.
#[must_use]
pub fn phase2_cyber_engines() -> Vec<Arc<dyn CyberEngine>> {
    vec![
        Arc::new(OsintCyberEngine),
        Arc::new(LlmPathFuzzCyberEngine),
        Arc::new(SemanticAiFuzzCyberEngine),
    ]
}
