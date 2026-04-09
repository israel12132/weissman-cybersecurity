//! SOC scan engines — OSINT, LLM path fuzz (vLLM / OpenAI-compatible API), semantic fuzz.
//!
//! Use [`CyberEngine`] implementations from [`factory::phase2_cyber_engines`] or call
//! module functions directly with a [`ScanContext`] built by the orchestrator.

#![forbid(unsafe_code)]
// LLM/OpenAPI call surfaces intentionally carry many parameters; keep explicit for auditability.
#![allow(clippy::too_many_arguments)]

pub mod context;
pub mod engine_trait;
pub mod factory;
pub mod fuzzer;
pub mod llm_handshake;
pub mod llm_json_repair;
pub mod llm_sanitize;
pub mod openai_chat;
pub mod osint;
pub mod result;
pub mod stealth;

pub use context::{EngineRunOutcome, ScanContext};
pub use engine_trait::CyberEngine;
pub use factory::phase2_cyber_engines;
pub use result::EngineResult;
pub use llm_json_repair::{deserialize_llm_json, extract_balanced_object, parse_value_from_llm};
pub use stealth::StealthConfig;

#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
