//! SOC scan engines — OSINT, LLM path fuzz (vLLM / OpenAI-compatible API), semantic fuzz.
//!
//! Use [`CyberEngine`] implementations from [`factory::phase2_cyber_engines`] or call
//! module functions directly with a [`ScanContext`] built by the orchestrator.
//!
//! ## Status: the [`CyberEngine`] trait system is RETIRED (not the whole crate)
//!
//! This crate began as a `CyberEngine`-trait engine framework, but that migration was not
//! completed: production dispatches all **563** engines through `fingerprint_engine`'s
//! `engine_dispatch` match, not through [`CyberEngine`]. Only OSINT + the two fuzzers are
//! wired as trait engines ([`factory::phase2_cyber_engines`]), so treat the trait/`factory`
//! surface as **frozen/legacy** — do not add new engines here; add them to
//! `fingerprint_engine::engine_dispatch` and `PRODUCTION_ENGINE_IDS`.
//!
//! What remains **live and load-bearing** are the shared building blocks that the monolith
//! depends on: [`stealth`] (Ghost Network jitter/headers), [`osint`], [`fuzzer`], and the
//! LLM plumbing ([`openai_chat`], [`llm_json_repair`], [`llm_sanitize`], [`llm_handshake`]).

#![forbid(unsafe_code)]
// LLM/OpenAPI call surfaces intentionally carry many parameters; keep explicit for auditability.
#![allow(clippy::too_many_arguments)]

pub mod context;
pub mod engine_trait;
pub mod factory;
pub mod fuzzer;
pub mod llm_handshake;
pub mod llm_json_repair;
pub mod llm_router;
pub mod llm_sanitize;
pub mod openai_chat;
pub mod osint;
pub mod result;
pub mod stealth;

pub use context::{EngineRunOutcome, ScanContext};
pub use engine_trait::CyberEngine;
pub use factory::phase2_cyber_engines;
pub use llm_json_repair::{deserialize_llm_json, extract_balanced_object, parse_value_from_llm};
pub use result::EngineResult;
pub use stealth::StealthConfig;

#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
