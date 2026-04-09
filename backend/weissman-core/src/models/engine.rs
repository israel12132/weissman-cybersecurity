//! Scan engine identifiers — canonical list matches orchestrator `ALL_ENGINES` / client config.

use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;

/// Known SOC engines (`snake_case` in JSON and `client_configs.enabled_engines`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(description = "Registered scan engine id (snake_case)")]
pub enum EngineId {
    Osint,
    Asm,
    SupplyChain,
    LeakHunter,
    BolaIdor,
    LlmPathFuzz,
    SemanticAiFuzz,
    MicrosecondTiming,
    AiAdversarialRedteam,
}

impl EngineId {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Osint => "osint",
            Self::Asm => "asm",
            Self::SupplyChain => "supply_chain",
            Self::LeakHunter => "leak_hunter",
            Self::BolaIdor => "bola_idor",
            Self::LlmPathFuzz => "llm_path_fuzz",
            Self::SemanticAiFuzz => "semantic_ai_fuzz",
            Self::MicrosecondTiming => "microsecond_timing",
            Self::AiAdversarialRedteam => "ai_adversarial_redteam",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "osint" => Some(Self::Osint),
            "asm" => Some(Self::Asm),
            "supply_chain" => Some(Self::SupplyChain),
            "leak_hunter" => Some(Self::LeakHunter),
            "bola_idor" => Some(Self::BolaIdor),
            "llm_path_fuzz" | "ollama_fuzz" => Some(Self::LlmPathFuzz),
            "semantic_ai_fuzz" => Some(Self::SemanticAiFuzz),
            "microsecond_timing" => Some(Self::MicrosecondTiming),
            "ai_adversarial_redteam" => Some(Self::AiAdversarialRedteam),
            _ => None,
        }
    }
}

impl fmt::Display for EngineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable list for validation / defaults (same order as legacy `ALL_ENGINES`).
pub const KNOWN_ENGINE_IDS: &[&str] = &[
    "osint",
    "asm",
    "supply_chain",
    "leak_hunter",
    "bola_idor",
    "llm_path_fuzz",
    "semantic_ai_fuzz",
    "microsecond_timing",
    "ai_adversarial_redteam",
];

#[must_use]
pub fn is_known_engine_id(s: &str) -> bool {
    KNOWN_ENGINE_IDS.iter().any(|&k| k == s.trim())
}

#[must_use]
pub fn default_enabled_engine_ids() -> Vec<String> {
    KNOWN_ENGINE_IDS.iter().map(|s| (*s).to_string()).collect()
}
