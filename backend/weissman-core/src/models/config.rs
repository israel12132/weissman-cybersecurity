//! Client configuration snapshot — aligned with dashboard `client_configs` JSON.

use super::engine::default_enabled_engine_ids;
use super::roe::RoeMode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

fn default_enabled_engines() -> Vec<String> {
    default_enabled_engine_ids()
}

/// Parsed client configuration (subset enforced by API; unknown fields ignored at serde level).
/// DB seeds and older rows may still store `ollama_fuzz` in `enabled_engines`; the engine layer treats it as `llm_path_fuzz`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClientConfigSnapshot {
    #[serde(default = "default_enabled_engines")]
    #[schema(example = json!(["osint", "asm"]))]
    pub enabled_engines: Vec<String>,
    #[serde(default)]
    pub roe_mode: RoeMode,
    #[serde(default = "default_stealth")]
    #[schema(example = 50, minimum = 0, maximum = 100)]
    pub stealth_level: u8,
    #[serde(default = "default_true")]
    pub auto_harvest: bool,
    #[serde(default)]
    pub industrial_ot_enabled: bool,
}

fn default_stealth() -> u8 {
    50
}

fn default_true() -> bool {
    true
}

impl Default for ClientConfigSnapshot {
    fn default() -> Self {
        Self {
            enabled_engines: default_enabled_engine_ids(),
            roe_mode: RoeMode::default(),
            stealth_level: 50,
            auto_harvest: true,
            industrial_ot_enabled: false,
        }
    }
}

impl ClientConfigSnapshot {
    /// Merge JSON object from DB / API into a snapshot (invalid engine entries may still deserialize).
    #[must_use]
    pub fn from_json_value(value: &serde_json::Value) -> Self {
        serde_json::from_value(value.clone()).unwrap_or_default()
    }
}
