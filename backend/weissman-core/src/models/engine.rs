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

/// Full ordered registry of all 52 engines in proper execution order.
/// Matches frontend/src/lib/enginesRegistry.js
pub const FULL_ENGINE_REGISTRY_ORDER: &[&str] = &[
    // Recon & OSINT (run first to discover attack surface)
    "osint",
    "asm",
    "leak_hunter",
    "discovery_engine",
    "recon",
    // Web / API attacks
    "bola_idor",
    "graphql_attack",
    "jwt_attack",
    "oauth_oidc",
    "http_smuggling",
    "prototype_pollution",
    "ssrf_advanced",
    "xxe",
    "ssti",
    "file_upload",
    "websocket_attack",
    "cache_poisoning",
    // AI / LLM
    "llm_path_fuzz",
    "semantic_ai_fuzz",
    "ai_adversarial_redteam",
    "llm_redteam",
    "adversarial_ml",
    "autonomous_pentest",
    // Cloud / Infra
    "aws_attack",
    "azure_attack",
    "gcp_attack",
    "k8s_container",
    "iac_misconfig",
    "serverless_attack",
    // OT / ICS / IoT
    "scada_ics",
    "iot_firmware",
    "ble_rf",
    // Stealth / Evasion
    "edr_evasion",
    "waf_bypass",
    "timing_sidechannel",
    "antiforensics",
    "stealth_engine",
    // Crypto / Identity
    "pki_tls",
    "pqc_scanner",
    "password_spray",
    "kerberoasting",
    "saml_attack",
    "crypto_engine",
    // Network / Protocol
    "bgp_dns_hijacking",
    "ipv6_attack",
    "mtls_grpc",
    "smb_netbios",
    // Supply Chain
    "supply_chain",
    "cicd_pipeline",
    "container_registry",
    "sbom_analyzer",
    "typosquatting_monitor",
    // APT / Top-Tier (run last as they may depend on previous findings)
    "kill_chain",
    "oast_oob",
    "deception_honeypot",
    "digital_twin",
    "zero_day_prediction",
    "threat_emulation",
    "poe_synthesis",
];

#[must_use]
pub fn is_known_engine_id(s: &str) -> bool {
    KNOWN_ENGINE_IDS.iter().any(|&k| k == s.trim()) 
        || FULL_ENGINE_REGISTRY_ORDER.iter().any(|&k| k == s.trim())
}

#[must_use]
pub fn default_enabled_engine_ids() -> Vec<String> {
    KNOWN_ENGINE_IDS.iter().map(|s| (*s).to_string()).collect()
}

/// Order a list of engine IDs by their position in the registry.
/// Engines not in the registry are placed at the end.
#[must_use]
pub fn order_engines_by_registry(engines: &[String]) -> Vec<String> {
    let mut ordered: Vec<(usize, String)> = engines
        .iter()
        .map(|e| {
            let pos = FULL_ENGINE_REGISTRY_ORDER
                .iter()
                .position(|&r| r == e.as_str())
                .unwrap_or(usize::MAX);
            (pos, e.clone())
        })
        .collect();
    ordered.sort_by_key(|(pos, _)| *pos);
    ordered.into_iter().map(|(_, e)| e).collect()
}
