//! AI / LLM / supply-chain hardening helpers (points 21–30).
//! Detection and prevention — no exploit payloads.

use regex::Regex;
use std::sync::LazyLock;

/// Jailbreak / prompt-injection technique families used by the red-team engine
/// as *scan cases* against the customer's own AI surfaces.
pub const JAILBREAK_TECHNIQUE_FAMILIES: &[&str] = &[
    "direct_override",
    "role_play",
    "encoded_instruction",
    "payload_splitting",
    "indirect_injection",
    "multilingual_smuggle",
    "tool_exfil",
    "system_prompt_extract",
    "context_overflow",
    "virtualization",
    "suffix_attack",
    "best_of_n",
    "many_shot",
    "crescendo",
    "skeleton_key",
    "developer_mode",
    "dan_variant",
    "grandma_exploit",
    "translation_pivot",
    "markdown_exfil",
    "json_mode_break",
    "xml_tag_break",
    "base64_wrap",
    "homoglyph",
    "zero_width",
    "rtl_override",
    "citation_poison",
    "rag_doc_inject",
    "function_call_hijack",
    "memory_write",
    "policy_puppetry",
    "alignment_faking",
    "prefill_assistant",
    "logit_bias_probe",
    "sampling_temp_abuse",
    "multi_agent_collusion",
    "image_stego_prompt",
    "audio_prompt",
    "code_interpreter_escape",
    "sql_in_nl",
    "ignore_previous",
    "new_session_sim",
    "ethical_override",
    "authority_impersonation",
    "urgent_safety",
    "token_smuggle",
    "delimiter_confusion",
    "chatml_injection",
    "llama_inst_break",
    "openai_policy_leak",
    "anthropic_xml_leak",
    "gemini_system_leak",
];

static SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(api[_-]?key|secret[_-]?key|aws_secret|begin [a-z ]*private key|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-)",
    )
    .expect("secret regex")
});

static HIDDEN_CODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(<script|javascript:|onerror=|eval\(|subprocess\.|os\.system|powershell -|cmd\.exe|/bin/sh)")
        .expect("hidden-code regex")
});

pub fn jailbreak_catalog_len() -> usize {
    JAILBREAK_TECHNIQUE_FAMILIES.len()
}

pub fn prompt_contains_secret(text: &str) -> bool {
    SECRET_RE.is_match(text)
}

pub fn embedding_text_has_hidden_code(text: &str) -> bool {
    HIDDEN_CODE_RE.is_match(text)
}

/// Cosine-space outlier: reject vectors whose L2 norm is pathological.
pub fn vector_is_anomalous(vec: &[f32]) -> bool {
    if vec.is_empty() {
        return true;
    }
    let mut sum = 0f64;
    for x in vec {
        if !x.is_finite() {
            return true;
        }
        sum += (*x as f64) * (*x as f64);
    }
    let norm = sum.sqrt();
    !(0.1..=8.0).contains(&norm)
}

pub fn trusted_memory_source(source: &str) -> bool {
    matches!(
        source,
        "oast_success" | "analyst_confirmed" | "probe_success" | "council_win"
    )
}

pub fn verify_model_sha256(expected_hex: &str, actual_hex: &str) -> bool {
    let e = hex::decode(expected_hex.trim()).ok();
    let a = hex::decode(actual_hex.trim()).ok();
    match (e, a) {
        (Some(ev), Some(av)) if ev.len() == 32 && av.len() == 32 => {
            use subtle::ConstantTimeEq;
            ev.ct_eq(av.as_slice()).into()
        }
        _ => false,
    }
}

/// Shadow-AI HTTP fingerprints (product detection, not exploitation).
pub const SHADOW_AI_PATHS: &[&str] = &[
    "/v1/models",
    "/v1/chat/completions",
    "/ollama/api/tags",
    "/api/generate",
    "/lmstudio",
    "/.well-known/ai-plugin.json",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifty_plus_techniques() {
        assert!(JAILBREAK_TECHNIQUE_FAMILIES.len() >= 50);
    }

    #[test]
    fn blocks_openai_key_in_prompt() {
        assert!(prompt_contains_secret(
            "please use sk-abcdefghijklmnopqrstuvwxyz012345"
        ));
        assert!(!prompt_contains_secret("summarize this finding"));
    }

    #[test]
    fn rejects_nan_vector() {
        assert!(vector_is_anomalous(&[f32::NAN]));
        assert!(!vector_is_anomalous(&[0.1; 16]));
    }

    #[test]
    fn memory_sources() {
        assert!(trusted_memory_source("oast_success"));
        assert!(!trusted_memory_source("anonymous"));
    }
}
