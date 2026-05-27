//! Advanced AI/LLM Engines — real probes against AI endpoints. All findings are evidence-based.
//!
//! Strategy:
//!   1. Try common LLM/AI endpoints on the target (/v1/chat/completions, /api/generate, /api/chat, …).
//!   2. Detect whether they are reachable and (when applicable) respond to canary prompts.
//!   3. Emit findings only on observed behaviour; no canned "simulated …" text.

use crate::engine_probes::{
    empty_ok, finding, http_client, http_get, http_post_json, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

/// Common LLM endpoints to probe (OpenAI-compatible / ollama / vLLM).
const LLM_PATHS: &[&str] = &[
    "/v1/chat/completions",
    "/v1/completions",
    "/api/generate",
    "/api/chat",
    "/chat",
    "/completion",
    "/api/v1/chat/completions",
];

async fn probe_llm_surface(target: &str) -> Vec<(String, u16)> {
    let client = http_client().await;
    let base = normalize_url(target);
    let mut out = Vec::new();
    for path in LLM_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let payload = json!({
            "model": "probe",
            "messages": [{"role":"user","content":"ping"}],
            "max_tokens": 1
        });
        if let Some(p) = http_post_json(&client, &url, &payload).await {
            // 400 (bad model) / 401 / 422 still proves the endpoint exists.
            if p.status < 600 && p.status != 0 && p.status != 404 && p.status != 405 {
                out.push((p.final_url, p.status));
            }
        }
    }
    out
}

fn ai_finding(engine_id: &str, title: &str, severity: &str, mitre: &str, target: &str, eps: &[(String, u16)]) -> Vec<Value> {
    if eps.is_empty() {
        return vec![];
    }
    let desc = format!(
        "Live LLM/AI endpoints reachable on {}: {}",
        target,
        eps.iter()
            .map(|(u, s)| format!("{} → HTTP {}", u, s))
            .collect::<Vec<_>>()
            .join(", ")
    );
    vec![finding(engine_id, title, severity, mitre, &desc, target)]
}

// ── llm_jailbreak ─────────────────────────────────────────────────────────────
pub async fn run_llm_jailbreak_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let eps = probe_llm_surface(target).await;
    let findings = ai_finding(
        "llm_jailbreak",
        "AI endpoint reachable for jailbreak probes",
        "medium",
        "T1059.008",
        target,
        &eps,
    );
    if findings.is_empty() {
        empty_ok("llm_jailbreak", target)
    } else {
        EngineResult::ok(findings, "llm_jailbreak: live endpoint surface".to_string())
    }
}
cli_wrapper!(run_llm_jailbreak, run_llm_jailbreak_result);

// ── prompt_injection_chain ────────────────────────────────────────────────────
pub async fn run_prompt_injection_chain_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let eps = probe_llm_surface(target).await;
    let findings = ai_finding(
        "prompt_injection_chain",
        "AI endpoint reachable for prompt-injection chaining",
        "medium",
        "T1059.008",
        target,
        &eps,
    );
    if findings.is_empty() {
        empty_ok("prompt_injection_chain", target)
    } else {
        EngineResult::ok(findings, "prompt_injection_chain: live endpoint surface".to_string())
    }
}
cli_wrapper!(run_prompt_injection_chain, run_prompt_injection_chain_result);

// ── model_inversion_attack ────────────────────────────────────────────────────
pub async fn run_model_inversion_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let eps = probe_llm_surface(target).await;
    let findings = ai_finding(
        "model_inversion_attack",
        "AI inference endpoint reachable",
        "low",
        "T1588.005",
        target,
        &eps,
    );
    if findings.is_empty() {
        empty_ok("model_inversion_attack", target)
    } else {
        EngineResult::ok(findings, "model_inversion_attack: live endpoint".to_string())
    }
}
cli_wrapper!(run_model_inversion_attack, run_model_inversion_attack_result);

// ── ai_supply_chain_attack ────────────────────────────────────────────────────
// Probe huggingface model name discovery via response body parsing.
pub async fn run_ai_supply_chain_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &base).await {
        let body = p.body.to_lowercase();
        for sig in ["huggingface", "from_pretrained", "model_id", "ollama"] {
            if body.contains(sig) {
                findings.push(finding(
                    "ai_supply_chain_attack",
                    &format!("AI model dependency hint: {}", sig),
                    "low",
                    "T1195.001",
                    &format!("Body of {} contains the token '{}' — verify model provenance and signature.", p.final_url, sig),
                    target,
                ));
                break;
            }
        }
    }
    if findings.is_empty() {
        empty_ok("ai_supply_chain_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("ai_supply_chain_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_ai_supply_chain_attack, run_ai_supply_chain_attack_result);

// Generic LLM-surface result helper (used for engines whose detection is "endpoint exists")
async fn llm_surface_engine(
    target: &str,
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let eps = probe_llm_surface(target).await;
    let findings = ai_finding(engine_id, title, severity, mitre, target, &eps);
    if findings.is_empty() {
        empty_ok(engine_id, target)
    } else {
        EngineResult::ok(findings, format!("{}: live endpoint surface", engine_id))
    }
}

pub async fn run_llm_agent_hijack_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "llm_agent_hijack", "Agent endpoint reachable", "medium", "T1059.008").await
}
cli_wrapper!(run_llm_agent_hijack, run_llm_agent_hijack_result);

pub async fn run_rag_poisoning_engine_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "rag_poisoning_engine", "RAG/AI endpoint reachable", "low", "T1565").await
}
cli_wrapper!(run_rag_poisoning_engine, run_rag_poisoning_engine_result);

pub async fn run_adversarial_examples_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "adversarial_examples", "ML endpoint reachable for adversarial examples", "low", "T1588.005").await
}
cli_wrapper!(run_adversarial_examples, run_adversarial_examples_result);

pub async fn run_data_poisoning_engine_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "data_poisoning_engine", "Training/feedback endpoint candidate", "low", "T1565").await
}
cli_wrapper!(run_data_poisoning_engine, run_data_poisoning_engine_result);

pub async fn run_deepfake_synthesis_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "deepfake_synthesis", "Generative endpoint reachable", "low", "T1565.002").await
}
cli_wrapper!(run_deepfake_synthesis, run_deepfake_synthesis_result);

pub async fn run_llm_dos_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let eps = probe_llm_surface(t).await;
    if eps.is_empty() {
        return empty_ok("llm_dos_attack", t);
    }
    // Send 5 concurrent probes; measure throughput hint.
    let client = http_client().await;
    let url = eps[0].0.clone();
    let payload = json!({"model":"probe","messages":[{"role":"user","content":"hi"}],"max_tokens":1});
    let mut hits = 0;
    for _ in 0..5 {
        if http_post_json(&client, &url, &payload).await.is_some() {
            hits += 1;
        }
    }
    let findings = vec![finding(
        "llm_dos_attack",
        "LLM endpoint accepted 5 rapid probes",
        "low",
        "T1499",
        &format!("{} accepted {}/5 rapid POSTs — verify rate limiting and token budget.", url, hits),
        t,
    )];
    EngineResult::ok(findings, "llm_dos_attack: 1 live indicator".to_string())
}
cli_wrapper!(run_llm_dos_attack, run_llm_dos_attack_result);

pub async fn run_multimodal_ai_attack_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "multimodal_ai_attack", "Multimodal endpoint candidate", "low", "T1059.008").await
}
cli_wrapper!(run_multimodal_ai_attack, run_multimodal_ai_attack_result);

pub async fn run_ai_bias_exploit_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "ai_bias_exploit", "AI endpoint reachable for bias probes", "low", "T1565").await
}
cli_wrapper!(run_ai_bias_exploit, run_ai_bias_exploit_result);

pub async fn run_gpt_plugin_attack_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "gpt_plugin_attack", "Plugin endpoint candidate", "low", "T1059.008").await
}
cli_wrapper!(run_gpt_plugin_attack, run_gpt_plugin_attack_result);

pub async fn run_autonomous_ai_escape_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "autonomous_ai_escape", "Agent endpoint reachable", "medium", "T1059.008").await
}
cli_wrapper!(run_autonomous_ai_escape, run_autonomous_ai_escape_result);

pub async fn run_llm_memory_extraction_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "llm_memory_extraction", "AI endpoint reachable for memory extraction", "low", "T1588.005").await
}
cli_wrapper!(run_llm_memory_extraction, run_llm_memory_extraction_result);

pub async fn run_neural_backdoor_detect_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "neural_backdoor_detect", "ML endpoint reachable", "info", "T1588.005").await
}
cli_wrapper!(run_neural_backdoor_detect, run_neural_backdoor_detect_result);

pub async fn run_ai_watermark_bypass_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "ai_watermark_bypass", "Generative endpoint reachable", "info", "T1565.002").await
}
cli_wrapper!(run_ai_watermark_bypass, run_ai_watermark_bypass_result);

pub async fn run_federated_learning_attack_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "federated_learning_attack", "Federated learning endpoint candidate", "low", "T1565").await
}
cli_wrapper!(run_federated_learning_attack, run_federated_learning_attack_result);

pub async fn run_llm_red_team_advanced_result(t: &str) -> EngineResult {
    crate::ai_redteam_engine::run_ai_redteam_attack(
        t,
        None,
        &crate::ai_redteam_engine::AiRedteamConfig::default(),
        None,
        None,
    )
    .await
}
cli_wrapper!(run_llm_red_team_advanced, run_llm_red_team_advanced_result);

pub async fn run_model_stealing_engine_result(t: &str) -> EngineResult {
    llm_surface_engine(t, "model_stealing_engine", "Inference endpoint reachable", "low", "T1588.005").await
}
cli_wrapper!(run_model_stealing_engine, run_model_stealing_engine_result);
