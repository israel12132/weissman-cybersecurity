//! **COGNITIVE STARVATION** — offensive AI poisoning for automated/LLM scanners.
//!
//! Detects bot-like inbound patterns, routes to deception shadow surfaces, and returns
//! adversarial payloads designed to exhaust attacker inference pipelines.

use crate::deception_engine::{self, TYPE_SHADOW_ENDPOINT};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, finding, http_client, http_get_with_headers, join_url,
};
use crate::engine_result::{print_result, EngineResult};
use crate::sovereign_defense_store::{self, COGNITIVE_STARVATION_ENGINE_ID};
use serde_json::{json, Map, Value};
use std::collections::HashSet;

const MITRE: &str = "T1566";

fn finding_evidence(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    evidence: Map<String, Value>,
) -> Value {
    let mut f = finding(
        COGNITIVE_STARVATION_ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("evidence".into(), Value::Object(evidence));
    }
    f
}

const BOT_USER_AGENTS: &[&str] = &[
    "GPTBot/1.0 (+https://openai.com/gptbot)",
    "ClaudeBot/1.0",
    "CCBot/2.0 (https://commoncrawl.org/faq/)",
    "Bytespider",
    "python-requests/2.31.0",
    "curl/8.5.0",
    "Go-http-client/1.1",
];

#[derive(Debug, Clone)]
pub struct CognitiveConfig {
    pub min_bot_score: f64,
    pub deploy_shadow: bool,
    pub poison_variants: Vec<String>,
    pub probe_rate: u32,
}

impl CognitiveConfig {
    pub fn from_params(params: &Value) -> Self {
        let variants = params
            .get("poison_variants")
            .and_then(Value::as_str)
            .unwrap_or("adversarial_prompt,zip_bomb_meta,xml_entity,shadow_api")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            min_bot_score: pf64(params, "min_bot_score", 0.55).clamp(0.0, 1.0),
            deploy_shadow: pbool(params, "deploy_shadow", true),
            poison_variants: variants,
            probe_rate: pi64(params, "probe_rate", 12).clamp(1, 50) as u32,
        }
    }
}

fn pi64(p: &Value, k: &str, d: i64) -> i64 {
    p.get(k).and_then(Value::as_i64).unwrap_or(d)
}

fn pf64(p: &Value, k: &str, d: f64) -> f64 {
    p.get(k)
        .and_then(Value::as_f64)
        .or_else(|| p.get(k).and_then(Value::as_i64).map(|n| n as f64))
        .unwrap_or(d)
}

fn pbool(p: &Value, k: &str, d: bool) -> bool {
    p.get(k).and_then(Value::as_bool).unwrap_or(d)
}

fn bot_header_pairs<'a>(ua: &'a str) -> [(&'static str, &'a str); 4] {
    [
        ("User-Agent", ua),
        ("X-Forwarded-For", "203.0.113.66"),
        ("Accept", "*/*"),
        ("X-Automation", "true"),
    ]
}

fn score_response(status: u16, body: &str, ua: &str) -> (f64, Vec<String>) {
    let mut signals = Vec::new();
    let mut score = 0.0f64;
    if status == 200 {
        score += 0.35;
        signals.push("200_ok_to_bot_ua".into());
    }
    if status == 403 || status == 401 {
        score -= 0.2;
        signals.push("blocked_bot".into());
    }
    let bl = body.to_ascii_lowercase();
    if bl.contains("api") || bl.contains("secret") || bl.contains("password") {
        score += 0.25;
        signals.push("honeypot_keywords_in_body".into());
    }
    if bl.contains("system override") || bl.contains("ignore all previous") {
        score += 0.3;
        signals.push("adversarial_prompt_surface".into());
    }
    if ua.contains("GPTBot") || ua.contains("ClaudeBot") {
        score += 0.15;
        signals.push("llm_crawler_ua".into());
    }
    (score.clamp(0.0, 1.0), signals)
}

pub async fn run_cognitive_starvation_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let cfg = CognitiveConfig::from_params(&ctx.job_params);
    let host = extract_host(target);
    if host.is_empty() {
        return EngineResult::error("target required");
    }

    let base_url = if target.starts_with("http") {
        target.to_string()
    } else {
        format!("https://{host}")
    };

    let (pool, tenant_id, client_id) = match (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id) {
        (Some(p), Some(t), Some(c)) => (p.clone(), t, c),
        _ => {
            return EngineResult::error(
                "COGNITIVE STARVATION requires client_id — select a client in Command Center",
            );
        }
    };

    let poison_lib = sovereign_defense_store::load_poison_library(pool.as_ref(), 20)
        .await
        .unwrap_or_default();
    let variant_set: HashSet<String> = cfg.poison_variants.iter().cloned().collect();
    let active_poison: Vec<Value> = poison_lib
        .into_iter()
        .filter(|p| {
            p.get("variant")
                .and_then(Value::as_str)
                .map(|v| variant_set.is_empty() || variant_set.contains(v))
                .unwrap_or(false)
        })
        .collect();

    if cfg.deploy_shadow {
        let (shadow_path, _) = deception_engine::generate_honeytoken(TYPE_SHADOW_ENDPOINT, &host);
        let shadow_url = join_url(&base_url, &shadow_path);
        let mut ev = serde_json::Map::new();
        ev.insert("shadow_path".into(), json!(shadow_path));
        ev.insert("shadow_url".into(), json!(shadow_url));
        ev.insert("poison_count".into(), json!(active_poison.len()));
    }

    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let mut sessions = 0i64;

    for (i, ua) in BOT_USER_AGENTS
        .iter()
        .enumerate()
        .take(cfg.probe_rate as usize)
    {
        let headers = bot_header_pairs(ua);
        let (status, body_preview) =
            if let Some(r) = http_get_with_headers(&client, &base_url, &headers).await {
                let preview: String = r.body.chars().take(400).collect();
                (r.status, preview)
            } else {
                (0, String::new())
            };

        let (bot_score, signals) = score_response(status, &body_preview, ua);
        if bot_score < cfg.min_bot_score {
            continue;
        }

        let poison = active_poison.get(i % active_poison.len().max(1));
        let poison_id = poison
            .and_then(|p| p.get("id").and_then(Value::as_str))
            .unwrap_or("adv_prompt_override_v1");
        let poison_variant = poison
            .and_then(|p| p.get("variant").and_then(Value::as_str))
            .unwrap_or("adversarial_prompt");

        if let Err(e) = sovereign_defense_store::insert_cognitive_session(
            pool.as_ref(),
            tenant_id,
            client_id,
            &base_url,
            bot_score,
            &signals,
            Some(poison_variant),
            Some(poison_id),
            Some(status as i32),
            json!({ "user_agent": ua, "body_preview": body_preview }),
        )
        .await
        {
            findings.push(finding_evidence(
                "Cognitive session persist warning",
                "info",
                MITRE,
                &format!("Bot signal detected but session persist failed: {e}"),
                &host,
                Map::from_iter([("persist_error".into(), json!(e.to_string()))]),
            ));
            continue;
        }
        sessions += 1;

        let mut ev = serde_json::Map::new();
        ev.insert("user_agent".into(), json!(ua));
        ev.insert("bot_score".into(), json!(bot_score));
        ev.insert("signals".into(), json!(signals));
        ev.insert("response_status".into(), json!(status));
        ev.insert("poison_payload_id".into(), json!(poison_id));
        ev.insert("poison_variant".into(), json!(poison_variant));
        if let Some(p) = poison {
            ev.insert(
                "recommended_poison".into(),
                json!(p.get("payload").and_then(Value::as_str).unwrap_or("")),
            );
        }

        findings.push(finding_evidence(
            &format!("Cognitive starvation candidate — bot score {:.0}% ({ua})", bot_score * 100.0),
            if bot_score >= 0.8 { "critical" } else { "high" },
            MITRE,
            "Automated/LLM scanner pattern detected. Deploy adversarial poison via deception shadow route instead of 403.",
            &host,
            ev,
        ));
    }

    if !active_poison.is_empty() {
        let mut ev = serde_json::Map::new();
        ev.insert("library_size".into(), json!(active_poison.len()));
        ev.insert(
            "variants".into(),
            json!(active_poison
                .iter()
                .filter_map(|p| p.get("variant").and_then(Value::as_str))
                .collect::<Vec<_>>()),
        );
        findings.push(finding_evidence(
            "Cognitive poison library armed",
            "info",
            "T1204",
            "Live adversarial payloads ready for shadow-route injection against offensive AI scanners.",
            &host,
            ev,
        ));
    }

    if findings.is_empty() {
        return empty_ok(
            COGNITIVE_STARVATION_ENGINE_ID,
            &format!(
                "COGNITIVE STARVATION: no bot score ≥ {:.0}% observed",
                cfg.min_bot_score * 100.0
            ),
        );
    }
    EngineResult::ok(
        findings,
        format!("COGNITIVE STARVATION: {sessions} poison session(s) recorded"),
    )
}

pub async fn run_cognitive_starvation(target: &str) {
    print_result(run_cognitive_starvation_result(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_score_detects_200_with_secrets() {
        let (s, sig) = score_response(200, "internal api secret key", "GPTBot/1.0");
        assert!(s >= 0.5);
        assert!(sig.contains(&"honeypot_keywords_in_body".to_string()));
    }
}
