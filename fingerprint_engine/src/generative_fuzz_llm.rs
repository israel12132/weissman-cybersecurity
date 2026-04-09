//! vLLM / OpenAI-compatible mutation generation for feedback fuzzing (`WEISSMAN_LLM_BASE_URL`, `/v1/chat/completions`).
//! Produces an async-filled buffer of payloads while HTTP workers consume in parallel; supports WAF feedback bypass rounds.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quick_xml::events::Event;
use quick_xml::Reader;
use tokio::sync::mpsc;
use tracing::warn;
use weissman_engines::openai_chat::{self, DEFAULT_LLM_BASE_URL, LlmError};

/// After this many seconds without a bypass batch, decay adrenaline (streak −1) toward baseline temperature.
const ADRENALINE_DECAY_SECS: u64 = 85;
/// Maximum dynamic temperature ("adrenaline" cap).
const ADRENALINE_MAX_TEMP: f64 = 1.1;
/// Per bypass streak step: multiply baseline by this ratio (exponential adrenaline).
const ADRENALINE_MULT_PER_STREAK: f64 = 1.09;
/// Cap streak exponent to avoid runaway.
const ADRENALINE_STREAK_CAP: u32 = 14;

/// One LLM-generated POST body plus the exact user prompt sent to the model (audit / DB provenance).
#[derive(Clone, Debug)]
pub struct GenerativeMutation {
    pub payload: String,
    pub llm_user_prompt: String,
}

/// Target indicated a block / WAF — feed back to the model for bypass-oriented mutations.
#[derive(Clone, Debug)]
pub struct BlockFeedback {
    pub blocked_payload: String,
    pub http_status: u16,
    pub response_excerpt: String,
    /// Normalized Shannon entropy (0..=1) of the response body excerpt; used to detect homogenizing errors.
    pub response_entropy: f64,
}

/// Byte-level Shannon entropy of `s`, scaled to 0..=1 (divide by 8 bits max).
#[must_use]
pub fn shannon_byte_entropy_normalized(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.as_bytes() {
        counts[usize::from(*b)] += 1;
    }
    let n = s.len() as f64;
    let mut h = 0.0_f64;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / n;
        h -= p * p.log2();
    }
    (h / 8.0).clamp(0.0, 1.0)
}

#[derive(Clone)]
pub struct GenerativeLlmConfig {
    pub base_url: String,
    pub model: String,
    pub temperature: f64,
    pub max_tokens: u32,
    pub tenant_id: Option<i64>,
}

impl GenerativeLlmConfig {
    #[must_use]
    pub fn from_env(tenant_id: Option<i64>) -> Self {
        let base_url = std::env::var("WEISSMAN_LLM_BASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_LLM_BASE_URL.to_string());
        let model = openai_chat::resolve_llm_model("");
        let temperature = std::env::var("WEISSMAN_GENERATIVE_FUZZ_TEMPERATURE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.55_f64)
            .clamp(0.0, 1.5);
        let max_tokens: u32 = std::env::var("WEISSMAN_GENERATIVE_FUZZ_MAX_TOKENS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4096)
            .clamp(512, 16_384);
        Self {
            base_url: openai_chat::normalize_openai_base_url(&base_url),
            model,
            temperature,
            max_tokens,
            tenant_id,
        }
    }
}

const SYSTEM_INITIAL: &str = r#"You are a principal application security researcher performing authorized red-team fuzzing of systems under written contract.

Output ONLY a single JSON object with key "payloads" whose value is an array of strings. No markdown fences, no commentary before or after JSON.

Each string must be a raw HTTP POST body exactly as sent on the wire. Cover: JSON objects/arrays (nested keys, unicode escapes, parser differentials), XML/SOAP-style fragments (elements, CDATA, entity-like patterns where safe), application/x-www-form-urlencoded and complex query-string shapes (repeated keys, bracket notation, semicolon separators, mixed encoding), and plain text. Include diverse classes: SQLi, NoSQLi, XSS, SSRF, path traversal, deserialization, command injection, LDAP, SSTI, JWT confusion, encoding/Unicode bypasses.

When the operator supplies a base payload, preserve its wire format (JSON stays JSON-shaped; XML stays tag-balanced enough to parse; form stays &-joined pairs) while escalating malicious content.

This is licensed security testing in an isolated lab."#;

const SYSTEM_BYPASS: &str = r#"You are bypassing WAFs and application filters in an authorized penetration test.

Before you emit payloads, briefly reason about what class of ruleset or parser is likely blocking traffic from the HTTP status and response_excerpt (e.g. ModSecurity/CRS, JSON field filter, XML bomb protection, rate limit, bot manager, custom ACL, Cloudflare/Akamai hints). Let that inference drive encoding and structure choices.

Output ONLY JSON: {"payloads":["..."]} with raw POST body strings. No markdown, no chain-of-thought outside that implicit reasoning. Propose variants that evade the specific block signal while preserving attack intent. If the block page suggests a WAF or JSON/XML/query parser, tailor encodings and structure (nested JSON, XML wrappers, split query params, transfer encodings, Unicode normalisation) accordingly.

When the user message includes an "Attempt memory" section, treat it as authoritative telemetry: it lists prior mutation classes and whether they were blocked at the edge or rejected locally for malformed syntax — pivot away from repeated failures (e.g. if hex and unicode escapes were blocked, try chunked framing, case folding, key reordering, parser differentials, or alternate wire shapes)."#;

fn tech_stack_line(hint: &str) -> String {
    let t = hint.trim();
    if t.is_empty() {
        "Technology stack: infer cautiously from URL path, file extensions, and base payload shape.".to_string()
    } else {
        format!("Technology stack hints from operator: {t}")
    }
}

fn json_implied_by_context(tech_stack: &str, base_payload: &str) -> bool {
    let t = tech_stack.to_lowercase();
    if t.contains("json") || t.contains("application/json") {
        return true;
    }
    let b = base_payload.trim_start();
    b.starts_with('{') || b.starts_with('[')
}

fn xml_implied_by_context(tech_stack: &str, base_payload: &str) -> bool {
    let t = tech_stack.to_lowercase();
    if t.contains("xml") || t.contains("soap") || t.contains("application/xml") {
        return true;
    }
    base_payload.trim_start().starts_with('<')
}

/// Lightweight scan: stream must parse without hard errors and include at least one element.
fn basic_xml_wire_ok(s: &str) -> bool {
    let t = s.trim();
    if !t.starts_with('<') {
        return false;
    }
    let mut r = Reader::from_str(t);
    r.trim_text(true);
    let mut saw_element = false;
    for _ in 0..8192 {
        match r.read_event() {
            Ok(Event::Start(_) | Event::Empty(_)) => saw_element = true,
            Ok(Event::Eof) => return saw_element,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    saw_element
}

/// Drop malformed wire shapes before HTTP to save probes and avoid tripping parser-stage WAFs.
#[must_use]
pub fn preflight_payload(tech_stack: &str, base_payload: &str, payload: &str) -> Result<(), String> {
    let p = payload.trim();
    if json_implied_by_context(tech_stack, base_payload) {
        if !(p.starts_with('{') || p.starts_with('[')) {
            return Err("expected_JSON_body_under_tech_or_base_shape".into());
        }
        serde_json::from_str::<serde_json::Value>(p)
            .map_err(|e| format!("json_syntax:{e}"))?;
        return Ok(());
    }
    if xml_implied_by_context(tech_stack, base_payload) {
        if !p.starts_with('<') {
            return Err("expected_XML_body_under_tech_or_base_shape".into());
        }
        if !basic_xml_wire_ok(p) {
            return Err("xml_syntax:ill_formed_stream".into());
        }
        return Ok(());
    }
    if p.starts_with('{') || p.starts_with('[') {
        serde_json::from_str::<serde_json::Value>(p)
            .map_err(|e| format!("json_syntax:{e}"))?;
    } else if p.starts_with('<') && !basic_xml_wire_ok(p) {
        return Err("xml_syntax:ill_formed_stream".into());
    }
    Ok(())
}

fn wire_class_label(tech_stack: &str, base_payload: &str, payload: &str) -> &'static str {
    let p = payload.trim();
    if p.starts_with('{') || p.starts_with('[') {
        "JSON"
    } else if p.starts_with('<') {
        "XML"
    } else if p.contains('&') && p.contains('=') {
        "form_like"
    } else if json_implied_by_context(tech_stack, base_payload) {
        "JSON_expected"
    } else if xml_implied_by_context(tech_stack, base_payload) {
        "XML_expected"
    } else {
        "text"
    }
}

fn push_attempt_memory(memory: &mut Vec<String>, line: String, cap: usize) {
    memory.push(line);
    while memory.len() > cap {
        memory.remove(0);
    }
}

fn adrenaline_effective_temperature(baseline: f64, streak: u32) -> f64 {
    let b = baseline.clamp(0.0, 1.5).max(0.05);
    let s = streak.min(ADRENALINE_STREAK_CAP);
    let t = b * ADRENALINE_MULT_PER_STREAK.powi(s as i32);
    t.min(ADRENALINE_MAX_TEMP).min(1.5)
}

#[must_use]
pub fn build_initial_user_message(
    target_url: &str,
    base_payload: &str,
    tech_stack: &str,
    cognitive_osint: &str,
) -> String {
    let oast = crate::fuzz_oob::oast_operator_prompt_hint();
    let oast_block = if oast.is_empty() {
        String::new()
    } else {
        format!("\n\n{oast}")
    };
    let cog = if cognitive_osint.trim().is_empty() {
        String::new()
    } else {
        format!(
            "\n\n## COGNITIVE / OSINT WEIGHTING (authorized recon)\nPrioritize tokens, path segments, JSON keys, and form fields that align with:\n{}\n",
            cognitive_osint.chars().take(4000).collect::<String>()
        )
    };
    format!(
        "{}{}{oast_block}\n\nTarget URL (HTTP POST): {}\nBase payload to evolve (verbatim):\n```\n{}\n```\n\nGenerate 16–28 distinct payloads in the JSON array.",
        tech_stack_line(tech_stack),
        cog,
        target_url,
        base_payload
    )
}

#[must_use]
pub fn build_followup_user_message(
    target_url: &str,
    base_payload: &str,
    tech_stack: &str,
    attempt_memory: &[String],
    cognitive_osint: &str,
) -> String {
    let mem = if attempt_memory.is_empty() {
        "(no structured memory yet — diversify broadly.)".to_string()
    } else {
        attempt_memory.join("\n")
    };
    let oast = crate::fuzz_oob::oast_operator_prompt_hint();
    let oast_block = if oast.is_empty() {
        String::new()
    } else {
        format!("\n\n{oast}")
    };
    let cog = if cognitive_osint.trim().is_empty() {
        String::new()
    } else {
        format!(
            "\n\n## COGNITIVE / OSINT WEIGHTING\nContinue to bias mutations toward:\n{}\n",
            cognitive_osint.chars().take(3000).collect::<String>()
        )
    };
    format!(
        "{}{}{oast_block}\n\nTarget: {}\nBase payload:\n```\n{}\n```\n\n## Attempt memory (structured — use to pivot tactics; do not blindly repeat failed classes)\n{}\n\nGenerate 14–26 NEW payloads as JSON only. Each line above states payload shape, local validation outcome, and short context.",
        tech_stack_line(tech_stack),
        cog,
        target_url,
        base_payload,
        mem
    )
}

#[must_use]
pub fn build_bypass_user_message(
    target_url: &str,
    blocked_payload: &str,
    http_status: u16,
    response_excerpt: &str,
    attempt_memory: &[String],
    entropy_collapse: bool,
    cognitive_osint: &str,
) -> String {
    let mem = if attempt_memory.is_empty() {
        String::new()
    } else {
        format!(
            "\n\n## Attempt memory (recent mutation classes & outcomes)\n{}\n",
            attempt_memory.join("\n")
        )
    };
    let pivot = if entropy_collapse {
        "\n\nTelemetry: successive blocked responses show **decreasing Shannon entropy** (errors homogenizing). Pivot away from the last encoding/parser class; try different attack families, framing, and wire shapes — not more of the same mutations.\n"
    } else {
        ""
    };
    let cog = if cognitive_osint.trim().is_empty() {
        String::new()
    } else {
        format!(
            "\n\n## COGNITIVE / OSINT (bias bypass tokens)\n{}\n",
            cognitive_osint.chars().take(2500).collect::<String>()
        )
    };
    format!(
        "Target POST URL: {}\nHTTP status from target: {}\nBody that was blocked or rejected:\n```\n{}\n```\n\nResponse excerpt:\n```\n{}\n```{}{}{}\nInfer likely WAF/parser behaviour from the excerpt, then generate 8–16 bypass-oriented variants. JSON only.",
        target_url,
        http_status,
        blocked_payload.chars().take(8000).collect::<String>(),
        response_excerpt.chars().take(6000).collect::<String>(),
        mem,
        pivot,
        cog
    )
}

#[must_use]
pub fn build_injection_url_user_message(
    target_url: &str,
    tech_stack: &str,
    cognitive_osint: &str,
) -> String {
    let cog = if cognitive_osint.trim().is_empty() {
        String::new()
    } else {
        format!(
            "\n\n## COGNITIVE / OSINT (bias parameter names and path tokens)\n{}\n",
            cognitive_osint.chars().take(2500).collect::<String>()
        )
    };
    format!(
        "{}\n\nTarget base URL for GET fuzzing: {}{}\n\nReturn JSON {{\"urls\":[\"https://...\"]}} with up to 96 distinct absolute URLs. Vary query parameter names and values (SQLi, XSS, SSRF, open redirect, LFI). Each URL must be a single string starting with http:// or https://.",
        tech_stack_line(tech_stack),
        target_url,
        cog
    )
}

fn strip_code_fence(s: &str) -> String {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("```") {
        let mut lines = rest.lines();
        let first = lines.next().unwrap_or("");
        let body: String = if first.trim_start().starts_with('{') {
            format!("{}\n{}", first, lines.collect::<Vec<_>>().join("\n"))
        } else {
            lines.collect::<Vec<_>>().join("\n")
        };
        let body = body.trim();
        if let Some(idx) = body.rfind("```") {
            body[..idx].trim().to_string()
        } else {
            body.to_string()
        }
    } else {
        t.to_string()
    }
}

#[must_use]
pub fn parse_payloads_json(text: &str) -> Result<Vec<String>, String> {
    let cleaned = strip_code_fence(text);
    let v: serde_json::Value =
        serde_json::from_str(&cleaned).map_err(|e| format!("json: {e}"))?;
    let arr = v
        .get("payloads")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "missing payloads array".to_string())?;
    let mut out = Vec::new();
    for item in arr {
        if let Some(ps) = item.as_str() {
            let p = ps.trim();
            if !p.is_empty() && p.len() <= 512_000 {
                out.push(p.to_string());
            }
        }
    }
    if out.is_empty() {
        return Err("empty payloads array".into());
    }
    Ok(out)
}

#[must_use]
pub fn parse_urls_json(text: &str) -> Result<Vec<String>, String> {
    let cleaned = strip_code_fence(text);
    let v: serde_json::Value =
        serde_json::from_str(&cleaned).map_err(|e| format!("json: {e}"))?;
    let arr = v
        .get("urls")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "missing urls array".to_string())?;
    let mut out = Vec::new();
    for item in arr {
        if let Some(u) = item.as_str() {
            let t = u.trim();
            if (t.starts_with("http://") || t.starts_with("https://")) && t.len() <= 16_384 {
                out.push(t.to_string());
            }
        }
    }
    if out.is_empty() {
        return Err("empty urls".into());
    }
    Ok(out)
}

pub async fn llm_completion(
    client: &reqwest::Client,
    cfg: &GenerativeLlmConfig,
    system: &str,
    user: &str,
    operation: &'static str,
) -> Result<String, LlmError> {
    openai_chat::chat_completion_text(
        client,
        &cfg.base_url,
        &cfg.model,
        Some(system),
        user,
        cfg.temperature,
        cfg.max_tokens,
        cfg.tenant_id,
        operation,
        true,
    )
    .await
}

pub async fn fetch_initial_batch(
    client: &reqwest::Client,
    cfg: &GenerativeLlmConfig,
    target_url: &str,
    base_payload: &str,
    tech_stack: &str,
    cognitive_osint: &str,
) -> Result<Vec<GenerativeMutation>, LlmError> {
    let user = build_initial_user_message(target_url, base_payload, tech_stack, cognitive_osint);
    let text = llm_completion(
        client,
        cfg,
        SYSTEM_INITIAL,
        &user,
        "generative_fuzz_batch",
    )
    .await?;
    let payloads = parse_payloads_json(&text).map_err(LlmError::Decode)?;
    Ok(payloads
        .into_iter()
        .map(|payload| GenerativeMutation {
            payload,
            llm_user_prompt: user.clone(),
        })
        .collect())
}

pub async fn fetch_followup_batch(
    client: &reqwest::Client,
    cfg: &GenerativeLlmConfig,
    target_url: &str,
    base_payload: &str,
    tech_stack: &str,
    attempt_memory: &[String],
    cognitive_osint: &str,
) -> Result<Vec<GenerativeMutation>, LlmError> {
    let user =
        build_followup_user_message(target_url, base_payload, tech_stack, attempt_memory, cognitive_osint);
    let text = llm_completion(
        client,
        cfg,
        SYSTEM_INITIAL,
        &user,
        "generative_fuzz_followup",
    )
    .await?;
    let payloads = parse_payloads_json(&text).map_err(LlmError::Decode)?;
    Ok(payloads
        .into_iter()
        .map(|payload| GenerativeMutation {
            payload,
            llm_user_prompt: user.clone(),
        })
        .collect())
}

pub async fn fetch_bypass_batch(
    client: &reqwest::Client,
    cfg: &GenerativeLlmConfig,
    target_url: &str,
    fb: &BlockFeedback,
    attempt_memory: &[String],
    entropy_collapse: bool,
    cognitive_osint: &str,
) -> Result<Vec<GenerativeMutation>, LlmError> {
    let user = build_bypass_user_message(
        target_url,
        &fb.blocked_payload,
        fb.http_status,
        &fb.response_excerpt,
        attempt_memory,
        entropy_collapse,
        cognitive_osint,
    );
    let text = llm_completion(client, cfg, SYSTEM_BYPASS, &user, "generative_fuzz_bypass").await?;
    let payloads = parse_payloads_json(&text).map_err(LlmError::Decode)?;
    Ok(payloads
        .into_iter()
        .map(|payload| GenerativeMutation {
            payload,
            llm_user_prompt: user.clone(),
        })
        .collect())
}

pub async fn fetch_injection_urls(
    client: &reqwest::Client,
    cfg: &GenerativeLlmConfig,
    target_url: &str,
    tech_stack: &str,
    cognitive_osint: &str,
) -> Result<(Vec<String>, String), LlmError> {
    let user = build_injection_url_user_message(target_url, tech_stack, cognitive_osint);
    let text = llm_completion(
        client,
        cfg,
        SYSTEM_INITIAL,
        &user,
        "generative_fuzz_injection_urls",
    )
    .await?;
    let urls = parse_urls_json(&text).map_err(LlmError::Decode)?;
    Ok((urls, user))
}

/// Keeps the mutation channel filled while HTTP workers consume; prioritizes WAF feedback bypass generations.
pub async fn run_generative_producer_loop(
    tx: mpsc::Sender<GenerativeMutation>,
    mut feedback_rx: mpsc::UnboundedReceiver<BlockFeedback>,
    stop: Arc<AtomicBool>,
    http: reqwest::Client,
    mut cfg: GenerativeLlmConfig,
    chan_cap: usize,
    low_water: usize,
    target_url: String,
    base_payload: String,
    tech_stack: String,
    cognitive_osint: String,
) {
    const MEM_CAP: usize = 40;
    let baseline_temp = cfg.temperature.clamp(0.0, 1.5);
    let mut block_streak: u32 = 0;
    let mut last_bypass_at: Option<Instant> = None;
    let mut attempt_memory: Vec<String> = Vec::new();
    let mut prev_block_entropy: Option<f64> = None;
    let entropy_drop_eps: f64 = std::env::var("WEISSMAN_FUZZ_ENTROPY_DROP_EPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.04_f64)
        .max(0.0);

    let mut first_batch = true;
    let mut feedback_queue: VecDeque<BlockFeedback> = VecDeque::new();

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        if let Some(t0) = last_bypass_at {
            if block_streak > 0 && t0.elapsed() >= Duration::from_secs(ADRENALINE_DECAY_SECS) {
                block_streak = block_streak.saturating_sub(1);
                if block_streak == 0 {
                    last_bypass_at = None;
                } else {
                    last_bypass_at = Some(Instant::now());
                }
            }
        }
        cfg.temperature = adrenaline_effective_temperature(baseline_temp, block_streak);

        while let Ok(fb) = feedback_rx.try_recv() {
            if feedback_queue.len() < 32 {
                feedback_queue.push_back(fb);
            }
        }

        if let Some(fb) = feedback_queue.pop_front() {
            block_streak = (block_streak + 1).min(ADRENALINE_STREAK_CAP);
            last_bypass_at = Some(Instant::now());
            cfg.temperature = adrenaline_effective_temperature(baseline_temp, block_streak);

            let prev_e = prev_block_entropy;
            let entropy_collapse = prev_e
                .map(|p| fb.response_entropy + entropy_drop_eps < p)
                .unwrap_or(false);
            prev_block_entropy = Some(fb.response_entropy);
            if entropy_collapse {
                if let Some(p) = prev_e {
                    push_attempt_memory(
                        &mut attempt_memory,
                        format!(
                            "• ENTROPY: blocked-response Shannon dropped ({p:.3} → {:.3}) — pivot structural/parser class.",
                            fb.response_entropy
                        ),
                        MEM_CAP,
                    );
                }
            }

            match fetch_bypass_batch(
                &http,
                &cfg,
                &target_url,
                &fb,
                &attempt_memory,
                entropy_collapse,
                &cognitive_osint,
            )
            .await
            {
                Ok(batch) => {
                    for m in batch {
                        let pre = preflight_payload(&tech_stack, &base_payload, &m.payload);
                        let cls = wire_class_label(&tech_stack, &base_payload, &m.payload);
                        let line = match &pre {
                            Ok(()) => format!(
                                "• [{cls}] BYPASS batch: ACCEPTED — local wire OK; queued for HTTP probe."
                            ),
                            Err(e) => format!(
                                "• [{cls}] BYPASS batch: REJECTED locally ({e}) — not sent; snippet=\"{}\"",
                                m.payload.chars().take(72).collect::<String>()
                            ),
                        };
                        push_attempt_memory(&mut attempt_memory, line, MEM_CAP);
                        if pre.is_err() {
                            continue;
                        }
                        if tx.send(m).await.is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    warn!(target: "generative_fuzz", "bypass LLM batch failed: {}", e);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
            continue;
        }

        let remaining = tx.capacity();
        if remaining > chan_cap.saturating_sub(low_water) {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }

        let use_initial = first_batch;
        let res = if use_initial {
            fetch_initial_batch(
                &http,
                &cfg,
                &target_url,
                &base_payload,
                &tech_stack,
                &cognitive_osint,
            )
            .await
        } else {
            fetch_followup_batch(
                &http,
                &cfg,
                &target_url,
                &base_payload,
                &tech_stack,
                &attempt_memory,
                &cognitive_osint,
            )
            .await
        };

        match res {
            Ok(batch) => {
                if use_initial {
                    first_batch = false;
                }

                let mut any_sent = false;
                for m in batch {
                    let pre = preflight_payload(&tech_stack, &base_payload, &m.payload);
                    let cls = wire_class_label(&tech_stack, &base_payload, &m.payload);
                    let line = match &pre {
                        Ok(()) => format!(
                            "• [{cls}] Mutation batch: ACCEPTED — local wire OK; queued for HTTP."
                        ),
                        Err(e) => format!(
                            "• [{cls}] Mutation batch: REJECTED locally ({e}) — not sent; snippet=\"{}\"",
                            m.payload.chars().take(72).collect::<String>()
                        ),
                    };
                    push_attempt_memory(&mut attempt_memory, line, MEM_CAP);
                    if pre.is_err() {
                        continue;
                    }
                    if tx.send(m).await.is_err() {
                        return;
                    }
                    any_sent = true;
                }

                if any_sent {
                    block_streak = 0;
                    last_bypass_at = None;
                    cfg.temperature = baseline_temp;
                }
            }
            Err(e) => {
                warn!(target: "generative_fuzz", "LLM mutation batch failed: {}", e);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

#[must_use]
pub fn generative_fuzz_channel_capacity() -> usize {
    std::env::var("WEISSMAN_GENERATIVE_FUZZ_CHANNEL_CAP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(256)
        .clamp(32, 2048)
}

#[must_use]
pub fn generative_fuzz_low_water(chan_cap: usize) -> usize {
    let w: usize = std::env::var("WEISSMAN_GENERATIVE_FUZZ_LOW_WATER")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(56)
        .clamp(8, chan_cap.saturating_sub(4).max(8));
    w.min(chan_cap.saturating_sub(1).max(8))
}

#[must_use]
pub fn generative_max_post_probes() -> usize {
    std::env::var("WEISSMAN_GENERATIVE_FUZZ_MAX_POST_PROBES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(640)
        .clamp(32, 50_000)
}

#[must_use]
pub fn tech_stack_hint() -> String {
    std::env::var("WEISSMAN_FUZZ_TECH_STACK")
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_json_context_enforces_parse() {
        let err = preflight_payload("application/json", "{}", "{\"a\":1,").unwrap_err();
        assert!(err.contains("json_syntax"), "{err}");
        preflight_payload("application/json", "{}", r#"{"ok":true}"#).unwrap();
    }

    #[test]
    fn preflight_self_detects_json_body() {
        preflight_payload("", "foo=1", r#"["x"]"#).unwrap();
        assert!(preflight_payload("", "foo=1", "{\"bad\"").is_err());
    }

    #[test]
    fn adrenaline_caps_at_1_1() {
        let t = adrenaline_effective_temperature(0.5, 100);
        assert!((t - ADRENALINE_MAX_TEMP).abs() < 0.001, "t={t}");
    }
}
