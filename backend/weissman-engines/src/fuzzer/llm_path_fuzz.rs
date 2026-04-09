//! LLM-assisted path fuzzing via OpenAI-compatible API (local vLLM).

use async_trait::async_trait;
use futures::stream::{self, StreamExt};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::context::{EngineRunOutcome, ScanContext};
use crate::engine_trait::CyberEngine;
use crate::openai_chat::{chat_completion_text, llm_http_client, resolve_llm_model};
use crate::result::EngineResult;
use crate::stealth;

const TARGET_TIMEOUT_SECS: u64 = 5;
const LLM_TIMEOUT_SECS: u64 = 38;
const MAX_PAYLOADS: usize = 32;
/// In-flight HTTP fuzz probes (URLs × payloads); bounded to avoid ephemeral port exhaustion.
const FUZZ_HTTP_CONCURRENCY: usize = 56;
const MAX_COMPLETION_TOKENS: u32 = 512;
const LENGTH_DEVIATION_PCT: f64 = 15.0;
const TIMING_ANOMALY_SECS: u64 = 2;

async fn client_insecure_default() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(TARGET_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn apply_stealth_headers(
    req: reqwest::RequestBuilder,
    st: Option<&stealth::StealthConfig>,
) -> reqwest::RequestBuilder {
    match st {
        Some(s) => req.headers(stealth::random_morph_headers(s)),
        None => req,
    }
}

fn normalize_url(target: &str) -> String {
    let target = target.trim();
    if target.is_empty() {
        return String::new();
    }
    if target.starts_with("http://") || target.starts_with("https://") {
        return target.to_string();
    }
    format!("https://{}", target)
}

fn build_url_list(targets: &[String], paths: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if targets.is_empty() {
        return out;
    }
    for base in targets {
        let base = normalize_url(base);
        if base.is_empty() {
            continue;
        }
        let base = base.trim_end_matches('/').to_string();
        if paths.is_empty() {
            out.push(base);
            continue;
        }
        for path in paths {
            let p = path.trim();
            let url = if p.is_empty() || p == "/" {
                base.clone()
            } else {
                let path_norm = p.trim_start_matches('/');
                format!("{}/{}", base, path_norm)
            };
            if !out.contains(&url) {
                out.push(url);
            }
        }
    }
    if out.is_empty() {
        for base in targets {
            let b = normalize_url(base);
            if !b.is_empty() {
                out.push(b.trim_end_matches('/').to_string());
                break;
            }
        }
    }
    out
}

/// Single-target entry (orchestrator compatibility).
pub async fn run_llm_path_fuzz_result(
    target: &str,
    st: Option<&stealth::StealthConfig>,
    llm_base_url: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> EngineResult {
    let targets = if target.is_empty() {
        vec![]
    } else {
        vec![target.to_string()]
    };
    run_llm_path_fuzz_result_multi(&targets, &[], st, llm_base_url, llm_model, llm_tenant_id).await
}

/// Path-aware multi-target fuzzing using vLLM `/v1/chat/completions`.
pub async fn run_llm_path_fuzz_result_multi(
    targets: &[String],
    paths: &[String],
    st: Option<&stealth::StealthConfig>,
    llm_base_url: &str,
    llm_model_config: &str,
    llm_tenant_id: Option<i64>,
) -> EngineResult {
    let targets = targets.to_vec();
    let paths = paths.to_vec();
    let llm_base_url = llm_base_url.to_string();
    let llm_model_config = llm_model_config.to_string();
    let st_owned: Option<stealth::StealthConfig> = st.cloned();
    let st_ref = st_owned.as_ref();

    let urls = build_url_list(&targets, &paths);
    if urls.is_empty() {
        return EngineResult::error("target required");
    }

    let c_in = match st_ref {
        Some(s) => {
            stealth::apply_jitter(s);
            stealth::build_client(s, TARGET_TIMEOUT_SECS)
        }
        None => client_insecure_default().await,
    };
    let c_llm = llm_http_client(LLM_TIMEOUT_SECS);
    let model = resolve_llm_model(llm_model_config.as_str());

    let first_url = urls.first().cloned().unwrap_or_default();
    let req = apply_stealth_headers(c_in.get(&first_url), st_ref);
    let (baseline_status, baseline_len) = match req.send().await {
        Ok(r) => (
            r.status().as_u16(),
            r.bytes().await.map(|b| b.len()).unwrap_or(0),
        ),
        Err(_) => (0, 0),
    };

    let context = match apply_stealth_headers(c_in.get(&first_url), st_ref)
        .send()
        .await
    {
        Ok(r) => {
            let headers: String = r
                .headers()
                .iter()
                .take(12)
                .map(|(k, v)| format!("{}: {:?}", k.as_str(), v))
                .collect();
            let body = r.text().await.unwrap_or_default();
            format!(
                "Headers:\n{}\n\nBody:\n{}",
                headers,
                body.chars().take(1500).collect::<String>()
            )
        }
        Err(e) => format!("Target unreachable: {}", e),
    };

    let user_prompt = format!(
        "You are a security fuzzer. Given this HTTP response from {}:\n{}\n\nOutput ONLY a list of fuzzing payloads, one per line, for XSS, SQLi, or path traversal. No explanation. Max 25 lines. Examples: <script>alert(1)</script>, ' OR 1=1--, ../../../etc/passwd",
        first_url, context
    );

    let text = chat_completion_text(
        &c_llm,
        llm_base_url.as_str(),
        model.as_str(),
        Some("You assist authorized security testing. Follow the user format exactly."),
        &user_prompt,
        0.4,
        MAX_COMPLETION_TOKENS,
        llm_tenant_id,
        "llm_path_fuzz",
        true,
    )
    .await
    .unwrap_or_default();

    let mut payloads: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.len() > 2000
            || line.starts_with('#')
            || line.starts_with("//")
        {
            continue;
        }
        payloads.push(line.to_string());
        if payloads.len() >= MAX_PAYLOADS {
            break;
        }
    }

    if payloads.is_empty() {
        return EngineResult::ok(
            vec![],
            "LLM unreachable or no payloads; ensure vLLM is running and llm_model / llm_base_url are set",
        );
    }

    let num_payloads = payloads.len();
    let c_in = Arc::new(c_in);
    let bs = baseline_status;
    let bl = baseline_len;
    let mut tasks = Vec::new();
    for url in &urls {
        for payload in &payloads {
            let url = url.clone();
            let payload = payload.clone();
            let c_in = Arc::clone(&c_in);
            let st = st_owned.clone();
            tasks.push(async move {
                if let Some(ref s) = st {
                    stealth::apply_jitter(s);
                }
                let sep = if url.contains('?') { "&" } else { "?" };
                let encoded = urlencoding::encode(&payload);
                let full_url = format!("{}{}q={}", url, sep, encoded);
                let req = apply_stealth_headers(c_in.get(&full_url), st.as_ref());
                let start = Instant::now();
                match req.send().await {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        let body_bytes = r.bytes().await.unwrap_or_default();
                        let len = body_bytes.len();
                        let body_str = String::from_utf8_lossy(&body_bytes);
                        let elapsed_secs = start.elapsed().as_secs();

                        let mut reasons = Vec::<&str>::new();
                        if bs != 0 && status != bs {
                            reasons.push("status_change");
                        }
                        if bl > 0 && len as f64 > 0.0 {
                            let deviation_pct =
                                ((len as f64 - bl as f64).abs() / bl as f64) * 100.0;
                            if deviation_pct > LENGTH_DEVIATION_PCT {
                                reasons.push("length_deviation");
                            }
                        }
                        if payload.len() <= 500 && body_str.contains(payload.as_str()) {
                            reasons.push("reflected_payload");
                        }
                        if elapsed_secs >= TIMING_ANOMALY_SECS {
                            reasons.push("timing_anomaly");
                        }

                        if reasons.is_empty() && bs != 0 && status == bs && bl > 0 {
                            let deviation_pct =
                                ((len as f64 - bl as f64).abs() / bl as f64) * 100.0;
                            if deviation_pct > LENGTH_DEVIATION_PCT {
                                reasons.push("length_deviation");
                            }
                        }

                        if !reasons.is_empty() || status >= 500 || (bs == 0 && status > 0) {
                            let severity =
                                if status >= 500 || reasons.contains(&"reflected_payload") {
                                    "high"
                                } else if reasons.contains(&"status_change")
                                    || reasons.contains(&"timing_anomaly")
                                {
                                    "medium"
                                } else {
                                    "low"
                                };
                            Some(json!({
                                "type": "llm_path_fuzz",
                                "url": url,
                                "payload": payload.chars().take(200).collect::<String>(),
                                "status": status,
                                "baseline_status": bs,
                                "length": len,
                                "baseline_length": bl,
                                "elapsed_secs": elapsed_secs,
                                "anomaly_reasons": reasons,
                                "severity": severity,
                                "title": format!("Fuzz anomaly: {} ({})", reasons.join(", "), if body_str.contains(payload.as_str()) { "reflected" } else { "behavioral" })
                            }))
                        } else {
                            None
                        }
                    }
                    Err(_) => Some(json!({
                        "type": "llm_path_fuzz",
                        "url": url,
                        "payload": payload.chars().take(100).collect::<String>(),
                        "error": "request_failed",
                        "severity": "medium",
                        "title": "Fuzz request failed (timeout or connection error)"
                    })),
                }
            });
        }
    }
    let rows: Vec<Option<serde_json::Value>> = stream::iter(tasks)
        .map(|fut| fut)
        .buffer_unordered(FUZZ_HTTP_CONCURRENCY)
        .collect()
        .await;
    let findings: Vec<serde_json::Value> = rows.into_iter().flatten().collect();

    let msg = format!(
        "LLM path fuzz: {} URLs, {} payloads, {} anomalies (universal persistence)",
        urls.len(),
        num_payloads,
        findings.len()
    );
    EngineResult::ok(findings, msg)
}

pub struct LlmPathFuzzCyberEngine;

#[async_trait]
impl CyberEngine for LlmPathFuzzCyberEngine {
    fn engine_id(&self) -> &'static str {
        "llm_path_fuzz"
    }

    fn display_label(&self) -> &'static str {
        "LLM Path Fuzz (vLLM)"
    }

    async fn execute(&self, ctx: &ScanContext) -> EngineRunOutcome {
        let base = ctx.llm_base_resolved();
        let r = run_llm_path_fuzz_result_multi(
            &ctx.target_list,
            &ctx.discovered_paths,
            ctx.stealth.as_ref(),
            base,
            ctx.semantic.llm_model.as_str(),
            ctx.llm_tenant_id,
        )
        .await;
        EngineRunOutcome::with_result(r)
    }
}
