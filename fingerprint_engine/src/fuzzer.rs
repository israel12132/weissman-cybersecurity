//! Feedback-driven API fuzzing: mutate inputs, measure response time / status / content-length,
//! detect anomalies (potential zero-days). Highly concurrent with a global rate limiter and
//! bounded in-flight probes; optional OAST/OOB correlation. Default mutation source is **vLLM**
//! (`WEISSMAN_LLM_BASE_URL`); set `WEISSMAN_GENERATIVE_FUZZ=0` for legacy static mutations.

use crate::fuzz_http_pool::FuzzHttpPool;
use crate::fuzz_oob::{inject_oob_token, oast_correlation_enabled, verify_oob_token_seen};
use crate::generative_fuzz_llm::{
    self, BlockFeedback, GenerativeLlmConfig, GenerativeMutation,
};
use fuzz_core::{
    append_query_param, build_param_injection_probe_urls, is_anomaly,
    load_guided_payloads_from_file, looks_like_sqli_response, reflected_xss_indicated,
    resolve_mutations, BASELINE_REQUESTS, RATE_LIMIT_DELAY_MS, TIME_ANOMALY_MULTIPLIER,
};
use futures::stream::{FuturesUnordered, StreamExt};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tracing::{error, warn};

pub use fuzz_core::{Baseline, Mutator, ValidatedAnomaly};

#[must_use]
pub fn generative_legacy_mode() -> bool {
    matches!(
        std::env::var("WEISSMAN_GENERATIVE_FUZZ").as_deref(),
        Ok("0") | Ok("false") | Ok("off")
    )
}

fn probe_suggests_waf_block(status: u16, body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    matches!(status, 401 | 403 | 405 | 406 | 429 | 503)
        || b.contains("waf")
        || b.contains("blocked")
        || b.contains("forbidden")
        || b.contains("cloudflare")
        || b.contains("akamai")
        || b.contains("request rejected")
        || b.contains("not acceptable")
        || b.contains("access denied")
}

fn fuzz_max_in_flight() -> usize {
    std::env::var("WEISSMAN_FUZZ_MAX_IN_FLIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .clamp(8, 100)
}

fn new_fuzz_rate_limiter() -> Arc<DefaultDirectRateLimiter> {
    let rps: u32 = std::env::var("WEISSMAN_FUZZ_GLOBAL_RPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(45)
        .clamp(1, 500);
    let burst: u32 = std::env::var("WEISSMAN_FUZZ_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(rps.saturating_mul(2).max(20))
        .clamp(rps.min(1), 2000);
    let rps_nz = NonZeroU32::new(rps.max(1)).unwrap_or(NonZeroU32::MIN);
    let burst_nz = NonZeroU32::new(burst.max(1)).unwrap_or(NonZeroU32::MIN);
    Arc::new(RateLimiter::direct(
        Quota::per_second(rps_nz).allow_burst(burst_nz),
    ))
}

fn oast_max_probes(mutation_count: usize) -> usize {
    if !oast_correlation_enabled() {
        return 0;
    }
    let cap: usize = std::env::var("WEISSMAN_OAST_MAX_PROBES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64)
        .clamp(1, 256);
    cap.min(mutation_count)
}

async fn measure_request(
    pool: &FuzzHttpPool,
    url: &str,
    body: Option<&str>,
) -> Result<(u16, usize, f64), reqwest::Error> {
    let client = pool.client_for_probe();
    let start = std::time::Instant::now();
    let seq = crate::fuzz_http_pool::ghost_swarm_sequence(None);
    let req = client.post(url);
    let req = if crate::fuzz_http_pool::ghost_swarm_fingerprint_enabled() {
        crate::fuzz_http_pool::apply_ghost_swarm_headers(req, seq)
    } else {
        req.header(
            "User-Agent",
            crate::fuzz_http_pool::random_fuzz_user_agent(),
        )
    }
    .body(body.unwrap_or("").to_string());
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let body_bytes = resp.bytes().await.unwrap_or_default();
    let len = body_bytes.len();
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok((status, len, latency_ms))
}

async fn measure_request_get(
    pool: &FuzzHttpPool,
    url_with_query: &str,
) -> Result<(u16, usize, f64), reqwest::Error> {
    let client = pool.client_for_probe();
    let start = std::time::Instant::now();
    let seq = crate::fuzz_http_pool::ghost_swarm_sequence(None);
    let req = client.get(url_with_query);
    let req = if crate::fuzz_http_pool::ghost_swarm_fingerprint_enabled() {
        crate::fuzz_http_pool::apply_ghost_swarm_headers(req, seq)
    } else {
        req.header(
            "User-Agent",
            crate::fuzz_http_pool::random_fuzz_user_agent(),
        )
    };
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let body_bytes = resp.bytes().await.unwrap_or_default();
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok((status, body_bytes.len(), latency_ms))
}

async fn measure_request_get_with_body(
    pool: &FuzzHttpPool,
    url_with_query: &str,
) -> Result<(u16, usize, f64, String), reqwest::Error> {
    let client = pool.client_for_probe();
    let start = std::time::Instant::now();
    let seq = crate::fuzz_http_pool::ghost_swarm_sequence(None);
    let req = client.get(url_with_query);
    let req = if crate::fuzz_http_pool::ghost_swarm_fingerprint_enabled() {
        crate::fuzz_http_pool::apply_ghost_swarm_headers(req, seq)
    } else {
        req.header(
            "User-Agent",
            crate::fuzz_http_pool::random_fuzz_user_agent(),
        )
    };
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let body_bytes = resp.bytes().await.unwrap_or_default();
    let body_text = String::from_utf8_lossy(&body_bytes).into_owned();
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok((status, body_bytes.len(), latency_ms, body_text))
}

async fn measure_request_with_body(
    pool: &FuzzHttpPool,
    url: &str,
    body: Option<&str>,
) -> Result<(u16, usize, f64, String), reqwest::Error> {
    let client = pool.client_for_probe();
    let start = std::time::Instant::now();
    let seq = crate::fuzz_http_pool::ghost_swarm_sequence(None);
    let req = client.post(url);
    let req = if crate::fuzz_http_pool::ghost_swarm_fingerprint_enabled() {
        crate::fuzz_http_pool::apply_ghost_swarm_headers(req, seq)
    } else {
        req.header(
            "User-Agent",
            crate::fuzz_http_pool::random_fuzz_user_agent(),
        )
    }
    .body(body.unwrap_or("").to_string());
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let body_bytes = resp.bytes().await.unwrap_or_default();
    let len = body_bytes.len();
    let body_text = String::from_utf8_lossy(&body_bytes).into_owned();
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok((status, len, latency_ms, body_text))
}

async fn establish_baseline(
    pool: &FuzzHttpPool,
    target_url: &str,
    base_payload: &str,
) -> Option<Baseline> {
    let mut latencies = Vec::with_capacity(BASELINE_REQUESTS);
    let mut statuses = Vec::with_capacity(BASELINE_REQUESTS);
    let mut lengths = Vec::with_capacity(BASELINE_REQUESTS);

    for _ in 0..BASELINE_REQUESTS {
        tokio::time::sleep(std::time::Duration::from_millis(RATE_LIMIT_DELAY_MS)).await;
        match measure_request(pool, target_url, Some(base_payload)).await {
            Ok((status, len, lat_ms)) => {
                statuses.push(status);
                lengths.push(len);
                latencies.push(lat_ms);
            }
            Err(_) => return None,
        }
    }

    let avg_latency = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let status = *statuses.first().unwrap_or(&200);
    let content_length = lengths.iter().sum::<usize>() / lengths.len().max(1);
    Some(Baseline {
        avg_latency_ms: avg_latency,
        status,
        content_length,
    })
}

async fn establish_baseline_get(pool: &FuzzHttpPool, target_url: &str) -> Option<Baseline> {
    let mut latencies = Vec::with_capacity(BASELINE_REQUESTS);
    let mut statuses = Vec::with_capacity(BASELINE_REQUESTS);
    let mut lengths = Vec::with_capacity(BASELINE_REQUESTS);
    for _ in 0..BASELINE_REQUESTS {
        tokio::time::sleep(std::time::Duration::from_millis(RATE_LIMIT_DELAY_MS)).await;
        if let Ok((status, len, lat_ms)) = measure_request_get(pool, target_url).await {
            statuses.push(status);
            lengths.push(len);
            latencies.push(lat_ms);
        } else {
            return None;
        }
    }
    let avg_latency = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let status = *statuses.first().unwrap_or(&200);
    let content_length = lengths.iter().sum::<usize>() / lengths.len().max(1);
    Some(Baseline {
        avg_latency_ms: avg_latency,
        status,
        content_length,
    })
}

fn truncate_for_log(s: &str, max: usize) -> String {
    let s = s.replace('\n', " ");
    if s.len() <= max {
        s
    } else {
        format!("{}...", &s[..max])
    }
}

async fn process_post_anomaly(
    pool: &FuzzHttpPool,
    target_url: &str,
    payload: &str,
    baseline: &Baseline,
    status: u16,
    content_length: usize,
    latency_ms: f64,
    anomaly: &str,
    signature_rules: &[crate::signatures::PayloadSignatureRule],
    oob_token: Option<String>,
    llm_user_prompt: Option<String>,
) -> Option<ValidatedAnomaly> {
    if let Some(rule) = crate::signatures::find_matching_rule(payload, signature_rules) {
        let (_, _, _, resp_body) =
            match measure_request_with_body(pool, target_url, Some(payload)).await {
                Ok(t) => t,
                Err(_) => return None,
            };
        if !crate::signatures::response_matches_signature(&resp_body, &rule.expected_signature) {
            return None;
        }
    }
    let baseline_vs = format!(
        "Baseline: status={}, content_length={}, latency_ms≈{:.0} | Anomaly: status={}, content_length={}, latency_ms={:.0}",
        baseline.status, baseline.content_length, baseline.avg_latency_ms,
        status, content_length, latency_ms
    );
    error!(
        "🚨 ZERO-DAY POTENTIAL DETECTED! Target: [{}] | Payload: [{}] | Anomaly: [{}]",
        target_url,
        truncate_for_log(payload, 200),
        anomaly
    );
    let high_confidence =
        status == 500 || latency_ms >= baseline.avg_latency_ms * TIME_ANOMALY_MULTIPLIER;
    if !high_confidence {
        return None;
    }
    let validation_baseline = crate::validator::ValidationBaseline {
        normal_status: baseline.status,
        avg_latency_ms: baseline.avg_latency_ms,
        content_length: baseline.content_length,
    };
    let confirmed =
        crate::validator::confirm_anomaly(target_url, anomaly, &validation_baseline).await;
    if !confirmed {
        return None;
    }
    crate::reporter::generate_bug_report(target_url, payload, anomaly, &baseline_vs);
    Some(ValidatedAnomaly {
        target_url: target_url.to_string(),
        payload: payload.to_string(),
        anomaly_type: anomaly.to_string(),
        baseline_vs_anomaly: baseline_vs,
        oob_token,
        llm_user_prompt,
    })
}

/// Concurrent POST mutation wave: same baseline for all probes; rate-limited + sem-bounded.
/// `jobs`: `(payload, optional vLLM user prompt provenance)`. When `feedback_tx` is set, response
/// bodies are read so WAF/blocks can be fed back to the generative producer.
async fn concurrent_post_mutation_wave(
    pool: Arc<FuzzHttpPool>,
    target_url: String,
    baseline: Baseline,
    jobs: Vec<(String, Option<String>)>,
    signature_rules: Arc<Vec<crate::signatures::PayloadSignatureRule>>,
    sem: Arc<Semaphore>,
    limiter: Arc<DefaultDirectRateLimiter>,
    feedback_tx: Option<mpsc::UnboundedSender<BlockFeedback>>,
) -> Vec<ValidatedAnomaly> {
    let mut collected = Vec::new();
    let mut futs = FuturesUnordered::new();
    for (payload, llm_prompt) in jobs {
        let p = pool.clone();
        let sem = sem.clone();
        let lim = limiter.clone();
        let rules = signature_rules.clone();
        let url = target_url.clone();
        let bl = baseline.clone();
        let fb = feedback_tx.clone();
        futs.push(async move {
            lim.until_ready().await;
            let _p = match sem.acquire().await {
                Ok(permit) => permit,
                Err(_) => return None,
            };
            let (status, content_length, latency_ms, body_text) = if fb.is_some() {
                match measure_request_with_body(p.as_ref(), &url, Some(&payload)).await {
                    Ok((a, b, c2, d)) => (a, b, c2, d),
                    Err(_) => return None,
                }
            } else {
                match measure_request(p.as_ref(), &url, Some(&payload)).await {
                    Ok((a, b, c2)) => (a, b, c2, String::new()),
                    Err(_) => return None,
                }
            };
            if let Some(ref ftx) = fb {
                if probe_suggests_waf_block(status, &body_text)
                    && is_anomaly(&bl, status, content_length, latency_ms).is_none()
                {
                    let excerpt: String = body_text.chars().take(4000).collect();
                    let response_entropy =
                        generative_fuzz_llm::shannon_byte_entropy_normalized(&excerpt);
                    let _ = ftx.send(BlockFeedback {
                        blocked_payload: payload.clone(),
                        http_status: status,
                        response_excerpt: excerpt,
                        response_entropy,
                    });
                }
            }
            let anomaly = is_anomaly(&bl, status, content_length, latency_ms)?;
            process_post_anomaly(
                p.as_ref(),
                &url,
                &payload,
                &bl,
                status,
                content_length,
                latency_ms,
                &anomaly,
                rules.as_slice(),
                None,
                llm_prompt,
            )
            .await
        });
    }
    while let Some(item) = futs.next().await {
        if let Some(va) = item {
            collected.push(va);
        }
    }
    collected
}

/// Fire OAST-instrumented POSTs (traffic only); verification happens after the wave.
async fn concurrent_oob_fire_wave(
    pool: Arc<FuzzHttpPool>,
    target_url: String,
    payloads: Vec<(String, String)>,
    sem: Arc<Semaphore>,
    limiter: Arc<DefaultDirectRateLimiter>,
) {
    let mut futs = FuturesUnordered::new();
    for (payload, _token) in payloads {
        let p = pool.clone();
        let sem = sem.clone();
        let lim = limiter.clone();
        let url = target_url.clone();
        futs.push(async move {
            lim.until_ready().await;
            let Ok(_p) = sem.acquire().await else {
                return;
            };
            let _ = measure_request(p.as_ref(), &url, Some(&payload)).await;
        });
    }
    while futs.next().await.is_some() {}
}

async fn collect_oob_verified_findings(
    pool: &FuzzHttpPool,
    target_url: &str,
    tokens: &[String],
    limiter: &DefaultDirectRateLimiter,
) -> Vec<ValidatedAnomaly> {
    let mut out = Vec::new();
    for token in tokens {
        limiter.until_ready().await;
        if verify_oob_token_seen(pool, token).await {
            let baseline_vs = format!(
                "OAST/OOB correlation: verify endpoint reported hit marker for token {}",
                token
            );
            error!(
                "🚨 HIGH-CONFIDENCE OAST HIT! Target: [{}] | token={}",
                target_url, token
            );
            let anomaly =
                "CRITICAL: OAST out-of-band interaction correlated (immediate SSRF/callback risk)"
                    .to_string();
            crate::reporter::generate_bug_report(
                target_url,
                &format!("OAST_TOKEN:{token}"),
                &anomaly,
                &baseline_vs,
            );
            out.push(ValidatedAnomaly {
                target_url: target_url.to_string(),
                payload: format!("OAST_TOKEN:{token}"),
                anomaly_type: anomaly,
                baseline_vs_anomaly: baseline_vs,
                oob_token: Some(token.clone()),
                llm_user_prompt: None,
            });
        }
    }
    out
}

async fn process_get_anomaly(
    pool: &FuzzHttpPool,
    target_url: &str,
    get_url: &str,
    payload_echo: &str,
    baseline: &Baseline,
    status: u16,
    content_length: usize,
    latency_ms: f64,
    anomaly: &str,
    signature_rules: &[crate::signatures::PayloadSignatureRule],
    llm_user_prompt: Option<String>,
) -> Option<ValidatedAnomaly> {
    if let Some(rule) = crate::signatures::find_matching_rule(payload_echo, signature_rules) {
        let (_, _, _, resp_body) =
            match measure_request_get_with_body(pool, get_url).await {
                Ok(t) => t,
                Err(_) => return None,
            };
        if !crate::signatures::response_matches_signature(&resp_body, &rule.expected_signature) {
            return None;
        }
    }
    let baseline_vs = format!(
        "GET Baseline: status={}, content_length={}, latency_ms≈{:.0} | Anomaly: status={}, content_length={}, latency_ms={:.0}",
        baseline.status, baseline.content_length, baseline.avg_latency_ms,
        status, content_length, latency_ms
    );
    error!(
        "🚨 ZERO-DAY POTENTIAL (GET)! Target: [{}] | Payload: [{}] | Anomaly: [{}]",
        target_url,
        truncate_for_log(payload_echo, 200),
        anomaly
    );
    let high_confidence =
        status == 500 || latency_ms >= baseline.avg_latency_ms * TIME_ANOMALY_MULTIPLIER;
    if !high_confidence {
        return None;
    }
    let validation_baseline = crate::validator::ValidationBaseline {
        normal_status: baseline.status,
        avg_latency_ms: baseline.avg_latency_ms,
        content_length: baseline.content_length,
    };
    let confirmed =
        crate::validator::confirm_anomaly(target_url, anomaly, &validation_baseline).await;
    if !confirmed {
        return None;
    }
    crate::reporter::generate_bug_report(target_url, get_url, anomaly, &baseline_vs);
    Some(ValidatedAnomaly {
        target_url: target_url.to_string(),
        payload: get_url.to_string(),
        anomaly_type: anomaly.to_string(),
        baseline_vs_anomaly: baseline_vs,
        oob_token: None,
        llm_user_prompt,
    })
}

async fn concurrent_get_mutation_wave(
    pool: Arc<FuzzHttpPool>,
    target_url: String,
    baseline: Baseline,
    jobs: Vec<(String, Option<String>)>,
    signature_rules: Arc<Vec<crate::signatures::PayloadSignatureRule>>,
    sem: Arc<Semaphore>,
    limiter: Arc<DefaultDirectRateLimiter>,
) -> Vec<ValidatedAnomaly> {
    let mut collected = Vec::new();
    let mut futs = FuturesUnordered::new();
    for (payload, llm_prompt) in jobs {
        let p = pool.clone();
        let sem = sem.clone();
        let lim = limiter.clone();
        let rules = signature_rules.clone();
        let base_url = target_url.clone();
        let bl = baseline.clone();
        let get_url = append_query_param(&base_url, "q", &payload);
        futs.push(async move {
            lim.until_ready().await;
            let _p = match sem.acquire().await {
                Ok(permit) => permit,
                Err(_) => return None,
            };
            let (status, content_length, latency_ms) =
                match measure_request_get(p.as_ref(), &get_url).await {
                    Ok(t) => t,
                    Err(_) => return None,
                };
            let anomaly = is_anomaly(&bl, status, content_length, latency_ms)?;
            process_get_anomaly(
                p.as_ref(),
                &base_url,
                &get_url,
                &payload,
                &bl,
                status,
                content_length,
                latency_ms,
                &anomaly,
                rules.as_slice(),
                llm_prompt,
            )
            .await
        });
    }
    while let Some(item) = futs.next().await {
        if let Some(va) = item {
            collected.push(va);
        }
    }
    collected
}

async fn execute_legacy_feedback_fuzz(
    target_url: &str,
    base_payload: &str,
    job_oast_token: Option<String>,
) -> Vec<ValidatedAnomaly> {
    let mut collected = Vec::new();
    let pool = match FuzzHttpPool::from_env().await {
        Ok(p) => Arc::new(p),
        Err(_) => return collected,
    };

    let baseline = match establish_baseline(pool.as_ref(), target_url, base_payload).await {
        Some(b) => b,
        None => return collected,
    };

    let signature_rules = Arc::new(crate::signatures::load_signature_rules());
    let mutator = Mutator::new(base_payload);
    let guided = std::env::var("FUZZ_PAYLOADS_FILE")
        .map(|p| load_guided_payloads_from_file(&p))
        .unwrap_or_default();
    let mutations = resolve_mutations(&mutator, &guided);
    let post_jobs: Vec<(String, Option<String>)> =
        mutations.iter().cloned().map(|m| (m, None)).collect();

    let sem = Arc::new(Semaphore::new(fuzz_max_in_flight()));
    let limiter = new_fuzz_rate_limiter();

    let post_findings = concurrent_post_mutation_wave(
        pool.clone(),
        target_url.to_string(),
        baseline.clone(),
        post_jobs,
        signature_rules.clone(),
        sem.clone(),
        limiter.clone(),
        None,
    )
    .await;
    collected.extend(post_findings);
    crate::fuzz_http_pool::batch_jitter_sleep().await;

    let n_oast = oast_max_probes(mutations.len());
    let mut oast_tokens: Vec<String> = Vec::new();
    let mut oast_payloads: Vec<(String, String)> = Vec::new();
    if n_oast > 0 {
        for (i, m) in mutations.iter().take(n_oast).enumerate() {
            let token = if i == 0 {
                job_oast_token
                    .as_ref()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
            } else {
                uuid::Uuid::new_v4().to_string()
            };
            let injected = inject_oob_token(m, &token);
            oast_payloads.push((injected, token.clone()));
            oast_tokens.push(token);
        }
        concurrent_oob_fire_wave(
            pool.clone(),
            target_url.to_string(),
            oast_payloads,
            sem.clone(),
            limiter.clone(),
        )
        .await;
        let oob_hits =
            collect_oob_verified_findings(pool.as_ref(), target_url, &oast_tokens, limiter.as_ref())
                .await;
        collected.extend(oob_hits);
    }

    let baseline_get = match establish_baseline_get(pool.as_ref(), target_url).await {
        Some(b) => b,
        None => return collected,
    };
    let get_jobs: Vec<(String, Option<String>)> =
        mutations.iter().cloned().map(|m| (m, None)).collect();
    let get_findings = concurrent_get_mutation_wave(
        pool.clone(),
        target_url.to_string(),
        baseline_get.clone(),
        get_jobs,
        signature_rules.clone(),
        sem.clone(),
        limiter.clone(),
    )
    .await;
    collected.extend(get_findings);
    crate::fuzz_http_pool::batch_jitter_sleep().await;

    let injection_found = param_injection_pass(
        pool.clone(),
        target_url,
        signature_rules.as_slice(),
        sem,
        limiter,
    )
    .await;
    for v in &injection_found {
        crate::reporter::generate_bug_report(
            &v.target_url,
            &v.payload,
            &v.anomaly_type,
            &v.baseline_vs_anomaly,
        );
    }
    collected.extend(injection_found);
    collected
}

async fn execute_generative_feedback_fuzz(
    target_url: &str,
    base_payload: &str,
    llm_tenant_id: Option<i64>,
    job_oast_token: Option<String>,
    cognitive_osint: Option<&str>,
) -> Vec<ValidatedAnomaly> {
    let mut collected = Vec::new();
    let pool = match FuzzHttpPool::from_env().await {
        Ok(p) => Arc::new(p),
        Err(_) => return collected,
    };

    let baseline = match establish_baseline(pool.as_ref(), target_url, base_payload).await {
        Some(b) => b,
        None => return collected,
    };

    let signature_rules = Arc::new(crate::signatures::load_signature_rules());
    let cfg = GenerativeLlmConfig::from_env(llm_tenant_id);
    let tech_stack = generative_fuzz_llm::tech_stack_hint();
    let chan_cap = generative_fuzz_llm::generative_fuzz_channel_capacity();
    let low_water = generative_fuzz_llm::generative_fuzz_low_water(chan_cap);
    let max_post = generative_fuzz_llm::generative_max_post_probes();

    let llm_timeout: u64 = std::env::var("WEISSMAN_GENERATIVE_FUZZ_LLM_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
        .max(30);

    let llm_http = weissman_engines::openai_chat::llm_http_client(llm_timeout);

    let (fb_tx, fb_rx) = mpsc::unbounded_channel::<BlockFeedback>();
    let (tx, mut rx) = mpsc::channel::<GenerativeMutation>(chan_cap);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_prod = stop.clone();
    let cognitive = cognitive_osint
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("")
        .to_string();
    let gen_task = tokio::spawn(generative_fuzz_llm::run_generative_producer_loop(
        tx,
        fb_rx,
        stop_prod,
        llm_http.clone(),
        cfg.clone(),
        chan_cap,
        low_water,
        target_url.to_string(),
        base_payload.to_string(),
        tech_stack.clone(),
        cognitive.clone(),
    ));

    let sem = Arc::new(Semaphore::new(fuzz_max_in_flight()));
    let limiter = new_fuzz_rate_limiter();

    let mut total_post: usize = 0;
    let mut oast_material: Vec<GenerativeMutation> = Vec::new();
    let mut pending: Vec<GenerativeMutation> = Vec::new();
    const BATCH: usize = 40;
    let mut flush_timer =
        tokio::time::interval(std::time::Duration::from_millis(140));
    flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    async fn flush_post(
        pending: &mut Vec<GenerativeMutation>,
        pool: &Arc<FuzzHttpPool>,
        target_url: &str,
        baseline: &Baseline,
        signature_rules: &Arc<Vec<crate::signatures::PayloadSignatureRule>>,
        sem: &Arc<Semaphore>,
        limiter: &Arc<DefaultDirectRateLimiter>,
        fb_tx: &mpsc::UnboundedSender<BlockFeedback>,
        collected: &mut Vec<ValidatedAnomaly>,
        total_post: &mut usize,
        max_post: usize,
    ) {
        if pending.is_empty() {
            return;
        }
        let room = max_post.saturating_sub(*total_post);
        if room == 0 {
            pending.clear();
            return;
        }
        let mut batch: Vec<GenerativeMutation> = pending.drain(..).collect();
        if batch.len() > room {
            batch.truncate(room);
        }
        let jobs: Vec<(String, Option<String>)> = batch
            .into_iter()
            .map(|g| (g.payload, Some(g.llm_user_prompt)))
            .collect();
        let n = jobs.len();
        if n == 0 {
            return;
        }
        let part = concurrent_post_mutation_wave(
            pool.clone(),
            target_url.to_string(),
            baseline.clone(),
            jobs,
            signature_rules.clone(),
            sem.clone(),
            limiter.clone(),
            Some(fb_tx.clone()),
        )
        .await;
        collected.extend(part);
        *total_post += n;
        crate::fuzz_http_pool::batch_jitter_sleep().await;
    }

    loop {
        if total_post >= max_post {
            break;
        }
        tokio::select! {
            biased;
            recv_m = rx.recv() => {
                match recv_m {
                    Some(m) => {
                        oast_material.push(GenerativeMutation {
                            payload: m.payload.clone(),
                            llm_user_prompt: m.llm_user_prompt.clone(),
                        });
                        pending.push(m);
                        if pending.len() >= BATCH {
                            flush_post(
                                &mut pending,
                                &pool,
                                target_url,
                                &baseline,
                                &signature_rules,
                                &sem,
                                &limiter,
                                &fb_tx,
                                &mut collected,
                                &mut total_post,
                                max_post,
                            )
                            .await;
                        }
                    }
                    None => break,
                }
            }
            _ = flush_timer.tick(), if !pending.is_empty() => {
                flush_post(
                    &mut pending,
                    &pool,
                    target_url,
                    &baseline,
                    &signature_rules,
                    &sem,
                    &limiter,
                    &fb_tx,
                    &mut collected,
                    &mut total_post,
                    max_post,
                )
                .await;
            }
        }
    }

    flush_post(
        &mut pending,
        &pool,
        target_url,
        &baseline,
        &signature_rules,
        &sem,
        &limiter,
        &fb_tx,
        &mut collected,
        &mut total_post,
        max_post,
    )
    .await;

    stop.store(true, Ordering::SeqCst);
    drop(rx);
    if let Err(e) = gen_task.await {
        warn!(target: "generative_fuzz", "producer task join: {:?}", e);
    }

    let n_oast = oast_max_probes(oast_material.len());
    let mut oast_tokens: Vec<String> = Vec::new();
    let mut oast_payloads: Vec<(String, String)> = Vec::new();
    if n_oast > 0 {
        for (i, m) in oast_material.iter().take(n_oast).enumerate() {
            let token = if i == 0 {
                job_oast_token
                    .as_ref()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
            } else {
                uuid::Uuid::new_v4().to_string()
            };
            let injected = inject_oob_token(&m.payload, &token);
            oast_payloads.push((injected, token.clone()));
            oast_tokens.push(token);
        }
        concurrent_oob_fire_wave(
            pool.clone(),
            target_url.to_string(),
            oast_payloads,
            sem.clone(),
            limiter.clone(),
        )
        .await;
        let oob_hits =
            collect_oob_verified_findings(pool.as_ref(), target_url, &oast_tokens, limiter.as_ref())
                .await;
        collected.extend(oob_hits);
    }

    let baseline_get = match establish_baseline_get(pool.as_ref(), target_url).await {
        Some(b) => b,
        None => return collected,
    };
    let cap_get = oast_material.len().min(420);
    let get_jobs: Vec<(String, Option<String>)> = oast_material
        .iter()
        .take(cap_get)
        .map(|g| (g.payload.clone(), Some(g.llm_user_prompt.clone())))
        .collect();
    let get_findings = concurrent_get_mutation_wave(
        pool.clone(),
        target_url.to_string(),
        baseline_get.clone(),
        get_jobs,
        signature_rules.clone(),
        sem.clone(),
        limiter.clone(),
    )
    .await;
    collected.extend(get_findings);
    crate::fuzz_http_pool::batch_jitter_sleep().await;

    let inj = generative_fuzz_llm::fetch_injection_urls(
        &llm_http,
        &cfg,
        target_url,
        &tech_stack,
        cognitive.as_str(),
    )
    .await;
    let (inj_urls, inj_prompt) = match inj {
        Ok(x) => x,
        Err(e) => {
            warn!(target: "generative_fuzz", "injection URL LLM failed: {}", e);
            (Vec::new(), String::new())
        }
    };
    let inj_urls: Vec<String> = inj_urls.into_iter().take(180).collect();
    let injection_found = param_injection_pass_with_urls(
        pool.clone(),
        target_url,
        signature_rules.as_slice(),
        sem.clone(),
        limiter.clone(),
        inj_urls,
        if inj_prompt.is_empty() {
            None
        } else {
            Some(inj_prompt)
        },
    )
    .await;
    for v in &injection_found {
        crate::reporter::generate_bug_report(
            &v.target_url,
            &v.payload,
            &v.anomaly_type,
            &v.baseline_vs_anomaly,
        );
    }
    collected.extend(injection_found);
    collected
}

async fn execute_feedback_fuzz(
    target_url: &str,
    base_payload: &str,
    llm_tenant_id: Option<i64>,
    job_oast_token: Option<String>,
    cognitive_osint: Option<&str>,
) -> Vec<ValidatedAnomaly> {
    if generative_legacy_mode() {
        execute_legacy_feedback_fuzz(target_url, base_payload, job_oast_token).await
    } else {
        execute_generative_feedback_fuzz(
            target_url,
            base_payload,
            llm_tenant_id,
            job_oast_token,
            cognitive_osint,
        )
        .await
    }
}

/// Runs the fuzzer: baseline first, then concurrent mutation waves with rate limiting.
pub async fn run_fuzzer(target_url: &str, base_payload: &str) {
    let _ = execute_feedback_fuzz(target_url, base_payload, None, None, None).await;
}

/// Runs the fuzzer and returns all validated anomalies (for API/DB). Still generates markdown reports.
pub async fn run_fuzzer_collect(target_url: &str, base_payload: &str) -> Vec<ValidatedAnomaly> {
    execute_feedback_fuzz(target_url, base_payload, None, None, None).await
}

/// Same as [`run_fuzzer_collect`] but passes tenant id into vLLM metering (`tenant_llm_usage`).
pub async fn run_fuzzer_collect_tenant(
    target_url: &str,
    base_payload: &str,
    llm_tenant_id: Option<i64>,
    job_oast_token: Option<String>,
    cognitive_osint: Option<&str>,
) -> Vec<ValidatedAnomaly> {
    execute_feedback_fuzz(
        target_url,
        base_payload,
        llm_tenant_id,
        job_oast_token,
        cognitive_osint,
    )
    .await
}

async fn param_injection_pass(
    pool: Arc<FuzzHttpPool>,
    target_url: &str,
    signature_rules: &[crate::signatures::PayloadSignatureRule],
    sem: Arc<Semaphore>,
    limiter: Arc<DefaultDirectRateLimiter>,
) -> Vec<ValidatedAnomaly> {
    let injection_urls = build_param_injection_probe_urls(target_url, 160);
    param_injection_pass_with_urls(
        pool,
        target_url,
        signature_rules,
        sem,
        limiter,
        injection_urls,
        None,
    )
    .await
}

async fn param_injection_pass_with_urls(
    pool: Arc<FuzzHttpPool>,
    target_url: &str,
    signature_rules: &[crate::signatures::PayloadSignatureRule],
    sem: Arc<Semaphore>,
    limiter: Arc<DefaultDirectRateLimiter>,
    injection_urls: Vec<String>,
    llm_user_prompt: Option<String>,
) -> Vec<ValidatedAnomaly> {
    if injection_urls.is_empty() {
        return Vec::new();
    }
    let Some(inj_baseline) = establish_baseline_get(pool.as_ref(), target_url).await else {
        return Vec::new();
    };
    let target_owned = target_url.to_string();
    let bl = inj_baseline.clone();
    let rules = Arc::new(signature_rules.to_vec());

    let mut futs = FuturesUnordered::new();
    for inj_url in injection_urls {
        let pool = pool.clone();
        let sem = sem.clone();
        let lim = limiter.clone();
        let rules = rules.clone();
        let target_url = target_owned.clone();
        let inj_baseline = bl.clone();
        let llm_p = llm_user_prompt.clone();
        futs.push(async move {
            lim.until_ready().await;
            let _p = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return None,
            };
            let Ok((status, content_length, latency_ms, resp_body)) =
                measure_request_get_with_body(pool.as_ref(), &inj_url).await
            else {
                return None;
            };
            let timing_anomaly = is_anomaly(&inj_baseline, status, content_length, latency_ms);
            let sqli = looks_like_sqli_response(&resp_body);
            let xss = reflected_xss_indicated(&resp_body);
            if timing_anomaly.is_none() && !sqli && !xss {
                return None;
            }
            let has_timing_anomaly = timing_anomaly.is_some();
            let anomaly = timing_anomaly.unwrap_or_else(|| {
                if sqli {
                    "Possible SQL injection (database error signature in response body)".to_string()
                } else {
                    "Possible reflected XSS (synthetic probe token echoed in response)".to_string()
                }
            });
            if has_timing_anomaly {
                let payload_key = inj_url
                    .split_once('?')
                    .map(|(_, q)| q)
                    .unwrap_or(inj_url.as_str());
                if let Some(rule) = crate::signatures::find_matching_rule(payload_key, rules.as_slice())
                {
                    if !crate::signatures::response_matches_signature(
                        &resp_body,
                        &rule.expected_signature,
                    ) {
                        return None;
                    }
                }
            }
            let baseline_vs = format!(
                "GET injection baseline: status={}, content_length={}, latency_ms≈{:.0} | Observed: status={}, content_length={}, latency_ms={:.0}",
                inj_baseline.status,
                inj_baseline.content_length,
                inj_baseline.avg_latency_ms,
                status,
                content_length,
                latency_ms
            );
            error!(
                "🚨 INJECTION SIGNAL (GET param)! Target: [{}] | {}",
                inj_url, anomaly
            );
            let high_confidence = status == 500
                || sqli
                || xss
                || latency_ms >= inj_baseline.avg_latency_ms * TIME_ANOMALY_MULTIPLIER;
            if !high_confidence {
                return None;
            }
            let validation_baseline = crate::validator::ValidationBaseline {
                normal_status: inj_baseline.status,
                avg_latency_ms: inj_baseline.avg_latency_ms,
                content_length: inj_baseline.content_length,
            };
            let confirmed =
                crate::validator::confirm_anomaly(&target_url, &anomaly, &validation_baseline)
                    .await;
            if !(confirmed || sqli || xss) {
                return None;
            }
            Some(ValidatedAnomaly {
                target_url: target_url.clone(),
                payload: inj_url.clone(),
                anomaly_type: anomaly.clone(),
                baseline_vs_anomaly: baseline_vs.clone(),
                oob_token: None,
                llm_user_prompt: llm_p,
            })
        });
    }

    let mut out = Vec::new();
    while let Some(item) = futs.next().await {
        if let Some(va) = item {
            out.push(va);
        }
    }
    out
}
