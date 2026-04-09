//! Safe Probe mode: verify possible vulnerability existence by response behavior
//! (header changes, timing side-channels) without executing a destructive payload.

use std::collections::HashMap;
use std::time::{Duration, Instant};

const REQUEST_TIMEOUT_SECS: u64 = 15;
const TIMING_ANOMALY_THRESHOLD_MS: u64 = 500; // probe taking >> baseline suggests processing difference
const HEADERS_TO_COMPARE: &[&str] = &["server", "x-powered-by", "x-aspnet-version", "via"];

fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 SecurityAssessmentBot-SafeProbe/1.0")
        .build()
}

fn extract_headers_map(resp: &reqwest::Response, names: &[&str]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for name in names {
        if let Some(v) = resp.headers().get(*name) {
            if let Ok(s) = v.to_str() {
                out.insert((*name).to_string(), s.to_string());
            }
        }
    }
    out
}

/// Result of a safe probe: no payload executed, only GET + optional probe GET.
#[derive(Debug, serde::Serialize)]
pub struct SafeProbeResult {
    pub header_changed: bool,
    pub timing_anomaly: bool,
    pub baseline_latency_ms: u64,
    pub probe_latency_ms: u64,
    pub baseline_headers: HashMap<String, String>,
    pub probe_headers: HashMap<String, String>,
    pub tech_hint: String,
}

/// Performs a non-destructive probe: baseline GET, then GET with a benign header
/// that can trigger different behavior on vulnerable systems (e.g. version leak,
/// timing side-channel). Does NOT run any exploit payload.
pub async fn safe_probe(url: &str, tech_hint: &str) -> Option<SafeProbeResult> {
    let url = url.trim();
    if url.is_empty() {
        return None;
    }
    let full_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };
    let client = build_client().ok()?;

    // Baseline GET
    let start = Instant::now();
    let baseline_resp = client.get(&full_url).send().await.ok()?;
    let baseline_headers = extract_headers_map(&baseline_resp, HEADERS_TO_COMPARE);
    let _ = baseline_resp.bytes().await;
    let baseline_ms = start.elapsed().as_millis() as u64;

    // Probe GET: add a benign header that some vuln checks use (e.g. version disclosure / timing)
    let probe_start = Instant::now();
    let probe_resp = client
        .get(&full_url)
        .header("X-Forwarded-For", "127.0.0.1")
        .header("X-Original-URL", "/")
        .send()
        .await
        .ok()?;
    let probe_headers = extract_headers_map(&probe_resp, HEADERS_TO_COMPARE);
    let _ = probe_resp.bytes().await;
    let probe_ms = probe_start.elapsed().as_millis() as u64;

    let header_changed = baseline_headers != probe_headers;
    let timing_anomaly = baseline_ms > 0 && probe_ms >= baseline_ms + TIMING_ANOMALY_THRESHOLD_MS
        || (baseline_ms + TIMING_ANOMALY_THRESHOLD_MS < probe_ms);

    Some(SafeProbeResult {
        header_changed,
        timing_anomaly,
        baseline_latency_ms: baseline_ms,
        probe_latency_ms: probe_ms,
        baseline_headers,
        probe_headers,
        tech_hint: tech_hint.to_string(),
    })
}
