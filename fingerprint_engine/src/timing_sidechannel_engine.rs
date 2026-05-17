//! Timing side-channel vulnerability detection.
use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::{Duration, Instant};

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn normalize_target(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") { t.to_string() } else { format!("https://{}", t) }
}

pub async fn run_timing_sidechannel_result(target: &str) -> EngineResult {
    if target.trim().is_empty() { return EngineResult::error("target required"); }
    let client = build_client().await;
    let base = normalize_target(target);
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // 5 baseline requests
    let mut baseline_times: Vec<f64> = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let _ = client.get(&base).send().await;
        baseline_times.push(start.elapsed().as_millis() as f64);
    }
    let mean_baseline = baseline_times.iter().sum::<f64>() / baseline_times.len() as f64;

    // 5 payload requests
    let long_string = "A".repeat(1000);
    let payload_url = format!("{}?q={}", base, long_string);
    let mut payload_times: Vec<f64> = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let _ = client.get(&payload_url).send().await;
        payload_times.push(start.elapsed().as_millis() as f64);
    }
    let mean_payload = payload_times.iter().sum::<f64>() / payload_times.len() as f64;

    if mean_payload > 2.0 * mean_baseline {
        findings.push(json!({
            "type": "timing_sidechannel",
            "title": "Potential timing side-channel vulnerability",
            "severity": "high",
            "mitre_attack": "T1600",
            "description": format!("Mean baseline: {:.1}ms, mean payload: {:.1}ms — payload response >2x slower.", mean_baseline, mean_payload)
        }));
    }
    EngineResult::ok(findings.clone(), format!("Timing Side-Channel: {} findings (baseline={:.1}ms, payload={:.1}ms)", findings.len(), mean_baseline, mean_payload))
}

pub async fn run_timing_sidechannel(target: &str) {
    print_result(run_timing_sidechannel_result(target).await);
}
