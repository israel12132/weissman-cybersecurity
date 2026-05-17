//! Serverless Attack Engine — probes for exposed serverless functions, env variable leakage, and cold-start timing.
//! MITRE: T1059 (Command and Scripting Interpreter).

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::{Duration, Instant};

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn normalize_target(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

const SERVERLESS_PATHS: &[&str] = &[
    "/.netlify/functions/",
    "/.netlify/functions/hello",
    "/.netlify/functions/api",
    "/api/",
    "/.functions/",
    "/serverless/",
    "/.api/",
    "/functions/",
    "/lambda/",
    "/fn/",
    "/.well-known/serverless",
];

const ENV_LEAK_PATHS: &[&str] = &[
    "/api/env",
    "/api/config",
    "/api/settings",
    "/api/debug",
    "/api/health",
    "/api/status",
    "/api/info",
    "/debug/env",
    "/debug/vars",
    "/.well-known/env",
    "/config.json",
    "/settings.json",
];

const ENV_KEY_INDICATORS: &[&str] = &[
    "SECRET",
    "PASSWORD",
    "TOKEN",
    "API_KEY",
    "DATABASE_URL",
    "REDIS_URL",
    "AWS_ACCESS",
    "PRIVATE_KEY",
    "CLIENT_SECRET",
    "AUTH_TOKEN",
    "DB_PASS",
    "MONGO_URI",
    "SENDGRID",
    "STRIPE_",
    "TWILIO_",
];

pub async fn run_serverless_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let client = build_client().await;
    let base = normalize_target(target);
    let mut findings = Vec::new();

    // Probe serverless function endpoints
    for path in SERVERLESS_PATHS {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 || status == 405 || status == 401 || status == 403 {
                let severity = if status == 200 { "high" } else { "medium" };
                findings.push(json!({
                    "type": "serverless_attack",
                    "title": format!("Serverless Function Endpoint Discovered: {}", path),
                    "severity": severity,
                    "mitre_attack": "T1059",
                    "description": format!(
                        "Serverless/FaaS endpoint found at {} (HTTP {}). This endpoint may be invocable and susceptible to event injection attacks.",
                        url, status
                    )
                }));
            }
        }
    }

    // Probe for environment variable leakage
    for path in ENV_LEAK_PATHS {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                let body = resp.text().await.unwrap_or_default();
                let upper_body = body.to_uppercase();
                let leaked_keys: Vec<&str> = ENV_KEY_INDICATORS
                    .iter()
                    .filter(|ind| upper_body.contains(&ind.to_uppercase()))
                    .copied()
                    .collect();

                if !leaked_keys.is_empty() {
                    findings.push(json!({
                        "type": "serverless_attack",
                        "title": format!("Environment Variable Leakage at {}", path),
                        "severity": "critical",
                        "mitre_attack": "T1059",
                        "description": format!(
                            "The endpoint {} (HTTP {}) appears to leak environment variables containing sensitive keys: {}. Immediate remediation required.",
                            url, status, leaked_keys.join(", ")
                        )
                    }));
                } else if body.len() > 20 {
                    findings.push(json!({
                        "type": "serverless_attack",
                        "title": format!("Configuration Endpoint Exposed: {}", path),
                        "severity": "medium",
                        "mitre_attack": "T1059",
                        "description": format!(
                            "Configuration/debug endpoint {} returned HTTP {} with {} bytes of data. Review for sensitive information disclosure.",
                            url, status, body.len()
                        )
                    }));
                }
            }
        }
    }

    // Cold-start timing analysis: make two rapid requests to detect timing anomalies
    let timing_url = format!("{}/api/", base);
    let start1 = Instant::now();
    let first_result = client.get(&timing_url).send().await;
    let elapsed1 = start1.elapsed().as_millis();

    let start2 = Instant::now();
    let second_result = client.get(&timing_url).send().await;
    let elapsed2 = start2.elapsed().as_millis();

    if first_result.is_ok() && second_result.is_ok() {
        let cold_start_diff = if elapsed1 > elapsed2 {
            elapsed1 - elapsed2
        } else {
            0
        };

        // Cold starts typically add 500ms+ latency
        if cold_start_diff > 500 {
            findings.push(json!({
                "type": "serverless_attack",
                "title": "Serverless Cold-Start Timing Detected",
                "severity": "info",
                "mitre_attack": "T1059",
                "description": format!(
                    "Timing analysis of {} suggests serverless cold-start behavior. First request: {}ms, Second request: {}ms (diff: {}ms). This confirms a serverless/FaaS deployment which may have different security properties.",
                    timing_url, elapsed1, elapsed2, cold_start_diff
                )
            }));
        }
    }

    EngineResult::ok(findings.clone(), format!("Serverless Attack: {} findings", findings.len()))
}

pub async fn run_serverless_attack(target: &str) {
    print_result(run_serverless_attack_result(target).await);
}
