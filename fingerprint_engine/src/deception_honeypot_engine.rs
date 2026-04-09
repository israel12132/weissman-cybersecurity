//! Deception/Honeypot Intelligence — detects honeypot/decoy indicators and adapts scanning accordingly.

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::{Duration, Instant};

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn normalize_target(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

pub async fn run_deception_honeypot_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();
    let mut honeypot_score: u32 = 0;
    let mut indicators: Vec<String> = Vec::new();

    // 1. Probe a non-existent path — honeypots often return 200 for everything
    let fake_path = format!("{}/this-path-definitely-does-not-exist-{}", base.trim_end_matches('/'), "xz7q9k");
    if let Ok(resp) = client.get(&fake_path).send().await {
        let status = resp.status().as_u16();
        if status == 200 {
            honeypot_score += 30;
            indicators.push(format!("Returns HTTP 200 for non-existent path ({})", fake_path));
        }
    }

    // 2. Measure response time consistency — honeypots often have suspiciously fast/uniform responses
    let mut times_ms: Vec<u128> = Vec::new();
    for _ in 0..3 {
        let t0 = Instant::now();
        let _ = client.get(&base).send().await;
        times_ms.push(t0.elapsed().as_millis());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if times_ms.len() >= 3 {
        let avg: u128 = times_ms.iter().sum::<u128>() / times_ms.len() as u128;
        let max_dev = times_ms.iter().map(|&t| (t as i128 - avg as i128).unsigned_abs()).max().unwrap_or(0);
        if avg < 5 && max_dev < 2 {
            honeypot_score += 20;
            indicators.push(format!("Suspiciously uniform sub-5ms responses (avg {}ms, max deviation {}ms)", avg, max_dev));
        }
    }

    // 3. Check for honeypot-specific headers / server strings
    if let Ok(resp) = client.get(&base).send().await {
        let headers = resp.headers().clone();
        let server = headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let powered_by = headers
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        // Known honeypot server strings
        let honeypot_servers = ["glastopf", "honeypot", "thinkst", "opencanary", "cowrie", "dionaea"];
        for hs in &honeypot_servers {
            if server.contains(hs) || powered_by.contains(hs) {
                honeypot_score += 50;
                indicators.push(format!("Honeypot server signature detected: Server={} X-Powered-By={}", server, powered_by));
            }
        }

        // Perfect/template server strings common in honeypots
        if server == "apache" || server == "nginx" || server == "iis" {
            // Too clean — might be honeypot
            honeypot_score += 5;
            indicators.push(format!("Suspiciously clean server header: {}", server));
        }

        // Check body for honeypot content
        if let Ok(body) = resp.text().await {
            let body_lower = body.to_lowercase();
            if body_lower.contains("honeypot") || body_lower.contains("canary token") || body_lower.contains("thinkst") {
                honeypot_score += 40;
                indicators.push("Response body contains honeypot/canary keywords".to_string());
            }
        }
    }

    // 4. Check for too-perfect security.txt (common in canary setups)
    let sec_url = format!("{}/.well-known/security.txt", base.trim_end_matches('/'));
    if let Ok(resp) = client.get(&sec_url).send().await {
        if resp.status().as_u16() == 200 {
            if let Ok(body) = resp.text().await {
                if body.contains("canary") || body.contains("honeypot") || body.contains("decoy") {
                    honeypot_score += 30;
                    indicators.push("security.txt references canary/honeypot/decoy".to_string());
                }
            }
        }
    }

    // 5. Check Canary Tokens via DNS (publicly known canarytoken.org patterns)
    let host_only: String = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(&base)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    if host_only.ends_with(".canarytokens.com") || host_only.ends_with(".canarytoken.org") {
        honeypot_score += 100;
        indicators.push(format!("Host {} is a known Canary Token domain", host_only));
    }

    // Final verdict
    let severity = if honeypot_score >= 60 {
        "critical"
    } else if honeypot_score >= 30 {
        "high"
    } else if honeypot_score >= 10 {
        "medium"
    } else {
        "info"
    };

    let verdict = if honeypot_score >= 60 {
        "HIGH PROBABILITY of honeypot/decoy"
    } else if honeypot_score >= 30 {
        "MODERATE honeypot indicators"
    } else {
        "Low honeypot probability"
    };

    findings.push(json!({
        "type": "deception_honeypot",
        "title": format!("Honeypot intelligence for {}: {} (score: {})", base, verdict, honeypot_score),
        "severity": severity,
        "mitre_attack": "T1036",
        "description": format!(
            "Honeypot/deception analysis for {}. Score: {}/100. Indicators: {}. \
            If honeypot probability is high, reduce scan intensity and avoid triggering alert thresholds. \
            Real targets do not typically accept all paths with HTTP 200 or have perfectly uniform response times.",
            base, honeypot_score,
            if indicators.is_empty() { "None detected".to_string() } else { indicators.join("; ") }
        ),
        "value": base,
        "honeypot_score": honeypot_score,
        "indicators": indicators,
        "verdict": verdict
    }));

    EngineResult::ok(
        findings.clone(),
        format!("DeceptionHoneypot: score={}/100 for {}", honeypot_score, base),
    )
}

pub async fn run_deception_honeypot(target: &str) {
    print_result(run_deception_honeypot_result(target).await);
}
