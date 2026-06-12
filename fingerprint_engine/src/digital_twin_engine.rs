//! Digital Twin Attack Simulator — builds an environment profile and simulates attack scenarios.

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
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

pub async fn run_digital_twin_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Phase 1: Build environment profile (Digital Twin)
    let mut twin_profile = serde_json::Map::new();

    // Fingerprint server technology
    if let Ok(resp) = client.get(&base).send().await {
        let headers = resp.headers().clone();
        let status = resp.status().as_u16();

        let server = headers
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        let powered_by = headers
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let has_hsts = headers.contains_key("strict-transport-security");
        let has_csp = headers.contains_key("content-security-policy");
        let has_cors = headers.contains_key("access-control-allow-origin");

        twin_profile.insert("server".to_string(), json!(server));
        twin_profile.insert("powered_by".to_string(), json!(powered_by));
        twin_profile.insert("http_status".to_string(), json!(status));
        twin_profile.insert("has_hsts".to_string(), json!(has_hsts));
        twin_profile.insert("has_csp".to_string(), json!(has_csp));
        twin_profile.insert("has_cors".to_string(), json!(has_cors));
        twin_profile.insert("content_type".to_string(), json!(content_type));

        findings.push(json!({
            "type": "digital_twin",
            "title": format!("Digital Twin profile built for {}", base),
            "severity": "info",
            "mitre_attack": "T1595.002",
            "description": format!(
                "Environment profile (Digital Twin) constructed: Server={}, PoweredBy={}, HSTS={}, CSP={}, CORS={}. \
                This profile drives attack simulation scenarios.",
                server, powered_by, has_hsts, has_csp, has_cors
            ),
            "value": base,
            "twin_profile": serde_json::Value::Object(twin_profile.clone())
        }));

        // Phase 2: Risk scenarios from live profile (advisory only — not stored as confirmed vulns)
        if content_type.contains("html") || content_type.contains("json") {
            findings.push(json!({
                "type": "digital_twin",
                "category": "risk_scenario",
                "title": format!("Advisory: SQLi test path for {}", base),
                "severity": "info",
                "mitre_attack": "T1190",
                "description": format!(
                    "Digital Twin profile suggests validating SQL injection on forms/API (server={}, content-type={}). \
                    Run bola_idor, semantic_ai_fuzz, or http_feedback_fuzz for live confirmation.",
                    server, content_type
                ),
                "value": base,
                "scenario": "sqli",
            }));
        }

        if !has_csp {
            findings.push(json!({
                "type": "digital_twin",
                "category": "risk_scenario",
                "title": format!("Advisory: XSS risk (no CSP) on {}", base),
                "severity": "info",
                "mitre_attack": "T1059.007",
                "description": format!(
                    "Content-Security-Policy is absent on {}. Validate with ssti/semantic_ai_fuzz engines.",
                    base
                ),
                "value": base,
                "scenario": "xss",
            }));
        }

        if !has_hsts {
            findings.push(json!({
                "type": "digital_twin",
                "category": "risk_scenario",
                "title": format!("Advisory: MITM/ssl-strip risk (no HSTS) on {}", base),
                "severity": "info",
                "mitre_attack": "T1557",
                "description": format!(
                    "HSTS not enforced on {}. Validate transport with pki_tls engine.",
                    base
                ),
                "value": base,
                "scenario": "sslstrip",
            }));
        }

        // Simulate CORS-based attack
        if has_cors {
            let origin_val = headers
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if origin_val == "*" {
                findings.push(json!({
                    "type": "digital_twin",
                    "category": "risk_scenario",
                    "title": format!("Advisory: permissive CORS on {}", base),
                    "severity": "info",
                    "mitre_attack": "T1557",
                    "description": format!(
                        "Access-Control-Allow-Origin: * observed on {}. Confirm impact with oauth_oidc or bola_idor.",
                        base
                    ),
                    "value": base,
                    "scenario": "cors",
                    "cors_policy": origin_val
                }));
            }
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!(
            "DigitalTwin: {} profile/risk advisories for {}",
            findings.len(),
            base
        ),
    )
}

pub async fn run_digital_twin(target: &str) {
    print_result(run_digital_twin_result(target).await);
}
