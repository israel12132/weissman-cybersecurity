//! WebSocket Attack Engine — upgrade endpoint discovery, CORS/origin validation, CSWSH risk.
//! MITRE: T1071 (Application Layer Protocol).

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn base_url(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

pub async fn run_websocket_attack_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    let ws_paths = ["/ws", "/wss", "/websocket", "/socket.io", "/socket", "/chat", "/live", "/realtime", "/api/ws", "/events"];

    for path in &ws_paths {
        let url = format!("{}{}", base, path);

        // Send a WebSocket Upgrade request via HTTP — if server responds with 101 or indicates upgrade support
        let upgrade_resp = client
            .get(&url)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .header("Origin", "https://attacker.example.com")
            .send()
            .await;

        match upgrade_resp {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers = resp.headers().clone();

                if status == 101 {
                    findings.push(json!({
                        "type": "websocket_attack",
                        "title": "WebSocket Upgrade Accepted",
                        "severity": "info",
                        "mitre_attack": "T1071",
                        "description": format!("WebSocket endpoint detected at {}. Upgrade handshake accepted (HTTP 101).", url),
                        "value": url
                    }));

                    // Check for Origin validation — if we sent a foreign origin and got 101, origin is not validated
                    findings.push(json!({
                        "type": "websocket_attack",
                        "title": "WebSocket: No Origin Validation (CSWSH Risk)",
                        "severity": "high",
                        "mitre_attack": "T1071",
                        "description": format!(
                            "WebSocket at {} accepted an upgrade from a foreign origin (https://attacker.example.com) without rejection. Cross-Site WebSocket Hijacking (CSWSH) is likely possible.",
                            url
                        ),
                        "value": url
                    }));
                } else if status == 400 || status == 426 {
                    findings.push(json!({
                        "type": "websocket_attack",
                        "title": "WebSocket Endpoint Detected (Upgrade Required)",
                        "severity": "info",
                        "mitre_attack": "T1071",
                        "description": format!("WebSocket endpoint found at {} (HTTP {}). Verify authentication and origin validation.", url, status),
                        "value": url
                    }));
                }

                // Check for missing Sec-WebSocket-Origin or similar validation header in response
                let has_origin_header = headers.contains_key("sec-websocket-origin")
                    || headers.contains_key("access-control-allow-origin");
                if status == 101 && !has_origin_header {
                    // Already flagged above as CSWSH — skip duplicate
                }

                // Check CORS policy on WS endpoints
                if let Ok(cors_resp) = client
                    .request(reqwest::Method::OPTIONS, &url)
                    .header("Origin", "https://evil.example.com")
                    .header("Access-Control-Request-Method", "GET")
                    .send()
                    .await
                {
                    if let Some(acao) = cors_resp.headers().get("access-control-allow-origin") {
                        let acao_str = acao.to_str().unwrap_or("");
                        if acao_str == "*" || acao_str.contains("evil.example.com") {
                            findings.push(json!({
                                "type": "websocket_attack",
                                "title": "WebSocket Endpoint: Permissive CORS Policy",
                                "severity": "high",
                                "mitre_attack": "T1071",
                                "description": format!(
                                    "WebSocket endpoint {} has a permissive CORS policy (Access-Control-Allow-Origin: {}). Combined with WebSocket upgrade, this enables CSWSH attacks.",
                                    url, acao_str
                                ),
                                "value": acao_str.to_string()
                            }));
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    // Check main page for WebSocket references in JS
    if let Ok(resp) = client.get(&base).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("new WebSocket(") || body.contains("io.connect(") || body.contains("socket.io") {
                findings.push(json!({
                    "type": "websocket_attack",
                    "title": "WebSocket Client Code Detected in Page Source",
                    "severity": "info",
                    "mitre_attack": "T1071",
                    "description": format!("WebSocket client initialization code found in page source of {}. WebSocket endpoints should be tested for authentication and origin validation.", base),
                    "value": base.clone()
                }));
            }
        }
    }

    let message = if findings.is_empty() {
        "No WebSocket vulnerabilities detected".to_string()
    } else {
        format!("{} WebSocket issue(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_websocket_attack(target: &str) {
    print_result(run_websocket_attack_result(target).await);
}
