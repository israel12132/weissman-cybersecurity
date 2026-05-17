//! IoT firmware exposure and default credential detection.
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
    if t.starts_with("http://") || t.starts_with("https://") { t.to_string() } else { format!("https://{}", t) }
}

pub async fn run_iot_firmware_result(target: &str) -> EngineResult {
    if target.trim().is_empty() { return EngineResult::error("target required"); }
    let client = build_client().await;
    let base = normalize_target(target);
    let paths = ["/cgi-bin/", "/cgi-bin/home.cgi", "/goform/", "/HNAP1/", "/api/system", "/api/device-info", "/api/firmware", "/upgrade.cgi"];
    let mut findings: Vec<serde_json::Value> = Vec::new();
    for path in &paths {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default().to_lowercase();
            if status == 200 {
                let has_default_creds = body.contains("admin") || body.contains("password") || body.contains("default");
                let severity = if has_default_creds { "critical" } else { "high" };
                findings.push(json!({
                    "type": "iot_firmware",
                    "title": format!("IoT endpoint exposed: {}", path),
                    "severity": severity,
                    "mitre_attack": "T1078",
                    "description": format!("Path {} returned 200. Default credential indicators: {}", path, has_default_creds)
                }));
            }
        }
    }
    EngineResult::ok(findings.clone(), format!("IoT Firmware: {} findings", findings.len()))
}

pub async fn run_iot_firmware(target: &str) {
    print_result(run_iot_firmware_result(target).await);
}
