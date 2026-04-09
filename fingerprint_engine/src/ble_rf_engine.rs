//! BLE/RF wireless management API exposure detection.
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

pub async fn run_ble_rf_result(target: &str) -> EngineResult {
    if target.trim().is_empty() { return EngineResult::error("target required"); }
    let client = build_client().await;
    let base = normalize_target(target);
    let paths = ["/api/ble/devices", "/api/wireless", "/api/bluetooth", "/api/zigbee", "/api/zwave", "/api/rf", "/api/network/wireless"];
    let mut findings: Vec<serde_json::Value> = Vec::new();
    for path in &paths {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().as_u16() == 200 {
                findings.push(json!({
                    "type": "ble_rf",
                    "title": format!("Wireless management API exposed: {}", path),
                    "severity": "high",
                    "mitre_attack": "T1040",
                    "description": format!("Path {} returned 200, potentially exposing wireless configuration.", path)
                }));
            }
        }
    }
    EngineResult::ok(findings.clone(), format!("BLE/RF: {} findings", findings.len()))
}

pub async fn run_ble_rf(target: &str) {
    print_result(run_ble_rf_result(target).await);
}
