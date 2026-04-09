//! Anti-forensics: log exposure and deletion endpoint detection.
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

pub async fn run_antiforensics_result(target: &str) -> EngineResult {
    if target.trim().is_empty() { return EngineResult::error("target required"); }
    let client = build_client().await;
    let base = normalize_target(target);
    let paths = [
        ("/logs", false), ("/audit-logs", false), ("/api/logs", false),
        ("/api/audit/clear", true), ("/api/delete-logs", true),
        ("/health", false), ("/api/healthz", false), ("/status", false),
    ];
    let mut findings: Vec<serde_json::Value> = Vec::new();
    for (path, is_delete) in &paths {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if status == 200 {
                let empty_array = body.trim() == "[]" || body.trim() == "{}";
                let (severity, title) = if *is_delete {
                    ("critical", format!("Log deletion endpoint exposed: {}", path))
                } else if empty_array {
                    ("high", format!("Log suppression suspected (empty response): {}", path))
                } else {
                    ("medium", format!("Log endpoint exposed: {}", path))
                };
                findings.push(json!({
                    "type": "antiforensics",
                    "title": title,
                    "severity": severity,
                    "mitre_attack": "T1070",
                    "description": format!("Path {} returned {}. Empty: {}", path, status, empty_array)
                }));
            }
        }
    }
    EngineResult::ok(findings.clone(), format!("Anti-Forensics: {} findings", findings.len()))
}

pub async fn run_antiforensics(target: &str) {
    print_result(run_antiforensics_result(target).await);
}
