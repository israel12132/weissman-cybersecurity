//! SCADA/ICS wrapper around ot_ics_engine.
use crate::engine_result::{print_result, EngineResult};
use serde_json::json;

fn extract_host(target: &str) -> String {
    let t = target.trim();
    let t = t.trim_start_matches("http://").trim_start_matches("https://");
    let t = t.split('/').next().unwrap_or(t);
    let t = t.split(':').next().unwrap_or(t);
    t.to_string()
}

pub async fn run_scada_ics_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let domains_json = serde_json::to_string(&[&host]).unwrap_or_else(|_| "[]".to_string());
    let hosts = crate::ot_ics_engine::resolve_scan_hosts(&domains_json, "[]", 64);
    let fingerprints = crate::ot_ics_engine::scan_hosts_passive(&hosts).await;
    let mut findings: Vec<serde_json::Value> = Vec::new();
    for fp in &fingerprints {
        let severity = if fp.confidence > 0.8 { "critical" } else if fp.confidence > 0.5 { "high" } else { "medium" };
        findings.push(json!({
            "type": "scada_ics",
            "title": format!("OT/ICS device detected: {} on {}:{}", fp.protocol, fp.host, fp.port),
            "severity": severity,
            "mitre_attack": "T0843",
            "description": format!("Vendor: {}, confidence: {:.2}, protocol: {}", fp.vendor_hint, fp.confidence, fp.protocol)
        }));
    }
    EngineResult::ok(findings.clone(), format!("SCADA/ICS: {} findings", findings.len()))
}

pub async fn run_scada_ics(target: &str) {
    print_result(run_scada_ics_result(target).await);
}
