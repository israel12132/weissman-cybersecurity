//! Ghost network / WAF evasion — implementation lives in `weissman-engines`.

pub use weissman_engines::stealth::*;

/// Run stealth engine health check on a target (tests WAF detection capabilities).
pub async fn run_stealth_engine_result(target: &str) -> crate::engine_result::EngineResult {
    use serde_json::json;
    
    // Build a basic client with default stealth config
    let config = StealthConfig::default();
    let client = build_client(&config, 10);
    
    // Try to detect WAF on target
    let mut findings = vec![];
    
    match client.get(target).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            
            if is_waf_or_rate_limit(status, &body) {
                findings.push(json!({
                    "type": "stealth_engine",
                    "subtype": "waf_detected",
                    "target": target,
                    "status_code": status,
                    "severity": "info",
                    "title": "WAF/Rate limiting detected on target"
                }));
            }
        }
        Err(e) => {
            findings.push(json!({
                "type": "stealth_engine",
                "subtype": "connectivity_error",
                "target": target,
                "error": e.to_string(),
                "severity": "low",
                "title": "Could not reach target for stealth analysis"
            }));
        }
    }
    
    let msg = format!("Stealth engine: analyzed {} - {} observations", target, findings.len());
    crate::engine_result::EngineResult::ok(findings, msg)
}
