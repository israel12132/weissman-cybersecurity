//! HTTP perimeter probes for WAF/CDN presence and script-delivery hardening gaps.
//! These are remote surface checks only — host-level EDR evasion (AMSI bypass, syscall
//! unhooking, process injection) requires the endpoint agent.
use crate::engine_probes::{
    empty_ok, finding, has_header, header_value, http_client, http_get, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

pub async fn run_edr_evasion_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    if let Some(p) = http_get(&client, &base).await {
        let waf_headers = [
            ("cf-ray", "Cloudflare"),
            ("x-sucuri-id", "Sucuri WAF"),
            ("x-akamai-transformed", "Akamai CDN/WAF"),
            ("x-imperva-waf", "Imperva WAF"),
        ];
        let observed: Vec<&str> = waf_headers
            .iter()
            .filter(|(h, _)| has_header(&p.headers, h))
            .map(|(_, label)| *label)
            .collect();
        if !observed.is_empty() {
            findings.push(finding(
                "edr_evasion",
                "Edge WAF/CDN headers observed (HTTP perimeter)",
                "info",
                "T1562",
                &format!(
                    "Response from {} includes edge-protection headers ({:?}). This confirms a WAF/CDN layer — not host EDR telemetry.",
                    p.final_url, observed
                ),
                target,
            ));
        }

        if !has_header(&p.headers, "x-content-type-options") {
            findings.push(finding(
                "edr_evasion",
                "Missing X-Content-Type-Options (script MIME confusion risk)",
                "low",
                "T1562",
                &format!(
                    "{} lacks X-Content-Type-Options: nosniff — browsers may execute attacker-controlled MIME types from this origin.",
                    p.final_url
                ),
                target,
            ));
        }

        let server = header_value(&p.headers, "server").unwrap_or("");
        let powered = header_value(&p.headers, "x-powered-by").unwrap_or("");
        if server.is_empty() && powered.is_empty() && p.status >= 200 && p.status < 400 {
            findings.push(finding(
                "edr_evasion",
                "Minimal HTTP fingerprint (stripped Server headers)",
                "info",
                "T1071",
                &format!(
                    "Response from {} omits Server and X-Powered-By — common on reverse proxies and C2 fronting; review outbound allow-lists.",
                    p.final_url
                ),
                target,
            ));
        }
    }

    let malicious_uas = ["sqlmap/1.0", "Nikto/2.1.6", "Mozilla/5.0 (compatible; Googlebot/2.1)"];
    let mut unblocked = 0usize;
    for ua in &malicious_uas {
        if let Some(p) = crate::engine_probes::http_get_with_headers(
            &client,
            &base,
            &[("User-Agent", ua)],
        )
        .await
        {
            if p.status >= 200 && p.status < 400 {
                unblocked += 1;
            }
        }
    }
    if unblocked == malicious_uas.len() {
        findings.push(finding(
            "edr_evasion",
            "HTTP edge did not block scanner User-Agents",
            "medium",
            "T1562",
            &format!(
                "All {} scanner/spider User-Agent probes received HTTP 2xx/3xx from {} — no edge WAF block observed (host EDR not tested).",
                unblocked, base
            ),
            target,
        ));
    }

    for path in ["/debug", "/trace", "/actuator", "/.env", "/server-status"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status >= 200 && p.status < 400 && p.body.len() > 16 {
                findings.push(finding(
                    "edr_evasion",
                    &format!("Debug/admin path reachable: {}", path),
                    "medium",
                    "T1562",
                    &format!(
                        "{} returned HTTP {} ({} B) — exposed diagnostics weaken detection and aid evasion.",
                        p.final_url, p.status, p.body.len()
                    ),
                    target,
                ));
            }
        }
    }

    if findings.is_empty() {
        empty_ok("edr_evasion", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("edr_evasion: {} remote perimeter signal(s)", findings.len()),
        )
    }
}

pub async fn run_edr_evasion(target: &str) {
    print_result(run_edr_evasion_result(target).await);
}
