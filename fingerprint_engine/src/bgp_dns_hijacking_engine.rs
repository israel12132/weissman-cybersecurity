//! BGP/DNS Hijacking Detector — queries RouteViews/RIPE RIS and public DNS APIs for hijack indicators.

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

fn extract_domain(target: &str) -> String {
    let t = target.trim();
    let stripped = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    stripped.split('/').next().unwrap_or(stripped).to_string()
}

pub async fn run_bgp_dns_hijacking_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let domain = extract_domain(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Query Cloudflare DNS-over-HTTPS for A records
    let doh_url = format!(
        "https://cloudflare-dns.com/dns-query?name={}&type=A",
        domain
    );
    let doh_resp = client
        .get(&doh_url)
        .header("Accept", "application/dns-json")
        .send()
        .await;

    let mut resolved_ips: Vec<String> = Vec::new();

    if let Ok(resp) = doh_resp {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(answers) = data.get("Answer").and_then(|a| a.as_array()) {
                for ans in answers {
                    if ans.get("type").and_then(|t| t.as_u64()) == Some(1) {
                        if let Some(ip) = ans.get("data").and_then(|d| d.as_str()) {
                            resolved_ips.push(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    if resolved_ips.is_empty() {
        findings.push(json!({
            "type": "bgp_dns_hijacking",
            "title": format!("DNS resolution failed for {}", domain),
            "severity": "info",
            "mitre_attack": "T1584.002",
            "description": format!("Could not resolve A records for {} via Cloudflare DoH. Domain may not exist or DNS may be configured unusually.", domain),
            "value": domain
        }));
        return EngineResult::ok(findings.clone(), format!("BGPDNSHijacking: {} findings", findings.len()));
    }

    // Cross-check with Google DoH for discrepancies (a sign of DNS poisoning)
    let google_doh = format!(
        "https://dns.google/resolve?name={}&type=A",
        domain
    );
    let mut google_ips: Vec<String> = Vec::new();
    if let Ok(resp) = client.get(&google_doh).send().await {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(answers) = data.get("Answer").and_then(|a| a.as_array()) {
                for ans in answers {
                    if ans.get("type").and_then(|t| t.as_u64()) == Some(1) {
                        if let Some(ip) = ans.get("data").and_then(|d| d.as_str()) {
                            google_ips.push(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    // Check for discrepancy between resolvers
    let cf_set: std::collections::HashSet<_> = resolved_ips.iter().collect();
    let g_set: std::collections::HashSet<_> = google_ips.iter().collect();
    let discrepancy: Vec<_> = cf_set.symmetric_difference(&g_set).collect();

    if !discrepancy.is_empty() {
        findings.push(json!({
            "type": "bgp_dns_hijacking",
            "title": format!("DNS resolution discrepancy detected for {}", domain),
            "severity": "high",
            "mitre_attack": "T1584.002",
            "description": format!(
                "Cloudflare DoH resolves {} to {:?} but Google DoH resolves to {:?}. \
                Discrepancies between authoritative resolvers may indicate DNS poisoning or BGP hijacking in progress.",
                domain, resolved_ips, google_ips
            ),
            "value": domain,
            "cloudflare_ips": resolved_ips,
            "google_ips": google_ips
        }));
    } else {
        findings.push(json!({
            "type": "bgp_dns_hijacking",
            "title": format!("DNS resolution consistent for {}: {:?}", domain, resolved_ips),
            "severity": "info",
            "mitre_attack": "T1584.002",
            "description": format!(
                "Both Cloudflare DoH and Google DoH resolve {} to the same IP addresses {:?}. \
                No immediate DNS hijacking indicators detected.",
                domain, resolved_ips
            ),
            "value": domain,
            "resolved_ips": resolved_ips
        }));
    }

    // Check RIPE Stat for BGP visibility
    if let Some(ip) = resolved_ips.first() {
        let ripe_url = format!(
            "https://stat.ripe.net/data/prefix-overview/data.json?resource={}",
            ip
        );
        if let Ok(resp) = client.get(&ripe_url).send().await {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let announced = data
                    .get("data")
                    .and_then(|d| d.get("announced"))
                    .and_then(|a| a.as_bool())
                    .unwrap_or(false);
                let block = data
                    .get("data")
                    .and_then(|d| d.get("block"))
                    .and_then(|b| b.get("resource"))
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown");

                findings.push(json!({
                    "type": "bgp_dns_hijacking",
                    "title": format!("BGP prefix visibility for {} ({})", ip, block),
                    "severity": "info",
                    "mitre_attack": "T1584.002",
                    "description": format!(
                        "IP {} belongs to BGP prefix {}. Announced: {}. \
                        Monitor RIPE RIS and RouteViews for unexpected origin AS changes which indicate BGP hijacking.",
                        ip, block, announced
                    ),
                    "value": ip,
                    "bgp_announced": announced,
                    "bgp_prefix": block
                }));
            }
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("BGPDNSHijacking: {} findings", findings.len()),
    )
}

pub async fn run_bgp_dns_hijacking(target: &str) {
    print_result(run_bgp_dns_hijacking_result(target).await);
}
