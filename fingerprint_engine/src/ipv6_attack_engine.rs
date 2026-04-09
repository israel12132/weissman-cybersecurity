//! IPv6 Attack Engine — detects IPv6 exposure, misconfigured dual-stack, and DHCPv6 indicators.

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
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

pub async fn run_ipv6_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let domain = extract_domain(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Resolve AAAA records via Cloudflare DoH
    let doh_url = format!(
        "https://cloudflare-dns.com/dns-query?name={}&type=AAAA",
        domain
    );
    let mut ipv6_addrs: Vec<String> = Vec::new();

    if let Ok(resp) = client
        .get(&doh_url)
        .header("Accept", "application/dns-json")
        .send()
        .await
    {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(answers) = data.get("Answer").and_then(|a| a.as_array()) {
                for ans in answers {
                    // AAAA = type 28
                    if ans.get("type").and_then(|t| t.as_u64()) == Some(28) {
                        if let Some(ip) = ans.get("data").and_then(|d| d.as_str()) {
                            ipv6_addrs.push(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    if ipv6_addrs.is_empty() {
        findings.push(json!({
            "type": "ipv6_attack",
            "title": format!("No IPv6 (AAAA) records found for {}", domain),
            "severity": "info",
            "mitre_attack": "T1590.005",
            "description": format!(
                "Domain {} has no AAAA DNS records — IPv6 is not configured. \
                IPv6-only security controls and monitoring may not be needed, but check for link-local exposure on internal networks.",
                domain
            ),
            "value": domain
        }));
        return EngineResult::ok(findings.clone(), format!("IPv6Attack: {} findings", findings.len()));
    }

    findings.push(json!({
        "type": "ipv6_attack",
        "title": format!("IPv6 addresses exposed for {}: {:?}", domain, ipv6_addrs),
        "severity": "info",
        "mitre_attack": "T1590.005",
        "description": format!(
            "Domain {} has AAAA records: {:?}. Ensure IPv6 firewall rules are equivalent to IPv4 rules. \
            Dual-stack misconfigurations often leave IPv6 paths unfiltered.",
            domain, ipv6_addrs
        ),
        "value": domain,
        "ipv6_addresses": ipv6_addrs.clone()
    }));

    // Check for link-local or loopback addresses (misconfiguration)
    for addr in &ipv6_addrs {
        if addr.starts_with("fe80") || addr.starts_with("::1") || addr.starts_with("fc") || addr.starts_with("fd") {
            findings.push(json!({
                "type": "ipv6_attack",
                "title": format!("Private/link-local IPv6 address exposed in DNS: {}", addr),
                "severity": "high",
                "mitre_attack": "T1590.005",
                "description": format!(
                    "DNS AAAA record for {} resolves to private/link-local IPv6 address {}. \
                    Exposing link-local or ULA addresses in public DNS leaks internal network topology \
                    and may enable Neighbor Discovery spoofing attacks.",
                    domain, addr
                ),
                "value": addr
            }));
        }
    }

    // Try to access the target via IPv6 URL if we have an address
    for ipv6 in ipv6_addrs.iter().take(1) {
        let ipv6_url = format!("https://[{}]/", ipv6);
        if let Ok(resp) = client.get(&ipv6_url).send().await {
            let status = resp.status().as_u16();
            findings.push(json!({
                "type": "ipv6_attack",
                "title": format!("IPv6 HTTP access confirmed: {} -> HTTP {}", ipv6, status),
                "severity": "medium",
                "mitre_attack": "T1590.005",
                "description": format!(
                    "The target responded to HTTP requests via IPv6 address {} (HTTP {}). \
                    Verify that WAF, rate-limiting, and all security controls also apply to IPv6 traffic. \
                    DHCPv6 and Neighbor Discovery spoofing attacks target dual-stack environments.",
                    ipv6, status
                ),
                "value": ipv6_url
            }));
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("IPv6Attack: {} findings", findings.len()),
    )
}

pub async fn run_ipv6_attack(target: &str) {
    print_result(run_ipv6_attack_result(target).await);
}
