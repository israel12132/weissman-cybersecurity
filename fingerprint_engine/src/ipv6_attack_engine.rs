//! IPv6 Attack Engine — IPv6 exposure, dual-stack skip (Host+SNI), and leaked ULA/link-local.
//!
//! Dual-stack DNS alone is informational. HTTP uses pinned Host+SNI via A/AAAA, never
//! `https://[ip]/` without a name. No AAAA → honest empty, not a fabricated finding.

use crate::dualstack_edge_skip::ENGINE_ID as SKIP_ENGINE;
use crate::engine_probes::{dns_a, dns_aaaa, empty_ok, extract_host, finding};
use crate::engine_result::{print_result, EngineResult};
use serde_json::json;

pub async fn run_ipv6_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let domain = extract_host(target);
    if domain.is_empty() {
        return EngineResult::error("target required");
    }

    let (ipv4_addrs, ipv6_addrs) = tokio::join!(dns_a(&domain), dns_aaaa(&domain));
    let mut findings: Vec<serde_json::Value> = Vec::new();

    if ipv6_addrs.is_empty() {
        return empty_ok("ipv6_attack", target);
    }

    for addr in &ipv6_addrs {
        let low = addr.to_ascii_lowercase();
        if low.starts_with("fe80")
            || low.starts_with("::1")
            || low.starts_with("fc")
            || low.starts_with("fd")
        {
            findings.push(finding(
                "ipv6_attack",
                &format!("Private/link-local IPv6 address in public DNS: {addr}"),
                "high",
                "T1590.005",
                &format!(
                    "AAAA for {domain} is {addr}. Publishing ULA/link-local in public DNS leaks internal topology."
                ),
                target,
            ));
        }
    }

    if !ipv4_addrs.is_empty() {
        // Real skip proof lives in dualstack_edge_skip_fusion (Host+SNI pin).
        let skip = crate::dualstack_edge_skip::run_dualstack_edge_skip_fusion_result(target).await;
        if skip.success {
            for mut f in skip.findings {
                if let Some(obj) = f.as_object_mut() {
                    obj.insert("source_engine".into(), json!(SKIP_ENGINE));
                    obj.entry("type").or_insert(json!("ipv6_attack"));
                }
                findings.push(f);
            }
        }
    } else {
        findings.push(finding(
            "ipv6_attack",
            &format!("IPv6-only DNS for {domain}"),
            "info",
            "T1590.005",
            &format!(
                "AAAA {:?} with no A records. IPv4-only WAF/logging will not see this name.",
                ipv6_addrs
            ),
            target,
        ));
    }

    if findings.is_empty() {
        empty_ok("ipv6_attack", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("IPv6Attack: {} findings", findings.len()),
        )
    }
}

pub async fn run_ipv6_attack(target: &str) {
    print_result(run_ipv6_attack_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_strips_https_scheme_and_path() {
        assert_eq!(extract_host("https://example.com/path/to"), "example.com");
    }

    #[test]
    fn extract_host_strips_http_scheme() {
        assert_eq!(extract_host("http://example.com"), "example.com");
    }
}
