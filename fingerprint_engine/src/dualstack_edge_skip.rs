//! **Dual-stack edge skip** — A vs AAAA with Host + SNI, not `https://[ip]/`.
//!
//! A finding is emitted only when IPv4 and IPv6 HTTP diverge (status, WAF, or body).
//! Dual-stack DNS alone is not a medium finding.

use crate::engine_probes::{dns_a, empty_ok, extract_host, finding, header_value, HttpProbe};
use crate::engine_result::EngineResult;
use reqwest::Client;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub const ENGINE_ID: &str = "dualstack_edge_skip_fusion";
const MITRE: &str = "T1590.005";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackShot {
    pub family: &'static str,
    pub ip: String,
    pub status: u16,
    pub waf: bool,
    pub body_sha256: String,
    pub server: String,
    pub final_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipKind {
    Status,
    Waf,
    Body,
}

#[must_use]
pub fn classify_skip(v4: &StackShot, v6: &StackShot) -> Option<SkipKind> {
    if v4.status != v6.status {
        return Some(SkipKind::Status);
    }
    if v4.waf != v6.waf {
        return Some(SkipKind::Waf);
    }
    if v4.body_sha256 != v6.body_sha256 {
        return Some(SkipKind::Body);
    }
    None
}

fn shot(family: &'static str, ip: &str, probe: &HttpProbe) -> StackShot {
    StackShot {
        family,
        ip: ip.to_string(),
        status: probe.status,
        waf: probe.is_waf_block(),
        body_sha256: crate::crypto_engine::sha256_hex(probe.body.as_bytes()),
        server: header_value(&probe.headers, "server")
            .unwrap_or("")
            .to_string(),
        final_url: probe.final_url.clone(),
    }
}

async fn http_via_ip(host: &str, ip: &str, port: u16) -> Option<HttpProbe> {
    let parsed: IpAddr = ip.parse().ok()?;
    let addr = SocketAddr::new(parsed, port);
    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .resolve(host, addr)
        .build()
        .ok()?;
    crate::engine_probes::http_get(&client, &format!("https://{host}/")).await
}

pub async fn run_dualstack_edge_skip_fusion_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    if host.is_empty() {
        return EngineResult::error("target required");
    }

    let (v4s, v6s) = tokio::join!(dns_a(&host), crate::engine_probes::dns_aaaa(&host));
    if v4s.is_empty() || v6s.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    let v4_ip = v4s[0].as_str();
    let v6_ip = v6s[0].as_str();
    let (p4, p6) = tokio::join!(
        http_via_ip(&host, v4_ip, 443),
        http_via_ip(&host, v6_ip, 443)
    );

    let mut findings = Vec::new();
    match (p4, p6) {
        (Some(a), Some(b)) => {
            let s4 = shot("ipv4", v4_ip, &a);
            let s6 = shot("ipv6", v6_ip, &b);
            match classify_skip(&s4, &s6) {
                Some(kind) => {
                    let title = match kind {
                        SkipKind::Status => format!(
                            "Dual-stack skip: HTTP {} on IPv4 vs {} on IPv6",
                            s4.status, s6.status
                        ),
                        SkipKind::Waf => {
                            "Dual-stack skip: WAF present on one stack only".to_string()
                        }
                        SkipKind::Body => {
                            "Dual-stack skip: Host+SNI body differs across A vs AAAA".to_string()
                        }
                    };
                    findings.push(finding(
                        ENGINE_ID,
                        &title,
                        "high",
                        MITRE,
                        &format!(
                            "Pinned Host={host} SNI={host}. IPv4 {v4_ip} HTTP {} waf={} sha={} server={}. IPv6 {v6_ip} HTTP {} waf={} sha={} server={}. Controls that only wrap IPv4 (or only IPv6) are skipped.",
                            s4.status, s4.waf, s4.body_sha256, s4.server, s6.status, s6.waf, s6.body_sha256, s6.server
                        ),
                        target,
                    ));
                    if let Some(obj) = findings.last_mut().and_then(|f| f.as_object_mut()) {
                        obj.insert("ipv4".into(), json!(s4.ip));
                        obj.insert("ipv6".into(), json!(s6.ip));
                        obj.insert(
                            "skip_kind".into(),
                            json!(format!("{kind:?}").to_ascii_lowercase()),
                        );
                        obj.insert("asset".into(), json!("dualstack_skip"));
                    }
                }
                None => {
                    findings.push(finding(
                        ENGINE_ID,
                        &format!("Dual-stack HTTP parity held for {host}"),
                        "info",
                        MITRE,
                        &format!(
                            "Host+SNI to A {v4_ip} and AAAA {v6_ip} both HTTP {} waf={} — no skip proven this run.",
                            s4.status, s4.waf
                        ),
                        target,
                    ));
                }
            }
        }
        (Some(a), None) => {
            findings.push(finding(
                ENGINE_ID,
                &format!("IPv6 HTTPS with Host/SNI did not respond for {host}"),
                "medium",
                MITRE,
                &format!(
                    "IPv4 {v4_ip} HTTP {} via Host/SNI. AAAA {v6_ip} produced no HTTPS response — IPv6 path may be filtered, broken, or a different origin. Not treated as IPv4 success.",
                    a.status
                ),
                target,
            ));
        }
        (None, Some(b)) => {
            findings.push(finding(
                ENGINE_ID,
                &format!("IPv4 HTTPS with Host/SNI did not respond; IPv6 did for {host}"),
                "high",
                MITRE,
                &format!(
                    "AAAA {v6_ip} HTTP {} via Host/SNI while A {v4_ip} failed. Edge/WAF on IPv4 is not the control that IPv6 clients hit.",
                    b.status
                ),
                target,
            ));
        }
        (None, None) => return empty_ok(ENGINE_ID, target),
    }

    if findings.is_empty() {
        empty_ok(ENGINE_ID, target)
    } else {
        EngineResult::ok(findings.clone(), format!("{ENGINE_ID}: {}", findings.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shot_at(family: &'static str, status: u16, waf: bool, body: &str) -> StackShot {
        StackShot {
            family,
            ip: "198.51.100.1".into(),
            status,
            waf,
            body_sha256: crate::crypto_engine::sha256_hex(body.as_bytes()),
            server: "nginx".into(),
            final_url: "https://example.test/".into(),
        }
    }

    #[test]
    fn skip_on_status_mismatch() {
        let a = shot_at("ipv4", 403, true, "blocked");
        let b = shot_at("ipv6", 200, false, "ok");
        assert_eq!(classify_skip(&a, &b), Some(SkipKind::Status));
    }

    #[test]
    fn skip_on_waf_only() {
        let a = shot_at("ipv4", 200, true, "same");
        let b = shot_at("ipv6", 200, false, "same");
        assert_eq!(classify_skip(&a, &b), Some(SkipKind::Waf));
    }

    #[test]
    fn skip_on_body_hash() {
        let a = shot_at("ipv4", 200, false, "origin-a");
        let b = shot_at("ipv6", 200, false, "origin-b");
        assert_eq!(classify_skip(&a, &b), Some(SkipKind::Body));
    }

    #[test]
    fn parity_is_not_a_finding_class() {
        let a = shot_at("ipv4", 200, false, "same");
        let b = shot_at("ipv6", 200, false, "same");
        assert!(classify_skip(&a, &b).is_none());
    }
}
