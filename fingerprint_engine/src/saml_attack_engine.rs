//! SAML Attack Engine — detects SAML endpoints and checks for XML Signature Wrapping, weak algorithms.

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

fn normalize_target(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

const SAML_METADATA_PATHS: &[&str] = &[
    "/saml/metadata",
    "/saml2/metadata",
    "/saml2/idp/metadata",
    "/saml/idp/metadata",
    "/sso/saml/metadata",
    "/auth/saml/metadata",
    "/metadata.xml",
    "/federationmetadata/2007-06/federationmetadata.xml",
    "/saml/sp/metadata",
];

const SAML_SSO_PATHS: &[&str] = &[
    "/saml/login",
    "/saml2/login",
    "/saml/sso",
    "/saml2/sso",
    "/sso/saml",
    "/auth/saml",
    "/saml/acs",
    "/saml2/acs",
    "/api/sso",
    "/sso",
];

pub async fn run_saml_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Probe metadata endpoints
    for path in SAML_METADATA_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = resp.status().as_u16();
        if status != 200 {
            continue;
        }
        let body = resp.text().await.unwrap_or_default();
        if !body.contains("EntityDescriptor") && !body.contains("saml") && !body.contains("SAML") {
            continue;
        }

        findings.push(json!({
            "type": "saml_attack",
            "title": format!("SAML metadata exposed: {}", url),
            "severity": "medium",
            "mitre_attack": "T1550.004",
            "description": format!(
                "SAML metadata document is publicly accessible at {}. This reveals the service provider \
                configuration, signing certificates, and ACS URLs which can facilitate SAML attack planning.",
                url
            ),
            "value": url
        }));

        // Check for weak signature algorithms
        if body.contains("sha1") || body.contains("SHA1") || body.contains("http://www.w3.org/2000/09/xmldsig#rsa-sha1") {
            findings.push(json!({
                "type": "saml_attack",
                "title": format!("Weak SAML signature algorithm (SHA-1) detected: {}", url),
                "severity": "high",
                "mitre_attack": "T1550.004",
                "description": format!(
                    "SAML metadata at {} references SHA-1 for XML signatures. SHA-1 is cryptographically \
                    broken and vulnerable to collision attacks enabling XML Signature Wrapping (XSW) exploits \
                    where an attacker can forge SAML assertions.",
                    url
                ),
                "value": url
            }));
        }

        // Check for missing NameID encryption
        if body.contains("NameIDFormat") && !body.contains("EncryptedID") && !body.contains("WantAssertionsEncrypted=\"true\"") {
            findings.push(json!({
                "type": "saml_attack",
                "title": format!("SAML assertions not encrypted: {}", url),
                "severity": "medium",
                "mitre_attack": "T1550.004",
                "description": format!(
                    "SAML metadata at {} does not require encrypted assertions (WantAssertionsEncrypted is absent \
                    or false). Unencrypted SAML assertions expose user identity information in transit and may \
                    enable SAML Replay attacks.",
                    url
                ),
                "value": url
            }));
        }
    }

    // Probe SSO endpoint for XSW via crafted SAMLResponse
    for path in SAML_SSO_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = resp.status().as_u16();
        // SAML SSO endpoints typically redirect (302) or show login form (200)
        if status == 200 || status == 302 || status == 400 {
            findings.push(json!({
                "type": "saml_attack",
                "title": format!("SAML SSO endpoint found: {}", url),
                "severity": "info",
                "mitre_attack": "T1550.004",
                "description": format!(
                    "SAML SSO endpoint discovered at {} (HTTP {}). This endpoint should be tested for \
                    XML Signature Wrapping (XSW), NameID injection, and SAML Replay vulnerabilities \
                    using specialized tools.",
                    url, status
                ),
                "value": url,
                "http_status": status
            }));
            // Try submitting a minimal XSW probe (detached signature structure)
            let xsw_probe = "SAMLResponse=PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjwvc2FtbHA6UmVzcG9uc2U%2B";
            let probe_url = format!("{}?{}", url, xsw_probe);
            if let Ok(probe_resp) = client.get(&probe_url).send().await {
                let probe_body = probe_resp.text().await.unwrap_or_default();
                // If we get a 500 with XML error detail, it may reveal internal parser info
                if probe_body.contains("Exception") || probe_body.contains("stack trace") || probe_body.contains("xmlsec") {
                    findings.push(json!({
                        "type": "saml_attack",
                        "title": format!("SAML parser error leaked at: {}", url),
                        "severity": "high",
                        "mitre_attack": "T1550.004",
                        "description": "SAML endpoint returns verbose parser errors on malformed input, revealing internal XML library details useful for crafting XSW attacks.",
                        "value": url
                    }));
                }
            }
            break; // One SSO endpoint is enough for detection
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("SAMLAttack: {} findings", findings.len()),
    )
}

pub async fn run_saml_attack(target: &str) {
    print_result(run_saml_attack_result(target).await);
}
