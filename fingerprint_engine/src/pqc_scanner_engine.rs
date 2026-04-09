//! PQC Readiness Scanner — checks post-quantum cryptography support and TLS posture.

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

fn extract_domain(target: &str) -> String {
    let t = target.trim();
    let stripped = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    stripped.split('/').next().unwrap_or(stripped).to_string()
}

pub async fn run_pqc_scanner_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let domain = extract_domain(&base);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Probe root for TLS/security headers
    if let Ok(resp) = client.get(&base).send().await {
        let headers = resp.headers().clone();

        // Check HSTS
        let hsts = headers
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if hsts.is_empty() {
            findings.push(json!({
                "type": "pqc_scanner",
                "title": format!("Missing HSTS header on {}", domain),
                "severity": "medium",
                "mitre_attack": "T1600",
                "description": "Strict-Transport-Security header is absent. Without HSTS, connections may be \
                    downgraded by quantum-capable adversaries intercepting the initial HTTP request.",
                "value": base
            }));
        } else if !hsts.contains("preload") {
            findings.push(json!({
                "type": "pqc_scanner",
                "title": format!("HSTS without preload on {}", domain),
                "severity": "low",
                "mitre_attack": "T1600",
                "description": format!(
                    "HSTS header present ({}) but lacks 'preload' directive. Preloading provides stronger \
                    protection against downgrade attacks relevant to post-quantum threat scenarios.",
                    hsts
                ),
                "value": base
            }));
        }

        // Check for certificate transparency header
        let ct = headers
            .get("expect-ct")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct.is_empty() {
            findings.push(json!({
                "type": "pqc_scanner",
                "title": format!("No Certificate Transparency enforcement on {}", domain),
                "severity": "info",
                "mitre_attack": "T1600",
                "description": "Expect-CT header is absent. Certificate Transparency is part of a robust \
                    PKI posture needed before migrating to post-quantum certificates.",
                "value": base
            }));
        }
    }

    // Probe well-known PQC endpoints
    let pqc_paths = [
        "/.well-known/pqc-capabilities",
        "/.well-known/quantum-safe",
        "/.well-known/pqc",
        "/pqc/status",
    ];
    for path in &pqc_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&url).send().await {
            if r.status().is_success() {
                findings.push(json!({
                    "type": "pqc_scanner",
                    "title": format!("PQC capabilities endpoint found: {}", url),
                    "severity": "info",
                    "mitre_attack": "T1600",
                    "description": format!(
                        "A PQC capabilities endpoint exists at {}. Review it to confirm supported \
                        post-quantum algorithms (e.g. X25519MLKEM768, Kyber, CRYSTALS-Dilithium).",
                        url
                    ),
                    "value": url
                }));
            }
        }
    }

    // Check crt.sh for certificate details
    let crt_url = format!("https://crt.sh/?q={}&output=json", domain);
    if let Ok(resp) = client.get(&crt_url).send().await {
        if let Ok(certs) = resp.json::<serde_json::Value>().await {
            if let Some(arr) = certs.as_array() {
                // Look for RSA certificates (quantum-vulnerable)
                let has_rsa = arr.iter().any(|c| {
                    c.get("issuer_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_lowercase().contains("rsa"))
                        .unwrap_or(false)
                });
                if has_rsa {
                    findings.push(json!({
                        "type": "pqc_scanner",
                        "title": format!("RSA certificate in use for {} — quantum-vulnerable", domain),
                        "severity": "medium",
                        "mitre_attack": "T1600",
                        "description": format!(
                            "Certificate Transparency logs show RSA certificates for {}. RSA is vulnerable \
                            to Shor's algorithm on a sufficiently large quantum computer. Migration to \
                            post-quantum algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium, FALCON, SPHINCS+) \
                            should be planned.",
                            domain
                        ),
                        "value": domain
                    }));
                }
            }
        }
    }

    // Overall PQC readiness assessment
    findings.push(json!({
        "type": "pqc_scanner",
        "title": format!("PQC readiness assessment for {}", domain),
        "severity": "info",
        "mitre_attack": "T1600",
        "description": format!(
            "Post-quantum cryptography readiness scan completed for {}. \
            NIST PQC standards (FIPS 203 ML-KEM/Kyber, FIPS 204 ML-DSA/Dilithium, FIPS 205 SLH-DSA/SPHINCS+) \
            are now finalized. Verify TLS library support for X25519MLKEM768 hybrid key exchange.",
            domain
        ),
        "value": domain
    }));

    EngineResult::ok(
        findings.clone(),
        format!("PQCScanner: {} findings", findings.len()),
    )
}

pub async fn run_pqc_scanner(target: &str) {
    print_result(run_pqc_scanner_result(target).await);
}
