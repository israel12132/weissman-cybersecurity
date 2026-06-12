//! PQC Readiness Scanner — live TLS cert/key analysis and PQC capability discovery.

use crate::engine_probes::{
    empty_ok, extract_host, finding_with_probe_depth, header_value, http_client, http_get,
    normalize_url, tls_cert_details,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

const PQC_PROBE_DEPTH: &str = "pqc_tls_posture";

fn pqc_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    extra: Value,
) -> Value {
    let mut f = finding_with_probe_depth(
        "pqc_scanner",
        title,
        severity,
        "T1600",
        description,
        target,
        PQC_PROBE_DEPTH,
    );
    if let Some(obj) = f.as_object_mut() {
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    f
}

pub async fn run_pqc_scanner_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let domain = extract_host(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();

    if let Some(cert) = tls_cert_details(&domain).await {
        if cert.expired {
            findings.push(pqc_finding(
                &format!("Expired TLS certificate for {}", domain),
                "high",
                &format!(
                    "Live cert for {} is expired (issuer: {}). Expired certs block crypto-agility migrations including PQC hybrid rollouts.",
                    domain, cert.issuer
                ),
                target,
                json!({ "issuer": cert.issuer, "subject": cert.subject }),
            ));
        } else if cert.days_until_expiry < 30 {
            findings.push(pqc_finding(
                &format!("TLS certificate expires in {} days", cert.days_until_expiry),
                "medium",
                &format!(
                    "Certificate for {} expires in {} days (sig: {}, {}-bit key). Short runway complicates staged PQC hybrid cutover.",
                    domain, cert.days_until_expiry, cert.signature_algorithm, cert.public_key_bits
                ),
                target,
                json!({ "days_until_expiry": cert.days_until_expiry }),
            ));
        }

        if cert.self_signed {
            findings.push(pqc_finding(
                "Self-signed TLS certificate",
                "high",
                &format!(
                    "Peer cert for {} is self-signed (subject={}). No public CA path — PQC migration must include a new trust anchor.",
                    domain, cert.subject
                ),
                target,
                json!({ "subject": cert.subject }),
            ));
        }

        if cert.is_rsa && cert.public_key_bits < 2048 {
            findings.push(pqc_finding(
                &format!("Weak RSA key ({} bits)", cert.public_key_bits),
                "high",
                &format!(
                    "Live cert uses {}-bit RSA with {} signature — below NIST minimum and quantum-vulnerable. Migrate to ≥2048-bit RSA or ECDSA, then plan ML-KEM hybrid.",
                    cert.public_key_bits, cert.signature_algorithm
                ),
                target,
                json!({ "public_key_bits": cert.public_key_bits, "signature_algorithm": cert.signature_algorithm }),
            ));
        } else if cert.is_rsa {
            findings.push(pqc_finding(
                &format!("RSA {}-bit certificate in use", cert.public_key_bits),
                "medium",
                &format!(
                    "Live TLS cert for {} uses RSA {}-bit / {} — vulnerable to Shor's algorithm at scale. Plan ML-KEM (FIPS 203) hybrid key exchange and ML-DSA (FIPS 204) signatures.",
                    domain, cert.public_key_bits, cert.signature_algorithm
                ),
                target,
                json!({ "public_key_bits": cert.public_key_bits, "is_rsa": true }),
            ));
        }

        if cert.is_ec && cert.public_key_bits <= 256 {
            findings.push(pqc_finding(
                &format!("ECDSA P-{} certificate", cert.public_key_bits),
                "info",
                &format!(
                    "ECDSA {}-bit curve in use (sig: {}). Prefer hybrid X25519MLKEM768 when the TLS stack supports it.",
                    cert.public_key_bits, cert.signature_algorithm
                ),
                target,
                json!({ "public_key_bits": cert.public_key_bits, "is_ec": true }),
            ));
        }
    }

    if let Some(p) = http_get(&client, &base).await {
        let hsts = header_value(&p.headers, "strict-transport-security").unwrap_or("");
        if hsts.is_empty() {
            findings.push(pqc_finding(
                "Missing HSTS header",
                "medium",
                &format!(
                    "HTTPS response from {} lacks Strict-Transport-Security — initial HTTP downgrade remains possible during PQC migration windows.",
                    p.final_url
                ),
                target,
                json!({}),
            ));
        } else if !hsts.contains("preload") {
            findings.push(pqc_finding(
                "HSTS without preload directive",
                "low",
                &format!(
                    "HSTS present ('{}') but lacks preload — weaker downgrade resistance.",
                    hsts
                ),
                target,
                json!({ "hsts": hsts }),
            ));
        }
    }

    let pqc_paths = [
        "/.well-known/pqc-capabilities",
        "/.well-known/quantum-safe",
        "/.well-known/pqc",
        "/pqc/status",
    ];
    for path in &pqc_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status >= 200 && p.status < 300 && p.body.len() > 8 {
                let body_low = p.body.to_ascii_lowercase();
                if body_low.contains("kyber")
                    || body_low.contains("ml-kem")
                    || body_low.contains("dilithium")
                    || body_low.contains("ml-dsa")
                    || body_low.contains("pqc")
                {
                    findings.push(pqc_finding(
                        &format!("PQC capabilities document at {}", path),
                        "info",
                        &format!(
                            "Endpoint {} advertises post-quantum algorithms in the response body — review supported hybrids (e.g. X25519MLKEM768).",
                            p.final_url
                        ),
                        target,
                        json!({ "url": p.final_url }),
                    ));
                    break;
                }
            }
        }
    }

    let crt_url = format!("https://crt.sh/?q={}&output=json", domain);
    if let Some(p) = http_get(&client, &crt_url).await {
        if p.status == 200 && p.body.starts_with('[') {
            if let Ok(certs) = serde_json::from_str::<Value>(&p.body) {
                if let Some(arr) = certs.as_array() {
                    let rsa_certs = arr
                        .iter()
                        .filter(|c| c.get("name_value").and_then(|v| v.as_str()).is_some())
                        .count();
                    if rsa_certs > 0
                        && findings.iter().all(|f| {
                            f.get("title")
                                .and_then(|t| t.as_str())
                                .is_none_or(|t| !t.contains("RSA"))
                        })
                    {
                        findings.push(pqc_finding(
                            &format!("{} CT log entries for {}", arr.len(), domain),
                            "info",
                            &format!(
                                "crt.sh returned {} certificate transparency entries for {}. Inventory all active RSA certs before PQC hybrid rollout.",
                                arr.len(), domain
                            ),
                            target,
                            json!({ "ct_count": arr.len() }),
                        ));
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        empty_ok("pqc_scanner", target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("pqc_scanner: {} live finding(s)", findings.len()),
        )
    }
}

pub async fn run_pqc_scanner(target: &str) {
    print_result(run_pqc_scanner_result(target).await);
}
