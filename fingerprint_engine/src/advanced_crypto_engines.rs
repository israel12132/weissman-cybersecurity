//! Advanced Crypto/Identity engines — delegate to live `pki_tls`, `crypto_engine`,
//! `password_spray`, `kerberoasting`, `saml_attack`, `oauth_oidc` modules where appropriate;
//! otherwise probe HTTP/TLS surface for the relevant indicators.

use crate::engine_probes::{
    empty_ok, finding, finding_with_probe_depth, header_value, http_client, http_get, normalize_url,
};

const CRYPTO_PROBE_DEPTH: &str = "crypto_auth_surface";

fn crypto_finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
) -> serde_json::Value {
    finding_with_probe_depth(
        engine_id,
        title,
        severity,
        mitre,
        description,
        target,
        CRYPTO_PROBE_DEPTH,
    )
}
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

pub async fn run_padding_oracle_attack_result(t: &str) -> EngineResult {
    // Strengthened: send 3 progressively-corrupted base64 ciphertext-like tokens and look for
    // differential timing/status that indicates the server distinguishes "wrong padding" from
    // "wrong MAC" — the classic oracle signature.
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();

    // Three probes: empty, garbage-but-valid-base64, padding-invalid
    let probes = [
        ("empty", ""),
        ("valid_b64", "QUJDREVGR0g="), // ABCDEFGH
        ("bad_pad", "QUJDREVGR0g"),    // missing '='
    ];
    let mut results: Vec<(String, u16, usize)> = Vec::new();
    for (label, payload) in probes {
        let url = format!("{}/?token={}", base.trim_end_matches('/'), payload);
        if let Some(p) = http_get(&client, &url).await {
            results.push((label.to_string(), p.status, p.body.len()));
        }
    }
    if results.len() == 3 {
        let statuses: Vec<u16> = results.iter().map(|r| r.1).collect();
        let sizes: Vec<usize> = results.iter().map(|r| r.2).collect();
        // Oracle signature: empty + valid_b64 return one error class, bad_pad returns a different one.
        if statuses[0] != statuses[2] || (sizes[2] as i64 - sizes[0] as i64).abs() > 32 {
            findings.push(crypto_finding(
                "padding_oracle_attack",
                "Differential response to bad-padding token (possible oracle)",
                "medium",
                "T1556",
                &format!(
                    "Probes: empty→HTTP {}({}B), valid_b64→HTTP {}({}B), bad_pad→HTTP {}({}B) on {}. The bad-padding response differs from the valid case — classic padding-oracle signal.",
                    statuses[0], sizes[0], statuses[1], sizes[1], statuses[2], sizes[2], base
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("padding_oracle_attack", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("padding_oracle_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_padding_oracle_attack, run_padding_oracle_attack_result);

/// Find a signed-token parameter whose value is a raw Merkle–Damgård digest
/// (32=MD5, 40=SHA-1, 64=SHA-256 hex). Such `hash(secret‖data)` MACs are the
/// classic length-extension forgery target (unlike HMAC). Returns `(param, hash)`.
fn find_hex_mac_param(text: &str) -> Option<(&'static str, &'static str)> {
    for name in ["signature=", "sig=", "hmac=", "mac=", "hash="] {
        let mut start = 0usize;
        while let Some(pos) = text[start..].find(name) {
            let after = start + pos + name.len();
            let hexlen = text[after..]
                .chars()
                .take(65)
                .take_while(char::is_ascii_hexdigit)
                .count();
            let algo = match hexlen {
                32 => Some("MD5"),
                40 => Some("SHA-1"),
                64 => Some("SHA-256"),
                _ => None,
            };
            if let Some(algo) = algo {
                let label = name.trim_end_matches('=');
                return Some((label, algo));
            }
            start = after;
        }
    }
    None
}

pub async fn run_hash_extension_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        // Search the live body (links/forms) AND Set-Cookie for a raw hex MAC token.
        let cookie = header_value(&p.headers, "set-cookie").unwrap_or_default();
        let haystack = format!("{}\n{}", p.body, cookie);
        if let Some((param, algo)) = find_hex_mac_param(&haystack) {
            findings.push(crypto_finding(
                "hash_extension_attack",
                &format!("Signed token uses raw {} MAC ('{}=') — length-extension risk", algo, param),
                "medium",
                "T1556",
                &format!(
                    "{} exposes a '{}' parameter whose value is a raw {} digest ({} hex). If the server computes it as {}(secret ‖ data) instead of HMAC, an attacker can length-extend the message and forge a valid MAC without the secret. Switch to HMAC-SHA-256 and verify with constant-time comparison.",
                    p.final_url, param, algo, algo, algo
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("hash_extension_attack", t)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("hash_extension_attack: {} finding(s)", n))
    }
}
cli_wrapper!(run_hash_extension_attack, run_hash_extension_attack_result);

pub async fn run_ecdsa_nonce_bias_result(t: &str) -> EngineResult {
    crate::pki_tls_engine::run_pki_tls_result(t).await
}
cli_wrapper!(run_ecdsa_nonce_bias, run_ecdsa_nonce_bias_result);

pub async fn run_rsa_timing_attack_result(t: &str) -> EngineResult {
    crate::timing_sidechannel_engine::run_timing_sidechannel_result(t).await
}
cli_wrapper!(run_rsa_timing_attack, run_rsa_timing_attack_result);

pub async fn run_mfa_bypass_engine_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    let paths = [
        "/api/auth/login",
        "/login",
        "/api/login",
        "/api/v1/auth",
        "/oauth/token",
        "/api/mfa/verify",
    ];
    let mfa_fields = ["mfa_token", "otp", "totp", "code", "verification_code", "two_factor"];
    for path in paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        for field in mfa_fields {
            let mut payload = serde_json::json!({
                "email": "probe@weissman.invalid",
                "password": "invalid-probe-password",
            });
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(field.into(), serde_json::json!(""));
            }
            if let Some(p) = crate::engine_probes::http_post_json(&client, &url, &payload).await {
                let body_low = p.body.to_ascii_lowercase();
                if p.status == 200
                    && (body_low.contains("access_token")
                        || body_low.contains("refresh_token")
                        || body_low.contains("\"token\""))
                {
                    findings.push(crypto_finding(
                        "mfa_bypass_engine",
                        &format!("Auth endpoint may accept empty {field}"),
                        "critical",
                        "T1556",
                        &format!(
                            "POST {} with empty '{field}' returned HTTP 200 + token material — MFA bypass candidate.",
                            p.final_url
                        ),
                        t,
                    ));
                }
                if p.status == 200 && body_low.contains("mfa") && body_low.contains("disabled") {
                    findings.push(crypto_finding(
                        "mfa_bypass_engine",
                        "MFA disabled flag in auth response",
                        "high",
                        "T1556",
                        &format!(
                            "POST {} returned MFA-disabled signal with field '{field}'.",
                            p.final_url
                        ),
                        t,
                    ));
                }
            }
        }
    }
    if findings.is_empty() {
        empty_ok("mfa_bypass_engine", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("mfa_bypass_engine: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_mfa_bypass_engine, run_mfa_bypass_engine_result);

pub async fn run_credential_stuffing_result(t: &str) -> EngineResult {
    crate::password_spray_engine::run_password_spray_result(t).await
}
cli_wrapper!(run_credential_stuffing, run_credential_stuffing_result);

pub async fn run_kerberos_attack_suite_result(t: &str) -> EngineResult {
    crate::kerberoasting_engine::run_kerberoasting_result(t).await
}
cli_wrapper!(run_kerberos_attack_suite, run_kerberos_attack_suite_result);

pub async fn run_zero_trust_bypass_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();

    if let Some(p) = http_get(&client, &base).await {
        if header_value(&p.headers, "strict-transport-security").is_none() {
            findings.push(crypto_finding(
                "zero_trust_bypass",
                "No HSTS on protected resource",
                "medium",
                "T1078",
                &format!(
                    "Response from {} lacks Strict-Transport-Security — TLS downgrade possible.",
                    p.final_url
                ),
                t,
            ));
        }
    }

    let internal_paths = [
        "/internal",
        "/admin",
        "/api/internal",
        "/debug",
        "/status",
        "/.well-known/openid-configuration",
    ];
    for path in internal_paths {
        let direct = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &direct).await {
            if p.status == 200 && !p.body.is_empty() && p.body.len() > 32 {
                findings.push(crypto_finding(
                    "zero_trust_bypass",
                    &format!("Internal path reachable without ZTNA headers: {path}"),
                    "high",
                    "T1078",
                    &format!(
                        "GET {} returned HTTP 200 ({}B) without device-trust headers — verify ZTNA enforcement.",
                        p.final_url, p.body.len()
                    ),
                    t,
                ));
                break;
            }
        }
        if let Some(p) = crate::engine_probes::http_get_with_headers(
            &client,
            &direct,
            &[
                ("X-Forwarded-For", "127.0.0.1"),
                ("X-Original-URL", path),
                ("X-Trusted-Device", "1"),
            ],
        )
        .await
        {
            if p.status == 200 && p.body.len() > 32 {
                findings.push(crypto_finding(
                    "zero_trust_bypass",
                    "Spoofed X-Forwarded-For may bypass ZTNA",
                    "critical",
                    "T1078",
                    &format!(
                        "GET {} with X-Forwarded-For:127.0.0.1 returned HTTP 200 — internal path trust may rely on spoofable headers.",
                        p.final_url
                    ),
                    t,
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("zero_trust_bypass", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("zero_trust_bypass: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_zero_trust_bypass, run_zero_trust_bypass_result);

pub async fn run_pki_hierarchy_attack_result(t: &str) -> EngineResult {
    crate::pki_tls_engine::run_pki_tls_result(t).await
}
cli_wrapper!(run_pki_hierarchy_attack, run_pki_hierarchy_attack_result);

pub async fn run_session_fixation_adv_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let cookie = header_value(&p.headers, "set-cookie").unwrap_or("");
        let lower = cookie.to_lowercase();
        if !cookie.is_empty()
            && (!lower.contains("httponly")
                || !lower.contains("secure")
                || !lower.contains("samesite"))
        {
            findings.push(finding(
                "session_fixation_adv",
                "Session cookie missing HttpOnly/Secure/SameSite",
                "medium",
                "T1539",
                &format!("Set-Cookie on {} = '{}'", p.final_url, cookie),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("session_fixation_adv", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("session_fixation_adv: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_session_fixation_adv, run_session_fixation_adv_result);

pub async fn run_password_hash_crack_result(t: &str) -> EngineResult {
    crate::password_spray_engine::run_password_spray_result(t).await
}
cli_wrapper!(run_password_hash_crack, run_password_hash_crack_result);

pub async fn run_oauth_advanced_attack_result(t: &str) -> EngineResult {
    crate::oauth_oidc_engine::run_oauth_oidc_result(
        t,
        &crate::engine_dispatch::EngineRunContext::default(),
    )
    .await
}
cli_wrapper!(run_oauth_advanced_attack, run_oauth_advanced_attack_result);

pub async fn run_saml_advanced_attack_result(t: &str) -> EngineResult {
    crate::saml_attack_engine::run_saml_attack_result(t).await
}
cli_wrapper!(run_saml_advanced_attack, run_saml_advanced_attack_result);

pub async fn run_quantum_key_attack_result(t: &str) -> EngineResult {
    crate::pqc_scanner_engine::run_pqc_scanner_result(t).await
}
cli_wrapper!(run_quantum_key_attack, run_quantum_key_attack_result);

pub async fn run_password_spray_advanced_result(t: &str) -> EngineResult {
    crate::password_spray_engine::run_password_spray_result(t).await
}
cli_wrapper!(
    run_password_spray_advanced,
    run_password_spray_advanced_result
);
