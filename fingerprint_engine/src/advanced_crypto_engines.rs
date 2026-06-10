//! Advanced Crypto/Identity engines — delegate to live `pki_tls`, `crypto_engine`,
//! `password_spray`, `kerberoasting`, `saml_attack`, `oauth_oidc` modules where appropriate;
//! otherwise probe HTTP/TLS surface for the relevant indicators.

use crate::engine_probes::{empty_ok, finding, header_value, http_client, http_get, normalize_url};
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
        ("empty",       ""),
        ("valid_b64",   "QUJDREVGR0g="),       // ABCDEFGH
        ("bad_pad",     "QUJDREVGR0g"),         // missing '='
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
            findings.push(finding(
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
        EngineResult::ok(findings.clone(), format!("padding_oracle_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_padding_oracle_attack, run_padding_oracle_attack_result);

pub async fn run_hash_extension_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let mac_q = ["mac", "signature", "sig", "hash", "token"]
            .iter()
            .any(|q| p.body.contains(&format!("{}=", q)));
        if mac_q {
            findings.push(finding(
                "hash_extension_attack",
                "Response references MAC/signature param",
                "info",
                "T1556",
                &format!("Body of {} references 'mac/sig/hash' query params — review for length-extension on weak HMAC.", p.final_url),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("hash_extension_attack", t)
    } else {
        EngineResult::ok(findings.clone(), format!("hash_extension_attack: {}", findings.len()))
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
    for path in ["/api/auth/login", "/login", "/api/login"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let payload = serde_json::json!({"email":"test@example.com","password":"x","mfa_token":""});
        if let Some(p) = crate::engine_probes::http_post_json(&client, &url, &payload).await {
            if p.status == 200 && p.body.contains("access_token") {
                findings.push(finding(
                    "mfa_bypass_engine",
                    "Login endpoint may accept empty mfa_token",
                    "high",
                    "T1556",
                    &format!("POST {} returned access_token with empty mfa_token.", p.final_url),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("mfa_bypass_engine", t)
    } else {
        EngineResult::ok(findings.clone(), format!("mfa_bypass_engine: {}", findings.len()))
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
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if header_value(&p.headers, "strict-transport-security").is_none() {
            findings.push(finding(
                "zero_trust_bypass",
                "No HSTS on protected resource",
                "low",
                "T1078",
                &format!("Response from {} lacks Strict-Transport-Security — TLS downgrade possible.", p.final_url),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("zero_trust_bypass", t)
    } else {
        EngineResult::ok(findings.clone(), format!("zero_trust_bypass: {}", findings.len()))
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
        if !cookie.is_empty() && (!lower.contains("httponly") || !lower.contains("secure") || !lower.contains("samesite")) {
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
        EngineResult::ok(findings.clone(), format!("session_fixation_adv: {}", findings.len()))
    }
}
cli_wrapper!(run_session_fixation_adv, run_session_fixation_adv_result);

pub async fn run_password_hash_crack_result(t: &str) -> EngineResult {
    crate::password_spray_engine::run_password_spray_result(t).await
}
cli_wrapper!(run_password_hash_crack, run_password_hash_crack_result);

pub async fn run_oauth_advanced_attack_result(t: &str) -> EngineResult {
    crate::oauth_oidc_engine::run_oauth_oidc_result(t).await
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
cli_wrapper!(run_password_spray_advanced, run_password_spray_advanced_result);
