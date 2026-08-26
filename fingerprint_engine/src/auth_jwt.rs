//! JWT access tokens (short-lived) for API and WebSocket auth. Refresh uses opaque DB-backed tokens
//! ([`crate::auth_refresh`]).
//!
//! **Transport:** `Authorization: Bearer` or HttpOnly `weissman_token` cookie only. Credentials must
//! never appear in URLs (logs, Referer, proxy history). SSE uses fetch + ReadableStream with Bearer
//! headers on the client; [`StreamBinding`] enforces IP/TLS context on stream connect.

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::OnceLock;

/// Contextual binding for SSE streams — encoded in access JWT at login/refresh.
#[derive(Clone, Debug, Default)]
pub struct StreamBinding {
    pub bind_ip: Option<String>,
    pub bind_tls_fp: Option<String>,
}

impl StreamBinding {
    /// Capture client context from the incoming HTTP request at token mint time.
    #[must_use]
    pub fn from_http(headers: &axum::http::HeaderMap, peer: SocketAddr) -> Self {
        Self {
            bind_ip: Some(crate::http::extract_client_ip(headers, peer)),
            bind_tls_fp: crate::http::sse_context::extract_tls_fingerprint(headers),
        }
    }
}

/// Authenticated session: JWT claims (`sub`, `tid`, `role`, `is_superadmin`, `cid`, `jti`) + stream binding.
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub user_id: i64,
    pub tenant_id: i64,
    pub role: String,
    pub is_superadmin: bool,
    /// Set for endpoint-agent session JWTs (`typ: agent`).
    pub agent_id: Option<String>,
    /// Access JWT id for logout revocation (`typ: access` only).
    pub jti: Option<String>,
    /// Originating client IP at token mint (SSE contextual binding).
    pub bind_ip: Option<String>,
    /// TLS/JA3 fingerprint at token mint when proxy provides it.
    pub bind_tls_fp: Option<String>,
    /// Bound customer id for portal users. `None` = owner/staff (all clients).
    pub assigned_client_id: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: i64,
    tid: i64,
    exp: i64,
    iat: i64,
    /// `"access"` for API tokens. Legacy tokens omit this field and are treated as access.
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    is_superadmin: Option<bool>,
    /// Endpoint agent UUID when `typ` is `agent`.
    #[serde(default)]
    agent_id: Option<String>,
    /// Unique token id for access JWT revocation.
    #[serde(default)]
    jti: Option<String>,
    /// Client IP at mint time (SSE zero-trust binding).
    #[serde(default)]
    bind_ip: Option<String>,
    /// TLS fingerprint at mint time when available.
    #[serde(default)]
    bind_tls_fp: Option<String>,
    /// Bound customer (`clients.id`) for portal users. Absent for owner/staff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cid: Option<i64>,
}

pub const WEISSMAN_COOKIE_NAME: &str = "weissman_token";

static JWT_SECRET: OnceLock<Vec<u8>> = OnceLock::new();
/// Verification keyring: current signing key first, then any rotated-out `WEISSMAN_JWT_SECRET_PREVIOUS`
/// keys. Signing always uses the current key; verification accepts any key here so a rotated secret
/// verifies tokens minted under the old one — zero-downtime JWT rotation.
static JWT_VERIFY_KEYS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();

fn access_token_ttl_secs() -> i64 {
    std::env::var("WEISSMAN_ACCESS_TOKEN_MINUTES")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(15)
        .clamp(5, 240)
        * 60
}

fn agent_token_ttl_secs() -> i64 {
    std::env::var("WEISSMAN_AGENT_JWT_TTL_MINS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(240)
        .clamp(30, 1440)
        * 60
}

/// Load `WEISSMAN_JWT_SECRET` once. Call from server entrypoints before handling traffic.
pub fn init_jwt_secret_from_env() -> Result<(), String> {
    if JWT_SECRET.get().is_some() {
        return Ok(());
    }
    let s = std::env::var("WEISSMAN_JWT_SECRET")
        .map_err(|_| "WEISSMAN_JWT_SECRET is not set (required; no default)".to_string())?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("WEISSMAN_JWT_SECRET is set but empty".to_string());
    }
    if weissman_core::tls_policy::is_production_environment() && trimmed.len() < 32 {
        return Err("WEISSMAN_JWT_SECRET must be at least 32 characters in production".to_string());
    }
    JWT_SECRET
        .set(trimmed.as_bytes().to_vec())
        .map_err(|_| "WEISSMAN_JWT_SECRET: internal init race".to_string())?;

    // Build the verification keyring: current key first, then any comma-separated
    // WEISSMAN_JWT_SECRET_PREVIOUS keys (rotated out but still within their token TTL window).
    let mut keys = vec![trimmed.as_bytes().to_vec()];
    if let Ok(prev) = std::env::var("WEISSMAN_JWT_SECRET_PREVIOUS") {
        for k in prev
            .split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .map(|k| k.as_bytes().to_vec())
        {
            if !keys.contains(&k) {
                keys.push(k);
            }
        }
    }
    let _ = JWT_VERIFY_KEYS.set(keys);
    Ok(())
}

/// Verification keyring (current + rotated-out previous keys). Falls back to the single
/// current secret when the keyring wasn't initialized (e.g. unit tests that set `JWT_SECRET` directly).
fn verify_keys() -> Vec<Vec<u8>> {
    if let Some(keys) = JWT_VERIFY_KEYS.get() {
        return keys.clone();
    }
    let s = jwt_secret();
    if s.is_empty() {
        Vec::new()
    } else {
        vec![s.to_vec()]
    }
}

/// Decode + validate claims, trying each verification key (current, then previous) in turn.
/// Returns the first key that both verifies the signature and passes `validation`.
fn decode_claims(token: &str, validation: &Validation) -> Option<JwtClaims> {
    for key in verify_keys() {
        if key.is_empty() {
            continue;
        }
        if let Ok(d) = decode::<JwtClaims>(token, &DecodingKey::from_secret(&key), validation) {
            return Some(d.claims);
        }
    }
    None
}

pub fn jwt_secret() -> &'static [u8] {
    match JWT_SECRET.get() {
        Some(v) => v.as_slice(),
        None => {
            tracing::error!(
                target: "auth_jwt",
                "WEISSMAN_JWT_SECRET not initialized; call init_jwt_secret_from_env at startup"
            );
            &[]
        }
    }
}

fn auth_context_from_claims(c: JwtClaims) -> Option<AuthContext> {
    if c.tid <= 0 {
        return None;
    }
    match c.typ.as_deref() {
        Some("agent") => {
            let aid = c
                .agent_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())?
                .to_string();
            Some(AuthContext {
                user_id: 0,
                tenant_id: c.tid,
                role: "agent".to_string(),
                is_superadmin: false,
                agent_id: Some(aid),
                jti: c.jti,
                bind_ip: c.bind_ip,
                bind_tls_fp: c.bind_tls_fp,
                assigned_client_id: None,
            })
        }
        Some("refresh") | Some("mfa_pending") => None,
        _ => {
            if c.sub <= 0 {
                return None;
            }
            let role = c
                .role
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("viewer")
                .to_string();
            Some(AuthContext {
                user_id: c.sub,
                tenant_id: c.tid,
                role,
                is_superadmin: c.is_superadmin.unwrap_or(false),
                agent_id: None,
                jti: c.jti,
                bind_ip: c.bind_ip,
                bind_tls_fp: c.bind_tls_fp,
                assigned_client_id: c.cid.filter(|id| *id > 0),
            })
        }
    }
}

/// Short-lived JWT for an enrolled endpoint agent (`typ: agent`).
pub fn create_agent_session_token(
    agent_id: &str,
    tenant_id: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let secret = jwt_secret();
    if secret.is_empty() {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into());
    }
    let aid = agent_id.trim();
    if aid.is_empty() || tenant_id <= 0 {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into());
    }
    let now = chrono::Utc::now();
    let exp = (now + chrono::Duration::seconds(agent_token_ttl_secs())).timestamp();
    let claims = JwtClaims {
        sub: 0,
        tid: tenant_id,
        exp,
        iat: now.timestamp(),
        typ: Some("agent".to_string()),
        role: Some("agent".to_string()),
        is_superadmin: Some(false),
        agent_id: Some(aid.to_string()),
        jti: None,
        bind_ip: None,
        bind_tls_fp: None,
        cid: None,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

/// Minted human access JWT plus its `jti` for session tracking / revocation.
#[derive(Clone, Debug)]
pub struct MintedAccessToken {
    pub token: String,
    pub jti: String,
}

/// Short-lived access JWT (`typ: access`) with RBAC + stream binding claims.
pub fn create_access_token(
    user_id: i64,
    tenant_id: i64,
    role: &str,
    is_superadmin: bool,
    binding: &StreamBinding,
    assigned_client_id: Option<i64>,
) -> Result<MintedAccessToken, jsonwebtoken::errors::Error> {
    let secret = jwt_secret();
    if secret.is_empty() {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into());
    }
    let now = chrono::Utc::now();
    let exp = (now + chrono::Duration::seconds(access_token_ttl_secs())).timestamp();
    let role_norm = role.trim();
    let role_s = if role_norm.is_empty() {
        "viewer".to_string()
    } else {
        role_norm.to_string()
    };
    let jti = uuid::Uuid::new_v4().to_string();
    let cid = assigned_client_id.filter(|id| *id > 0);
    let claims = JwtClaims {
        sub: user_id,
        tid: tenant_id,
        exp,
        iat: now.timestamp(),
        typ: Some("access".to_string()),
        role: Some(role_s),
        is_superadmin: Some(is_superadmin),
        agent_id: None,
        jti: Some(jti.clone()),
        bind_ip: binding.bind_ip.clone(),
        bind_tls_fp: binding.bind_tls_fp.clone(),
        cid,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )?;
    Ok(MintedAccessToken { token, jti })
}

/// Backward-compatible alias (viewer, not superadmin).
#[inline]
pub fn create_session_token(
    user_id: i64,
    tenant_id: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    create_access_token(
        user_id,
        tenant_id,
        "viewer",
        false,
        &StreamBinding::default(),
        None,
    )
    .map(|m| m.token)
}

fn mfa_pending_ttl_secs() -> i64 {
    std::env::var("WEISSMAN_MFA_PENDING_MINUTES")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(5)
        .clamp(2, 15)
        * 60
}

/// Short-lived JWT after password OK when MFA is enabled.
pub fn create_mfa_pending_token(
    user_id: i64,
    tenant_id: i64,
    role: &str,
    is_superadmin: bool,
) -> Result<String, jsonwebtoken::errors::Error> {
    let secret = jwt_secret();
    if secret.is_empty() {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into());
    }
    let now = chrono::Utc::now();
    let exp = (now + chrono::Duration::seconds(mfa_pending_ttl_secs())).timestamp();
    let claims = JwtClaims {
        sub: user_id,
        tid: tenant_id,
        exp,
        iat: now.timestamp(),
        typ: Some("mfa_pending".to_string()),
        role: Some(role.trim().to_string()),
        is_superadmin: Some(is_superadmin),
        agent_id: None,
        jti: None,
        bind_ip: None,
        bind_tls_fp: None,
        cid: None,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

/// Verify stream contextual binding (IP + optional TLS fingerprint).
#[must_use]
pub fn verify_stream_context(auth: &AuthContext, client_ip: &str, tls_fp: Option<&str>) -> bool {
    if let Some(ref expected) = auth.bind_ip {
        if expected != client_ip {
            return false;
        }
    }
    if let Some(ref expected) = auth.bind_tls_fp {
        let Some(actual) = tls_fp else {
            return false;
        };
        if actual != expected {
            return false;
        }
    }
    true
}

pub fn verify_mfa_pending_token(token: &str) -> Option<AuthContext> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    let c = decode_claims(token, &validation)?;
    if c.typ.as_deref() != Some("mfa_pending") {
        return None;
    }
    // A pending token is not a session, so it does not go through
    // `auth_context_from_claims` (which deliberately rejects `mfa_pending`).
    // Build the pending context inline after validating tenant + subject.
    if c.tid <= 0 || c.sub <= 0 {
        return None;
    }
    let role = c
        .role
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("viewer")
        .to_string();
    Some(AuthContext {
        user_id: c.sub,
        tenant_id: c.tid,
        role,
        is_superadmin: c.is_superadmin.unwrap_or(false),
        agent_id: None,
        jti: c.jti,
        bind_ip: c.bind_ip,
        bind_tls_fp: c.bind_tls_fp,
        assigned_client_id: c.cid.filter(|id| *id > 0),
    })
}

/// Verify access JWT; rejects explicit refresh-type claims and expired tokens.
/// Returns AuthContext on success, None on any verification failure.
pub fn verify_access_token(token: &str) -> Option<AuthContext> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    let Some(c) = decode_claims(token, &validation) else {
        let token_preview: String = token.chars().take(20).collect();
        tracing::debug!(
            target: "auth_jwt",
            token_preview = %token_preview,
            "JWT verification failed (no verification key matched)"
        );
        return None;
    };
    if matches!(
        c.typ.as_deref(),
        Some("refresh") | Some("mfa_pending") | Some("sse_ticket")
    ) {
        tracing::debug!(target: "auth_jwt", "Rejected refresh token used as access token");
        return None;
    }
    let sub = c.sub;
    let tid = c.tid;
    let typ = c.typ.clone();
    auth_context_from_claims(c).or_else(|| {
        tracing::warn!(
            target: "auth_jwt",
            sub,
            tid,
            typ = ?typ,
            "Invalid JWT claims for access token"
        );
        None
    })
}

/// Verified access JWT `(jti, exp)` for logout revocation. Legacy tokens without `jti` return `None`.
pub fn access_token_revocation_info(token: &str) -> Option<(String, i64)> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    let c = decode_claims(token, &validation)?;
    if matches!(
        c.typ.as_deref(),
        Some("refresh") | Some("mfa_pending") | Some("sse_ticket") | Some("agent")
    ) {
        return None;
    }
    let jti = c.jti.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
    Some((jti.to_string(), c.exp))
}

/// Alias for [`verify_access_token`].
#[inline]
pub fn verify_session_token(token: &str) -> Option<AuthContext> {
    verify_access_token(token)
}

/// True when `ctx` is a human user access session (not an endpoint agent).
#[inline]
pub fn is_user_access_context(ctx: &AuthContext) -> bool {
    ctx.agent_id.is_none() && !ctx.role.eq_ignore_ascii_case("agent")
}

/// Verify endpoint-agent session JWT (`typ: agent`). Rejects human user access tokens.
pub fn verify_agent_session_token(token: &str) -> Option<AuthContext> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    let c = decode_claims(token, &validation)?;
    if c.typ.as_deref() != Some("agent") {
        return None;
    }
    auth_context_from_claims(c)
        .filter(|ctx| ctx.agent_id.is_some() && ctx.role.eq_ignore_ascii_case("agent"))
}

/// `Set-Cookie` for access token. Max-Age tracks JWT lifetime.
/// `Secure` on session cookies. Default **false** in dev; **true** when `WEISSMAN_ENV=production` unless overridden.
#[inline]
pub fn cookie_use_secure() -> bool {
    match std::env::var("WEISSMAN_COOKIE_SECURE") {
        Ok(s) => {
            let t = s.trim().to_ascii_lowercase();
            t == "1" || t == "true" || t == "yes"
        }
        Err(_) => weissman_core::tls_policy::is_production_environment(),
    }
}

fn cookie_secure_suffix() -> &'static str {
    if cookie_use_secure() {
        "; Secure"
    } else {
        ""
    }
}

pub fn session_cookie_value(token: &str) -> String {
    let max_age = access_token_ttl_secs().max(60);
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        WEISSMAN_COOKIE_NAME,
        token,
        max_age,
        cookie_secure_suffix()
    )
}

/// Expire access cookie (logout / force re-login for new JWT claims).
pub fn session_cookie_clear_value() -> String {
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        WEISSMAN_COOKIE_NAME,
        cookie_secure_suffix()
    )
}

#[cfg(test)]
mod agent_token_tests {
    use super::*;

    #[test]
    fn verify_agent_session_rejects_human_access_token() {
        let secret = b"unit-test-secret-at-least-32-chars-long";
        let _ = JWT_SECRET.set(secret.to_vec());
        let now = chrono::Utc::now();
        let claims = JwtClaims {
            sub: 1,
            tid: 10,
            exp: (now + chrono::Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
            typ: Some("access".to_string()),
            role: Some("admin".to_string()),
            is_superadmin: Some(false),
            agent_id: None,
            jti: Some("test-jti".to_string()),
            bind_ip: None,
            bind_tls_fp: None,
            cid: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .expect("mint access");
        assert!(verify_agent_session_token(&token).is_none());
    }

    #[test]
    fn agent_session_token_roundtrip() {
        let secret = b"unit-test-secret-at-least-32-chars-long";
        let now = chrono::Utc::now();
        let claims = JwtClaims {
            sub: 0,
            tid: 42,
            exp: (now + chrono::Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
            typ: Some("agent".to_string()),
            role: Some("agent".to_string()),
            is_superadmin: Some(false),
            agent_id: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
            jti: None,
            bind_ip: None,
            bind_tls_fp: None,
            cid: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .expect("mint");
        let mut validation = Validation::default();
        validation.validate_exp = true;
        let c = decode::<JwtClaims>(
            token.as_str(),
            &DecodingKey::from_secret(secret),
            &validation,
        )
        .expect("decode")
        .claims;
        let ctx = auth_context_from_claims(c).expect("agent ctx");
        assert_eq!(ctx.role, "agent");
        assert_eq!(ctx.tenant_id, 42);
        assert_eq!(
            ctx.agent_id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[test]
    fn mfa_pending_token_roundtrips_to_context() {
        let secret = b"unit-test-secret-at-least-32-chars-long";
        let _ = JWT_SECRET.set(secret.to_vec());
        let token = create_mfa_pending_token(7, 3, "admin", false).expect("mint pending");
        let ctx = verify_mfa_pending_token(&token).expect("pending ctx");
        assert_eq!(ctx.user_id, 7);
        assert_eq!(ctx.tenant_id, 3);
        assert_eq!(ctx.role, "admin");
        assert!(ctx.agent_id.is_none());
    }

    #[test]
    fn verify_mfa_pending_rejects_access_token() {
        let secret = b"unit-test-secret-at-least-32-chars-long";
        let _ = JWT_SECRET.set(secret.to_vec());
        let now = chrono::Utc::now();
        let claims = JwtClaims {
            sub: 1,
            tid: 10,
            exp: (now + chrono::Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
            typ: Some("access".to_string()),
            role: Some("admin".to_string()),
            is_superadmin: Some(false),
            agent_id: None,
            jti: Some("j".to_string()),
            bind_ip: None,
            bind_tls_fp: None,
            cid: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .expect("mint");
        assert!(verify_mfa_pending_token(&token).is_none());
    }

    #[test]
    fn access_token_signed_with_unknown_key_is_rejected() {
        // Keyring security invariant: a token signed with a key that is NOT in the
        // verification keyring must never verify (rotation must not widen trust).
        let secret = b"unit-test-secret-at-least-32-chars-long";
        let _ = JWT_SECRET.set(secret.to_vec());
        let wrong = b"a-totally-different-secret-not-in-the-ring";
        let now = chrono::Utc::now();
        let claims = JwtClaims {
            sub: 1,
            tid: 10,
            exp: (now + chrono::Duration::hours(1)).timestamp(),
            iat: now.timestamp(),
            typ: Some("access".to_string()),
            role: Some("admin".to_string()),
            is_superadmin: Some(false),
            agent_id: None,
            jti: Some("j".to_string()),
            bind_ip: None,
            bind_tls_fp: None,
            cid: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(wrong),
        )
        .expect("mint");
        assert!(verify_access_token(&token).is_none());
    }
}
