//! JWT access tokens (short-lived) for API and WebSocket auth. Refresh uses opaque DB-backed tokens
//! ([`crate::auth_refresh`]).

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Authenticated session: JWT claims (`sub`, `tid`, `role`, `is_superadmin`).
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub user_id: i64,
    pub tenant_id: i64,
    pub role: String,
    pub is_superadmin: bool,
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
}

pub const WEISSMAN_COOKIE_NAME: &str = "weissman_token";

static JWT_SECRET: OnceLock<Vec<u8>> = OnceLock::new();

fn access_token_ttl_secs() -> i64 {
    std::env::var("WEISSMAN_ACCESS_TOKEN_MINUTES")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(15)
        .clamp(5, 240)
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
    JWT_SECRET
        .set(trimmed.as_bytes().to_vec())
        .map_err(|_| "WEISSMAN_JWT_SECRET: internal init race".to_string())
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

/// Short-lived access JWT (`typ: access`) with RBAC claims for middleware and `/api/auth/me`.
pub fn create_access_token(
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
    let exp = (now + chrono::Duration::seconds(access_token_ttl_secs())).timestamp();
    let role_norm = role.trim();
    let role_s = if role_norm.is_empty() {
        "viewer".to_string()
    } else {
        role_norm.to_string()
    };
    let claims = JwtClaims {
        sub: user_id,
        tid: tenant_id,
        exp,
        iat: now.timestamp(),
        typ: Some("access".to_string()),
        role: Some(role_s),
        is_superadmin: Some(is_superadmin),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

/// Backward-compatible alias (viewer, not superadmin).
#[inline]
pub fn create_session_token(
    user_id: i64,
    tenant_id: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    create_access_token(user_id, tenant_id, "viewer", false)
}

/// Verify access JWT; rejects explicit refresh-type claims and expired tokens.
/// Returns AuthContext on success, None on any verification failure.
pub fn verify_access_token(token: &str) -> Option<AuthContext> {
    let secret = jwt_secret();
    if secret.is_empty() {
        tracing::warn!(
            target: "auth_jwt",
            "JWT secret empty — verify_access_token returning None"
        );
        return None;
    }
    let mut validation = Validation::default();
    validation.validate_exp = true;
    match decode::<JwtClaims>(token, &DecodingKey::from_secret(secret), &validation) {
        Ok(d) => {
            let c = d.claims;
            if matches!(c.typ.as_deref(), Some("refresh")) {
                tracing::debug!(
                    target: "auth_jwt",
                    "Rejected refresh token used as access token"
                );
                return None;
            }
            if c.sub > 0 && c.tid > 0 {
                let role = c
                    .role
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("viewer")
                    .to_string();
                let is_superadmin = c.is_superadmin.unwrap_or(false);
                Some(AuthContext {
                    user_id: c.sub,
                    tenant_id: c.tid,
                    role,
                    is_superadmin,
                })
            } else {
                tracing::warn!(
                    target: "auth_jwt",
                    sub = c.sub,
                    tid = c.tid,
                    "Invalid sub/tid in JWT claims"
                );
                None
            }
        }
        Err(e) => {
            // Log token verification failure for debugging
            let token_preview: String = token.chars().take(20).collect();
            tracing::debug!(
                target: "auth_jwt",
                error = %e,
                token_preview = %token_preview,
                "JWT verification failed"
            );
            None
        }
    }
}

/// Alias for [`verify_access_token`].
#[inline]
pub fn verify_session_token(token: &str) -> Option<AuthContext> {
    verify_access_token(token)
}

/// `Set-Cookie` for access token. Max-Age tracks JWT lifetime.
/// `Secure` on session cookies. Default **false** so `http://127.0.0.1` dev works; set `WEISSMAN_COOKIE_SECURE=1` in production (HTTPS).
#[inline]
pub fn cookie_use_secure() -> bool {
    match std::env::var("WEISSMAN_COOKIE_SECURE") {
        Ok(s) => {
            let t = s.trim().to_ascii_lowercase();
            t == "1" || t == "true" || t == "yes"
        }
        Err(_) => false,
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
