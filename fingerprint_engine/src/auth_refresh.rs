//! Opaque refresh tokens stored as SHA-256 at rest; rotation invalidates the previous row.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionCookieError {
    #[error("JWT: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("refresh token persistence: {0}")]
    RefreshDb(#[from] sqlx::Error),
    #[error("user inactive or not found")]
    InactiveUser,
}

/// Role + superadmin for JWT (from `auth.v_user_lookup`). `None` when user is missing or deactivated.
pub async fn user_rbac_snapshot(
    pool: &PgPool,
    user_id: i64,
) -> Result<Option<(String, bool)>, sqlx::Error> {
    let row = sqlx::query(
        r#"SELECT COALESCE(NULLIF(trim(role), ''), 'viewer') AS role,
                  COALESCE(is_superadmin, false) AS is_superadmin
           FROM auth.v_user_lookup
           WHERE id = $1 AND is_active = true"#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| {
        (
            r.try_get::<String, _>("role")
                .unwrap_or_else(|_| "viewer".into()),
            r.try_get::<bool, _>("is_superadmin").unwrap_or(false),
        )
    }))
}

/// Access JWT (for JSON + `Authorization`) + two `Set-Cookie` lines: access + opaque refresh (`Path=/api/auth`).
pub async fn build_session_cookie_headers(
    pool: &PgPool,
    user_id: i64,
    tenant_id: i64,
) -> Result<(String, String, String), SessionCookieError> {
    let (role, is_superadmin) = user_rbac_snapshot(pool, user_id)
        .await?
        .ok_or(SessionCookieError::InactiveUser)?;
    let minted =
        crate::auth_jwt::create_access_token(user_id, tenant_id, role.as_str(), is_superadmin)?;
    let access_line = crate::auth_jwt::session_cookie_value(&minted.token);
    let refresh = issue_refresh_token(pool, user_id, tenant_id, Some(&minted.jti)).await?;
    Ok((minted.token, access_line, refresh_cookie_value(&refresh)))
}

/// Re-read live RBAC from DB; returns `None` when user inactive or missing.
pub async fn revalidate_auth_context(
    pool: &PgPool,
    auth: &crate::auth_jwt::AuthContext,
) -> Result<Option<crate::auth_jwt::AuthContext>, sqlx::Error> {
    let Some((role, is_superadmin)) = user_rbac_snapshot(pool, auth.user_id).await? else {
        return Ok(None);
    };
    Ok(Some(crate::auth_jwt::AuthContext {
        user_id: auth.user_id,
        tenant_id: auth.tenant_id,
        role,
        is_superadmin,
        agent_id: auth.agent_id.clone(),
        jti: auth.jti.clone(),
    }))
}

/// True when the access JWT `jti` was revoked (logout).
pub async fn is_access_jti_revoked(pool: &PgPool, jti: &str) -> Result<bool, sqlx::Error> {
    let revoked: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM weissman_revoked_tokens WHERE jti = $1 AND expires_at > now() LIMIT 1",
    )
    .bind(jti)
    .fetch_optional(pool)
    .await?;
    Ok(revoked.is_some())
}

/// Record revoked access JWT until its natural expiry.
pub async fn revoke_access_jti(
    pool: &PgPool,
    jti: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO weissman_revoked_tokens (jti, expires_at)
           VALUES ($1, $2)
           ON CONFLICT (jti) DO NOTHING"#,
    )
    .bind(jti)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Link the current access JWT jti to the active refresh row.
pub async fn store_refresh_access_jti(
    pool: &PgPool,
    refresh_raw: &str,
    access_jti: &str,
) -> Result<(), sqlx::Error> {
    let th = hash_token(refresh_raw);
    sqlx::query(
        r#"UPDATE user_refresh_tokens SET access_jti = $2
           WHERE token_hash = $1 AND revoked_at IS NULL"#,
    )
    .bind(&th)
    .bind(access_jti)
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke opaque refresh token from cookie value.
pub async fn revoke_refresh_token_by_raw(pool: &PgPool, raw: &str) -> Result<(), sqlx::Error> {
    let th = hash_token(raw);
    sqlx::query(
        r#"UPDATE user_refresh_tokens SET revoked_at = now()
           WHERE token_hash = $1 AND revoked_at IS NULL"#,
    )
    .bind(&th)
    .execute(pool)
    .await?;
    Ok(())
}

pub const REFRESH_COOKIE_NAME: &str = "weissman_refresh";

#[derive(Debug, Error)]
pub enum RefreshTokenError {
    #[error("refresh token not found or revoked")]
    InvalidOrRevoked,
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

fn refresh_ttl_days() -> i64 {
    std::env::var("WEISSMAN_REFRESH_TOKEN_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
        .clamp(1, 365)
}

fn hash_token(raw: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(raw.trim().as_bytes());
    h.finalize().to_vec()
}

fn generate_opaque_token() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &b)
}

/// Insert a new refresh token; returns the raw secret to send to the client once.
pub async fn issue_refresh_token(
    pool: &PgPool,
    user_id: i64,
    tenant_id: i64,
    access_jti: Option<&str>,
) -> Result<String, sqlx::Error> {
    let raw = generate_opaque_token();
    let th = hash_token(&raw);
    let exp = chrono::Utc::now() + chrono::Duration::days(refresh_ttl_days());
    sqlx::query(
        r#"INSERT INTO user_refresh_tokens (user_id, tenant_id, token_hash, expires_at, access_jti)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(&th)
    .bind(exp)
    .bind(access_jti)
    .execute(pool)
    .await?;
    Ok(raw)
}

/// Validates `raw`, revokes that row, inserts a new token, returns the new raw secret and session ids.
pub async fn rotate_refresh_token(
    pool: &PgPool,
    raw: &str,
) -> Result<(i64, i64, String), RefreshTokenError> {
    let th = hash_token(raw);
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        r#"SELECT id, user_id, tenant_id FROM user_refresh_tokens
           WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
           FOR UPDATE"#,
    )
    .bind(&th)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Err(RefreshTokenError::InvalidOrRevoked);
    };
    let old_id: i64 = row.try_get("id")?;
    let user_id: i64 = row.try_get("user_id")?;
    let tenant_id: i64 = row.try_get("tenant_id")?;

    let new_raw = generate_opaque_token();
    let new_hash = hash_token(&new_raw);
    let exp = chrono::Utc::now() + chrono::Duration::days(refresh_ttl_days());

    let new_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO user_refresh_tokens (user_id, tenant_id, token_hash, expires_at, access_jti)
           VALUES ($1, $2, $3, $4, NULL) RETURNING id"#,
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(&new_hash)
    .bind(exp)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        r#"UPDATE user_refresh_tokens SET revoked_at = now(), replaced_by = $2 WHERE id = $1"#,
    )
    .bind(old_id)
    .bind(new_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok((user_id, tenant_id, new_raw))
}

fn refresh_secure_suffix() -> &'static str {
    if crate::auth_jwt::cookie_use_secure() {
        "; Secure"
    } else {
        ""
    }
}

/// `Path=/api/auth` — not sent on arbitrary API calls.
pub fn refresh_cookie_value(token: &str) -> String {
    let max_age = refresh_ttl_days().saturating_mul(24 * 3600);
    format!(
        "{}={}; Path=/api/auth; HttpOnly; SameSite=Strict; Max-Age={}{}",
        REFRESH_COOKIE_NAME,
        token,
        max_age,
        refresh_secure_suffix()
    )
}

/// Clear refresh cookie (client stops sending it).
pub fn refresh_cookie_clear_value() -> String {
    format!(
        "{}=; Path=/api/auth; HttpOnly; SameSite=Strict; Max-Age=0{}",
        REFRESH_COOKIE_NAME,
        refresh_secure_suffix()
    )
}
