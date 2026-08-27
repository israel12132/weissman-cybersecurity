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

/// Role + superadmin + bound customer for JWT (from `auth.v_user_lookup`).
/// `None` when user is missing or deactivated.
pub async fn user_rbac_snapshot(
    pool: &PgPool,
    user_id: i64,
) -> Result<Option<(String, bool, Option<i64>)>, sqlx::Error> {
    let row = sqlx::query(
        r#"SELECT COALESCE(NULLIF(trim(role), ''), 'viewer') AS role,
                  COALESCE(is_superadmin, false) AS is_superadmin,
                  assigned_client_id
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
            r.try_get::<Option<i64>, _>("assigned_client_id")
                .ok()
                .flatten()
                .filter(|id| *id > 0),
        )
    }))
}

/// Access JWT (for JSON + `Authorization`) + two `Set-Cookie` lines: access + opaque refresh (`Path=/api/auth`).
pub async fn build_session_cookie_headers(
    pool: &PgPool,
    user_id: i64,
    tenant_id: i64,
    binding: &crate::auth_jwt::StreamBinding,
) -> Result<(String, String, String), SessionCookieError> {
    let (role, is_superadmin, assigned_client_id) = user_rbac_snapshot(pool, user_id)
        .await?
        .ok_or(SessionCookieError::InactiveUser)?;
    let minted = crate::auth_jwt::create_access_token(
        user_id,
        tenant_id,
        role.as_str(),
        is_superadmin,
        binding,
        assigned_client_id,
    )?;
    if !crate::client_isolation::is_client_role(&role) && assigned_client_id.is_none() {
        // Staff/owner login: ensure a wildcard grant exists so scope-switch
        // authenticates against the management table even for users created
        // outside admin_users (bootstrap admin, JIT). Stamp tenant GUC with
        // empty client GUC so FORCE RLS on the grants table allows the insert
        // on weissman_app (NOBYPASSRLS).
        let mut tx = weissman_db::begin_tenant_tx_scoped(pool, tenant_id, None).await?;
        crate::scope_switch::ensure_wildcard_grant(&mut tx, tenant_id, user_id, None).await?;
        tx.commit().await?;
    }
    let access_line = crate::auth_jwt::session_cookie_value(&minted.token);
    let refresh = issue_refresh_token(
        pool,
        user_id,
        tenant_id,
        Some(&minted.jti),
        assigned_client_id,
    )
    .await?;
    Ok((minted.token, access_line, refresh_cookie_value(&refresh)))
}

/// Re-read live RBAC from DB; returns `None` when user inactive or missing.
///
/// JWT `cid` is the sole session customer anchor for staff impersonation.
/// Portal users (`role=client` / DB `assigned_client_id`) are always locked to
/// the database value. Staff JWT `cid` is preserved when the grant table still
/// allows that customer — never overwritten with NULL from `users.assigned_client_id`.
pub async fn revalidate_auth_context(
    pool: &PgPool,
    auth: &crate::auth_jwt::AuthContext,
) -> Result<Option<crate::auth_jwt::AuthContext>, sqlx::Error> {
    let Some((role, is_superadmin, db_assigned_client_id)) =
        user_rbac_snapshot(pool, auth.user_id).await?
    else {
        return Ok(None);
    };
    // Re-derive the tenant from the DB as well: revalidation is the one place authority is
    // rebuilt from the database, and trusting the JWT's `tid` for the token's full lifetime lets
    // a reassigned user's stale token keep operating against its old tenant. A mismatch is either
    // a tenant reassignment or a forgery signal — fail closed via the existing 401 path.
    let db_tenant: Option<i64> = sqlx::query_scalar(
        "SELECT tenant_id FROM auth.v_user_lookup WHERE id = $1 AND is_active = true",
    )
    .bind(auth.user_id)
    .fetch_optional(pool)
    .await?;
    match db_tenant {
        Some(t) if t == auth.tenant_id => {}
        Some(t) => {
            tracing::warn!(
                target: "auth",
                user_id = auth.user_id,
                token_tenant = auth.tenant_id,
                db_tenant = t,
                "tenant mismatch on token revalidation; rejecting"
            );
            return Ok(None);
        }
        None => return Ok(None),
    }

    let assigned_client_id = if crate::client_isolation::is_client_role(&role)
        || db_assigned_client_id.is_some()
    {
        db_assigned_client_id
    } else if let Some(jwt_cid) = auth.assigned_client_id.filter(|id| *id > 0) {
        match crate::scope_switch::grant_allows(pool, auth.tenant_id, auth.user_id, Some(jwt_cid))
            .await
        {
            Ok(true) => Some(jwt_cid),
            Ok(false) => {
                tracing::warn!(
                    target: "auth",
                    user_id = auth.user_id,
                    jwt_cid,
                    "impersonation cid no longer granted; rejecting"
                );
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    } else {
        None
    };

    Ok(Some(crate::auth_jwt::AuthContext {
        user_id: auth.user_id,
        tenant_id: auth.tenant_id,
        role,
        is_superadmin,
        agent_id: auth.agent_id.clone(),
        jti: auth.jti.clone(),
        bind_ip: auth.bind_ip.clone(),
        bind_tls_fp: auth.bind_tls_fp.clone(),
        assigned_client_id,
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
    scope_client_id: Option<i64>,
) -> Result<String, sqlx::Error> {
    let raw = generate_opaque_token();
    let th = hash_token(&raw);
    let exp = chrono::Utc::now() + chrono::Duration::days(refresh_ttl_days());
    sqlx::query(
        r#"INSERT INTO user_refresh_tokens (user_id, tenant_id, token_hash, expires_at, access_jti, scope_client_id)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(&th)
    .bind(exp)
    .bind(access_jti)
    .bind(scope_client_id)
    .execute(pool)
    .await?;
    Ok(raw)
}

/// Stamp the live JWT cid onto the current refresh row (scope-switch).
pub async fn update_refresh_scope(
    pool: &PgPool,
    raw: &str,
    scope_client_id: Option<i64>,
    access_jti: &str,
) -> Result<(), sqlx::Error> {
    let th = hash_token(raw);
    sqlx::query(
        r#"UPDATE user_refresh_tokens
           SET scope_client_id = $2, access_jti = $3
           WHERE token_hash = $1 AND revoked_at IS NULL"#,
    )
    .bind(&th)
    .bind(scope_client_id)
    .bind(access_jti)
    .execute(pool)
    .await?;
    Ok(())
}

/// Validates `raw`, revokes that row, inserts a new token, returns the new raw secret and session ids.
/// Validates `raw`, revokes that row, inserts a new token, returns the new raw secret,
/// session ids, and the persisted impersonation `cid` (if any).
pub async fn rotate_refresh_token(
    pool: &PgPool,
    raw: &str,
) -> Result<(i64, i64, String, Option<i64>), RefreshTokenError> {
    let th = hash_token(raw);
    let mut tx = pool.begin().await?;
    // Bound the `FOR UPDATE` below. This runs on the AUTH pool with no tenant GUC, so it does
    // not pass through `set_tenant_tx` and would otherwise inherit the connection's
    // `lock_timeout` — 0, i.e. *infinite*, under any bare test pool.
    //
    // The row lock is deliberate and stays: it is what makes "validate, revoke, re-issue" atomic
    // and so what stops two concurrent presentations of the same refresh token from both
    // succeeding (token replay). Bounding the wait does not weaken that — on timeout the
    // statement errors, the transaction aborts, and neither rotation is committed.
    weissman_db::advisory_lock::bound_lock_wait(
        &mut tx,
        weissman_db::advisory_lock::lock_timeout(),
    )
    .await?;
    let row = sqlx::query(
        r#"SELECT id, user_id, tenant_id, scope_client_id FROM user_refresh_tokens
           WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
           FOR UPDATE"#,
    )
    .bind(&th)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        // Reuse detection (OAuth 2.0 Security BCP §4.14.2): the strict lookup missed. If a row with
        // this hash exists but is already revoked, an already-rotated token is being replayed — a
        // confirmed theft signal. Revoke the whole token family for that user and every access
        // token minted from it, so the attacker's freshly-rotated descendant is killed too (the
        // previous behaviour let it keep rotating for the full 30-day window, undetected).
        if let Ok(Some(reused)) = sqlx::query(
            r#"SELECT user_id, tenant_id FROM user_refresh_tokens
               WHERE token_hash = $1 AND revoked_at IS NOT NULL
               LIMIT 1"#,
        )
        .bind(&th)
        .fetch_optional(&mut *tx)
        .await
        {
            let ru: i64 = reused.try_get("user_id").unwrap_or(0);
            let rt: i64 = reused.try_get("tenant_id").unwrap_or(0);
            if ru > 0 {
                let jtis: Vec<String> = sqlx::query_scalar(
                    r#"SELECT access_jti FROM user_refresh_tokens
                       WHERE user_id = $1 AND access_jti IS NOT NULL AND expires_at > now()"#,
                )
                .bind(ru)
                .fetch_all(&mut *tx)
                .await
                .unwrap_or_default();
                let _ = sqlx::query(
                    r#"UPDATE user_refresh_tokens SET revoked_at = now()
                       WHERE user_id = $1 AND revoked_at IS NULL"#,
                )
                .bind(ru)
                .execute(&mut *tx)
                .await;
                let _ = tx.commit().await;
                // Best-effort: revoke every access JWT bound to the family until its natural expiry.
                let expiry = chrono::Utc::now() + chrono::Duration::hours(6);
                for jti in jtis {
                    let _ = revoke_access_jti(pool, &jti, expiry).await;
                }
                metrics::counter!("weissman_refresh_reuse_total").increment(1);
                tracing::warn!(
                    target: "auth",
                    user_id = ru,
                    tenant_id = rt,
                    "refresh token reuse detected; revoked entire token family"
                );
                return Err(RefreshTokenError::InvalidOrRevoked);
            }
        }
        return Err(RefreshTokenError::InvalidOrRevoked);
    };
    let old_id: i64 = row.try_get("id")?;
    let user_id: i64 = row.try_get("user_id")?;
    let tenant_id: i64 = row.try_get("tenant_id")?;
    let scope_client_id: Option<i64> = row
        .try_get::<Option<i64>, _>("scope_client_id")
        .ok()
        .flatten()
        .filter(|id| *id > 0);

    let new_raw = generate_opaque_token();
    let new_hash = hash_token(&new_raw);
    let exp = chrono::Utc::now() + chrono::Duration::days(refresh_ttl_days());

    let new_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO user_refresh_tokens (user_id, tenant_id, token_hash, expires_at, access_jti, scope_client_id)
           VALUES ($1, $2, $3, $4, NULL, $5) RETURNING id"#,
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(&new_hash)
    .bind(exp)
    .bind(scope_client_id)
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
    Ok((user_id, tenant_id, new_raw, scope_client_id))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_token_is_deterministic_and_trims() {
        let a = hash_token("secrettoken");
        let b = hash_token("  secrettoken  ");
        assert_eq!(a, b); // trims before hashing
        assert_eq!(a.len(), 32); // SHA-256 digest length
    }

    #[test]
    fn hash_token_differs_for_different_input() {
        assert_ne!(hash_token("aaa"), hash_token("bbb"));
    }

    #[test]
    fn generate_opaque_token_length_and_charset() {
        let t = generate_opaque_token();
        // 32 random bytes, URL-safe base64 without padding.
        assert_eq!(t.len(), 43);
        assert!(t
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn refresh_cookie_name_is_stable() {
        assert_eq!(REFRESH_COOKIE_NAME, "weissman_refresh");
    }

    #[test]
    fn refresh_cookie_value_structure() {
        let c = refresh_cookie_value("abc123");
        assert!(c.starts_with("weissman_refresh=abc123;"));
        assert!(c.contains("Path=/api/auth"));
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Strict"));
        assert!(c.contains("Max-Age="));
    }

    #[test]
    fn refresh_cookie_clear_has_zero_max_age() {
        let c = refresh_cookie_clear_value();
        assert!(c.starts_with("weissman_refresh=;"));
        assert!(c.contains("Max-Age=0"));
        assert!(c.contains("Path=/api/auth"));
    }
}
