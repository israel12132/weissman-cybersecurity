//! Sync `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD` with the auth DB on boot.
//!
//! Prevents password hash drift when env credentials change or a user row was
//! deactivated during testing. Idempotent: only re-hashes when verify fails.

use sqlx::PgPool;

/// Sync admin credentials using the app pool (RLS-scoped writes). The auth pool
/// (`weissman_auth`) cannot UPDATE `users` after sovereign hardening.
pub async fn sync_admin_credentials(app_pool: &PgPool) {
    let email = match std::env::var("WEISSMAN_ADMIN_EMAIL") {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return,
    };
    let password = match std::env::var("WEISSMAN_ADMIN_PASSWORD") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return,
    };

    let row = match sqlx::query_as::<_, (i64, String, bool)>(
        r#"SELECT u.id, COALESCE(u.password_hash, ''), COALESCE(u.is_active, false)
           FROM users u
           INNER JOIN tenants t ON t.id = u.tenant_id
           WHERE lower(trim(u.email)) = lower(trim($1))
             AND t.slug = 'default'
           LIMIT 1"#,
    )
    .bind(&email)
    .fetch_optional(app_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target: "auth_bootstrap", error = %e, "admin credential sync lookup failed");
            return;
        }
    };

    let Some((user_id, hash, is_active)) = row else {
        tracing::debug!(target: "auth_bootstrap", email = %email, "no default-tenant admin row to sync");
        return;
    };

    let password_ok = !hash.is_empty() && matches!(bcrypt::verify(&password, &hash), Ok(true));
    if password_ok && is_active {
        return;
    }

    let new_hash = match bcrypt::hash(&password, 12) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(target: "auth_bootstrap", error = %e, "bcrypt hash failed");
            return;
        }
    };

    if let Err(e) = sqlx::query(
        "UPDATE users SET password_hash = $1, is_active = true WHERE id = $2",
    )
    .bind(&new_hash)
    .bind(user_id)
    .execute(app_pool)
    .await
    {
        tracing::warn!(target: "auth_bootstrap", user_id, error = %e, "admin credential sync update failed");
        return;
    }

    tracing::info!(
        target: "auth_bootstrap",
        user_id,
        email = %email,
        reactivated = !is_active,
        "Admin credentials synced from WEISSMAN_ADMIN_* env"
    );
}
