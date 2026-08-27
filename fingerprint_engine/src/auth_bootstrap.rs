//! Sync `WEISSMAN_ADMIN_EMAIL` / `WEISSMAN_ADMIN_PASSWORD` with the auth DB on boot.
//!
//! Prevents password hash drift when env credentials change or a user row was
//! deactivated during testing. Idempotent: only re-hashes when the row has no
//! usable credential yet.
//!
//! **RLS:** `users` is FORCE ROW LEVEL SECURITY. Lookups must use the auth pool
//! (`auth.v_user_lookup`, BYPASSRLS). Writes must run inside
//! [`weissman_db::begin_tenant_tx`] on the app pool — an unscoped `UPDATE` is a
//! silent no-op, which previously left the env operator as `role=admin` without
//! `is_superadmin` and blocked owner-only client create/delete.
//!
//! **Owner promotion:** client create/delete is owner-only (`is_superadmin` or
//! CEO). Both `WEISSMAN_ADMIN_EMAIL` and `WEISSMAN_MASTER_BOOTSTRAP_EMAIL` are
//! env operators. Promoting only the former left the master-bootstrap login
//! (CI smoke: `ci-smoke@localhost`) as staff admin, so `POST /api/clients`
//! returned `owner_required`.

use sqlx::{PgPool, Row};

/// Sync admin credentials and promote configured env operators to platform owner.
///
/// `auth_pool` is BYPASSRLS (`weissman_auth`). `app_pool` is RLS-subject
/// (`weissman_app`) and is only written through a tenant-scoped transaction.
pub async fn sync_admin_credentials(auth_pool: &PgPool, app_pool: &PgPool) {
    let admin_email = env_nonempty("WEISSMAN_ADMIN_EMAIL");
    let admin_password = env_nonempty("WEISSMAN_ADMIN_PASSWORD");
    let master_email = env_nonempty("WEISSMAN_MASTER_BOOTSTRAP_EMAIL");

    if let Some(email) = admin_email.as_deref() {
        sync_one_operator(auth_pool, app_pool, email, admin_password.as_deref()).await;
    }

    if let Some(email) = master_email.as_deref() {
        if !emails_equal(admin_email.as_deref(), Some(email)) {
            // Password for this row was set at insert (`ensure_master_bootstrap_user`).
            // Promote only — never overwrite a hash from WEISSMAN_ADMIN_PASSWORD.
            sync_one_operator(auth_pool, app_pool, email, None).await;
        }
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn emails_equal(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        _ => false,
    }
}

/// Unique env-operator emails that must be platform owners after boot.
#[cfg(test)]
fn operator_emails_from(admin: Option<&str>, master: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    for raw in [admin, master].into_iter().flatten() {
        let e = raw.trim();
        if e.is_empty() {
            continue;
        }
        if out.iter().any(|x: &String| x.eq_ignore_ascii_case(e)) {
            continue;
        }
        out.push(e.to_string());
    }
    out
}

async fn sync_one_operator(
    auth_pool: &PgPool,
    app_pool: &PgPool,
    email: &str,
    password: Option<&str>,
) {
    let row = match sqlx::query(
        r#"SELECT u.id,
                  u.tenant_id,
                  COALESCE(u.password_hash, '') AS password_hash,
                  COALESCE(u.is_active, false) AS is_active,
                  COALESCE(u.is_superadmin, false) AS is_superadmin
           FROM auth.v_user_lookup u
           INNER JOIN tenants t ON t.id = u.tenant_id
           WHERE lower(trim(u.email)) = lower(trim($1))
             AND t.slug = 'default'
           LIMIT 1"#,
    )
    .bind(email)
    .fetch_optional(auth_pool)
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target: "auth_bootstrap",
                error = %e,
                "admin credential sync lookup failed"
            );
            return;
        }
    };

    let Some(row) = row else {
        tracing::debug!(
            target: "auth_bootstrap",
            email = %email,
            "no default-tenant admin row to sync"
        );
        return;
    };

    let user_id: i64 = match row.try_get("id") {
        Ok(v) => v,
        Err(_) => return,
    };
    let tenant_id: i64 = match row.try_get("tenant_id") {
        Ok(v) if v > 0 => v,
        _ => {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id,
                "admin row has no tenant_id; refusing unscoped write"
            );
            return;
        }
    };
    let hash: String = row.try_get("password_hash").unwrap_or_default();
    let is_active: bool = row.try_get("is_active").unwrap_or(false);
    let already_owner: bool = row.try_get("is_superadmin").unwrap_or(false);

    let mut tx = match weissman_db::begin_tenant_tx(app_pool, tenant_id).await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id,
                tenant_id,
                error = %e,
                "admin credential sync could not open tenant transaction"
            );
            return;
        }
    };

    // Client create/delete is owner-only (CEO / superadmin). Env operators are
    // the platform owner; promote without touching a password they chose later.
    if !already_owner {
        if let Err(e) = sqlx::query(
            r#"UPDATE users
               SET is_superadmin = true
               WHERE id = $1
                 AND COALESCE(is_superadmin, false) = false
                 AND assigned_client_id IS NULL
                 AND lower(trim(COALESCE(role, ''))) <> 'client'"#,
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id,
                error = %e,
                "owner superadmin promotion failed"
            );
            let _ = tx.rollback().await;
            return;
        } else {
            tracing::info!(
                target: "auth_bootstrap",
                user_id,
                email = %email,
                "Promoted configured operator to platform owner (is_superadmin)"
            );
        }
    }

    // Only WRITE the password hash during first-boot bootstrap (when there is no usable
    // hash yet). Re-hashing from WEISSMAN_ADMIN_PASSWORD on every boot would silently
    // revert a password the operator changed in the UI back to the env value — directly
    // contradicting the launcher's "change the admin password after first login" guidance,
    // and reviving the original password (which is echoed in the boot banner and stored in
    // .env) forever. A disabled account is still re-activated for recovery, but its
    // existing credential is preserved.
    if !hash.is_empty() {
        if !is_active {
            if let Err(e) = sqlx::query("UPDATE users SET is_active = true WHERE id = $1")
                .bind(user_id)
                .execute(&mut *tx)
                .await
            {
                tracing::warn!(
                    target: "auth_bootstrap",
                    user_id,
                    error = %e,
                    "admin reactivation failed"
                );
                let _ = tx.rollback().await;
                return;
            }
            tracing::info!(
                target: "auth_bootstrap",
                user_id,
                email = %email,
                "Re-activated disabled admin (existing password preserved)"
            );
        }
        if let Err(e) = tx.commit().await {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id,
                error = %e,
                "admin credential sync commit failed"
            );
        }
        return;
    }

    let Some(password) = password.filter(|p| !p.is_empty()) else {
        if let Err(e) = tx.commit().await {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id,
                error = %e,
                "admin owner promotion commit failed"
            );
        }
        return;
    };

    // First boot: no credential yet — seed it from WEISSMAN_ADMIN_PASSWORD.
    let new_hash = match bcrypt::hash(password, 12) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(target: "auth_bootstrap", error = %e, "bcrypt hash failed");
            let _ = tx.rollback().await;
            return;
        }
    };

    if let Err(e) = sqlx::query(
        r#"UPDATE users
           SET password_hash = $1,
               is_active = true,
               is_superadmin = true
           WHERE id = $2
             AND assigned_client_id IS NULL
             AND lower(trim(COALESCE(role, ''))) <> 'client'"#,
    )
    .bind(&new_hash)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    {
        tracing::warn!(
            target: "auth_bootstrap",
            user_id,
            error = %e,
            "admin credential bootstrap failed"
        );
        let _ = tx.rollback().await;
        return;
    }

    if let Err(e) = tx.commit().await {
        tracing::warn!(
            target: "auth_bootstrap",
            user_id,
            error = %e,
            "admin credential bootstrap commit failed"
        );
        return;
    }

    tracing::info!(
        target: "auth_bootstrap",
        user_id,
        email = %email,
        "Admin credential bootstrapped from WEISSMAN_ADMIN_* env (first boot)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_emails_include_admin_and_distinct_master_bootstrap() {
        assert_eq!(
            operator_emails_from(Some("admin@localhost"), Some("ci-smoke@localhost")),
            vec![
                "admin@localhost".to_string(),
                "ci-smoke@localhost".to_string()
            ]
        );
    }

    #[test]
    fn operator_emails_dedupe_case_insensitive() {
        assert_eq!(
            operator_emails_from(Some("Admin@Localhost"), Some("admin@localhost")),
            vec!["Admin@Localhost".to_string()]
        );
    }

    #[test]
    fn operator_emails_skip_blank() {
        assert_eq!(
            operator_emails_from(Some("  "), Some("ci-smoke@localhost")),
            vec!["ci-smoke@localhost".to_string()]
        );
        assert!(operator_emails_from(None, None).is_empty());
    }

    #[test]
    fn master_bootstrap_is_an_env_operator_even_without_admin_email() {
        assert_eq!(
            operator_emails_from(None, Some("ci-smoke@localhost")),
            vec!["ci-smoke@localhost".to_string()]
        );
    }

    fn require_db_tests() -> bool {
        std::env::var("WEISSMAN_REQUIRE_DB_TESTS")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false)
    }

    fn test_database_url() -> String {
        match std::env::var("TEST_DATABASE_URL") {
            Ok(u) if !u.trim().is_empty() => u.trim().to_string(),
            _ => {
                assert!(
                    !require_db_tests(),
                    "auth_bootstrap owner promotion requires TEST_DATABASE_URL, but \
                     WEISSMAN_REQUIRE_DB_TESTS is set"
                );
                String::new()
            }
        }
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// CI smoke logs in as WEISSMAN_MASTER_BOOTSTRAP_EMAIL. That user must become
    /// is_superadmin or POST /api/clients returns owner_required.
    #[tokio::test]
    async fn sync_promotes_master_bootstrap_user_to_owner() {
        let url = test_database_url();
        if url.is_empty() {
            eprintln!("SKIP sync_promotes_master_bootstrap_user_to_owner: no TEST_DATABASE_URL");
            return;
        }
        let _guard = env_lock();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("connect TEST_DATABASE_URL");

        let email = format!(
            "bootstrap-owner-{}@localhost",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let tenant_id: i64 = sqlx::query_scalar(
            "SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1",
        )
        .fetch_optional(&pool)
        .await
        .expect("lookup default tenant")
        .expect("default tenant must exist");

        sqlx::query(
            "INSERT INTO users (tenant_id, email, password_hash, role, is_superadmin, is_active) \
             VALUES ($1, $2, 'x', 'admin', false, true)",
        )
        .bind(tenant_id)
        .bind(&email)
        .execute(&pool)
        .await
        .expect("seed bootstrap staff admin");

        let prev_admin = std::env::var("WEISSMAN_ADMIN_EMAIL").ok();
        let prev_password = std::env::var("WEISSMAN_ADMIN_PASSWORD").ok();
        let prev_master = std::env::var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL").ok();
        struct RestoreEnv {
            admin: Option<String>,
            password: Option<String>,
            master: Option<String>,
        }
        impl Drop for RestoreEnv {
            fn drop(&mut self) {
                match &self.admin {
                    Some(v) => std::env::set_var("WEISSMAN_ADMIN_EMAIL", v),
                    None => std::env::remove_var("WEISSMAN_ADMIN_EMAIL"),
                }
                match &self.password {
                    Some(v) => std::env::set_var("WEISSMAN_ADMIN_PASSWORD", v),
                    None => std::env::remove_var("WEISSMAN_ADMIN_PASSWORD"),
                }
                match &self.master {
                    Some(v) => std::env::set_var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL", v),
                    None => std::env::remove_var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL"),
                }
            }
        }
        let _restore = RestoreEnv {
            admin: prev_admin,
            password: prev_password,
            master: prev_master,
        };
        std::env::remove_var("WEISSMAN_ADMIN_EMAIL");
        std::env::remove_var("WEISSMAN_ADMIN_PASSWORD");
        std::env::set_var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL", &email);

        sync_admin_credentials(&pool, &pool).await;

        let owner: bool = sqlx::query_scalar(
            "SELECT COALESCE(is_superadmin, false) FROM users WHERE tenant_id = $1 AND email = $2",
        )
        .bind(tenant_id)
        .bind(&email)
        .fetch_one(&pool)
        .await
        .expect("read is_superadmin");

        let _ = sqlx::query("DELETE FROM users WHERE tenant_id = $1 AND email = $2")
            .bind(tenant_id)
            .bind(&email)
            .execute(&pool)
            .await;

        assert!(
            owner,
            "WEISSMAN_MASTER_BOOTSTRAP_EMAIL must be promoted to is_superadmin so \
             owner-only client create works for the CI/smoke operator"
        );
    }
}
