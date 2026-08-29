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
//! `WEISSMAN_MASTER_BOOTSTRAP_EMAIL` is promoted the same way. Client create is
//! owner-only (`is_superadmin` or CEO). The master-bootstrap account is the
//! first-install / CI smoke operator; leaving it as staff `role=admin` yields
//! HTTP 403 `owner_required` on `POST /api/clients`.

use sqlx::{PgPool, Row};

fn env_trimmed(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Default-tenant emails that must be platform owners after boot.
///
/// The env operator (`WEISSMAN_ADMIN_EMAIL`) and the optional master-bootstrap
/// account (`WEISSMAN_MASTER_BOOTSTRAP_EMAIL`) are both promoted. Duplicate
/// values (case-insensitive) collapse to one entry.
pub(crate) fn owner_bootstrap_emails() -> Vec<String> {
    let mut emails = Vec::with_capacity(2);
    for key in ["WEISSMAN_ADMIN_EMAIL", "WEISSMAN_MASTER_BOOTSTRAP_EMAIL"] {
        if let Some(email) = env_trimmed(key) {
            if !emails
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(&email))
            {
                emails.push(email);
            }
        }
    }
    emails
}

/// Sync admin credentials and promote configured operators to platform owner.
///
/// `auth_pool` is BYPASSRLS (`weissman_auth`). `app_pool` is RLS-subject
/// (`weissman_app`) and is only written through a tenant-scoped transaction.
pub async fn sync_admin_credentials(auth_pool: &PgPool, app_pool: &PgPool) {
    let admin_email = env_trimmed("WEISSMAN_ADMIN_EMAIL");
    let admin_password = env_trimmed("WEISSMAN_ADMIN_PASSWORD");
    for email in owner_bootstrap_emails() {
        let password = admin_email
            .as_ref()
            .filter(|a| a.eq_ignore_ascii_case(&email))
            .and(admin_password.as_deref());
        sync_one_operator(auth_pool, app_pool, &email, password).await;
    }
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
                email = %email,
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
                email = %email,
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
                email = %email,
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
                email = %email,
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
                    email = %email,
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
                email = %email,
                error = %e,
                "admin credential sync commit failed"
            );
        }
        return;
    }

    let Some(password) = password else {
        if let Err(e) = tx.commit().await {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id,
                email = %email,
                error = %e,
                "admin credential sync commit failed"
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
            email = %email,
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
            email = %email,
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
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    struct EnvRestore {
        admin: Option<String>,
        master: Option<String>,
    }

    impl EnvRestore {
        fn capture() -> Self {
            Self {
                admin: std::env::var("WEISSMAN_ADMIN_EMAIL").ok(),
                master: std::env::var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL").ok(),
            }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.admin.take() {
                Some(v) => std::env::set_var("WEISSMAN_ADMIN_EMAIL", v),
                None => std::env::remove_var("WEISSMAN_ADMIN_EMAIL"),
            }
            match self.master.take() {
                Some(v) => std::env::set_var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL", v),
                None => std::env::remove_var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL"),
            }
        }
    }

    #[test]
    fn owner_emails_include_admin_and_distinct_master_bootstrap() {
        let _g = env_lock();
        let _restore = EnvRestore::capture();
        std::env::set_var("WEISSMAN_ADMIN_EMAIL", " admin@localhost ");
        std::env::set_var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL", "ci-smoke@localhost");
        assert_eq!(
            owner_bootstrap_emails(),
            vec![
                "admin@localhost".to_string(),
                "ci-smoke@localhost".to_string()
            ]
        );
    }

    #[test]
    fn owner_emails_dedupe_case_insensitive() {
        let _g = env_lock();
        let _restore = EnvRestore::capture();
        std::env::set_var("WEISSMAN_ADMIN_EMAIL", "ci-smoke@localhost");
        std::env::set_var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL", "CI-SMOKE@localhost");
        assert_eq!(
            owner_bootstrap_emails(),
            vec!["ci-smoke@localhost".to_string()]
        );
    }

    #[test]
    fn owner_emails_skip_blank() {
        let _g = env_lock();
        let _restore = EnvRestore::capture();
        std::env::set_var("WEISSMAN_ADMIN_EMAIL", "   ");
        std::env::remove_var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL");
        assert!(owner_bootstrap_emails().is_empty());
    }
}
