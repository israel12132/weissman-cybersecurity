//! Sync env operators (`WEISSMAN_ADMIN_EMAIL`, `WEISSMAN_MASTER_BOOTSTRAP_EMAIL`)
//! with the auth DB on boot.
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
//! CI smoke logs in as `WEISSMAN_MASTER_BOOTSTRAP_EMAIL`. That account is
//! inserted as `role=admin` (staff). Client create/delete is owner-only, so boot
//! must promote the master-bootstrap email the same way as `WEISSMAN_ADMIN_EMAIL`.

use sqlx::{PgPool, Row};

/// Unique default-tenant operator emails that must be platform owners after boot.
#[must_use]
pub fn owner_emails_from(admin: Option<&str>, master: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    for raw in [admin, master].into_iter().flatten() {
        let email = raw.trim();
        if email.is_empty() {
            continue;
        }
        if !out
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(email))
        {
            out.push(email.to_string());
        }
    }
    out
}

fn env_trimmed(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Sync admin credentials and promote configured operators to platform owner.
///
/// `auth_pool` is BYPASSRLS (`weissman_auth`). `app_pool` is RLS-subject
/// (`weissman_app`) and is only written through a tenant-scoped transaction.
///
/// Password seeding applies only to `WEISSMAN_ADMIN_EMAIL` when that row has no
/// hash yet. The master-bootstrap user is created with a hash by
/// `ensure_master_bootstrap_user` and is only promoted here.
pub async fn sync_admin_credentials(auth_pool: &PgPool, app_pool: &PgPool) {
    let admin_email = env_trimmed("WEISSMAN_ADMIN_EMAIL");
    let admin_password = env_trimmed("WEISSMAN_ADMIN_PASSWORD");
    let master_email = env_trimmed("WEISSMAN_MASTER_BOOTSTRAP_EMAIL");
    let emails = owner_emails_from(admin_email.as_deref(), master_email.as_deref());
    for email in emails {
        let seed_password = if admin_email
            .as_deref()
            .is_some_and(|admin| admin.eq_ignore_ascii_case(&email))
        {
            admin_password.as_deref()
        } else {
            None
        };
        sync_one_owner(auth_pool, app_pool, &email, seed_password).await;
    }
}

/// Promote one default-tenant operator to `is_superadmin` (and optionally seed
/// a first-boot password). Used by boot and by the live owner-bootstrap test.
pub async fn sync_one_owner(
    auth_pool: &PgPool,
    app_pool: &PgPool,
    email: &str,
    seed_password: Option<&str>,
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

    // Client create/delete is owner-only (CEO / superadmin). Env operators
    // (ADMIN_EMAIL and MASTER_BOOTSTRAP_EMAIL) are platform owners.
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

    let Some(password) = seed_password.filter(|p| !p.is_empty()) else {
        if let Err(e) = tx.commit().await {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id,
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
    use super::owner_emails_from;

    #[test]
    fn owner_emails_include_admin_and_master_once() {
        let emails = owner_emails_from(Some(" admin@localhost "), Some("ci-smoke@localhost"));
        assert_eq!(
            emails,
            vec![
                "admin@localhost".to_string(),
                "ci-smoke@localhost".to_string()
            ]
        );
    }

    #[test]
    fn owner_emails_dedupe_same_identity() {
        let emails = owner_emails_from(Some("ci-smoke@localhost"), Some("CI-SMOKE@localhost"));
        assert_eq!(emails, vec!["ci-smoke@localhost".to_string()]);
    }

    #[test]
    fn owner_emails_master_only_when_admin_unset() {
        assert_eq!(
            owner_emails_from(None, Some("ci-smoke@localhost")),
            vec!["ci-smoke@localhost".to_string()]
        );
        assert!(owner_emails_from(Some("  "), None).is_empty());
    }
}
