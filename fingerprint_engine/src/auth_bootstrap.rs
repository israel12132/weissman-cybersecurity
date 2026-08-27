//! Sync env operator credentials and promote them to platform owner.
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
//! Identities promoted: `WEISSMAN_ADMIN_EMAIL` and, when set,
//! `WEISSMAN_MASTER_BOOTSTRAP_EMAIL`. CI live smoke logs in as the master
//! bootstrap user (`ci-smoke@localhost`); that account must be owner or
//! `POST /api/clients` returns `403 owner_required`.

use sqlx::{PgPool, Row};

/// Env operators that must be platform owners (`is_superadmin`).
///
/// Client create/delete is owner-only. Command Center admin **and** the
/// optional first-boot master bootstrap user are both env-provisioned
/// operators, so both get the flag. Duplicate emails (same identity on both
/// vars) are collapsed case-insensitively.
pub(crate) fn env_operator_emails_from(
    admin: Option<&str>,
    master_bootstrap: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    for raw in [admin, master_bootstrap] {
        let Some(s) = raw else {
            continue;
        };
        let email = s.trim();
        if email.is_empty() {
            continue;
        }
        if out
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(email))
        {
            continue;
        }
        out.push(email.to_string());
    }
    out
}

fn env_operator_emails() -> Vec<String> {
    env_operator_emails_from(
        std::env::var("WEISSMAN_ADMIN_EMAIL").ok().as_deref(),
        std::env::var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL")
            .ok()
            .as_deref(),
    )
}

/// Sync admin credentials and promote configured operators to platform owner.
///
/// `auth_pool` is BYPASSRLS (`weissman_auth`). `app_pool` is RLS-subject
/// (`weissman_app`) and is only written through a tenant-scoped transaction.
pub async fn sync_admin_credentials(auth_pool: &PgPool, app_pool: &PgPool) {
    let emails = env_operator_emails();
    if emails.is_empty() {
        return;
    }
    let admin_email = std::env::var("WEISSMAN_ADMIN_EMAIL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let admin_password = std::env::var("WEISSMAN_ADMIN_PASSWORD")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    for email in emails {
        let seed_password = admin_email
            .as_ref()
            .filter(|a| a.eq_ignore_ascii_case(&email))
            .and_then(|_| admin_password.as_deref());
        sync_one_operator(auth_pool, app_pool, &email, seed_password).await;
    }
}

async fn sync_one_operator(
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

    // First boot: no credential yet — seed it from WEISSMAN_ADMIN_PASSWORD for
    // the admin email only. Master bootstrap already hashed at insert time.
    let Some(password) = seed_password else {
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
    use super::env_operator_emails_from;

    #[test]
    fn env_operators_empty_when_neither_identity_is_set() {
        assert!(env_operator_emails_from(None, None).is_empty());
        assert!(env_operator_emails_from(Some("  "), Some("")).is_empty());
    }

    #[test]
    fn env_operators_include_admin_and_master_bootstrap() {
        assert_eq!(
            env_operator_emails_from(Some("admin@localhost"), None),
            vec!["admin@localhost".to_string()]
        );
        assert_eq!(
            env_operator_emails_from(None, Some("ci-smoke@localhost")),
            vec!["ci-smoke@localhost".to_string()]
        );
        assert_eq!(
            env_operator_emails_from(Some("admin@localhost"), Some("ci-smoke@localhost")),
            vec![
                "admin@localhost".to_string(),
                "ci-smoke@localhost".to_string()
            ]
        );
    }

    #[test]
    fn env_operators_collapse_duplicate_emails_case_insensitively() {
        assert_eq!(
            env_operator_emails_from(Some("Admin@LocalHost"), Some("admin@localhost")),
            vec!["Admin@LocalHost".to_string()]
        );
    }

    #[test]
    fn env_operators_trim_whitespace() {
        assert_eq!(
            env_operator_emails_from(Some("  admin@localhost \n"), Some(" ci-smoke@localhost ")),
            vec![
                "admin@localhost".to_string(),
                "ci-smoke@localhost".to_string()
            ]
        );
    }
}
