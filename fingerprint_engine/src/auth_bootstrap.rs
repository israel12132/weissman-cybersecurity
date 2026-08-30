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
//! CI smoke logs in as `WEISSMAN_MASTER_BOOTSTRAP_EMAIL` (not `WEISSMAN_ADMIN_EMAIL`).
//! Both identities are platform owners: client create/delete is owner-only.

use sqlx::{PgPool, Row};

/// Env-configured operators that must be able to create clients (owner plane).
/// Dedupes case-insensitively; empty strings are ignored.
#[must_use]
pub fn merge_owner_emails(admin: Option<&str>, bootstrap: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    for raw in [admin, bootstrap].into_iter().flatten() {
        let t = raw.trim().to_ascii_lowercase();
        if t.is_empty() {
            continue;
        }
        if !out.iter().any(|e| e == &t) {
            out.push(t);
        }
    }
    out
}

fn env_owner_emails() -> Vec<String> {
    merge_owner_emails(
        std::env::var("WEISSMAN_ADMIN_EMAIL").ok().as_deref(),
        std::env::var("WEISSMAN_MASTER_BOOTSTRAP_EMAIL")
            .ok()
            .as_deref(),
    )
}

/// Sync admin credentials and promote env operators to platform owner.
///
/// `auth_pool` is BYPASSRLS (`weissman_auth`). `app_pool` is RLS-subject
/// (`weissman_app`) and is only written through a tenant-scoped transaction.
pub async fn sync_admin_credentials(auth_pool: &PgPool, app_pool: &PgPool) {
    for email in env_owner_emails() {
        promote_env_operator(auth_pool, app_pool, &email).await;
    }

    let email = match std::env::var("WEISSMAN_ADMIN_EMAIL") {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return,
    };
    let password = match std::env::var("WEISSMAN_ADMIN_PASSWORD") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return,
    };

    let Some(row) = lookup_default_user(auth_pool, &email).await else {
        tracing::debug!(
            target: "auth_bootstrap",
            email = %email,
            "no default-tenant admin row to sync"
        );
        return;
    };

    seed_admin_password_if_empty(app_pool, &row, &email, &password).await;
}

struct OwnerRow {
    user_id: i64,
    tenant_id: i64,
    hash: String,
    is_active: bool,
    already_owner: bool,
}

async fn lookup_default_user(auth_pool: &PgPool, email: &str) -> Option<OwnerRow> {
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
            return None;
        }
    };
    let row = row?;
    let user_id: i64 = row.try_get("id").ok()?;
    let tenant_id: i64 = match row.try_get("tenant_id") {
        Ok(v) if v > 0 => v,
        _ => {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id,
                "admin row has no tenant_id; refusing unscoped write"
            );
            return None;
        }
    };
    Some(OwnerRow {
        user_id,
        tenant_id,
        hash: row.try_get("password_hash").unwrap_or_default(),
        is_active: row.try_get("is_active").unwrap_or(false),
        already_owner: row.try_get("is_superadmin").unwrap_or(false),
    })
}

/// Promote a default-tenant env operator to `is_superadmin` so owner-only
/// client lifecycle works. Refuses portal (`client`) and assigned-client rows.
async fn promote_env_operator(auth_pool: &PgPool, app_pool: &PgPool, email: &str) {
    let Some(row) = lookup_default_user(auth_pool, email).await else {
        return;
    };
    if row.already_owner {
        return;
    }
    let mut tx = match weissman_db::begin_tenant_tx(app_pool, row.tenant_id).await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id = row.user_id,
                tenant_id = row.tenant_id,
                error = %e,
                "owner promotion could not open tenant transaction"
            );
            return;
        }
    };
    if let Err(e) = sqlx::query(
        r#"UPDATE users
           SET is_superadmin = true
           WHERE id = $1
             AND COALESCE(is_superadmin, false) = false
             AND assigned_client_id IS NULL
             AND lower(trim(COALESCE(role, ''))) <> 'client'"#,
    )
    .bind(row.user_id)
    .execute(&mut *tx)
    .await
    {
        tracing::warn!(
            target: "auth_bootstrap",
            user_id = row.user_id,
            error = %e,
            "owner superadmin promotion failed"
        );
        let _ = tx.rollback().await;
        return;
    }
    if let Err(e) = tx.commit().await {
        tracing::warn!(
            target: "auth_bootstrap",
            user_id = row.user_id,
            error = %e,
            "owner superadmin promotion commit failed"
        );
        return;
    }
    tracing::info!(
        target: "auth_bootstrap",
        user_id = row.user_id,
        email = %email,
        "Promoted configured operator to platform owner (is_superadmin)"
    );
}

async fn seed_admin_password_if_empty(
    app_pool: &PgPool,
    row: &OwnerRow,
    email: &str,
    password: &str,
) {
    let mut tx = match weissman_db::begin_tenant_tx(app_pool, row.tenant_id).await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id = row.user_id,
                tenant_id = row.tenant_id,
                error = %e,
                "admin credential sync could not open tenant transaction"
            );
            return;
        }
    };

    // Only WRITE the password hash during first-boot bootstrap (when there is no usable
    // hash yet). Re-hashing from WEISSMAN_ADMIN_PASSWORD on every boot would silently
    // revert a password the operator changed in the UI back to the env value — directly
    // contradicting the launcher's "change the admin password after first login" guidance,
    // and reviving the original password (which is echoed in the boot banner and stored in
    // .env) forever. A disabled account is still re-activated for recovery, but its
    // existing credential is preserved.
    if !row.hash.is_empty() {
        if !row.is_active {
            if let Err(e) = sqlx::query("UPDATE users SET is_active = true WHERE id = $1")
                .bind(row.user_id)
                .execute(&mut *tx)
                .await
            {
                tracing::warn!(
                    target: "auth_bootstrap",
                    user_id = row.user_id,
                    error = %e,
                    "admin reactivation failed"
                );
                let _ = tx.rollback().await;
                return;
            }
            tracing::info!(
                target: "auth_bootstrap",
                user_id = row.user_id,
                email = %email,
                "Re-activated disabled admin (existing password preserved)"
            );
        }
        if let Err(e) = tx.commit().await {
            tracing::warn!(
                target: "auth_bootstrap",
                user_id = row.user_id,
                error = %e,
                "admin credential sync commit failed"
            );
        }
        return;
    }

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
    .bind(row.user_id)
    .execute(&mut *tx)
    .await
    {
        tracing::warn!(
            target: "auth_bootstrap",
            user_id = row.user_id,
            error = %e,
            "admin credential bootstrap failed"
        );
        let _ = tx.rollback().await;
        return;
    }

    if let Err(e) = tx.commit().await {
        tracing::warn!(
            target: "auth_bootstrap",
            user_id = row.user_id,
            error = %e,
            "admin credential bootstrap commit failed"
        );
        return;
    }

    tracing::info!(
        target: "auth_bootstrap",
        user_id = row.user_id,
        email = %email,
        "Admin credential bootstrapped from WEISSMAN_ADMIN_* env (first boot)"
    );
}

#[cfg(test)]
mod tests {
    use super::merge_owner_emails;

    #[test]
    fn ci_smoke_bootstrap_is_an_owner_alongside_admin() {
        assert_eq!(
            merge_owner_emails(Some("admin@localhost"), Some("ci-smoke@localhost")),
            vec![
                "admin@localhost".to_string(),
                "ci-smoke@localhost".to_string()
            ]
        );
    }

    #[test]
    fn duplicate_admin_and_bootstrap_collapse() {
        assert_eq!(
            merge_owner_emails(Some("Admin@Localhost"), Some("admin@localhost")),
            vec!["admin@localhost".to_string()]
        );
    }

    #[test]
    fn empty_and_missing_are_skipped() {
        assert!(merge_owner_emails(None, Some("  ")).is_empty());
        assert_eq!(
            merge_owner_emails(None, Some("owner@example")),
            vec!["owner@example".to_string()]
        );
    }
}
