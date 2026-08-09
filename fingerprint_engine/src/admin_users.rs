// Admin User Management APIs for admin, CEO or superadmin (see require_admin_access)
// Routes: GET/POST /api/admin/users, PATCH /api/admin/users/:id, POST /api/admin/users/:id/deactivate

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::Arc;

use crate::auth_jwt::AuthContext;
use crate::http::AppState;

#[derive(Deserialize)]
pub struct CreateUserBody {
    pub email: String,
    pub password: String,
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default)]
    pub is_superadmin: bool,
}

fn default_role() -> String {
    "viewer".to_string()
}

#[derive(Deserialize)]
pub struct UpdateUserBody {
    pub role: Option<String>,
    pub is_superadmin: Option<bool>,
}

#[derive(Serialize)]
struct UserInfo {
    id: i64,
    email: String,
    role: String,
    is_superadmin: bool,
    is_active: bool,
    created_at: Option<String>,
}

/// Allow the DB `guard_users_ceo_role` trigger for this transaction.
async fn allow_ceo_role_assignment(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), Response> {
    sqlx::query("SET LOCAL app.ceo_role_assignment = '1'")
        .execute(&mut **tx)
        .await
        .map(|_| ())
        .map_err(|e| {
            tracing::error!(target: "admin", error = %e, "set ceo_role_assignment guc failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "Failed to authorize CEO role assignment"})),
            )
                .into_response()
        })
}

/// Check if the caller is admin, CEO or superadmin (uses live DB role, not JWT alone).
async fn require_admin_access(pool: &PgPool, auth: &AuthContext) -> Result<AuthContext, Response> {
    let auth = match crate::auth_refresh::revalidate_auth_context(pool, auth).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"ok": false, "detail": "Account inactive or not found"})),
            )
                .into_response());
        }
        Err(e) => {
            tracing::error!(target: "admin", error = %e, "RBAC revalidation failed");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "RBAC lookup failed"})),
            )
                .into_response());
        }
    };
    if auth.is_superadmin
        || auth.role.to_lowercase() == "ceo"
        || auth.role.to_lowercase() == "admin"
    {
        Ok(auth)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "detail": "admin, CEO or superadmin role required"})),
        )
            .into_response())
    }
}

/// Effective privilege rank: a superadmin outranks every named role.
fn effective_rank(role: &str, is_superadmin: bool) -> u8 {
    if is_superadmin {
        u8::MAX
    } else {
        crate::rbac::role_rank(&role.to_lowercase())
    }
}

/// Guard: a non-superadmin actor may only modify a target of strictly LOWER
/// effective rank. This stops a lower-privileged admin from demoting, role-swapping,
/// or deactivating a CEO or a peer admin. Superadmins bypass.
fn ensure_can_manage_target(
    actor: &AuthContext,
    target_role: &str,
    target_is_superadmin: bool,
) -> Result<(), Response> {
    if actor.is_superadmin {
        return Ok(());
    }
    let actor_rank = effective_rank(&actor.role, actor.is_superadmin);
    let target_rank = effective_rank(target_role, target_is_superadmin);
    if target_rank >= actor_rank {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "detail": "Cannot modify a user of equal or higher privilege"
            })),
        )
            .into_response());
    }
    Ok(())
}

/// GET /api/admin/users — List all users in the tenant
pub async fn api_admin_users_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    let auth = match require_admin_access(state.auth_pool.as_ref(), &auth).await {
        Ok(a) => a,
        Err(r) => return r,
    };

    // `users` is RLS-forced
    // We MUST open a tenant-scoped transaction so the GUC is set, otherwise even superuser hits
    // "permission denied" because the row simply isn't visible. Use the app_pool which goes
    // through begin_tenant_tx; users live in the same DB.
    let mut tx = match crate::db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(target: "admin", error = %e, "begin_tenant_tx failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "Database unavailable"})),
            )
                .into_response();
        }
    };

    let query = r#"
        SELECT id, email, COALESCE(role, 'viewer') AS role,
               COALESCE(is_superadmin, false) AS is_superadmin,
               COALESCE(is_active, true) AS is_active,
               created_at
        FROM users
        WHERE tenant_id = $1
        ORDER BY created_at DESC
        LIMIT 500
    "#;

    match sqlx::query(query)
        .bind(auth.tenant_id)
        .fetch_all(&mut *tx)
        .await
    {
        Ok(rows) => {
            let _ = tx.commit().await;
            let users: Vec<UserInfo> = rows
                .into_iter()
                .map(|r| UserInfo {
                    id: r.try_get::<i64, _>("id").unwrap_or(0),
                    email: r.try_get::<String, _>("email").unwrap_or_default(),
                    role: r
                        .try_get::<String, _>("role")
                        .unwrap_or_else(|_| "viewer".to_string()),
                    is_superadmin: r.try_get::<bool, _>("is_superadmin").unwrap_or(false),
                    is_active: r.try_get::<bool, _>("is_active").unwrap_or(true),
                    created_at: r
                        .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                        .ok()
                        .map(|d| d.to_rfc3339()),
                })
                .collect();
            (StatusCode::OK, Json(json!({ "users": users }))).into_response()
        }
        Err(e) => {
            tracing::error!(target: "admin", error = %e, "Failed to list users");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "Database error"})),
            )
                .into_response()
        }
    }
}

/// POST /api/admin/users — Create a new user
pub async fn api_admin_users_create(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<CreateUserBody>,
) -> Response {
    let auth = match require_admin_access(state.auth_pool.as_ref(), &auth).await {
        Ok(a) => a,
        Err(r) => return r,
    };

    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "Email is required"})),
        )
            .into_response();
    }

    if body.password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "Password must be at least 8 characters"})),
        )
            .into_response();
    }
    // bcrypt silently truncates at 72 bytes, so a longer passphrase would authenticate on any
    // 72-byte prefix collision. Reject over-long input rather than discarding its entropy.
    if body.password.as_bytes().len() > 72 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "Password must be at most 72 bytes"})),
        )
            .into_response();
    }

    // Hash password with bcrypt
    let hash = match bcrypt::hash(&body.password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(target: "admin", error = %e, "Failed to hash password");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "Failed to hash password"})),
            )
                .into_response();
        }
    };

    let role = body.role.trim().to_lowercase();
    let valid_roles = ["viewer", "analyst", "operator", "admin", "ceo"];
    // Reject unknown roles instead of silently downgrading to "viewer": a botched or typo'd
    // role otherwise creates a user the operator did not intend.
    if !valid_roles.contains(&role.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "role must be one of viewer|analyst|operator|admin|ceo"})),
        )
            .into_response();
    }

    // Rank guard on create (mirrors the update path and ensure_can_manage_target): a
    // non-superadmin may only create a user of strictly lower effective rank. Without this an
    // `admin` could mint a peer-`admin` sock-puppet and defeat the two-person ROE approval control.
    if !auth.is_superadmin
        && crate::rbac::role_rank(&role) >= effective_rank(&auth.role, auth.is_superadmin)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "detail": "Cannot create a user of equal or higher privilege"})),
        )
            .into_response();
    }

    if role == crate::rbac::roles::CEO {
        if let Err(r) = crate::rbac::require_can_assign_ceo(&auth) {
            return r;
        }
    }

    // Only superadmin can create superadmin users
    let is_superadmin = if auth.is_superadmin {
        body.is_superadmin
    } else {
        false
    };

    let mut tx = match crate::db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(target: "admin", error = %e, "begin_tenant_tx failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "Database unavailable"})),
            )
                .into_response();
        }
    };

    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM users WHERE tenant_id = $1 AND lower(trim(email)) = $2 LIMIT 1",
    )
    .bind(auth.tenant_id)
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    if exists.is_some() {
        let _ = tx.rollback().await;
        return (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "detail": "User with this email already exists"})),
        )
            .into_response();
    }

    if role == crate::rbac::roles::CEO {
        if let Err(r) = allow_ceo_role_assignment(&mut tx).await {
            return r;
        }
    }

    let query = r#"
        INSERT INTO users (tenant_id, email, password_hash, role, is_superadmin, is_active)
        VALUES ($1, $2, $3, $4, $5, true)
        RETURNING id
    "#;

    match sqlx::query_scalar::<_, i64>(query)
        .bind(auth.tenant_id)
        .bind(&email)
        .bind(&hash)
        .bind(&role)
        .bind(is_superadmin)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(user_id) => {
            let _ = tx.commit().await;
            tracing::info!(target: "admin", user_id = user_id, email = %email, "User created by admin");
            (
                StatusCode::CREATED,
                Json(json!({
                    "ok": true,
                    "id": user_id,
                    "email": email,
                    "role": role,
                    "is_superadmin": is_superadmin,
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(target: "admin", error = %e, "Failed to create user");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "Failed to create user"})),
            )
                .into_response()
        }
    }
}

/// PATCH /api/admin/users/:id — Update user role/superadmin status
pub async fn api_admin_users_update(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(user_id): Path<i64>,
    Json(body): Json<UpdateUserBody>,
) -> Response {
    let auth = match require_admin_access(state.auth_pool.as_ref(), &auth).await {
        Ok(a) => a,
        Err(r) => return r,
    };

    let mut tx = match crate::db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(target: "admin", error = %e, "begin_tenant_tx failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "Database unavailable"})),
            )
                .into_response();
        }
    };

    let target: Option<(String, bool)> = sqlx::query_as(
        "SELECT role, is_superadmin FROM users WHERE id = $1 AND tenant_id = $2 LIMIT 1",
    )
    .bind(user_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let (target_role, target_is_superadmin) = match target {
        Some(t) => t,
        None => {
            let _ = tx.rollback().await;
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "detail": "User not found"})),
            )
                .into_response();
        }
    };

    // A lower-privileged admin must not be able to modify a peer or a higher-ranked
    // account (e.g. an admin demoting the tenant CEO or another admin).
    if let Err(r) = ensure_can_manage_target(&auth, &target_role, target_is_superadmin) {
        let _ = tx.rollback().await;
        return r;
    }

    // Authorization must be separate from change detection: a non-superadmin who sends
    // `{"is_superadmin": ...}` must be denied (403), not silently reported "No changes" (which
    // happened because the change-detection gate folded `&& auth.is_superadmin` into it).
    if body.is_superadmin.is_some() && !auth.is_superadmin {
        let _ = tx.rollback().await;
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "detail": "Only superadmin can modify superadmin status"})),
        )
            .into_response();
    }

    // Validate role if provided — reject an unknown role (400) instead of collapsing it to None,
    // which is indistinguishable from "field omitted" and silently swallows a typo'd promotion.
    let valid_role: Option<String> = match body.role.as_ref() {
        Some(r) => {
            let role = r.trim().to_lowercase();
            let valid_roles = ["viewer", "analyst", "operator", "admin", "ceo"];
            if valid_roles.contains(&role.as_str()) {
                Some(role)
            } else {
                let _ = tx.rollback().await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"ok": false, "detail": "role must be one of viewer|analyst|operator|admin|ceo"})),
                )
                    .into_response();
            }
        }
        None => None,
    };

    if let Some(ref role) = valid_role {
        if role == crate::rbac::roles::CEO {
            if let Err(r) = crate::rbac::require_can_assign_ceo(&auth) {
                return r;
            }
        }
        // Prevent privilege escalation: a non-superadmin cannot grant a role above
        // their own privilege level.
        if !auth.is_superadmin
            && crate::rbac::role_rank(role) > effective_rank(&auth.role, auth.is_superadmin)
        {
            let _ = tx.rollback().await;
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "ok": false,
                    "detail": "Cannot assign a role above your own privilege level"
                })),
            )
                .into_response();
        }
    }

    // Check if there are any changes to make. Authorization for the superadmin field was
    // already enforced above, so change detection no longer needs the `&& auth.is_superadmin`
    // clause (which is what made the denial branch unreachable).
    let has_role_change = valid_role.is_some();
    let has_superadmin_change = body.is_superadmin.is_some();

    if !has_role_change && !has_superadmin_change {
        return (
            StatusCode::OK,
            Json(json!({"ok": true, "detail": "No changes"})),
        )
            .into_response();
    }

    if let Some(ref role) = valid_role {
        if role == crate::rbac::roles::CEO {
            if let Err(r) = allow_ceo_role_assignment(&mut tx).await {
                return r;
            }
        }
    }

    // Execute update with proper parameter binding
    let update_sql = if let Some(ref role) = valid_role {
        if let Some(is_sa) = body.is_superadmin {
            if auth.is_superadmin {
                sqlx::query(
                    "UPDATE users SET role = $1, is_superadmin = $2 WHERE id = $3 AND tenant_id = $4",
                )
                .bind(role)
                .bind(is_sa)
                .bind(user_id)
                .bind(auth.tenant_id)
                .execute(&mut *tx)
                .await
            } else {
                sqlx::query("UPDATE users SET role = $1 WHERE id = $2 AND tenant_id = $3")
                    .bind(role)
                    .bind(user_id)
                    .bind(auth.tenant_id)
                    .execute(&mut *tx)
                    .await
            }
        } else {
            sqlx::query("UPDATE users SET role = $1 WHERE id = $2 AND tenant_id = $3")
                .bind(role)
                .bind(user_id)
                .bind(auth.tenant_id)
                .execute(&mut *tx)
                .await
        }
    } else if let Some(is_sa) = body.is_superadmin {
        if auth.is_superadmin {
            sqlx::query("UPDATE users SET is_superadmin = $1 WHERE id = $2 AND tenant_id = $3")
                .bind(is_sa)
                .bind(user_id)
                .bind(auth.tenant_id)
                .execute(&mut *tx)
                .await
        } else {
            return (
                StatusCode::FORBIDDEN,
                Json(
                    json!({"ok": false, "detail": "Only superadmin can modify superadmin status"}),
                ),
            )
                .into_response();
        }
    } else {
        return (
            StatusCode::OK,
            Json(json!({"ok": true, "detail": "No changes"})),
        )
            .into_response();
    };

    match update_sql {
        Ok(_) => {
            if let Err(e) = tx.commit().await {
                tracing::error!(target: "admin", error = %e, "Failed to commit user update");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"ok": false, "detail": "Failed to update user"})),
                )
                    .into_response();
            }
            tracing::info!(target: "admin", user_id = user_id, "User updated by admin");
            (StatusCode::OK, Json(json!({"ok": true}))).into_response()
        }
        Err(e) => {
            tracing::error!(target: "admin", error = %e, "Failed to update user");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "Failed to update user"})),
            )
                .into_response()
        }
    }
}

/// POST /api/admin/users/:id/deactivate — Deactivate a user
pub async fn api_admin_users_deactivate(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
    Path(user_id): Path<i64>,
) -> Response {
    let auth = match require_admin_access(state.auth_pool.as_ref(), &auth).await {
        Ok(a) => a,
        Err(r) => return r,
    };

    // Don't allow deactivating yourself
    if user_id == auth.user_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "Cannot deactivate yourself"})),
        )
            .into_response();
    }

    let mut tx = match crate::db::begin_tenant_tx(state.app_pool.as_ref(), auth.tenant_id).await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(target: "admin", error = %e, "begin_tenant_tx failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"ok": false, "detail": "Database unavailable"})),
            )
                .into_response();
        }
    };

    let target: Option<(String, bool)> = sqlx::query_as(
        "SELECT role, is_superadmin FROM users WHERE id = $1 AND tenant_id = $2 LIMIT 1",
    )
    .bind(user_id)
    .bind(auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();

    let (target_role, target_is_superadmin) = match target {
        Some(t) => t,
        None => {
            let _ = tx.rollback().await;
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "detail": "User not found"})),
            )
                .into_response();
        }
    };

    // A lower-privileged admin must not be able to deactivate a peer or higher account.
    if let Err(r) = ensure_can_manage_target(&auth, &target_role, target_is_superadmin) {
        let _ = tx.rollback().await;
        return r;
    }

    let result = sqlx::query("UPDATE users SET is_active = false WHERE id = $1 AND tenant_id = $2")
        .bind(user_id)
        .bind(auth.tenant_id)
        .execute(&mut *tx)
        .await;

    match result {
        Ok(result) => {
            let _ = tx.commit().await;
            if result.rows_affected() > 0 {
                tracing::info!(target: "admin", user_id = user_id, "User deactivated by admin");
                (StatusCode::OK, Json(json!({"ok": true}))).into_response()
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(json!({"ok": false, "detail": "User not found"})),
                )
                    .into_response()
            }
        }
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::error!(target: "admin", error = %e, "Failed to deactivate user");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "Failed to deactivate user"})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_role_is_viewer() {
        assert_eq!(default_role(), "viewer");
    }

    #[test]
    fn create_user_body_applies_defaults() {
        let b: CreateUserBody = serde_json::from_value(json!({
            "email": "x@y.com",
            "password": "password123"
        }))
        .unwrap();
        assert_eq!(b.email, "x@y.com");
        assert_eq!(b.role, "viewer"); // default_role
        assert!(!b.is_superadmin); // default false
    }

    #[test]
    fn create_user_body_explicit_fields() {
        let b: CreateUserBody = serde_json::from_value(json!({
            "email": "a@b.com",
            "password": "pw",
            "role": "admin",
            "is_superadmin": true
        }))
        .unwrap();
        assert_eq!(b.role, "admin");
        assert!(b.is_superadmin);
    }

    #[test]
    fn update_user_body_all_optional() {
        let empty: UpdateUserBody = serde_json::from_value(json!({})).unwrap();
        assert!(empty.role.is_none());
        assert!(empty.is_superadmin.is_none());

        let some: UpdateUserBody = serde_json::from_value(json!({"role": "ceo"})).unwrap();
        assert_eq!(some.role.as_deref(), Some("ceo"));
        assert!(some.is_superadmin.is_none());
    }

    #[test]
    fn user_info_serializes_expected_fields() {
        let u = UserInfo {
            id: 7,
            email: "u@e.com".to_string(),
            role: "analyst".to_string(),
            is_superadmin: false,
            is_active: true,
            created_at: None,
        };
        let v = serde_json::to_value(&u).unwrap();
        assert_eq!(v["id"], json!(7));
        assert_eq!(v["email"], json!("u@e.com"));
        assert_eq!(v["role"], json!("analyst"));
        assert_eq!(v["is_superadmin"], json!(false));
        assert_eq!(v["is_active"], json!(true));
        assert_eq!(v["created_at"], serde_json::Value::Null);
    }
}
