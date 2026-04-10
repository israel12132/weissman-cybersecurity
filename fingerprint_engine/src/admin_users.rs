// Admin User Management APIs for CEO/Superadmin only
// Routes: GET/POST /api/admin/users, PATCH /api/admin/users/:id, POST /api/admin/users/:id/deactivate

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
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

/// Check if the caller is superadmin or CEO
fn require_admin_access(auth: &AuthContext) -> Result<(), Response> {
    if auth.is_superadmin || auth.role.to_lowercase() == "ceo" || auth.role.to_lowercase() == "admin" {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "detail": "Superadmin or CEO role required"})),
        )
            .into_response())
    }
}

/// GET /api/admin/users — List all users in the tenant
pub async fn api_admin_users_list(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthContext>,
) -> Response {
    if let Err(r) = require_admin_access(&auth) {
        return r;
    }

    let pool = state.auth_pool.as_ref();
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
        .fetch_all(pool)
        .await
    {
        Ok(rows) => {
            let users: Vec<UserInfo> = rows
                .into_iter()
                .map(|r| UserInfo {
                    id: r.try_get::<i64, _>("id").unwrap_or(0),
                    email: r.try_get::<String, _>("email").unwrap_or_default(),
                    role: r.try_get::<String, _>("role").unwrap_or_else(|_| "viewer".to_string()),
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
    if let Err(r) = require_admin_access(&auth) {
        return r;
    }

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
    let role = if valid_roles.contains(&role.as_str()) {
        role
    } else {
        "viewer".to_string()
    };

    // Only superadmin can create superadmin users
    let is_superadmin = if auth.is_superadmin {
        body.is_superadmin
    } else {
        false
    };

    let pool = state.auth_pool.as_ref();

    // Check if user already exists
    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM users WHERE tenant_id = $1 AND lower(trim(email)) = $2 LIMIT 1",
    )
    .bind(auth.tenant_id)
    .bind(&email)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    if exists.is_some() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"ok": false, "detail": "User with this email already exists"})),
        )
            .into_response();
    }

    // Insert user
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
        .fetch_one(pool)
        .await
    {
        Ok(user_id) => {
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
    if let Err(r) = require_admin_access(&auth) {
        return r;
    }

    let pool = state.auth_pool.as_ref();

    // Verify user belongs to this tenant
    let exists: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM users WHERE id = $1 AND tenant_id = $2 LIMIT 1",
    )
    .bind(user_id)
    .bind(auth.tenant_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    if exists.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "detail": "User not found"})),
        )
            .into_response();
    }

    // Build update query dynamically
    let mut updates = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(ref role) = body.role {
        let role = role.trim().to_lowercase();
        let valid_roles = ["viewer", "analyst", "operator", "admin", "ceo"];
        if valid_roles.contains(&role.as_str()) {
            updates.push(format!("role = ${}", params.len() + 1));
            params.push(role);
        }
    }

    // Only superadmin can grant superadmin
    if let Some(is_superadmin) = body.is_superadmin {
        if auth.is_superadmin {
            updates.push(format!("is_superadmin = ${}", params.len() + 1));
            params.push(is_superadmin.to_string());
        }
    }

    if updates.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({"ok": true, "detail": "No changes"})),
        )
            .into_response();
    }

    // Execute update with proper parameter binding
    let update_sql = if let Some(ref role) = body.role {
        if let Some(is_sa) = body.is_superadmin {
            if auth.is_superadmin {
                sqlx::query(
                    "UPDATE users SET role = $1, is_superadmin = $2 WHERE id = $3 AND tenant_id = $4",
                )
                .bind(role.trim().to_lowercase())
                .bind(is_sa)
                .bind(user_id)
                .bind(auth.tenant_id)
                .execute(pool)
                .await
            } else {
                sqlx::query("UPDATE users SET role = $1 WHERE id = $2 AND tenant_id = $3")
                    .bind(role.trim().to_lowercase())
                    .bind(user_id)
                    .bind(auth.tenant_id)
                    .execute(pool)
                    .await
            }
        } else {
            sqlx::query("UPDATE users SET role = $1 WHERE id = $2 AND tenant_id = $3")
                .bind(role.trim().to_lowercase())
                .bind(user_id)
                .bind(auth.tenant_id)
                .execute(pool)
                .await
        }
    } else if let Some(is_sa) = body.is_superadmin {
        if auth.is_superadmin {
            sqlx::query("UPDATE users SET is_superadmin = $1 WHERE id = $2 AND tenant_id = $3")
                .bind(is_sa)
                .bind(user_id)
                .bind(auth.tenant_id)
                .execute(pool)
                .await
        } else {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"ok": false, "detail": "Only superadmin can modify superadmin status"})),
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
    if let Err(r) = require_admin_access(&auth) {
        return r;
    }

    // Don't allow deactivating yourself
    if user_id == auth.user_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "detail": "Cannot deactivate yourself"})),
        )
            .into_response();
    }

    let pool = state.auth_pool.as_ref();

    match sqlx::query("UPDATE users SET is_active = false WHERE id = $1 AND tenant_id = $2")
        .bind(user_id)
        .bind(auth.tenant_id)
        .execute(pool)
        .await
    {
        Ok(result) => {
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
            tracing::error!(target: "admin", error = %e, "Failed to deactivate user");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "detail": "Failed to deactivate user"})),
            )
                .into_response()
        }
    }
}
