//! Role-Based Access Control gates for HTTP handlers.
//!
//! Wire by calling `require_role` / `require_any_role` at the top of an `axum` handler. Each gate
//! pulls the live `AuthContext` injected by the auth middleware and returns a `403 Forbidden`
//! response (with `application/json` body) on denial. Superadmins always pass.

use crate::auth_jwt::AuthContext;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Canonical role names. Anything else is treated as "viewer".
pub mod roles {
    pub const VIEWER: &str = "viewer";
    pub const ANALYST: &str = "analyst";
    pub const OPERATOR: &str = "operator";
    pub const ADMIN: &str = "admin";
    pub const CEO: &str = "ceo";
}

#[must_use]
pub fn role_rank(role: &str) -> u8 {
    match role.trim().to_ascii_lowercase().as_str() {
        roles::CEO => 5,
        roles::ADMIN => 4,
        roles::OPERATOR => 3,
        roles::ANALYST => 2,
        roles::VIEWER => 1,
        _ => 0,
    }
}

/// Returns Err(Response) on denial; Ok(()) on success. Pattern is `let _ = require_role(&auth, "admin")?;`.
pub fn require_role(auth: &AuthContext, min_role: &str) -> Result<(), Response> {
    if auth.is_superadmin {
        return Ok(());
    }
    if role_rank(&auth.role) >= role_rank(min_role) {
        return Ok(());
    }
    Err(forbidden(
        auth,
        &format!("role '{}' required (have '{}')", min_role, auth.role),
    ))
}

/// Allow if the authenticated role matches any of the listed roles (case-insensitive).
pub fn require_any_role(auth: &AuthContext, allowed: &[&str]) -> Result<(), Response> {
    if auth.is_superadmin {
        return Ok(());
    }
    let lr = auth.role.to_ascii_lowercase();
    if allowed.iter().any(|r| r.eq_ignore_ascii_case(&lr)) {
        return Ok(());
    }
    Err(forbidden(
        auth,
        &format!("requires one of {:?} (have '{}')", allowed, auth.role),
    ))
}

/// Reject anything below admin (admin, ceo, or superadmin).
#[inline]
pub fn require_admin(auth: &AuthContext) -> Result<(), Response> {
    require_role(auth, roles::ADMIN)
}

/// Reject anything below analyst (analyst, operator, admin, ceo, or superadmin).
#[inline]
pub fn require_analyst(auth: &AuthContext) -> Result<(), Response> {
    require_role(auth, roles::ANALYST)
}

fn forbidden(auth: &AuthContext, detail: &str) -> Response {
    tracing::warn!(
        target: "rbac",
        user_id = auth.user_id,
        tenant_id = auth.tenant_id,
        role = %auth.role,
        is_superadmin = auth.is_superadmin,
        denial_reason = %detail,
        "RBAC denial"
    );
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "ok": false,
            "detail": detail,
            "error_code": "rbac_denied",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(role: &str, superadmin: bool) -> AuthContext {
        AuthContext {
            user_id: 1,
            tenant_id: 1,
            role: role.to_string(),
            is_superadmin: superadmin,
            agent_id: None,
        }
    }

    #[test]
    fn superadmin_always_passes() {
        assert!(require_role(&ctx("viewer", true), "ceo").is_ok());
    }

    #[test]
    fn rank_ordering() {
        assert!(require_role(&ctx("admin", false), "analyst").is_ok());
        assert!(require_role(&ctx("viewer", false), "operator").is_err());
    }

    #[test]
    fn any_role() {
        assert!(require_any_role(&ctx("operator", false), &["operator", "admin"]).is_ok());
        assert!(require_any_role(&ctx("viewer", false), &["operator", "admin"]).is_err());
    }
}
