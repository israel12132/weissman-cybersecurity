//! Role-Based Access Control gates for HTTP handlers.
//!
//! Wire by calling `require_role` / `require_any_role` at the top of an `axum` handler. Each gate
//! pulls the live `AuthContext` injected by the auth middleware and returns a `403 Forbidden`
//! response (with `application/json` body) on denial. Superadmins always pass.

use crate::auth_jwt::AuthContext;
use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
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
    /// Customer-portal identity. Isolated to `assigned_client_id`.
    pub const CLIENT: &str = "client";
}

#[must_use]
pub fn role_rank(role: &str) -> u8 {
    match role.trim().to_ascii_lowercase().as_str() {
        roles::CEO => 5,
        roles::ADMIN => 4,
        // Portal users operate engines on their own customer (operator-equivalent
        // writes) but client-lifecycle and staff-only routes are gated separately.
        roles::OPERATOR | roles::CLIENT => 3,
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

/// Reject anything below operator (operator, admin, ceo, or superadmin).
#[inline]
pub fn require_operator(auth: &AuthContext) -> Result<(), Response> {
    require_role(auth, roles::OPERATOR)
}

/// Reject anything below analyst (analyst, operator, admin, ceo, or superadmin).
#[inline]
pub fn require_analyst(auth: &AuthContext) -> Result<(), Response> {
    require_role(auth, roles::ANALYST)
}

/// Only CEO or superadmin may grant the CEO role to another user.
#[inline]
#[must_use]
pub fn can_assign_ceo_role(auth: &AuthContext) -> bool {
    auth.is_superadmin || auth.role.eq_ignore_ascii_case(roles::CEO)
}

/// HTTP gate for handlers that assign `role = ceo`.
pub fn require_can_assign_ceo(auth: &AuthContext) -> Result<(), Response> {
    if can_assign_ceo_role(auth) {
        return Ok(());
    }
    Err(forbidden(
        auth,
        "Only CEO or superadmin may assign the CEO role",
    ))
}

/// Endpoint-agent WebSocket / fleet APIs — only JWTs with `role=agent` (not human RBAC ranks).
#[inline]
pub fn require_agent(auth: &AuthContext) -> Result<(), Response> {
    if auth.role.eq_ignore_ascii_case("agent") {
        return Ok(());
    }
    Err(forbidden(auth, "agent JWT required"))
}

/// Self-service mutation paths any authenticated user (incl. `viewer`) may call.
const SELF_SERVICE_PREFIXES: &[&str] = &[
    "/api/logout",
    "/api/auth/logout",
    "/api/auth/refresh",
    "/api/auth/me",
    "/api/auth/mfa",
    "/api/auth/change-password",
    "/api/auth/password",
    "/api/account",
    "/api/me",
    "/api/ask",
    "/api/telemetry",
    "/api/preferences",
];

fn path_in(prefixes: &[&str], path: &str) -> bool {
    prefixes
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")))
}

/// Minimum role required to perform a **mutating** request on `path`.
/// `None` ⇒ any authenticated user (self-service). This is a coarse, central
/// safety net layered *above* the per-handler `require_operator/admin` checks —
/// it guarantees no mutating endpoint is reachable by a read-only `viewer`.
#[must_use]
pub fn required_min_role(method: &Method, path: &str) -> Option<&'static str> {
    if path_in(SELF_SERVICE_PREFIXES, path) {
        return None;
    }
    if path.starts_with("/api/ceo") {
        return Some(roles::CEO);
    }
    if path.starts_with("/api/admin") {
        return Some(roles::ADMIN);
    }
    if path.starts_with("/api/clients") {
        // Create (POST /api/clients) and delete are owner-only (CEO/superadmin).
        // Nested mutations (scan, config, update) stay operator+ so staff and
        // in-scope portal users can still run engines on a customer they can see.
        if *method == Method::DELETE {
            return Some(roles::CEO);
        }
        if *method == Method::POST && (path == "/api/clients" || path == "/api/clients/") {
            return Some(roles::CEO);
        }
        return Some(roles::OPERATOR);
    }
    // Tuning outbound traffic-shaping (stealth pacing) is an operational lever:
    // operator+ only, never a read-only viewer or triage analyst.
    if path.starts_with("/api/stealth") {
        return Some(roles::OPERATOR);
    }
    // Baseline: every other write requires at least analyst (blocks read-only viewers).
    Some(roles::ANALYST)
}

/// Central RBAC middleware. Runs after `auth_guard` (so `AuthContext` is present
/// for authenticated requests). Reads pass through (gated by auth + tenant RLS);
/// mutations are checked against [`required_min_role`]. Unauthenticated allowlisted
/// paths (login/signup/etc.) have no `AuthContext` and are not RBAC-gated here.
pub async fn mutation_rbac_middleware(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    if matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    let Some(auth) = req.extensions().get::<AuthContext>().cloned() else {
        // A mutating /api request reached the RBAC layer with no AuthContext. For the
        // declared public POSTs (signup/webhooks/refresh/…) this is expected; but any
        // *protected* path here — or a spike above the public-POST baseline — means
        // `auth_guard` did not run, a layer-ordering regression that would silently open
        // every mutation. Emit fail-closed telemetry so it is observable, without changing
        // behaviour. Login/MFA-verify are excluded as the highest-frequency expected case.
        let path = req.uri().path();
        if !crate::http::is_account_lockout_post(&method, path) {
            metrics::counter!("weissman_rbac_missing_authcontext_total").increment(1);
            tracing::warn!(
                target: "rbac",
                method = %method,
                path = %path,
                "mutating request reached RBAC with no AuthContext (expected only for public POSTs; investigate if this is a protected route)"
            );
        }
        return next.run(req).await;
    };
    // Agent JWTs use a separate role space; their routes enforce `require_agent`.
    if auth.role.eq_ignore_ascii_case("agent") {
        return next.run(req).await;
    }
    let path = req.uri().path().to_string();
    if let Some(min_role) = required_min_role(&method, &path) {
        if let Err(resp) = require_role(&auth, min_role) {
            return resp;
        }
    }
    next.run(req).await
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
            jti: None,
            bind_ip: None,
            bind_tls_fp: None,
            assigned_client_id: None,
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
        assert!(require_operator(&ctx("operator", false)).is_ok());
        assert!(require_operator(&ctx("analyst", false)).is_err());
        assert!(require_operator(&ctx("client", false)).is_ok());
        assert_eq!(role_rank("client"), role_rank("operator"));
    }

    #[test]
    fn any_role() {
        assert!(require_any_role(&ctx("operator", false), &["operator", "admin"]).is_ok());
        assert!(require_any_role(&ctx("viewer", false), &["operator", "admin"]).is_err());
    }

    #[test]
    fn agent_role() {
        assert!(require_agent(&ctx("agent", false)).is_ok());
        assert!(require_agent(&ctx("admin", false)).is_err());
        assert!(require_agent(&ctx("agent", true)).is_ok());
    }

    #[test]
    fn mutation_matrix_roles() {
        // Self-service is open to any authenticated user.
        assert_eq!(required_min_role(&Method::POST, "/api/auth/refresh"), None);
        assert_eq!(required_min_role(&Method::POST, "/api/ask"), None);
        assert_eq!(required_min_role(&Method::POST, "/api/logout"), None);
        // Privileged prefixes.
        assert_eq!(
            required_min_role(&Method::POST, "/api/ceo/x"),
            Some(roles::CEO)
        );
        assert_eq!(
            required_min_role(&Method::PUT, "/api/ceo/platform-keys"),
            Some(roles::CEO)
        );
        assert_eq!(
            required_min_role(&Method::DELETE, "/api/ceo/platform-keys/NVD_API_KEY"),
            Some(roles::CEO)
        );
        assert_eq!(
            required_min_role(&Method::POST, "/api/admin/users"),
            Some(roles::ADMIN)
        );
        // Client create = owner (ceo+); nested client mutations = operator+; delete = owner.
        assert_eq!(
            required_min_role(&Method::POST, "/api/clients"),
            Some(roles::CEO)
        );
        assert_eq!(
            required_min_role(&Method::DELETE, "/api/clients/5"),
            Some(roles::CEO)
        );
        assert_eq!(
            required_min_role(&Method::POST, "/api/clients/5/scan/run-all"),
            Some(roles::OPERATOR)
        );
        // Stealth traffic-shaping tuning is operator+.
        assert_eq!(
            required_min_role(&Method::POST, "/api/stealth/config"),
            Some(roles::OPERATOR)
        );
        // Everything else that mutates requires at least analyst (viewer blocked).
        assert_eq!(
            required_min_role(&Method::PATCH, "/api/findings/1/status"),
            Some(roles::ANALYST)
        );
    }

    #[test]
    fn viewer_blocked_from_generic_write_but_analyst_allowed() {
        let min = required_min_role(&Method::POST, "/api/playbooks").unwrap();
        assert!(require_role(&ctx("viewer", false), min).is_err());
        assert!(require_role(&ctx("analyst", false), min).is_ok());
    }

    #[test]
    fn ceo_assignment_gate() {
        assert!(can_assign_ceo_role(&ctx("ceo", false)));
        assert!(can_assign_ceo_role(&ctx("admin", true)));
        assert!(!can_assign_ceo_role(&ctx("admin", false)));
        assert!(!can_assign_ceo_role(&ctx("operator", false)));
        assert!(require_can_assign_ceo(&ctx("ceo", false)).is_ok());
        assert!(require_can_assign_ceo(&ctx("admin", false)).is_err());
    }
}
