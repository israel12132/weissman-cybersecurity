//! Customer-client isolation policy (MSSP).
//!
//! Two planes live inside one tenant:
//!
//! * **Owner** — `is_superadmin` or `role=ceo`. Creates and deletes clients.
//! * **Staff** — unscoped human users. See every client; operate scans; cannot
//!   delete clients and cannot create them.
//! * **Client portal** — `role=client` with `assigned_client_id`. Login does not
//!   ask which customer they are; the account is bound at provisioning. Every
//!   API/WS/DB path is forced onto that client.
//!
//! Enforcement is layered: JWT `cid` claim, live DB revalidation, HTTP
//! middleware (path/query/body), Postgres RLS via `app.current_client_id`.

use crate::auth_jwt::AuthContext;
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// Canonical portal-user role. Ranked with operator for in-scope writes so a
/// customer can run engines against *their* assets; isolation middleware and
/// RLS still prevent cross-client access and client lifecycle mutations.
pub const CLIENT_ROLE: &str = "client";

#[inline]
#[must_use]
pub fn is_platform_owner(auth: &AuthContext) -> bool {
    auth.is_superadmin || auth.role.eq_ignore_ascii_case(crate::rbac::roles::CEO)
}

#[inline]
#[must_use]
pub fn is_client_role(role: &str) -> bool {
    role.trim().eq_ignore_ascii_case(CLIENT_ROLE)
}

#[inline]
#[must_use]
pub fn is_client_scoped(auth: &AuthContext) -> bool {
    auth.agent_id.is_none()
        && (auth.assigned_client_id.is_some() || is_client_role(&auth.role))
}

#[inline]
#[must_use]
pub fn is_staff(auth: &AuthContext) -> bool {
    auth.agent_id.is_none() && !is_client_scoped(auth)
}

#[inline]
#[must_use]
pub fn can_create_clients(auth: &AuthContext) -> bool {
    is_platform_owner(auth) && !is_client_scoped(auth)
}

#[inline]
#[must_use]
pub fn can_delete_clients(auth: &AuthContext) -> bool {
    is_platform_owner(auth) && !is_client_scoped(auth)
}

/// Session capabilities returned by `GET /api/auth/me` so the UI cannot drift
/// from the server policy.
#[must_use]
pub fn capabilities_json(auth: &AuthContext) -> Value {
    json!({
        "assigned_client_id": auth.assigned_client_id,
        "is_owner": is_platform_owner(auth),
        "is_staff": is_staff(auth),
        "is_client_user": is_client_scoped(auth),
        "can_create_clients": can_create_clients(auth),
        "can_delete_clients": can_delete_clients(auth),
    })
}

pub fn require_owner(auth: &AuthContext) -> Result<(), Response> {
    if can_create_clients(auth) {
        return Ok(());
    }
    Err(denied(
        auth,
        "Only the platform owner can perform this client-lifecycle action",
        "owner_required",
    ))
}

pub fn require_can_delete_client(auth: &AuthContext) -> Result<(), Response> {
    if can_delete_clients(auth) {
        return Ok(());
    }
    Err(denied(
        auth,
        "Only the platform owner can delete a client",
        "owner_required",
    ))
}

/// Parse a client id from `/api/clients/{id}` or `/api/financial-risk/{id}`.
#[must_use]
pub fn extract_path_client_id(path: &str) -> Option<i64> {
    for prefix in ["/api/clients/", "/api/financial-risk/"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            let token = rest.split('/').next().unwrap_or("");
            if token.is_empty() {
                return None;
            }
            return token.parse::<i64>().ok().filter(|id| *id > 0);
        }
    }
    None
}

/// Append `client_id` to a query string when a portal user omitted it.
#[must_use]
pub fn inject_query_client_id(query: Option<&str>, cid: i64) -> Option<String> {
    if cid <= 0 {
        return None;
    }
    if extract_query_client_id(query).is_some() {
        return None;
    }
    Some(match query {
        None | Some("") => format!("client_id={cid}"),
        Some(q) => format!("{q}&client_id={cid}"),
    })
}

#[must_use]
pub fn extract_query_client_id(query: Option<&str>) -> Option<i64> {
    let q = query?;
    for pair in q.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next()?.trim();
        if key != "client_id" && key != "clientId" {
            continue;
        }
        let raw = parts.next().unwrap_or("").trim();
        if raw.is_empty() {
            continue;
        }
        if let Ok(id) = raw.parse::<i64>() {
            if id > 0 {
                return Some(id);
            }
        }
    }
    None
}

#[must_use]
pub fn json_client_id(value: &Value) -> Option<i64> {
    fn as_id(v: &Value) -> Option<i64> {
        v.as_i64()
            .or_else(|| v.as_u64().and_then(|n| i64::try_from(n).ok()))
            .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
            .filter(|id| *id > 0)
    }
    match value {
        Value::Object(map) => map
            .get("client_id")
            .or_else(|| map.get("clientId"))
            .and_then(as_id),
        _ => None,
    }
}

/// Bind a requested client id to the caller's scope.
///
/// * Staff/owner: the requested id is unchanged (including `None` = all).
/// * Portal user: missing id is filled with their bound client; a different
///   id is rejected.
pub fn bind_requested_client(
    auth: &AuthContext,
    requested: Option<i64>,
) -> Result<Option<i64>, Response> {
    match auth.assigned_client_id {
        None => {
            if is_client_role(&auth.role) {
                return Err(denied(
                    auth,
                    "Client portal account is missing a bound customer",
                    "client_scope_unbound",
                ));
            }
            Ok(requested)
        }
        Some(cid) => match requested {
            None => Ok(Some(cid)),
            Some(req) if req == cid => Ok(Some(cid)),
            Some(_) => Err(not_found(auth)),
        },
    }
}

/// True when a job/telemetry payload is visible to this caller.
#[must_use]
pub fn payload_visible_to(auth: &AuthContext, payload: &Value) -> bool {
    let Some(cid) = auth.assigned_client_id else {
        return !is_client_role(&auth.role);
    };
    json_client_id(payload) == Some(cid)
}

/// Inject `client_id` into a JSON object for portal users (engines auto-aim).
/// Returns `Err` when the body already names a different client.
pub fn force_json_client_id(auth: &AuthContext, body: &mut Value) -> Result<(), Response> {
    let Some(cid) = auth.assigned_client_id else {
        return Ok(());
    };
    match body {
        Value::Object(map) => {
            if let Some(existing) = json_client_id(&Value::Object(map.clone())) {
                if existing != cid {
                    return Err(not_found(auth));
                }
            }
            map.insert("client_id".to_string(), json!(cid));
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Paths a portal user may always call (session + self-service).
#[must_use]
pub fn is_portal_self_service(method: &Method, path: &str) -> bool {
    if path == "/api/auth/me" || path == "/api/logout" || path == "/api/auth/logout" {
        return true;
    }
    if path.starts_with("/api/auth/") {
        return true;
    }
    if path.starts_with("/api/account") || path.starts_with("/api/me") {
        return true;
    }
    if path.starts_with("/api/preferences") {
        return true;
    }
    if matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
        && (path == "/api/health" || path.starts_with("/api/health/"))
    {
        return true;
    }
    false
}

/// Privileged prefixes a portal user must never reach, even via GET.
#[must_use]
pub fn is_staff_only_path(path: &str) -> bool {
    path.starts_with("/api/admin")
        || path.starts_with("/api/ceo")
        || path.starts_with("/api/system-config")
        || path.starts_with("/api/sso")
        || path.starts_with("/api/billing")
        || path.starts_with("/api/audit")
}

/// Client lifecycle mutations: POST `/api/clients` (create) and DELETE `/api/clients/:id`.
#[must_use]
pub fn is_client_create_path(method: &Method, path: &str) -> bool {
    *method == Method::POST && (path == "/api/clients" || path == "/api/clients/")
}

#[must_use]
pub fn is_client_delete_path(method: &Method, path: &str) -> bool {
    *method == Method::DELETE
        && path
            .strip_prefix("/api/clients/")
            .is_some_and(|rest| rest.split('/').next().is_some_and(|t| t.parse::<i64>().is_ok())
                && !rest.contains('/'))
}

fn denied(auth: &AuthContext, detail: &str, code: &str) -> Response {
    tracing::warn!(
        target: "client_isolation",
        user_id = auth.user_id,
        tenant_id = auth.tenant_id,
        role = %auth.role,
        assigned_client_id = ?auth.assigned_client_id,
        code = code,
        "client isolation denial"
    );
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "ok": false,
            "detail": detail,
            "error_code": code,
        })),
    )
        .into_response()
}

fn not_found(auth: &AuthContext) -> Response {
    tracing::warn!(
        target: "client_isolation",
        user_id = auth.user_id,
        tenant_id = auth.tenant_id,
        assigned_client_id = ?auth.assigned_client_id,
        "client isolation: cross-client reference hidden"
    );
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "ok": false,
            "detail": "Not found",
            "error_code": "not_found",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(role: &str, superadmin: bool, cid: Option<i64>) -> AuthContext {
        AuthContext {
            user_id: 1,
            tenant_id: 1,
            role: role.to_string(),
            is_superadmin: superadmin,
            agent_id: None,
            jti: None,
            bind_ip: None,
            bind_tls_fp: None,
            assigned_client_id: cid,
        }
    }

    #[test]
    fn owner_is_ceo_or_superadmin() {
        assert!(is_platform_owner(&ctx("ceo", false, None)));
        assert!(is_platform_owner(&ctx("viewer", true, None)));
        assert!(!is_platform_owner(&ctx("admin", false, None)));
        assert!(!is_platform_owner(&ctx("operator", false, None)));
        assert!(!is_platform_owner(&ctx("client", false, Some(9))));
    }

    #[test]
    fn only_owner_creates_and_deletes() {
        assert!(can_create_clients(&ctx("ceo", false, None)));
        assert!(can_delete_clients(&ctx("admin", true, None)));
        assert!(!can_create_clients(&ctx("admin", false, None)));
        assert!(!can_delete_clients(&ctx("admin", false, None)));
        assert!(!can_create_clients(&ctx("operator", false, None)));
        assert!(!can_delete_clients(&ctx("client", false, Some(3))));
    }

    #[test]
    fn portal_user_is_scoped() {
        assert!(is_client_scoped(&ctx("client", false, Some(4))));
        assert!(is_client_scoped(&ctx("viewer", false, Some(4))));
        assert!(!is_client_scoped(&ctx("analyst", false, None)));
        assert!(is_staff(&ctx("operator", false, None)));
        assert!(!is_staff(&ctx("client", false, Some(1))));
    }

    #[test]
    fn path_client_id_extraction() {
        assert_eq!(extract_path_client_id("/api/clients/42"), Some(42));
        assert_eq!(extract_path_client_id("/api/clients/42/findings"), Some(42));
        assert_eq!(extract_path_client_id("/api/financial-risk/7"), Some(7));
        assert_eq!(extract_path_client_id("/api/clients"), None);
        assert_eq!(extract_path_client_id("/api/findings"), None);
        assert_eq!(extract_path_client_id("/api/clients/not-a-number"), None);
    }

    #[test]
    fn query_client_id_extraction() {
        assert_eq!(
            extract_query_client_id(Some("limit=10&client_id=12")),
            Some(12)
        );
        assert_eq!(extract_query_client_id(Some("foo=1")), None);
        assert_eq!(extract_query_client_id(None), None);
    }

    #[test]
    fn bind_fills_and_rejects() {
        let portal = ctx("client", false, Some(5));
        assert_eq!(bind_requested_client(&portal, None).unwrap(), Some(5));
        assert_eq!(bind_requested_client(&portal, Some(5)).unwrap(), Some(5));
        assert!(bind_requested_client(&portal, Some(9)).is_err());

        let staff = ctx("operator", false, None);
        assert_eq!(bind_requested_client(&staff, None).unwrap(), None);
        assert_eq!(bind_requested_client(&staff, Some(9)).unwrap(), Some(9));
    }

    #[test]
    fn json_force_injects_client_id() {
        let portal = ctx("client", false, Some(8));
        let mut body = json!({"engine": "asm", "target": "https://ex.test"});
        force_json_client_id(&portal, &mut body).unwrap();
        assert_eq!(body["client_id"], json!(8));

        let mut bad = json!({"client_id": 99});
        assert!(force_json_client_id(&portal, &mut bad).is_err());
    }

    #[test]
    fn create_and_delete_path_detectors() {
        assert!(is_client_create_path(&Method::POST, "/api/clients"));
        assert!(!is_client_create_path(&Method::POST, "/api/clients/1/scan/run-all"));
        assert!(is_client_delete_path(&Method::DELETE, "/api/clients/12"));
        assert!(!is_client_delete_path(&Method::DELETE, "/api/clients/12/config"));
        assert!(!is_client_delete_path(&Method::POST, "/api/clients/12"));
    }

    #[test]
    fn staff_only_prefixes_include_tenant_admin_surfaces() {
        assert!(is_staff_only_path("/api/admin/users"));
        assert!(is_staff_only_path("/api/sso/idps"));
        assert!(is_staff_only_path("/api/billing/usage"));
        assert!(is_staff_only_path("/api/audit-logs"));
        assert!(!is_staff_only_path("/api/clients"));
        assert!(!is_staff_only_path("/api/findings"));
    }

    #[test]
    fn inject_query_fills_missing_client_id() {
        assert_eq!(
            inject_query_client_id(None, 9).as_deref(),
            Some("client_id=9")
        );
        assert_eq!(
            inject_query_client_id(Some("limit=10"), 9).as_deref(),
            Some("limit=10&client_id=9")
        );
        assert_eq!(inject_query_client_id(Some("client_id=9"), 9), None);
    }

    #[test]
    fn payload_visibility() {
        let portal = ctx("client", false, Some(3));
        assert!(payload_visible_to(&portal, &json!({"client_id": 3})));
        assert!(payload_visible_to(&portal, &json!({"client_id": "3"})));
        assert!(!payload_visible_to(&portal, &json!({"client_id": 4})));
        assert!(!payload_visible_to(&portal, &json!({"engine": "asm"})));
        let staff = ctx("analyst", false, None);
        assert!(payload_visible_to(&staff, &json!({"client_id": 4})));
    }
}
