//! [`TenantScopeGuard`] — Axum router layer on the authenticated API tree.
//!
//! Runs **after** `auth_guard` (so [`AuthContext`] is live) and **before**
//! handlers. JWT `cid` / `assigned_client_id` is the **sole** customer-session
//! anchor. Body / query / path `client_id` from the caller is ignored and
//! overwritten for scoped sessions. Public login is not wrapped (this layer
//! sits inside `auth_guard`).
//!
//! Every `begin_tenant_tx` on this task reads [`crate::db::REQUEST_CLIENT_SCOPE`]
//! and stamps `SET LOCAL app.current_tenant_id` **and** `app.current_client_id`
//! so FORCE RLS still holds when a handler forgets `bind_requested_client`.

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{header, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::auth_jwt::AuthContext;
use crate::client_isolation;

const MAX_REWRITE_BODY: usize = 1_048_576;

/// Architect-mandated authenticated-API middleware. Install with
/// `middleware::from_fn(tenant_scope_guard)` (an Axum router [`tower::Layer`])
/// on the tree that already has `auth_guard`. Public login is not wrapped.
#[derive(Clone, Copy, Debug, Default)]
pub struct TenantScopeGuard;

/// JWT `cid` is the sole customer-session anchor. Overwrites spoofed `client_id`.
pub async fn tenant_scope_guard(req: Request, next: Next) -> Response {
    let auth = req.extensions().get::<AuthContext>().cloned();
    let scope = auth.as_ref().and_then(|a| a.assigned_client_id);

    let req = match enforce(auth.as_ref(), req).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    crate::db::REQUEST_CLIENT_SCOPE
        .scope(scope, next.run(req))
        .await
}

/// Backward-compatible alias.
pub async fn client_scope_middleware(req: Request, next: Next) -> Response {
    tenant_scope_guard(req, next).await
}

async fn enforce(auth: Option<&AuthContext>, req: Request) -> Result<Request, Response> {
    let Some(auth) = auth else {
        return Ok(req);
    };
    if auth.agent_id.is_some() || auth.role.eq_ignore_ascii_case("agent") {
        return Ok(req);
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if !client_isolation::is_client_scoped(auth) {
        if client_isolation::is_client_create_path(&method, &path) {
            if let Err(r) = client_isolation::require_owner(auth) {
                return Err(r);
            }
        }
        if client_isolation::is_client_delete_path(&method, &path) {
            if let Err(r) = client_isolation::require_can_delete_client(auth) {
                return Err(r);
            }
        }
        return Ok(req);
    }

    // Scoped session (portal lock OR staff impersonation JWT cid).
    if auth.assigned_client_id.is_none() {
        if client_isolation::is_portal_self_service(&method, &path) {
            return Ok(req);
        }
        return Err(unbound(auth));
    }

    if client_isolation::is_portal_self_service(&method, &path)
        || client_isolation::is_scope_switch_path(&path)
    {
        // Do not rewrite scope-switch's target client_id — that body is the
        // destination of a new JWT, not a data-plane filter.
        return Ok(req);
    }

    if client_isolation::is_staff_only_path(&path)
        || client_isolation::is_client_create_path(&method, &path)
        || client_isolation::is_client_delete_path(&method, &path)
    {
        return Err(forbidden_portal());
    }

    let req = force_path_and_query_uri(auth, req)?;

    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        return rewrite_json_body(auth, req).await;
    }
    Ok(req)
}

/// Overwrite path `/:client_id` and query `client_id` from JWT `cid`.
fn force_path_and_query_uri(auth: &AuthContext, req: Request) -> Result<Request, Response> {
    let Some(cid) = auth.assigned_client_id else {
        return Ok(req);
    };
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    let new_path = client_isolation::force_path_client_id(&path, cid);
    let new_query = client_isolation::force_query_client_id(query.as_deref(), cid);

    let path_out = new_path.as_deref().unwrap_or(&path);
    let query_out = new_query.as_deref().or(query.as_deref());
    let rebuilt = match query_out {
        Some(q) if !q.is_empty() => format!("{path_out}?{q}"),
        _ => path_out.to_string(),
    };
    let current = match req.uri().query() {
        Some(q) => format!("{}?{q}", req.uri().path()),
        None => req.uri().path().to_string(),
    };
    if rebuilt == current {
        return Ok(req);
    }
    let Ok(uri) = rebuilt.parse::<Uri>() else {
        return Ok(req);
    };
    let (mut parts, body) = req.into_parts();
    parts.uri = uri;
    Ok(Request::from_parts(parts, body))
}

async fn rewrite_json_body(auth: &AuthContext, req: Request) -> Result<Request, Response> {
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.to_ascii_lowercase().contains("json") {
        return Ok(req);
    }
    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, MAX_REWRITE_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"ok": false, "detail": "Request body too large"})),
            )
                .into_response());
        }
    };
    if bytes.is_empty() {
        return Ok(Request::from_parts(parts, Body::from(bytes)));
    }
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(mut value) => {
            client_isolation::force_json_client_id(auth, &mut value)?;
            let out = value.to_string();
            let mut parts = parts;
            if let Ok(len) = header::HeaderValue::from_str(&out.len().to_string()) {
                parts.headers.insert(header::CONTENT_LENGTH, len);
            }
            Ok(Request::from_parts(parts, Body::from(out)))
        }
        Err(_) => Ok(Request::from_parts(parts, Body::from(bytes))),
    }
}

fn unbound(auth: &AuthContext) -> Response {
    tracing::error!(
        target: "tenant_scope_guard",
        user_id = auth.user_id,
        "portal user has no assigned_client_id"
    );
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "ok": false,
            "detail": "This account is not bound to a customer workspace. Contact the platform owner.",
            "error_code": "client_scope_unbound",
        })),
    )
        .into_response()
}

fn forbidden_portal() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "ok": false,
            "detail": "This action is not available on a customer-portal account",
            "error_code": "portal_forbidden",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::middleware;
    use axum::routing::{get, post};
    use axum::Router;
    use tower::ServiceExt;

    fn portal() -> AuthContext {
        AuthContext {
            user_id: 7,
            tenant_id: 1,
            role: "client".to_string(),
            is_superadmin: false,
            agent_id: None,
            jti: Some("j".into()),
            bind_ip: None,
            bind_tls_fp: None,
            assigned_client_id: Some(5),
        }
    }

    async fn inject_portal(mut req: Request, next: Next) -> Response {
        req.extensions_mut().insert(portal());
        next.run(req).await
    }

    async fn echo_uri(req: Request) -> String {
        match req.uri().query() {
            Some(q) => format!("{}?{q}", req.uri().path()),
            None => req.uri().path().to_string(),
        }
    }

    async fn echo_body(req: Request) -> String {
        let bytes = to_bytes(req.into_body(), 64 * 1024)
            .await
            .unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn staff_impersonating() -> AuthContext {
        AuthContext {
            user_id: 2,
            tenant_id: 1,
            role: "operator".to_string(),
            is_superadmin: false,
            agent_id: None,
            jti: Some("j-staff".into()),
            bind_ip: None,
            bind_tls_fp: None,
            assigned_client_id: Some(5),
        }
    }

    async fn inject_staff(mut req: Request, next: Next) -> Response {
        req.extensions_mut().insert(staff_impersonating());
        next.run(req).await
    }

    fn scoped_app() -> Router {
        Router::new()
            .route("/api/findings", get(echo_uri))
            .route("/api/clients/:id/findings", get(echo_uri))
            .route("/api/scan", post(echo_body))
            .layer(middleware::from_fn(tenant_scope_guard))
            .layer(middleware::from_fn(inject_portal))
    }

    fn staff_switch_app() -> Router {
        Router::new()
            .route("/api/auth/scope-switch", post(echo_body))
            .layer(middleware::from_fn(tenant_scope_guard))
            .layer(middleware::from_fn(inject_staff))
    }

    #[tokio::test]
    async fn spoofed_query_client_id_is_overwritten() {
        let app = scoped_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/findings?limit=10&client_id=99")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(res.into_body(), 4096).await.unwrap();
        let s = String::from_utf8_lossy(&body);
        assert!(s.contains("client_id=5"), "got {s}");
        assert!(!s.contains("client_id=99"), "spoof survived: {s}");
    }

    #[tokio::test]
    async fn spoofed_path_client_id_is_overwritten() {
        let app = scoped_app();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/api/clients/99/findings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(res.into_body(), 4096).await.unwrap();
        let s = String::from_utf8_lossy(&body);
        assert!(
            s.starts_with("/api/clients/5/findings"),
            "path must be rewritten to JWT cid, got {s}"
        );
        assert!(!s.contains("/api/clients/99"), "spoofed path survived: {s}");
    }

    #[tokio::test]
    async fn spoofed_json_client_id_is_overwritten() {
        let app = scoped_app();
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/scan")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"engine":"asm","client_id":99}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(res.into_body(), 4096).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["client_id"], json!(5));
        assert_eq!(v["engine"], json!("asm"));
    }

    #[tokio::test]
    async fn jwt_cid_is_session_anchor_on_request_scope() {
        assert_eq!(portal().assigned_client_id, Some(5));
        let rewritten = client_isolation::force_query_client_id(Some("client_id=1"), 5);
        assert_eq!(rewritten.as_deref(), Some("client_id=5"));
    }

    #[tokio::test]
    async fn scope_switch_body_is_not_rewritten() {
        let app = staff_switch_app();
        let res = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/scope-switch")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"client_id":99}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(res.into_body(), 4096).await.unwrap();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            v["client_id"],
            json!(99),
            "scope-switch destination must not be overwritten to JWT cid"
        );
    }
}
