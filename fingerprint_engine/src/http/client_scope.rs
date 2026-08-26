//! HTTP middleware: bind a customer-portal session to its assigned client.
//!
//! Runs after `auth_guard` (so [`AuthContext`] is live). Sets the request-scoped
//! [`crate::db::REQUEST_CLIENT_SCOPE`] task-local so every `begin_tenant_tx` on
//! this task stamps `app.current_client_id` for RLS. Also:
//!
//! * Rejects cross-client ids in path, query, and JSON body (404, no leak).
//! * Injects `client_id` into JSON mutations so engines auto-aim at the bound customer.
//! * Blocks client create/delete and staff-only prefixes for portal users.

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::auth_jwt::AuthContext;
use crate::client_isolation;

const MAX_REWRITE_BODY: usize = 1_048_576;

pub async fn client_scope_middleware(req: Request, next: Next) -> Response {
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

    // Portal user.
    if auth.assigned_client_id.is_none() {
        if client_isolation::is_portal_self_service(&method, &path) {
            return Ok(req);
        }
        return Err(unbound(auth));
    }

    if client_isolation::is_portal_self_service(&method, &path) {
        return Ok(req);
    }

    if client_isolation::is_staff_only_path(&path)
        || client_isolation::is_client_create_path(&method, &path)
        || client_isolation::is_client_delete_path(&method, &path)
    {
        return Err(forbidden_portal());
    }

    if let Some(path_cid) = client_isolation::extract_path_client_id(&path) {
        if let Err(r) = client_isolation::bind_requested_client(auth, Some(path_cid)) {
            return Err(r);
        }
    }
    // Query `client_id` is never trusted: rewrite to the bound customer (insert or override).
    let req = match force_query_client_id_uri(auth, req) {
        Ok(r) => r,
        Err(resp) => return Err(resp),
    };

    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        return rewrite_json_body(auth, req).await;
    }
    Ok(req)
}

/// Scoped sessions always bind `?client_id=` to the assigned customer.
/// A UI-supplied id is overwritten; a missing id is filled.
fn force_query_client_id_uri(auth: &AuthContext, req: Request) -> Result<Request, Response> {
    let Some(cid) = auth.assigned_client_id else {
        return Ok(req);
    };
    let Some(new_q) = client_isolation::force_query_client_id(req.uri().query(), cid) else {
        return Ok(req);
    };
    let current = req.uri().query().unwrap_or("");
    if current == new_q {
        return Ok(req);
    }
    let path = req.uri().path().to_string();
    let rebuilt = format!("{path}?{new_q}");
    let Ok(uri) = rebuilt.parse() else {
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
        Err(_) => {
            // Non-object JSON (arrays) — restore original bytes.
            Ok(Request::from_parts(parts, Body::from(bytes)))
        }
    }
}

fn unbound(auth: &AuthContext) -> Response {
    tracing::error!(
        target: "client_isolation",
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
