//! Owner-only Sovereign Operator — live engine logs, knowledge, tool bus, theater chat.

pub mod chat;
pub mod forge;
pub mod hourly;
pub mod knowledge;
pub mod llm_fence;
pub mod log_stream;
pub mod memory;
pub mod scripts;
pub mod stream_ticket;
pub mod tools;

use crate::auth_jwt::AuthContext;
use crate::client_isolation::is_platform_owner;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub const API_PREFIX: &str = "/api/sovereign/operator";

/// Hide the surface from non-owners (404, not 403).
pub fn path_is_sovereign_operator(path: &str) -> bool {
    path == API_PREFIX || path.starts_with(&format!("{API_PREFIX}/"))
}

pub fn owner_or_hidden(auth: Option<&AuthContext>) -> Result<(), Response> {
    match auth {
        Some(ctx) if is_platform_owner(ctx) => Ok(()),
        _ => Err(hidden()),
    }
}

pub fn hidden() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "ok": false, "detail": "not found" })),
    )
        .into_response()
}

pub async fn sovereign_operator_rbac_middleware(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path().to_string();
    if !path_is_sovereign_operator(&path) {
        return next.run(request).await;
    }
    let auth = request.extensions().get::<AuthContext>().cloned();
    if owner_or_hidden(auth.as_ref()).is_err() {
        return hidden();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_jwt::AuthContext;

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
    fn prefix_matches_nested() {
        assert!(path_is_sovereign_operator("/api/sovereign/operator"));
        assert!(path_is_sovereign_operator("/api/sovereign/operator/chat"));
        assert!(path_is_sovereign_operator(
            "/api/sovereign/operator/stream-ticket"
        ));
        assert!(!path_is_sovereign_operator("/api/sovereign/phantom-trap"));
        assert!(!path_is_sovereign_operator("/api/ceo/sovereign/trigger"));
    }

    #[test]
    fn owner_allows_ceo_and_superadmin() {
        assert!(owner_or_hidden(Some(&ctx("ceo", false))).is_ok());
        assert!(owner_or_hidden(Some(&ctx("viewer", true))).is_ok());
        assert!(owner_or_hidden(Some(&ctx("admin", false))).is_err());
        assert!(owner_or_hidden(Some(&ctx("operator", false))).is_err());
        assert!(owner_or_hidden(None).is_err());
    }
}
