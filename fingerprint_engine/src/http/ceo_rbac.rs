//! Restrict `/api/ceo/*` to `role = CEO` (case-insensitive) or `is_superadmin` on the JWT.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::auth_jwt::AuthContext;

#[must_use]
pub fn auth_is_ceo(ctx: &AuthContext) -> bool {
    ctx.is_superadmin || ctx.role.eq_ignore_ascii_case("ceo")
}

pub async fn ceo_rbac_middleware(request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path();
    if !path.starts_with("/api/ceo/") {
        return next.run(request).await;
    }
    let Some(ctx) = request.extensions().get::<AuthContext>().cloned() else {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "ok": false,
                "detail": "Unauthorized",
            })),
        )
            .into_response();
    };
    if !auth_is_ceo(&ctx) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "ok": false,
                "detail": "CEO role or superadmin required for this endpoint",
            })),
        )
            .into_response();
    }
    next.run(request).await
}
