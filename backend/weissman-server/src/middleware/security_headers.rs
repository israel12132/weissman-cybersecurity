//! Defense-in-depth response headers (HSTS, frame denial, MIME sniffing, Referrer-Policy).
//!
//! Set `WEISSMAN_DISABLE_SECURITY_HEADERS=1` for local HTTP-only labs. Prefer TLS in production.

use axum::http::header;
use axum::http::{HeaderName, HeaderValue};
use axum::Router;
use tower_http::set_header::SetResponseHeaderLayer;

pub fn apply(router: Router) -> Router {
    if std::env::var("WEISSMAN_DISABLE_SECURITY_HEADERS").is_ok() {
        return router;
    }
    router
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self' ws: wss:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests",
            ),
        ))
}
