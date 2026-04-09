//! Browser CORS for the Command Center origin. Applied only by `weissman-server` (single HTTP entrypoint).

use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderName, HeaderValue, Method};
use axum::Router;
use tower_http::cors::CorsLayer;

pub fn apply(router: Router) -> Router {
    // tower-http forbids allow_credentials(true) with allow_headers(Any); list concrete headers.
    let cors = CorsLayer::new()
        .allow_origin(HeaderValue::from_static("https://weissmancyber.com"))
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::OPTIONS])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCEPT,
            HeaderName::from_static("x-weissman-destructive-confirm"),
        ]);
    router.layer(cors)
}
