//! Browser CORS for the Command Center origin. Applied only by `weissman-server` (single HTTP entrypoint).
//!
//! Set `WEISSMAN_CORS_ORIGINS` to a comma-separated list (e.g. `https://app.example.com,https://weissmancyber.com`).
//! When unset, falls back to the origin of `WEISSMAN_PUBLIC_BASE_URL`, then `https://weissmancyber.com`.

use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderName, HeaderValue, Method};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};

fn configured_origins() -> Vec<HeaderValue> {
    let raw = std::env::var("WEISSMAN_CORS_ORIGINS")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("WEISSMAN_PUBLIC_BASE_URL")
                .ok()
                .and_then(|base| url::Url::parse(base.trim()).ok())
                .map(|u| u.origin().ascii_serialization())
        });
    let Some(raw) = raw else {
        return vec![HeaderValue::from_static("https://weissmancyber.com")];
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect()
}

pub fn apply(router: Router) -> Router {
    let origins = configured_origins();
    let allow_origin = if origins.len() == 1 {
        AllowOrigin::exact(origins[0].clone())
    } else {
        AllowOrigin::list(origins)
    };
    // tower-http forbids allow_credentials(true) with allow_headers(Any); list concrete headers.
    let cors = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            ACCEPT,
            HeaderName::from_static("x-weissman-destructive-confirm"),
        ]);
    router.layer(cors)
}
