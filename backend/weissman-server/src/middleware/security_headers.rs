//! Defense-in-depth response headers (HSTS, frame denial, MIME sniffing, Referrer-Policy).
//!
//! Set `WEISSMAN_DISABLE_SECURITY_HEADERS=1` for local HTTP-only labs. Prefer TLS in production.

use axum::http::header;
use axum::http::{HeaderName, HeaderValue};
use axum::Router;
use tower_http::set_header::SetResponseHeaderLayer;

pub fn apply(router: Router) -> Router {
    // Only honor the lab switch when explicitly set to a truthy value AND outside
    // production — a stray or empty `WEISSMAN_DISABLE_SECURITY_HEADERS` (even `=0`)
    // must never silently strip CSP/HSTS/etc. off every response.
    let disabled = std::env::var("WEISSMAN_DISABLE_SECURITY_HEADERS")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    let is_prod = std::env::var("WEISSMAN_ENV")
        .map(|v| v.trim().eq_ignore_ascii_case("production"))
        .unwrap_or(false);
    if disabled && !is_prod {
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
            // This server can serve the built SPA (frontend/dist), so the CSP must match what the
            // SPA needs or the app silently breaks under it:
            //   * script-src adds 'wasm-unsafe-eval' — the SPA loads WebAssembly (AST-cap /
            //     provenance); without it WASM instantiation is blocked. Narrower than
            //     'unsafe-eval'. No 'unsafe-inline' — Vite emits no inline scripts.
            //   * style-src adds 'unsafe-inline' — framer-motion sets per-frame inline styles and
            //     the SPA uses many static inline style attributes; neither is hashable.
            HeaderValue::from_static(
                // 'wasm-unsafe-eval' is required for the SPA's WebAssembly modules (AST-cap /
                // provenance); 'unsafe-inline' in style-src covers React inline styles / framer-motion.
                "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self' ws: wss:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests",
            ),
        ))
}
