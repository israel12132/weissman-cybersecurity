//! Optional Brotli-4 / gzip for **static Command Center assets only**.
//!
//! API JSON is never compressed in-process. Brotli-4 on every JSON response is a
//! CPU-exhaustion DoS: a flood of large `/api/*` bodies starves Tokio workers,
//! drops agent WebSockets, and takes the cockpit down. Production JSON
//! compression belongs at nginx (`deploy/nginx-brotli.inc` / gateway gzip).
//!
//! Still excluded here: `text/event-stream` (buffering delays SOC alerts) and
//! WebSocket `101 Switching Protocols`.

use axum::http::{header, Extensions, HeaderMap, StatusCode, Version};
use axum::Router;
use tower_http::compression::predicate::{NotForContentType, Predicate, SizeAbove};
use tower_http::compression::{CompressionLayer, CompressionLevel};

/// Brotli quality that matches nginx's on-the-fly default (level 4).
pub const BROTLI_QUALITY: i32 = 4;

fn is_static_asset_content_type(headers: &HeaderMap) -> bool {
    let Some(ct) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let ct = ct
        .split(';')
        .next()
        .unwrap_or(ct)
        .trim()
        .to_ascii_lowercase();
    matches!(
        ct.as_str(),
        "text/html"
            | "text/css"
            | "text/javascript"
            | "application/javascript"
            | "application/wasm"
            | "image/svg+xml"
            | "application/manifest+json"
    )
}

fn compress_predicate() -> impl Predicate {
    SizeAbove::new(256)
        .and(NotForContentType::GRPC)
        .and(NotForContentType::IMAGES)
        .and(NotForContentType::SSE)
        .and(
            |status: StatusCode, _: Version, headers: &HeaderMap, _: &Extensions| {
                status != StatusCode::SWITCHING_PROTOCOLS && is_static_asset_content_type(headers)
            },
        )
}

/// Wrap the router with Brotli-4 + gzip for SPA/static types only.
pub fn apply(router: Router) -> Router {
    let layer = CompressionLayer::new()
        .br(true)
        .gzip(true)
        .no_deflate()
        .quality(CompressionLevel::Precise(BROTLI_QUALITY))
        .compress_when(compress_predicate());
    router.layer(layer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use axum::routing::get;
    use tower::ServiceExt;

    #[tokio::test]
    async fn json_api_is_never_compressed() {
        let app = apply(Router::new().route(
            "/",
            get(|| async {
                axum::Json(serde_json::json!({
                    "detail": "x".repeat(512),
                    "ok": true
                }))
            }),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT_ENCODING, "br")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.headers().get(header::CONTENT_ENCODING).is_none(),
            "API JSON must not be Brotli-compressed in Axum (CPU DoS surface)"
        );
    }

    #[tokio::test]
    async fn html_static_is_brotli_when_accepted() {
        let app = apply(Router::new().route(
            "/",
            get(|| async {
                axum::http::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(Body::from(format!("<html>{}</html>", "x".repeat(512))))
                    .unwrap()
            }),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ACCEPT_ENCODING, "br")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let enc = resp
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(enc, "br", "Command Center HTML still gets Brotli-4");
    }

    #[tokio::test]
    async fn switching_protocols_is_not_compressed() {
        let app = apply(Router::new().route(
            "/ws",
            get(|| async {
                axum::http::Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header(header::CONNECTION, "Upgrade")
                    .body(Body::empty())
                    .unwrap()
            }),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ws")
                    .header(header::ACCEPT_ENCODING, "br")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn sse_is_never_compressed() {
        let app = apply(Router::new().route(
            "/sse",
            get(|| async {
                let payload = format!("data: {}\n\n", "event-payload-".repeat(40));
                axum::http::Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from(payload))
                    .unwrap()
            }),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/sse")
                    .header(header::ACCEPT_ENCODING, "br, gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.headers().get(header::CONTENT_ENCODING).is_none(),
            "SSE must not be Brotli/gzip buffered — cockpit alerts must flush immediately"
        );
    }
}
