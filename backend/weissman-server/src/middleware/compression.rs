//! Brotli (quality 4) + gzip for API, SSE, and JSON. Skips WebSocket upgrades.
//!
//! tower-http's `DefaultPredicate` refuses `text/event-stream`. Command Center
//! SSE is exactly the payload we want compressed at brotli level 4 (speed vs
//! bandwidth). WebSocket `101 Switching Protocols` must never be compressed.

use axum::http::{Extensions, HeaderMap, StatusCode, Version};
use axum::Router;
use tower_http::compression::predicate::{NotForContentType, Predicate, SizeAbove};
use tower_http::compression::{CompressionLayer, CompressionLevel};

/// Brotli quality that matches nginx's on-the-fly default (level 4).
pub const BROTLI_QUALITY: i32 = 4;

fn compress_predicate() -> impl Predicate {
    SizeAbove::new(32)
        .and(NotForContentType::GRPC)
        .and(NotForContentType::IMAGES)
        .and(
            |status: StatusCode, _: Version, _: &HeaderMap, _: &Extensions| {
                status != StatusCode::SWITCHING_PROTOCOLS
            },
        )
}

/// Wrap the router with Brotli-4 + gzip. Outermost so it encodes the final body.
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
    async fn json_response_is_brotli_when_accepted() {
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
        let enc = resp
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            enc, "br",
            "Accept-Encoding: br must select Brotli quality 4"
        );
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
    async fn sse_is_compressed_when_accepted() {
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
        assert_eq!(
            enc, "br",
            "Command Center SSE with Accept-Encoding: br must be Brotli-4"
        );
    }
}
