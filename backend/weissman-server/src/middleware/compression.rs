//! Brotli (quality 4) + gzip for API JSON. Skips SSE and WebSocket upgrades.
//!
//! Architect rule: never Brotli-buffer `text/event-stream`. Brotli's internal
//! window holds a small SOC alert until more bytes arrive — that is cockpit
//! latency. SSE stays uncompressed. JSON still gets Brotli-4 (or gzip).
//! WebSocket `101 Switching Protocols` must never be compressed.

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
        .and(NotForContentType::SSE)
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
