//! Reject oversized **raw** HTTP bodies before serde/sonic-rs touch the bytes.
//!
//! The 4 MiB inflate cap does not apply to uncompressed JSON. This middleware:
//! 1. Drops `Content-Length` above [`crate::api::json_policy::max_request_body_bytes`]
//!    (hard-clamped at 8 MiB) with 413 — no buffering.
//! 2. After the inner stack, any 413 (inflate bomb or `DefaultBodyLimit`) arms a
//!    TCP RST so ALB/proxy buffers stop filling.

use crate::api::json_policy::max_request_body_bytes;
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use fingerprint_engine::http::tcp_socket::{abrupt_close_http_peer, TcpRstHandle};

fn parse_content_length(req: &Request<Body>) -> Option<u64> {
    req.headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

fn reject_too_large(cap: usize) -> Response {
    tracing::error!(
        target: "http",
        cap,
        "raw Content-Length exceeds ingest ceiling — dropping connection before serde"
    );
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        [(header::CONNECTION, "close")],
        "request body exceeds the 8 MiB ingest ceiling",
    )
        .into_response()
}

pub async fn content_length_limit_middleware(req: Request<Body>, next: Next) -> Response {
    let cap = max_request_body_bytes();
    let rst = req.extensions().get::<TcpRstHandle>().cloned();

    if !matches!(
        *req.method(),
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) {
        if let Some(len) = parse_content_length(&req) {
            if len > cap as u64 {
                abrupt_close_http_peer(&req);
                return reject_too_large(cap);
            }
        }
    }

    let resp = next.run(req).await;
    if resp.status() == StatusCode::PAYLOAD_TOO_LARGE {
        if let Some(ref h) = rst {
            h.abort();
        }
    }
    resp
}

pub fn apply(router: Router) -> Router {
    router.layer(axum::middleware::from_fn(content_length_limit_middleware))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn content_length_over_cap_is_413_before_handler() {
        let hit = Arc::new(AtomicBool::new(false));
        let hit2 = hit.clone();
        let app = apply(Router::new().route(
            "/",
            post(move || {
                hit2.store(true, Ordering::SeqCst);
                async { "ok" }
            }),
        ));
        let cap = max_request_body_bytes();
        let handle = TcpRstHandle::noop();
        let mut req = Request::builder()
            .method("POST")
            .uri("/")
            .header(header::CONTENT_LENGTH, (cap as u64 + 1).to_string())
            .body(Body::from(vec![0u8; 8]))
            .unwrap();
        req.extensions_mut().insert(handle.clone());
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            !hit.load(Ordering::SeqCst),
            "handler must not run for oversize Content-Length"
        );
        assert!(handle.is_armed(), "413 must arm TCP RST");
        let conn = resp
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(conn, "close");
    }

    #[tokio::test]
    async fn content_length_within_cap_reaches_handler() {
        let app = apply(Router::new().route("/", post(|| async { "ok" })));
        let body = br#"{"ok":true}"#;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_LENGTH, body.len().to_string())
                    .body(Body::from(body.as_slice()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn inner_413_arms_rst_handle() {
        let handle = TcpRstHandle::noop();
        let inner = Router::new().route(
            "/",
            post(|| async { (StatusCode::PAYLOAD_TOO_LARGE, "no").into_response() }),
        );
        let app = apply(inner);
        let mut req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::from("{}"))
            .unwrap();
        req.extensions_mut().insert(handle.clone());
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(handle.is_armed());
    }
}
