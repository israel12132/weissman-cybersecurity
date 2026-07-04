//! Zero-trust contextual binding for SSE streams — IP + optional TLS fingerprint must match JWT claims.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;

use super::client_ip::extract_client_ip;
use crate::auth_jwt::{self, AuthContext};

/// Paths that use server-sent events (require contextual binding after JWT auth).
#[must_use]
pub fn is_sse_stream_path(path: &str) -> bool {
    path == "/api/telemetry/stream"
        || path == "/api/ceo/war-room/stream"
        || (path.starts_with("/api/ceo/council/sessions/") && path.ends_with("/stream"))
        || path.starts_with("/api/poe-scan/stream/")
}

/// TLS / JA3 fingerprint from terminating proxy headers (when present).
#[must_use]
pub fn extract_tls_fingerprint(headers: &HeaderMap) -> Option<String> {
    const KEYS: &[&str] = &[
        "x-tls-fingerprint",
        "x-ssl-ja3",
        "cf-ssl-ja3",
        "x-client-cert-fingerprint",
        "x-ja3-fingerprint",
    ];
    for key in KEYS {
        if let Some(v) = headers.get(*key).and_then(|h| h.to_str().ok()) {
            let s = v.trim();
            if !s.is_empty() && s.len() <= 128 {
                return Some(s.to_ascii_lowercase());
            }
        }
    }
    None
}

/// Hard connection drop — `Connection: close`, empty body (no JSON leak surface).
#[must_use]
pub fn drop_connection_response() -> Response {
    match Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONNECTION, "close")
        .body(Body::empty())
    {
        Ok(r) => r,
        Err(_) => {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = StatusCode::FORBIDDEN;
            r
        }
    }
}

/// Middleware: after JWT auth, verify stream binding before handler runs.
pub async fn sse_context_middleware(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if !is_sse_stream_path(path) {
        return next.run(request).await;
    }
    let Some(auth) = request.extensions().get::<AuthContext>().cloned() else {
        return next.run(request).await;
    };
    if !auth_jwt::is_user_access_context(&auth) {
        return next.run(request).await;
    }
    let client_ip = extract_client_ip(&headers, peer);
    let tls_fp = extract_tls_fingerprint(&headers);
    if !auth_jwt::verify_stream_context(&auth, &client_ip, tls_fp.as_deref()) {
        tracing::warn!(
            target: "sse_context",
            path = %path,
            user_id = auth.user_id,
            tenant_id = auth.tenant_id,
            expected_ip = ?auth.bind_ip,
            actual_ip = %client_ip,
            tls_bound = auth.bind_tls_fp.is_some(),
            "stream context mismatch — terminating connection"
        );
        return drop_connection_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_sse_paths() {
        assert!(is_sse_stream_path("/api/telemetry/stream"));
        assert!(is_sse_stream_path("/api/poe-scan/stream/abc"));
        assert!(!is_sse_stream_path("/api/login"));
    }
}
