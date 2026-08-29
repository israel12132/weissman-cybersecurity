//! Timing & header mimicry so real API 401s and honeynet responses share a
//! network fingerprint (architect: Differential Analysis Bypass).
//!
//! Status codes and bodies still differ (JSON 401 vs trap HTML/JSON) — the SPA
//! requires that. Hop-level headers and TTFB are unified.

use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::time::{Duration, Instant};

/// Marker so a honeynet response that already paid the TTFB floor is not delayed twice.
#[derive(Clone, Copy)]
pub struct FabricTimingApplied;

/// Shared TTFB floor (ms) + jitter band. Large enough to cover body-buffer +
/// classify on the honey path; small enough that the SPA login/401 path stays snappy.
const FLOOR_MS: u64 = 14;
const JITTER_MS: u64 = 8;

/// Header pairs applied identically to honeynet and unauthenticated 401 responses.
pub const FABRIC_HEADERS: &[(&str, &str)] = &[
    ("cache-control", "no-store, no-cache, must-revalidate"),
    ("pragma", "no-cache"),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    ("x-xss-protection", "0"),
    (
        "permissions-policy",
        "geolocation=(), microphone=(), camera=()",
    ),
];

#[must_use]
pub fn fabric_header_names() -> Vec<&'static str> {
    FABRIC_HEADERS.iter().map(|(k, _)| *k).collect()
}

pub fn apply_fabric_headers(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    for (name, value) in FABRIC_HEADERS {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(n, v);
        }
    }
    // Never advertise a distinct application server on either path.
    headers.remove(header::SERVER);
    resp
}

/// Sleep until `start + floor + jitter` so 401 TTFB matches honeynet TTFB.
pub async fn pad_to_fabric_floor(start: Instant) {
    let jitter = (start.elapsed().subsec_nanos() as u64) % (JITTER_MS + 1);
    let target = Duration::from_millis(FLOOR_MS + jitter);
    if let Some(remain) = target.checked_sub(start.elapsed()) {
        tokio::time::sleep(remain).await;
    }
}

pub async fn finish_fabric_response(start: Instant, resp: Response) -> Response {
    pad_to_fabric_floor(start).await;
    let mut resp = apply_fabric_headers(resp);
    resp.extensions_mut().insert(FabricTimingApplied);
    resp
}

/// Outermost hop: every 401/403 from Axum (auth_guard, RBAC, handlers) shares
/// honeynet TTFB + hop headers so differential probing cannot split the fabric.
pub async fn fabric_401_403_middleware(request: Request<Body>, next: Next) -> Response {
    let start = Instant::now();
    let resp = next.run(request).await;
    if resp.extensions().get::<FabricTimingApplied>().is_some() {
        return resp;
    }
    match resp.status().as_u16() {
        401 | 403 => finish_fabric_response(start, resp).await,
        _ => resp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[test]
    fn fabric_header_set_is_stable() {
        let names = fabric_header_names();
        assert!(names.contains(&"cache-control"));
        assert!(names.contains(&"x-content-type-options"));
        assert!(names.contains(&"x-frame-options"));
        assert_eq!(names.len(), FABRIC_HEADERS.len());
    }

    #[test]
    fn apply_strips_server_and_sets_unified_headers() {
        let mut resp = (StatusCode::UNAUTHORIZED, "x").into_response();
        resp.headers_mut()
            .insert(header::SERVER, HeaderValue::from_static("axum/0.8"));
        let resp = apply_fabric_headers(resp);
        assert!(resp.headers().get(header::SERVER).is_none());
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store, no-cache, must-revalidate")
        );
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
    }

    #[tokio::test]
    async fn pad_does_not_return_before_floor() {
        let start = Instant::now();
        pad_to_fabric_floor(start).await;
        assert!(start.elapsed() >= Duration::from_millis(FLOOR_MS));
    }

    #[tokio::test]
    async fn middleware_applies_floor_and_headers_to_401() {
        use axum::body::Body as ReqBody;
        use axum::http::Request;
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        let app = Router::new()
            .route(
                "/denied",
                get(|| async { (StatusCode::UNAUTHORIZED, "nope") }),
            )
            .layer(axum::middleware::from_fn(fabric_401_403_middleware));
        let start = Instant::now();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/denied")
                    .body(ReqBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(start.elapsed() >= Duration::from_millis(FLOOR_MS));
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert!(resp.headers().get(header::SERVER).is_none());
    }
}
