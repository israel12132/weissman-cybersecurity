//! Timing & header mimicry so real API 401s and honeynet responses share a
//! network fingerprint (architect: Differential Analysis Bypass).
//!
//! Status codes and bodies still differ (JSON 401 vs trap HTML/JSON) — the SPA
//! requires that. Hop-level headers and TTFB are unified via a **live Gaussian**
//! of legitimate 401/403 latency — never a hard millisecond floor.

use axum::body::Body;
use axum::http::{header, HeaderName, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::gaussian::sample_normal;

/// Marker so a honeynet response that already paid mimicry delay is not delayed twice.
#[derive(Clone, Copy)]
pub struct FabricTimingApplied;

/// Bootstrap when no live 401/403 samples exist (architect Normal(8.5, 2.1) ms).
const BOOTSTRAP_MEAN_MS: f64 = 8.5;
const BOOTSTRAP_STD_MS: f64 = 2.1;
const BOOTSTRAP_MIN_MS: f64 = 4.0;
const BOOTSTRAP_MAX_MS: f64 = 18.0;
const LIVE_MIN_SAMPLES: u64 = 16;
const OBSERVE_MAX_MS: f64 = 200.0;

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

struct LatencyEwma {
    n: u64,
    mean: f64,
    var: f64,
}

impl LatencyEwma {
    fn observe(&mut self, ms: f64) {
        if !ms.is_finite() || ms < 0.05 || ms > OBSERVE_MAX_MS {
            return;
        }
        if self.n == 0 {
            self.mean = ms;
            self.var = BOOTSTRAP_STD_MS * BOOTSTRAP_STD_MS;
            self.n = 1;
            return;
        }
        let alpha = 0.08;
        let d = ms - self.mean;
        self.mean += alpha * d;
        self.var = (1.0 - alpha) * (self.var + alpha * d * d);
        self.n = self.n.saturating_add(1);
    }
}

fn ewma() -> &'static Mutex<LatencyEwma> {
    static S: std::sync::OnceLock<Mutex<LatencyEwma>> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(LatencyEwma {
            n: 0,
            mean: BOOTSTRAP_MEAN_MS,
            var: BOOTSTRAP_STD_MS * BOOTSTRAP_STD_MS,
        })
    })
}

/// Record raw (pre-pad) latency of a **legitimate** 401/403 so honey TTFB tracks live API.
pub fn observe_legitimate_401_ms(ms: f64) {
    if let Ok(mut g) = ewma().lock() {
        g.observe(ms);
    }
}

#[must_use]
pub fn live_latency_stats() -> (u64, f64, f64) {
    ewma()
        .lock()
        .map(|g| (g.n, g.mean, g.var.sqrt()))
        .unwrap_or((0, BOOTSTRAP_MEAN_MS, BOOTSTRAP_STD_MS))
}

/// Dynamic mimicry delay: Normal matching live 401/403, else Normal(8.5, 2.1) clamped 4–18 ms.
#[must_use]
pub fn calculate_dynamic_mimicry_delay() -> Duration {
    let (n, mean, std) = live_latency_stats();
    let (mean, std, lo, hi) = if n >= LIVE_MIN_SAMPLES {
        let std = std.max(0.4);
        let lo = (mean - 4.0 * std).max(1.0);
        let hi = (mean + 4.0 * std).min(50.0).max(lo + 0.5);
        (mean, std, lo, hi)
    } else {
        (
            BOOTSTRAP_MEAN_MS,
            BOOTSTRAP_STD_MS,
            BOOTSTRAP_MIN_MS,
            BOOTSTRAP_MAX_MS,
        )
    };
    let delay_ms = sample_normal(mean, std).max(lo).min(hi);
    Duration::from_nanos((delay_ms * 1_000_000.0) as u64)
}

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
    headers.remove("x-powered-by");
    resp
}

/// Sleep until `start + sampled Gaussian delay` (no hard floor).
pub async fn pad_to_fabric_floor(start: Instant) {
    pad_to_mimicry_delay(start).await;
}

pub async fn pad_to_mimicry_delay(start: Instant) {
    let target = calculate_dynamic_mimicry_delay();
    if let Some(remain) = target.checked_sub(start.elapsed()) {
        tokio::time::sleep(remain).await;
    }
}

pub async fn finish_fabric_response(start: Instant, resp: Response) -> Response {
    pad_to_mimicry_delay(start).await;
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
        401 | 403 => {
            observe_legitimate_401_ms(start.elapsed().as_secs_f64() * 1000.0);
            finish_fabric_response(start, resp).await
        }
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
        resp.headers_mut()
            .insert("x-powered-by", HeaderValue::from_static("php"));
        let resp = apply_fabric_headers(resp);
        assert!(resp.headers().get(header::SERVER).is_none());
        assert!(resp.headers().get("x-powered-by").is_none());
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

    #[test]
    fn dynamic_delay_is_gaussian_not_hard_14ms_floor() {
        let mut samples = Vec::with_capacity(400);
        for _ in 0..400 {
            samples.push(calculate_dynamic_mimicry_delay().as_secs_f64() * 1000.0);
        }
        let min = samples.iter().copied().fold(f64::INFINITY, f64::min);
        let max = samples.iter().copied().fold(0.0_f64, f64::max);
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!(min < 14.0, "hard 14ms floor still present: min={min:.3}");
        assert!(min >= BOOTSTRAP_MIN_MS - 0.01, "min={min}");
        assert!(max <= BOOTSTRAP_MAX_MS + 0.01, "max={max}");
        assert!(
            (6.0..12.0).contains(&mean),
            "mean {mean} not near Normal(8.5, 2.1)"
        );
        let below_floor = samples.iter().filter(|ms| **ms < 14.0).count();
        assert!(
            below_floor > 50,
            "only {below_floor}/400 samples below 14ms"
        );
    }

    #[tokio::test]
    async fn pad_returns_within_bootstrap_band() {
        let start = Instant::now();
        pad_to_mimicry_delay(start).await;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        assert!(ms < 40.0, "pad took {ms}ms");
    }

    #[tokio::test]
    async fn middleware_applies_headers_to_401() {
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
        assert!(start.elapsed() < Duration::from_millis(50));
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert!(resp.headers().get(header::SERVER).is_none());
    }
}
