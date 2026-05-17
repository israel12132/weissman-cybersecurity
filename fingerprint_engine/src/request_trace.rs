//! HTTP request / trace id at the edge (propagated to async jobs and logs).

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use std::sync::LazyLock;
use tracing::Instrument;
use uuid::Uuid;

static TRACE_HEADER: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("x-trace-id"));

fn normalize_incoming_trace(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() || t.len() > 128 {
        return None;
    }
    if t.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        Some(t.to_string())
    } else {
        None
    }
}

#[must_use]
pub fn trace_id_from_request_headers(req: &Request<Body>) -> String {
    let from_hdr = req
        .headers()
        .get(&*TRACE_HEADER)
        .or_else(|| req.headers().get("x-request-id"))
        .and_then(|v| v.to_str().ok())
        .and_then(normalize_incoming_trace);
    from_hdr.unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// Outermost middleware: sets `x-trace-id`, attaches tracing span field `trace_id`.
pub async fn trace_http_middleware(mut request: Request<Body>, next: Next) -> Response {
    let trace_id = trace_id_from_request_headers(&request);
    let span = tracing::info_span!("http.request", trace_id = %trace_id);
    let trace_for_header = trace_id.clone();
    async move {
        request.extensions_mut().insert(TraceId(trace_id.clone()));
        let mut response = next.run(request).await;
        if let Ok(v) = HeaderValue::from_str(&trace_for_header) {
            response.headers_mut().insert(&*TRACE_HEADER, v);
        }
        response
    }
    .instrument(span)
    .await
}

/// Carries the active trace id for the HTTP handler task (also in tracing span).
#[derive(Clone, Debug)]
pub struct TraceId(pub String);
