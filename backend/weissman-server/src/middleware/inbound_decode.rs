//! Inbound Content-Encoding: stream-decompress with a hard output cap.
//!
//! Response Brotli lives at nginx. Request gzip/br is a classic decompression bomb:
//! a ~10 KiB body can inflate to gigabytes and OOM the Axum process. We decode at
//! most [`MAX_DECOMPRESSED_BODY_BYTES`] and then 413 + `Connection: close`. Nested
//! encodings (`gzip, gzip`) are rejected. Unencoded bodies are unchanged (the
//! router `DefaultBodyLimit` still applies).

use crate::api::json_policy::{max_request_body_bytes, MAX_DECOMPRESSED_BODY_BYTES};
use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use std::io::Read;

/// Gzip / deflate / brotli request inflate cap (architect: 4 MiB).
pub const MAX_INFLATE: usize = MAX_DECOMPRESSED_BODY_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Gzip,
    Deflate,
    Brotli,
}

fn parse_single_encoding(raw: &str) -> Option<Encoding> {
    let v = raw
        .split(';')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    if v.contains(',') {
        return None;
    }
    match v.as_str() {
        "gzip" | "x-gzip" => Some(Encoding::Gzip),
        "deflate" => Some(Encoding::Deflate),
        "br" | "brotli" => Some(Encoding::Brotli),
        "identity" | "" => None,
        _ => None,
    }
}

fn is_identity_or_absent(raw: &str) -> bool {
    let v = raw
        .split(';')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    v.is_empty() || v == "identity"
}

#[derive(Debug)]
pub enum DecodeErr {
    TooLarge,
    Corrupt,
    Unsupported,
}

/// Inflate `input` into at most `max` bytes. Stops before the output buffer can grow
/// past `max` (zip bomb / Brotli bomb).
pub fn decompress_limited(
    encoding: Encoding,
    input: &[u8],
    max: usize,
) -> Result<Vec<u8>, DecodeErr> {
    match encoding {
        Encoding::Gzip => read_limited(flate2::read::GzDecoder::new(input), max),
        Encoding::Deflate => read_limited(flate2::read::DeflateDecoder::new(input), max),
        Encoding::Brotli => read_limited(brotli::Decompressor::new(input, 4096), max),
    }
}

fn read_limited<R: Read>(mut decoder: R, max: usize) -> Result<Vec<u8>, DecodeErr> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 16 * 1024];
    loop {
        match decoder.read(&mut tmp) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                if out.len().saturating_add(n) > max {
                    return Err(DecodeErr::TooLarge);
                }
                out.extend_from_slice(&tmp[..n]);
            }
            Err(_) => return Err(DecodeErr::Corrupt),
        }
    }
}

fn reject_too_large() -> Response {
    tracing::error!(
        target: "http",
        max = MAX_INFLATE,
        "inbound decompress cap exceeded — dropping connection (brotli/gzip bomb defense)"
    );
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        [(header::CONNECTION, "close")],
        "decompressed request exceeds 4 MiB",
    )
        .into_response()
}

fn reject_unsupported() -> Response {
    (
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        [(header::CONNECTION, "close")],
        "unsupported or nested Content-Encoding",
    )
        .into_response()
}

fn reject_corrupt() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONNECTION, "close")],
        "invalid compressed request body",
    )
        .into_response()
}

pub async fn inbound_decode_middleware(req: Request<Body>, next: Next) -> Response {
    if matches!(
        *req.method(),
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) {
        return next.run(req).await;
    }
    let encoding_hdr = req
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(raw) = encoding_hdr else {
        return next.run(req).await;
    };
    if is_identity_or_absent(raw) {
        return next.run(req).await;
    }
    let Some(enc) = parse_single_encoding(raw) else {
        return reject_unsupported();
    };

    let (parts, body) = req.into_parts();
    let wire_cap = max_request_body_bytes();
    let collected = match axum::body::to_bytes(body, wire_cap).await {
        Ok(b) => b,
        Err(_) => return reject_too_large(),
    };
    let plain = match decompress_limited(enc, &collected, MAX_INFLATE) {
        Ok(v) => v,
        Err(DecodeErr::TooLarge) => return reject_too_large(),
        Err(DecodeErr::Corrupt) => return reject_corrupt(),
        Err(DecodeErr::Unsupported) => return reject_unsupported(),
    };
    let mut req = Request::from_parts(parts, Body::from(plain));
    req.headers_mut().remove(header::CONTENT_ENCODING);
    req.headers_mut().remove(header::CONTENT_LENGTH);
    next.run(req).await
}

pub fn apply(router: Router) -> Router {
    router.layer(axum::middleware::from_fn(inbound_decode_middleware))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use axum::routing::{get, post};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tower::ServiceExt;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn gzip_bomb_stops_at_cap() {
        let payload = vec![0u8; MAX_INFLATE + 64 * 1024];
        let gz = gzip(&payload);
        assert!(
            gz.len() < 64 * 1024,
            "zeros must compress far below the cap"
        );
        match decompress_limited(Encoding::Gzip, &gz, MAX_INFLATE) {
            Err(DecodeErr::TooLarge) => {}
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn gzip_small_payload_roundtrips() {
        let raw = br#"{"agent_id":"a","ok":true}"#;
        let gz = gzip(raw);
        let out = decompress_limited(Encoding::Gzip, &gz, MAX_INFLATE).expect("inflate");
        assert_eq!(out, raw);
    }

    #[test]
    fn nested_encoding_is_unsupported() {
        assert!(parse_single_encoding("gzip, gzip").is_none());
        assert!(parse_single_encoding("br, deflate").is_none());
    }

    #[tokio::test]
    async fn gzip_json_is_inflated_for_handler() {
        let app =
            apply(Router::new().route("/", post(|body: axum::body::Bytes| async move { body })));
        let gz = gzip(br#"{"ok":true}"#);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_ENCODING, "gzip")
                    .body(Body::from(gz))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], br#"{"ok":true}"#);
    }

    #[tokio::test]
    async fn gzip_bomb_http_is_413_with_connection_close() {
        let app = apply(Router::new().route("/", post(|| async { "ok" })));
        let gz = gzip(&vec![0u8; MAX_INFLATE + 1024]);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::CONTENT_ENCODING, "gzip")
                    .body(Body::from(gz))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let conn = resp
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(conn, "close");
    }

    #[tokio::test]
    async fn get_is_not_inflated() {
        let app = apply(Router::new().route("/", get(|| async { "ok" })));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::CONTENT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
