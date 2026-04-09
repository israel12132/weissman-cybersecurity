//! Global HTTP body size bound for JSON (and other) request bodies.
//!
//! Per-endpoint **semantic** validation (required fields, enums, bounds) is implemented on handlers in
//! `fingerprint_engine::http` (Axum `Json<T>` + serde). This module enforces a hard ceiling so oversized
//! payloads are rejected before deserialization and before any database work.

const DEFAULT_MAX_BYTES: usize = 5 * 1024 * 1024;

/// Maximum request body size applied at the router (`DefaultBodyLimit`).
///
/// Override with `WEISSMAN_MAX_REQUEST_BODY_BYTES` (clamped between 1 KiB and 128 MiB).
#[must_use]
pub fn max_request_body_bytes() -> usize {
    std::env::var("WEISSMAN_MAX_REQUEST_BODY_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| (1024..=128 * 1024 * 1024).contains(&n))
        .unwrap_or(DEFAULT_MAX_BYTES)
}
