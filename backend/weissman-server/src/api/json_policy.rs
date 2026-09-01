//! Global HTTP body size bound for JSON (and other) request bodies.
//!
//! Per-endpoint **semantic** validation (required fields, enums, bounds) is implemented on handlers in
//! `fingerprint_engine::http` (Axum `Json<T>` + serde). This module enforces a hard ceiling so oversized
//! payloads are rejected before deserialization and before any database work.

const DEFAULT_MAX_BYTES: usize = 5 * 1024 * 1024;

/// Hard cap on **decompressed** request size. A 10 KiB gzip/br body that inflates
/// past this is a bomb: 413 and drop, never gigabytes of RAM.
pub const MAX_DECOMPRESSED_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Absolute ceiling on the **raw** HTTP buffer (`Content-Length` / `DefaultBodyLimit`).
/// Uncompressed JSON is not covered by the inflate cap; 8 MiB is the ingest OOM wall.
pub const MAX_RAW_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Maximum request body size applied at the router (`DefaultBodyLimit`) and the
/// Content-Length middleware. Override with `WEISSMAN_MAX_REQUEST_BODY_BYTES`
/// (clamped between 1 KiB and [`MAX_RAW_REQUEST_BODY_BYTES`]).
#[must_use]
pub fn max_request_body_bytes() -> usize {
    std::env::var("WEISSMAN_MAX_REQUEST_BODY_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| (1024..=MAX_RAW_REQUEST_BODY_BYTES).contains(&n))
        .unwrap_or(DEFAULT_MAX_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Single test owns the shared env var so parallel tests never race on it.
    #[test]
    fn max_body_bytes_clamps_and_defaults() {
        let key = "WEISSMAN_MAX_REQUEST_BODY_BYTES";

        std::env::remove_var(key);
        assert_eq!(max_request_body_bytes(), DEFAULT_MAX_BYTES);

        // In-range override honored.
        std::env::set_var(key, "2048");
        assert_eq!(max_request_body_bytes(), 2048);

        // Below floor (1 KiB) rejected -> default.
        std::env::set_var(key, "512");
        assert_eq!(max_request_body_bytes(), DEFAULT_MAX_BYTES);

        // Exact 8 MiB ceiling honored.
        std::env::set_var(key, &MAX_RAW_REQUEST_BODY_BYTES.to_string());
        assert_eq!(max_request_body_bytes(), MAX_RAW_REQUEST_BODY_BYTES);

        // 50 MiB raw POST (architect OOM case) rejected -> default, never 50 MiB serde.
        std::env::set_var(key, &(50 * 1024 * 1024).to_string());
        assert_eq!(max_request_body_bytes(), DEFAULT_MAX_BYTES);

        // Above ceiling (8 MiB + 1) rejected -> default.
        std::env::set_var(key, &(MAX_RAW_REQUEST_BODY_BYTES + 1).to_string());
        assert_eq!(max_request_body_bytes(), DEFAULT_MAX_BYTES);

        // Non-numeric rejected -> default.
        std::env::set_var(key, "lots");
        assert_eq!(max_request_body_bytes(), DEFAULT_MAX_BYTES);

        std::env::remove_var(key);
    }
}
