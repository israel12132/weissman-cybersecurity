//! API route table: paths are registered in `fingerprint_engine::http::build_http_router`.
//! **Production:** only `weissman-server` should listen; it wraps this router with CORS, security
//! headers, global rate limiting, and a request body size cap ([`super::json_policy`]).
//!
//! **I/O:** [`build_full_router`] **inputs** `AppState` (DB pools, broadcast buses) and optional static
//! `PathBuf`; **output** is a fully wired `Router` consumed by `fingerprint_engine::http::run_http_tcp_listener`.

use axum::extract::DefaultBodyLimit;
use axum::Router;
use fingerprint_engine::http::{self, AppState};
use std::path::PathBuf;
use std::sync::Arc;

use super::json_policy;

/// Full Weissman HTTP surface (same contract as the historical `server.rs` router).
pub async fn build_full_router(state: Arc<AppState>, static_dir: Option<PathBuf>) -> Router {
    http::build_http_router(state, static_dir)
        .await
        .layer(DefaultBodyLimit::max(json_policy::max_request_body_bytes()))
}
