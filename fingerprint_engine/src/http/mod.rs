//! Axum HTTP server (API, dashboard, WebSockets).

pub mod ai_quota_mem;
pub mod api_rate_limit;
pub mod blocking_io;
pub mod bounded_codec;
pub mod ceo_rbac;
pub mod client_ip;
pub mod login_lockout;
pub mod login_rate_limit;
pub mod simd_json;
pub mod tcp_socket;

pub use api_rate_limit::api_rate_limit_middleware;
pub use login_lockout::{
    check_lockout, check_lockout_status, clear_failures, is_account_lockout_post, locked_response,
    record_failure, LockoutStatus, ACCOUNT_LOCKOUT_PATHS,
};
pub use login_rate_limit::{is_login_post, login_rate_limit_middleware};
pub mod client_scope;
pub mod event_replay;
pub mod rate_limit_metrics;
pub mod rate_limit_redis;
mod serve;
pub mod sse_bridge;
pub mod sse_context;
pub mod tenant_scan_limit;
pub mod tenant_stream;

pub use client_ip::extract_client_ip;
pub use serve::{
    build_http_router, new_app_state, run_http_tcp_listener, spawn_http_background_tasks, AppState,
};
