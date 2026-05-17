//! Axum HTTP server (API, dashboard, WebSockets).

pub mod ceo_rbac;
pub mod client_ip;
pub mod tenant_scan_limit;
mod serve;

pub use client_ip::extract_client_ip;
pub use serve::{
    build_http_router, new_app_state, run_http_tcp_listener, spawn_http_background_tasks,
    AppState,
};
