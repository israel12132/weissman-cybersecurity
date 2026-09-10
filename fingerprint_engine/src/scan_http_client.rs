//! Aggressive HTTP connection reuse for long scans: large idle pools, long-lived sockets, TCP keepalive.
//! DNS is performed per new connection; reusing connections avoids repeated lookups for the same host.

use reqwest::Client;
use std::time::Duration;

fn pool_max_idle_per_host() -> usize {
    crate::elite_hardening::probe_io::pool_max_idle()
}

fn pool_idle_timeout() -> Duration {
    let secs: u64 = std::env::var("WEISSMAN_HTTP_POOL_IDLE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(604_800); // 7 days — keep sockets warm for full scan windows
    Duration::from_secs(secs.max(60))
}

fn tcp_keepalive() -> Duration {
    let secs: u64 = std::env::var("WEISSMAN_HTTP_TCP_KEEPALIVE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    Duration::from_secs(secs.max(10))
}

/// `ClientBuilder` preset for probe/fuzz traffic (invalid TLS allowed for lab targets).
pub fn scan_client_builder(timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(
            crate::elite_hardening::probe_io::connect_timeout_secs(),
        ))
        .pool_max_idle_per_host(pool_max_idle_per_host())
        .pool_idle_timeout(Some(pool_idle_timeout()))
        .tcp_keepalive(Some(tcp_keepalive()))
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
}

/// Shared scan client: connection pool keyed by host: reuse across sequential requests to the same origin.
pub fn scan_http_client(timeout: Duration) -> Client {
    scan_client_builder(timeout)
        .build()
        .unwrap_or_else(|_| Client::new())
}

/// Internal JSON client (valid TLS); tuned connection pool for scan workloads.
pub fn internal_json_client_builder(timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(
            crate::elite_hardening::probe_io::connect_timeout_secs(),
        ))
        .pool_max_idle_per_host(pool_max_idle_per_host())
        .pool_idle_timeout(Some(pool_idle_timeout()))
        .tcp_keepalive(Some(tcp_keepalive()))
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
}

pub fn internal_json_client(timeout: Duration) -> Client {
    internal_json_client_builder(timeout)
        .build()
        .unwrap_or_else(|_| Client::new())
}
