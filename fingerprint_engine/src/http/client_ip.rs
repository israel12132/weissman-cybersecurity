//! Client IP for audit logs and rate limiting (X-Forwarded-For aware).

use axum::http::HeaderMap;
use std::net::SocketAddr;

pub fn extract_client_ip(headers: &HeaderMap, peer: SocketAddr) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    if let Some(xr) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let ip = xr.trim();
        if !ip.is_empty() {
            return ip.to_string();
        }
    }
    peer.ip().to_string()
}
