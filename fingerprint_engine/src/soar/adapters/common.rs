//! Shared HTTP helpers for SOAR provider adapters.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use std::time::Duration;

pub fn http_client(timeout_secs: u64) -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| e.to_string())
}

pub fn bearer_headers(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    let val = format!("Bearer {token}");
    if let Ok(v) = HeaderValue::from_str(&val) {
        h.insert(AUTHORIZATION, v);
    }
    h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h
}

pub fn basic_auth_header(user: &str, pass: &str) -> HeaderMap {
    use base64::Engine;
    let mut h = HeaderMap::new();
    let creds = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    if let Ok(v) = HeaderValue::from_str(&format!("Basic {creds}")) {
        h.insert(AUTHORIZATION, v);
    }
    h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    h
}
