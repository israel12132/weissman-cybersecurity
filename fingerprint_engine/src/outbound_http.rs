//! Central outbound HTTP for third-party APIs (NVD, OSV, GitHub): timeouts, retries, optional cache hooks.

use reqwest::header::HeaderMap;
use reqwest::StatusCode;
use std::time::Duration;
use thiserror::Error;

/// Full-jitter helper: returns a random sleep duration in `[0, min(base*2^attempt, cap_ms)]`.
/// Prevents thundering-herd retry storms (AWS Architecture Blog: "Exponential Backoff And Jitter").
fn jitter_backoff(base_ms: u64, attempt: u32, cap_ms: u64) -> Duration {
    let exp = base_ms.saturating_mul(2u64.saturating_pow(attempt)).min(cap_ms);
    let entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0) as u64;
    let jitter_ms = if exp == 0 { 0 } else { entropy % exp };
    Duration::from_millis(jitter_ms)
}

/// Default connect timeout for external dependency calls.
pub const EXTERNAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default total request timeout (read + write).
pub const EXTERNAL_TOTAL_TIMEOUT: Duration = Duration::from_secs(55);

#[derive(Debug, Clone, Error)]
pub enum OutboundHttpError {
    #[error("failed to build HTTP client: {0}")]
    ClientBuild(String),
    #[error("request failed: {0}")]
    Request(String),
    #[error("HTTP {0}")]
    Status(u16),
    #[error("empty response body")]
    EmptyBody,
    #[error("read body: {0}")]
    Body(String),
}

/// Shared client: strict TLS, tuned for intel APIs (not scan targets).
pub fn external_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(EXTERNAL_CONNECT_TIMEOUT)
        .timeout(EXTERNAL_TOTAL_TIMEOUT)
        .user_agent(concat!("WeissmanEnterprise/", env!("CARGO_PKG_VERSION")))
        .pool_max_idle_per_host(32)
}

pub fn external_json_client() -> Result<reqwest::Client, OutboundHttpError> {
    external_client_builder()
        .build()
        .map_err(|e| OutboundHttpError::ClientBuild(e.to_string()))
}

/// GET with exponential backoff on 429 and 5xx (max `max_retries` extra attempts).
pub async fn get_bytes_with_retry(
    client: &reqwest::Client,
    url: &str,
    headers: HeaderMap,
    max_retries: u32,
    metrics_label: Option<&'static str>,
) -> Result<Vec<u8>, OutboundHttpError> {
    let mut attempt = 0u32;
    loop {
        let resp = match client
            .get(url)
            .headers(headers.clone())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if let Some(src) = metrics_label {
                    metrics::counter!("weissman_external_api_errors_total", "source" => src)
                        .increment(1);
                }
                return Err(OutboundHttpError::Request(e.to_string()));
            }
        };
        let status = resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            if attempt >= max_retries {
                if let Some(src) = metrics_label {
                    metrics::counter!("weissman_external_api_errors_total", "source" => src)
                        .increment(1);
                }
                return Err(OutboundHttpError::Status(status.as_u16()));
            }
            // Respect Retry-After header if present; otherwise use full-jitter backoff.
            let retry_after_ms = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(|s| s.saturating_mul(1000));
            let wait = match retry_after_ms {
                Some(ms) => Duration::from_millis(ms.min(60_000)),
                None => jitter_backoff(800, attempt, 60_000),
            };
            tracing::warn!(
                target: "outbound_http",
                url = %url,
                status = %status,
                attempt = attempt + 1,
                wait_ms = wait.as_millis(),
                "retrying external GET"
            );
            tokio::time::sleep(wait).await;
            attempt += 1;
            continue;
        }
        if !status.is_success() {
            if let Some(src) = metrics_label {
                metrics::counter!("weissman_external_api_errors_total", "source" => src).increment(1);
            }
            return Err(OutboundHttpError::Status(status.as_u16()));
        }
        let bytes = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                if let Some(src) = metrics_label {
                    metrics::counter!("weissman_external_api_errors_total", "source" => src)
                        .increment(1);
                }
                return Err(OutboundHttpError::Body(e.to_string()));
            }
        };
        if bytes.is_empty() {
            if let Some(src) = metrics_label {
                metrics::counter!("weissman_external_api_errors_total", "source" => src).increment(1);
            }
            return Err(OutboundHttpError::EmptyBody);
        }
        return Ok(bytes.to_vec());
    }
}
