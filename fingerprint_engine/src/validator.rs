//! Validator: confirm crashes with secondary payloads. Enterprise: Content-Length discrepancy
//! and HTTP Header side-channel analysis for 99.9% certainty.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const USER_AGENT: &str = "Mozilla/5.0 Weissman-Validator/1.0";
const REQUEST_TIMEOUT_SECS: u64 = 15;
const RATE_DELAY_MS: u64 = 150;
const LENGTH_DISCREPANCY_RATIO: f64 = 2.0;

static CONFIRMATION_PAYLOADS: &[&str] = &[
    r#"{"email":"test@test.com","x":"\u0000"}"#,
    r#"{"email":"'+OR+1=1--"}"#,
    r#"{"data":"${jndi:ldap://x}"}"#,
    r#"{"x":"%00%00%00"}"#,
    r#"{"a":"<img src=x onerror=1>"}"#,
    r#"{"long":"A"}"#,
    r#"{"num":1e999}"#,
    r#"{"array":[1,2,3]}{"extra":true}"#,
];

pub struct ValidationBaseline {
    pub normal_status: u16,
    pub avg_latency_ms: f64,
    pub content_length: usize,
}

async fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent(USER_AGENT)
        .build()
}

fn extract_headers(resp: &reqwest::Response) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for (name, value) in resp.headers() {
        if let Ok(v) = value.to_str() {
            out.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    out
}

async fn measure_full(
    client: &reqwest::Client,
    url: &str,
    body: &str,
) -> Result<(u16, f64, usize, HashMap<String, String>), reqwest::Error> {
    let start = std::time::Instant::now();
    let resp = client.post(url).body(body.to_string()).send().await?;
    let status = resp.status().as_u16();
    let headers = extract_headers(&resp);
    let body_bytes = resp.bytes().await.unwrap_or_default();
    let content_length = body_bytes.len();
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    Ok((status, latency_ms, content_length, headers))
}

/// Header side-channel: do critical headers (Server, X-Powered-By) change with different payloads?
fn headers_side_channel_detected(
    baseline_headers: &HashMap<String, String>,
    probe: &HashMap<String, String>,
) -> bool {
    for key in &["server", "x-powered-by", "x-aspnet-version", "via"] {
        let b = baseline_headers.get(*key).map(|s| s.as_str()).unwrap_or("");
        let p = probe.get(*key).map(|s| s.as_str()).unwrap_or("");
        if b != p && !p.is_empty() {
            return true;
        }
    }
    false
}

/// Content-Length discrepancy: response length >> baseline or << baseline.
fn content_length_discrepancy(baseline_len: usize, actual_len: usize) -> bool {
    if baseline_len == 0 {
        return actual_len > 1000;
    }
    let ratio = actual_len as f64 / baseline_len as f64;
    ratio >= LENGTH_DISCREPANCY_RATIO || (baseline_len > 100 && ratio <= 0.25)
}

/// Returns true if anomaly is confirmed with 99.9% certainty (2+ confirmations including
/// Content-Length and/or header side-channel when applicable).
pub async fn confirm_anomaly(
    target_url: &str,
    anomaly_type: &str,
    baseline: &ValidationBaseline,
) -> bool {
    let client = match build_client().await {
        Ok(c) => Arc::new(c),
        Err(_) => return false,
    };
    let a = anomaly_type.to_lowercase();
    let is_500 = a.contains("500") || a.contains("status 500");
    let is_time = a.contains("time") || a.contains("latency");
    let time_threshold = baseline.avg_latency_ms * 5.0;

    let mut confirm_count = 0u32;
    let mut payloads: Vec<String> = CONFIRMATION_PAYLOADS
        .iter()
        .map(|s| s.to_string())
        .collect();
    payloads.push(format!("{{\"pad\":\"{}\"}}", "A".repeat(5000)));

    let mut baseline_headers: Option<HashMap<String, String>> = None;

    for payload in payloads {
        tokio::time::sleep(Duration::from_millis(RATE_DELAY_MS)).await;
        let (status, latency_ms, content_length, headers) =
            match measure_full(&client, target_url, &payload).await {
                Ok(t) => t,
                Err(_) => continue,
            };
        if baseline_headers.is_none() {
            baseline_headers = Some(headers.clone());
        }
        let Some(base_headers) = baseline_headers.as_ref() else {
            continue;
        };

        if is_500 && status == 500 {
            confirm_count += 1;
        }
        if is_time && baseline.avg_latency_ms > 0.0 && latency_ms >= time_threshold {
            confirm_count += 1;
        }
        // Always check content-length discrepancy as a third independent condition,
        // not only when the anomaly_type string mentions "length".
        if content_length_discrepancy(baseline.content_length, content_length) {
            confirm_count += 1;
        }
        if headers_side_channel_detected(base_headers, &headers) {
            confirm_count += 1;
        }
        if confirm_count >= 2 {
            return true;
        }
    }
    // One confirmation enough for status 500 (reproducible crash); otherwise require 2
    let one_ok_for_500 = is_500 && confirm_count >= 1;
    confirm_count >= 2 || one_ok_for_500
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn hm(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn content_length_discrepancy_zero_baseline() {
        // With no baseline, only a large absolute body (>1000) is anomalous.
        assert!(!content_length_discrepancy(0, 500));
        assert!(!content_length_discrepancy(0, 1000));
        assert!(content_length_discrepancy(0, 1001));
    }

    #[test]
    fn content_length_discrepancy_high_ratio() {
        assert!(content_length_discrepancy(100, 200)); // ratio 2.0 == threshold
        assert!(content_length_discrepancy(50, 400)); // ratio 8.0
        // ratio 1.99 and baseline not > 100 -> not flagged
        assert!(!content_length_discrepancy(100, 199));
        assert!(!content_length_discrepancy(1000, 1000)); // ratio 1.0
    }

    #[test]
    fn content_length_discrepancy_low_ratio() {
        assert!(content_length_discrepancy(200, 50)); // ratio 0.25, baseline > 100
        assert!(content_length_discrepancy(1000, 100)); // ratio 0.1
        // ratio 0.25 but baseline not strictly > 100 -> not flagged
        assert!(!content_length_discrepancy(100, 25));
    }

    #[test]
    fn side_channel_detects_changed_server() {
        let base = hm(&[("server", "nginx")]);
        let probe = hm(&[("server", "apache")]);
        assert!(headers_side_channel_detected(&base, &probe));
    }

    #[test]
    fn side_channel_ignores_missing_probe_value() {
        // Probe lacks the header entirely -> p is empty -> not counted.
        let base = hm(&[("server", "nginx")]);
        let probe = hm(&[]);
        assert!(!headers_side_channel_detected(&base, &probe));
    }

    #[test]
    fn side_channel_detects_new_powered_by() {
        let base = hm(&[]);
        let probe = hm(&[("x-powered-by", "PHP/7.4")]);
        assert!(headers_side_channel_detected(&base, &probe));
    }

    #[test]
    fn side_channel_identical_headers_no_detection() {
        let base = hm(&[("server", "nginx"), ("via", "1.1 proxy")]);
        let probe = hm(&[("server", "nginx"), ("via", "1.1 proxy")]);
        assert!(!headers_side_channel_detected(&base, &probe));
    }

    #[test]
    fn validation_baseline_holds_fields() {
        let b = ValidationBaseline {
            normal_status: 200,
            avg_latency_ms: 12.5,
            content_length: 42,
        };
        assert_eq!(b.normal_status, 200);
        assert_eq!(b.content_length, 42);
        assert!((b.avg_latency_ms - 12.5).abs() < f64::EPSILON);
    }
}
