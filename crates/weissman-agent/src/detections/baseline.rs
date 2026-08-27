//! UEBA baseline sampler.
//!
//! Collects a host snapshot the server-side `ueba_detector` baselines. Sampling is
//! `/proc`-native on Linux (no netstat/ss), Event Log 4625 on Windows, Unified Logging
//! on macOS. Metrics are sanitised, EMA-smoothed, and tagged with UTC hour-of-week,
//! seq/nonce, and a hardware id so the ingest path can reject replay and scope forgery.

use anyhow::Result;
use serde_json::{Map, Value};

use super::ueba;

pub async fn run(engine: &str) -> Result<Vec<Value>> {
    // Small jitter so a fleet of agents that wake on the same scheduler tick do not
    // stampede the ingest queue. Tests skip it so the suite stays fast.
    if !cfg!(test) {
        let jitter_ms = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
            % 20_000) as u64;
        tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
    }

    let lite = ueba::is_lite() || ueba::rss_over_cap();
    let mut metrics = ueba::collect_metrics(lite);
    let hour = ueba::hour_of_week_corrected();
    let seq = metrics
        .get("seq")
        .and_then(Value::as_u64)
        .unwrap_or_else(ueba::next_seq);
    let nonce = metrics
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(ueba::next_nonce);
    let hardware_id = metrics
        .get("hardware_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    let sampled_at = chrono::Utc::now().to_rfc3339();

    if let Some(obj) = metrics.as_object_mut() {
        obj.insert("sampled_at".into(), Value::String(sampled_at.clone()));
    }

    let metrics_gz = gzip_if_large(&metrics);

    let mut extras: Map<String, Value> = Map::new();
    extras.insert("metrics".to_string(), metrics.clone());
    extras.insert("kind".to_string(), Value::String("ueba_sample".to_string()));
    extras.insert("hour_of_week".to_string(), Value::from(hour));
    extras.insert("seq".to_string(), Value::from(seq));
    extras.insert("nonce".to_string(), Value::String(nonce));
    extras.insert("sampled_at".to_string(), Value::String(sampled_at));
    if let Some(hw) = hardware_id {
        extras.insert("hardware_id".to_string(), Value::String(hw));
    }
    if let Some(gz) = metrics_gz {
        extras.insert("metrics_gz".to_string(), Value::String(gz));
    }

    let summary = format!(
        "Host UEBA sample: ports={} processes={} users={}",
        metrics
            .get("open_port_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        metrics
            .get("process_count")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        metrics
            .get("unique_users")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    );

    Ok(vec![super::finding(
        engine,
        "Host UEBA baseline sample",
        "info",
        "T1057",
        &summary,
        extras,
    )])
}

fn gzip_if_large(v: &Value) -> Option<String> {
    use base64::Engine;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let bytes = serde_json::to_vec(v).ok()?;
    if bytes.len() < 1024 {
        return None;
    }
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(&bytes).ok()?;
    let gz = enc.finish().ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(gz))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sample_has_required_shape() {
        let findings = run("ueba_baseline").await.expect("sample");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.get("metrics").is_some());
        assert!(f.get("hour_of_week").is_some());
        assert!(f.get("seq").is_some());
        assert!(f.get("nonce").is_some());
        let hour = f.get("hour_of_week").and_then(Value::as_i64).unwrap_or(-1);
        assert!((0..=167).contains(&hour));
    }
}
