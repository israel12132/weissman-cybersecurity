//! NDR seed — deterministic beaconing & exfiltration detection over flow samples.
//!
//! The platform had no network-detection capability. This is a real, statistics-based seed: given
//! per-destination flow samples (timestamp + outbound bytes), it detects
//!
//!   * **C2 beaconing** — highly regular call-home intervals (low jitter / coefficient of variation)
//!     in a plausible cadence band, and
//!   * **bulk exfiltration** — outbound volume to a destination crossing a threshold within the
//!     observation window.
//!
//! It is pure (no capture stack, no I/O) so it slots behind any flow source — agent netflow, Zeek
//! `conn.log`, VPC flow logs — and is fully unit-tested. No randomness, no fabricated hits.

use serde::Serialize;

/// One observed flow to a destination at a point in time.
#[derive(Debug, Clone)]
pub struct FlowSample {
    pub ts: i64,
    pub dst: String,
    pub bytes_out: u64,
}

impl FlowSample {
    pub fn new(ts: i64, dst: &str, bytes_out: u64) -> Self {
        Self {
            ts,
            dst: dst.to_string(),
            bytes_out,
        }
    }
}

/// Tunables for the detectors.
#[derive(Debug, Clone)]
pub struct NdrConfig {
    /// Minimum number of inter-arrival intervals (connections - 1) to consider a beacon.
    pub min_intervals: usize,
    /// Maximum coefficient of variation (stddev/mean) of intervals to call it "regular".
    pub max_cv: f64,
    /// Plausible beacon cadence band, in seconds.
    pub min_interval_secs: f64,
    pub max_interval_secs: f64,
    /// Bytes to a single destination (summed over the window) that flags bulk exfiltration.
    pub exfil_bytes_threshold: u64,
}

impl Default for NdrConfig {
    fn default() -> Self {
        Self {
            min_intervals: 4,
            max_cv: 0.15,
            min_interval_secs: 1.0,
            max_interval_secs: 86_400.0,
            exfil_bytes_threshold: 50 * 1024 * 1024, // 50 MiB
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum NdrKind {
    Beacon,
    Exfiltration,
}

impl NdrKind {
    pub fn label(&self) -> &'static str {
        match self {
            NdrKind::Beacon => "c2_beacon",
            NdrKind::Exfiltration => "bulk_exfiltration",
        }
    }
}

/// A network detection.
#[derive(Debug, Clone, Serialize)]
pub struct NdrFinding {
    pub kind: String,
    pub dst: String,
    pub severity: String,
    /// 0–1 confidence.
    pub confidence: f64,
    pub mitre: String,
    pub evidence: serde_json::Value,
}

/// Sample mean of a slice. Returns 0.0 for empty input.
pub fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Sample standard deviation (n-1). Returns 0.0 for fewer than 2 elements.
pub fn stddev(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let m = mean(xs);
    let var = xs.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (xs.len() as f64 - 1.0);
    var.sqrt()
}

/// Coefficient of variation = stddev/mean. Returns f64::INFINITY when mean is ~0 (undefined).
pub fn coefficient_of_variation(xs: &[f64]) -> f64 {
    let m = mean(xs);
    if m.abs() < f64::EPSILON {
        return f64::INFINITY;
    }
    stddev(xs) / m
}

fn group_by_dst(samples: &[FlowSample]) -> std::collections::BTreeMap<String, Vec<&FlowSample>> {
    let mut map: std::collections::BTreeMap<String, Vec<&FlowSample>> =
        std::collections::BTreeMap::new();
    for s in samples {
        map.entry(s.dst.clone()).or_default().push(s);
    }
    map
}

/// Detect regular-cadence beaconing per destination.
pub fn detect_beacons(samples: &[FlowSample], cfg: &NdrConfig) -> Vec<NdrFinding> {
    let mut out = Vec::new();
    for (dst, mut flows) in group_by_dst(samples) {
        flows.sort_by_key(|f| f.ts);
        if flows.len() < cfg.min_intervals + 1 {
            continue;
        }
        let intervals: Vec<f64> = flows
            .windows(2)
            .map(|w| (w[1].ts - w[0].ts) as f64)
            .collect();
        let m = mean(&intervals);
        if m < cfg.min_interval_secs || m > cfg.max_interval_secs {
            continue;
        }
        let cv = coefficient_of_variation(&intervals);
        if cv > cfg.max_cv {
            continue;
        }
        // Lower jitter ⇒ higher confidence.
        let confidence = (1.0 - (cv / cfg.max_cv)).clamp(0.0, 1.0);
        let severity = if confidence >= 0.8 { "high" } else { "medium" };
        out.push(NdrFinding {
            kind: NdrKind::Beacon.label().to_string(),
            dst: dst.clone(),
            severity: severity.to_string(),
            confidence: (confidence * 10000.0).round() / 10000.0,
            mitre: "T1071".to_string(),
            evidence: serde_json::json!({
                "connections": flows.len(),
                "mean_interval_secs": (m * 1000.0).round() / 1000.0,
                "coefficient_of_variation": (cv * 10000.0).round() / 10000.0,
                "jitter_threshold": cfg.max_cv,
            }),
        });
    }
    out
}

/// Detect bulk outbound exfiltration per destination over the observation window.
pub fn detect_exfiltration(samples: &[FlowSample], cfg: &NdrConfig) -> Vec<NdrFinding> {
    let mut out = Vec::new();
    for (dst, flows) in group_by_dst(samples) {
        let total: u64 = flows.iter().map(|f| f.bytes_out).sum();
        if total < cfg.exfil_bytes_threshold {
            continue;
        }
        let over = total as f64 / cfg.exfil_bytes_threshold as f64;
        let severity = if over >= 4.0 {
            "critical"
        } else if over >= 2.0 {
            "high"
        } else {
            "medium"
        };
        let confidence = (1.0 - 1.0 / (over + 1.0)).clamp(0.0, 1.0);
        out.push(NdrFinding {
            kind: NdrKind::Exfiltration.label().to_string(),
            dst: dst.clone(),
            severity: severity.to_string(),
            confidence: (confidence * 10000.0).round() / 10000.0,
            mitre: "T1041".to_string(),
            evidence: serde_json::json!({
                "bytes_out_total": total,
                "threshold": cfg.exfil_bytes_threshold,
                "over_threshold_ratio": (over * 1000.0).round() / 1000.0,
                "flows": flows.len(),
            }),
        });
    }
    out
}

/// Run both detectors.
pub fn analyze(samples: &[FlowSample], cfg: &NdrConfig) -> Vec<NdrFinding> {
    let mut v = detect_beacons(samples, cfg);
    v.extend(detect_exfiltration(samples, cfg));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cv_of_constant_intervals_is_zero() {
        assert_eq!(coefficient_of_variation(&[10.0, 10.0, 10.0, 10.0]), 0.0);
    }

    #[test]
    fn regular_beacon_is_detected() {
        // 60s cadence, perfectly regular.
        let samples: Vec<FlowSample> = (0..10)
            .map(|i| FlowSample::new(1000 + i * 60, "evil.example", 512))
            .collect();
        let hits = detect_beacons(&samples, &NdrConfig::default());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, "c2_beacon");
        assert!(
            hits[0].confidence > 0.9,
            "near-zero jitter ⇒ high confidence"
        );
    }

    #[test]
    fn jittery_traffic_is_not_a_beacon() {
        // Irregular human-like intervals: high CV.
        let times = [0i64, 5, 90, 95, 400, 410, 1200, 1205, 5000, 9000];
        let samples: Vec<FlowSample> = times
            .iter()
            .map(|&t| FlowSample::new(1000 + t, "cdn.example", 800))
            .collect();
        let hits = detect_beacons(&samples, &NdrConfig::default());
        assert!(
            hits.is_empty(),
            "high-jitter traffic must not flag as beacon"
        );
    }

    #[test]
    fn too_few_samples_no_beacon() {
        let samples = vec![
            FlowSample::new(0, "x", 1),
            FlowSample::new(60, "x", 1),
            FlowSample::new(120, "x", 1),
        ];
        assert!(detect_beacons(&samples, &NdrConfig::default()).is_empty());
    }

    #[test]
    fn bulk_exfil_detected_and_scaled() {
        let cfg = NdrConfig::default();
        let samples = vec![
            FlowSample::new(0, "drop.example", 200 * 1024 * 1024),
            FlowSample::new(5, "drop.example", 60 * 1024 * 1024),
        ];
        let hits = detect_exfiltration(&samples, &cfg);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, "bulk_exfiltration");
        assert_eq!(hits[0].severity, "critical"); // > 4x threshold
    }

    #[test]
    fn normal_volume_no_exfil() {
        let samples = vec![FlowSample::new(0, "api.example", 1024 * 1024)];
        assert!(detect_exfiltration(&samples, &NdrConfig::default()).is_empty());
    }

    #[test]
    fn analyze_runs_both() {
        let mut samples: Vec<FlowSample> = (0..8)
            .map(|i| FlowSample::new(i * 300, "c2.example", 1024))
            .collect();
        samples.push(FlowSample::new(10, "leak.example", 80 * 1024 * 1024));
        let hits = analyze(&samples, &NdrConfig::default());
        assert!(hits.iter().any(|h| h.kind == "c2_beacon"));
        assert!(hits.iter().any(|h| h.kind == "bulk_exfiltration"));
    }
}
