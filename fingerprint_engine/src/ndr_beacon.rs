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

/// Floor for live beacon sampling so Lomb–Scargle / FFT have enough intervals.
pub const MIN_BEACON_SAMPLES: usize = 12;
/// Ceiling so a single engine cannot hang on an unbounded sample loop.
pub const MAX_BEACON_SAMPLES: usize = 48;
/// Minimum inter-arrival count before a periodogram is honest.
pub const MIN_SPECTRAL_INTERVALS: usize = 8;
/// Peak / median DFT power required to call a bin significant.
pub const SPECTRAL_FFT_SNR: f64 = 4.0;

/// Standard score. Returns 0 when σ is not usable.
#[must_use]
pub fn zscore(x: f64, mean: f64, sd: f64) -> f64 {
    if !sd.is_finite() || sd.abs() < f64::EPSILON {
        return 0.0;
    }
    (x - mean) / sd
}

/// Stretch jitter when the last sample is an outlier vs the live mean.
#[must_use]
pub fn jitter_should_adapt(z: f64, threshold: f64) -> bool {
    z.abs() > threshold
}

/// Peak of a Lomb–Scargle periodogram over uneven samples.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LombScarglePeak {
    pub period: f64,
    pub power: f64,
    pub false_alarm_prob: f64,
    pub significant: bool,
}

/// Lomb–Scargle periodogram peak (uneven sampling). Returns `None` when the
/// series is too short or has no positive time span.
#[must_use]
pub fn lomb_scargle_peak(times: &[f64], values: &[f64]) -> Option<LombScarglePeak> {
    if times.len() < 4 || times.len() != values.len() {
        return None;
    }
    let t0 = *times.first()?;
    let t1 = *times.last()?;
    let tspan = t1 - t0;
    if tspan <= 0.0 {
        return None;
    }
    let mut dts: Vec<f64> = times
        .windows(2)
        .map(|w| w[1] - w[0])
        .filter(|d| *d > 0.0)
        .collect();
    if dts.is_empty() {
        return None;
    }
    dts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let min_p = dts[dts.len() / 2].max(1e-4);
    let max_p = (tspan / 2.0).max(min_p * 1.01);
    let ymean = mean(values);
    let yy: f64 = values.iter().map(|v| (v - ymean).powi(2)).sum();
    if yy <= 0.0 {
        return None;
    }
    let steps = 64usize;
    let mut best: Option<LombScarglePeak> = None;
    for i in 1..=steps {
        let frac = i as f64 / steps as f64;
        let period = min_p * (max_p / min_p).powf(frac);
        let omega = 2.0 * std::f64::consts::PI / period;
        let mut s2 = 0.0;
        let mut c2 = 0.0;
        for &t in times {
            s2 += (2.0 * omega * t).sin();
            c2 += (2.0 * omega * t).cos();
        }
        let tau = 0.5 * s2.atan2(c2) / omega;
        let mut yc = 0.0;
        let mut ys = 0.0;
        let mut cc = 0.0;
        let mut ss = 0.0;
        for (idx, &t) in times.iter().enumerate() {
            let wt = omega * (t - tau);
            let y = values[idx] - ymean;
            yc += y * wt.cos();
            ys += y * wt.sin();
            cc += wt.cos().powi(2);
            ss += wt.sin().powi(2);
        }
        if cc <= 0.0 || ss <= 0.0 {
            continue;
        }
        let power = 0.5 * (yc.powi(2) / cc + ys.powi(2) / ss);
        let fap = (-power).exp().clamp(0.0, 1.0);
        let significant = power > 0.5 && fap < 0.05;
        let cand = LombScarglePeak {
            period,
            power,
            false_alarm_prob: fap,
            significant,
        };
        match best {
            None => best = Some(cand),
            Some(prev) if cand.power > prev.power => best = Some(cand),
            _ => {}
        }
    }
    best
}

/// Discrete Fourier peak vs median bin power. `snr` is peak/median.
#[must_use]
pub fn fft_peak_significant(values: &[f64], snr_thresh: f64) -> Option<(usize, f64)> {
    let n = values.len();
    if n < 8 {
        return None;
    }
    let m = mean(values);
    let xs: Vec<f64> = values.iter().map(|v| v - m).collect();
    let mut powers: Vec<(usize, f64)> = Vec::with_capacity(n / 2);
    for k in 1..=n / 2 {
        let mut re = 0.0;
        let mut im = 0.0;
        for (i, &x) in xs.iter().enumerate() {
            let ang = 2.0 * std::f64::consts::PI * k as f64 * i as f64 / n as f64;
            re += x * ang.cos();
            im += x * ang.sin();
        }
        powers.push((k, (re * re + im * im).sqrt()));
    }
    let mut sorted: Vec<f64> = powers.iter().map(|(_, p)| *p).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = sorted[sorted.len() / 2];
    let (k, peak) = powers
        .iter()
        .copied()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))?;
    let snr = if median > 1e-12 { peak / median } else { peak };
    if snr >= snr_thresh {
        Some((k, snr))
    } else {
        None
    }
}

/// True when either periodogram recovered a significant peak.
#[must_use]
pub fn spectral_hit(ls: Option<LombScarglePeak>, fft: Option<(usize, f64)>) -> bool {
    ls.map(|p| p.significant).unwrap_or(false) || fft.is_some()
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

    #[test]
    fn periodic_series_has_fft_peak() {
        let values: Vec<f64> = (0..32)
            .map(|i| (2.0 * std::f64::consts::PI * (i as f64) / 8.0).sin())
            .collect();
        let fft = fft_peak_significant(&values, 2.0);
        assert!(fft.is_some(), "sine wave must produce an FFT peak");
        assert!(spectral_hit(None, fft));
    }

    #[test]
    fn regular_intervals_have_lomb_peak() {
        let times: Vec<f64> = (0..16).map(|i| i as f64 * 0.5).collect();
        let values: Vec<f64> = times.iter().map(|t| (2.0 * std::f64::consts::PI * t).sin()).collect();
        let ls = lomb_scargle_peak(&times, &values);
        assert!(ls.is_some());
    }
}
