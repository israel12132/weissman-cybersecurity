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

/// Standard score of `x` against a learned window (`mean`, `std`).
///
/// Used by the fused C2 engine to decide whether a beacon/RTT sample has drifted
/// more than 3σ from the 7-day UEBA-style baseline — at which point the scan
/// adapts jitter rather than repeating a blocked cadence.
#[must_use]
pub fn zscore(x: f64, mean: f64, std: f64) -> f64 {
    if !std.is_finite() || std.abs() < f64::EPSILON {
        return 0.0;
    }
    (x - mean) / std
}

/// `|z| > threshold` (default 3.0) means the firewall/NDR response has shifted
/// enough that repeating the previous cadence is a detection risk.
#[must_use]
pub fn jitter_should_adapt(z: f64, threshold: f64) -> bool {
    z.is_finite() && z.abs() > threshold
}

/// Significant spectral peak in an unevenly sampled series (Lomb–Scargle).
#[derive(Debug, Clone, Copy)]
pub struct SpectralPeak {
    pub period: f64,
    pub power: f64,
    pub false_alarm_prob: f64,
    pub significant: bool,
}

/// Lomb–Scargle periodogram peak (Scargle 1982 / Numerical Recipes).
///
/// Z-score / CV assume a unimodal Gaussian around a fixed mean. APT beacons that
/// jitter with a deterministic chaotic map (logistic / Lorenz-class) or a
/// high-amplitude sinusoid inflate time-domain variance and evade `|z|>3` and
/// `CV < 0.15`. The periodogram still sees the hidden frequency.
///
/// `t` and `y` must be the same length. Returns `None` when the series is too
/// short, constant, or has no finite span.
#[must_use]
pub fn lomb_scargle_peak(t: &[f64], y: &[f64]) -> Option<SpectralPeak> {
    if t.len() != y.len() || y.len() < 8 {
        return None;
    }
    if y.iter().any(|v| !v.is_finite()) || t.iter().any(|v| !v.is_finite()) {
        return None;
    }
    let n = y.len() as f64;
    let ybar = mean(y);
    let sigma = stddev(y);
    if !sigma.is_finite() || sigma < 1e-12 {
        return None;
    }
    let var = sigma * sigma;
    let tmin = t.iter().copied().fold(f64::INFINITY, f64::min);
    let tmax = t.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let span = tmax - tmin;
    if span <= 1e-9 {
        return None;
    }
    let nfreq = (4 * y.len()).clamp(32, 256);
    let fmin = 1.0 / span;
    let fmax = (n / 2.0) / span;
    if fmax <= fmin {
        return None;
    }
    let mut best_p = 0.0;
    let mut best_f = fmin;
    for i in 0..nfreq {
        let f = fmin + (fmax - fmin) * (i as f64) / nfreq as f64;
        let w = 2.0 * std::f64::consts::PI * f;
        let mut s2 = 0.0;
        let mut c2 = 0.0;
        for &ti in t {
            s2 += (2.0 * w * ti).sin();
            c2 += (2.0 * w * ti).cos();
        }
        let tau = (s2.atan2(c2)) / (2.0 * w);
        let mut sc = 0.0;
        let mut ss = 0.0;
        let mut cc = 0.0;
        let mut cs = 0.0;
        for (&ti, &yi) in t.iter().zip(y.iter()) {
            let a = w * (ti - tau);
            let yc = yi - ybar;
            let c = a.cos();
            let s = a.sin();
            sc += yc * c;
            ss += yc * s;
            cc += c * c;
            cs += s * s;
        }
        let p = 0.5 * (sc * sc / cc.max(1e-18) + ss * ss / cs.max(1e-18)) / var;
        if p > best_p {
            best_p = p;
            best_f = f;
        }
    }
    let m = nfreq as f64;
    let ez = (-best_p).exp();
    let fap = (1.0 - (1.0 - ez).powf(m)).clamp(0.0, 1.0);
    Some(SpectralPeak {
        period: 1.0 / best_f,
        power: best_p,
        false_alarm_prob: fap,
        significant: fap < 0.01 && best_p > 4.0,
    })
}

/// Naive real DFT power spectrum (DC skipped). Fine for N ≤ 256; no extra crate.
#[must_use]
pub fn dft_power(y: &[f64]) -> Vec<f64> {
    let n = y.len();
    if n < 2 {
        return Vec::new();
    }
    let m = mean(y);
    let half = n / 2;
    let mut out = vec![0.0; half];
    for k in 0..half {
        let mut re = 0.0;
        let mut im = 0.0;
        for (n_i, &v) in y.iter().enumerate() {
            let ang = -2.0 * std::f64::consts::PI * (k as f64) * (n_i as f64) / n as f64;
            let yc = v - m;
            re += yc * ang.cos();
            im += yc * ang.sin();
        }
        out[k] = re * re + im * im;
    }
    out
}

/// Dominant non-DC DFT bin. `Some((k, peak/mean))` when the peak is ≥ `ratio` times the rest.
#[must_use]
pub fn fft_peak_significant(y: &[f64], ratio: f64) -> Option<(usize, f64)> {
    if y.len() < 8 {
        return None;
    }
    let p = dft_power(y);
    if p.len() < 3 {
        return None;
    }
    let (k, peak) = p
        .iter()
        .enumerate()
        .skip(2) // skip DC and the window-length trend (k=1)
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))?;
    if *peak <= 0.0 {
        return None;
    }
    let rest: Vec<f64> = p
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != k)
        .map(|(_, v)| *v)
        .collect();
    let mean_rest = mean(&rest);
    if mean_rest <= 1e-18 {
        return None;
    }
    let snr = peak / mean_rest;
    if snr >= ratio {
        Some((k, snr))
    } else {
        None
    }
}

/// Hidden-periodicity detector for high-CV / chaotic jitter that evades Z-score.
///
/// Runs Lomb–Scargle on (arrival time, interval) plus a DFT of the interval
/// sequence. Does **not** require low coefficient of variation.
pub fn detect_spectral_beacons(samples: &[FlowSample], cfg: &NdrConfig) -> Vec<NdrFinding> {
    let mut out = Vec::new();
    let min_iv = cfg.min_intervals.max(7);
    for (dst, mut flows) in group_by_dst(samples) {
        flows.sort_by_key(|f| f.ts);
        if flows.len() < min_iv + 1 {
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
        let times: Vec<f64> = flows.iter().skip(1).map(|f| f.ts as f64).collect();
        let ls = lomb_scargle_peak(&times, &intervals);
        let fft = fft_peak_significant(&intervals, 10.0);
        let ls_hit = ls.map(|p| p.significant).unwrap_or(false);
        // FFT-only hits must also show a Lomb–Scargle peak (power>3) so a slow
        // browsing trend (DFT bin 1) cannot impersonate a C2 periodogram.
        let fft_hit = fft.is_some() && ls.map(|p| p.power > 3.0).unwrap_or(false);
        if !ls_hit && !fft_hit {
            continue;
        }
        let cv = coefficient_of_variation(&intervals);
        let mut evidence = serde_json::json!({
            "connections": flows.len(),
            "mean_interval_secs": (m * 1000.0).round() / 1000.0,
            "coefficient_of_variation": (cv * 10000.0).round() / 10000.0,
            "detector": "lomb_scargle_fft",
            "zscore_evasion": cv > cfg.max_cv,
        });
        if let Some(p) = ls {
            evidence["lomb_scargle_period"] =
                serde_json::json!((p.period * 1000.0).round() / 1000.0);
            evidence["lomb_scargle_power"] = serde_json::json!((p.power * 1000.0).round() / 1000.0);
            evidence["lomb_scargle_fap"] =
                serde_json::json!((p.false_alarm_prob * 1e6).round() / 1e6);
            evidence["lomb_scargle_significant"] = serde_json::json!(p.significant);
        }
        if let Some((k, snr)) = fft {
            evidence["fft_bin"] = serde_json::json!(k);
            evidence["fft_snr"] = serde_json::json!((snr * 100.0).round() / 100.0);
        }
        let confidence = ls
            .map(|p| (1.0 - p.false_alarm_prob).clamp(0.55, 0.97))
            .unwrap_or(0.7);
        out.push(NdrFinding {
            kind: "c2_beacon_spectral".to_string(),
            dst: dst.clone(),
            severity: if cv > cfg.max_cv {
                "high".to_string()
            } else {
                "medium".to_string()
            },
            confidence: (confidence * 10000.0).round() / 10000.0,
            mitre: "T1071".to_string(),
            evidence,
        });
    }
    out
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

/// Run cadence, spectral (Z-score-evasion), and volume detectors.
pub fn analyze(samples: &[FlowSample], cfg: &NdrConfig) -> Vec<NdrFinding> {
    let mut v = detect_beacons(samples, cfg);
    v.extend(detect_spectral_beacons(samples, cfg));
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
    fn zscore_three_sigma_triggers_adapt() {
        let z = zscore(13.0, 10.0, 1.0);
        assert!((z - 3.0).abs() < 1e-9);
        assert!(jitter_should_adapt(3.1, 3.0));
        assert!(!jitter_should_adapt(2.9, 3.0));
        assert_eq!(zscore(10.0, 10.0, 0.0), 0.0);
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

    fn sine_jittered_beacon(n: usize, base: f64, amp: f64, period: usize) -> Vec<FlowSample> {
        let mut t = 0.0_f64;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(FlowSample::new(t.round() as i64, "apt.example", 64));
            let phase = 2.0 * std::f64::consts::PI * (i as f64) / period as f64;
            t += base + amp * phase.sin();
        }
        out
    }

    #[test]
    fn high_cv_sine_jitter_evades_zscore_cv_but_fft_catches() {
        // Amplitude 25 on a 30s base ⇒ CV ≫ 0.15 (classic detector miss) but a
        // period-8 sinusoid is a textbook spectral signature (Lorenz/Fibonacci-
        // class deterministic jitter that looks random in the time domain).
        let samples = sine_jittered_beacon(32, 30.0, 25.0, 8);
        let cfg = NdrConfig::default();
        assert!(
            detect_beacons(&samples, &cfg).is_empty(),
            "high-CV sine jitter must not trip the Gaussian CV detector"
        );
        let iv: Vec<f64> = samples
            .windows(2)
            .map(|w| (w[1].ts - w[0].ts) as f64)
            .collect();
        assert!(
            coefficient_of_variation(&iv) > cfg.max_cv,
            "test fixture must actually evade CV"
        );
        let fft = fft_peak_significant(&iv, 6.0);
        assert!(
            fft.is_some(),
            "FFT must see the period-8 component, got {fft:?}"
        );
        let times: Vec<f64> = samples.iter().skip(1).map(|f| f.ts as f64).collect();
        let ls = lomb_scargle_peak(&times, &iv);
        assert!(
            ls.is_some_and(|p| p.power > 3.0),
            "Lomb-Scargle must report a strong peak, got {ls:?}"
        );
        let spectral = detect_spectral_beacons(&samples, &cfg);
        assert!(
            spectral.iter().any(|h| h.kind == "c2_beacon_spectral"),
            "fused spectral detector must fire, got {spectral:?}"
        );
    }

    #[test]
    fn whiteish_irregular_intervals_are_not_spectral_beacons() {
        // Same human-like series as jittery_traffic, extended so N ≥ 8.
        let times = [
            0i64, 5, 90, 95, 400, 410, 1200, 1205, 5000, 9000, 9020, 14000, 18111, 25000, 31000,
            40000,
        ];
        let samples: Vec<FlowSample> = times
            .iter()
            .map(|&t| FlowSample::new(1000 + t, "cdn.example", 800))
            .collect();
        let hits = detect_spectral_beacons(&samples, &NdrConfig::default());
        assert!(
            hits.is_empty(),
            "irregular browsing must not flag as spectral beacon: {hits:?}"
        );
    }

    #[test]
    fn constant_intervals_have_no_fft_peak() {
        let y = vec![60.0; 16];
        assert!(fft_peak_significant(&y, 8.0).is_none());
        let t: Vec<f64> = (0..16).map(|i| i as f64 * 60.0).collect();
        assert!(lomb_scargle_peak(&t, &y).is_none());
    }
}
