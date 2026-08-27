//! Statistical primitives for the UEBA detector.
//!
//! Every numeric path is `f64`, sanitised before Postgres, and refuses to produce NaN/Inf
//! (division-by-zero → z = 0). MAD is the robust fallback when a few outliers would otherwise
//! inflate σ. Welford lets the ingest path update mean/σ online without re-scanning the sample
//! table.

use std::cmp::Ordering;

/// Floor below which σ is treated as zero (constant signal).
pub const SIGMA_EPS: f64 = 1e-12;
/// Default |z| gate for load/memory/counts.
pub const DEFAULT_Z_THRESHOLD: f64 = 3.0;
/// |z| gate past which severity is `high`.
pub const HIGH_Z: f64 = 6.0;
/// Isolation / lateral-movement |z| that triggers isolate_host consideration.
pub const CRITICAL_Z: f64 = 10.0;
/// Winsorization clip in σ-units (≈ 99th percentile of a normal).
pub const WINSOR_SIGMA: f64 = 2.33;
/// Scale factor that makes MAD comparable to σ for a normal distribution.
pub const MAD_TO_SIGMA: f64 = 1.4826;
/// Minimum |Δ| that can raise an anomaly on a near-constant metric.
pub const DEFAULT_DELTA: f64 = 0.0;

/// Finite, Postgres-safe `f64`. Non-finite values become 0; magnitude is clamped so the
/// `double precision` column cannot overflow on INSERT.
pub fn sanitize_f64(x: f64) -> f64 {
    if !x.is_finite() {
        return 0.0;
    }
    x.clamp(-1.0e15, 1.0e15)
}

/// z-score. σ ≈ 0 or non-finite inputs → 0 (never NaN, never a panic).
pub fn z_score(observed: f64, mean: f64, stddev: f64) -> f64 {
    if !observed.is_finite() || !mean.is_finite() || !stddev.is_finite() {
        return 0.0;
    }
    let observed = sanitize_f64(observed);
    let mean = sanitize_f64(mean);
    let stddev = sanitize_f64(stddev);
    if stddev.abs() < SIGMA_EPS {
        return 0.0;
    }
    let z = (observed - mean) / stddev;
    sanitize_f64(z)
}

/// Robust z-score via median absolute deviation. Falls back to 0 when MAD is 0.
#[allow(dead_code)]
pub fn robust_z(observed: f64, median: f64, mad: f64) -> f64 {
    let mad = sanitize_f64(mad);
    if mad.abs() < SIGMA_EPS {
        return 0.0;
    }
    sanitize_f64(0.6745 * (sanitize_f64(observed) - sanitize_f64(median)) / mad)
}

/// Per-metric |z| threshold. Auth-failure signals are tighter so a brute-force burst
/// cannot hide inside a 3σ memory-style gate. `uptime_seconds` is excluded from z-score
/// entirely (handled as a delta/reboot event).
pub fn z_threshold_for(metric: &str) -> f64 {
    match metric {
        "failed_logins" | "sudo_failures" | "uac_failures" | "lsass_handle_count" => 2.0,
        "open_port_count" | "unique_users" | "outbound_bytes" | "conn_fail_count" => 2.5,
        "uptime_seconds" => f64::INFINITY,
        _ => DEFAULT_Z_THRESHOLD,
    }
}

/// Minimum absolute delta vs baseline mean before a z-score is allowed to fire.
/// Completely constant metrics (unique_users on a locked-down server) would otherwise
/// alarm on a 1-user change once σ collapses to 0 — we already map σ=0 → z=0, but a
/// tiny σ still needs a floor.
pub fn min_delta_for(metric: &str) -> f64 {
    match metric {
        "unique_users" | "open_port_count" | "process_count" => 1.0,
        "failed_logins" | "sudo_failures" => 1.0,
        "memory_used_pct" => 3.0,
        "load_1m" => 0.20,
        "uptime_seconds" => f64::INFINITY,
        _ => DEFAULT_DELTA,
    }
}

/// Relative weight of a metric in the combined (multi-dimensional) score.
pub fn metric_weight(metric: &str) -> f64 {
    match metric {
        "failed_logins" | "sudo_failures" | "lsass_handle_count" => 2.5,
        "open_port_count" | "conn_fail_count" | "unique_remote_ips" => 1.8,
        "process_count" | "top_processes" | "open_ports" => 1.4,
        "memory_used_pct" | "load_1m" | "memory_rss_kb" => 1.0,
        "uptime_seconds" => 0.0,
        _ => 1.0,
    }
}

pub fn severity_for_z(z: f64) -> &'static str {
    let a = z.abs();
    if a >= CRITICAL_Z {
        "critical"
    } else if a >= HIGH_Z {
        "high"
    } else if a >= DEFAULT_Z_THRESHOLD {
        "medium"
    } else {
        "low"
    }
}

/// Clip `x` to `[mean − kσ, mean + kσ]` so a single extreme sample cannot destroy future σ.
pub fn winsorize(x: f64, mean: f64, stddev: f64) -> f64 {
    let x = sanitize_f64(x);
    let mean = sanitize_f64(mean);
    let stddev = sanitize_f64(stddev);
    if stddev.abs() < SIGMA_EPS {
        return x;
    }
    let lo = mean - WINSOR_SIGMA * stddev;
    let hi = mean + WINSOR_SIGMA * stddev;
    x.clamp(lo, hi)
}

/// Online mean / sample-variance (Welford). `m2` is the sum of squared deviations.
#[derive(Debug, Clone, Copy, Default)]
pub struct Welford {
    pub n: u64,
    pub mean: f64,
    pub m2: f64,
}

impl Welford {
    pub fn from_parts(n: i32, mean: f64, m2: f64) -> Self {
        Self {
            n: n.max(0) as u64,
            mean: sanitize_f64(mean),
            m2: sanitize_f64(m2).max(0.0),
        }
    }

    pub fn update(&mut self, x: f64) {
        let x = sanitize_f64(x);
        self.n = self.n.saturating_add(1);
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = x - self.mean;
        self.m2 = sanitize_f64(self.m2 + delta * delta2).max(0.0);
        self.mean = sanitize_f64(self.mean);
    }

    /// Apply exponential decay toward "recent samples matter more" then update.
    /// `lambda` in (0, 1]; 1.0 = no decay. Typical: 0.97 / sample (~half-life of ~23 samples).
    pub fn decay_then_update(&mut self, x: f64, lambda: f64) {
        let lambda = sanitize_f64(lambda).clamp(0.50, 1.0);
        if self.n > 0 && lambda < 1.0 {
            self.m2 *= lambda;
            self.n = ((self.n as f64) * lambda).floor().max(1.0) as u64;
        }
        self.update(x);
    }

    pub fn variance(&self) -> f64 {
        if self.n < 2 {
            return 0.0;
        }
        sanitize_f64(self.m2 / (self.n - 1) as f64).max(0.0)
    }

    pub fn stddev(&self) -> f64 {
        sanitize_f64(self.variance().sqrt())
    }
}

/// Median + MAD of a slice. Empty → (0, 0).
#[allow(dead_code)]
pub fn median_and_mad(values: &[f64]) -> (f64, f64) {
    let mut v: Vec<f64> = values
        .iter()
        .copied()
        .map(sanitize_f64)
        .filter(|x| x.is_finite())
        .collect();
    if v.is_empty() {
        return (0.0, 0.0);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let median = percentile_sorted(&v, 0.5);
    let mut dev: Vec<f64> = v.iter().map(|x| (x - median).abs()).collect();
    dev.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let mad = percentile_sorted(&dev, 0.5);
    (median, mad)
}

#[allow(dead_code)]
fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let p = p.clamp(0.0, 1.0);
    let idx = (p * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Prefer MAD-scaled σ when the classical σ is inflated by outliers (> 3× robust σ).
pub fn effective_stddev(classical: f64, mad: f64) -> f64 {
    let classical = sanitize_f64(classical).max(0.0);
    let robust = sanitize_f64(mad).max(0.0) * MAD_TO_SIGMA;
    if robust < SIGMA_EPS {
        return classical;
    }
    if classical > 3.0 * robust {
        robust
    } else {
        classical
    }
}

/// Combined weighted score across a metric vector: √Σ(wᵢ zᵢ²). Isolation-forest-class
/// signal without a training set — joint deviation, not a single axis.
pub fn combined_score(pairs: &[(f64, f64)]) -> f64 {
    // (weight, z)
    let mut acc = 0.0;
    for (w, z) in pairs {
        let w = sanitize_f64(*w).max(0.0);
        let z = sanitize_f64(*z);
        acc += w * z * z;
    }
    sanitize_f64(acc.sqrt())
}

/// Concept-drift detector: recent mean vs long-run mean in σ units.
#[allow(dead_code)]
pub fn drift_z(recent_mean: f64, long_mean: f64, long_stddev: f64) -> f64 {
    z_score(recent_mean, long_mean, long_stddev)
}

/// Half-life decay weight for a sample `age_days` old. 7-day half-life by default.
#[allow(dead_code)]
pub fn decay_weight(age_days: f64, half_life_days: f64) -> f64 {
    let half = sanitize_f64(half_life_days).clamp(0.5, 90.0);
    let age = sanitize_f64(age_days).max(0.0);
    sanitize_f64(0.5_f64.powf(age / half))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn z_score_zero_sigma_is_zero() {
        assert_eq!(z_score(100.0, 50.0, 0.0), 0.0);
        assert_eq!(z_score(100.0, 50.0, 1e-16), 0.0);
        assert_eq!(z_score(f64::NAN, 1.0, 1.0), 0.0);
        assert!(z_score(10.0, 4.0, 2.0) > 2.9);
    }

    #[test]
    fn sanitize_rejects_non_finite() {
        assert_eq!(sanitize_f64(f64::NAN), 0.0);
        assert_eq!(sanitize_f64(f64::INFINITY), 0.0);
        assert_eq!(sanitize_f64(f64::NEG_INFINITY), 0.0);
        assert_eq!(sanitize_f64(3.5), 3.5);
    }

    #[test]
    fn welford_matches_known_series() {
        let mut w = Welford::default();
        for x in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            w.update(x);
        }
        assert_eq!(w.n, 8);
        assert!((w.mean - 5.0).abs() < 1e-9);
        assert!((w.stddev() - 2.138).abs() < 0.01);
    }

    #[test]
    fn mad_is_robust_to_outlier() {
        let clean = [10.0, 10.2, 9.8, 10.1, 9.9, 10.0, 10.05];
        let (m, mad) = median_and_mad(&clean);
        assert!((m - 10.0).abs() < 0.1);
        assert!(mad < 0.2);
        let mut noisy = clean.to_vec();
        noisy.push(10_000.0);
        let (m2, mad2) = median_and_mad(&noisy);
        assert!((m2 - 10.0).abs() < 0.2);
        assert!(mad2 < 0.3);
        let classical = {
            let mut w = Welford::default();
            for x in &noisy {
                w.update(*x);
            }
            w.stddev()
        };
        let effective = effective_stddev(classical, mad2);
        assert!(
            effective < classical,
            "MAD fallback must shrink an outlier-inflated σ"
        );
    }

    #[test]
    fn winsorize_clips_extreme() {
        let x = winsorize(1000.0, 10.0, 2.0);
        assert!(x < 20.0);
        assert!(x > 10.0);
    }

    #[test]
    fn failed_logins_use_tighter_gate() {
        assert_eq!(z_threshold_for("failed_logins"), 2.0);
        assert_eq!(z_threshold_for("memory_used_pct"), 3.0);
        assert!(z_threshold_for("uptime_seconds").is_infinite());
        assert!(min_delta_for("uptime_seconds").is_infinite());
    }

    #[test]
    fn decay_weight_halves_at_half_life() {
        assert!((decay_weight(7.0, 7.0) - 0.5).abs() < 1e-9);
        assert!(decay_weight(0.0, 7.0) > 0.99);
        assert!(decay_weight(21.0, 7.0) < 0.13);
    }

    #[test]
    fn combined_score_joint_deviation() {
        let mild = combined_score(&[(1.0, 1.0), (1.0, 1.0)]);
        let joint = combined_score(&[(2.5, 4.0), (1.8, 3.0)]);
        assert!(joint > mild);
        assert!(combined_score(&[]).abs() < 1e-12);
    }

    #[test]
    fn welford_decay_keeps_mean_stable() {
        let mut w = Welford::default();
        for _ in 0..50 {
            w.update(10.0);
        }
        w.decay_then_update(10.0, 0.97);
        assert!((w.mean - 10.0).abs() < 0.01);
        assert!(w.n < 50);
    }
}
