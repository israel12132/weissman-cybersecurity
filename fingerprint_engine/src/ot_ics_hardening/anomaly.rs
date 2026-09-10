//! Anomaly scoring for OT poll-rate / packet-rate / timing series.
//!
//! A hard σ floor (1e-5) inflates noise on ultra-stable PLCs: a 20 µs stall
//! against a true 10 ns jitter becomes Z≈2 and is dropped as routine. Scale is
//! therefore relative (CV × |μ|) with a MAD fallback whenever σ is degenerate.
//! Public scores stay finite so Postgres NUMERIC never sees NaN/∞.

/// Switch to MAD / CV when sample σ is below this (still not a denominator).
pub const MAD_SWITCH: f64 = 1e-5;
/// Coefficient-of-variation floor: scale ≥ this fraction of |μ|.
pub const CV_FLOOR: f64 = 1e-4;
/// Last-resort scale so a zero mean + zero MAD series stays finite.
pub const MIN_SCALE: f64 = 1e-18;
/// Absolute cap so persist/compare never see Inf/NaN.
pub const Z_ABS_CAP: f64 = 100.0;
/// Default isolate threshold from the OT blueprint (Z > 6).
pub const Z_ISOLATE: f64 = 6.0;
/// Consistency alias — not used as a Z denominator.
pub const STDDEV_FLOOR: f64 = MAD_SWITCH;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Baseline {
    pub mean: f64,
    pub stddev: f64,
    pub mad: f64,
    pub median: f64,
    pub samples: u64,
}

impl Baseline {
    #[must_use]
    pub fn from_samples(xs: &[f64]) -> Option<Self> {
        if xs.len() < 3 {
            return None;
        }
        let n = xs.len() as f64;
        let mean = xs.iter().sum::<f64>() / n;
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let (median, mad) = median_and_mad(xs)?;
        Some(Self {
            mean,
            stddev: var.sqrt(),
            mad,
            median,
            samples: xs.len() as u64,
        })
    }

    /// Online Welford + EWMA median/MAD (7-day GOOSE window, scan-rate, poll-rate).
    #[must_use]
    pub fn update(self, x: f64) -> Self {
        let n = (self.samples + 1) as f64;
        let mean = self.mean + (x - self.mean) / n;
        let stddev = if self.samples == 0 {
            0.0
        } else {
            let m2 = self.stddev.powi(2) * (self.samples as f64) + (x - self.mean) * (x - mean);
            (m2 / n).max(0.0).sqrt()
        };
        let median = self.median + 0.1 * (x - self.median);
        let mad = 0.9 * self.mad + 0.1 * (x - median).abs();
        Self {
            mean,
            stddev,
            mad,
            median,
            samples: self.samples + 1,
        }
    }

    /// Finite, CV/MAD-scaled, capped Z. Never NaN, never ±∞.
    #[must_use]
    pub fn z_score(self, observed: f64) -> f64 {
        persistable_z(raw_z(self, observed)).unwrap_or(0.0)
    }

    #[must_use]
    pub fn is_high(self, observed: f64, threshold: f64) -> bool {
        self.z_score(observed).abs() > threshold
    }

    /// Denominator actually used: σ, else MAD/0.6745, else CV·|μ|.
    #[must_use]
    pub fn scale(self) -> f64 {
        robust_scale(self.mean, self.stddev, self.mad)
    }
}

fn median_and_mad(xs: &[f64]) -> Option<(f64, f64)> {
    let mut sorted: Vec<f64> = xs.iter().copied().filter(|v| v.is_finite()).collect();
    if sorted.len() < 3 {
        return None;
    }
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = percentile_sorted(&sorted, 0.5);
    let mut devs: Vec<f64> = sorted.iter().map(|x| (x - median).abs()).collect();
    devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = percentile_sorted(&devs, 0.5);
    Some((median, mad))
}

fn percentile_sorted(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

fn cv_scale(mean: f64) -> f64 {
    let rel = CV_FLOOR * mean.abs();
    if rel > MIN_SCALE {
        rel
    } else {
        MIN_SCALE
    }
}

fn robust_scale(mean: f64, stddev: f64, mad: f64) -> f64 {
    if stddev.is_finite() && stddev >= MAD_SWITCH {
        return stddev;
    }
    let mad_sigma = mad / 0.6745;
    if mad_sigma.is_finite() && mad_sigma > MIN_SCALE {
        return mad_sigma.max(cv_scale(mean) * 0.1);
    }
    cv_scale(mean)
}

fn raw_z(b: Baseline, observed: f64) -> f64 {
    if !b.mean.is_finite() || !observed.is_finite() {
        return 0.0;
    }
    let center = if b.mad > MIN_SCALE && b.stddev < MAD_SWITCH {
        b.median
    } else {
        b.mean
    };
    let delta = observed - center;
    let sigma = robust_scale(b.mean, b.stddev, b.mad);
    delta / sigma
}

/// Postgres-safe Z: `None` if the value must not be bound to NUMERIC.
#[must_use]
pub fn persistable_z(z: f64) -> Option<f64> {
    if !z.is_finite() {
        return None;
    }
    Some(z.clamp(-Z_ABS_CAP, Z_ABS_CAP))
}

#[must_use]
pub fn classify_z(z: f64) -> &'static str {
    let a = persistable_z(z).unwrap_or(0.0).abs();
    if a > Z_ISOLATE {
        "critical"
    } else if a > 3.0 {
        "high"
    } else if a > 2.0 {
        "medium"
    } else {
        "info"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_series_has_low_z() {
        let b = Baseline::from_samples(&[10.0, 10.1, 9.9, 10.0, 10.05]).unwrap();
        assert!(b.z_score(10.0).abs() < 1.0);
        assert!(!b.is_high(10.0, Z_ISOLATE));
    }

    #[test]
    fn spike_exceeds_six_sigma() {
        let xs: Vec<f64> = (0..50).map(|_| 10.0).collect();
        let b = Baseline::from_samples(&xs).unwrap();
        assert_eq!(b.stddev, 0.0);
        let z = b.z_score(80.0);
        assert!(z.is_finite(), "flat PLC series must not yield Inf/NaN");
        assert!(z.abs() <= Z_ABS_CAP);
        assert!(b.is_high(80.0, Z_ISOLATE));
        assert_eq!(classify_z(z), "critical");
    }

    #[test]
    fn micro_timing_stall_is_not_swallowed_by_hard_floor() {
        // 1 ms poll, perfectly flat. A 20 µs stall is 20× a 1e-5 hard floor (Z=2,
        // missed). CV·μ = 1e-7, so Z ≫ 6 and SOAR still sees it.
        let xs: Vec<f64> = (0..40).map(|_| 0.001).collect();
        let b = Baseline::from_samples(&xs).unwrap();
        assert!(b.stddev < MAD_SWITCH);
        let z = b.z_score(0.001 + 2e-5);
        assert!(z.is_finite());
        assert!(
            z.abs() > Z_ISOLATE,
            "micro stall must remain critical, z={z}"
        );
        assert!(
            b.scale() < MAD_SWITCH,
            "must not substitute the 1e-5 hard floor as σ"
        );
    }

    #[test]
    fn persistable_z_rejects_nan_and_inf() {
        assert!(persistable_z(f64::NAN).is_none());
        assert!(persistable_z(f64::INFINITY).is_none());
        assert!(persistable_z(f64::NEG_INFINITY).is_none());
        assert_eq!(persistable_z(12.0), Some(12.0));
        assert_eq!(persistable_z(10_000.0), Some(Z_ABS_CAP));
    }

    #[test]
    fn too_few_samples_is_none() {
        assert!(Baseline::from_samples(&[1.0, 2.0]).is_none());
    }

    #[test]
    fn welford_update_moves_mean() {
        let b = Baseline {
            mean: 10.0,
            stddev: 1.0,
            mad: 0.5,
            median: 10.0,
            samples: 10,
        }
        .update(20.0);
        assert!(b.mean > 10.0);
        assert_eq!(b.samples, 11);
    }
}
