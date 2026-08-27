//! Z-score anomaly detection over OT packet-rate / poll-rate baselines.
//!
//! Industrial registers (temperature, current) are often perfectly flat. A raw
//! \(Z = (x-\mu)/\sigma\) with \(\sigma = 0\) yields NaN/∞ in IEEE-754, which
//! panics comparisons and cannot be stored in Postgres NUMERIC. Every public
//! score is therefore finite, floored, and capped.

/// Minimum σ used in the denominator. PLC deadbands sit well above this.
pub const STDDEV_FLOOR: f64 = 1e-5;
/// Absolute cap so persist/compare never see Inf/NaN (architect: bounded, controlled).
pub const Z_ABS_CAP: f64 = 100.0;
/// Default isolate threshold from the OT blueprint (Z > 6).
pub const Z_ISOLATE: f64 = 6.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Baseline {
    pub mean: f64,
    pub stddev: f64,
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
        Some(Self {
            mean,
            stddev: var.sqrt(),
            samples: xs.len() as u64,
        })
    }

    /// Online Welford update (7-day GOOSE window, scan-rate, poll-rate).
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
        Self {
            mean,
            stddev,
            samples: self.samples + 1,
        }
    }

    /// Finite, floored, capped Z. Never NaN, never ±∞.
    #[must_use]
    pub fn z_score(self, observed: f64) -> f64 {
        persistable_z(raw_z(self.mean, self.stddev, observed)).unwrap_or(0.0)
    }

    #[must_use]
    pub fn is_high(self, observed: f64, threshold: f64) -> bool {
        self.z_score(observed).abs() > threshold
    }
}

fn raw_z(mean: f64, stddev: f64, observed: f64) -> f64 {
    if !mean.is_finite() || !observed.is_finite() {
        return 0.0;
    }
    let delta = observed - mean;
    let mut sigma = stddev;
    if !sigma.is_finite() || sigma < STDDEV_FLOOR {
        sigma = STDDEV_FLOOR;
    }
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
            samples: 10,
        }
        .update(20.0);
        assert!(b.mean > 10.0);
        assert_eq!(b.samples, 11);
    }
}
