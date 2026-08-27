//! Z-score anomaly detection over OT packet-rate / poll-rate baselines.

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
            let m2 = self.stddev.powi(2) * (self.samples as f64)
                + (x - self.mean) * (x - mean);
            (m2 / n).max(0.0).sqrt()
        };
        Self {
            mean,
            stddev,
            samples: self.samples + 1,
        }
    }

    #[must_use]
    pub fn z_score(self, observed: f64) -> f64 {
        let delta = observed - self.mean;
        if self.stddev < 1e-9 {
            // Perfectly flat baseline: any movement is infinite sigma, not "quiet".
            if delta.abs() < 1e-9 {
                0.0
            } else if delta > 0.0 {
                f64::INFINITY
            } else {
                f64::NEG_INFINITY
            }
        } else {
            delta / self.stddev
        }
    }

    #[must_use]
    pub fn is_high(self, observed: f64, threshold: f64) -> bool {
        self.z_score(observed).abs() > threshold
    }
}

/// Default isolate threshold from the OT blueprint (Z > 6).
pub const Z_ISOLATE: f64 = 6.0;

#[must_use]
pub fn classify_z(z: f64) -> &'static str {
    let a = z.abs();
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
        assert!(b.is_high(80.0, Z_ISOLATE));
        assert_eq!(classify_z(b.z_score(80.0)), "critical");
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
