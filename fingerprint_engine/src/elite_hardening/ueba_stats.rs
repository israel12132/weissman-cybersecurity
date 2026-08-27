//! UEBA statistical helpers (points 41, 44, 50).
//!
//! Hour-of-week overlay lives alongside the global bucket: raw samples already
//! record `hour_of_week`. Scoring uses the architect hybrid cascade:
//!   * Phase A (`n < 24`): learning, no alerts
//!   * Phase B (`24 ≤ n < 168`): score against the global baseline only
//!   * Phase C (`n ≥ 168`): score against the current hour-of-week bucket when
//!     it has ≥ 3 local samples, else fall back to the global baseline
//!
//! This module also supplies the cloud-safe stddev floor so bursty autoscaling
//! environments do not emit a wall of false positives.

/// Cloud-safe standard deviation: never divide by ~0; floor at 1% of |mean|.
pub fn cloud_safe_stddev(mean: f64, stddev: f64) -> f64 {
    if !mean.is_finite() {
        return stddev.max(1e-9);
    }
    let floor = mean.abs() * 0.01;
    if !stddev.is_finite() || stddev < 1e-6 {
        return floor.max(1e-9);
    }
    stddev.max(floor).max(1e-9)
}

/// Z-score with the cloud-safe floor. Returns None when still degenerate.
pub fn z_score(observed: f64, mean: f64, stddev: f64) -> Option<f64> {
    if !observed.is_finite() || !mean.is_finite() {
        return None;
    }
    let s = cloud_safe_stddev(mean, stddev);
    Some((observed - mean) / s)
}

/// Spec: |z| > 3 medium, |z| > 6 high. No operator override.
pub fn severity_for_z(z: f64) -> &'static str {
    if z.abs() > 6.0 {
        "high"
    } else if z.abs() > 3.0 {
        "medium"
    } else {
        "info"
    }
}

/// Hour-of-week in 0..=167 (UTC).
pub fn hour_of_week_utc(hour: u32, weekday_sun0: u32) -> i16 {
    let h = hour.min(23);
    let d = weekday_sun0.min(6);
    (d * 24 + h) as i16
}

/// Unix epoch → hour-of-week. 1970-01-01 was Thursday (4 if Sunday = 0).
pub fn hour_of_week_from_unix(unix: i64) -> i16 {
    let days = unix.div_euclid(86_400);
    let hour = unix.div_euclid(3_600).rem_euclid(24) as u32;
    let weekday_sun0 = ((days + 4).rem_euclid(7)) as u32;
    hour_of_week_utc(hour, weekday_sun0)
}

/// Hard learning floor (matches `ueba_detector::MIN_BASELINE_SAMPLES`).
pub const MIN_LEARNING_SAMPLES: i32 = 24;
/// One full week of hourly samples before hour-of-week scoring is eligible.
pub const FULL_WEEK_SAMPLES: i32 = 168;
/// Local hour bucket must have this many samples before it beats the global baseline.
pub const HOUR_BUCKET_MIN_SAMPLES: i32 = 3;
/// Sentinel used in architecture notes for the global baseline (`hour_of_week = -1`).
/// The detector still *stores* the global row under bucket `0` so existing
/// baselines keep accumulating; scoring treats that row as the global bucket.
pub const GLOBAL_HOUR_SENTINEL: i16 = -1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridPhase {
    Learning,
    GlobalOnly,
    HourThenGlobal,
}

pub fn hybrid_phase(global_n: i32) -> HybridPhase {
    if global_n < MIN_LEARNING_SAMPLES {
        HybridPhase::Learning
    } else if global_n < FULL_WEEK_SAMPLES {
        HybridPhase::GlobalOnly
    } else {
        HybridPhase::HourThenGlobal
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BaselineStats {
    pub n: i32,
    pub mean: f64,
    pub stddev: f64,
    pub hour_of_week: i16,
}

/// Pick the baseline used for the Z-score. Never alerts during learning.
pub fn pick_scoring_baseline(
    global: BaselineStats,
    hour: Option<BaselineStats>,
) -> Option<BaselineStats> {
    match hybrid_phase(global.n) {
        HybridPhase::Learning => None,
        HybridPhase::GlobalOnly => Some(global),
        HybridPhase::HourThenGlobal => {
            if let Some(h) = hour {
                if h.n >= HOUR_BUCKET_MIN_SAMPLES {
                    return Some(h);
                }
            }
            Some(global)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_prevents_zero_division() {
        let s = cloud_safe_stddev(100.0, 0.0);
        assert!(s >= 1.0);
        let z = z_score(200.0, 100.0, 0.0).unwrap();
        assert!(z.abs() > 3.0);
    }

    #[test]
    fn z_thresholds() {
        assert_eq!(severity_for_z(3.1), "medium");
        assert_eq!(severity_for_z(6.1), "high");
        assert_eq!(severity_for_z(1.0), "info");
    }

    #[test]
    fn hour_bucket_sunday_midnight() {
        assert_eq!(hour_of_week_utc(0, 0), 0);
        assert_eq!(hour_of_week_utc(23, 6), 167);
        // 1970-01-01 00:00 UTC = Thursday → weekday 4, hour 0 → bucket 96
        assert_eq!(hour_of_week_from_unix(0), 96);
    }

    #[test]
    fn hybrid_phases_match_architect_spec() {
        assert_eq!(hybrid_phase(0), HybridPhase::Learning);
        assert_eq!(hybrid_phase(23), HybridPhase::Learning);
        assert_eq!(hybrid_phase(24), HybridPhase::GlobalOnly);
        assert_eq!(hybrid_phase(167), HybridPhase::GlobalOnly);
        assert_eq!(hybrid_phase(168), HybridPhase::HourThenGlobal);
    }

    #[test]
    fn phase_a_never_scores() {
        let g = BaselineStats {
            n: 10,
            mean: 1.0,
            stddev: 0.1,
            hour_of_week: GLOBAL_HOUR_SENTINEL,
        };
        assert!(pick_scoring_baseline(g, None).is_none());
    }

    #[test]
    fn phase_b_ignores_thin_hour_bucket() {
        let g = BaselineStats {
            n: 50,
            mean: 10.0,
            stddev: 1.0,
            hour_of_week: GLOBAL_HOUR_SENTINEL,
        };
        let h = BaselineStats {
            n: 8,
            mean: 99.0,
            stddev: 1.0,
            hour_of_week: 3,
        };
        let picked = pick_scoring_baseline(g, Some(h)).unwrap();
        assert_eq!(picked.hour_of_week, GLOBAL_HOUR_SENTINEL);
        assert_eq!(picked.mean, 10.0);
    }

    #[test]
    fn phase_c_uses_hour_when_local_n_ge_3_else_global() {
        let g = BaselineStats {
            n: 200,
            mean: 10.0,
            stddev: 1.0,
            hour_of_week: GLOBAL_HOUR_SENTINEL,
        };
        let thin = BaselineStats {
            n: 2,
            mean: 50.0,
            stddev: 1.0,
            hour_of_week: 42,
        };
        assert_eq!(
            pick_scoring_baseline(g, Some(thin)).unwrap().hour_of_week,
            GLOBAL_HOUR_SENTINEL
        );
        let fat = BaselineStats {
            n: 3,
            mean: 50.0,
            stddev: 1.0,
            hour_of_week: 42,
        };
        assert_eq!(
            pick_scoring_baseline(g, Some(fat)).unwrap().hour_of_week,
            42
        );
        assert_eq!(
            pick_scoring_baseline(g, None).unwrap().hour_of_week,
            GLOBAL_HOUR_SENTINEL
        );
    }
}
