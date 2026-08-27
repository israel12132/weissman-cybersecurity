//! UEBA statistical helpers (points 41, 44, 50).
//!
//! Hour-of-week overlay lives alongside the global bucket: raw samples already
//! record `hour_of_week`; this module supplies the cloud-safe stddev floor so
//! bursty autoscaling environments do not emit a wall of false positives.

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
    }
}
