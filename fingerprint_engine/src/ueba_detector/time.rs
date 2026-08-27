//! UTC hour-of-week, DST-safe bucketing, temporal smoothing, holidays, and learning windows.

use chrono::{DateTime, Datelike, Timelike, Utc};

/// Mon 00:00 UTC = 0 … Sun 23:00 UTC = 167. Always UTC so DST never moves a sample.
pub fn hour_of_week_utc(ts: DateTime<Utc>) -> i16 {
    let dow = ts.weekday().num_days_from_monday() as i16;
    let hour = ts.hour() as i16;
    (dow * 24 + hour).clamp(0, 167)
}

pub fn clamp_hour_of_week(h: i16) -> i16 {
    h.clamp(0, 167)
}

/// Adjacent hour-of-week buckets (wraps at the week boundary).
pub fn adjacent_hours(h: i16) -> (i16, i16) {
    let h = clamp_hour_of_week(h);
    let prev = if h == 0 { 167 } else { h - 1 };
    let next = if h == 167 { 0 } else { h + 1 };
    (prev, next)
}

/// True when a spike sits only on a bucket boundary (13:59 vs 14:01) and both neighbours
/// are quiet — a classic false-positive from hour-of-week quantization.
pub fn is_boundary_false_positive(
    z: f64,
    z_prev: Option<f64>,
    z_next: Option<f64>,
    thresh: f64,
) -> bool {
    let a = z.abs();
    if a < thresh || a >= thresh * 1.75 {
        return false;
    }
    let quiet = |o: Option<f64>| o.map(|v| v.abs() < thresh * 0.5).unwrap_or(true);
    quiet(z_prev) && quiet(z_next)
}

/// Saturday=5, Sunday=6 in the Monday-based week used by [`hour_of_week_utc`].
pub fn is_weekend_hour(hour_of_week: i16) -> bool {
    let h = clamp_hour_of_week(hour_of_week);
    h >= 5 * 24
}

pub fn is_holiday(ts: DateTime<Utc>, holiday_dates: &[chrono::NaiveDate]) -> bool {
    let d = ts.date_naive();
    holiday_dates.iter().any(|h| *h == d)
}

/// Treat holidays as weekend for scoring (quiet-hours boost still applies).
pub fn is_offhours(
    hour_of_week: i16,
    ts: DateTime<Utc>,
    business_start_hour: i16,
    business_end_hour: i16,
    holiday_dates: &[chrono::NaiveDate],
    treat_holidays_as_weekend: bool,
) -> bool {
    if treat_holidays_as_weekend && is_holiday(ts, holiday_dates) {
        return true;
    }
    if is_weekend_hour(hour_of_week) {
        return true;
    }
    let hod = clamp_hour_of_week(hour_of_week) % 24;
    let start = business_start_hour.clamp(0, 23);
    let end = business_end_hour.clamp(1, 24);
    hod < start || hod >= end
}

/// Night / weekend anomalies are scored harder (lateral movement loves 02:00).
pub fn offhours_multiplier(offhours: bool) -> f64 {
    if offhours {
        1.35
    } else {
        1.0
    }
}

/// Allowed learning windows (days). Default 7; orgs with monthly cycles use 14 or 30.
pub fn clamp_learn_window_days(days: i64) -> i64 {
    match days {
        14 | 30 => days,
        _ => 7,
    }
}

/// Clock-skew warning when the agent's sampled_at drifts from server receipt by > 5 minutes.
pub const CLOCK_SKEW_WARN_SECS: i64 = 5 * 60;

pub fn clock_skew_secs(sampled_at: DateTime<Utc>, received_at: DateTime<Utc>) -> i64 {
    (received_at - sampled_at).num_seconds().abs()
}

/// Distinct weekdays represented in a set of hour-of-week values (0..=6 Monday-based).
pub fn distinct_weekdays(hours: &[i16]) -> usize {
    let mut mask = 0u8;
    for h in hours {
        let d = (clamp_hour_of_week(*h) / 24).clamp(0, 6) as u8;
        mask |= 1 << d;
    }
    mask.count_ones() as usize
}

/// Leave the learning window only when we have ≥ `min_samples` AND coverage across
/// at least 5 distinct weekdays (so a burst of 24 samples on Monday is not "trained").
pub fn learning_complete(n: i32, min_samples: i32, distinct_days: usize) -> bool {
    n >= min_samples && distinct_days >= 5
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn hour_of_week_is_utc_monday_zero() {
        // 2026-08-24 is a Monday.
        let ts = Utc.with_ymd_and_hms(2026, 8, 24, 0, 15, 0).unwrap();
        assert_eq!(hour_of_week_utc(ts), 0);
        let sun = Utc.with_ymd_and_hms(2026, 8, 30, 23, 0, 0).unwrap();
        assert_eq!(hour_of_week_utc(sun), 167);
    }

    #[test]
    fn adjacent_wraps_week() {
        assert_eq!(adjacent_hours(0), (167, 1));
        assert_eq!(adjacent_hours(167), (166, 0));
        assert_eq!(adjacent_hours(42), (41, 43));
    }

    #[test]
    fn boundary_fp_only_for_mild_edge_spikes() {
        assert!(is_boundary_false_positive(3.2, Some(0.4), Some(0.2), 3.0));
        assert!(!is_boundary_false_positive(8.0, Some(0.1), Some(0.1), 3.0));
        assert!(!is_boundary_false_positive(3.2, Some(4.0), Some(0.1), 3.0));
    }

    #[test]
    fn weekend_and_business_hours() {
        assert!(is_weekend_hour(5 * 24));
        assert!(!is_weekend_hour(4 * 24 + 17));
        let tue_3am = Utc.with_ymd_and_hms(2026, 8, 25, 3, 0, 0).unwrap();
        let h = hour_of_week_utc(tue_3am);
        assert!(is_offhours(h, tue_3am, 8, 18, &[], true));
        let tue_10 = Utc.with_ymd_and_hms(2026, 8, 25, 10, 0, 0).unwrap();
        let h10 = hour_of_week_utc(tue_10);
        assert!(!is_offhours(h10, tue_10, 8, 18, &[], true));
    }

    #[test]
    fn learning_requires_weekday_spread() {
        assert!(!learning_complete(24, 24, 1));
        assert!(learning_complete(24, 24, 5));
        assert!(!learning_complete(10, 24, 7));
    }

    #[test]
    fn learn_window_clamped() {
        assert_eq!(clamp_learn_window_days(7), 7);
        assert_eq!(clamp_learn_window_days(14), 14);
        assert_eq!(clamp_learn_window_days(30), 30);
        assert_eq!(clamp_learn_window_days(99), 7);
    }
}
