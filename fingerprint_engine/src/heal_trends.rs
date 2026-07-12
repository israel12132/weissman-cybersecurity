//! Auto-heal **trend / SLA analytics** — daily buckets of heal outcomes for a client, so an operator
//! can see success rate and effort move over time rather than a single snapshot.
//!
//! [`compute_trends`] is a **pure function** over `(day, verdict, attempts)` rows (the handler does the
//! tenant/date-window SQL); it is fully unit-tested. ISO `YYYY-MM-DD` day strings sort lexicographically,
//! so buckets come out chronological with no date maths.

use serde::Serialize;

/// One day's aggregate.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DayBucket {
    pub day: String,
    pub total: i64,
    pub fixed: i64,
    /// fixed / total, 0..=1, rounded to 2 dp.
    pub success_rate: f64,
    /// mean attempts that day, rounded to 2 dp.
    pub avg_attempts: f64,
}

/// The trend report over the requested window.
#[derive(Debug, Clone, Serialize)]
pub struct TrendReport {
    pub days: Vec<DayBucket>,
    pub total: i64,
    pub fixed: i64,
    pub success_rate: f64,
    pub avg_attempts: f64,
    /// `(attempts, count)` ascending — how many heals took N attempts.
    pub attempts_histogram: Vec<(i64, i64)>,
    /// Day with the most heals (first on a tie), or None when there is no data.
    pub best_day: Option<String>,
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// Aggregate `(day, verdict, attempts)` rows into a daily trend report.
pub fn compute_trends(rows: &[(String, String, i64)]) -> TrendReport {
    use std::collections::BTreeMap;

    // day -> (total, fixed, attempts_sum)
    let mut by_day: BTreeMap<String, (i64, i64, i64)> = BTreeMap::new();
    let mut hist: BTreeMap<i64, i64> = BTreeMap::new();
    let mut total = 0i64;
    let mut fixed = 0i64;
    let mut attempts_sum = 0i64;

    for (day, verdict, attempts) in rows {
        let is_fixed = verdict.eq_ignore_ascii_case("fixed");
        let a = (*attempts).max(1);
        let e = by_day.entry(day.clone()).or_insert((0, 0, 0));
        e.0 += 1;
        e.1 += is_fixed as i64;
        e.2 += a;
        *hist.entry(a).or_insert(0) += 1;
        total += 1;
        fixed += is_fixed as i64;
        attempts_sum += a;
    }

    let days: Vec<DayBucket> = by_day
        .into_iter()
        .map(|(day, (t, f, asum))| DayBucket {
            day,
            total: t,
            fixed: f,
            success_rate: if t > 0 {
                round2(f as f64 / t as f64)
            } else {
                0.0
            },
            avg_attempts: if t > 0 {
                round2(asum as f64 / t as f64)
            } else {
                0.0
            },
        })
        .collect();

    // First day (chronologically) achieving the max total — `days` is already ascending, and using
    // `>=` in the fold keeps the earlier day on a tie (`max_by_key` would keep the later one).
    let best_day = days
        .iter()
        .fold(None::<&DayBucket>, |acc, d| match acc {
            Some(b) if b.total >= d.total => Some(b),
            _ => Some(d),
        })
        .filter(|d| d.total > 0)
        .map(|d| d.day.clone());

    TrendReport {
        days,
        total,
        fixed,
        success_rate: if total > 0 {
            round2(fixed as f64 / total as f64)
        } else {
            0.0
        },
        avg_attempts: if total > 0 {
            round2(attempts_sum as f64 / total as f64)
        } else {
            0.0
        },
        attempts_histogram: hist.into_iter().collect(),
        best_day,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<(String, String, i64)> {
        vec![
            ("2026-07-01".into(), "fixed".into(), 1),
            ("2026-07-01".into(), "broke_app".into(), 2),
            ("2026-07-01".into(), "fixed".into(), 3),
            ("2026-07-03".into(), "fixed".into(), 1),
            ("2026-07-02".into(), "still_vulnerable".into(), 2),
        ]
    }

    #[test]
    fn buckets_are_chronological_and_correct() {
        let r = compute_trends(&rows());
        assert_eq!(r.days.len(), 3);
        assert_eq!(r.days[0].day, "2026-07-01");
        assert_eq!(r.days[1].day, "2026-07-02");
        assert_eq!(r.days[2].day, "2026-07-03");
        // Day 1: 3 heals, 2 fixed -> 0.67, avg attempts (1+2+3)/3 = 2.0
        assert_eq!(r.days[0].total, 3);
        assert_eq!(r.days[0].fixed, 2);
        assert_eq!(r.days[0].success_rate, 0.67);
        assert_eq!(r.days[0].avg_attempts, 2.0);
    }

    #[test]
    fn overall_rollups() {
        let r = compute_trends(&rows());
        assert_eq!(r.total, 5);
        assert_eq!(r.fixed, 3);
        assert_eq!(r.success_rate, 0.6);
        // attempts: (1+2+3+1+2)/5 = 1.8
        assert_eq!(r.avg_attempts, 1.8);
        assert_eq!(r.best_day.as_deref(), Some("2026-07-01"));
    }

    #[test]
    fn best_day_breaks_ties_toward_the_earliest() {
        let rows = vec![
            ("2026-07-02".into(), "fixed".into(), 1),
            ("2026-07-02".into(), "fixed".into(), 1),
            ("2026-07-01".into(), "fixed".into(), 1),
            ("2026-07-01".into(), "fixed".into(), 1),
        ];
        // Both days tie at 2; the earliest chronological day must win (documented contract).
        assert_eq!(
            compute_trends(&rows).best_day.as_deref(),
            Some("2026-07-01")
        );
    }

    #[test]
    fn attempts_histogram_is_sorted_counts() {
        let r = compute_trends(&rows());
        // attempts 1 -> 2 heals, 2 -> 2 heals, 3 -> 1 heal
        assert_eq!(r.attempts_histogram, vec![(1, 2), (2, 2), (3, 1)]);
    }

    #[test]
    fn attempts_floored_to_one() {
        let r = compute_trends(&[("2026-07-01".into(), "fixed".into(), 0)]);
        assert_eq!(r.avg_attempts, 1.0);
        assert_eq!(r.attempts_histogram, vec![(1, 1)]);
    }

    #[test]
    fn empty_is_zeroed_not_nan() {
        let r = compute_trends(&[]);
        assert_eq!(r.total, 0);
        assert_eq!(r.success_rate, 0.0);
        assert_eq!(r.avg_attempts, 0.0);
        assert!(r.days.is_empty());
        assert!(r.best_day.is_none());
        assert!(r.attempts_histogram.is_empty());
    }

    #[test]
    fn verdict_match_is_case_insensitive() {
        let r = compute_trends(&[("2026-07-01".into(), "FIXED".into(), 1)]);
        assert_eq!(r.fixed, 1);
        assert_eq!(r.success_rate, 1.0);
    }
}
