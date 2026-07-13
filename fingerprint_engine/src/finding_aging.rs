//! Backlog-aging analytics — how stale are our open findings?
//!
//! The SLA engine answers "what is past its deadline". Boards also ask the simpler backlog-health
//! question: "how old is our open risk, by severity — do we have criticals rotting for months?"
//! This module bucketizes open findings by age (from `discovered_at`) against severity and flags
//! the aged criticals/highs that a mature program should never carry.
//!
//! Pure/deterministic; the DB loader is read-only and RLS-scoped.

use serde::Serialize;
use serde_json::{json, Value};

/// Age-bucket upper bounds in days (last bucket is open-ended). Chosen to match common
/// vuln-management backlog reviews: this week, this month, this quarter, this half, older.
const BUCKET_BOUNDS: [i64; 4] = [7, 30, 90, 180];
const BUCKET_LABELS: [&str; 5] = ["0-7d", "8-30d", "31-90d", "91-180d", "180d+"];

/// A finding as consumed here: its severity and age in whole days.
#[derive(Debug, Clone)]
pub struct FindingAge {
    pub severity: String,
    pub age_days: Option<i64>,
}

fn norm_severity(sev: &str) -> &'static str {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" | "informational" => "info",
        _ => "other",
    }
}

/// Index of the age bucket for `age_days` (0..=4). Ages < 0 clamp to the freshest bucket.
fn bucket_index(age_days: i64) -> usize {
    let a = age_days.max(0);
    for (i, bound) in BUCKET_BOUNDS.iter().enumerate() {
        if a <= *bound {
            return i;
        }
    }
    BUCKET_LABELS.len() - 1
}

/// One age bucket with its per-severity counts.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgeBucket {
    pub label: String,
    pub max_days: Option<i64>, // None for the open-ended last bucket
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub other: usize,
}

/// Backlog-aging report.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgingReport {
    pub buckets: Vec<AgeBucket>,
    /// Findings with no known discovery age (excluded from buckets).
    pub unknown_age: usize,
    /// Red flags: criticals/highs open longer than 90 days.
    pub aged_criticals: usize,
    pub aged_highs: usize,
    /// Oldest open critical / high age in days, if any.
    pub oldest_critical_days: Option<i64>,
    pub oldest_high_days: Option<i64>,
}

#[derive(Debug, Default, Clone)]
struct BucketAcc {
    total: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    other: usize,
}

impl BucketAcc {
    fn bump(&mut self, sev: &str) {
        self.total += 1;
        match sev {
            "critical" => self.critical += 1,
            "high" => self.high += 1,
            "medium" => self.medium += 1,
            "low" => self.low += 1,
            "info" => self.info += 1,
            _ => self.other += 1,
        }
    }
}

/// Aggregate findings into the backlog-aging report. Deterministic.
#[must_use]
pub fn aggregate(findings: &[FindingAge]) -> AgingReport {
    let mut accs: Vec<BucketAcc> = vec![BucketAcc::default(); BUCKET_LABELS.len()];
    let mut unknown_age = 0usize;
    let mut aged_criticals = 0usize;
    let mut aged_highs = 0usize;
    let mut oldest_critical: Option<i64> = None;
    let mut oldest_high: Option<i64> = None;

    for f in findings {
        let sev = norm_severity(&f.severity);
        let Some(age) = f.age_days else {
            unknown_age += 1;
            continue;
        };
        let age = age.max(0);
        accs[bucket_index(age)].bump(sev);
        if sev == "critical" {
            oldest_critical = Some(oldest_critical.map_or(age, |c| c.max(age)));
            if age > 90 {
                aged_criticals += 1;
            }
        } else if sev == "high" {
            oldest_high = Some(oldest_high.map_or(age, |c| c.max(age)));
            if age > 90 {
                aged_highs += 1;
            }
        }
    }

    let buckets = accs
        .into_iter()
        .enumerate()
        .map(|(i, a)| AgeBucket {
            label: BUCKET_LABELS[i].to_string(),
            max_days: BUCKET_BOUNDS.get(i).copied(),
            total: a.total,
            critical: a.critical,
            high: a.high,
            medium: a.medium,
            low: a.low,
            info: a.info,
            other: a.other,
        })
        .collect();

    AgingReport {
        buckets,
        unknown_age,
        aged_criticals,
        aged_highs,
        oldest_critical_days: oldest_critical,
        oldest_high_days: oldest_high,
    }
}

/// Load a client's open findings and compute the backlog-aging report. Read-only; RLS-scoped.
pub async fn load_and_aggregate(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> Result<Value, String> {
    use sqlx::Row;

    let limit = limit.clamp(1, 5000);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let rows = sqlx::query(
        r#"SELECT COALESCE(severity, '') AS severity,
                  FLOOR(EXTRACT(EPOCH FROM (now() - discovered_at)) / 86400.0)::bigint AS age_days
             FROM vulnerabilities
            WHERE tenant_id = $1
              AND client_id = $2
              AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED')
            ORDER BY id DESC
            LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    let findings: Vec<FindingAge> = rows
        .iter()
        .map(|r| FindingAge {
            severity: r.try_get("severity").unwrap_or_default(),
            age_days: r
                .try_get::<Option<i64>, _>("age_days")
                .unwrap_or(None)
                .map(|d| d.max(0)),
        })
        .collect();

    let report = aggregate(&findings);
    Ok(json!({
        "ok": true,
        "client_id": client_id,
        "findings_analyzed": findings.len(),
        "aging": report,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(sev: &str, age: Option<i64>) -> FindingAge {
        FindingAge {
            severity: sev.to_string(),
            age_days: age,
        }
    }

    #[test]
    fn bucket_boundaries_are_inclusive_upper() {
        assert_eq!(bucket_index(0), 0);
        assert_eq!(bucket_index(7), 0);
        assert_eq!(bucket_index(8), 1);
        assert_eq!(bucket_index(30), 1);
        assert_eq!(bucket_index(31), 2);
        assert_eq!(bucket_index(90), 2);
        assert_eq!(bucket_index(91), 3);
        assert_eq!(bucket_index(180), 3);
        assert_eq!(bucket_index(181), 4);
        assert_eq!(bucket_index(100000), 4);
    }

    #[test]
    fn negative_age_clamps_to_freshest_bucket() {
        let r = aggregate(&[f("high", Some(-5))]);
        assert_eq!(r.buckets[0].high, 1);
    }

    #[test]
    fn severity_and_buckets_are_counted() {
        let r = aggregate(&[
            f("critical", Some(3)),   // bucket 0
            f("critical", Some(120)), // bucket 3, aged
            f("high", Some(200)),     // bucket 4, aged
            f("medium", Some(45)),    // bucket 2
            f("low", Some(400)),      // bucket 4
        ]);
        assert_eq!(r.buckets[0].critical, 1);
        assert_eq!(r.buckets[3].critical, 1);
        assert_eq!(r.buckets[4].high, 1);
        assert_eq!(r.buckets[2].medium, 1);
        assert_eq!(r.buckets[4].low, 1);
        let total: usize = r.buckets.iter().map(|b| b.total).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn aged_flags_and_oldest_tracked() {
        let r = aggregate(&[
            f("critical", Some(120)),
            f("critical", Some(365)),
            f("high", Some(100)),
            f("high", Some(40)), // not aged
        ]);
        assert_eq!(r.aged_criticals, 2);
        assert_eq!(r.aged_highs, 1);
        assert_eq!(r.oldest_critical_days, Some(365));
        assert_eq!(r.oldest_high_days, Some(100));
    }

    #[test]
    fn unknown_age_is_excluded_from_buckets() {
        let r = aggregate(&[f("critical", None), f("high", Some(5))]);
        assert_eq!(r.unknown_age, 1);
        let total: usize = r.buckets.iter().map(|b| b.total).sum();
        assert_eq!(total, 1);
        assert_eq!(r.oldest_critical_days, None);
    }

    #[test]
    fn ninety_day_boundary_is_not_aged() {
        // "> 90" means exactly 90 days is not yet an aged critical.
        let r = aggregate(&[f("critical", Some(90))]);
        assert_eq!(r.aged_criticals, 0);
        assert_eq!(r.buckets[2].critical, 1);
    }
}
