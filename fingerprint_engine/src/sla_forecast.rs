//! Proactive remediation-SLA breach forecast.
//!
//! Wave 17 tells you what is *already* overdue. Teams also need to get *ahead* of breaches: "by day
//! 30, how many actions will be in SLA breach, and how many of those are KEV?" This module answers
//! that from the same ranked fix-first program, projecting each action's SLA clock forward over a
//! set of horizons. Pure/deterministic; the DB loader reuses [`crate::remediation_priority`] so the
//! forecast and the remediation queue can never disagree.

use crate::remediation_priority::RemediationItem;
use serde::Serialize;
use serde_json::{json, Value};

/// Default forecast horizons in days (cumulative: each includes everything already breached).
pub const DEFAULT_HORIZONS: [i64; 5] = [7, 14, 30, 60, 90];

/// Cumulative breach counts by a given horizon (an action counts if its SLA due date is on or
/// before `within_days` — already-overdue actions therefore count in every horizon).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ForecastBucket {
    pub within_days: i64,
    pub breached: usize,
    pub kev_breached: usize,
    pub ransomware_breached: usize,
    pub crown_jewel_breached: usize,
}

/// True if an action's SLA clock is due on or before `horizon` days from now. Actions with an
/// unknown clock (no discovery age) are never counted — we don't invent a deadline.
fn breaches_within(item: &RemediationItem, horizon: i64) -> bool {
    matches!(item.sla.due_in_days, Some(d) if d <= horizon)
}

/// Build the cumulative breach forecast across `horizons`. Deterministic; horizons are sorted
/// ascending and de-duplicated so the curve is monotonic and stable.
#[must_use]
pub fn forecast(items: &[RemediationItem], horizons: &[i64]) -> Vec<ForecastBucket> {
    let mut hs: Vec<i64> = horizons.to_vec();
    hs.sort_unstable();
    hs.dedup();
    hs.into_iter()
        .map(|h| {
            let mut breached = 0;
            let mut kev = 0;
            let mut ransom = 0;
            let mut crown = 0;
            for it in items {
                if breaches_within(it, h) {
                    breached += 1;
                    if it.kev_ransomware {
                        ransom += 1;
                        kev += 1;
                    } else if it.kev {
                        kev += 1;
                    }
                    if it.crown_jewel {
                        crown += 1;
                    }
                }
            }
            ForecastBucket {
                within_days: h,
                breached,
                kev_breached: kev,
                ransomware_breached: ransom,
                crown_jewel_breached: crown,
            }
        })
        .collect()
}

/// Count actions already past SLA (due date in the past).
#[must_use]
pub fn overdue_now(items: &[RemediationItem]) -> usize {
    items
        .iter()
        .filter(|it| matches!(it.sla.due_in_days, Some(d) if d < 0))
        .count()
}

/// Load a client's live findings, rank them, and forecast SLA breaches. Read-only; RLS-scoped.
pub async fn load_and_forecast(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> Result<Value, String> {
    let findings =
        crate::remediation_priority::load_findings(pool, tenant_id, client_id, limit).await?;
    let program = crate::remediation_priority::rank(&findings);
    let buckets = forecast(&program, &DEFAULT_HORIZONS);

    Ok(json!({
        "ok": true,
        "client_id": client_id,
        "remediation_actions": program.len(),
        "overdue_now": overdue_now(&program),
        "horizon_days": DEFAULT_HORIZONS,
        "forecast": buckets,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remediation_priority::{rank, FindingInput};

    fn finding(id: &str, sev: &str, er: Option<f64>, age: Option<i64>) -> FindingInput {
        FindingInput {
            finding_id: id.to_string(),
            title: format!("finding {id}"),
            severity: sev.to_string(),
            cwe: format!("CWE-{id}"), // distinct groups → one action each
            asset: format!("asset-{id}.example.com"),
            effective_risk: er,
            epss: None,
            kev: false,
            kev_ransomware: false,
            cluster_id: None,
            on_choke_point: false,
            crown_jewel: false,
            asset_value: 1.0,
            business_value_usd: None,
            first_seen_days: age,
        }
    }

    #[test]
    fn empty_program_forecasts_zero() {
        let f = forecast(&[], &DEFAULT_HORIZONS);
        assert_eq!(f.len(), DEFAULT_HORIZONS.len());
        assert!(f.iter().all(|b| b.breached == 0));
    }

    #[test]
    fn forecast_is_cumulative_and_monotonic() {
        // High risk (non-KEV) → 30-day SLA window. Age 20 → due in 10 → breaches by day 14/30, not 7.
        let program = rank(&[finding("a", "high", Some(7.5), Some(20))]);
        let f = forecast(&program, &[7, 14, 30, 60, 90]);
        assert_eq!(f[0].breached, 0); // within 7 days: due_in 10 > 7
        assert_eq!(f[1].breached, 1); // within 14: 10 <= 14
        // monotonic non-decreasing
        for w in f.windows(2) {
            assert!(w[1].breached >= w[0].breached);
        }
    }

    #[test]
    fn already_overdue_counts_in_every_horizon() {
        let mut fkev = finding("a", "high", Some(7.5), Some(90)); // 30-day window, age 90 → overdue
        fkev.kev = true;
        let program = rank(&[fkev]);
        let f = forecast(&program, &[7, 14, 30]);
        assert!(f.iter().all(|b| b.breached == 1 && b.kev_breached == 1));
        assert_eq!(overdue_now(&program), 1);
    }

    #[test]
    fn unknown_age_never_forecast_as_breach() {
        let program = rank(&[finding("a", "critical", Some(9.0), None)]);
        let f = forecast(&program, &[7, 30, 90, 3650]);
        assert!(f.iter().all(|b| b.breached == 0));
        assert_eq!(overdue_now(&program), 0);
    }

    #[test]
    fn kev_and_crown_subsets_are_tracked() {
        let mut a = finding("a", "high", Some(7.5), Some(90)); // overdue
        a.kev = true;
        a.kev_ransomware = true;
        a.crown_jewel = true;
        let program = rank(&[a]);
        let f = forecast(&program, &[30]);
        assert_eq!(f[0].breached, 1);
        assert_eq!(f[0].kev_breached, 1);
        assert_eq!(f[0].ransomware_breached, 1);
        assert_eq!(f[0].crown_jewel_breached, 1);
    }

    #[test]
    fn horizons_are_sorted_and_deduped() {
        let program = rank(&[finding("a", "low", Some(2.0), Some(1))]);
        let f = forecast(&program, &[30, 7, 30, 14]);
        let days: Vec<i64> = f.iter().map(|b| b.within_days).collect();
        assert_eq!(days, vec![7, 14, 30]);
    }
}
