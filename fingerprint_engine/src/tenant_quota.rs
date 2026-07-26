//! Per-tenant resource quotas: period-scoped consumption accounting enforced against
//! plan limits. This is the *longer-horizon* budget (monthly scan quota, daily API budget)
//! that complements the short-horizon rate limiters in `http::api_rate_limit` /
//! `http::tenant_scan_limit`. Backed by `weissman_tenant_quota_usage` under forced RLS, so
//! one tenant can never read or spend another's budget.
//!
//! The period math and the allow/deny decision are pure and fully unit-tested; the atomic
//! upsert-increment runs inside a tenant transaction (`begin_tenant_tx`) so the count is
//! consistent under concurrency and isolated per tenant.

use chrono::{Datelike, TimeZone, Utc};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Accounting period for a quota.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QuotaWindow {
    Daily,
    Monthly,
}

impl QuotaWindow {
    /// The period-bucket key for `unix_secs` (UTC): `YYYY-MM-DD` daily, `YYYY-MM` monthly.
    pub fn period_key(self, unix_secs: u64) -> String {
        let dt = Utc
            .timestamp_opt(unix_secs as i64, 0)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap());
        match self {
            QuotaWindow::Daily => format!("{:04}-{:02}-{:02}", dt.year(), dt.month(), dt.day()),
            QuotaWindow::Monthly => format!("{:04}-{:02}", dt.year(), dt.month()),
        }
    }

    /// Unix seconds at which the current period rolls over (start of next day / month, UTC).
    pub fn reset_at(self, unix_secs: u64) -> u64 {
        let dt = Utc
            .timestamp_opt(unix_secs as i64, 0)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap());
        let next = match self {
            QuotaWindow::Daily => {
                let day = dt.date_naive();
                let next_day = day.succ_opt().unwrap_or(day);
                next_day
                    .and_hms_opt(0, 0, 0)
                    .map(|n| n.and_utc().timestamp())
            }
            QuotaWindow::Monthly => {
                let (y, m) = (dt.year(), dt.month());
                let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
                chrono::NaiveDate::from_ymd_opt(ny, nm, 1)
                    .and_then(|d| d.and_hms_opt(0, 0, 0))
                    .map(|n| n.and_utc().timestamp())
            }
        };
        next.map(|s| s.max(0) as u64).unwrap_or(unix_secs)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            QuotaWindow::Daily => "daily",
            QuotaWindow::Monthly => "monthly",
        }
    }
}

/// Outcome of a quota check (also the shape returned by `GET /api/quota`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaDecision {
    pub resource: String,
    pub window: QuotaWindow,
    /// True when this consumption is within budget. Always true when `limit == 0` (unlimited).
    pub allowed: bool,
    /// Usage *after* accounting for the current request.
    pub used: u64,
    /// Configured ceiling; `0` means unlimited.
    pub limit: u64,
    pub remaining: u64,
    pub period_key: String,
    pub reset_at_unix: u64,
}

/// Pure decision: given post-increment `used` and the `limit`, decide allow/deny.
/// `limit == 0` is treated as unlimited (always allowed). The request that takes usage
/// exactly to `limit` is allowed; the next one (over) is denied.
pub fn evaluate(
    resource: &str,
    window: QuotaWindow,
    used: u64,
    limit: u64,
    now_unix: u64,
) -> QuotaDecision {
    let unlimited = limit == 0;
    let allowed = unlimited || used <= limit;
    let remaining = if unlimited {
        u64::MAX
    } else {
        limit.saturating_sub(used)
    };
    QuotaDecision {
        resource: resource.to_string(),
        window,
        allowed,
        used,
        limit,
        remaining,
        period_key: window.period_key(now_unix),
        reset_at_unix: window.reset_at(now_unix),
    }
}

/// Current wall-clock unix seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve the effective limit for `resource` — per-tenant override from `system_configs`
/// (key `<resource>_<window>_quota`, e.g. `scans_monthly_quota`) falling back to the
/// process default env var, else `default`. `0` = unlimited.
pub async fn resolve_limit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    resource: &str,
    window: QuotaWindow,
    default: u64,
) -> u64 {
    let key = format!("{resource}_{}_quota", window.as_str());
    let override_val: Option<String> =
        sqlx::query_scalar("SELECT value FROM system_configs WHERE tenant_id = $1 AND key = $2")
            .bind(tenant_id)
            .bind(&key)
            .fetch_optional(&mut **tx)
            .await
            .ok()
            .flatten();
    override_val
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// Atomically account one unit and return the decision — resolving the per-tenant limit
/// and doing the upsert-increment in a single tenant tx (RLS-scoped). The increment is one
/// statement so concurrent requests can't lose a count. `default_limit` is the fallback when
/// no per-tenant override exists; `0` = unlimited.
pub async fn enforce(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    resource: &str,
    window: QuotaWindow,
    default_limit: u64,
) -> Result<QuotaDecision, sqlx::Error> {
    let now = now_unix();
    let period = window.period_key(now);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let limit = resolve_limit(&mut tx, tenant_id, resource, window, default_limit).await;
    let used: i64 = sqlx::query_scalar(
        "INSERT INTO weissman_tenant_quota_usage (tenant_id, resource, period_key, used) \
         VALUES ($1, $2, $3, 1) \
         ON CONFLICT (tenant_id, resource, period_key) \
         DO UPDATE SET used = weissman_tenant_quota_usage.used + 1, updated_at = now() \
         RETURNING used",
    )
    .bind(tenant_id)
    .bind(resource)
    .bind(&period)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let decision = evaluate(resource, window, used.max(0) as u64, limit, now);
    metrics::gauge!("weissman_tenant_quota_used", "resource" => resource.to_string())
        .set(decision.used as f64);
    if !decision.allowed {
        metrics::counter!("weissman_tenant_quota_denied_total", "resource" => resource.to_string())
            .increment(1);
    }
    Ok(decision)
}

/// Report current usage without consuming (for `GET /api/quota`) — resolves the limit and
/// reads the current count in one tenant tx. Missing row → used 0.
pub async fn report(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    resource: &str,
    window: QuotaWindow,
    default_limit: u64,
) -> Result<QuotaDecision, sqlx::Error> {
    let now = now_unix();
    let period = window.period_key(now);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let limit = resolve_limit(&mut tx, tenant_id, resource, window, default_limit).await;
    let used: Option<i64> = sqlx::query_scalar(
        "SELECT used FROM weissman_tenant_quota_usage \
         WHERE tenant_id = $1 AND resource = $2 AND period_key = $3",
    )
    .bind(tenant_id)
    .bind(resource)
    .bind(&period)
    .fetch_optional(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    // report reflects current usage without the +1 the next request would add.
    Ok(evaluate(
        resource,
        window,
        used.unwrap_or(0).max(0) as u64,
        limit,
        now,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-07-24T12:00:00Z
    const T: u64 = 1_784_894_400;

    #[test]
    fn period_key_formats() {
        assert_eq!(QuotaWindow::Daily.period_key(T), "2026-07-24");
        assert_eq!(QuotaWindow::Monthly.period_key(T), "2026-07");
    }

    #[test]
    fn period_key_is_stable_within_and_changes_across_periods() {
        let plus_hours = T + 6 * 3600; // still 2026-07-24 (18:00Z)
        assert_eq!(
            QuotaWindow::Daily.period_key(T),
            QuotaWindow::Daily.period_key(plus_hours)
        );
        let plus_days = T + 10 * 86400; // 2026-08-03
        assert_ne!(
            QuotaWindow::Daily.period_key(T),
            QuotaWindow::Daily.period_key(plus_days)
        );
        assert_eq!(QuotaWindow::Monthly.period_key(plus_days), "2026-08");
    }

    #[test]
    fn daily_reset_is_next_midnight_utc() {
        let reset = QuotaWindow::Daily.reset_at(T);
        assert_eq!(QuotaWindow::Daily.period_key(reset), "2026-07-25");
        // exactly midnight: seconds since epoch divisible by 86400
        assert_eq!(reset % 86400, 0);
        assert!(reset > T);
    }

    #[test]
    fn monthly_reset_is_first_of_next_month() {
        let reset = QuotaWindow::Monthly.reset_at(T);
        assert_eq!(QuotaWindow::Daily.period_key(reset), "2026-08-01");
        assert!(reset > T);
    }

    #[test]
    fn monthly_reset_rolls_over_year_in_december() {
        // 2026-12-15T00:00:00Z
        let dec = Utc
            .with_ymd_and_hms(2026, 12, 15, 0, 0, 0)
            .unwrap()
            .timestamp() as u64;
        let reset = QuotaWindow::Monthly.reset_at(dec);
        assert_eq!(QuotaWindow::Daily.period_key(reset), "2027-01-01");
    }

    #[test]
    fn evaluate_allows_up_to_and_including_limit() {
        let d = evaluate("scans", QuotaWindow::Monthly, 5, 5, T);
        assert!(d.allowed, "usage == limit is the last allowed request");
        assert_eq!(d.remaining, 0);
        let over = evaluate("scans", QuotaWindow::Monthly, 6, 5, T);
        assert!(!over.allowed);
        assert_eq!(over.remaining, 0);
    }

    #[test]
    fn evaluate_reports_remaining() {
        let d = evaluate("scans", QuotaWindow::Monthly, 2, 10, T);
        assert!(d.allowed);
        assert_eq!(d.remaining, 8);
    }

    #[test]
    fn evaluate_zero_limit_is_unlimited() {
        let d = evaluate("scans", QuotaWindow::Monthly, 999_999, 0, T);
        assert!(d.allowed);
        assert_eq!(d.remaining, u64::MAX);
        assert_eq!(d.limit, 0);
    }

    #[test]
    fn decision_carries_period_and_reset() {
        let d = evaluate("api_requests", QuotaWindow::Daily, 1, 100, T);
        assert_eq!(d.period_key, "2026-07-24");
        assert_eq!(d.reset_at_unix, QuotaWindow::Daily.reset_at(T));
        assert_eq!(d.window, QuotaWindow::Daily);
    }

    #[test]
    fn window_labels_stable() {
        assert_eq!(QuotaWindow::Daily.as_str(), "daily");
        assert_eq!(QuotaWindow::Monthly.as_str(), "monthly");
    }
}
