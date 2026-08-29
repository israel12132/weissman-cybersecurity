//! Cross-tenant billing/quota aggregation for `weissman_analytics`.
//!
//! Must run on the analytics pool (BYPASSRLS, SELECT-only on metrics tables).
//! `weissman_app` under FORCE RLS cannot sum usage across tenants.

use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct QuotaUsageRow {
    pub tenant_id: i64,
    pub resource: String,
    pub period_key: String,
    pub used: i64,
}

/// All tenants' quota counters.
pub async fn quota_usage_snapshot(pool: &PgPool) -> Result<Vec<QuotaUsageRow>, sqlx::Error> {
    let rows: Vec<(i64, String, String, i64)> = sqlx::query_as(
        r#"SELECT tenant_id, resource, period_key, used
           FROM weissman_tenant_quota_usage
           ORDER BY tenant_id, resource, period_key"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(tenant_id, resource, period_key, used)| QuotaUsageRow {
            tenant_id,
            resource,
            period_key,
            used,
        })
        .collect())
}

/// Scan-start counters for every tenant in `period_ym` (`YYYY-MM`).
pub async fn tenant_scan_usage_for_period(
    pool: &PgPool,
    period_ym: &str,
) -> Result<Vec<(i64, i64)>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT tenant_id, scans_started
           FROM tenant_usage_counters
           WHERE period_ym = $1
           ORDER BY tenant_id"#,
    )
    .bind(period_ym)
    .fetch_all(pool)
    .await
}
