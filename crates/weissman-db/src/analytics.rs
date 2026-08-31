//! Billing/quota reads for `weissman_analytics` and the worker refresh path.
//!
//! Live aggregation over raw meter tables is forbidden: `weissman_analytics` has
//! no GRANT on those heaps. The worker calls
//! [`refresh_billing_usage_snapshot`] (SECURITY DEFINER) on the control pool;
//! API and analytics SELECT a single PK row from `weissman_billing_usage_snapshot`.

use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct BillingUsageSnapshotRow {
    pub tenant_id: i64,
    pub period_ym: String,
    pub scans_started: i64,
    pub llm_tokens: i64,
}

/// Run the owner-definer upsert. Must use the **worker** pool (`weissman_worker`
/// has EXECUTE; analytics is transaction-read-only).
pub async fn refresh_billing_usage_snapshot(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>("SELECT public.weissman_refresh_billing_usage_snapshot()")
        .fetch_one(pool)
        .await
}

/// Ready snapshot rows (one per tenant per period). Cheap seq scan of a small table.
pub async fn billing_usage_snapshot(
    pool: &PgPool,
) -> Result<Vec<BillingUsageSnapshotRow>, sqlx::Error> {
    let rows: Vec<(i64, String, i64, i64)> = sqlx::query_as(
        r#"SELECT tenant_id, period_ym, scans_started, llm_tokens
           FROM weissman_billing_usage_snapshot
           ORDER BY tenant_id, period_ym"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(tenant_id, period_ym, scans_started, llm_tokens)| BillingUsageSnapshotRow {
                tenant_id,
                period_ym,
                scans_started,
                llm_tokens,
            },
        )
        .collect())
}

/// Scan-start counters for every tenant in `period_ym` (`YYYY-MM`) from the snapshot.
pub async fn tenant_scan_usage_for_period(
    pool: &PgPool,
    period_ym: &str,
) -> Result<Vec<(i64, i64)>, sqlx::Error> {
    sqlx::query_as(
        r#"SELECT tenant_id, scans_started
           FROM weissman_billing_usage_snapshot
           WHERE period_ym = $1
           ORDER BY tenant_id"#,
    )
    .bind(period_ym)
    .fetch_all(pool)
    .await
}
