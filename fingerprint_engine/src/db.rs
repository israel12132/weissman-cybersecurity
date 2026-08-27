//! Re-exports the authoritative Postgres / RLS layer ([`weissman_db`]). Prefer importing `weissman_db`
//! directly in new code; this module keeps `crate::db::` and `fingerprint_engine::db::` stable.
//!
//! HTTP requests wrap work in [`REQUEST_CLIENT_SCOPE`] (set by
//! [`crate::http::client_scope::TenantScopeGuard`] from the JWT `cid`). The local
//! [`begin_tenant_tx`] shadows the glob re-export and stamps
//! `SET LOCAL app.current_tenant_id` **and** `app.current_client_id` so a
//! forgotten `WHERE client_id` filter cannot leak another customer's rows.
//! Background workers that call [`weissman_db::begin_tenant_tx`] directly leave the
//! client GUC empty (all customers in the tenant — required for dequeue).

pub use weissman_db::*;

tokio::task_local! {
    /// Assigned customer id for this HTTP request (`None` = owner/staff).
    pub static REQUEST_CLIENT_SCOPE: Option<i64>;
}

#[must_use]
pub fn current_request_client_scope() -> Option<i64> {
    REQUEST_CLIENT_SCOPE.try_with(|c| *c).ok().flatten()
}

pub async fn set_tenant_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
) -> Result<(), sqlx::Error> {
    weissman_db::set_tenant_tx_scoped(tx, tenant_id, current_request_client_scope()).await
}

pub async fn begin_tenant_tx(
    pool: &sqlx::PgPool,
    tenant_id: i64,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
    weissman_db::begin_tenant_tx_scoped(pool, tenant_id, current_request_client_scope()).await
}

pub async fn begin_tenant_tx_arc(
    pool: std::sync::Arc<sqlx::PgPool>,
    tenant_id: i64,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, sqlx::Error> {
    weissman_db::begin_tenant_tx_arc_scoped(pool, tenant_id, current_request_client_scope()).await
}
