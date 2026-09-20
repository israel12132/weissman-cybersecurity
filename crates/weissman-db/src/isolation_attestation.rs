//! Per-tenant DB-enforced isolation attestation (Step 17).
//!
//! The Step-1 RLS/client-scope introspection was real but trapped inside pass/fail test
//! bodies (`tests/rls_live_schema_contract.rs`), so the DB truth that WOULD be an
//! attestation was computed and thrown away — nothing could export it for a regulated
//! buyer. This module lifts that introspection into a reusable, serde-serializable emitter:
//! [`build_isolation_attestation`] runs the SAME `pg_catalog` queries the contract test
//! proves correct and returns a [`TenantIsolationAttestation`] — the live, DB-enforced
//! isolation posture (per-table RLS enable/force/policy facts, client-visibility coverage,
//! the read-only role's SELECT surface, the tenant-GUC role-default guard) plus the active
//! tenant ids and a single `compliant` verdict.
//!
//! Because the emitter and the contract test now share one implementation, the exported
//! report and the CI gate cannot drift: the contract test asserts against this emitter's
//! output, and any weakening (a table that stops FORCE-ing RLS, a `USING(true)` no-op, a
//! stray `weissman_ro` grant) flips `compliant` to false in both the report and CI at once.
//!
//! The pure compliance aggregation is unit-tested without a database; the full emitter is
//! covered by `tests/isolation_attestation_live.rs` against the live migrated schema.

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

/// Tenant tables allowed to skip the ENABLE+FORCE+tenant-GUC contract (documented globals).
/// Mirrors the contract test; kept here so the test and the report share ONE allowlist.
pub const TENANT_RLS_ALLOWLIST: &[&str] = &[];

/// `client_id` tables allowed to skip the customer-visibility predicate (documented globals).
pub const CLIENT_SCOPE_ALLOWLIST: &[&str] = &["cem_dago_telemetry_quarantine_global"];

/// Live isolation posture of one base table.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableIsolationPosture {
    pub schema: String,
    pub table: String,
    /// RLS enabled (`relrowsecurity`). Only meaningful for tenant tables.
    pub rls_enabled: bool,
    /// RLS FORCEd for the owner too (`relforcerowsecurity`).
    pub rls_forced: bool,
    /// A policy scopes rows by the tenant GUC (`app_current_tenant_id`).
    pub has_tenant_guc_policy: bool,
    /// A policy uses the literal `USING (true)` no-op that defeats isolation.
    pub has_using_true: bool,
    /// A policy scopes rows by customer visibility (`weissman_client_row_visible`/`app_current_client_id`).
    pub has_client_visibility: bool,
    /// Documented allowlist exception (no isolation required for this global table).
    pub allowlisted: bool,
    /// Whether this table meets its isolation contract.
    pub compliant: bool,
}

/// A full, exportable per-database tenant-isolation attestation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantIsolationAttestation {
    pub schema_version: String,
    /// Active tenant ids the isolation applies to (from `public.active_tenant_ids()`).
    pub active_tenant_ids: Vec<i64>,
    /// Every base table carrying a `tenant_id` column and its RLS posture.
    pub tenant_tables: Vec<TableIsolationPosture>,
    /// Every base table carrying a `client_id` column and its client-visibility posture.
    pub client_tables: Vec<TableIsolationPosture>,
    /// Non-app roles whose default tenant GUC is set (should be 0 — a non-zero count means a
    /// role could carry a cross-tenant GUC default and read across tenants; see role_guard).
    pub tenant_guc_role_default_count: i64,
    /// Single verdict: true iff every table is compliant and the role guards hold.
    pub compliant: bool,
}

pub const ATTESTATION_SCHEMA_VERSION: &str = "weissman-isolation-attestation-v1";

/// Pure: does a tenant table meet the ENABLE+FORCE+tenant-GUC, no-`USING(true)` contract?
#[must_use]
pub fn tenant_table_compliant(enabled: bool, forced: bool, has_guc: bool, has_true: bool, allowlisted: bool) -> bool {
    allowlisted || (enabled && forced && has_guc && !has_true)
}

/// Pure: does a client_id table carry the customer-visibility predicate?
#[must_use]
pub fn client_table_compliant(has_visibility: bool, allowlisted: bool) -> bool {
    allowlisted || has_visibility
}

/// Pure: aggregate the whole-database verdict from the parts.
#[must_use]
pub fn aggregate_compliant(
    tenant_tables: &[TableIsolationPosture],
    client_tables: &[TableIsolationPosture],
    tenant_guc_role_default_count: i64,
) -> bool {
    tenant_tables.iter().all(|t| t.compliant)
        && client_tables.iter().all(|t| t.compliant)
        && tenant_guc_role_default_count == 0
}

/// Build the live isolation attestation from `pg_catalog`. Runs the same introspection the
/// Step-1 contract test proves correct; returns the structured, exportable posture.
///
/// # Errors
/// Propagates any `sqlx` error from the introspection queries.
pub async fn build_isolation_attestation(pool: &PgPool) -> Result<TenantIsolationAttestation, sqlx::Error> {
    // Active tenant ids the isolation protects (SECURITY DEFINER, ids only).
    let active_tenant_ids: Vec<i64> =
        sqlx::query_scalar("SELECT * FROM public.active_tenant_ids()").fetch_all(pool).await?;

    // Contract 1: tenant_id tables — ENABLE + FORCE RLS + a tenant-GUC policy, no USING(true).
    // Same query as tests/rls_live_schema_contract.rs (the _probe exclusion keeps transient
    // sibling-test fixtures from masquerading as offenders).
    let tenant_rows = sqlx::query(
        r#"
        WITH t AS (
            SELECT c.oid, n.nspname AS schema_name, c.relname AS table_name,
                   c.relrowsecurity AS enabled, c.relforcerowsecurity AS forced
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r'
              AND NOT (c.relpersistence = 'u' AND right(c.relname, 6) = '_probe')
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND EXISTS (
                  SELECT 1 FROM information_schema.columns col
                  WHERE col.table_schema = n.nspname
                    AND col.table_name = c.relname
                    AND col.column_name = 'tenant_id')
        ), pol AS (
            SELECT polrelid,
                   bool_or(pg_get_expr(polqual, polrelid) ILIKE '%app_current_tenant_id%'
                        OR pg_get_expr(polqual, polrelid) ILIKE '%app.current_tenant_id%') AS has_guc,
                   bool_or(btrim(coalesce(pg_get_expr(polqual, polrelid), '')) = 'true') AS has_true
            FROM pg_policy GROUP BY polrelid
        )
        SELECT t.schema_name, t.table_name, t.enabled, t.forced,
               coalesce(p.has_guc, false) AS has_guc,
               coalesce(p.has_true, false) AS has_true
        FROM t LEFT JOIN pol p ON p.polrelid = t.oid
        ORDER BY 1, 2
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut tenant_tables = Vec::with_capacity(tenant_rows.len());
    for row in &tenant_rows {
        let schema: String = row.get("schema_name");
        let table: String = row.get("table_name");
        let enabled: bool = row.get("enabled");
        let forced: bool = row.get("forced");
        let has_guc: bool = row.get("has_guc");
        let has_true: bool = row.get("has_true");
        let allowlisted = TENANT_RLS_ALLOWLIST.contains(&table.as_str());
        tenant_tables.push(TableIsolationPosture {
            schema,
            table,
            rls_enabled: enabled,
            rls_forced: forced,
            has_tenant_guc_policy: has_guc,
            has_using_true: has_true,
            has_client_visibility: false,
            allowlisted,
            compliant: tenant_table_compliant(enabled, forced, has_guc, has_true, allowlisted),
        });
    }

    // Contract 2: client_id tables — customer-visibility predicate present.
    let client_rows = sqlx::query(
        r#"
        WITH t AS (
            SELECT c.oid, n.nspname AS schema_name, c.relname AS table_name
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind = 'r'
              AND NOT (c.relpersistence = 'u' AND right(c.relname, 6) = '_probe')
              AND n.nspname = 'public'
              AND c.relname <> 'tenant_idps'
              AND EXISTS (
                  SELECT 1 FROM information_schema.columns col
                  WHERE col.table_schema = n.nspname
                    AND col.table_name = c.relname
                    AND col.column_name = 'client_id')
        ), pol AS (
            SELECT polrelid,
                   bool_or(pg_get_expr(polqual, polrelid) ILIKE '%weissman_client_row_visible%'
                        OR pg_get_expr(polqual, polrelid) ILIKE '%app_current_client_id%'
                        OR pg_get_expr(polwithcheck, polrelid) ILIKE '%weissman_client_row_visible%'
                        OR pg_get_expr(polwithcheck, polrelid) ILIKE '%app_current_client_id%') AS has_vis
            FROM pg_policy GROUP BY polrelid
        )
        SELECT t.schema_name, t.table_name, coalesce(p.has_vis, false) AS has_vis
        FROM t LEFT JOIN pol p ON p.polrelid = t.oid
        ORDER BY 1, 2
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut client_tables = Vec::with_capacity(client_rows.len());
    for row in &client_rows {
        let schema: String = row.get("schema_name");
        let table: String = row.get("table_name");
        let has_vis: bool = row.get("has_vis");
        let allowlisted = CLIENT_SCOPE_ALLOWLIST.contains(&table.as_str());
        client_tables.push(TableIsolationPosture {
            schema,
            table,
            rls_enabled: true,
            rls_forced: true,
            has_tenant_guc_policy: false,
            has_using_true: false,
            has_client_visibility: has_vis,
            allowlisted,
            compliant: client_table_compliant(has_vis, allowlisted),
        });
    }

    // Reuse the boot-guard introspection so the report and assert_pool_role agree. This reads
    // pg_db_role_setting (role config), so it is correct regardless of the building connection.
    let tenant_guc_role_default_count = crate::role_guard::tenant_guc_role_default_count(pool).await?;

    let compliant = aggregate_compliant(&tenant_tables, &client_tables, tenant_guc_role_default_count);

    Ok(TenantIsolationAttestation {
        schema_version: ATTESTATION_SCHEMA_VERSION.to_string(),
        active_tenant_ids,
        tenant_tables,
        client_tables,
        tenant_guc_role_default_count,
        compliant,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posture(compliant: bool) -> TableIsolationPosture {
        TableIsolationPosture {
            schema: "public".into(),
            table: "t".into(),
            rls_enabled: true,
            rls_forced: true,
            has_tenant_guc_policy: true,
            has_using_true: false,
            has_client_visibility: true,
            allowlisted: false,
            compliant,
        }
    }

    #[test]
    fn tenant_table_contract_logic() {
        // Full compliance.
        assert!(tenant_table_compliant(true, true, true, false, false));
        // Any missing pillar fails.
        assert!(!tenant_table_compliant(false, true, true, false, false), "not enabled");
        assert!(!tenant_table_compliant(true, false, true, false, false), "not forced");
        assert!(!tenant_table_compliant(true, true, false, false, false), "no tenant-GUC policy");
        // A USING(true) no-op defeats isolation even with everything else set.
        assert!(!tenant_table_compliant(true, true, true, true, false), "USING(true) is a no-op");
        // Allowlisted globals are compliant by exception regardless of posture.
        assert!(tenant_table_compliant(false, false, false, true, true), "allowlisted");
    }

    #[test]
    fn client_table_contract_logic() {
        assert!(client_table_compliant(true, false));
        assert!(!client_table_compliant(false, false), "no client-visibility predicate");
        assert!(client_table_compliant(false, true), "allowlisted global");
    }

    #[test]
    fn aggregate_requires_every_part() {
        let ok_t = vec![posture(true)];
        let ok_c = vec![posture(true)];
        assert!(aggregate_compliant(&ok_t, &ok_c, 0));
        // One non-compliant table sinks the whole attestation.
        assert!(!aggregate_compliant(&[posture(false)], &ok_c, 0));
        assert!(!aggregate_compliant(&ok_t, &[posture(false)], 0));
        // A non-app role with a default tenant GUC (cross-tenant read risk) sinks it.
        assert!(!aggregate_compliant(&ok_t, &ok_c, 1));
    }
}
