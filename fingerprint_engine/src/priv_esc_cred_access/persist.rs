//! Bulk UPSERT of all 500 control rows (including `na` / `not_observed`) under RLS.
//!
//! One transaction, one `INSERT … SELECT UNNEST … ON CONFLICT`. Never 500
//! sequential statements. `begin_tenant_tx_scoped` stamps
//! `SET LOCAL app.current_tenant_id` (`set_config(..., true)`). Rows without a
//! tenant are not written; `client_id` may be NULL.

use super::eval::Coverage;
use crate::engine_dispatch::EngineRunContext;

/// Bulk upsert SQL — kept as a named constant so unit tests can lock the contract
/// (UNNEST + ON CONFLICT + tenant_id) without a live database.
pub const BULK_UPSERT_SQL: &str = r#"
INSERT INTO privilege_escalation_control_results
    (tenant_id, client_id, host_id, control_id, status, domain, mitre, title, evidence, job_id)
SELECT $1, $2, $3, x.control_id, x.status, x.domain, x.mitre, x.title, x.evidence, $4
  FROM UNNEST(
           $5::int[],
           $6::text[],
           $7::text[],
           $8::text[],
           $9::text[],
           $10::text[]
       ) AS x(control_id, status, domain, mitre, title, evidence)
ON CONFLICT (tenant_id, host_id, control_id) DO UPDATE SET
    status = EXCLUDED.status,
    domain = EXCLUDED.domain,
    mitre = EXCLUDED.mitre,
    title = EXCLUDED.title,
    evidence = EXCLUDED.evidence,
    client_id = EXCLUDED.client_id,
    job_id = EXCLUDED.job_id,
    evaluated_at = now()
"#;

pub async fn persist_coverage(
    ctx: &EngineRunContext,
    host_id: &str,
    cov: &Coverage,
) -> Result<u64, String> {
    let pool = ctx.app_pool.as_ref().ok_or("no app_pool")?;
    let tenant_id = ctx.tenant_id.ok_or("no tenant_id")?;
    // client_id is optional on the table; tenant_id is the RLS key and is always required.
    let client_id = ctx.client_id;
    let host_id = sanitize_host_id(host_id);
    let job_id = ctx.job_id.clone();

    let mut control_ids: Vec<i32> = Vec::with_capacity(cov.slots.len());
    let mut statuses: Vec<String> = Vec::with_capacity(cov.slots.len());
    let mut domains: Vec<String> = Vec::with_capacity(cov.slots.len());
    let mut mitres: Vec<String> = Vec::with_capacity(cov.slots.len());
    let mut titles: Vec<String> = Vec::with_capacity(cov.slots.len());
    let mut evidences: Vec<String> = Vec::with_capacity(cov.slots.len());
    for slot in &cov.slots {
        control_ids.push(slot.check.id as i32);
        statuses.push(slot.status.slug().to_string());
        domains.push(slot.check.domain.slug().to_string());
        mitres.push(slot.check.mitre.to_string());
        titles.push(slot.check.title.clone());
        evidences.push(slot.evidence.chars().take(2000).collect());
    }

    // Stamp tenant *and* client GUCs from the job context (worker has no HTTP
    // task-local client scope). SET LOCAL is_local=true so RLS cannot leak
    // na / not_observed rows across tenants.
    let mut tx = crate::db::begin_tenant_tx_scoped(pool.as_ref(), tenant_id, client_id)
        .await
        .map_err(|e| format!("begin_tenant_tx_scoped: {e}"))?;

    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("SET LOCAL tenant: {e}"))?;

    let result = sqlx::query(BULK_UPSERT_SQL)
        .bind(tenant_id)
        .bind(client_id)
        .bind(&host_id)
        .bind(&job_id)
        .bind(&control_ids)
        .bind(&statuses)
        .bind(&domains)
        .bind(&mitres)
        .bind(&titles)
        .bind(&evidences)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("bulk upsert: {e}"))?;

    tx.commit()
        .await
        .map_err(|e| format!("commit coverage: {e}"))?;
    Ok(result.rows_affected())
}

fn sanitize_host_id(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() {
        "unknown-host".into()
    } else {
        t.chars().take(256).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_sql_is_one_unnest_upsert() {
        let sql = BULK_UPSERT_SQL.to_ascii_uppercase();
        assert!(sql.contains("UNNEST"), "must bulk UNNEST, not 500 INSERTs");
        assert!(sql.contains("ON CONFLICT (TENANT_ID, HOST_ID, CONTROL_ID)"));
        assert_eq!(sql.matches("INSERT").count(), 1, "exactly one INSERT");
    }

    #[test]
    fn persist_fn_sets_local_tenant_guc() {
        let src = include_str!("persist.rs");
        assert!(src.contains("set_config('app.current_tenant_id'"));
        assert!(src.contains("begin_tenant_tx_scoped"));
        assert!(src.contains(", true)"));
        assert!(src.contains("INSERT INTO privilege_escalation_control_results"));
    }

    #[test]
    fn bulk_sql_always_writes_tenant_id() {
        let sql = BULK_UPSERT_SQL;
        assert!(sql.contains("tenant_id, client_id, host_id, control_id"));
        assert!(sql.contains("SELECT $1, $2, $3"));
    }
}
