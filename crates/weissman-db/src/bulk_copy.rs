//! High-throughput Postgres `COPY` ingest for stealth-evasion check results.
//!
//! Falls back to batched `INSERT` when `COPY FROM STDIN` is unavailable (RLS
//! role, tests without the table, etc.). Tenant GUC is set before either path
//! so FORCE RLS WITH CHECK still applies.

use serde_json::Value;
use sqlx::{Pool, Postgres, Row};

#[derive(Debug, Clone)]
pub struct StealthCheckRow {
    pub check_id: i16,
    pub domain: i16,
    pub status: String,
    pub severity: String,
    pub mitre: String,
    pub title: String,
    pub evidence: Value,
}

impl StealthCheckRow {
    pub fn new(
        check_id: u16,
        domain: u8,
        status: impl Into<String>,
        severity: impl Into<String>,
        mitre: impl Into<String>,
        title: impl Into<String>,
        evidence: Value,
    ) -> Self {
        Self {
            check_id: check_id as i16,
            domain: i16::from(domain),
            status: status.into(),
            severity: severity.into(),
            mitre: mitre.into(),
            title: title.into(),
            evidence,
        }
    }
}

/// COPY into a session-scoped TEMP table, then one atomic UPSERT
/// (`INSERT … ON CONFLICT DO UPDATE`). Avoids UniqueViolation when the
/// control-plane and an agent persist the same (tenant, client, check_id).
pub async fn copy_stealth_check_results(
    pool: &Pool<Postgres>,
    tenant_id: i64,
    client_id: i64,
    rows: &[StealthCheckRow],
) -> Result<(u64, bool), sqlx::Error> {
    match try_copy_upsert(pool, tenant_id, client_id, rows).await {
        Ok(n) => Ok((n, true)),
        Err(e) => {
            tracing::warn!(
                target: "bulk_copy",
                error = %e,
                rows = rows.len(),
                "COPY+UPSERT failed; falling back to INSERT"
            );
            let n = insert_rows(pool, tenant_id, client_id, rows).await?;
            Ok((n, false))
        }
    }
}

async fn try_copy_upsert(
    pool: &Pool<Postgres>,
    tenant_id: i64,
    client_id: i64,
    rows: &[StealthCheckRow],
) -> Result<u64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(tenant_id.to_string())
        .execute(&mut *conn)
        .await?;
    sqlx::query("SELECT set_config('app.current_client_id', $1, true)")
        .bind(client_id.to_string())
        .execute(&mut *conn)
        .await?;

    sqlx::query("DROP TABLE IF EXISTS stealth_evasion_ingest")
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        r#"CREATE TEMP TABLE stealth_evasion_ingest (
            tenant_id BIGINT NOT NULL,
            client_id BIGINT NOT NULL,
            check_id SMALLINT NOT NULL,
            domain SMALLINT NOT NULL,
            status TEXT NOT NULL,
            severity TEXT NOT NULL,
            mitre TEXT NOT NULL,
            title TEXT NOT NULL,
            evidence_json JSONB NOT NULL
        )"#,
    )
    .execute(&mut *conn)
    .await?;

    let csv = encode_csv(tenant_id, client_id, rows);
    let stmt = concat!(
        "COPY stealth_evasion_ingest ",
        "(tenant_id, client_id, check_id, domain, status, severity, mitre, title, evidence_json) ",
        "FROM STDIN WITH (FORMAT csv, HEADER false)"
    );
    let mut copy = conn.copy_in_raw(stmt).await?;
    if !csv.is_empty() {
        copy.send(csv.into_bytes()).await?;
    }
    let _copied = copy.finish().await?;

    let n = sqlx::query_scalar::<_, i64>(
        r#"WITH up AS (
            INSERT INTO stealth_evasion_check_results
                (tenant_id, client_id, check_id, domain, status, severity, mitre, title, evidence_json)
            SELECT tenant_id, client_id, check_id, domain, status, severity, mitre, title, evidence_json
              FROM stealth_evasion_ingest
            ON CONFLICT (tenant_id, client_id, check_id) DO UPDATE SET
                domain = EXCLUDED.domain,
                status = EXCLUDED.status,
                severity = EXCLUDED.severity,
                mitre = EXCLUDED.mitre,
                title = EXCLUDED.title,
                evidence_json = EXCLUDED.evidence_json,
                created_at = now()
            RETURNING 1
        )
        SELECT COUNT(*) FROM up"#,
    )
    .fetch_one(&mut *conn)
    .await?;

    let _ = sqlx::query("DROP TABLE IF EXISTS stealth_evasion_ingest")
        .execute(&mut *conn)
        .await;

    Ok(n as u64)
}

fn encode_csv(tenant_id: i64, client_id: i64, rows: &[StealthCheckRow]) -> String {
    let mut out = String::new();
    for r in rows {
        let evidence = r.evidence.to_string();
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            tenant_id,
            client_id,
            r.check_id,
            r.domain,
            csv_field(&r.status),
            csv_field(&r.severity),
            csv_field(&r.mitre),
            csv_field(&r.title),
            csv_field(&evidence),
        ));
    }
    out
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

async fn insert_rows(
    pool: &Pool<Postgres>,
    tenant_id: i64,
    client_id: i64,
    rows: &[StealthCheckRow],
) -> Result<u64, sqlx::Error> {
    let mut tx = crate::begin_tenant_tx(pool, tenant_id).await?;
    let mut n = 0u64;
    for r in rows {
        sqlx::query(
            r#"INSERT INTO stealth_evasion_check_results
                (tenant_id, client_id, check_id, domain, status, severity, mitre, title, evidence_json)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
               ON CONFLICT (tenant_id, client_id, check_id) DO UPDATE SET
                 domain = EXCLUDED.domain,
                 status = EXCLUDED.status,
                 severity = EXCLUDED.severity,
                 mitre = EXCLUDED.mitre,
                 title = EXCLUDED.title,
                 evidence_json = EXCLUDED.evidence_json,
                 created_at = now()"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(r.check_id)
        .bind(r.domain)
        .bind(&r.status)
        .bind(&r.severity)
        .bind(&r.mitre)
        .bind(&r.title)
        .bind(sqlx::types::Json(&r.evidence))
        .execute(&mut *tx)
        .await?;
        n += 1;
    }
    tx.commit().await?;
    Ok(n)
}

/// Confirm SKIP LOCKED claim SQL is present in the live catalog (planner accepts it).
pub async fn skip_locked_is_live(
    pool: &Pool<Postgres>,
    tenant_id: i64,
) -> Result<bool, sqlx::Error> {
    let mut tx = crate::begin_tenant_tx(pool, tenant_id).await?;
    let ok = sqlx::query(
        r#"SELECT id FROM weissman_async_jobs
            WHERE status = 'pending'
              AND (run_after IS NULL OR run_after <= now())
            FOR UPDATE SKIP LOCKED LIMIT 0"#,
    )
    .fetch_all(&mut *tx)
    .await
    .is_ok();
    let _ = tx.commit().await;
    Ok(ok)
}

/// Count RLS policies on the stealth results table.
pub async fn stealth_rls_policy_count(
    pool: &Pool<Postgres>,
    tenant_id: i64,
) -> Result<i64, sqlx::Error> {
    let mut tx = crate::begin_tenant_tx(pool, tenant_id).await?;
    let n = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM pg_policies WHERE tablename = 'stealth_evasion_check_results'"#,
    )
    .fetch_one(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(n)
}

/// Latest check results for a client (tenant-scoped).
pub async fn latest_results(
    pool: &Pool<Postgres>,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT check_id, domain, status, severity, mitre, title, evidence_json, created_at
             FROM stealth_evasion_check_results
            WHERE client_id = $1
            ORDER BY id DESC
            LIMIT $2"#,
    )
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "check_id": r.try_get::<i16, _>("check_id").unwrap_or(0),
                "domain": r.try_get::<i16, _>("domain").unwrap_or(0),
                "status": r.try_get::<String, _>("status").unwrap_or_default(),
                "severity": r.try_get::<String, _>("severity").unwrap_or_default(),
                "mitre": r.try_get::<String, _>("mitre").unwrap_or_default(),
                "title": r.try_get::<String, _>("title").unwrap_or_default(),
                "evidence": r.try_get::<sqlx::types::Json<Value>, _>("evidence_json")
                    .ok()
                    .map(|j| j.0)
                    .unwrap_or(Value::Null),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .ok()
                    .map(|t| t.to_rfc3339()),
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_commas_and_quotes() {
        assert_eq!(csv_field("ok"), "ok");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
