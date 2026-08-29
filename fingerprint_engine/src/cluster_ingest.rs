//! Out-of-band finding-cluster assignment.
//!
//! The hot persist transaction writes `vulnerabilities` (and an append-only
//! ingest row) only. It must **not** lock `weissman_finding_clusters` — concurrent
//! workers on the same identity used to invert lock order (vuln row ↔ cluster
//! row) and deadlock the pool.
//!
//! COPY / binary ingest is not used here: each row carries a per-finding
//! `ON CONFLICT` identity and must participate in the persist transaction so a
//! failed enqueue aborts the finding write. After commit, [`drain_for_tenant`]
//! claims pending rows (`FOR UPDATE SKIP LOCKED`), takes a per-`cluster_key`
//! advisory lock, upserts the cluster, and stamps `vulnerabilities.cluster_id`.
//! Same-cluster work is serial; different keys proceed in parallel.

use std::collections::HashMap;

use serde_json::json;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::db;
use crate::findings_correlator::{self, ClusterAttrs};

#[derive(Debug, Clone)]
pub struct ClusterIngestRow {
    pub vuln_id: i64,
    pub cluster_key: String,
    pub target: String,
    pub engine: String,
    pub source: String,
    pub title: String,
    pub severity: String,
    pub cwe: String,
    pub vuln_signature: String,
    pub cve: Option<String>,
    pub cvss: Option<f64>,
    pub epss: Option<f32>,
    pub kev_listed: bool,
    pub is_new_member: bool,
}

/// Append-only enqueue inside the persist transaction (no cluster-row lock).
///
/// Failures **must** propagate — a swallowed SQL error aborts the PostgreSQL
/// transaction while `COMMIT` still returns success (it becomes ROLLBACK),
/// so the caller would report inserts that never landed.
pub async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
    row: &ClusterIngestRow,
) -> Result<(), String> {
    sqlx::query(
        r#"INSERT INTO weissman_cluster_ingest (
                tenant_id, client_id, vuln_id, cluster_key, target, engine, source,
                title, severity, cwe, vuln_signature, cve, cvss, epss, kev_listed, is_new_member
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(row.vuln_id)
    .bind(&row.cluster_key)
    .bind(&row.target)
    .bind(&row.engine)
    .bind(&row.source)
    .bind(&row.title)
    .bind(&row.severity)
    .bind(&row.cwe)
    .bind(&row.vuln_signature)
    .bind(&row.cve)
    .bind(row.cvss)
    .bind(row.epss)
    .bind(row.kev_listed)
    .bind(row.is_new_member)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("cluster ingest enqueue: {e}"))?;
    Ok(())
}

/// Drain pending cluster work for one tenant. Safe to call after persist commit
/// and from the worker idle loop. Returns rows processed.
pub async fn drain_for_tenant(pool: &PgPool, tenant_id: i64, limit: i64) -> Result<u64, String> {
    let cap = limit.clamp(1, 500);
    let mut processed: u64 = 0;
    loop {
        let n = drain_once(pool, tenant_id, cap).await?;
        processed += n;
        if n < cap as u64 {
            break;
        }
    }
    Ok(processed)
}

/// Crash-recovery sweep: drain every active tenant. Serial per tenant so a
/// wide scan cannot lock-invert against the hot persist path.
pub async fn drain_all_tenants(pool: &PgPool, per_tenant: i64) -> Result<u64, String> {
    let tenants = db::active_tenant_ids(pool)
        .await
        .map_err(|e| format!("cluster ingest tenants: {e}"))?;
    let mut processed: u64 = 0;
    for tid in tenants {
        match requeue_unclustered(pool, tid, per_tenant).await {
            Ok(n) if n > 0 => {
                tracing::info!(
                    target: "cluster_ingest",
                    tenant_id = tid,
                    requeued = n,
                    "re-enqueued unclustered findings after unlogged outbox loss"
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    target: "cluster_ingest",
                    tenant_id = tid,
                    error = %e,
                    "unclustered requeue failed"
                );
            }
        }
        processed += drain_for_tenant(pool, tid, per_tenant).await?;
    }
    Ok(processed)
}

/// `vulnerabilities.id` → `cluster_id` after drain (for SOAR events built pre-cluster).
pub async fn vuln_cluster_ids(
    pool: &PgPool,
    tenant_id: i64,
    vuln_ids: &[i64],
) -> HashMap<i64, Option<i64>> {
    let mut out = HashMap::new();
    if vuln_ids.is_empty() {
        return out;
    }
    let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await else {
        return out;
    };
    let Ok(rows) = sqlx::query(
        "SELECT id, cluster_id FROM vulnerabilities WHERE tenant_id = $1 AND id = ANY($2)",
    )
    .bind(tenant_id)
    .bind(vuln_ids)
    .fetch_all(&mut *tx)
    .await
    else {
        let _ = tx.rollback().await;
        return out;
    };
    let _ = tx.commit().await;
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let cid: Option<i64> = r.try_get("cluster_id").ok().flatten();
        out.insert(id, cid);
    }
    out
}

/// After an unclean Postgres restart an UNLOGGED outbox is truncated.
/// Re-enqueue recent findings that never received a `cluster_id` so the
/// logged `vulnerabilities` row is not stranded. Bounded per call.
async fn requeue_unclustered(pool: &PgPool, tenant_id: i64, limit: i64) -> Result<u64, String> {
    let cap = limit.clamp(1, 500);
    let mut tx = db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("cluster ingest requeue tx: {e}"))?;
    let n = sqlx::query(
        r#"INSERT INTO weissman_cluster_ingest (
                tenant_id, client_id, vuln_id, cluster_key, target, engine, source,
                title, severity, cwe, vuln_signature, cve, cvss, epss, kev_listed, is_new_member
           )
           SELECT v.tenant_id,
                  v.client_id,
                  v.id,
                  COALESCE(v.signature_hash, ''),
                  COALESCE(NULLIF(v.raw_data->>'target', ''), ''),
                  COALESCE(v.source, ''),
                  COALESCE(v.source, ''),
                  COALESCE(v.title, ''),
                  COALESCE(v.severity, 'info'),
                  COALESCE(v.raw_data->>'cwe', ''),
                  COALESCE(v.signature_hash, ''),
                  NULLIF(v.raw_data->>'cve', ''),
                  NULL,
                  v.epss_score,
                  COALESCE(v.kev_listed, false),
                  true
             FROM vulnerabilities v
            WHERE v.tenant_id = $1
              AND v.cluster_id IS NULL
              AND v.discovered_at > NOW() - INTERVAL '90 days'
              AND NOT EXISTS (
                    SELECT 1 FROM weissman_cluster_ingest i
                     WHERE i.tenant_id = v.tenant_id AND i.vuln_id = v.id
              )
            LIMIT $2"#,
    )
    .bind(tenant_id)
    .bind(cap)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("cluster ingest requeue: {e}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("cluster ingest requeue commit: {e}"))?;
    Ok(n.rows_affected())
}

async fn drain_once(pool: &PgPool, tenant_id: i64, limit: i64) -> Result<u64, String> {
    let mut tx = db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("cluster ingest tx: {e}"))?;
    let rows = sqlx::query(
        r#"SELECT id, client_id, vuln_id, cluster_key, target, engine, source,
                  title, severity, cwe, vuln_signature, cve, cvss, epss, kev_listed, is_new_member
             FROM weissman_cluster_ingest
            WHERE tenant_id = $1 AND processed_at IS NULL
            ORDER BY id
            FOR UPDATE SKIP LOCKED
            LIMIT $2"#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("cluster ingest claim: {e}"))?;

    if rows.is_empty() {
        let _ = tx.commit().await;
        return Ok(0);
    }

    let mut n = 0u64;
    for r in rows {
        let ingest_id: i64 = r.try_get("id").unwrap_or(0);
        let client_id: i64 = r.try_get("client_id").unwrap_or(0);
        let vuln_id: i64 = r.try_get("vuln_id").unwrap_or(0);
        let cluster_key: String = r.try_get("cluster_key").unwrap_or_default();
        let target: String = r.try_get("target").unwrap_or_default();
        let engine: String = r.try_get("engine").unwrap_or_default();
        let source: String = r.try_get("source").unwrap_or_default();
        let title: String = r.try_get("title").unwrap_or_default();
        let severity: String = r.try_get("severity").unwrap_or_default();
        let cwe: String = r.try_get("cwe").unwrap_or_default();
        let vuln_signature: String = r.try_get("vuln_signature").unwrap_or_default();
        let cve: Option<String> = r.try_get("cve").ok().flatten();
        let cvss: Option<f64> = r.try_get("cvss").ok().flatten();
        let epss: Option<f32> = r.try_get("epss").ok().flatten();
        let kev_listed: bool = r.try_get("kev_listed").unwrap_or(false);
        let is_new_member: bool = r.try_get("is_new_member").unwrap_or(true);

        sqlx::query("SAVEPOINT cluster_row")
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("cluster ingest savepoint: {e}"))?;

        // Bounded helper — never call pg_advisory_xact_lock raw. On timeout the
        // savepoint keeps this drain transaction usable and the row stays pending.
        let lock_key = format!("{tenant_id}:{cluster_key}");
        if let Err(e) =
            weissman_db::advisory_lock::advisory_xact_lock_text(&mut *tx, &lock_key).await
        {
            tracing::warn!(
                target: "cluster_ingest",
                error = %e,
                cluster_key = %cluster_key,
                "cluster ingest lock not taken; row stays pending"
            );
            let _ = sqlx::query("ROLLBACK TO SAVEPOINT cluster_row")
                .execute(&mut *tx)
                .await;
            continue;
        }

        let finding = json!({ "signature": vuln_signature, "title": title, "cwe": cwe });
        let cve_ref = cve.as_deref();
        match findings_correlator::upsert_cluster_for_finding(
            &mut tx,
            tenant_id,
            client_id,
            &finding,
            ClusterAttrs {
                target: &target,
                engine: &engine,
                source: &source,
                title: &title,
                severity: &severity,
                cwe: &cwe,
                cve: cve_ref,
                cvss,
                epss_score: epss,
                kev_listed,
                is_new_member,
                vuln_signature: Some(&vuln_signature),
                cluster_key: Some(&cluster_key),
            },
        )
        .await
        {
            Ok((cid, _)) => {
                let _ = sqlx::query(
                    "UPDATE vulnerabilities SET cluster_id = $1 WHERE id = $2 AND tenant_id = $3",
                )
                .bind(cid)
                .bind(vuln_id)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await;
                let _ = sqlx::query("RELEASE SAVEPOINT cluster_row")
                    .execute(&mut *tx)
                    .await;
            }
            Err(e) => {
                tracing::warn!(
                    target: "cluster_ingest",
                    error = %e,
                    vuln_id,
                    "cluster upsert failed; row stays pending"
                );
                let _ = sqlx::query("ROLLBACK TO SAVEPOINT cluster_row")
                    .execute(&mut *tx)
                    .await;
                continue;
            }
        }

        sqlx::query(
            "UPDATE weissman_cluster_ingest SET processed_at = now() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(ingest_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("cluster ingest mark processed: {e}"))?;
        n += 1;
    }

    tx.commit()
        .await
        .map_err(|e| format!("cluster ingest commit: {e}"))?;
    Ok(n)
}
