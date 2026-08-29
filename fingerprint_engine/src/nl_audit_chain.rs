//! Async SHA-256 hash chain for `/api/ask` rows in `nl_query_audit`.
//!
//! HTTP inserts do **not** compute the chain (keeps Ask latency off the lock). A
//! worker later seals `event_hash` / `prev_hash`. Concurrent inserts can COMMIT
//! out of wall-clock order; the sealer **always** sorts by the table's BIGSERIAL
//! `id` (the monotonic sequence), never by `asked_at`. Ordering by timestamps
//! would fork the chain and trip integrity audits as false "log tamper" alerts.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};

const CHAIN_VERSION: &str = "nl-audit-v1";

#[derive(Debug, Clone)]
pub struct NlAuditRow {
    pub id: i64,
    pub tenant_id: i64,
    pub user_id: Option<i64>,
    pub asked_at: DateTime<Utc>,
    pub question: String,
    pub compiled_sql: String,
    pub rows_returned: i32,
    pub elapsed_ms: i32,
    pub error: String,
    pub prev_hash: Option<String>,
    pub event_hash: Option<String>,
}

/// Canonical bytes hashed into `event_hash`. Must stay stable for verification.
pub fn canonical_nl_audit_payload(prev_hash: &str, row: &NlAuditRow) -> String {
    format!(
        "{CHAIN_VERSION}|{prev_hash}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        row.id,
        row.tenant_id,
        row.user_id.unwrap_or(0),
        row.asked_at.to_rfc3339(),
        row.question,
        row.compiled_sql,
        row.rows_returned,
        row.elapsed_ms,
        row.error
    )
}

pub fn sha256_hex(input: &str) -> String {
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

/// Sort pending rows for sealing. **Sequence `id` only** — timestamps are not total-ordered.
pub fn sort_pending_for_chain(rows: &mut [NlAuditRow]) {
    rows.sort_by_key(|r| r.id);
}

/// Walk rows in `id` order and assign hashes. `head` is the last already-sealed hash
/// for the tenant (empty string = genesis).
pub fn seal_in_id_order(head: &str, rows: &mut [NlAuditRow]) {
    sort_pending_for_chain(rows);
    let mut prev = head.to_string();
    for row in rows.iter_mut() {
        let canonical = canonical_nl_audit_payload(&prev, row);
        let hash = sha256_hex(&canonical);
        row.prev_hash = Some(prev.clone());
        row.event_hash = Some(hash.clone());
        prev = hash;
    }
}

/// Verify a sealed chain is consistent when walked by `id` (not `asked_at`).
pub fn verify_sealed_id_order(head_before: &str, rows: &[NlAuditRow]) -> Result<(), String> {
    let mut ordered: Vec<&NlAuditRow> = rows.iter().collect();
    ordered.sort_by_key(|r| r.id);
    let mut prev = head_before.to_string();
    for row in ordered {
        let Some(stored) = row.event_hash.as_deref() else {
            return Err(format!("row {} missing event_hash", row.id));
        };
        let expected = sha256_hex(&canonical_nl_audit_payload(&prev, row));
        if stored != expected {
            return Err(format!(
                "chain break at id {}: stored hash does not match sequence-order digest",
                row.id
            ));
        }
        if row.prev_hash.as_deref().unwrap_or("") != prev {
            return Err(format!("chain break at id {}: prev_hash mismatch", row.id));
        }
        prev = stored.to_string();
    }
    Ok(())
}

/// False-positive detector: hashing in `asked_at` order on the same rows must not be
/// used for verification. Exposed so tests prove timestamp order is the bug.
pub fn verify_sealed_asked_at_order(head_before: &str, rows: &[NlAuditRow]) -> Result<(), String> {
    let mut ordered: Vec<&NlAuditRow> = rows.iter().collect();
    ordered.sort_by(|a, b| a.asked_at.cmp(&b.asked_at).then(a.id.cmp(&b.id)));
    let mut prev = head_before.to_string();
    for row in ordered {
        let stored = row.event_hash.as_deref().unwrap_or("");
        let expected = sha256_hex(&canonical_nl_audit_payload(&prev, row));
        if stored != expected {
            return Err("timestamp order disagrees with sequence-sealed hashes".into());
        }
        prev = stored.to_string();
    }
    Ok(())
}

pub async fn chain_pending(pool: &PgPool, limit: i64) -> Result<u64, sqlx::Error> {
    let tenants = weissman_db::active_tenant_ids(pool).await?;
    let mut sealed = 0u64;
    for tenant_id in tenants {
        sealed += chain_pending_for_tenant(pool, tenant_id, limit).await?;
    }
    Ok(sealed)
}

pub async fn chain_pending_for_tenant(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> Result<u64, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    // Owned Transaction derefs to PgConnection (audit_log uses `&mut **tx` when
    // the transaction is already a `&mut Transaction`). One deref here.
    weissman_db::advisory_lock::advisory_xact_lock_text(
        &mut *tx,
        &format!("nl_audit_chain:{tenant_id}"),
    )
    .await?;

    let head: String = sqlx::query_scalar(
        r#"SELECT COALESCE(event_hash, '') FROM nl_query_audit
           WHERE tenant_id = $1 AND event_hash IS NOT NULL
           ORDER BY id DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or_default();

    // Sequence order: BIGSERIAL `id`, never asked_at.
    let rows = sqlx::query(
        r#"SELECT id, tenant_id, user_id, asked_at, question, compiled_sql,
                  rows_returned, elapsed_ms, error
           FROM nl_query_audit
           WHERE tenant_id = $1 AND event_hash IS NULL
           ORDER BY id ASC
           LIMIT $2
           FOR UPDATE SKIP LOCKED"#,
    )
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;

    let mut pending: Vec<NlAuditRow> = rows
        .into_iter()
        .map(|r| NlAuditRow {
            id: r.get("id"),
            tenant_id: r.get("tenant_id"),
            user_id: r.get("user_id"),
            asked_at: r.get("asked_at"),
            question: r.get("question"),
            compiled_sql: r.get("compiled_sql"),
            rows_returned: r.get("rows_returned"),
            elapsed_ms: r.get("elapsed_ms"),
            error: r.get("error"),
            prev_hash: None,
            event_hash: None,
        })
        .collect();

    if pending.is_empty() {
        tx.commit().await?;
        return Ok(0);
    }

    seal_in_id_order(&head, &mut pending);
    let n = pending.len() as u64;
    persist_sealed(&mut tx, &pending).await?;
    tx.commit().await?;
    Ok(n)
}

async fn persist_sealed(
    tx: &mut Transaction<'_, Postgres>,
    rows: &[NlAuditRow],
) -> Result<(), sqlx::Error> {
    for row in rows {
        sqlx::query(
            r#"UPDATE nl_query_audit
               SET prev_hash = $2, event_hash = $3, chained_at = now()
               WHERE id = $1 AND event_hash IS NULL"#,
        )
        .bind(row.id)
        .bind(row.prev_hash.as_deref())
        .bind(row.event_hash.as_deref())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Leader / worker loop: seal unchained Ask rows.
pub fn spawn_nl_audit_chain_loop(pool: std::sync::Arc<PgPool>) {
    static SPAWNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match chain_pending(pool.as_ref(), 256).await {
                Ok(0) => {}
                Ok(n) => {
                    tracing::debug!(target: "nl_audit_chain", sealed = n, "sealed NL audit rows");
                }
                Err(e) => {
                    tracing::warn!(target: "nl_audit_chain", error = %e, "NL audit chain seal failed");
                }
            }
        }
    });
}

#[cfg(test)]
fn sample_row(id: i64, asked_at: DateTime<Utc>, question: &str) -> NlAuditRow {
    NlAuditRow {
        id,
        tenant_id: 1,
        user_id: Some(9),
        asked_at,
        question: question.to_string(),
        compiled_sql: "SELECT 1".into(),
        rows_returned: 1,
        elapsed_ms: 4,
        error: String::new(),
        prev_hash: None,
        event_hash: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).single().expect("ts")
    }

    #[test]
    fn pending_sort_is_sequence_id_not_timestamp() {
        let mut rows = vec![
            sample_row(3, ts(100), "late insert finished first"),
            sample_row(1, ts(300), "earliest id, later wall clock"),
            sample_row(2, ts(200), "middle"),
        ];
        sort_pending_for_chain(&mut rows);
        let ids: Vec<i64> = rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn out_of_order_commits_still_seal_by_id() {
        // Row 2 COMMITTED (and has a later asked_at) before row 1 — the race the
        // architect described. Sealing by id keeps the chain linear.
        let mut rows = vec![
            sample_row(2, ts(50), "second id, earlier wall clock"),
            sample_row(1, ts(90), "first id, later wall clock"),
        ];
        seal_in_id_order("", &mut rows);
        sort_pending_for_chain(&mut rows);
        assert!(verify_sealed_id_order("", &rows).is_ok());
        assert!(
            verify_sealed_asked_at_order("", &rows).is_err(),
            "timestamp order on out-of-order commits must NOT match the sequence-sealed chain"
        );
    }

    #[test]
    fn in_order_timestamps_also_verify_by_id() {
        let mut rows = vec![sample_row(1, ts(10), "a"), sample_row(2, ts(20), "b")];
        seal_in_id_order("genesis", &mut rows);
        assert!(verify_sealed_id_order("genesis", &rows).is_ok());
        assert!(verify_sealed_asked_at_order("genesis", &rows).is_ok());
    }

    #[tokio::test]
    #[ignore = "live Postgres; cargo test -- --ignored --nocapture with DATABASE_URL"]
    async fn live_postgres_out_of_order_asked_at_chains_by_id() {
        let url = std::env::var("TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_default();
        if url.trim().is_empty() {
            eprintln!("skip live NL chain demo: DATABASE_URL unset");
            return;
        }
        let pool = match sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skip live NL chain demo: connect failed: {e}");
                return;
            }
        };
        let has_col: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'nl_query_audit'
                  AND column_name = 'event_hash'
            )",
        )
        .fetch_one(&pool)
        .await
        .unwrap_or(false);
        if !has_col {
            eprintln!("skip live NL chain demo: event_hash column missing");
            return;
        }

        let tenant_id: i64 = 1;
        let marker = format!(
            "architect-4433-nl-chain-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let late = ts(1_777_000_000); // later wall clock
        let early = ts(1_700_000_000); // earlier wall clock

        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("tenant tx");
        sqlx::query(
            "INSERT INTO nl_query_audit
                (tenant_id, user_id, asked_at, question, compiled_sql, rows_returned, elapsed_ms, error)
             VALUES ($1, 9, $2, $3, 'SELECT 1', 1, 4, '')",
        )
        .bind(tenant_id)
        .bind(late)
        .bind(format!("{marker}-id-first-later-clock"))
        .execute(&mut *tx)
        .await
        .expect("insert later-clock first (lower id)");
        sqlx::query(
            "INSERT INTO nl_query_audit
                (tenant_id, user_id, asked_at, question, compiled_sql, rows_returned, elapsed_ms, error)
             VALUES ($1, 9, $2, $3, 'SELECT 1', 1, 4, '')",
        )
        .bind(tenant_id)
        .bind(early)
        .bind(format!("{marker}-id-second-earlier-clock"))
        .execute(&mut *tx)
        .await
        .expect("insert earlier-clock second (higher id)");
        tx.commit().await.expect("commit inserts");

        let sealed = chain_pending_for_tenant(&pool, tenant_id, 256)
            .await
            .expect("seal by id");
        assert!(
            sealed >= 2,
            "sealer must persist both demo rows, got {sealed}"
        );

        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("read tx");
        let rows = sqlx::query(
            r#"SELECT id, tenant_id, user_id, asked_at, question, compiled_sql,
                      rows_returned, elapsed_ms, error, prev_hash, event_hash
               FROM nl_query_audit
               WHERE tenant_id = $1 AND question LIKE $2
               ORDER BY id ASC"#,
        )
        .bind(tenant_id)
        .bind(format!("{marker}%"))
        .fetch_all(&mut *tx)
        .await
        .expect("fetch sealed");
        let _ = tx.commit().await;

        assert_eq!(rows.len(), 2);
        let parsed: Vec<NlAuditRow> = rows
            .iter()
            .map(|r| NlAuditRow {
                id: r.get("id"),
                tenant_id: r.get("tenant_id"),
                user_id: r.get("user_id"),
                asked_at: r.get("asked_at"),
                question: r.get("question"),
                compiled_sql: r.get("compiled_sql"),
                rows_returned: r.get("rows_returned"),
                elapsed_ms: r.get("elapsed_ms"),
                error: r.get("error"),
                prev_hash: r.get("prev_hash"),
                event_hash: r.get("event_hash"),
            })
            .collect();
        assert!(
            parsed[0].asked_at > parsed[1].asked_at,
            "demo rows must have inverted timestamps vs id order"
        );
        assert!(
            parsed[0].event_hash.is_some() && parsed[1].event_hash.is_some(),
            "both rows must be sealed"
        );
        assert!(
            verify_sealed_id_order("", &parsed).is_ok(),
            "live chain must verify in BIGSERIAL id order"
        );
        assert!(
            verify_sealed_asked_at_order("", &parsed).is_err(),
            "live chain must NOT verify in asked_at order"
        );

        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("cleanup tx");
        let _ = sqlx::query("DELETE FROM nl_query_audit WHERE tenant_id = $1 AND question LIKE $2")
            .bind(tenant_id)
            .bind(format!("{marker}%"))
            .execute(&mut *tx)
            .await;
        let _ = tx.commit().await;
    }
}
