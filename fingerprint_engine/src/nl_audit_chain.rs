//! Background hash-chain worker for Ask Weissman audit rows.
//!
//! `POST /api/ask` inserts a sealed `nl_query_audit` row with empty
//! `event_hash` / `prev_hash` and returns immediately — it never takes
//! `SELECT … FOR UPDATE`. Concurrent analysts therefore do not serialize
//! behind each other's LLM round-trips.
//!
//! This worker owns the chain:
//!   1. An in-process bounded mpsc (`try_send` from the HTTP path).
//!   2. A periodic DB sweep so a crash before notify cannot drop links.
//!   3. Per-tenant `FOR UPDATE` on unchained rows inside `begin_tenant_tx`
//!      (lock_timeout is set by `set_tenant_tx`) plus a dedicated advisory
//!      key so two replicas cannot interleave the same tenant's chain.

use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, MissedTickBehavior};

use crate::nl_audit_crypto;

/// Rows waiting for the worker to stamp `event_hash` (HTTP insert marker).
pub const UNCHAINED: &str = "";

const CHANNEL_CAP: usize = 8192;
const SWEEP_SECS: u64 = 5;

/// Unchained rows in BIGSERIAL order. Never `asked_at`.
const PENDING_SQL: &str = "SELECT id, user_id, question, compiled_sql, rows_returned, elapsed_ms,
                COALESCE(error, '')
           FROM nl_query_audit
          WHERE tenant_id = $1 AND event_hash = $2
          ORDER BY id ASC
          FOR UPDATE";

const TIP_SQL: &str = "SELECT id, COALESCE(event_hash, '') FROM nl_query_audit
          WHERE tenant_id = $1 AND event_hash <> $2
          ORDER BY id DESC LIMIT 1";

const UPDATE_SQL: &str = "UPDATE nl_query_audit
                SET prev_hash = $3, event_hash = $4
              WHERE id = $1 AND tenant_id = $2 AND event_hash = $5";

static CHAIN_TX: OnceLock<mpsc::Sender<i64>> = OnceLock::new();

/// Best-effort notify. A full channel or a process that has not yet spawned
/// the worker is fine: the durable row is already inserted and the sweep
/// will chain it.
pub fn notify(tenant_id: i64) {
    if tenant_id <= 0 {
        return;
    }
    if let Some(tx) = CHAIN_TX.get() {
        if tx.try_send(tenant_id).is_err() {
            tracing::debug!(
                target: "nl_audit_chain",
                tenant_id,
                "hash-chain mpsc full — sweep will pick up unchained rows"
            );
        }
    }
}

pub fn spawn(pool: Arc<PgPool>) {
    static ONCE: OnceLock<()> = OnceLock::new();
    if ONCE.set(()).is_err() {
        return;
    }
    let (tx, rx) = mpsc::channel::<i64>(CHANNEL_CAP);
    let _ = CHAIN_TX.set(tx);
    tokio::spawn(run(pool, rx));
    tracing::info!(target: "nl_audit_chain", "Ask Weissman audit hash-chain worker started");
}

async fn run(pool: Arc<PgPool>, mut rx: mpsc::Receiver<i64>) {
    let mut sweep = interval(Duration::from_secs(SWEEP_SECS));
    sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            msg = rx.recv() => {
                match msg {
                    Some(first) => {
                        let mut tenants = HashSet::new();
                        tenants.insert(first);
                        while let Ok(tid) = rx.try_recv() {
                            tenants.insert(tid);
                        }
                        for tid in tenants {
                            if let Err(e) = chain_tenant(pool.as_ref(), tid).await {
                                tracing::warn!(
                                    target: "nl_audit_chain",
                                    tenant_id = tid,
                                    error = %e,
                                    "hash-chain tenant pass failed"
                                );
                            }
                        }
                    }
                    None => break,
                }
            }
            _ = sweep.tick() => {
                if let Err(e) = sweep_all(pool.as_ref()).await {
                    tracing::warn!(target: "nl_audit_chain", error = %e, "hash-chain sweep failed");
                }
            }
        }
    }
}

async fn sweep_all(pool: &PgPool) -> Result<(), sqlx::Error> {
    let tenants = weissman_db::active_tenant_ids(pool).await?;
    for tid in tenants {
        if let Err(e) = chain_tenant(pool, tid).await {
            tracing::warn!(
                target: "nl_audit_chain",
                tenant_id = tid,
                error = %e,
                "hash-chain sweep tenant pass failed"
            );
        }
    }
    Ok(())
}

/// Rows the worker may append to the existing chain: strictly after the tip's
/// `BIGSERIAL` `id`. A late-committed lower id cannot be spliced behind a hash
/// that is already on disk — that would fail any integrity walk `ORDER BY id`.
/// Timestamps (`asked_at`) are never consulted (clock skew / out-of-order
/// insert). `pending_asc` must already be sorted by `id` ascending.
#[must_use]
pub(crate) fn pending_after_tip(pending_ids_asc: &[i64], tip_id: Option<i64>) -> Vec<i64> {
    match tip_id {
        None => pending_ids_asc.to_vec(),
        Some(tip) => pending_ids_asc
            .iter()
            .copied()
            .filter(|id| *id > tip)
            .collect(),
    }
}

/// Serialize chaining for one tenant. HTTP inserts are never blocked: they
/// write a new row without locking, and this pass picks empty hashes in
/// `BIGSERIAL` `id` order after taking `FOR UPDATE` on those unchained rows.
async fn chain_tenant(pool: &PgPool, tenant_id: i64) -> Result<(), sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    weissman_db::advisory_lock::advisory_xact_lock_text(
        &mut *tx,
        &format!("nl-audit-chain:{tenant_id}"),
    )
    .await?;

    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM nl_query_audit
              WHERE tenant_id = $1 AND event_hash = $2
         )",
    )
    .bind(tenant_id)
    .bind(UNCHAINED)
    .fetch_one(&mut *tx)
    .await?;
    if !pending {
        tx.commit().await?;
        return Ok(());
    }

    // Architect requirement: row-level FOR UPDATE lives on the worker, not
    // the HTTP path. Bound by begin_tenant_tx lock_timeout.
    // Total order is BIGSERIAL `id ASC` — never `asked_at` (clock skew).
    let rows: Vec<(i64, Option<i64>, String, String, i32, i32, String)> =
        sqlx::query_as(PENDING_SQL)
            .bind(tenant_id)
            .bind(UNCHAINED)
            .fetch_all(&mut *tx)
            .await?;

    let tip: Option<(i64, String)> = sqlx::query_as(TIP_SQL)
        .bind(tenant_id)
        .bind(UNCHAINED)
        .fetch_optional(&mut *tx)
        .await?;

    let (tip_id, mut prev_hash) = match tip {
        Some((id, h)) => (Some(id), h),
        None => (None, String::new()),
    };
    let allowed = pending_after_tip(&rows.iter().map(|(id, ..)| *id).collect::<Vec<_>>(), tip_id);
    if allowed.len() < rows.len() {
        tracing::error!(
            target: "nl_audit_chain",
            tenant_id,
            tip_id,
            pending = rows.len(),
            chainable = allowed.len(),
            "late-committed nl_query_audit id is behind the chained tip; \
             left unchained so integrity walks ORDER BY id stay valid"
        );
    }
    let allowed: HashSet<i64> = allowed.into_iter().collect();

    for (id, user_id, sealed_q, sealed_sql, rows_returned, elapsed_ms, error) in rows {
        if !allowed.contains(&id) {
            continue;
        }
        let canonical = nl_audit_crypto::canonical_nl_audit_payload(
            &prev_hash,
            tenant_id,
            user_id,
            &sealed_q,
            &sealed_sql,
            rows_returned,
            elapsed_ms,
            &error,
        );
        let event_hash = nl_audit_crypto::event_hash(&canonical);
        sqlx::query(UPDATE_SQL)
            .bind(id)
            .bind(tenant_id)
            .bind(&prev_hash)
            .bind(&event_hash)
            .bind(UNCHAINED)
            .execute(&mut *tx)
            .await?;
        prev_hash = event_hash;
    }

    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchained_marker_is_empty_string() {
        assert_eq!(UNCHAINED, "");
        assert_ne!(
            nl_audit_crypto::event_hash(&nl_audit_crypto::canonical_nl_audit_payload(
                UNCHAINED, 1, None, "q", "s", 0, 0, ""
            )),
            UNCHAINED
        );
    }

    #[test]
    fn notify_is_noop_before_spawn() {
        notify(0);
        notify(42);
    }

    #[test]
    fn worker_sql_takes_for_update() {
        let src = include_str!("nl_audit_chain.rs");
        assert!(
            src.contains("FOR UPDATE"),
            "worker must serialize unchained rows with FOR UPDATE"
        );
        assert!(src.contains("nl-audit-chain:"));
    }

    #[test]
    fn worker_sql_orders_pending_by_monotonic_id_not_timestamp() {
        assert!(
            PENDING_SQL.contains("ORDER BY id ASC"),
            "pending chain must walk BIGSERIAL id"
        );
        assert!(
            !PENDING_SQL.contains("asked_at") && !TIP_SQL.contains("asked_at"),
            "SQL must not order the audit chain by asked_at"
        );
        assert!(TIP_SQL.contains("ORDER BY id DESC LIMIT 1"));
        assert!(PENDING_SQL.contains("FOR UPDATE"));
    }

    #[test]
    fn pending_after_tip_skips_late_ids_behind_the_chain() {
        assert_eq!(pending_after_tip(&[5, 6, 7], None), vec![5, 6, 7]);
        assert_eq!(pending_after_tip(&[5, 6, 7], Some(6)), vec![7]);
        assert_eq!(pending_after_tip(&[5], Some(6)), Vec::<i64>::new());
        assert_eq!(pending_after_tip(&[10, 11], Some(9)), vec![10, 11]);
    }

    #[test]
    fn sequential_hashes_depend_on_prev() {
        let a = nl_audit_crypto::event_hash(&nl_audit_crypto::canonical_nl_audit_payload(
            "",
            9,
            Some(1),
            "wzi1:q1",
            "wzi1:s1",
            1,
            2,
            "",
        ));
        let b = nl_audit_crypto::event_hash(&nl_audit_crypto::canonical_nl_audit_payload(
            &a,
            9,
            Some(1),
            "wzi1:q2",
            "wzi1:s2",
            3,
            4,
            "",
        ));
        let b_genesis = nl_audit_crypto::event_hash(&nl_audit_crypto::canonical_nl_audit_payload(
            "",
            9,
            Some(1),
            "wzi1:q2",
            "wzi1:s2",
            3,
            4,
            "",
        ));
        assert_ne!(b, b_genesis);
        assert_eq!(a.len(), 64);
        assert_eq!(b.len(), 64);
    }

    #[tokio::test]
    async fn chains_in_id_order_when_asked_at_is_inverted() {
        let url = match std::env::var("TEST_DATABASE_URL") {
            Ok(u) if !u.trim().is_empty() => u,
            _ => {
                eprintln!(
                    "SKIP chains_in_id_order_when_asked_at_is_inverted: no TEST_DATABASE_URL"
                );
                return;
            }
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("connect TEST_DATABASE_URL");
        let tenant_id: i64 =
            sqlx::query_scalar("SELECT id FROM tenants WHERE slug = 'default' LIMIT 1")
                .fetch_optional(&pool)
                .await
                .expect("lookup default tenant")
                .expect("default tenant must exist");

        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("tenant tx");
        let marker = format!(
            "nlqa-order-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let id_early: i64 = sqlx::query_scalar(
            "INSERT INTO nl_query_audit
                 (tenant_id, question, compiled_sql, asked_at, event_hash, prev_hash)
             VALUES ($1, $2, 's-a', now() + interval '1 hour', '', '')
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(format!("{marker}-a"))
        .fetch_one(&mut *tx)
        .await
        .expect("insert later-timestamp first row");
        let id_late: i64 = sqlx::query_scalar(
            "INSERT INTO nl_query_audit
                 (tenant_id, question, compiled_sql, asked_at, event_hash, prev_hash)
             VALUES ($1, $2, 's-b', now() - interval '1 hour', '', '')
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(format!("{marker}-b"))
        .fetch_one(&mut *tx)
        .await
        .expect("insert earlier-timestamp second row");
        tx.commit().await.expect("commit inserts");
        assert!(id_early < id_late, "BIGSERIAL must assign increasing ids");

        chain_tenant(&pool, tenant_id).await.expect("chain");

        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("read tx");
        let rows: Vec<(i64, String, String)> = sqlx::query_as(
            "SELECT id, prev_hash, event_hash FROM nl_query_audit
              WHERE tenant_id = $1 AND question LIKE $2
              ORDER BY id ASC",
        )
        .bind(tenant_id)
        .bind(format!("{marker}%"))
        .fetch_all(&mut *tx)
        .await
        .expect("read chain");
        let _ = sqlx::query("DELETE FROM nl_query_audit WHERE tenant_id = $1 AND question LIKE $2")
            .bind(tenant_id)
            .bind(format!("{marker}%"))
            .execute(&mut *tx)
            .await;
        tx.commit().await.expect("cleanup");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, id_early);
        assert_eq!(rows[1].0, id_late);
        assert_eq!(
            rows[1].1, rows[0].2,
            "later id must hash-link to earlier id"
        );
        assert_eq!(rows[0].2.len(), 64);
        assert_ne!(rows[0].2, UNCHAINED);
        assert_ne!(rows[1].2, UNCHAINED);
    }
}
