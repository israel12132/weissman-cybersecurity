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
//!
//! Late-committed `BIGSERIAL` ids behind the tip are re-hashed when the hole
//! is shallow (`WEISSMAN_NL_AUDIT_MAX_HOLE_DISTANCE`, default 100). A deeper
//! hole freezes the current `chain_epoch` and stamps only the unchained rows
//! onto a parallel epoch so a 50k-row rewrite cannot DoS the tenant.

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

const SEGMENT_SQL: &str = "SELECT id, user_id, question, compiled_sql, rows_returned, elapsed_ms,
                COALESCE(error, '')
           FROM nl_query_audit
          WHERE tenant_id = $1 AND id >= $2
          ORDER BY id ASC
          FOR UPDATE";

const TIP_SQL: &str = "SELECT id, COALESCE(event_hash, ''), COALESCE(chain_epoch, 1)
           FROM nl_query_audit
          WHERE tenant_id = $1 AND event_hash <> $2
          ORDER BY id DESC LIMIT 1";

const PREV_BEFORE_SQL: &str = "SELECT COALESCE(event_hash, ''), COALESCE(chain_epoch, 1)
           FROM nl_query_audit
          WHERE tenant_id = $1 AND id < $2 AND event_hash <> $3
          ORDER BY id DESC LIMIT 1";

const STAMP_SQL: &str = "UPDATE nl_query_audit
                SET prev_hash = $3, event_hash = $4, chain_epoch = $5
              WHERE id = $1 AND tenant_id = $2";

/// Default cap on how far behind the tip a late id may sit before we freeze
/// the current epoch instead of rewriting every already-chained row.
pub const DEFAULT_MAX_HOLE_DISTANCE: i64 = 100;

type AuditRow = (i64, Option<i64>, String, String, i32, i32, String);

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

/// Late-committed `BIGSERIAL` id at or behind the chained tip: the worker must
/// not leave the hole unchained for an attacker to hide DML in.
#[must_use]
pub(crate) fn hole_behind_tip(pending_ids_asc: &[i64], tip_id: Option<i64>) -> bool {
    match (pending_ids_asc.first(), tip_id) {
        (Some(&id), Some(tip)) => id <= tip,
        _ => false,
    }
}

/// `tip_id - hole_id` is the BIGSERIAL distance, not a COUNT(*). A stuck
/// writer that finally commits 50_000 ids behind the tip would otherwise force
/// a single tenant transaction to re-hash the entire history.
#[must_use]
pub(crate) fn hole_too_deep(hole_id: i64, tip_id: i64, max_distance: i64) -> bool {
    tip_id.saturating_sub(hole_id) > max_distance
}

#[must_use]
pub(crate) fn max_hole_distance() -> i64 {
    std::env::var("WEISSMAN_NL_AUDIT_MAX_HOLE_DISTANCE")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&n| n >= 0)
        .unwrap_or(DEFAULT_MAX_HOLE_DISTANCE)
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

    let pending_rows: Vec<AuditRow> = sqlx::query_as(PENDING_SQL)
        .bind(tenant_id)
        .bind(UNCHAINED)
        .fetch_all(&mut *tx)
        .await?;
    if pending_rows.is_empty() {
        tx.commit().await?;
        return Ok(());
    }

    let tip: Option<(i64, String, i32)> = sqlx::query_as(TIP_SQL)
        .bind(tenant_id)
        .bind(UNCHAINED)
        .fetch_optional(&mut *tx)
        .await?;
    let start_id = pending_rows[0].0;
    let max_dist = max_hole_distance();

    match tip {
        None => {
            stamp_rows(&mut tx, tenant_id, pending_rows, String::new(), 1).await?;
        }
        Some((tip_id, tip_hash, tip_epoch)) if start_id > tip_id => {
            stamp_rows(&mut tx, tenant_id, pending_rows, tip_hash, tip_epoch).await?;
        }
        Some((tip_id, tip_hash, tip_epoch))
            if hole_behind_tip(&[start_id], Some(tip_id))
                && hole_too_deep(start_id, tip_id, max_dist) =>
        {
            let new_epoch = tip_epoch.saturating_add(1);
            tracing::warn!(
                target: "nl_audit_chain",
                tenant_id,
                hole_id = start_id,
                tip_id,
                max_hole_distance = max_dist,
                frozen_epoch = tip_epoch,
                new_epoch,
                "late audit id exceeds max hole distance — freezing current epoch and starting a parallel chain"
            );
            let mut late = Vec::new();
            let mut after = Vec::new();
            for row in pending_rows {
                if row.0 <= tip_id {
                    late.push(row);
                } else {
                    after.push(row);
                }
            }
            stamp_rows(&mut tx, tenant_id, late, String::new(), new_epoch).await?;
            stamp_rows(&mut tx, tenant_id, after, tip_hash, tip_epoch).await?;
        }
        Some((tip_id, _, _)) => {
            tracing::warn!(
                target: "nl_audit_chain",
                tenant_id,
                hole_id = start_id,
                tip_id,
                "re-chaining audit segment from late-committed id through the tip"
            );
            let segment: Vec<AuditRow> = sqlx::query_as(SEGMENT_SQL)
                .bind(tenant_id)
                .bind(start_id)
                .fetch_all(&mut *tx)
                .await?;
            let pred: Option<(String, i32)> = sqlx::query_as(PREV_BEFORE_SQL)
                .bind(tenant_id)
                .bind(start_id)
                .bind(UNCHAINED)
                .fetch_optional(&mut *tx)
                .await?;
            let (prev, epoch) = pred.unwrap_or_else(|| (String::new(), 1));
            stamp_rows(&mut tx, tenant_id, segment, prev, epoch).await?;
        }
    }

    tx.commit().await?;
    Ok(())
}

async fn stamp_rows(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    rows: Vec<AuditRow>,
    mut prev_hash: String,
    epoch: i32,
) -> Result<(), sqlx::Error> {
    for (id, user_id, sealed_q, sealed_sql, rows_returned, elapsed_ms, error) in rows {
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
        sqlx::query(STAMP_SQL)
            .bind(id)
            .bind(tenant_id)
            .bind(&prev_hash)
            .bind(&event_hash)
            .bind(epoch)
            .execute(&mut **tx)
            .await?;
        prev_hash = event_hash;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    static LIVE_DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn assert_segment_chained(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: i64,
        from_id: i64,
        to_id: i64,
    ) {
        let rows: Vec<(i64, String, String)> = sqlx::query_as(
            "SELECT id, prev_hash, event_hash FROM nl_query_audit
              WHERE tenant_id = $1 AND id >= $2 AND id <= $3
              ORDER BY id ASC",
        )
        .bind(tenant_id)
        .bind(from_id)
        .bind(to_id)
        .fetch_all(&mut **tx)
        .await
        .expect("read segment");
        assert!(!rows.is_empty(), "segment {from_id}..={to_id} empty");
        assert_eq!(rows[0].0, from_id);
        assert_eq!(rows.last().map(|r| r.0), Some(to_id));
        for (id, _prev, ev) in &rows {
            assert_ne!(ev.as_str(), UNCHAINED, "id {id} left unchained");
            assert_eq!(ev.len(), 64, "id {id} hash must be SHA-256 hex");
        }
        for w in rows.windows(2) {
            assert_eq!(
                w[1].1, w[0].2,
                "id {} must hash-link to id {}",
                w[1].0, w[0].0
            );
        }
    }

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
    fn hole_behind_tip_triggers_rechain_not_a_blind_skip() {
        assert!(!hole_behind_tip(&[5, 6, 7], None));
        assert!(hole_behind_tip(&[5, 6, 7], Some(6)));
        assert!(hole_behind_tip(&[5], Some(6)));
        assert!(!hole_behind_tip(&[10, 11], Some(9)));
        assert!(SEGMENT_SQL.contains("id >= $2"));
        assert!(STAMP_SQL.contains("SET prev_hash"));
        assert!(
            STAMP_SQL.contains("chain_epoch"),
            "stamp must persist chain_epoch so a deep hole can fork without rewriting the tip"
        );
        assert!(
            !STAMP_SQL.contains("AND event_hash"),
            "re-chain must overwrite already-signed tip hashes"
        );
        assert!(TIP_SQL.contains("chain_epoch"));
    }

    #[test]
    fn hole_too_deep_uses_id_distance_not_a_full_history_rewrite() {
        assert!(
            !hole_too_deep(10, 110, 100),
            "exactly 100 ids behind is allowed"
        );
        assert!(hole_too_deep(10, 111, 100), "101 ids behind must fork");
        assert!(hole_too_deep(1, 50_001, 100));
        assert!(!hole_too_deep(5, 5, 100));
        assert!(
            hole_too_deep(5, 6, 0),
            "max 0 means any hole behind the tip forks"
        );
        assert_eq!(DEFAULT_MAX_HOLE_DISTANCE, 100);
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
        assert!(
            !nl_audit_crypto::canonical_nl_audit_payload("", 1, None, "q", "s", 0, 0, "")
                .contains("chain_epoch"),
            "chain_epoch must not enter the hash payload or existing hashes break"
        );
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
        let _live = LIVE_DB_LOCK.lock().await;
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
        assert_segment_chained(&mut tx, tenant_id, id_early, id_late).await;
        let _ = sqlx::query("DELETE FROM nl_query_audit WHERE tenant_id = $1 AND question LIKE $2")
            .bind(tenant_id)
            .bind(format!("{marker}%"))
            .execute(&mut *tx)
            .await;
        tx.commit().await.expect("cleanup");
    }

    #[tokio::test]
    async fn rechains_hole_behind_tip_instead_of_leaving_unchained() {
        let url = match std::env::var("TEST_DATABASE_URL") {
            Ok(u) if !u.trim().is_empty() => u,
            _ => {
                eprintln!(
                    "SKIP rechains_hole_behind_tip_instead_of_leaving_unchained: no TEST_DATABASE_URL"
                );
                return;
            }
        };
        let _live = LIVE_DB_LOCK.lock().await;
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
        let marker = format!(
            "nlqa-rechain-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("tenant tx");
        let id_a: i64 = sqlx::query_scalar(
            "INSERT INTO nl_query_audit
                 (tenant_id, question, compiled_sql, event_hash, prev_hash)
             VALUES ($1, $2, 's-a', '', '')
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(format!("{marker}-a"))
        .fetch_one(&mut *tx)
        .await
        .expect("insert A");
        let id_b: i64 = sqlx::query_scalar(
            "INSERT INTO nl_query_audit
                 (tenant_id, question, compiled_sql, event_hash, prev_hash)
             VALUES ($1, $2, 's-b', '', '')
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(format!("{marker}-b"))
        .fetch_one(&mut *tx)
        .await
        .expect("insert B");
        tx.commit().await.expect("commit inserts");
        chain_tenant(&pool, tenant_id).await.expect("initial chain");

        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("punch hole");
        sqlx::query(
            "UPDATE nl_query_audit SET event_hash = '', prev_hash = ''
              WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id_a)
        .execute(&mut *tx)
        .await
        .expect("clear A hashes");
        tx.commit().await.expect("commit hole");

        chain_tenant(&pool, tenant_id).await.expect("re-chain hole");

        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("read tx");
        assert_segment_chained(&mut tx, tenant_id, id_a, id_b).await;
        let _ = sqlx::query("DELETE FROM nl_query_audit WHERE tenant_id = $1 AND question LIKE $2")
            .bind(tenant_id)
            .bind(format!("{marker}%"))
            .execute(&mut *tx)
            .await;
        tx.commit().await.expect("cleanup");
    }

    #[tokio::test]
    async fn deep_hole_forks_parallel_epoch_without_rewriting_the_tip() {
        let url = match std::env::var("TEST_DATABASE_URL") {
            Ok(u) if !u.trim().is_empty() => u,
            _ => {
                eprintln!(
                    "SKIP deep_hole_forks_parallel_epoch_without_rewriting_the_tip: no TEST_DATABASE_URL"
                );
                return;
            }
        };
        let _live = LIVE_DB_LOCK.lock().await;
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
        let marker = format!(
            "nlqa-epoch-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("tenant tx");
        let id_a: i64 = sqlx::query_scalar(
            "INSERT INTO nl_query_audit
                 (tenant_id, question, compiled_sql, event_hash, prev_hash)
             VALUES ($1, $2, 's-a', '', '')
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(format!("{marker}-a"))
        .fetch_one(&mut *tx)
        .await
        .expect("insert A");
        let id_b: i64 = sqlx::query_scalar(
            "INSERT INTO nl_query_audit
                 (tenant_id, question, compiled_sql, event_hash, prev_hash)
             VALUES ($1, $2, 's-b', '', '')
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(format!("{marker}-b"))
        .fetch_one(&mut *tx)
        .await
        .expect("insert B");
        tx.commit().await.expect("commit inserts");
        chain_tenant(&pool, tenant_id).await.expect("initial chain");

        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("snapshot B");
        let before: (String, String, i32) = sqlx::query_as(
            "SELECT prev_hash, event_hash, COALESCE(chain_epoch, 1)
               FROM nl_query_audit WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id_b)
        .fetch_one(&mut *tx)
        .await
        .expect("read B hashes");
        sqlx::query(
            "UPDATE nl_query_audit SET event_hash = '', prev_hash = ''
              WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id_a)
        .execute(&mut *tx)
        .await
        .expect("clear A hashes");
        tx.commit().await.expect("commit hole");

        let prev_max = std::env::var("WEISSMAN_NL_AUDIT_MAX_HOLE_DISTANCE").ok();
        std::env::set_var("WEISSMAN_NL_AUDIT_MAX_HOLE_DISTANCE", "0");
        let chain_res = chain_tenant(&pool, tenant_id).await;
        match prev_max {
            Some(v) => std::env::set_var("WEISSMAN_NL_AUDIT_MAX_HOLE_DISTANCE", v),
            None => std::env::remove_var("WEISSMAN_NL_AUDIT_MAX_HOLE_DISTANCE"),
        }
        chain_res.expect("fork epoch for deep hole");

        let mut tx = crate::db::begin_tenant_tx(&pool, tenant_id)
            .await
            .expect("read tx");
        let after_b: (String, String, i32) = sqlx::query_as(
            "SELECT prev_hash, event_hash, COALESCE(chain_epoch, 1)
               FROM nl_query_audit WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id_b)
        .fetch_one(&mut *tx)
        .await
        .expect("read B after fork");
        assert_eq!(after_b, before, "frozen epoch must not rewrite the tip row");
        let after_a: (String, String, i32) = sqlx::query_as(
            "SELECT prev_hash, event_hash, COALESCE(chain_epoch, 1)
               FROM nl_query_audit WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(id_a)
        .fetch_one(&mut *tx)
        .await
        .expect("read A after fork");
        assert_eq!(after_a.0, "", "new epoch is genesis");
        assert_ne!(after_a.1, UNCHAINED, "late row must still be signed");
        assert_eq!(after_a.1.len(), 64);
        assert_eq!(after_a.2, before.2 + 1, "A must land on the next epoch");
        assert_ne!(
            after_a.2, after_b.2,
            "A and B must not share an epoch after a deep fork"
        );
        let _ = sqlx::query("DELETE FROM nl_query_audit WHERE tenant_id = $1 AND question LIKE $2")
            .bind(tenant_id)
            .bind(format!("{marker}%"))
            .execute(&mut *tx)
            .await;
        tx.commit().await.expect("cleanup");
    }
}
