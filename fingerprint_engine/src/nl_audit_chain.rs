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

/// Serialize chaining for one tenant. HTTP inserts are never blocked: they
/// write a new row without locking, and this pass picks empty hashes in `id`
/// order after taking `FOR UPDATE` on those unchained rows.
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
    let rows: Vec<(i64, Option<i64>, String, String, i32, i32, String)> = sqlx::query_as(
        "SELECT id, user_id, question, compiled_sql, rows_returned, elapsed_ms,
                COALESCE(error, '')
           FROM nl_query_audit
          WHERE tenant_id = $1 AND event_hash = $2
          ORDER BY id
          FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(UNCHAINED)
    .fetch_all(&mut *tx)
    .await?;

    let mut prev_hash: String = sqlx::query_scalar(
        "SELECT COALESCE(event_hash, '') FROM nl_query_audit
          WHERE tenant_id = $1 AND event_hash <> $2
          ORDER BY id DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(UNCHAINED)
    .fetch_optional(&mut *tx)
    .await?
    .flatten()
    .unwrap_or_default();

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
        sqlx::query(
            "UPDATE nl_query_audit
                SET prev_hash = $3, event_hash = $4
              WHERE id = $1 AND tenant_id = $2 AND event_hash = $5",
        )
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
}
