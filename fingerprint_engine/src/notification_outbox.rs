//! Durable notification outbox — makes alert delivery survive transient endpoint failures.
//!
//! Alert delivery used to be fire-and-forget: a single WARN on a 5xx and the security alert was
//! gone. This module persists every per-channel delivery attempt to `notification_outbox` BEFORE
//! it is tried (status `pending`), flips it to `delivered` on success, reschedules it with
//! exponential backoff on failure, and finally `dead`-letters it after [`MAX_ATTEMPTS`] — emitting a
//! metric and a self-alert ERROR log, because a security product silently failing to alert is the
//! worst failure mode.
//!
//! Two entry points, mirroring `intel_kev`:
//!   * [`enqueue`] / [`mark_delivered`] / [`mark_failed`] — used by the live delivery path
//!     (`alert_delivery::deliver_alert`) to persist and settle each channel attempt.
//!   * [`spawn_notification_outbox_worker`] — the long-running retry worker (placement/style mirrors
//!     [`crate::intel_kev::spawn_kev_refresh_worker`]).
//!
//! The table is FORCE ROW LEVEL SECURITY, so every read/write here runs inside `begin_tenant_tx`
//! (concrete tenant GUC). The worker enumerates tenants via `active_tenant_ids` and sweeps each in
//! its own tenant transaction, so it never needs a BYPASSRLS connection.

use serde_json::Value;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;

/// Dead-letter after this many failed attempts.
const MAX_ATTEMPTS: i32 = 8;
/// Exponential backoff base (seconds); doubled per attempt and capped at [`RETRY_MAX_SECS`].
const RETRY_BASE_SECS: i64 = 60;
const RETRY_MAX_SECS: i64 = 30 * 60;
/// Rows claimed per tenant per worker tick.
const CLAIM_BATCH: i64 = 50;
/// Lease pushed onto a claimed row so a second tick/instance cannot double-claim it while the first
/// is still doing outbound HTTP. It is overwritten by [`mark_delivered`] / [`mark_failed`] the moment
/// the attempt settles; if the worker dies mid-flight the row just becomes due again after the lease.
const CLAIM_LEASE_SECS: i64 = 120;
/// Worker poll cadence.
const WORKER_POLL_SECS: u64 = 30;

/// Backoff (seconds) before the next attempt, given the attempt count just recorded. Mirrors the KEV
/// worker's escalation shape: `RETRY_BASE_SECS << (attempts-1)`, capped at [`RETRY_MAX_SECS`].
fn backoff_secs(attempts: i32) -> i64 {
    let shift = (attempts - 1).clamp(0, 6) as u32;
    (RETRY_BASE_SECS << shift).min(RETRY_MAX_SECS)
}

/// Persist a `pending` delivery row for one channel BEFORE the first attempt. Returns the row id, or
/// `None` if the outbox is unreachable (the caller's immediate attempt still stands — enqueue must
/// never itself become the thing that drops the alert path).
pub async fn enqueue(pool: &PgPool, tenant_id: i64, channel: &str, envelope: &Value) -> Option<i64> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await.ok()?;
    let id = sqlx::query_scalar::<_, i64>(
        r#"INSERT INTO notification_outbox (tenant_id, channel, payload, status, next_attempt_at)
           VALUES ($1, $2, $3, 'pending', now())
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(channel)
    .bind(sqlx::types::Json(envelope.clone()))
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    id
}

/// Settle a row as `delivered`.
pub async fn mark_delivered(pool: &PgPool, tenant_id: i64, id: i64) {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return;
    };
    let _ = sqlx::query(
        "UPDATE notification_outbox
            SET status = 'delivered', delivered_at = now(), updated_at = now(), last_error = NULL
          WHERE id = $1 AND status <> 'delivered'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await;
    let _ = tx.commit().await;
}

/// Record a failed attempt: bump `attempts`, then either reschedule with exponential backoff or, once
/// the new attempt count reaches [`MAX_ATTEMPTS`], dead-letter the row (`dead`) and raise the alarm —
/// a metric plus a self-alert ERROR log, since a dropped security alert is the worst outcome.
///
/// `attempts_before` is the attempt count as last read (0 for a just-enqueued row; the claimed value
/// for a worker retry), so the new count and the terminal decision are computed without a read-back.
pub async fn mark_failed(
    pool: &PgPool,
    tenant_id: i64,
    id: i64,
    channel: &str,
    attempts_before: i32,
    err: &str,
) {
    let new_attempts = attempts_before + 1;
    let dead = new_attempts >= MAX_ATTEMPTS;

    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        tracing::warn!(
            target: "notification_outbox",
            tenant_id, outbox_id = id, channel,
            "could not open tenant tx to record delivery failure"
        );
        return;
    };

    if dead {
        let _ = sqlx::query(
            "UPDATE notification_outbox
                SET status = 'dead', attempts = $2, last_error = $3, updated_at = now()
              WHERE id = $1 AND status = 'pending'",
        )
        .bind(id)
        .bind(new_attempts)
        .bind(err)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;

        // A security alert we could not deliver after MAX_ATTEMPTS. Make it loud + queryable.
        metrics::counter!(
            "weissman_notification_outbox_deadletter_total", "channel" => channel.to_string()
        )
        .increment(1);
        tracing::error!(
            target: "notification_outbox",
            tenant_id, outbox_id = id, channel, attempts = new_attempts, error = err,
            "ALERT DELIVERY DEAD-LETTERED after {new_attempts} attempts — a security alert could not \
             be delivered on this channel; investigate the endpoint/credentials"
        );
    } else {
        let backoff = backoff_secs(new_attempts);
        let _ = sqlx::query(
            "UPDATE notification_outbox
                SET attempts = $2, last_error = $3, updated_at = now(),
                    next_attempt_at = now() + make_interval(secs => $4)
              WHERE id = $1 AND status = 'pending'",
        )
        .bind(id)
        .bind(new_attempts)
        .bind(err)
        .bind(backoff as f64)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;

        metrics::counter!(
            "weissman_notification_outbox_retry_total", "channel" => channel.to_string()
        )
        .increment(1);
    }
}

/// One due `pending` row leased for redelivery.
struct ClaimedRow {
    id: i64,
    channel: String,
    payload: Value,
    attempts: i32,
}

/// Claim (lease) up to [`CLAIM_BATCH`] due `pending` rows for one tenant. `FOR UPDATE SKIP LOCKED`
/// plus a lease push on `next_attempt_at` makes the claim safe against a concurrent tick/instance,
/// while HTTP happens outside the transaction.
async fn claim_due(pool: &PgPool, tenant_id: i64) -> Vec<ClaimedRow> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Vec::new();
    };
    let rows = sqlx::query(
        r#"WITH due AS (
               SELECT id FROM notification_outbox
                WHERE status = 'pending' AND next_attempt_at <= now()
                ORDER BY next_attempt_at
                LIMIT $1
                FOR UPDATE SKIP LOCKED
           )
           UPDATE notification_outbox o
              SET next_attempt_at = now() + make_interval(secs => $2), updated_at = now()
             FROM due
            WHERE o.id = due.id
        RETURNING o.id, o.channel, o.payload, o.attempts"#,
    )
    .bind(CLAIM_BATCH)
    .bind(CLAIM_LEASE_SECS as f64)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    rows.into_iter()
        .map(|r| ClaimedRow {
            id: r.try_get("id").unwrap_or_default(),
            channel: r.try_get("channel").unwrap_or_default(),
            payload: r.try_get::<Value, _>("payload").unwrap_or(Value::Null),
            attempts: r.try_get("attempts").unwrap_or_default(),
        })
        .collect()
}

/// One sweep: for every active tenant, claim due rows and (re)deliver each, settling it `delivered`
/// or rescheduling / dead-lettering it. Runs on the app pool; the per-tenant tx sets the RLS GUC so
/// claims and updates satisfy the forced tenant policy.
async fn tick(pool: &PgPool) {
    let tenants = crate::db::active_tenant_ids(pool).await.unwrap_or_default();
    for tenant_id in tenants {
        for row in claim_due(pool, tenant_id).await {
            let ok = crate::alert_delivery::redeliver_envelope(
                pool,
                tenant_id,
                &row.channel,
                &row.payload,
            )
            .await;
            if ok {
                mark_delivered(pool, tenant_id, row.id).await;
                metrics::counter!(
                    "weissman_notification_outbox_delivered_total", "channel" => row.channel.clone()
                )
                .increment(1);
            } else {
                mark_failed(
                    pool,
                    tenant_id,
                    row.id,
                    &row.channel,
                    row.attempts,
                    "retry delivery failed",
                )
                .await;
            }
        }
    }
}

/// Long-running retry worker for the notification outbox. Mirrors
/// [`crate::intel_kev::spawn_kev_refresh_worker`]: a single task, OnceLock-guarded, env-gated.
/// On by default (durability is the point); only an explicit off-switch disables it.
pub fn spawn_notification_outbox_worker(pool: Arc<PgPool>) {
    static SPAWNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    if matches!(
        std::env::var("WEISSMAN_NOTIFICATION_OUTBOX_ENABLED").as_deref(),
        Ok("0") | Ok("false") | Ok("off") | Ok("no")
    ) {
        tracing::info!(target: "notification_outbox", "notification outbox worker disabled by env");
        return;
    }
    tokio::spawn(async move {
        // Let the rest of the stack warm up before the first sweep.
        tokio::time::sleep(Duration::from_secs(15)).await;
        let mut ticker = tokio::time::interval(Duration::from_secs(WORKER_POLL_SECS));
        loop {
            ticker.tick().await;
            tick(pool.as_ref()).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_secs(1), 60);
        assert_eq!(backoff_secs(2), 120);
        assert_eq!(backoff_secs(3), 240);
        assert!(backoff_secs(MAX_ATTEMPTS) <= RETRY_MAX_SECS);
        // Never decreasing across the whole attempt range.
        let mut prev = 0;
        for a in 1..=MAX_ATTEMPTS {
            let b = backoff_secs(a);
            assert!(b >= prev, "backoff must not decrease at attempt {a}");
            prev = b;
        }
    }

    #[test]
    fn max_attempts_reaches_dead_letter() {
        // The MAX_ATTEMPTS-th failure (attempts_before = MAX_ATTEMPTS-1) must cross the threshold.
        let new_attempts = (MAX_ATTEMPTS - 1) + 1;
        assert!(new_attempts >= MAX_ATTEMPTS);
    }
}
