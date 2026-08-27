//! Batched UEBA sample retention with advisory locking, archival, and audit.

use chrono::{Timelike, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::health;

/// Stable session-level advisory lock key for UEBA retention (`'UEBA' << 32 | 'RETN'`).
const RETENTION_LOCK_KEY: i64 = 0x5545_4241_0000_5245;
const BATCH: i64 = 5000;
const DEFAULT_SAMPLE_DAYS: i64 = 14;
const DEFAULT_ANOMALY_DAYS: i64 = 90;
const EMERGENCY_SAMPLE_DAYS: i64 = 7;

pub fn sample_retention_days() -> i64 {
    std::env::var("WEISSMAN_UEBA_SAMPLE_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SAMPLE_DAYS)
        .clamp(7, 90)
}

pub fn anomaly_retention_days() -> i64 {
    std::env::var("WEISSMAN_UEBA_ANOMALY_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_ANOMALY_DAYS)
        .clamp(30, 3650)
}

/// Seconds past the hour at which the hourly purge prefers to run (low-traffic minute).
pub const PURGE_MINUTE: u32 = 45;

pub fn seconds_until_purge_minute() -> u64 {
    let now = Utc::now();
    let minute = now.minute();
    let sec = now.second();
    if minute < PURGE_MINUTE {
        ((PURGE_MINUTE - minute) as u64) * 60 - sec as u64
    } else {
        ((60 - minute + PURGE_MINUTE) as u64) * 60 - sec as u64
    }
}

async fn try_lock(pool: &PgPool) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
        .bind(RETENTION_LOCK_KEY)
        .fetch_one(pool)
        .await
}

async fn unlock(pool: &PgPool) {
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(RETENTION_LOCK_KEY)
        .execute(pool)
        .await;
}

#[derive(Debug, Clone, Copy)]
pub struct RetentionReport {
    pub samples_deleted: u64,
    pub samples_archived: u64,
    pub anomalies_deleted: u64,
    pub nonces_deleted: u64,
    pub elapsed_ms: u64,
    pub skipped_lock: bool,
    pub emergency: bool,
}

/// One retention pass. Safe to call from both the API process and weissman-worker;
/// the advisory lock guarantees a single runner.
pub async fn run_retention_once(pool: &PgPool) -> Result<RetentionReport, sqlx::Error> {
    let started = Instant::now();
    if !try_lock(pool).await? {
        return Ok(RetentionReport {
            samples_deleted: 0,
            samples_archived: 0,
            anomalies_deleted: 0,
            nonces_deleted: 0,
            elapsed_ms: started.elapsed().as_millis() as u64,
            skipped_lock: true,
            emergency: false,
        });
    }
    let result = run_retention_locked(pool).await;
    unlock(pool).await;
    match &result {
        Ok(r) => {
            health::note_retention(r.elapsed_ms, r.samples_deleted);
            health::set_retention_ok(true);
        }
        Err(_) => health::set_retention_ok(false),
    }
    result
}

async fn run_retention_locked(pool: &PgPool) -> Result<RetentionReport, sqlx::Error> {
    let started = Instant::now();
    let emergency = health::disk_free_pct("/")
        .map(|p| p < 10.0)
        .unwrap_or(false);
    let sample_days = if emergency {
        EMERGENCY_SAMPLE_DAYS
    } else {
        sample_retention_days()
    };

    let mut samples_archived = 0u64;
    let mut samples_deleted = 0u64;

    // Archive then delete in small batches so autovacuum can keep up and we never
    // hold a multi-million-row lock.
    loop {
        let n_arch: i64 = sqlx::query_scalar(
            r#"WITH doomed AS (
                   SELECT id FROM agent_metric_samples
                    WHERE sampled_at < now() - ($1::bigint * interval '1 day')
                    ORDER BY sampled_at
                    LIMIT $2
               ), moved AS (
                   INSERT INTO agent_metric_samples_archive
                       (id, tenant_id, agent_id, client_id, sampled_at, hour_of_week,
                        metrics, raw_size_bytes, seq, nonce, ingested_at, open_ports, source_ip)
                   SELECT s.id, s.tenant_id, s.agent_id, s.client_id, s.sampled_at, s.hour_of_week,
                          s.metrics, s.raw_size_bytes, s.seq, s.nonce, s.ingested_at, s.open_ports, s.source_ip
                     FROM agent_metric_samples s
                     JOIN doomed d ON d.id = s.id
                   ON CONFLICT DO NOTHING
                   RETURNING id
               )
               SELECT COUNT(*)::bigint FROM moved"#,
        )
        .bind(sample_days)
        .bind(BATCH)
        .fetch_one(pool)
        .await
        .unwrap_or(0);

        let deleted = sqlx::query(
            r#"WITH doomed AS (
                   SELECT id FROM agent_metric_samples
                    WHERE sampled_at < now() - ($1::bigint * interval '1 day')
                    ORDER BY sampled_at
                    LIMIT $2
               )
               DELETE FROM agent_metric_samples s
                USING doomed d
                WHERE s.id = d.id"#,
        )
        .bind(sample_days)
        .bind(BATCH)
        .execute(pool)
        .await?;
        let n = deleted.rows_affected();
        samples_archived += n_arch.max(0) as u64;
        samples_deleted += n;
        if n < BATCH as u64 {
            break;
        }
        // Yield so API traffic is not starved.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let anomaly_days = anomaly_retention_days();
    let anom = sqlx::query(
        r#"DELETE FROM agent_anomalies
            WHERE detected_at < now() - ($1::bigint * interval '1 day')
              AND COALESCE(status, 'open') NOT IN ('open', 'approved')"#,
    )
    .bind(anomaly_days)
    .execute(pool)
    .await?;

    let nonces = sqlx::query(
        r#"DELETE FROM ueba_ingest_nonces WHERE seen_at < now() - interval '48 hours'"#,
    )
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);

    // Age learned_set entries (JSON object of item → last-seen unix).
    let _ = sqlx::query(
        r#"UPDATE agent_metric_baselines
              SET learned_set = COALESCE((
                    SELECT jsonb_object_agg(key, value)
                      FROM jsonb_each(learned_set)
                     WHERE jsonb_typeof(learned_set) = 'object'
                       AND COALESCE((value #>> '{}')::bigint, 0) > extract(epoch from now()) - 30*86400
              ), learned_set)
            WHERE jsonb_typeof(learned_set) = 'object'"#,
    )
    .execute(pool)
    .await;

    let elapsed_ms = started.elapsed().as_millis() as u64;

    // Fleet-wide audit (tenant 0 is not valid). Write one row per active tenant would be
    // chatty; we log to nl_query_audit-style ueba_retention_runs instead.
    let _ = sqlx::query(
        r#"INSERT INTO ueba_retention_runs
               (started_at, finished_at, samples_deleted, samples_archived,
                anomalies_deleted, elapsed_ms, emergency, lock_skipped)
           VALUES (now() - ($1::bigint * interval '1 millisecond'), now(), $2, $3, $4, $5, $6, false)"#,
    )
    .bind(elapsed_ms as i64)
    .bind(samples_deleted as i64)
    .bind(samples_archived as i64)
    .bind(anom.rows_affected() as i64)
    .bind(elapsed_ms as i64)
    .bind(emergency)
    .execute(pool)
    .await;

    tracing::info!(
        target: "ueba_detector::retention",
        samples_deleted,
        samples_archived,
        anomalies_deleted = anom.rows_affected(),
        elapsed_ms,
        emergency,
        "UEBA retention pass complete"
    );

    Ok(RetentionReport {
        samples_deleted,
        samples_archived,
        anomalies_deleted: anom.rows_affected(),
        nonces_deleted: nonces,
        elapsed_ms,
        skipped_lock: false,
        emergency,
    })
}

/// Background loop. Sleeps until minute 45 of each hour, then runs a pass.
pub fn spawn_retention_loop(pool: Arc<PgPool>) {
    static SPAWNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    tokio::spawn(async move {
        // Align to :45. First tick still runs after the wait so boot does not dump a
        // multi-million-row DELETE onto a warming database.
        loop {
            let wait = seconds_until_purge_minute().clamp(5, 3600);
            tokio::time::sleep(Duration::from_secs(wait)).await;
            if let Err(e) = run_retention_once(pool.as_ref()).await {
                tracing::warn!(target: "ueba_detector::retention", error = %e, "retention pass failed");
                health::set_retention_ok(false);
            }
        }
    });
}

/// Worker-side daily baseline recalibration (Welford rebuild from the rolling window).
pub fn spawn_baseline_recompute_loop(pool: Arc<PgPool>) {
    static SPAWNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(24 * 3600));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) = recompute_all_baselines(pool.as_ref()).await {
                tracing::warn!(target: "ueba_detector", error = %e, "daily baseline recompute failed");
            }
        }
    });
}

async fn recompute_all_baselines(pool: &PgPool) -> Result<(), sqlx::Error> {
    // Isolation: READ COMMITTED, outside the API write path. We only touch baseline rows.
    sqlx::query(
        r#"UPDATE agent_metric_baselines b
              SET n = s.n,
                  mean = s.mean,
                  stddev = s.stddev,
                  welford_m2 = CASE WHEN s.n > 1 THEN (s.stddev * s.stddev) * (s.n - 1) ELSE 0 END,
                  last_updated_at = now()
             FROM (
                SELECT agent_id, key AS metric_name,
                       COUNT(*)::int AS n,
                       AVG(val) AS mean,
                       COALESCE(STDDEV_SAMP(val), 0) AS stddev
                  FROM agent_metric_samples samp
                  CROSS JOIN LATERAL (
                      SELECT e.key, (e.value #>> '{}')::double precision AS val
                        FROM jsonb_each(samp.metrics) e
                       WHERE jsonb_typeof(e.value) = 'number'
                  ) m
                 WHERE samp.sampled_at > now() - interval '7 days'
                 GROUP BY agent_id, key
             ) s
            WHERE b.agent_id = s.agent_id
              AND b.metric_name = s.metric_name
              AND b.hour_of_week = 0"#,
    )
    .execute(pool)
    .await?;
    Ok(())
}
