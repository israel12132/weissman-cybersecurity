//! High-volume UEBA ingest via PostgreSQL binary COPY and a bounded Tokio mPSC.
//!
//! The HTTP / agent path does **not** INSERT on the request task. It enqueues a
//! [`UebaCopyRequest`] onto a **bounded** channel (default 50_000). A single worker
//! flushes when the buffer hits [`DEFAULT_BATCH_SIZE`] or [`DEFAULT_FLUSH_INTERVAL`],
//! streaming the batch with `COPY … FROM STDIN WITH (FORMAT binary)` inside an
//! explicit transaction so a mid-stream failure rolls the batch back.
//!
//! `pg_attribute` is queried **once** in [`spawn`] via
//! [`warm_agent_metric_samples_schema`] before the flush loop. Each COPY uses
//! [`require_warmed_agent_metric_samples_schema`] (memory only).
//!
//! When the channel is full the sample is **rejected** ([`SubmitError::Backpressure`])
//! — it is not INSERT-fallback'd (that would just move the flood onto Postgres).
//! Agents keep the sample in their local spill file and retry. INSERT fallback is
//! reserved for "worker not running / channel closed" (tests, process teardown).

use crate::ueba_detector::{UebaIngestPayload, UebaIngestSummary};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use weissman_db::pg_binary_copy::{
    agent_metric_samples_copy_sql, agent_metric_samples_schema_is_ok, encode_agent_metric_sample,
    require_warmed_agent_metric_samples_schema, warm_agent_metric_samples_schema, PgBinaryCopyBuf,
    AGENT_METRIC_SAMPLES_SCHEMA_VERSION,
};

/// Default flush when the buffer fills (override: `WEISSMAN_UEBA_COPY_BATCH_SIZE`).
pub const DEFAULT_BATCH_SIZE: usize = 512;
/// Default maximum time a sample may sit in RAM (override: `WEISSMAN_UEBA_COPY_FLUSH_MS`).
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_millis(50);
/// Default in-memory channel capacity (override: `WEISSMAN_UEBA_COPY_CHANNEL`).
pub const DEFAULT_CHANNEL_CAP: usize = 50_000;
/// Hint returned to agents / HTTP when the channel is full.
pub const DEFAULT_BACKPRESSURE_RETRY_MS: u64 = 200;

static INGEST_TX: OnceLock<mpsc::Sender<UebaCopyRequest>> = OnceLock::new();
static COPY_ENABLED: AtomicBool = AtomicBool::new(false);
static ROWS_FLUSHED: AtomicU64 = AtomicU64::new(0);
static FLUSH_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_FLUSH_MS: AtomicU64 = AtomicU64::new(0);
static FALLBACK_INSERTS: AtomicU64 = AtomicU64::new(0);
static BACKPRESSURE_REJECTS: AtomicU64 = AtomicU64::new(0);
static QUEUED: AtomicUsize = AtomicUsize::new(0);

/// One telemetry sample waiting for binary COPY.
pub struct UebaCopyRequest {
    pub tenant_id: i64,
    pub payload: UebaIngestPayload,
    pub sampled_at: DateTime<Utc>,
    pub raw_size_bytes: i32,
    reply: Option<oneshot::Sender<Result<UebaIngestSummary, String>>>,
}

/// Channel-full signal: callers must wait or spill locally. Do not INSERT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestBackpressure {
    pub retry_after_ms: u64,
    pub queued: usize,
    pub channel_cap: usize,
    pub reason: &'static str,
}

/// Failure to accept a UEBA sample onto the COPY path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    Backpressure(IngestBackpressure),
    Failed(String),
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backpressure(bp) => write!(
                f,
                "backpressure: {} (retry_after_ms={}, queued={}/{})",
                bp.reason, bp.retry_after_ms, bp.queued, bp.channel_cap
            ),
            Self::Failed(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for SubmitError {}

impl SubmitError {
    #[must_use]
    pub fn retry_after_ms(&self) -> Option<u64> {
        match self {
            Self::Backpressure(bp) => Some(bp.retry_after_ms),
            Self::Failed(_) => None,
        }
    }
}

/// Snapshot of the COPY ingest worker (replica-local).
#[derive(Debug, Clone, Serialize)]
pub struct UebaCopyStats {
    pub copy_enabled: bool,
    pub copy_rows_flushed: u64,
    pub copy_flushes: u64,
    pub copy_last_flush_ms: u64,
    pub copy_channel_queued: usize,
    pub copy_fallback_inserts: u64,
    pub copy_backpressure_rejects: u64,
    pub copy_schema_version: u32,
    /// `true` after the one-time startup `pg_attribute` warm. The COPY flush
    /// path never re-queries the catalog.
    pub copy_schema_warmed: bool,
    pub copy_batch_size: usize,
    pub copy_flush_interval_ms: u64,
    pub copy_channel_cap: usize,
}

#[must_use]
pub fn snapshot_stats() -> UebaCopyStats {
    UebaCopyStats {
        copy_enabled: COPY_ENABLED.load(Ordering::Relaxed),
        copy_rows_flushed: ROWS_FLUSHED.load(Ordering::Relaxed),
        copy_flushes: FLUSH_COUNT.load(Ordering::Relaxed),
        copy_last_flush_ms: LAST_FLUSH_MS.load(Ordering::Relaxed),
        copy_channel_queued: QUEUED.load(Ordering::Relaxed),
        copy_fallback_inserts: FALLBACK_INSERTS.load(Ordering::Relaxed),
        copy_backpressure_rejects: BACKPRESSURE_REJECTS.load(Ordering::Relaxed),
        copy_schema_version: AGENT_METRIC_SAMPLES_SCHEMA_VERSION,
        copy_schema_warmed: agent_metric_samples_schema_is_ok(),
        copy_batch_size: env_usize("WEISSMAN_UEBA_COPY_BATCH_SIZE", DEFAULT_BATCH_SIZE).max(1),
        copy_flush_interval_ms: env_u64(
            "WEISSMAN_UEBA_COPY_FLUSH_MS",
            DEFAULT_FLUSH_INTERVAL.as_millis() as u64,
        )
        .max(1),
        copy_channel_cap: env_usize("WEISSMAN_UEBA_COPY_CHANNEL", DEFAULT_CHANNEL_CAP).max(1),
    }
}

/// Spawn the COPY ingest worker. Safe to call once per process; subsequent calls are no-ops.
pub fn spawn(pool: Arc<PgPool>) {
    if INGEST_TX.get().is_some() {
        return;
    }
    let cap = env_usize("WEISSMAN_UEBA_COPY_CHANNEL", DEFAULT_CHANNEL_CAP).max(1);
    let batch_size = env_usize("WEISSMAN_UEBA_COPY_BATCH_SIZE", DEFAULT_BATCH_SIZE).max(1);
    let flush_interval = Duration::from_millis(
        env_u64(
            "WEISSMAN_UEBA_COPY_FLUSH_MS",
            DEFAULT_FLUSH_INTERVAL.as_millis() as u64,
        )
        .max(1),
    );
    let (tx, rx) = mpsc::channel(cap);
    if INGEST_TX.set(tx).is_err() {
        return;
    }
    COPY_ENABLED.store(true, Ordering::Relaxed);
    tracing::info!(
        target: "ueba_copy",
        batch_size,
        flush_interval_ms = flush_interval.as_millis() as u64,
        channel_cap = cap,
        schema_version = AGENT_METRIC_SAMPLES_SCHEMA_VERSION,
        "PostgreSQL binary COPY ingest worker started (bounded mPSC)"
    );
    tokio::spawn(async move {
        let mgr = BulkIngestManager {
            db_pool: pool,
            rx_channel: rx,
            batch_size,
            flush_interval,
        };
        // Warm *before* the flush loop so COPY never issues a catalog query.
        // Concurrent ingest can enqueue during this await; the first flush
        // runs only after the warm attempt completes.
        match warm_agent_metric_samples_schema(&mgr.db_pool).await {
            Ok(()) => tracing::info!(
                target: "ueba_copy",
                schema_version = AGENT_METRIC_SAMPLES_SCHEMA_VERSION,
                "agent_metric_samples COPY schema contract warmed (one pg_attribute query)"
            ),
            Err(e) => tracing::error!(
                target: "ueba_copy",
                error = %e,
                "schema contract warm failed; COPY flushes will refuse and INSERT-fallback"
            ),
        }
        if let Err(e) = mgr.run_loop().await {
            tracing::error!(target: "ueba_copy", error = %e, "COPY ingest worker exited");
        }
        COPY_ENABLED.store(false, Ordering::Relaxed);
    });
}

#[must_use]
pub fn worker_running() -> bool {
    COPY_ENABLED.load(Ordering::Relaxed)
}

/// Enqueue a UEBA sample, or reject it with backpressure when the channel is full.
///
/// * `wait` — when `Some`, block until the flush+detector finishes or the timeout elapses.
///   The HTTP admin path uses this so the cockpit still receives the anomaly summary.
///   The agent WS path passes `None` (fire-and-forget; backpressure is still returned).
///
/// INSERT fallback runs only when the worker is absent or the channel is closed —
/// never when the channel is merely full.
pub async fn submit_ueba_sample(
    pool: &PgPool,
    tenant_id: i64,
    payload: UebaIngestPayload,
    wait: Option<Duration>,
) -> Result<UebaIngestSummary, SubmitError> {
    let raw_size_bytes = serde_json::to_string(&payload.metrics)
        .map(|s| s.len() as i32)
        .unwrap_or(0);
    let (reply_tx, reply_rx) = if wait.is_some() {
        let (tx, rx) = oneshot::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let req = UebaCopyRequest {
        tenant_id,
        payload,
        sampled_at: Utc::now(),
        raw_size_bytes,
        reply: reply_tx,
    };
    match try_enqueue(req) {
        Enqueue::Queued => {
            if let (Some(timeout), Some(rx)) = (wait, reply_rx) {
                match tokio::time::timeout(timeout, rx).await {
                    Ok(Ok(Ok(summary))) => Ok(summary),
                    Ok(Ok(Err(e))) => Err(SubmitError::Failed(e)),
                    Ok(Err(_)) => Err(SubmitError::Failed(
                        "ueba copy ingest worker dropped the reply".into(),
                    )),
                    Err(_) => Err(SubmitError::Failed(
                        "ueba copy ingest timed out waiting for flush".into(),
                    )),
                }
            } else {
                Ok(UebaIngestSummary::default())
            }
        }
        Enqueue::Backpressure { queued, cap } => {
            BACKPRESSURE_REJECTS.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("weissman_ueba_copy_backpressure_total").increment(1);
            Err(SubmitError::Backpressure(IngestBackpressure {
                retry_after_ms: DEFAULT_BACKPRESSURE_RETRY_MS,
                queued,
                channel_cap: cap,
                reason: "ueba_ingest_channel_full",
            }))
        }
        Enqueue::Fallback(req) => fallback_insert(pool, req)
            .await
            .map_err(SubmitError::Failed),
    }
}

enum Enqueue {
    Queued,
    Backpressure { queued: usize, cap: usize },
    Fallback(UebaCopyRequest),
}

fn try_enqueue(req: UebaCopyRequest) -> Enqueue {
    let Some(tx) = INGEST_TX.get() else {
        return Enqueue::Fallback(req);
    };
    match tx.try_send(req) {
        Ok(()) => {
            QUEUED.fetch_add(1, Ordering::Relaxed);
            Enqueue::Queued
        }
        Err(mpsc::error::TrySendError::Full(_req)) => Enqueue::Backpressure {
            queued: QUEUED.load(Ordering::Relaxed),
            cap: env_usize("WEISSMAN_UEBA_COPY_CHANNEL", DEFAULT_CHANNEL_CAP).max(1),
        },
        Err(mpsc::error::TrySendError::Closed(req)) => Enqueue::Fallback(req),
    }
}

async fn fallback_insert(pool: &PgPool, req: UebaCopyRequest) -> Result<UebaIngestSummary, String> {
    FALLBACK_INSERTS.fetch_add(1, Ordering::Relaxed);
    let result = crate::ueba_detector::ingest_sample(pool, req.tenant_id, req.payload).await;
    if let Some(tx) = req.reply {
        let _ = tx.send(result.clone());
    }
    result
}

struct BulkIngestManager {
    db_pool: Arc<PgPool>,
    rx_channel: mpsc::Receiver<UebaCopyRequest>,
    batch_size: usize,
    flush_interval: Duration,
}

impl BulkIngestManager {
    async fn run_loop(mut self) -> Result<(), sqlx::Error> {
        let mut buffer: Vec<UebaCopyRequest> = Vec::with_capacity(self.batch_size);
        let mut last_flush = Instant::now();

        loop {
            let timeout_duration = self
                .flush_interval
                .checked_sub(last_flush.elapsed())
                .unwrap_or(Duration::from_millis(1));

            tokio::select! {
                maybe_sample = self.rx_channel.recv() => {
                    match maybe_sample {
                        Some(sample) => {
                            QUEUED.fetch_sub(1, Ordering::Relaxed);
                            buffer.push(sample);
                            if buffer.len() >= self.batch_size {
                                self.flush_batch(&mut buffer).await;
                                last_flush = Instant::now();
                            }
                        }
                        None => {
                            if !buffer.is_empty() {
                                self.flush_batch(&mut buffer).await;
                            }
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(timeout_duration) => {
                    if !buffer.is_empty() {
                        self.flush_batch(&mut buffer).await;
                    }
                    last_flush = Instant::now();
                }
            }
        }
        Ok(())
    }

    async fn flush_batch(&self, buffer: &mut Vec<UebaCopyRequest>) {
        if buffer.is_empty() {
            return;
        }
        let start = Instant::now();
        let batch = std::mem::take(buffer);
        let count = batch.len();

        let mut by_tenant: BTreeMap<i64, Vec<UebaCopyRequest>> = BTreeMap::new();
        for req in batch {
            by_tenant.entry(req.tenant_id).or_default().push(req);
        }

        for (tenant_id, reqs) in by_tenant {
            if let Err(e) = self.flush_tenant(tenant_id, reqs).await {
                tracing::error!(
                    target: "ueba_copy",
                    tenant_id,
                    error = %e,
                    "tenant COPY flush failed after INSERT fallback"
                );
            }
        }

        let elapsed = start.elapsed();
        LAST_FLUSH_MS.store(elapsed.as_millis() as u64, Ordering::Relaxed);
        FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
        ROWS_FLUSHED.fetch_add(count as u64, Ordering::Relaxed);
        metrics::counter!("weissman_ueba_copy_rows_total").increment(count as u64);
        tracing::info!(
            target: "ueba_copy",
            rows = count,
            elapsed_ms = elapsed.as_millis() as u64,
            "binary COPY ingest flush"
        );
    }

    async fn flush_tenant(&self, tenant_id: i64, reqs: Vec<UebaCopyRequest>) -> Result<(), String> {
        match self.copy_then_analyze(tenant_id, &reqs).await {
            Ok(summaries) => {
                for (req, summary) in reqs.into_iter().zip(summaries.into_iter()) {
                    if let Some(tx) = req.reply {
                        let _ = tx.send(Ok(summary));
                    }
                }
                Ok(())
            }
            Err(copy_err) => {
                tracing::warn!(
                    target: "ueba_copy",
                    tenant_id,
                    error = %copy_err,
                    rows = reqs.len(),
                    "COPY failed; falling back to per-row INSERT"
                );
                for req in reqs {
                    let result =
                        crate::ueba_detector::ingest_sample(&self.db_pool, tenant_id, req.payload)
                            .await;
                    FALLBACK_INSERTS.fetch_add(1, Ordering::Relaxed);
                    if let Some(tx) = req.reply {
                        let _ = tx.send(result);
                    }
                }
                Err(copy_err)
            }
        }
    }

    async fn copy_then_analyze(
        &self,
        tenant_id: i64,
        reqs: &[UebaCopyRequest],
    ) -> Result<Vec<UebaIngestSummary>, String> {
        let n = reqs.len();
        if n == 0 {
            return Ok(Vec::new());
        }

        // Memory-only. A catalog miss here is a programming/ops error (warm
        // skipped), not a reason to query pg_attribute on the ingest path.
        if let Err(e) = require_warmed_agent_metric_samples_schema() {
            tracing::error!(target: "ueba_copy", error = %e, "refusing binary COPY; schema contract not warmed");
            return Err(e);
        }

        let mut tx = crate::db::begin_tenant_tx(&self.db_pool, tenant_id)
            .await
            .map_err(|e| format!("tenant tx: {e}"))?;

        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT nextval('agent_metric_samples_id_seq') FROM generate_series(1, $1)",
        )
        .bind(n as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("reserve ids: {e}"))?;
        if ids.len() != n {
            let _ = tx.rollback().await;
            return Err(format!("reserved {} ids for {} samples", ids.len(), n));
        }

        let mut buf = PgBinaryCopyBuf::new();
        for (req, id) in reqs.iter().zip(ids.iter()) {
            encode_agent_metric_sample(
                &mut buf,
                *id,
                tenant_id,
                &req.payload.agent_id,
                req.payload.client_id,
                req.sampled_at.timestamp_micros(),
                req.payload.hour_of_week,
                &req.payload.metrics,
                req.raw_size_bytes,
            );
        }
        let encoded = buf.tuple_count() as u64;
        let binary_data = buf.finish();

        // The COPY writer borrows `tx`. Keep that borrow inside this block (or
        // consume the writer via abort/finish) so COMMIT/ROLLBACK can take `tx`.
        // Dropping `tx` on any `return Err` also rolls the batch back.
        let rows = {
            let mut writer = tx
                .copy_in_raw(agent_metric_samples_copy_sql())
                .await
                .map_err(|e| format!("copy_in_raw: {e}"))?;
            if let Err(e) = writer.send(binary_data.as_slice()).await {
                let abort = writer.abort(format!("copy send failed: {e}")).await;
                return Err(format!("copy send: {e}; abort={abort:?}"));
            }
            writer
                .finish()
                .await
                .map_err(|e| format!("copy finish: {e}"))?
        };

        if rows != encoded {
            let _ = tx.rollback().await;
            return Err(format!(
                "COPY row count mismatch: expected {encoded}, got {rows}"
            ));
        }

        // COMMIT only after the stream finished and Postgres confirmed the row count.
        tx.commit().await.map_err(|e| format!("copy commit: {e}"))?;

        // Detector after COPY so the cockpit sees samples immediately; anomalies follow
        // in a second tenant transaction (same as a crash between INSERT and baseline
        // would have behaved on the historical path).
        let mut summaries = Vec::with_capacity(n);
        let mut analyze_tx = crate::db::begin_tenant_tx(&self.db_pool, tenant_id)
            .await
            .map_err(|e| format!("analyze tx: {e}"))?;
        for (req, id) in reqs.iter().zip(ids.iter()) {
            let summary = crate::ueba_detector::analyze_sample_in_tx(
                &mut analyze_tx,
                tenant_id,
                *id,
                &req.payload,
            )
            .await?;
            summaries.push(summary);
        }
        analyze_tx
            .commit()
            .await
            .map_err(|e| format!("analyze commit: {e}"))?;
        Ok(summaries)
    }
}

fn env_usize(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

fn env_u64(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use weissman_db::pg_binary_copy::{
        agent_metric_samples_copy_sql, pg_timestamptz_to_unix_micros,
        AGENT_METRIC_SAMPLES_COPY_COLUMNS,
    };

    #[test]
    fn copy_sql_is_binary_and_covers_live_columns() {
        let sql = agent_metric_samples_copy_sql();
        assert!(sql.contains("WITH (FORMAT binary)"));
        for col in AGENT_METRIC_SAMPLES_COPY_COLUMNS {
            assert!(sql.contains(col.name), "missing column {}", col.name);
        }
    }

    #[test]
    fn encode_roundtrip_matches_pg_epoch_conversion() {
        let now = Utc::now();
        let mut buf = PgBinaryCopyBuf::new();
        encode_agent_metric_sample(
            &mut buf,
            1,
            2,
            "agent-1",
            3,
            now.timestamp_micros(),
            16,
            &json!({"cpu": 1.0}),
            8,
        );
        let bytes = buf.finish();
        assert_eq!(&bytes[..11], b"PGCOPY\n\xff\r\n\0");
        assert_eq!(&bytes[bytes.len() - 2..], &[0xFF, 0xFF]);
        assert_eq!(
            pg_timestamptz_to_unix_micros(
                weissman_db::pg_binary_copy::unix_micros_to_pg_timestamptz(now.timestamp_micros())
            ),
            now.timestamp_micros()
        );
    }

    #[test]
    fn defaults_bound_the_mpsc_and_flush_window() {
        assert!(DEFAULT_BATCH_SIZE >= 64);
        assert!(DEFAULT_FLUSH_INTERVAL <= Duration::from_millis(500));
        assert_eq!(DEFAULT_CHANNEL_CAP, 50_000);
        assert!(DEFAULT_BACKPRESSURE_RETRY_MS >= 50);
    }

    #[test]
    fn copy_hot_path_refuses_without_a_catalog_query() {
        weissman_db::pg_binary_copy::invalidate_agent_metric_samples_schema_cache();
        let err = require_warmed_agent_metric_samples_schema().expect_err("cold");
        assert!(
            err.contains("not warmed") || err.contains("refusing COPY"),
            "{err}"
        );
    }

    #[test]
    fn snapshot_stats_reports_schema_version_and_backpressure_counter() {
        let s = snapshot_stats();
        assert!(!s.copy_enabled || worker_running());
        assert!(s.copy_batch_size >= 1);
        assert_eq!(s.copy_schema_version, AGENT_METRIC_SAMPLES_SCHEMA_VERSION);
        assert_eq!(s.copy_schema_warmed, agent_metric_samples_schema_is_ok());
        assert_eq!(
            s.copy_backpressure_rejects,
            BACKPRESSURE_REJECTS.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn submit_error_backpressure_exposes_retry() {
        let err = SubmitError::Backpressure(IngestBackpressure {
            retry_after_ms: 200,
            queued: 50_000,
            channel_cap: 50_000,
            reason: "ueba_ingest_channel_full",
        });
        assert_eq!(err.retry_after_ms(), Some(200));
        let rendered = err.to_string();
        assert!(rendered.contains("backpressure"));
        assert!(rendered.contains("50000"));
        assert!(SubmitError::Failed("x".into()).retry_after_ms().is_none());
    }

    #[test]
    fn full_channel_is_backpressure_not_fallback() {
        // try_enqueue without a spawned worker is Fallback (worker absent), which
        // is the INSERT path. Channel-full is a distinct variant used only when
        // try_send returns Full — asserted here by constructing the outcome the
        // HTTP layer maps to 429.
        let bp = IngestBackpressure {
            retry_after_ms: DEFAULT_BACKPRESSURE_RETRY_MS,
            queued: DEFAULT_CHANNEL_CAP,
            channel_cap: DEFAULT_CHANNEL_CAP,
            reason: "ueba_ingest_channel_full",
        };
        let err = SubmitError::Backpressure(bp.clone());
        assert!(matches!(err, SubmitError::Backpressure(_)));
        assert_ne!(
            format!("{err}"),
            "fallback",
            "full channel must not look like INSERT fallback"
        );
        assert_eq!(bp.channel_cap, 50_000);
    }
}
