//! MPSC ingest queue, per-agent rate limit, gzip payload, dedicated pool semaphore.
//!
//! HTTP/WS enqueue is `try_send` only — Axum never waits on Postgres. The recv
//! loop `spawn`s immediately; the **DB** semaphore is acquired inside the task
//! so a slow query cannot stall the worker loop or the HTTP thread pool.
//! A separate task-slot cap (not the PG pool) keeps spawn fan-out bounded so
//! the 50k MPSC remains the HTTP-facing burst buffer.

use flate2::read::GzDecoder;
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use sqlx::PgPool;
use std::io::Read;
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use super::health;
use super::validate::IngestReject;
use super::{ingest_sample, UebaIngestPayload};

const DEFAULT_QUEUE_CAP: usize = 50_000;
const MIN_QUEUE_CAP: usize = 4_096;
const MAX_QUEUE_CAP: usize = 200_000;
const DEFAULT_INFLIGHT: usize = 256;
const MIN_INFLIGHT: usize = 32;
const RATE_PER_MIN: u32 = 2;

struct IngestJob {
    tenant_id: i64,
    payload: UebaIngestPayload,
    source_ip: Option<String>,
    require_live_session: bool,
}

fn limiter() -> Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>> {
    static LIM: OnceLock<Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>> =
        OnceLock::new();
    LIM.get_or_init(|| {
        let n = NonZeroU32::new(RATE_PER_MIN).unwrap_or(NonZeroU32::MIN);
        Arc::new(RateLimiter::keyed(Quota::per_minute(n).allow_burst(n)))
    })
    .clone()
}

fn tx_slot() -> &'static OnceLock<mpsc::Sender<IngestJob>> {
    static TX: OnceLock<mpsc::Sender<IngestJob>> = OnceLock::new();
    &TX
}

fn channel_opt() -> Option<&'static mpsc::Sender<IngestJob>> {
    tx_slot().get()
}

fn install_channel(tx: mpsc::Sender<IngestJob>) {
    let _ = tx_slot().set(tx);
}

pub fn clamp_queue_cap(n: usize) -> usize {
    n.clamp(MIN_QUEUE_CAP, MAX_QUEUE_CAP)
}

pub fn configured_queue_cap() -> usize {
    let parsed = std::env::var("WEISSMAN_UEBA_INGEST_QUEUE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_QUEUE_CAP);
    clamp_queue_cap(parsed)
}

fn queue_cap() -> usize {
    static CAP: OnceLock<usize> = OnceLock::new();
    *CAP.get_or_init(configured_queue_cap)
}

pub fn clamp_inflight(n: usize) -> usize {
    n.clamp(MIN_INFLIGHT, queue_cap_or_default())
}

fn queue_cap_or_default() -> usize {
    DEFAULT_QUEUE_CAP
}

fn configured_inflight() -> usize {
    let parsed = std::env::var("WEISSMAN_UEBA_INGEST_INFLIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_INFLIGHT);
    parsed.clamp(MIN_INFLIGHT, configured_queue_cap())
}

fn task_slots() -> Arc<Semaphore> {
    static S: OnceLock<Arc<Semaphore>> = OnceLock::new();
    S.get_or_init(|| Arc::new(Semaphore::new(configured_inflight())))
        .clone()
}

/// UEBA writes share a semaphore so a noisy agent cannot exhaust the UI pool.
fn ueba_permits() -> Arc<Semaphore> {
    static S: OnceLock<Arc<Semaphore>> = OnceLock::new();
    S.get_or_init(|| {
        let n = std::env::var("WEISSMAN_UEBA_POOL_PERMITS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8)
            .clamp(2, 32);
        Arc::new(Semaphore::new(n))
    })
    .clone()
}

pub fn agent_rate_ok(agent_id: &str) -> bool {
    limiter().check_key(&agent_id.to_string()).is_ok()
}

/// Decode optional gzip+base64 metrics overlay.
pub fn maybe_decompress_metrics(p: &mut UebaIngestPayload) {
    let Some(gz) = p.metrics_gz.as_deref() else {
        return;
    };
    let Ok(raw) = base64_decode(gz) else {
        return;
    };
    let mut dec = GzDecoder::new(raw.as_slice());
    let mut out = Vec::new();
    if dec.read_to_end(&mut out).is_err() {
        return;
    }
    if let Ok(v) = serde_json::from_slice(&out) {
        p.metrics = v;
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| ())
}

pub fn gzip_json(v: &serde_json::Value) -> Option<String> {
    use base64::Engine;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let bytes = serde_json::to_vec(v).ok()?;
    if bytes.len() < 1024 {
        return None;
    }
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(&bytes).ok()?;
    let gz = enc.finish().ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(gz))
}

#[derive(Debug)]
pub enum EnqueueError {
    Reject(IngestReject),
    QueueFull,
    NotStarted,
}

pub fn enqueue(
    tenant_id: i64,
    payload: UebaIngestPayload,
    source_ip: Option<String>,
    require_live_session: bool,
) -> Result<(), EnqueueError> {
    if !agent_rate_ok(&payload.agent_id) {
        return Err(EnqueueError::Reject(IngestReject::RateLimited));
    }
    let Some(tx) = channel_opt() else {
        return Err(EnqueueError::NotStarted);
    };
    let job = IngestJob {
        tenant_id,
        payload,
        source_ip,
        require_live_session,
    };
    match tx.try_send(job) {
        Ok(()) => {
            health::set_queue_depth(queue_cap().saturating_sub(tx.capacity()));
            Ok(())
        }
        Err(mpsc::error::TrySendError::Full(_)) => Err(EnqueueError::QueueFull),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(EnqueueError::NotStarted),
    }
}

/// Direct path used by tests and by the worker after dequeue.
/// The DB semaphore is acquired inside the spawned ingest task, not here.
pub async fn process_job(
    pool: &PgPool,
    tenant_id: i64,
    mut payload: UebaIngestPayload,
    source_ip: Option<String>,
    require_live_session: bool,
) -> Result<super::UebaIngestSummary, String> {
    maybe_decompress_metrics(&mut payload);
    if let Some(ip) = source_ip {
        payload.source_ip = Some(ip);
    }
    payload.require_live_session = require_live_session;
    ingest_sample(pool, tenant_id, payload).await
}

pub fn spawn_ingest_worker(pool: Arc<PgPool>) {
    static SPAWNED: OnceLock<()> = OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    let cap = queue_cap();
    let (tx, mut rx) = mpsc::channel::<IngestJob>(cap);
    install_channel(tx);
    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            health::set_queue_depth(rx.len());
            let pool = pool.clone();
            let db_sem = ueba_permits();
            // Bound tokio tasks (not PG connections). Recv waits here only after
            // INFLIGHT tasks exist; HTTP try_send is still non-blocking.
            let slot: OwnedSemaphorePermit = match task_slots().acquire_owned().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _slot = slot;
                let _db_permit = match db_sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                match process_job(
                    pool.as_ref(),
                    job.tenant_id,
                    job.payload,
                    job.source_ip,
                    job.require_live_session,
                )
                .await
                {
                    Ok(_) => health::note_ingest(),
                    Err(e) => {
                        health::set_ingest_ok(false);
                        tracing::warn!(target: "ueba_ingest", error = %e, "ingest job failed");
                    }
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gzip_roundtrip_replaces_metrics() {
        let original = json!({"load_1m": 1.25, "failed_logins": 3});
        let gz = gzip_json(&original);
        // gzip_json skips payloads < 1 KiB
        let mut p = crate::ueba_detector::UebaIngestPayload {
            agent_id: "a".into(),
            client_id: 0,
            hour_of_week: 0,
            metrics: json!({}),
            seq: None,
            nonce: None,
            sampled_at: None,
            metrics_gz: gz.or_else(|| {
                use base64::Engine;
                use flate2::write::GzEncoder;
                use flate2::Compression;
                use std::io::Write;
                let bytes = serde_json::to_vec(&original).unwrap();
                let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
                enc.write_all(&bytes).unwrap();
                Some(base64::engine::general_purpose::STANDARD.encode(enc.finish().unwrap()))
            }),
            hardware_id: None,
            source_ip: None,
            require_live_session: false,
        };
        maybe_decompress_metrics(&mut p);
        assert_eq!(p.metrics["load_1m"], 1.25);
        assert_eq!(p.metrics["failed_logins"], 3);
    }

    #[test]
    fn ingest_queue_default_is_fifty_thousand() {
        assert_eq!(clamp_queue_cap(50_000), 50_000);
        assert_eq!(clamp_queue_cap(100), MIN_QUEUE_CAP);
        assert_eq!(clamp_queue_cap(1_000_000), MAX_QUEUE_CAP);
        assert!(DEFAULT_QUEUE_CAP >= 50_000);
    }

    #[test]
    fn inflight_slots_are_not_the_db_pool() {
        assert_eq!(clamp_inflight(1), MIN_INFLIGHT);
        assert_eq!(clamp_inflight(256), 256);
        assert!(DEFAULT_INFLIGHT >= MIN_INFLIGHT);
        assert!(DEFAULT_INFLIGHT < DEFAULT_QUEUE_CAP);
    }
}
