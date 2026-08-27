//! MPSC ingest queue, per-agent rate limit, gzip payload, dedicated pool semaphore.

use flate2::read::GzDecoder;
use governor::{clock::DefaultClock, state::keyed::DefaultKeyedStateStore, Quota, RateLimiter};
use sqlx::PgPool;
use std::io::Read;
use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};
use tokio::sync::{mpsc, Semaphore};

use super::health;
use super::validate::IngestReject;
use super::{ingest_sample, UebaIngestPayload};

const QUEUE_CAP: usize = 4096;
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

/// UEBA writes share a semaphore so a noisy agent cannot exhaust the UI pool.
fn ueba_permits() -> &'static Semaphore {
    static S: OnceLock<Semaphore> = OnceLock::new();
    S.get_or_init(|| {
        let n = std::env::var("WEISSMAN_UEBA_POOL_PERMITS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8)
            .clamp(2, 32);
        Semaphore::new(n)
    })
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
            health::set_queue_depth(QUEUE_CAP.saturating_sub(tx.capacity()));
            Ok(())
        }
        Err(mpsc::error::TrySendError::Full(_)) => Err(EnqueueError::QueueFull),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(EnqueueError::NotStarted),
    }
}

/// Direct path used by tests and by the worker after dequeue.
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
    let _permit = ueba_permits().acquire().await.map_err(|e| e.to_string())?;
    ingest_sample(pool, tenant_id, payload).await
}

pub fn spawn_ingest_worker(pool: Arc<PgPool>) {
    static SPAWNED: OnceLock<()> = OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    let (tx, mut rx) = mpsc::channel::<IngestJob>(QUEUE_CAP);
    install_channel(tx);
    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            health::set_queue_depth(rx.len());
            let pool = pool.clone();
            tokio::spawn(async move {
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
}
