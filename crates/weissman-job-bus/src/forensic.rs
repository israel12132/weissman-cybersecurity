//! Forensic dead-letter queue — cryptographically sealed failure bundles.

use crate::error::JobBusError;
use crate::events::fetch_event_chain_hash;
use crate::signing::SignedJobEnvelope;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

type HmacSha256 = Hmac<sha2::Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    pub rss_kb: u64,
    pub vm_size_kb: u64,
    pub thread_count: u32,
    pub open_fds: Option<u32>,
    pub captured_at: String,
}

impl MemorySnapshot {
    pub fn capture_current() -> Self {
        let (rss, vm, threads) = proc_status_memory().unwrap_or((0, 0, 1));
        // Real fd count — a hardcoded `open_fds: None`/`thread_count: 1` is actively misleading for
        // exactly the failure modes this bundle exists to diagnose (leaked threads, fd exhaustion).
        let open_fds = std::fs::read_dir("/proc/self/fd")
            .map(|d| d.count() as u32)
            .ok();
        Self {
            rss_kb: rss,
            vm_size_kb: vm,
            thread_count: threads,
            open_fds,
            captured_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

fn proc_status_memory() -> Option<(u64, u64, u32)> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut rss = 0u64;
    let mut vm = 0u64;
    let mut threads = 1u32;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            rss = v.split_whitespace().next()?.parse().ok()?;
        }
        if let Some(v) = line.strip_prefix("VmSize:") {
            vm = v.split_whitespace().next()?.parse().ok()?;
        }
        if let Some(v) = line.strip_prefix("Threads:") {
            threads = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);
        }
    }
    Some((rss, vm, threads))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicBundle {
    pub job_id: Uuid,
    pub tenant_id: i64,
    pub worker_id: String,
    pub failure_class: String,
    pub stack_trace: String,
    pub signed_envelope: Option<SignedJobEnvelope>,
    pub input_params: Value,
    pub memory_snapshot: MemorySnapshot,
    pub event_chain_hash: String,
    pub bundle_seal: String,
}

impl ForensicBundle {
    pub async fn build(
        pool: &PgPool,
        job_id: Uuid,
        tenant_id: i64,
        worker_id: &str,
        failure_class: &str,
        stack_trace: &str,
        signed_envelope: Option<SignedJobEnvelope>,
        input_params: Value,
        signing_key: Option<&[u8]>,
    ) -> Result<Self, JobBusError> {
        let event_chain_hash = fetch_event_chain_hash(pool, job_id).await?;
        let memory_snapshot = MemorySnapshot::capture_current();
        let mut bundle = Self {
            job_id,
            tenant_id,
            worker_id: worker_id.to_string(),
            failure_class: failure_class.to_string(),
            stack_trace: stack_trace.chars().take(16_384).collect(),
            signed_envelope,
            input_params,
            memory_snapshot,
            event_chain_hash,
            bundle_seal: String::new(),
        };
        bundle.bundle_seal = seal_bundle(&bundle, signing_key)?;
        Ok(bundle)
    }
}

fn seal_bundle(bundle: &ForensicBundle, key: Option<&[u8]>) -> Result<String, JobBusError> {
    let mut for_hash = bundle.clone();
    for_hash.bundle_seal = String::new();
    let canonical =
        serde_json::to_vec(&for_hash).map_err(|e| JobBusError::Forensic(e.to_string()))?;
    let digest = format!("{:x}", Sha256::digest(&canonical));
    if let Some(k) = key {
        let mut mac =
            HmacSha256::new_from_slice(k).map_err(|e| JobBusError::Forensic(e.to_string()))?;
        mac.update(digest.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    } else {
        Ok(digest)
    }
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

/// Persist sealed forensic bundle. Returns DLQ row id.
pub async fn enqueue_forensic_dlq(
    pool: &PgPool,
    bundle: &ForensicBundle,
    signing_key: Option<&[u8]>,
) -> Result<Uuid, JobBusError> {
    let seal = seal_bundle(bundle, signing_key)?;
    if seal != bundle.bundle_seal {
        return Err(JobBusError::Forensic("bundle seal mismatch".into()));
    }
    // `weissman_job_forensic_dlq` is FORCE ROW LEVEL SECURITY and `weissman_app` is NOBYPASSRLS;
    // scope the INSERT to the bundle's tenant so its WITH CHECK passes (an unscoped pool inherits
    // the database default GUC '0' and the insert is rejected). Mirrors `events::append_event`.
    let mut tx = weissman_db::begin_tenant_tx(pool, bundle.tenant_id).await?;
    let id: Uuid = sqlx::query_scalar(
        r#"INSERT INTO weissman_job_forensic_dlq
             (job_id, tenant_id, worker_id, failure_class, stack_trace,
              input_params, memory_snapshot, event_chain_hash, bundle_seal, signed_envelope)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           RETURNING id"#,
    )
    .bind(bundle.job_id)
    .bind(bundle.tenant_id)
    .bind(&bundle.worker_id)
    .bind(&bundle.failure_class)
    .bind(&bundle.stack_trace)
    .bind(sqlx::types::Json(bundle.input_params.clone()))
    .bind(sqlx::types::Json(bundle.memory_snapshot.clone()))
    .bind(&bundle.event_chain_hash)
    .bind(&bundle.bundle_seal)
    .bind(
        bundle
            .signed_envelope
            .as_ref()
            .map(|e| sqlx::types::Json(e.clone())),
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::error!(
        target: "job_bus",
        %id,
        job_id = %bundle.job_id,
        failure_class = %bundle.failure_class,
        "forensic DLQ bundle sealed"
    );
    Ok(id)
}
