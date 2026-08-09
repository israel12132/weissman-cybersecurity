//! Append-only job event log (Postgres) + Redis Streams fan-out.

use crate::error::JobBusError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub const REDIS_STREAM_KEY: &str = "weissman:jobs:events";
/// Approximate cap on retained Redis stream entries (Postgres is the durable source of truth).
pub const REDIS_STREAM_MAXLEN: i64 = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobEventKind {
    JobDispatched,
    WorkerClaimed,
    LeaseAcquired,
    LeaseExtended,
    ExploitFired,
    JobCompleted,
    JobFailed,
    JobRetryScheduled,
    WorkerTerminated,
    JobOrphaned,
    ForensicDlqEnqueued,
}

impl JobEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JobDispatched => "job_dispatched",
            Self::WorkerClaimed => "worker_claimed",
            Self::LeaseAcquired => "lease_acquired",
            Self::LeaseExtended => "lease_extended",
            Self::ExploitFired => "exploit_fired",
            Self::JobCompleted => "job_completed",
            Self::JobFailed => "job_failed",
            Self::JobRetryScheduled => "job_retry_scheduled",
            Self::WorkerTerminated => "worker_terminated",
            Self::JobOrphaned => "job_orphaned",
            Self::ForensicDlqEnqueued => "forensic_dlq_enqueued",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobEventRecord {
    pub seq: i64,
    pub job_id: Uuid,
    pub tenant_id: i64,
    pub kind: JobEventKind,
    pub payload: Value,
    pub occurred_at: DateTime<Utc>,
    pub event_hash: String,
    pub prev_hash: Option<String>,
}

fn canonical_event_bytes(
    job_id: Uuid,
    tenant_id: i64,
    kind: JobEventKind,
    payload: &Value,
    occurred_at: &DateTime<Utc>,
    prev_hash: Option<&str>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(job_id.as_bytes());
    buf.extend_from_slice(&tenant_id.to_le_bytes());
    buf.extend_from_slice(kind.as_str().as_bytes());
    if let Ok(p) = serde_json::to_vec(payload) {
        buf.extend_from_slice(&p);
    }
    buf.extend_from_slice(occurred_at.to_rfc3339().as_bytes());
    if let Some(h) = prev_hash {
        buf.extend_from_slice(h.as_bytes());
    }
    buf
}

pub fn hash_event(
    job_id: Uuid,
    tenant_id: i64,
    kind: JobEventKind,
    payload: &Value,
    occurred_at: &DateTime<Utc>,
    prev_hash: Option<&str>,
) -> String {
    let bytes = canonical_event_bytes(job_id, tenant_id, kind, payload, occurred_at, prev_hash);
    format!("{:x}", Sha256::digest(bytes))
}

/// Append immutable event. **Never UPDATE** — forensic replay reads this table only.
pub async fn append_event(
    pool: &PgPool,
    job_id: Uuid,
    tenant_id: i64,
    kind: JobEventKind,
    payload: Value,
) -> Result<JobEventRecord, JobBusError> {
    // Serialize appends per job inside one transaction. Two concurrent producers
    // (e.g. a heartbeat's `lease_extended` racing `job_completed`) would otherwise read the
    // same `prev_hash` and insert sibling events, silently forking the tamper-evident chain.
    // A per-job advisory xact lock makes read-prev-hash + insert atomic against each other.
    let mut tx = pool.begin().await?;

    // Set tenant GUC for RLS enforcement (defense-in-depth: consistent with scoped callers).
    // Without this, an unscoped pool bypasses RLS. The INSERT below still stamped tenant_id,
    // but a crafted payload could circumvent the WHERE filter if RLS were the only gate.
    sqlx::query("SELECT set_config('app.current_tenant_id', $1::text, true)")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;

    if !job_id.is_nil() {
        // BOUNDED (weissman_db::advisory_lock) — a bare `pg_advisory_xact_lock` waits forever,
        // which under `cargo test` (pools with no lock_timeout) turned a stuck producer into a
        // wedged test binary. On timeout this returns Err, the transaction aborts and the event
        // is not appended: the chain is never forked by an unserialized append.
        weissman_db::advisory_lock::advisory_xact_lock_text(&mut tx, &job_id.to_string()).await?;
    }

    let prev_hash: Option<String> = if job_id.is_nil() {
        None
    } else {
        sqlx::query_scalar(
            r#"SELECT event_hash FROM weissman_job_events
               WHERE job_id = $1 ORDER BY seq DESC LIMIT 1"#,
        )
        .bind(job_id)
        .fetch_optional(&mut *tx)
        .await?
    };

    let occurred_at = Utc::now();
    let event_hash = hash_event(
        job_id,
        tenant_id,
        kind,
        &payload,
        &occurred_at,
        prev_hash.as_deref(),
    );

    let row = sqlx::query(
        r#"INSERT INTO weissman_job_events
             (job_id, tenant_id, kind, payload, occurred_at, event_hash, prev_hash)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING seq"#,
    )
    .bind(job_id)
    .bind(tenant_id)
    .bind(kind.as_str())
    .bind(sqlx::types::Json(payload.clone()))
    .bind(occurred_at)
    .bind(&event_hash)
    .bind(&prev_hash)
    .fetch_one(&mut *tx)
    .await?;

    let seq: i64 = row.try_get("seq")?;
    tx.commit().await?;

    Ok(JobEventRecord {
        seq,
        job_id,
        tenant_id,
        kind,
        payload,
        occurred_at,
        event_hash,
        prev_hash,
    })
}

pub async fn fetch_event_chain_hash(pool: &PgPool, job_id: Uuid) -> Result<String, JobBusError> {
    let h: Option<String> = sqlx::query_scalar(
        r#"SELECT event_hash FROM weissman_job_events
           WHERE job_id = $1 ORDER BY seq DESC LIMIT 1"#,
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await?;
    Ok(h.unwrap_or_else(|| "genesis".to_string()))
}

pub async fn xadd_event(redis: &redis::aio::ConnectionManager, record: &JobEventRecord) {
    let mut conn = redis.clone();
    let payload_str = serde_json::to_string(&record.payload).unwrap_or_else(|_| "{}".into());
    let mut cmd = redis::cmd("XADD");
    // MAXLEN ~ N: approximate capped trim so the Redis stream (best-effort fan-out; Postgres
    // is source of truth) can't grow without bound and OOM the shared Redis.
    cmd.arg(REDIS_STREAM_KEY)
        .arg("MAXLEN")
        .arg("~")
        .arg(REDIS_STREAM_MAXLEN)
        .arg("*");
    cmd.arg("seq").arg(record.seq.to_string());
    cmd.arg("job_id").arg(record.job_id.to_string());
    cmd.arg("tenant_id").arg(record.tenant_id.to_string());
    cmd.arg("kind").arg(record.kind.as_str());
    cmd.arg("event_hash").arg(&record.event_hash);
    cmd.arg("payload").arg(&payload_str);
    cmd.arg("occurred_at").arg(record.occurred_at.to_rfc3339());
    if let Err(e) = cmd.query_async::<()>(&mut conn).await {
        tracing::warn!(target: "job_bus", error = %e, "Redis XADD failed (Postgres event is source of truth)");
    }
}
