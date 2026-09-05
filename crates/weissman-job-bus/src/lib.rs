//! Zero-trust distributed job orchestration for Weissman Red Team platform.
//!
//! - **Event sourcing (CQRS):** append-only [`JobEvent`] log in Postgres + Redis Streams fan-out.
//! - **Cryptographic claims:** HMAC-signed job envelopes; workers verify before execution.
//! - **Distributed leases:** Redis NX locks with cryptographic claim tokens (Redlock-style).
//! - **Swarm liveness:** sub-second worker registry TTL + instant orphan detection.
//! - **Forensic DLQ:** sealed failure bundles with stack traces and memory snapshots.

#![forbid(unsafe_code)]

mod cqrs;
mod error;
mod events;
mod forensic;
pub mod keepalive;
mod lease;
pub mod live_inspect;
mod signing;
mod swarm;

pub use cqrs::project_event;
pub use error::JobBusError;
pub use events::{append_event, fetch_event_chain_hash, JobEventKind, JobEventRecord};
pub use forensic::{enqueue_forensic_dlq, ForensicBundle, MemorySnapshot};
pub use lease::{DistributedLease, LeaseHandle};
pub use live_inspect::{
    inspect_orchestration, inspect_swarm_census, redis_url_configured, LeaseView,
    LiveOrchestrationView, LiveSwarmCensus, WorkerLivenessView,
};
pub use signing::{
    forensic_seal_key_from_env, sign_job_envelope, verify_job_envelope, SignedJobEnvelope,
};
pub use swarm::{spawn_coordinator_if_enabled, SwarmCoordinator, WorkerSwarm};

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

/// Facade over the military-grade job bus. Gracefully degrades when Redis/secret unset.
pub struct JobBus {
    pool: PgPool,
    redis: Option<redis::aio::ConnectionManager>,
    signing_key: Option<Vec<u8>>,
}

impl JobBus {
    /// Build from environment: `REDIS_URL`, `WEISSMAN_JOB_ORCHESTRATOR_SECRET`.
    pub async fn from_env(pool: PgPool) -> Self {
        let redis = swarm::redis_manager_from_env().await;
        let signing_key = signing::orchestrator_key_from_env();
        Self {
            pool,
            redis,
            signing_key,
        }
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.redis.is_some() && self.signing_key.is_some()
    }

    /// Orchestrator dispatch: sign envelope + append `JobDispatched` + Redis stream.
    pub async fn on_job_dispatched(
        &self,
        job_id: Uuid,
        tenant_id: i64,
        kind: &str,
        payload: &Value,
        trace_id: Option<&str>,
    ) -> Result<Option<SignedJobEnvelope>, JobBusError> {
        let envelope = if let Some(key) = self.signing_key.as_ref() {
            Some(sign_job_envelope(key, job_id, tenant_id, kind, payload)?)
        } else {
            None
        };

        let mut event_payload = json!({
            "kind": kind,
            "trace_id": trace_id,
            "signed": envelope.is_some(),
        });
        if let Some(ref env) = envelope {
            event_payload["envelope_digest"] = json!(env.content_digest());
            event_payload["signature"] = json!(env.signature);
            event_payload["nonce"] = json!(env.nonce);
            event_payload["issued_at"] = json!(env.issued_at);
        }

        let record = append_event(
            &self.pool,
            job_id,
            tenant_id,
            JobEventKind::JobDispatched,
            event_payload,
        )
        .await?;
        project_event(&self.pool, &record).await?;
        self.publish_stream(&record).await;
        Ok(envelope)
    }

    /// Worker claim: verify signature, acquire lease, append events.
    pub async fn on_worker_claimed(
        &self,
        job_id: Uuid,
        tenant_id: i64,
        worker_id: &str,
        signed_envelope: Option<&SignedJobEnvelope>,
        lock_secs: i64,
    ) -> Result<Option<LeaseHandle>, JobBusError> {
        if let Some(key) = self.signing_key.as_ref() {
            let env = signed_envelope.ok_or_else(|| {
                JobBusError::SignatureMismatch(
                    "missing signed envelope — zero-trust claim rejected".into(),
                )
            })?;
            verify_job_envelope(key, env)?;
            if env.job_id != job_id {
                return Err(JobBusError::SignatureMismatch(
                    "envelope job_id mismatch".into(),
                ));
            }
            // The HMAC binds tenant_id; enforce it so a claim under a different tenant than the
            // envelope was signed for cannot mis-attribute the tamper-evident event chain.
            if env.tenant_id != tenant_id {
                return Err(JobBusError::SignatureMismatch(
                    "envelope tenant_id mismatch".into(),
                ));
            }
        } else if self.redis.is_some() {
            return Err(JobBusError::Signing(
                "job bus Redis enabled but orchestrator signing key missing".into(),
            ));
        }

        let claim_token = lease::new_claim_token();
        let lease = if let Some(ref redis) = self.redis {
            let lease = DistributedLease::acquire(
                redis.clone(),
                job_id,
                worker_id,
                &claim_token,
                lock_secs,
            )
            .await?;
            Some(lease)
        } else {
            None
        };

        let record = append_event(
            &self.pool,
            job_id,
            tenant_id,
            JobEventKind::WorkerClaimed,
            json!({
                "worker_id": worker_id,
                "claim_token_prefix": &claim_token[..8],
                "lease_acquired": lease.is_some(),
            }),
        )
        .await?;
        project_event(&self.pool, &record).await?;
        self.publish_stream(&record).await;

        if lease.is_some() {
            let lease_rec = append_event(
                &self.pool,
                job_id,
                tenant_id,
                JobEventKind::LeaseAcquired,
                json!({ "worker_id": worker_id, "lock_secs": lock_secs }),
            )
            .await?;
            project_event(&self.pool, &lease_rec).await?;
            self.publish_stream(&lease_rec).await;
        }

        Ok(lease)
    }

    /// Execution started (exploit fired).
    pub async fn on_exploit_fired(
        &self,
        job_id: Uuid,
        tenant_id: i64,
        worker_id: &str,
        kind: &str,
    ) -> Result<(), JobBusError> {
        let record = append_event(
            &self.pool,
            job_id,
            tenant_id,
            JobEventKind::ExploitFired,
            json!({ "worker_id": worker_id, "job_kind": kind }),
        )
        .await?;
        project_event(&self.pool, &record).await?;
        self.publish_stream(&record).await;
        Ok(())
    }

    /// Extend distributed lease + append `LeaseExtended` event.
    pub async fn on_lease_extended(
        &self,
        job_id: Uuid,
        tenant_id: i64,
        lease: &LeaseHandle,
        lock_secs: i64,
    ) -> Result<(), JobBusError> {
        lease.extend(lock_secs).await?;
        let record = append_event(
            &self.pool,
            job_id,
            tenant_id,
            JobEventKind::LeaseExtended,
            json!({ "worker_id": lease.worker_id(), "lock_secs": lock_secs }),
        )
        .await?;
        // Project the LeaseExtended event so `weissman_async_jobs.locked_until` is actually
        // pushed forward. Without this the read-model lock is frozen at claim+lock_secs and the
        // reclaim sweep re-queues every job that runs longer than one lease window, causing
        // duplicate execution. Every other `on_*` handler projects its event.
        project_event(&self.pool, &record).await?;
        self.publish_stream(&record).await;
        Ok(())
    }

    pub async fn on_job_completed(
        &self,
        job_id: Uuid,
        tenant_id: i64,
        worker_id: &str,
        result: &Value,
        lease: Option<LeaseHandle>,
    ) -> Result<(), JobBusError> {
        if let Some(l) = lease {
            let _ = l.release().await;
        }
        let record = append_event(
            &self.pool,
            job_id,
            tenant_id,
            JobEventKind::JobCompleted,
            json!({ "worker_id": worker_id, "result": result }),
        )
        .await?;
        project_event(&self.pool, &record).await?;
        self.publish_stream(&record).await;
        Ok(())
    }

    pub async fn on_job_failed(
        &self,
        job_id: Uuid,
        tenant_id: i64,
        worker_id: &str,
        error: &str,
        retry: bool,
        lease: Option<LeaseHandle>,
    ) -> Result<(), JobBusError> {
        if let Some(l) = lease {
            let _ = l.release().await;
        }
        let kind = if retry {
            JobEventKind::JobRetryScheduled
        } else {
            JobEventKind::JobFailed
        };
        let record = append_event(
            &self.pool,
            job_id,
            tenant_id,
            kind,
            json!({ "worker_id": worker_id, "error": error, "retry": retry }),
        )
        .await?;
        project_event(&self.pool, &record).await?;
        self.publish_stream(&record).await;
        Ok(())
    }

    /// Forensic DLQ: sealed bundle + immutable events. No bare `status=dead` UPDATE.
    pub async fn on_forensic_dlq(
        &self,
        bundle: ForensicBundle,
        lease: Option<LeaseHandle>,
    ) -> Result<Uuid, JobBusError> {
        if let Some(l) = lease {
            let _ = l.release().await;
        }
        // Re-seal with the SAME dedicated forensic-key resolution the worker used to build the
        // bundle — not `self.signing_key` (the orchestrator key). Using two different keys
        // guaranteed a "bundle seal mismatch" whenever WEISSMAN_FORENSIC_SEAL_SECRET was set (the
        // documented config), which left the exhausted job stuck `running` and looping forever.
        let forensic_key = crate::signing::forensic_seal_key_from_env();
        let dlq_id = enqueue_forensic_dlq(&self.pool, &bundle, forensic_key.as_deref()).await?;
        let record = append_event(
            &self.pool,
            bundle.job_id,
            bundle.tenant_id,
            JobEventKind::ForensicDlqEnqueued,
            json!({
                "dlq_id": dlq_id,
                "worker_id": bundle.worker_id,
                "failure_class": bundle.failure_class,
                "bundle_seal": bundle.bundle_seal,
            }),
        )
        .await?;
        project_event(&self.pool, &record).await?;
        self.publish_stream(&record).await;
        Ok(dlq_id)
    }

    pub async fn on_worker_terminated(
        &self,
        tenant_id: i64,
        worker_id: &str,
        reason: &str,
    ) -> Result<(), JobBusError> {
        // tenant_id must be a real tenant: weissman_job_events.tenant_id is a NOT NULL
        // FK to tenants(id). The prior hardcoded 0 sentinel violated that FK on every
        // worker-liveness expiry, which aborted the swarm coordinator's tick before it
        // could orphan/requeue the stalled job (see swarm.rs) — so the job was retried
        // forever. The caller already holds the affected job's tenant; thread it in.
        let record = append_event(
            &self.pool,
            Uuid::nil(),
            tenant_id,
            JobEventKind::WorkerTerminated,
            json!({ "worker_id": worker_id, "reason": reason }),
        )
        .await?;
        self.publish_stream(&record).await;
        Ok(())
    }

    pub async fn on_job_orphaned(
        &self,
        job_id: Uuid,
        tenant_id: i64,
        worker_id: &str,
        reason: &str,
    ) -> Result<(), JobBusError> {
        let record = append_event(
            &self.pool,
            job_id,
            tenant_id,
            JobEventKind::JobOrphaned,
            json!({ "worker_id": worker_id, "reason": reason }),
        )
        .await?;
        project_event(&self.pool, &record).await?;
        self.publish_stream(&record).await;
        Ok(())
    }

    async fn publish_stream(&self, record: &JobEventRecord) {
        if let Some(ref redis) = self.redis {
            events::xadd_event(redis, record).await;
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn redis(&self) -> Option<&redis::aio::ConnectionManager> {
        self.redis.as_ref()
    }
}
