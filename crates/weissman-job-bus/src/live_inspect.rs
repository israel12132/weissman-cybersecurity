//! Read-only operator view of live Redis lease + swarm keys.
//!
//! Consumes the same key layout as [`crate::lease::DistributedLease`] and the swarm
//! registry. Never acquires, extends, releases, or orphans.

use crate::error::JobBusError;
use crate::lease::{DistributedLease, LeaseView};
use crate::swarm::{inspect_workers, shared_redis, WorkerLivenessView};
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

const INSPECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Combined live orchestration snapshot for a batch of jobs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LiveOrchestrationView {
    pub redis_configured: bool,
    pub inspect_ok: bool,
    pub leases: HashMap<Uuid, LeaseView>,
    pub workers: HashMap<String, WorkerLivenessView>,
}

#[must_use]
pub fn redis_url_configured() -> bool {
    std::env::var("REDIS_URL")
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
}

/// Inspect live Redis leases and swarm liveness for the given jobs/workers.
///
/// Returns `inspect_ok = false` (and empty maps) when Redis is unset, unreachable, or slow.
/// Callers must not treat a failed inspect as "lease missing".
pub async fn inspect_orchestration(
    job_ids: &[Uuid],
    worker_ids: &[String],
) -> LiveOrchestrationView {
    let redis_configured = redis_url_configured();
    if !redis_configured {
        return LiveOrchestrationView {
            redis_configured: false,
            inspect_ok: false,
            leases: HashMap::new(),
            workers: HashMap::new(),
        };
    }
    let fut = async {
        let mut conn = shared_redis().await.ok_or(JobBusError::Redis(
            "redis connection manager unavailable".into(),
        ))?;
        let leases = DistributedLease::inspect_many(&mut conn, job_ids).await?;
        let workers = inspect_workers(&mut conn, worker_ids).await?;
        Ok::<_, JobBusError>((leases, workers))
    };
    match tokio::time::timeout(INSPECT_TIMEOUT, fut).await {
        Ok(Ok((leases, workers))) => LiveOrchestrationView {
            redis_configured: true,
            inspect_ok: true,
            leases,
            workers,
        },
        Ok(Err(e)) => {
            tracing::warn!(target: "job_bus_inspect", error = %e, "live lease/swarm inspect failed");
            LiveOrchestrationView {
                redis_configured: true,
                inspect_ok: false,
                leases: HashMap::new(),
                workers: HashMap::new(),
            }
        }
        Err(_) => {
            tracing::warn!(target: "job_bus_inspect", "live lease/swarm inspect timed out");
            LiveOrchestrationView {
                redis_configured: true,
                inspect_ok: false,
                leases: HashMap::new(),
                workers: HashMap::new(),
            }
        }
    }
}
