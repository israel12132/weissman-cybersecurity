//! Read-only operator view of live Redis lease + swarm keys.
//!
//! Uses the same key layout as [`crate::lease`] (`weissman:job:lease:`) and
//! [`crate::swarm`] (`weissman:swarm:worker:`). Never acquires, extends, or deletes.

use crate::swarm::redis_manager_from_env;
use redis::AsyncCommands;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

const INSPECT_TIMEOUT: Duration = Duration::from_secs(2);
const LEASE_PREFIX: &str = "weissman:job:lease:";
const SWARM_PREFIX: &str = "weissman:swarm:worker:";

/// Snapshot of one Redis job lease (GET only).
#[derive(Debug, Clone, Default, Serialize)]
pub struct LeaseView {
    pub job_id: Uuid,
    pub present: bool,
    pub ttl_secs: i64,
    pub worker_id: Option<String>,
}

/// Snapshot of one swarm liveness key (GET only).
#[derive(Debug, Clone, Default, Serialize)]
pub struct WorkerLivenessView {
    pub worker_id: String,
    pub present: bool,
    pub ttl_secs: i64,
    pub payload: Option<String>,
}

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
        let mut conn = redis_manager_from_env().await.ok_or_else(|| {
            anyhow_msg("redis connection manager unavailable")
        })?;
        let mut leases = HashMap::new();
        for job_id in job_ids {
            let key = format!("{LEASE_PREFIX}{job_id}");
            let value: Option<String> = conn.get(&key).await.unwrap_or(None);
            let ttl: i64 = conn.ttl(&key).await.unwrap_or(-2);
            let worker_id = value.as_ref().and_then(|v| v.split(':').next().map(str::to_string));
            leases.insert(
                *job_id,
                LeaseView {
                    job_id: *job_id,
                    present: value.is_some(),
                    ttl_secs: ttl,
                    worker_id,
                },
            );
        }
        let mut workers = HashMap::new();
        for worker_id in worker_ids {
            let key = format!("{SWARM_PREFIX}{worker_id}");
            let payload: Option<String> = conn.get(&key).await.unwrap_or(None);
            let ttl: i64 = conn.ttl(&key).await.unwrap_or(-2);
            workers.insert(
                worker_id.clone(),
                WorkerLivenessView {
                    worker_id: worker_id.clone(),
                    present: payload.is_some(),
                    ttl_secs: ttl,
                    payload,
                },
            );
        }
        Ok::<_, String>((leases, workers))
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

/// Live census of swarm liveness keys (`weissman:swarm:worker:*`). SCAN only — never KEYS.
#[derive(Debug, Clone, Default, Serialize)]
pub struct LiveSwarmCensus {
    pub redis_configured: bool,
    pub inspect_ok: bool,
    pub workers: Vec<WorkerLivenessView>,
}

/// Enumerate currently registered workers from Redis. Fail-open (empty + inspect_ok=false)
/// when Redis is unset, unreachable, or slow — never invent a live fleet.
pub async fn inspect_swarm_census() -> LiveSwarmCensus {
    let redis_configured = redis_url_configured();
    if !redis_configured {
        return LiveSwarmCensus {
            redis_configured: false,
            inspect_ok: false,
            workers: Vec::new(),
        };
    }
    let fut = async {
        let mut conn = redis_manager_from_env()
            .await
            .ok_or_else(|| anyhow_msg("redis connection manager unavailable"))?;
        let mut keys: Vec<String> = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{SWARM_PREFIX}*"))
                .arg("COUNT")
                .arg(100i64)
                .query_async(&mut conn)
                .await
                .map_err(|e| e.to_string())?;
            keys.extend(batch);
            cursor = next;
            if cursor == 0 || keys.len() >= 2048 {
                break;
            }
        }
        let mut workers = Vec::with_capacity(keys.len());
        for key in keys {
            let worker_id = key
                .strip_prefix(SWARM_PREFIX)
                .unwrap_or(key.as_str())
                .to_string();
            if worker_id.is_empty() {
                continue;
            }
            let payload: Option<String> = conn.get(&key).await.unwrap_or(None);
            let ttl: i64 = conn.ttl(&key).await.unwrap_or(-2);
            workers.push(WorkerLivenessView {
                worker_id,
                present: payload.is_some(),
                ttl_secs: ttl,
                payload,
            });
        }
        Ok::<_, String>(workers)
    };
    match tokio::time::timeout(INSPECT_TIMEOUT, fut).await {
        Ok(Ok(workers)) => LiveSwarmCensus {
            redis_configured: true,
            inspect_ok: true,
            workers,
        },
        Ok(Err(e)) => {
            tracing::warn!(target: "job_bus_inspect", error = %e, "swarm census failed");
            LiveSwarmCensus {
                redis_configured: true,
                inspect_ok: false,
                workers: Vec::new(),
            }
        }
        Err(_) => {
            tracing::warn!(target: "job_bus_inspect", "swarm census timed out");
            LiveSwarmCensus {
                redis_configured: true,
                inspect_ok: false,
                workers: Vec::new(),
            }
        }
    }
}

fn anyhow_msg(msg: impl Into<String>) -> String {
    msg.into()
}
