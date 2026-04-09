//! Limits concurrent full-platform scan cycles so the DB pool and CPU are not saturated by overlapping orchestrator runs.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

fn max_concurrent_full_scans() -> usize {
    std::env::var("WEISSMAN_MAX_CONCURRENT_FULL_SCANS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2)
        .max(1)
}

fn queue_wait_secs() -> u64 {
    std::env::var("WEISSMAN_SCAN_QUEUE_WAIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120)
        .max(5)
}

fn semaphore() -> Arc<Semaphore> {
    static SEM: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(max_concurrent_full_scans())))
        .clone()
}

/// Non-blocking acquire for the background orchestrator tick (skips the cycle if all slots busy).
pub fn try_acquire_full_scan_permit() -> Option<OwnedSemaphorePermit> {
    semaphore().try_acquire_owned().ok()
}

/// Waits up to `WEISSMAN_SCAN_QUEUE_WAIT_SECS` for a slot to run a full scan job (API-triggered scans).
pub async fn acquire_full_scan_permit() -> Result<OwnedSemaphorePermit, ()> {
    let wait = Duration::from_secs(queue_wait_secs());
    match tokio::time::timeout(wait, semaphore().acquire_owned()).await {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(_)) => Err(()),
        Err(_) => {
            metrics::counter!("weissman_scan_acquire_timeout_total").increment(1);
            Err(())
        }
    }
}
