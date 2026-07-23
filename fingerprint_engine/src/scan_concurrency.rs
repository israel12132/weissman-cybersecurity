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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_concurrent_clamps_to_at_least_one() {
        let k = "WEISSMAN_MAX_CONCURRENT_FULL_SCANS";
        std::env::remove_var(k);
        assert_eq!(max_concurrent_full_scans(), 2); // default
        std::env::set_var(k, "0");
        assert_eq!(max_concurrent_full_scans(), 1); // clamped up to 1
        std::env::set_var(k, "8");
        assert_eq!(max_concurrent_full_scans(), 8);
        std::env::set_var(k, "junk");
        assert_eq!(max_concurrent_full_scans(), 2); // parse failure -> default
        std::env::remove_var(k);
    }

    #[test]
    fn queue_wait_clamps_to_floor() {
        let k = "WEISSMAN_SCAN_QUEUE_WAIT_SECS";
        std::env::remove_var(k);
        assert_eq!(queue_wait_secs(), 120); // default
        std::env::set_var(k, "1");
        assert_eq!(queue_wait_secs(), 5); // floor of 5
        std::env::set_var(k, "300");
        assert_eq!(queue_wait_secs(), 300);
        std::env::remove_var(k);
    }

    #[test]
    fn try_acquire_returns_permit_when_slot_free() {
        // Default provides >= 1 slot, so a first non-blocking acquire succeeds.
        let permit = try_acquire_full_scan_permit();
        assert!(permit.is_some());
    }
}
