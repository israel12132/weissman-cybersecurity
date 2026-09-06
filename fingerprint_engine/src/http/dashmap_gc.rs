//! Periodic eviction for process-local DashMaps (AI quotas, lockout, heal windows, …).
//!
//! Sharded maps avoid a global `Mutex<HashMap>`, but keys still accumulate across months
//! of uptime (disconnected tenants, rolled UTC days, expired lockouts). One sweeper
//! drops stale entries so RSS does not creep.

use std::time::Duration;

/// Default sweep interval (15 minutes). `WEISSMAN_DASHMAP_EVICT_SECS=0` disables.
const DEFAULT_EVICT_SECS: u64 = 900;

fn evict_interval() -> Option<Duration> {
    match std::env::var("WEISSMAN_DASHMAP_EVICT_SECS") {
        Ok(s) => {
            let n: u64 = s.trim().parse().ok()?;
            if n == 0 {
                None
            } else {
                Some(Duration::from_secs(n.clamp(30, 24 * 3600)))
            }
        }
        Err(_) => Some(Duration::from_secs(DEFAULT_EVICT_SECS)),
    }
}

/// Drop stale keys from every hot in-process DashMap. Returns how many entries left.
pub fn sweep_once() -> usize {
    let mut dropped = 0usize;
    dropped = dropped.saturating_add(crate::http::ai_quota_mem::evict_stale());
    dropped = dropped.saturating_add(crate::heal_rate_limit::evict_stale());
    dropped = dropped.saturating_add(crate::http::login_lockout::evict_stale());
    if dropped > 0 {
        tracing::info!(target: "dashmap_gc", dropped, "evicted stale in-process DashMap keys");
    }
    dropped
}

/// Background eviction. No-op when `WEISSMAN_DASHMAP_EVICT_SECS=0`.
pub fn spawn_eviction_loop() {
    let Some(period) = evict_interval() else {
        tracing::info!(target: "dashmap_gc", "DashMap eviction disabled (WEISSMAN_DASHMAP_EVICT_SECS=0)");
        return;
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let _ = sweep_once();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_is_safe_on_empty_maps() {
        let _ = sweep_once();
    }
}
