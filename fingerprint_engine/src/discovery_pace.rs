//! Adaptive discovery pacing: slow down or rotate identity when the target WAF bites.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use weissman_engines::stealth::{self, StealthConfig};

const MIN_SAMPLES: u64 = 20;
const FAIL_RATE_TRIP: f64 = 0.10;
const WAF_STREAK_TRIP: u32 = 3;
const MAX_DELAY_MS: u64 = 2_500;

/// Live probe budget that decelerates on connection errors and 403/429 streaks.
pub struct DiscoveryPace {
    attempts: AtomicU64,
    failures: AtomicU64,
    waf_streak: AtomicU32,
    delay_ms: AtomicU64,
    concurrency: AtomicUsize,
    decelerating: AtomicBool,
    just_tripped: AtomicBool,
}

impl DiscoveryPace {
    #[must_use]
    pub fn new(initial_concurrency: usize) -> Self {
        Self {
            attempts: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            waf_streak: AtomicU32::new(0),
            delay_ms: AtomicU64::new(0),
            concurrency: AtomicUsize::new(initial_concurrency.max(2)),
            decelerating: AtomicBool::new(false),
            just_tripped: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn concurrency(&self) -> usize {
        self.concurrency.load(Ordering::Relaxed).max(2)
    }

    #[must_use]
    pub fn is_decelerating(&self) -> bool {
        self.decelerating.load(Ordering::Relaxed)
    }

    /// True once when the trip fires; callers apply ghost/proxy rotation.
    pub fn take_trip(&self) -> bool {
        self.just_tripped.swap(false, Ordering::SeqCst)
    }

    pub fn observe_connect_error(&self) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.waf_streak.fetch_add(1, Ordering::Relaxed);
        self.recompute(true);
    }

    pub fn observe_status(&self, status: u16) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        let waf = matches!(status, 403 | 429 | 503);
        if waf {
            self.waf_streak.fetch_add(1, Ordering::Relaxed);
        } else {
            self.waf_streak.store(0, Ordering::Relaxed);
        }
        self.recompute(waf);
    }

    fn recompute(&self, worsen: bool) {
        let attempts = self.attempts.load(Ordering::Relaxed);
        let failures = self.failures.load(Ordering::Relaxed);
        let streak = self.waf_streak.load(Ordering::Relaxed);
        let fail_rate = if attempts == 0 {
            0.0
        } else {
            failures as f64 / attempts as f64
        };
        let trip =
            (attempts >= MIN_SAMPLES && fail_rate > FAIL_RATE_TRIP) || streak >= WAF_STREAK_TRIP;
        if !trip {
            return;
        }
        let was = self.decelerating.swap(true, Ordering::SeqCst);
        if !was {
            self.just_tripped.store(true, Ordering::SeqCst);
            self.apply_slowdown();
        } else if worsen {
            self.apply_slowdown();
        }
    }

    fn apply_slowdown(&self) {
        let cur = self.concurrency.load(Ordering::Relaxed);
        let next = (cur / 2).max(2);
        self.concurrency.store(next, Ordering::Relaxed);
        let delay = self
            .delay_ms
            .load(Ordering::Relaxed)
            .max(200)
            .saturating_mul(2);
        self.delay_ms
            .store(delay.min(MAX_DELAY_MS), Ordering::Relaxed);
    }

    pub async fn before_probe(&self, stealth: Option<&StealthConfig>) {
        let extra = self.delay_ms.load(Ordering::Relaxed);
        if extra > 0 {
            tokio::time::sleep(Duration::from_millis(extra)).await;
        }
        if let Some(s) = stealth {
            stealth::apply_jitter(s).await;
            if self.is_decelerating() {
                stealth::apply_rotation_delay(s).await;
            }
        }
    }
}

/// Load the configured proxy swarm (empty when unset).
#[must_use]
pub fn proxy_swarm_from_env() -> Vec<String> {
    std::env::var("WEISSMAN_PROXY_SWARM")
        .ok()
        .map(|s| StealthConfig::parse_proxy_swarm(&s))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_on_waf_streak() {
        let p = DiscoveryPace::new(32);
        p.observe_status(403);
        p.observe_status(429);
        p.observe_status(403);
        assert!(p.is_decelerating());
        assert!(p.take_trip());
        assert!(!p.take_trip());
        assert!(p.concurrency() < 32);
    }

    #[test]
    fn trips_on_fail_rate_after_min_samples() {
        let p = DiscoveryPace::new(16);
        for _ in 0..18 {
            p.observe_status(200);
        }
        for _ in 0..5 {
            p.observe_connect_error();
        }
        assert!(p.is_decelerating());
    }

    #[test]
    fn quiet_success_does_not_trip() {
        let p = DiscoveryPace::new(32);
        for _ in 0..40 {
            p.observe_status(200);
        }
        assert!(!p.is_decelerating());
        assert_eq!(p.concurrency(), 32);
    }
}
