//! Per-tenant **governance rate-limit** for autonomous auto-heal actions.
//!
//! The auto-heal subsystem can generate a patch, verify it in an ephemeral container, and
//! open a pull request — fully autonomously. Triggered without bound (a noisy scanner, a
//! retry storm, a compromised trigger) it could **flood a tenant's repository with heal PRs**
//! and **burn LLM budget**. This module caps how many heals a single tenant may *start* within
//! a rolling window, so the blast radius of a runaway is bounded.
//!
//! It is an **in-memory, per-replica** sliding window (like the LLM circuit breaker) — cheap
//! and dependency-free. A durable cross-replica budget (Postgres-counted) is a follow-up; the
//! API here is small enough to swap. Fail-open on lock poisoning: governance must never wedge
//! the heal path shut on an internal error.
//!
//! Config: `WEISSMAN_HEAL_MAX_PER_HOUR` (default 20). Window is one hour.

use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Default heals allowed per tenant per window when `WEISSMAN_HEAL_MAX_PER_HOUR` is unset.
const DEFAULT_MAX_PER_WINDOW: u32 = 20;
/// Rolling window length (one hour).
const WINDOW: Duration = Duration::from_secs(3600);

/// Recorded heal-start timestamps for one tenant.
struct TenantWindow {
    starts: Vec<Instant>,
}

fn state() -> &'static DashMap<i64, TenantWindow> {
    static S: OnceLock<DashMap<i64, TenantWindow>> = OnceLock::new();
    S.get_or_init(DashMap::new)
}

fn max_per_window() -> u32 {
    std::env::var("WEISSMAN_HEAL_MAX_PER_HOUR")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MAX_PER_WINDOW)
}

/// Outcome of a rate-limit check.
pub struct HealRateDecision {
    /// True when the heal may proceed (and was recorded).
    pub allowed: bool,
    /// Heals used in the current window (including this one if allowed).
    pub used: u32,
    /// The configured per-window limit.
    pub limit: u32,
}

/// Check whether `tenant_id` may start another heal now; if allowed, record the start.
/// Per-replica in-memory sliding window over the last hour.
#[must_use]
pub fn check_and_record(tenant_id: i64) -> HealRateDecision {
    let mut entry = state()
        .entry(tenant_id)
        .or_insert_with(|| TenantWindow { starts: Vec::new() });
    decide_window(entry.value_mut(), Instant::now(), max_per_window(), WINDOW)
}

/// Pure core (time/limit/window injected, operates on a supplied map) so the sliding-window
/// semantics are unit-tested without touching the process-global state or the wall clock.
fn decide(
    map: &mut HashMap<i64, TenantWindow>,
    tenant_id: i64,
    now: Instant,
    limit: u32,
    window: Duration,
) -> HealRateDecision {
    let w = map
        .entry(tenant_id)
        .or_insert_with(|| TenantWindow { starts: Vec::new() });
    decide_window(w, now, limit, window)
}

fn decide_window(
    w: &mut TenantWindow,
    now: Instant,
    limit: u32,
    window: Duration,
) -> HealRateDecision {
    // Drop starts that have aged out of the window.
    let cutoff = now.checked_sub(window);
    w.starts.retain(|&t| cutoff.is_none_or(|c| t >= c));
    let used = w.starts.len() as u32;
    if used >= limit {
        return HealRateDecision {
            allowed: false,
            used,
            limit,
        };
    }
    w.starts.push(now);
    HealRateDecision {
        allowed: true,
        used: used + 1,
        limit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_limit_then_throttles() {
        let mut map = HashMap::new();
        let now = Instant::now();
        for i in 1..=3 {
            let d = decide(&mut map, 1, now, 3, WINDOW);
            assert!(d.allowed, "call {i} should be allowed");
            assert_eq!(d.used, i);
            assert_eq!(d.limit, 3);
        }
        let denied = decide(&mut map, 1, now, 3, WINDOW);
        assert!(!denied.allowed, "4th within window must be throttled");
        assert_eq!(denied.used, 3);
    }

    #[test]
    fn window_slides_and_reallows_after_expiry() {
        let mut map = HashMap::new();
        let base = Instant::now();
        let window = Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(decide(&mut map, 7, base, 3, window).allowed);
        }
        assert!(!decide(&mut map, 7, base, 3, window).allowed, "at limit");
        // Advance past the window: the three early starts age out, so a heal is allowed again.
        let later = base + window + Duration::from_secs(1);
        let d = decide(&mut map, 7, later, 3, window);
        assert!(
            d.allowed,
            "after the window slides, heals are allowed again"
        );
        assert_eq!(d.used, 1);
    }

    #[test]
    fn tenants_are_isolated() {
        let mut map = HashMap::new();
        let now = Instant::now();
        // Tenant 1 exhausts its budget.
        for _ in 0..2 {
            assert!(decide(&mut map, 1, now, 2, WINDOW).allowed);
        }
        assert!(!decide(&mut map, 1, now, 2, WINDOW).allowed);
        // Tenant 2 is unaffected.
        assert!(decide(&mut map, 2, now, 2, WINDOW).allowed);
    }
}
