//! Sharded in-memory daily AI token counters (DashMap).
//!
//! Durable metering is Postgres (`tenant_llm_usage`). This map is the hot-path
//! process-local view used to avoid a global `Mutex<HashMap>` on every LLM
//! completion. Keys expire lazily when the UTC day rolls.

use chrono::Datelike;
use dashmap::DashMap;
use std::sync::OnceLock;

fn store() -> &'static DashMap<(i64, u32), u64> {
    static S: OnceLock<DashMap<(i64, u32), u64>> = OnceLock::new();
    S.get_or_init(DashMap::new)
}

fn utc_yyyymmdd() -> u32 {
    let n = chrono::Utc::now().date_naive();
    let y = u32::try_from(n.year()).unwrap_or(0);
    y.saturating_mul(10_000)
        .saturating_add(u32::from(n.month()))
        .saturating_mul(100)
        .saturating_add(u32::from(n.day()))
}

/// Add prompt+completion tokens for `tenant_id` (today, UTC). Returns the new daily total.
pub fn add_usage(tenant_id: i64, prompt_tokens: u32, completion_tokens: u32) -> u64 {
    let day = utc_yyyymmdd();
    let add = u64::from(prompt_tokens).saturating_add(u64::from(completion_tokens));
    let mut entry = store().entry((tenant_id, day)).or_insert(0);
    *entry = entry.saturating_add(add);
    *entry
}

/// Tokens recorded in this process for `tenant_id` today (UTC). `0` if none.
#[must_use]
pub fn used_today(tenant_id: i64) -> u64 {
    let day = utc_yyyymmdd();
    store().get(&(tenant_id, day)).map(|v| *v).unwrap_or(0)
}

/// Drop counters whose UTC day is before `today`. Returns the number of keys removed.
pub fn evict_before_day(today: u32) -> usize {
    let mut dropped = 0usize;
    store().retain(|(_, day), _| {
        if *day < today {
            dropped += 1;
            false
        } else {
            true
        }
    });
    dropped
}

/// Drop counters from previous UTC days.
pub fn evict_stale() -> usize {
    evict_before_day(utc_yyyymmdd())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increments_are_visible() {
        let tenant = 9_001_337_i64;
        let before = used_today(tenant);
        let after = add_usage(tenant, 10, 5);
        assert_eq!(after, before + 15);
        assert_eq!(used_today(tenant), after);
    }

    #[test]
    fn tenants_do_not_share_counters() {
        let a = add_usage(9_001_338, 1, 0);
        let b = add_usage(9_001_339, 1, 0);
        assert!(a >= 1 && b >= 1);
        // Isolated keys: bumping B must not change A's stored value beyond its own add.
        let a2 = used_today(9_001_338);
        let _ = add_usage(9_001_339, 100, 0);
        assert_eq!(used_today(9_001_338), a2);
    }

    #[test]
    fn evicts_previous_utc_days() {
        store().insert((9_001_340, 19990101), 7);
        store().insert((9_001_340, utc_yyyymmdd()), 3);
        let n = evict_before_day(utc_yyyymmdd());
        assert!(n >= 1);
        assert_eq!(used_today(9_001_340), 3);
        assert!(store().get(&(9_001_340, 19990101)).is_none());
    }
}
