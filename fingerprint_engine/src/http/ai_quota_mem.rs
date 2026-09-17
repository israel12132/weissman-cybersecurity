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

// --- Pre-call per-tenant daily TOKEN budget gate (OWASP LLM04/LLM10) ---
//
// Cost is metered durably (`tenant_llm_usage`) and mirrored here in-process
// (`used_today`), but historically nothing *blocked* a tenant-scoped AI-heavy LLM
// call once a daily token budget was blown. These helpers add that pre-call gate.
// Enforcement is opt-in and fails OPEN by default: a budget of `0` (the default when
// neither `system_configs` nor the env override is set) means "unlimited", which
// preserves the platform's historical behavior exactly.

/// Env var naming the default per-tenant daily LLM token budget. `0` / unset = unlimited.
pub const DAILY_TOKEN_BUDGET_ENV: &str = "WEISSMAN_LLM_DAILY_TOKEN_BUDGET";

/// Default per-tenant daily token budget from the environment.
/// `0` (also the value for unset/unparseable) means unlimited — no enforcement.
#[must_use]
pub fn daily_token_budget_env_default() -> u64 {
    std::env::var(DAILY_TOKEN_BUDGET_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Resolve the effective daily token budget: an explicit per-tenant budget (e.g. a
/// `system_configs` value) wins when `> 0`; otherwise the env default. `0` = unlimited.
#[must_use]
pub fn resolve_daily_token_budget(configured: Option<u64>) -> u64 {
    match configured {
        Some(b) if b > 0 => b,
        _ => daily_token_budget_env_default(),
    }
}

/// Typed outcome of a pre-call budget check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaError {
    /// The tenant's per-day LLM token budget is already met or exceeded.
    DailyTokenBudgetExceeded {
        tenant_id: i64,
        used: u64,
        budget: u64,
    },
}

impl std::fmt::Display for QuotaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuotaError::DailyTokenBudgetExceeded {
                tenant_id,
                used,
                budget,
            } => write!(
                f,
                "tenant {tenant_id} daily LLM token budget exceeded: {used}/{budget} tokens used today (UTC)"
            ),
        }
    }
}

impl std::error::Error for QuotaError {}

/// Pre-call gate: deny a tenant-scoped, AI-heavy LLM call when today's in-process
/// token usage (`used_today`) has reached `budget`. `budget == 0` disables enforcement
/// (unlimited) and always returns `Ok(())`, preserving historical behavior.
pub fn check_daily_token_budget(tenant_id: i64, budget: u64) -> Result<(), QuotaError> {
    if budget == 0 {
        return Ok(());
    }
    let used = used_today(tenant_id);
    if used >= budget {
        return Err(QuotaError::DailyTokenBudgetExceeded {
            tenant_id,
            used,
            budget,
        });
    }
    Ok(())
}

/// Convenience: resolve the effective budget (per-tenant override or env default) and
/// enforce it in one call. Call this BEFORE issuing a tenant-scoped AI-heavy LLM request.
pub fn enforce_daily_token_budget(
    tenant_id: i64,
    configured: Option<u64>,
) -> Result<(), QuotaError> {
    check_daily_token_budget(tenant_id, resolve_daily_token_budget(configured))
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

    #[test]
    fn zero_budget_is_unlimited() {
        // Default (budget 0 / unset) preserves historical behavior: never blocks.
        let tenant = 9_001_341_i64;
        let _ = add_usage(tenant, 1_000_000, 1_000_000);
        assert!(check_daily_token_budget(tenant, 0).is_ok());
        // `enforce` with no per-tenant override falls back to the env default; only assert the
        // unlimited outcome when the env default is itself unlimited (keeps the test hermetic).
        if daily_token_budget_env_default() == 0 {
            assert!(enforce_daily_token_budget(tenant, None).is_ok());
        }
    }

    #[test]
    fn budget_blocks_once_used_reaches_it() {
        let tenant = 9_001_342_i64;
        assert!(check_daily_token_budget(tenant, 100).is_ok());
        let _ = add_usage(tenant, 60, 50); // 110 >= 100
        match check_daily_token_budget(tenant, 100) {
            Err(QuotaError::DailyTokenBudgetExceeded { budget, used, .. }) => {
                assert_eq!(budget, 100);
                assert!(used >= 100);
            }
            other => panic!("expected budget exceeded, got {other:?}"),
        }
    }

    #[test]
    fn resolve_prefers_configured_over_env_default() {
        assert_eq!(resolve_daily_token_budget(Some(500)), 500);
        // Configured 0 falls through to the env default (0 unless overridden).
        assert_eq!(resolve_daily_token_budget(Some(0)), daily_token_budget_env_default());
    }
}
