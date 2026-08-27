//! Wall-clock budgets for `tenant_full_scan` / `onboarding_tenant_scan`.
//!
//! A full tenant cycle runs discovery plus every enabled engine per client, sequentially.
//! The worker used to give the *whole job* 3600s and the orchestrator gave *each engine*
//! no timeout at all. One hung probe (LLM, timing, spider, outbound HTTP without a
//! socket deadline) consumed the entire hour; `fail_job` then requeued from scratch, so
//! attempt 2/3/4/5 repeated the same prefix and timed out at the same wall. Observed
//! live: `job timed out after 3600s (tenant_full_scan)` with `attempt_count` climbing
//! while findings from the prefix were already persisted.
//!
//! These budgets make that failure mode inexpressible:
//!   * each engine/discovery probe is capped ([`ORCH_ENGINE_BUDGET`]);
//!   * the cycle stops with ~[`TENANT_FULL_SCAN_GUARD_SECS`] left and enqueues a
//!     continuation that skips completed clients/engines;
//!   * the worker job ceiling ([`TENANT_FULL_SCAN_TIMEOUT_SECS`]) sits above the
//!     cycle limit so the job completes (or continues) instead of being killed.

use serde_json::{json, Value};
use std::future::Future;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Worker wall-clock ceiling for `tenant_full_scan` / `onboarding_tenant_scan`.
///
/// Sized for two clients × (discovery + radar + ~9 engines × 180s + PoE) with
/// headroom. Estates larger than that finish via continuation jobs, not by
/// raising this without bound (a heavy slot is scarce).
pub const TENANT_FULL_SCAN_TIMEOUT_SECS: u64 = 90 * 60;

/// Seconds reserved at the end of the job so persist / complete / continuation
/// enqueue cannot race the worker `tokio::time::timeout`.
pub const TENANT_FULL_SCAN_GUARD_SECS: u64 = 90;

/// Hard cap for one orchestrator engine (or discovery/PoE/radar/OT) probe.
/// Matches `engine_resilience::MAX_ATTEMPT_TIMEOUT` so a hung target cannot
/// stall the rest of the cycle.
pub const ORCH_ENGINE_BUDGET_SECS: u64 = 180;

/// Cap on chained continuation jobs for one logical scan (each is a new row).
pub const MAX_RESUME_GENERATION: u32 = 40;

pub const ORCH_ENGINE_BUDGET: Duration = Duration::from_secs(ORCH_ENGINE_BUDGET_SECS);

/// Job metadata the worker passes into the cycle so we can resume and continue.
#[derive(Debug, Clone)]
pub struct ScanJobOpts {
    pub job_id: Uuid,
    pub payload: Value,
}

/// Cursor written into the next `tenant_full_scan` payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanResume {
    pub generation: u32,
    pub skip_client_ids: Vec<i64>,
    pub resume_client_id: Option<i64>,
    pub resume_skip_engines: Vec<String>,
}

impl ScanResume {
    pub fn from_payload(payload: &Value) -> Self {
        let generation = payload
            .get("resume_generation")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        let skip_client_ids = payload
            .get("skip_client_ids")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        v.as_i64()
                            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let resume_client_id = payload.get("resume_client_id").and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });
        let resume_skip_engines = payload
            .get("resume_skip_engines")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Self {
            generation,
            skip_client_ids,
            resume_client_id,
            resume_skip_engines,
        }
    }

    pub fn to_extra_json(&self) -> Value {
        json!({
            "resume_generation": self.generation,
            "skip_client_ids": self.skip_client_ids,
            "resume_client_id": self.resume_client_id,
            "resume_skip_engines": self.resume_skip_engines,
        })
    }

    pub fn should_skip_client(&self, client_id: i64) -> bool {
        self.skip_client_ids.contains(&client_id)
    }

    pub fn skip_engines_for(&self, client_id: i64) -> &[String] {
        if self.resume_client_id == Some(client_id) {
            &self.resume_skip_engines
        } else {
            &[]
        }
    }

    pub fn can_continue(&self) -> bool {
        self.generation < MAX_RESUME_GENERATION
    }
}

/// Outcome of one cycle (findings are already persisted per engine).
#[derive(Debug, Clone, Default)]
pub struct TenantScanOutcome {
    pub engines_completed: usize,
    pub partial: bool,
    pub continuation_job_id: Option<Uuid>,
    pub remaining_engines: usize,
}

/// Cycle wall-clock limit derived from the worker job ceiling.
pub fn cycle_limit() -> Duration {
    Duration::from_secs(TENANT_FULL_SCAN_TIMEOUT_SECS.saturating_sub(TENANT_FULL_SCAN_GUARD_SECS))
}

#[derive(Debug)]
pub struct ScanBudget {
    started: Instant,
    limit: Duration,
}

impl ScanBudget {
    pub fn new(limit: Duration) -> Self {
        Self {
            started: Instant::now(),
            limit,
        }
    }

    pub fn remaining(&self) -> Duration {
        self.limit.saturating_sub(self.started.elapsed())
    }

    /// True when another 180s engine plus the job-complete guard still fit.
    pub fn can_start_engine(&self) -> bool {
        self.remaining() > ORCH_ENGINE_BUDGET + Duration::from_secs(TENANT_FULL_SCAN_GUARD_SECS)
    }
}

/// Bound one probe. Never panics the caller; timeout becomes `Err(message)`.
pub async fn with_engine_budget<T>(
    engine_id: &str,
    budget: Duration,
    fut: impl Future<Output = T>,
) -> Result<T, String> {
    tokio::time::timeout(budget, fut)
        .await
        .map_err(|_| format!("{engine_id} timed out after {}s", budget.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cycle_limit_leaves_guard_before_worker_timeout() {
        let cycle = cycle_limit().as_secs();
        assert!(cycle < TENANT_FULL_SCAN_TIMEOUT_SECS);
        assert_eq!(
            cycle,
            TENANT_FULL_SCAN_TIMEOUT_SECS - TENANT_FULL_SCAN_GUARD_SECS
        );
        // One engine (180s) + guard (90s) must fit inside the remaining window
        // when can_start_engine is true: remaining > 270s.
        assert!(ORCH_ENGINE_BUDGET_SECS + TENANT_FULL_SCAN_GUARD_SECS < cycle);
    }

    #[test]
    fn worker_timeout_covers_two_worst_case_nine_engine_clients() {
        // discovery + radar + 9×180s + PoE ≈ 2170s per client; two clients ≈ 4340s.
        let two_clients_worst: u64 = 2 * (180 + 180 + 9 * 180 + 180);
        assert!(
            TENANT_FULL_SCAN_TIMEOUT_SECS > two_clients_worst,
            "90m must cover two worst-case default-engine clients; larger estates continue"
        );
        // The previous 3600s ceiling was below that.
        assert!(two_clients_worst > 3600);
    }

    #[test]
    fn resume_round_trips_payload() {
        let src = ScanResume {
            generation: 3,
            skip_client_ids: vec![1, 7],
            resume_client_id: Some(9),
            resume_skip_engines: vec!["osint".into(), "asm".into()],
        };
        let parsed = ScanResume::from_payload(&src.to_extra_json());
        assert_eq!(parsed, src);
        assert!(parsed.should_skip_client(7));
        assert!(!parsed.should_skip_client(9));
        assert_eq!(parsed.skip_engines_for(9), &["osint", "asm"]);
        assert!(parsed.skip_engines_for(1).is_empty());
    }

    #[test]
    fn resume_parses_string_ids() {
        let payload = json!({
            "resume_generation": 1,
            "skip_client_ids": ["12", 4],
            "resume_client_id": "8",
            "resume_skip_engines": ["bola_idor", "  ", "leak_hunter"]
        });
        let r = ScanResume::from_payload(&payload);
        assert_eq!(r.skip_client_ids, vec![12, 4]);
        assert_eq!(r.resume_client_id, Some(8));
        assert_eq!(r.resume_skip_engines, vec!["bola_idor", "leak_hunter"]);
    }

    #[test]
    fn empty_payload_is_a_fresh_scan() {
        let r = ScanResume::from_payload(&json!({"trigger": "orchestrator_tick"}));
        assert_eq!(r, ScanResume::default());
        assert!(r.can_continue());
    }

    #[test]
    fn generation_cap_stops_infinite_continuations() {
        let r = ScanResume {
            generation: MAX_RESUME_GENERATION,
            ..ScanResume::default()
        };
        assert!(!r.can_continue());
    }

    #[test]
    fn budget_refuses_a_start_when_guard_would_not_fit() {
        let budget = ScanBudget {
            started: Instant::now() - Duration::from_secs(10),
            limit: Duration::from_secs(11),
        };
        assert!(!budget.can_start_engine());
    }

    #[tokio::test]
    async fn engine_budget_returns_the_value() {
        let v = with_engine_budget("t", Duration::from_secs(1), async { 7u32 }).await;
        assert_eq!(v, Ok(7));
    }

    #[tokio::test]
    async fn engine_budget_times_out_instead_of_hanging() {
        let v: Result<(), String> =
            with_engine_budget("hung_engine", Duration::from_millis(30), async {
                tokio::time::sleep(Duration::from_secs(30)).await;
            })
            .await;
        let err = v.expect_err("must time out");
        assert!(
            err.contains("hung_engine timed out"),
            "timeout must name the engine, got {err}"
        );
    }
}
