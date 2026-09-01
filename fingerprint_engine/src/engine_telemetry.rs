//! Live, in-process per-engine run telemetry — the data behind the operator "Engine Reliability"
//! view (inspired by Datadog/CrowdStrike fleet health). Every resilient engine run records its
//! outcome here so the UI can show, per engine: total runs, self-heal (recovered) count, failures,
//! and the last run's status / attempts / strategy / latency.
//!
//! Process-local DashMap (sharded, no process-wide mutex). Bounded by the engine catalog
//! size, so memory is constant.

use dashmap::DashMap;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Default, Serialize)]
pub struct EngineHealth {
    pub total_runs: u64,
    pub recovered_runs: u64,
    pub failed_runs: u64,
    pub last_status: String,
    pub last_attempts: u32,
    pub last_strategy: String,
    pub last_elapsed_ms: u64,
    pub last_error: Option<String>,
    pub updated_ts: i64,
}

fn store() -> &'static DashMap<String, EngineHealth> {
    static S: OnceLock<DashMap<String, EngineHealth>> = OnceLock::new();
    S.get_or_init(DashMap::new)
}

fn apply_telem(h: &mut EngineHealth, telem: &crate::engine_resilience::EngineExecTelemetry) {
    h.total_runs += 1;
    if telem.recovered {
        h.recovered_runs += 1;
    }
    if telem.status != "ok" {
        h.failed_runs += 1;
    }
    h.last_status = telem.status.clone();
    h.last_attempts = telem.attempts;
    h.last_strategy = telem.strategy.clone();
    h.last_elapsed_ms = telem.elapsed_ms;
    h.last_error = telem.error.clone();
    h.updated_ts = chrono::Utc::now().timestamp();
}

/// Record the outcome of one resilient engine run.
pub fn record(engine_id: &str, telem: &crate::engine_resilience::EngineExecTelemetry) {
    store()
        .entry(engine_id.to_string())
        .and_modify(|h| apply_telem(h, telem))
        .or_insert_with(|| {
            let mut h = EngineHealth::default();
            apply_telem(&mut h, telem);
            h
        });
}

/// Snapshot of all observed engines, most-recently-run first.
pub fn snapshot() -> Vec<(String, EngineHealth)> {
    let mut v: Vec<(String, EngineHealth)> = store()
        .iter()
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    v.sort_by(|a, b| b.1.updated_ts.cmp(&a.1.updated_ts));
    v
}

pub fn to_json() -> serde_json::Value {
    let snap = snapshot();
    let total_runs: u64 = snap.iter().map(|(_, h)| h.total_runs).sum();
    let recovered: u64 = snap.iter().map(|(_, h)| h.recovered_runs).sum();
    let failed: u64 = snap.iter().map(|(_, h)| h.failed_runs).sum();
    serde_json::json!({
        "engines_observed": snap.len(),
        "total_runs": total_runs,
        "recovered_runs": recovered,
        "failed_runs": failed,
        "engines": snap.iter().map(|(id, h)| serde_json::json!({
            "engine_id": id,
            "total_runs": h.total_runs,
            "recovered_runs": h.recovered_runs,
            "failed_runs": h.failed_runs,
            "last_status": h.last_status,
            "last_attempts": h.last_attempts,
            "last_strategy": h.last_strategy,
            "last_elapsed_ms": h.last_elapsed_ms,
            "last_error": h.last_error,
            "updated_ts": h.updated_ts,
        })).collect::<Vec<_>>(),
    })
}

/// Drop engines that have not reported in `max_age_secs` (default 30 days).
pub fn evict_stale() -> usize {
    evict_older_than(
        chrono::Utc::now()
            .timestamp()
            .saturating_sub(30 * 24 * 3600),
    )
}

fn evict_older_than(cutoff_ts: i64) -> usize {
    let mut dropped = 0usize;
    store().retain(|_, h| {
        if h.updated_ts > 0 && h.updated_ts < cutoff_ts {
            dropped += 1;
            false
        } else {
            true
        }
    });
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_resilience::EngineExecTelemetry;

    #[test]
    fn record_then_snapshot_reflects_run() {
        let telem = EngineExecTelemetry {
            engine_id: "telemetry_test_engine_zzz".into(),
            attempts: 2,
            strategy: "https://x".into(),
            elapsed_ms: 17,
            status: "ok".into(),
            recovered: true,
            error: None,
            failure_class: None,
        };
        record("telemetry_test_engine_zzz", &telem);
        record("telemetry_test_engine_zzz", &telem);
        let snap = snapshot();
        let (_, h) = snap
            .iter()
            .find(|(id, _)| id == "telemetry_test_engine_zzz")
            .expect("engine recorded");
        assert!(h.total_runs >= 2);
        assert!(h.recovered_runs >= 2);
        assert_eq!(h.last_status, "ok");
        assert_eq!(h.last_attempts, 2);
    }

    #[test]
    fn failed_run_counts_as_failure() {
        let telem = EngineExecTelemetry {
            engine_id: "telemetry_fail_engine_zzz".into(),
            attempts: 3,
            strategy: "exhausted".into(),
            elapsed_ms: 50,
            status: "timeout".into(),
            recovered: false,
            error: Some("timed out".into()),
            failure_class: Some("timeout".into()),
        };
        record("telemetry_fail_engine_zzz", &telem);
        let snap = snapshot();
        let (_, h) = snap
            .iter()
            .find(|(id, _)| id == "telemetry_fail_engine_zzz")
            .expect("engine recorded");
        assert!(h.failed_runs >= 1);
        assert_eq!(h.last_status, "timeout");
    }

    #[test]
    fn evicts_engines_older_than_cutoff() {
        store().insert(
            "telemetry_stale_engine_zzz".into(),
            EngineHealth {
                updated_ts: 1,
                ..EngineHealth::default()
            },
        );
        let n = evict_older_than(1_000);
        assert!(n >= 1);
        assert!(store().get("telemetry_stale_engine_zzz").is_none());
    }
}
