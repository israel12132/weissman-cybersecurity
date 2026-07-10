//! Live, in-process per-engine run telemetry — the data behind the operator "Engine Reliability"
//! view (inspired by Datadog/CrowdStrike fleet health). Every resilient engine run records its
//! outcome here so the UI can show, per engine: total runs, self-heal (recovered) count, failures,
//! and the last run's status / attempts / strategy / latency.
//!
//! Process-local and lock-guarded (no external store, no fake data). Bounded by the engine catalog
//! size, so memory is constant.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

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

fn store() -> &'static Mutex<HashMap<String, EngineHealth>> {
    static S: OnceLock<Mutex<HashMap<String, EngineHealth>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record the outcome of one resilient engine run.
pub fn record(engine_id: &str, telem: &crate::engine_resilience::EngineExecTelemetry) {
    let Ok(mut map) = store().lock() else {
        return;
    };
    let h = map.entry(engine_id.to_string()).or_default();
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

/// Snapshot of all observed engines, most-recently-run first.
pub fn snapshot() -> Vec<(String, EngineHealth)> {
    let Ok(map) = store().lock() else {
        return Vec::new();
    };
    let mut v: Vec<(String, EngineHealth)> =
        map.iter().map(|(k, h)| (k.clone(), h.clone())).collect();
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
}
