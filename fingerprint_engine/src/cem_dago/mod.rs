//! CEM-DAGO — Cognitive Engine Mesh & Directed Attack-Graph Orchestrator.
//!
//! Replaces flat serial engine loops with:
//! 1. A **shared Redis blackboard** (engines never talk peer-to-peer).
//! 2. An **active DAG router** that launches engines whose prerequisites are on
//!    the blackboard, in bounded parallel waves.
//! 3. **Pivot / recursive fallback** via Dijkstra over live `risk_graph_*` plus
//!    overlapping cognitive manifests.
//! 4. **Supreme Council / vLLM planner** that emits a validated JSON plan
//!    (offensive probes + optional `weissman_ro` QueryPlan) when deterministic
//!    engines stall — never fabricated findings.
//!
//! Production engines still run through [`crate::engine_dispatch::run_engine`].
//! This module does **not** materialise 563 `Arc<dyn CognitiveEngine>` objects
//! per scan (that would pin CPU/RAM); manifests are static lookup, execution is
//! dispatch-on-id.

pub mod blackboard;
pub mod lanes;
pub mod manifest;
pub mod mesh;
pub mod payload_trie;
pub mod pivot;
pub mod planner;
pub mod registry;
pub mod router;

pub use blackboard::{BlackboardError, Evidence, FailureLog, ScanBlackboard};
pub use lanes::{engine_lane, EngineLane};
pub use manifest::{CognitiveEngine, EdgeKind, EngineManifest};
pub use mesh::{
    execute_mesh, manifests_json, seed_scan_context, status_json, MeshEngineOutcome, MeshRequest,
    MeshRunReport, PivotEvent,
};
pub use payload_trie::{
    prewarm_payload_trie, PayloadTrie, PrewarmStats, PREWARM_BATCH_SIZE, PREWARM_HARD_CAP,
    PREWARM_WINDOW_DAYS,
};
pub use registry::{manifest_for, PIPELINE_SPECIAL_ENGINES};
pub use router::{next_ready_wave, partition_scan_engines, schedule_waves, PartitionedEngines};

/// Default TTL for blackboard hashes and failure lists (24 hours).
pub const BLACKBOARD_TTL_SECS: i64 = 86_400;

/// Process-wide enable switch. Default **on**; set `WEISSMAN_CEM_DAGO=0` to keep
/// the legacy serial loop for mesh engines.
#[must_use]
pub fn is_enabled() -> bool {
    match std::env::var("WEISSMAN_CEM_DAGO") {
        Ok(v) => {
            let t = v.trim();
            !(t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off"))
        }
        Err(_) => true,
    }
}

/// Bounded fork-join width for the web lane of one wave. Clamped 1..=32.
#[must_use]
pub fn max_parallel() -> usize {
    parse_bounded_parallel(
        std::env::var("WEISSMAN_CEM_DAGO_MAX_PARALLEL")
            .ok()
            .as_deref(),
        4,
        1,
        32,
    )
}

/// Isolated OT/ICS lane width. Tight so web fuzzing cannot starve Modbus/S7.
#[must_use]
pub fn ot_max_parallel() -> usize {
    parse_bounded_parallel(
        std::env::var("WEISSMAN_CEM_DAGO_OT_PARALLEL")
            .ok()
            .as_deref(),
        2,
        1,
        8,
    )
}

/// Isolated APT lane width.
#[must_use]
pub fn apt_max_parallel() -> usize {
    parse_bounded_parallel(
        std::env::var("WEISSMAN_CEM_DAGO_APT_PARALLEL")
            .ok()
            .as_deref(),
        2,
        1,
        8,
    )
}

#[must_use]
pub(crate) fn parse_bounded_parallel(
    raw: Option<&str>,
    default: usize,
    lo: usize,
    hi: usize,
) -> usize {
    raw.and_then(|s| s.parse().ok())
        .unwrap_or(default)
        .clamp(lo, hi)
}

/// Cached `weissman_ro` pool from `WEISSMAN_READ_ONLY_DATABASE_URL`.
/// Council QueryPlans never run on the application role.
#[must_use]
pub fn weissman_ro_pool() -> Option<std::sync::Arc<sqlx::PgPool>> {
    static POOL: std::sync::OnceLock<Option<std::sync::Arc<sqlx::PgPool>>> =
        std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        let url = std::env::var("WEISSMAN_READ_ONLY_DATABASE_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_lazy(&url)
            .ok()
            .map(std::sync::Arc::new)
    })
    .clone()
}

/// Whether exhausted deterministic fallbacks may invoke the vLLM / Supreme Council planner.
#[must_use]
pub fn council_enabled() -> bool {
    match std::env::var("WEISSMAN_CEM_DAGO_COUNCIL") {
        Ok(v) => {
            let t = v.trim();
            !(t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off"))
        }
        Err(_) => true,
    }
}

/// Record a live engine result onto the scan blackboard (signals + optional failure).
pub async fn record_engine_result(
    blackboard: &ScanBlackboard,
    engine_id: &str,
    target: &str,
    result: &crate::engine_result::EngineResult,
) {
    let manifest = manifest_for(engine_id);
    let payload = serde_json::json!({
        "status": result.status,
        "success": result.success,
        "findings_count": result.findings.len(),
        "message": result.message,
        "target": target,
    });
    if let Err(e) = blackboard
        .write_evidence(&format!("engine:{engine_id}:status"), engine_id, payload)
        .await
    {
        tracing::warn!(
            target: "cem_dago",
            engine = %engine_id,
            error = %e,
            "blackboard write failed (scan continues; evidence not shared)"
        );
    }
    if result.success {
        for signal in &manifest.output_signals {
            let val = serde_json::json!({
                "from_engine": engine_id,
                "findings_count": result.findings.len(),
            });
            let _ = blackboard.write_evidence(signal, engine_id, val).await;
        }
    } else {
        let _ = blackboard
            .log_engine_failure(engine_id, target, &result.message)
            .await;
        metrics::counter!("weissman_cem_dago_engine_failures_total").increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockWebEngine;

    #[async_trait::async_trait]
    impl CognitiveEngine for MockWebEngine {
        fn manifest(&self) -> EngineManifest {
            EngineManifest {
                id: "MOCK_WEB_ENGINE".into(),
                required_inputs: vec!["internet_exposed".into()],
                output_signals: vec!["web_port_active".into()],
                mitre_techniques: vec!["T1190".into()],
                edge_kinds: vec![EdgeKind::WebPort],
            }
        }

        async fn run(
            &self,
            _target: &str,
            blackboard: Arc<ScanBlackboard>,
        ) -> Result<Vec<serde_json::Value>, String> {
            blackboard
                .write_evidence(
                    "web_port_active",
                    "MOCK_WEB_ENGINE",
                    serde_json::json!(true),
                )
                .await
                .map_err(|e| e.to_string())?;
            Ok(vec![
                serde_json::json!({"finding": "Port 80 is open", "evidence": true}),
            ])
        }
    }

    struct MockOtEngine;

    #[async_trait::async_trait]
    impl CognitiveEngine for MockOtEngine {
        fn manifest(&self) -> EngineManifest {
            EngineManifest {
                id: "MOCK_OT_ENGINE".into(),
                required_inputs: vec!["web_port_active".into()],
                output_signals: vec!["ot_findings".into()],
                mitre_techniques: vec!["T0861".into()],
                edge_kinds: vec![EdgeKind::OtProtocol],
            }
        }

        async fn run(
            &self,
            _target: &str,
            _blackboard: Arc<ScanBlackboard>,
        ) -> Result<Vec<serde_json::Value>, String> {
            Ok(vec![
                serde_json::json!({"finding": "PLC Modbus register write succeeded", "evidence": true}),
            ])
        }
    }

    #[tokio::test]
    async fn test_cognitive_engine_mesh_state_propagation() {
        let blackboard = Arc::new(ScanBlackboard::memory(1, 1, "test-scan-uuid"));
        blackboard
            .write_evidence(
                "internet_exposed",
                "seed",
                serde_json::json!({"target": "127.0.0.1"}),
            )
            .await
            .unwrap();

        let engine_web = MockWebEngine;
        let engine_ot = MockOtEngine;

        let web_results = engine_web
            .run("127.0.0.1", blackboard.clone())
            .await
            .unwrap();
        assert!(!web_results.is_empty());

        let evidence = blackboard.read_evidence("web_port_active").await.unwrap();
        assert!(evidence.is_some());
        assert_eq!(evidence.unwrap().source_engine, "MOCK_WEB_ENGINE");

        let mut has_pre_req = true;
        for pre in &engine_ot.manifest().required_inputs {
            if blackboard.read_evidence(pre).await.unwrap().is_none() {
                has_pre_req = false;
            }
        }
        assert!(
            has_pre_req,
            "MockOtEngine should detect its required inputs from the shared Blackboard"
        );
    }

    #[test]
    fn max_parallel_clamps() {
        assert_eq!(parse_bounded_parallel(None, 4, 1, 32), 4);
        assert_eq!(parse_bounded_parallel(Some("0"), 4, 1, 32), 1);
        assert_eq!(parse_bounded_parallel(Some("99"), 4, 1, 32), 32);
        assert_eq!(parse_bounded_parallel(Some("2"), 2, 1, 8), 2);
    }
}
