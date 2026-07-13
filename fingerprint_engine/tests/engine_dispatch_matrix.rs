//! Dispatch matrix — every production engine id must resolve to a real runner, and the
//! specific synthesis/sovereign engines keep dedicated arms.

use weissman_core::models::engine::PRODUCTION_ENGINE_IDS;

/// Source files that together contain a wiring for every production engine id: the main
/// dispatch match, the alias table, the agent-required path, the OT/critical-infra group,
/// and the agent remote-surface probes.
const DISPATCH_SOURCES: &[&str] = &[
    include_str!("../src/engine_dispatch.rs"),
    include_str!("../src/alias_engine_runner.rs"),
    include_str!("../src/engine_dispatch_agent.rs"),
    include_str!("../src/critical_infra/engines.rs"),
    include_str!("../src/agent_remote_surface.rs"),
];

/// Drift guard: every id in `PRODUCTION_ENGINE_IDS` must appear as a string literal in one of
/// the dispatch sources. This catches the "registered in PRODUCTION_ENGINE_IDS but has no
/// dispatch runner" fallback (`engine_dispatch.rs`) at test time instead of at runtime — the
/// single cheapest guard against the catalog and the dispatcher drifting apart.
#[test]
fn every_production_engine_id_has_a_dispatch_path() {
    let mut missing: Vec<&str> = Vec::new();
    for &id in PRODUCTION_ENGINE_IDS {
        let needle = format!("\"{id}\"");
        if !DISPATCH_SOURCES.iter().any(|src| src.contains(&needle)) {
            missing.push(id);
        }
    }
    assert!(
        missing.is_empty(),
        "{} production engine id(s) have no dispatch runner: {:?}",
        missing.len(),
        missing
    );
}

#[test]
fn synthesis_and_sovereign_engines_wired_in_dispatch() {
    let dispatch = include_str!("../src/engine_dispatch.rs");
    let required = [
        "external_exposure_supreme",
        "identity_attack_chain",
        "pipeline_to_runtime_risk",
        "risk_superposition_collapse",
        "chronos",
        "liquid_matrix",
        "cognitive_starvation",
    ];
    for engine_id in required {
        assert!(
            dispatch.contains(&format!("\"{engine_id}\"")),
            "missing engine id in dispatch: {engine_id}"
        );
        let arm_prefix = format!("\"{engine_id}\" =>");
        assert!(
            dispatch.contains(&arm_prefix),
            "missing dispatch arm for {engine_id}"
        );
    }
}
