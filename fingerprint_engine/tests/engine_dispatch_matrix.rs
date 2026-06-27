//! Dispatch matrix — synthesis and sovereign engines must have dedicated arms.

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
