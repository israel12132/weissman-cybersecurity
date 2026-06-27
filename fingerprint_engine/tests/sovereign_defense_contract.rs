//! Contract tests for sovereign defense wiring and auth expectations.

#[test]
fn chronos_not_in_agent_required_short_circuit_list() {
    let dispatch = include_str!("../src/engine_dispatch.rs");
    let agent_src = include_str!("../src/engine_dispatch_agent.rs");
    let block = agent_src
        .split("pub const AGENT_REQUIRED_ENGINES")
        .nth(1)
        .and_then(|s| s.split("];").next())
        .unwrap_or("");
    assert!(
        !block.contains("\"chronos\""),
        "chronos must run via chronos_engine hybrid, not agent-only short-circuit"
    );
    assert!(
        dispatch.contains("mod engine_dispatch_agent"),
        "agent dispatch split into engine_dispatch_agent.rs"
    );
    assert!(
        dispatch.contains("\"chronos\" => crate::chronos_engine::run_chronos_result"),
        "chronos dispatch arm must exist"
    );
}

#[test]
fn poison_library_requires_analyst_rbac() {
    let handlers = include_str!("../src/server_handlers_sovereign_defense.inc");
    assert!(handlers.contains("api_sovereign_defense_poison_library"));
    assert!(handlers.contains("Extension(auth): Extension<AuthContext>"));
    assert!(handlers.contains("require_analyst(&auth)"));
}

#[test]
fn liquid_matrix_declares_simulation_mode() {
    let src = include_str!("../src/liquid_matrix_engine.rs");
    assert!(src.contains("simulation_mode"));
}
