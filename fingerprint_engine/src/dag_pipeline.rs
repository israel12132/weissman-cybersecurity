//! Strict 5-stage execution pipeline (DAG). Engines cannot skip stages.
//! Stage 0 = Global Intel (Zero-Day Radar), Stage 1 = Deep Discovery, Stage 2 = Vuln Scanning,
//! Stage 3 = Kill Shot (PoE, Deception, LLM Red Team, Self-Heal) only if Stage 2 found foothold,
//! Stage 4 = Compliance (Audit Root Hash, PDF/Alert).

pub const STAGE_GLOBAL_INTEL: u8 = 0;
pub const STAGE_DEEP_DISCOVERY: u8 = 1;
pub const STAGE_VULN_SCANNING: u8 = 2;
pub const STAGE_KILL_SHOT: u8 = 3;
pub const STAGE_COMPLIANCE: u8 = 4;

pub const STAGE_LABELS: [&str; 5] = [
    "Global Intel (Zero-Day Radar)",
    "Deep Discovery (OSINT, ASM, GraphQL, Wasm)",
    "Vulnerability Scanning (Supply Chain, Leak Hunter, Identity, Fuzz)",
    "Kill Shot (PoE, Deception, LLM Red Team, Self-Heal)",
    "Compliance (Audit Hash, PDF)",
];

/// Engine IDs that belong to each stage. Used to filter client-enabled engines by stage.
pub fn engines_for_stage(stage: u8) -> &'static [&'static str] {
    match stage {
        STAGE_GLOBAL_INTEL => &["zero_day_radar"],
        STAGE_DEEP_DISCOVERY => &["osint", "asm"],
        STAGE_VULN_SCANNING => &[
            "supply_chain",
            "leak_hunter",
            "bola_idor",
            "llm_path_fuzz",
            "semantic_ai_fuzz",
            "microsecond_timing",
            "ai_adversarial_redteam",
        ],
        STAGE_KILL_SHOT => &["poe_synthesis"],
        STAGE_COMPLIANCE => &[],
        _ => &[],
    }
}

/// Whether stage 3 (Kill Shot) is allowed only when stage 2 produced findings.
pub fn stage_3_requires_foothold() -> bool {
    true
}

pub const GLOBAL_SCOPE_ID: &str = "__global__";
