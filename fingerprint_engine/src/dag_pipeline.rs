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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_constants_are_sequential() {
        assert_eq!(STAGE_GLOBAL_INTEL, 0);
        assert_eq!(STAGE_DEEP_DISCOVERY, 1);
        assert_eq!(STAGE_VULN_SCANNING, 2);
        assert_eq!(STAGE_KILL_SHOT, 3);
        assert_eq!(STAGE_COMPLIANCE, 4);
    }

    #[test]
    fn stage_labels_has_five_entries_indexed_by_constant() {
        assert_eq!(STAGE_LABELS.len(), 5);
        assert_eq!(
            STAGE_LABELS[STAGE_GLOBAL_INTEL as usize],
            "Global Intel (Zero-Day Radar)"
        );
        assert_eq!(
            STAGE_LABELS[STAGE_DEEP_DISCOVERY as usize],
            "Deep Discovery (OSINT, ASM, GraphQL, Wasm)"
        );
        assert_eq!(
            STAGE_LABELS[STAGE_COMPLIANCE as usize],
            "Compliance (Audit Hash, PDF)"
        );
    }

    #[test]
    fn engines_for_global_intel_stage() {
        assert_eq!(engines_for_stage(STAGE_GLOBAL_INTEL), &["zero_day_radar"][..]);
    }

    #[test]
    fn engines_for_deep_discovery_stage() {
        assert_eq!(engines_for_stage(STAGE_DEEP_DISCOVERY), &["osint", "asm"][..]);
    }

    #[test]
    fn engines_for_vuln_scanning_stage() {
        assert_eq!(
            engines_for_stage(STAGE_VULN_SCANNING),
            &[
                "supply_chain",
                "leak_hunter",
                "bola_idor",
                "llm_path_fuzz",
                "semantic_ai_fuzz",
                "microsecond_timing",
                "ai_adversarial_redteam",
            ][..]
        );
    }

    #[test]
    fn engines_for_kill_shot_stage() {
        assert_eq!(engines_for_stage(STAGE_KILL_SHOT), &["poe_synthesis"][..]);
    }

    #[test]
    fn compliance_and_unknown_stages_have_no_engines() {
        assert!(engines_for_stage(STAGE_COMPLIANCE).is_empty());
        assert!(engines_for_stage(99).is_empty());
        assert!(engines_for_stage(255).is_empty());
    }

    #[test]
    fn stage_3_requires_foothold_is_true() {
        assert!(stage_3_requires_foothold());
    }

    #[test]
    fn global_scope_id_constant() {
        assert_eq!(GLOBAL_SCOPE_ID, "__global__");
    }
}
