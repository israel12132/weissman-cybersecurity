//! Fusion engine layer — multi-domain live synthesis (world-first correlated probes).
//!
//! Every engine exported here combines **≥2 evidence domains** (live network probes,
//! tenant DB telemetry, FAIR financial models, endpoint agent signals). No fabricated
//! findings — empty inputs yield honest empty or informational results.
//!
//! ## Catalog
//!
//! | Engine ID | Domains fused |
//! |-----------|---------------|
//! | `external_exposure_supreme` | ASM + email/DNS + cloud posture |
//! | `identity_attack_chain` | Kerberos + spray + ITDR auth events |
//! | `pipeline_to_runtime_risk` | IaC + supply chain + CI/CD |
//! | `risk_superposition_collapse` | Multi-engine Bayesian belief + STRIPS + FAIR |
//! | `sovereign_active_defense_fusion` | MTD + cognitive starvation + deception + CHRONOS |
//! | `fair_exposure_fusion` | External exposure grade + FAIR ALE/SLE roll-up |

/// Production fusion engine IDs — must remain a subset of `PRODUCTION_ENGINE_IDS`.
pub const FUSION_ENGINE_IDS: &[&str] = &[
    "external_exposure_supreme",
    "identity_attack_chain",
    "pipeline_to_runtime_risk",
    "risk_superposition_collapse",
    "sovereign_active_defense_fusion",
    "fair_exposure_fusion",
];

pub use crate::external_exposure_supreme::{
    run_external_exposure_supreme, run_external_exposure_supreme_result,
};
pub use crate::fair_exposure_fusion_engine::{
    run_fair_exposure_fusion, run_fair_exposure_fusion_result,
};
pub use crate::identity_attack_chain_engine::{
    run_identity_attack_chain, run_identity_attack_chain_result,
};
pub use crate::pipeline_to_runtime_risk_engine::{
    run_pipeline_to_runtime_risk, run_pipeline_to_runtime_risk_result,
};
pub use crate::risk_superposition_collapse_engine::{
    run_risk_superposition_collapse, run_risk_superposition_collapse_result,
};
pub use crate::sovereign_active_defense_fusion_engine::{
    run_sovereign_active_defense_fusion, run_sovereign_active_defense_fusion_result,
};

#[cfg(test)]
mod tests {
    use super::*;
    use weissman_core::models::engine::production_engine_ids;

    #[test]
    fn fusion_catalog_subset_of_production() {
        let prod: std::collections::HashSet<&str> =
            production_engine_ids().iter().copied().collect();
        for id in FUSION_ENGINE_IDS {
            assert!(
                prod.contains(id),
                "fusion engine {id} missing from PRODUCTION_ENGINE_IDS"
            );
        }
    }
}
