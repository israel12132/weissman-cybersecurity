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
//! | `first_mover_surface_delta` | Live DNS/HTTP/CT vs last snapshot — new/changed hosts before weekly scanners |
//! | `first_mover_delta_fusion` | New host → immediate takeover/leak/BOLA/JWT on that same FQDN |
//! | `first_seen_osv_nvd` | Live SBOM × OSV, proven before NVD when nvd_status is absent_cve/unpublished |
//! | `adversary_underground_delta` | HIBP + ransomware.live exact-domain + ThreatFox/URLhaus/urlscan vs last snapshot — new criminal-index hits then leak_hunter |
//! | `external_exposure_supreme` | ASM + email/DNS + cloud posture |
//! | `identity_attack_chain` | Kerberos + spray + ITDR auth events |
//! | `pipeline_to_runtime_risk` | IaC + supply chain + CI/CD |
//! | `risk_superposition_collapse` | Multi-engine Bayesian belief + STRIPS + FAIR |
//! | `sovereign_active_defense_fusion` | MTD + cognitive starvation + deception + CHRONOS |
//! | `fair_exposure_fusion` | External exposure grade + FAIR ALE/SLE roll-up |
//! | `control_plane_of_controls` | EDR/WAF/email-DNS/cloud control proof |
//! | `ot_cloud_identity_killpath` | OT + cloud + identity kill path |
//! | `bec_ato_chain` | Email DNS + BEC + OAuth + ITDR |
//! | `ai_casb_saas` | LLM agent hijack + OAuth SaaS grants |
//! | `dns_security_posture_fusion` | DNS exfil + email DNS + ASM |
//! | `toxic_combo_runtime_proof` | CNAPP + IMDS + S3 + IAM + K8s |

/// Production fusion engine IDs — must remain a subset of `PRODUCTION_ENGINE_IDS`.
pub const FUSION_ENGINE_IDS: &[&str] = &[
    "first_mover_surface_delta",
    "first_mover_delta_fusion",
    "first_seen_osv_nvd",
    "adversary_underground_delta",
    "external_exposure_supreme",
    "identity_attack_chain",
    "pipeline_to_runtime_risk",
    "risk_superposition_collapse",
    "sovereign_active_defense_fusion",
    "fair_exposure_fusion",
    "control_plane_of_controls",
    "ot_cloud_identity_killpath",
    "bec_ato_chain",
    "ai_casb_saas",
    "dns_security_posture_fusion",
    "toxic_combo_runtime_proof",
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
