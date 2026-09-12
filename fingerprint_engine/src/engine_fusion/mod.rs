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
//!
//! Alert evaluator also calls `correlate_finding_to_paths` so webhook fires
//! include the shortest matching Dijkstra hop + jewel (honest miss → omit).

/// Production fusion engine IDs — must remain a subset of `PRODUCTION_ENGINE_IDS`.
pub const FUSION_ENGINE_IDS: &[&str] = &[
    "first_mover_surface_delta",
    "first_mover_delta_fusion",
    "first_seen_osv_nvd",
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

/// Correlate a live finding to Dijkstra attack-path snapshots (alert fusion).
/// Matches finding title/source/target against path step labels. Honest miss → None.
/// Labels shorter than 4 chars are ignored to avoid false positives on tokens like "db".
pub fn correlate_finding_to_paths(
    title: &str,
    source: &str,
    extra: &str,
    paths_json: &serde_json::Value,
) -> Option<(u32, String)> {
    let hay = format!("{title} {source} {extra}").to_ascii_lowercase();
    if hay.trim().is_empty() {
        return None;
    }
    let paths = paths_json
        .as_array()
        .or_else(|| paths_json.get("paths").and_then(|v| v.as_array()))?;
    let mut best: Option<(u32, String)> = None;
    for p in paths {
        let hops = p.get("hops").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let jewel = p
            .get("steps")
            .and_then(|s| s.as_array())
            .and_then(|steps| steps.last())
            .and_then(|s| {
                s.get("label")
                    .and_then(|v| v.as_str())
                    .filter(|l| !l.is_empty())
                    .or_else(|| s.get("graph_key").and_then(|v| v.as_str()))
            })
            .unwrap_or("")
            .to_string();
        let hit = p
            .get("steps")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .any(|s| {
                let label = s
                    .get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let key = s
                    .get("graph_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let label_hit = label.len() >= 4 && hay.contains(&label);
                let key_hit = key.len() >= 4 && hay.contains(&key);
                label_hit || key_hit
            });
        if hit {
            match &best {
                None => best = Some((hops, jewel)),
                Some((h, _)) if hops < *h => best = Some((hops, jewel)),
                _ => {}
            }
        }
    }
    best
}

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

    #[test]
    fn correlate_finding_to_paths_picks_shortest_hit() {
        let paths = serde_json::json!([
            {
                "hops": 4,
                "steps": [
                    {"label": "edge.example", "graph_key": "asm:edge"},
                    {"label": "vault.internal", "graph_key": "identity:vault"}
                ]
            },
            {
                "hops": 2,
                "steps": [
                    {"label": "www.example", "graph_key": "asm:www"},
                    {"label": "vault.internal", "graph_key": "identity:vault"}
                ]
            }
        ]);
        let hit = correlate_finding_to_paths("SQLi on vault.internal", "sqli_advanced", "", &paths);
        assert_eq!(hit.as_ref().map(|h| h.0), Some(2));
        assert_eq!(hit.as_ref().map(|h| h.1.as_str()), Some("vault.internal"));
        assert!(correlate_finding_to_paths("unrelated", "osint", "", &paths).is_none());
        assert!(correlate_finding_to_paths("x", "y", "", &serde_json::json!([])).is_none());
        assert!(
            correlate_finding_to_paths("db dump", "osint", "", &paths).is_none(),
            "short tokens must not match"
        );
    }
}
