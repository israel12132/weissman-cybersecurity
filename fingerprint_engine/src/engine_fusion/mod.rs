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
/// Matches finding title/source against path step labels, and `finding:{id}`
/// graph keys. Bracket tags in labels (`title [source]`) are stripped first.
/// Honest miss → None.
pub fn correlate_finding_to_paths(
    title: &str,
    source: &str,
    paths_json: &serde_json::Value,
) -> Option<(u32, String)> {
    correlate_finding_to_paths_keyed(title, source, "", paths_json)
}

pub fn correlate_finding_to_paths_keyed(
    title: &str,
    source: &str,
    finding_key: &str,
    paths_json: &serde_json::Value,
) -> Option<(u32, String)> {
    let title_l = title.to_ascii_lowercase();
    let source_l = source.to_ascii_lowercase();
    let hay = format!("{title_l} {source_l}");
    if hay.trim().is_empty() && finding_key.trim().is_empty() {
        return None;
    }
    let finding_gkey = if finding_key.trim().is_empty() {
        String::new()
    } else {
        format!("finding:{}", finding_key.to_ascii_lowercase())
    };
    let paths = paths_json.as_array()?;
    let mut best: Option<(u32, String)> = None;
    for p in paths {
        let hops = p.get("hops").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let jewel = p
            .get("steps")
            .and_then(|s| s.as_array())
            .and_then(|steps| steps.last())
            .and_then(|s| s.get("label").and_then(|v| v.as_str()))
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
                let label_n = strip_bracket_tags(&label);
                (!label_n.is_empty()
                    && ((!hay.trim().is_empty() && hay.contains(&label_n))
                        || (!title_l.is_empty() && label_n.contains(&title_l))))
                    || (!key.is_empty()
                        && ((!hay.trim().is_empty() && hay.contains(&key))
                            || (!finding_gkey.is_empty() && key == finding_gkey)))
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

fn strip_bracket_tags(s: &str) -> String {
    let mut out = String::new();
    let mut in_br = false;
    for c in s.chars() {
        match c {
            '[' => in_br = true,
            ']' => in_br = false,
            _ if !in_br => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
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
        let hit = correlate_finding_to_paths("SQLi on vault.internal", "sqli_advanced", &paths);
        assert_eq!(hit.as_ref().map(|h| h.0), Some(2));
        assert_eq!(hit.as_ref().map(|h| h.1.as_str()), Some("vault.internal"));
        assert!(correlate_finding_to_paths("unrelated", "osint", &paths).is_none());
        assert!(correlate_finding_to_paths("x", "y", &serde_json::json!([])).is_none());
        let tagged = serde_json::json!([{
            "hops": 3,
            "steps": [
                {"label": "SQLi on vault.internal [sqli_advanced]", "graph_key": "finding:fid-9"},
                {"label": "prod-vault", "graph_key": "identity:vault"}
            ]
        }]);
        let hit = correlate_finding_to_paths("SQLi on vault.internal", "sqli_advanced", &tagged);
        assert_eq!(hit.as_ref().map(|h| h.0), Some(3));
        let keyed =
            correlate_finding_to_paths_keyed("other title", "sqli_advanced", "fid-9", &tagged);
        assert_eq!(keyed.as_ref().map(|h| h.0), Some(3));
    }
}
