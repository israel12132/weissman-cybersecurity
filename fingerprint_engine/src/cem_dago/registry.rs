//! Manifests for every production engine — group defaults + explicit core overrides.
//! Lookup is O(1) per id; nothing is stored as a trait object.

use super::manifest::{EdgeKind, EngineManifest};
use weissman_core::models::engine::resolve_engine_id;

/// Orchestrator pipeline engines that keep dedicated post-processing (ASM graph,
/// identity harvest, BOLA kill-chain, semantic log, …). CEM-DAGO still records
/// their blackboard evidence; scheduling of the remaining 500+ engines is the mesh.
pub const PIPELINE_SPECIAL_ENGINES: &[&str] = &[
    "osint",
    "asm",
    "supply_chain",
    "leak_hunter",
    "bola_idor",
    "llm_path_fuzz",
    "semantic_ai_fuzz",
    "microsecond_timing",
    "ai_adversarial_redteam",
];

#[must_use]
pub fn is_pipeline_special(id: &str) -> bool {
    let c = resolve_engine_id(id);
    PIPELINE_SPECIAL_ENGINES.contains(&c)
}

#[must_use]
pub fn manifest_for(engine_id: &str) -> EngineManifest {
    let canonical = resolve_engine_id(engine_id);
    if let Some(m) = explicit_override(canonical) {
        return EngineManifest {
            id: engine_id.to_string(),
            ..m
        };
    }
    let group = crate::engine_requirements::engine_group(canonical).unwrap_or("web");
    let mut m = group_defaults(group, canonical);
    m.id = engine_id.to_string();
    m
}

fn explicit_override(id: &str) -> Option<EngineManifest> {
    let m = |req: &[&str], out: &[&str], mitre: &[&str], kinds: &[EdgeKind]| EngineManifest {
        id: id.to_string(),
        required_inputs: req.iter().map(|s| (*s).to_string()).collect(),
        output_signals: out.iter().map(|s| (*s).to_string()).collect(),
        mitre_techniques: mitre.iter().map(|s| (*s).to_string()).collect(),
        edge_kinds: kinds.to_vec(),
    };
    Some(match id {
        "osint" | "recon" | "discovery_engine" => m(
            &[],
            &["internet_exposed", "osint_complete"],
            &["T1595", "T1592"],
            &[EdgeKind::WebPort],
        ),
        "asm" => m(
            &[],
            &["web_port_active", "asm_complete", "internet_exposed"],
            &["T1046", "T1595"],
            &[EdgeKind::WebPort],
        ),
        "leak_hunter" => m(
            &["internet_exposed"],
            &["credential_access", "leak_signal"],
            &["T1552", "T1530"],
            &[EdgeKind::CredentialAccess],
        ),
        "supply_chain" => m(
            &["internet_exposed"],
            &["supply_chain_signal"],
            &["T1195"],
            &[EdgeKind::WebPort],
        ),
        "bola_idor" => m(
            &["web_port_active", "discovery_paths"],
            &["credential_access"],
            &["T1190"],
            &[EdgeKind::WebPort, EdgeKind::CredentialAccess],
        ),
        "llm_path_fuzz" | "semantic_ai_fuzz" => m(
            &["web_port_active", "discovery_paths"],
            &["web_port_active"],
            &["T1190", "T1059"],
            &[EdgeKind::WebPort],
        ),
        "microsecond_timing" | "timing_sidechannel" => m(
            &["web_port_active"],
            &["credential_access"],
            &["T1552"],
            &[EdgeKind::CredentialAccess],
        ),
        "ai_adversarial_redteam" | "llm_redteam" => m(
            &["web_port_active"],
            &["web_port_active"],
            &["T1059"],
            &[EdgeKind::WebPort],
        ),
        "scada_ics" | "ot_ics" | "iot_firmware" | "ble_rf" => m(
            &["ot_protocol"],
            &["ot_findings"],
            &["T0861", "T0801"],
            &[EdgeKind::OtProtocol],
        ),
        "kerberoasting" | "password_spray" | "smb_netbios" => m(
            &["ad_domain"],
            &["credential_access", "ad_domain"],
            &["T1558", "T1110"],
            &[EdgeKind::ActiveDirectoryDomain, EdgeKind::CredentialAccess],
        ),
        "aws_attack" | "azure_attack" | "gcp_attack" | "cloud_posture" | "serverless_attack" => m(
            &[],
            &["cloud_metadata"],
            &["T1580", "T1078"],
            &[EdgeKind::CloudMetadata],
        ),
        "waf_bypass" | "http_smuggling" | "graphql_attack" | "websocket_attack" => m(
            &["web_port_active"],
            &["web_port_active"],
            &["T1190"],
            &[EdgeKind::WebPort],
        ),
        _ => return None,
    })
}

fn group_defaults(group: &str, id: &str) -> EngineManifest {
    let (req, out, mitre, kinds): (&[&str], &[&str], &[&str], &[EdgeKind]) = match group {
        "recon" => (
            &["internet_exposed"],
            &["web_port_active", "asm_complete"],
            &["T1595"],
            &[EdgeKind::WebPort],
        ),
        "web" => (
            &["web_port_active"],
            &["credential_access"],
            &["T1190"],
            &[EdgeKind::WebPort],
        ),
        "ot" => (
            &["ot_protocol"],
            &["ot_findings"],
            &["T0861"],
            &[EdgeKind::OtProtocol],
        ),
        "cloud" => (
            &["internet_exposed"],
            &["cloud_metadata"],
            &["T1580"],
            &[EdgeKind::CloudMetadata],
        ),
        "network" => (
            &["internet_exposed"],
            &["web_port_active"],
            &["T1046"],
            &[EdgeKind::WebPort],
        ),
        "crypto" => (
            &["web_port_active"],
            &["credential_access"],
            &["T1552"],
            &[EdgeKind::CredentialAccess],
        ),
        "ai" => (
            &["web_port_active"],
            &["web_port_active"],
            &["T1059"],
            &[EdgeKind::WebPort],
        ),
        "apt" => (
            &["web_port_active"],
            &["credential_access"],
            &["T1078"],
            &[EdgeKind::CredentialAccess],
        ),
        "stealth" => (
            &["web_port_active"],
            &["web_port_active"],
            &["T1027"],
            &[EdgeKind::WebPort],
        ),
        "supply_chain" => (
            &["internet_exposed"],
            &["supply_chain_signal"],
            &["T1195"],
            &[EdgeKind::WebPort],
        ),
        "data" => (
            &["web_port_active"],
            &["credential_access"],
            &["T1530"],
            &[EdgeKind::CredentialAccess],
        ),
        "malware" => (
            &["web_port_active"],
            &["credential_access"],
            &["T1204"],
            &[EdgeKind::WebPort],
        ),
        "mobile" => (
            &["internet_exposed"],
            &["web_port_active"],
            &["T1458"],
            &[EdgeKind::WebPort],
        ),
        "social" => (
            &["internet_exposed"],
            &["credential_access"],
            &["T1566"],
            &[EdgeKind::WebPort],
        ),
        "defense" => (
            &["internet_exposed"],
            &["web_port_active"],
            &["T1562"],
            &[EdgeKind::WebPort],
        ),
        _ => (
            &["internet_exposed"],
            &["web_port_active"],
            &["T1595"],
            &[EdgeKind::WebPort],
        ),
    };
    EngineManifest {
        id: id.to_string(),
        required_inputs: req.iter().map(|s| (*s).to_string()).collect(),
        output_signals: out.iter().map(|s| (*s).to_string()).collect(),
        mitre_techniques: mitre.iter().map(|s| (*s).to_string()).collect(),
        edge_kinds: kinds.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osint_has_no_hard_prereq() {
        let m = manifest_for("osint");
        assert!(m.required_inputs.is_empty());
        assert!(m.output_signals.iter().any(|s| s == "internet_exposed"));
    }

    #[test]
    fn ot_group_requires_ot_protocol() {
        let m = manifest_for("scada_ics");
        assert!(m.required_inputs.iter().any(|s| s == "ot_protocol"));
        assert!(m.edge_kinds.contains(&EdgeKind::OtProtocol));
    }

    #[test]
    fn alias_resolves_override() {
        // resolve_engine_id maps aliases; even unknown ids get group defaults.
        let m = manifest_for("graphql_attack");
        assert_eq!(m.id, "graphql_attack");
        assert!(m.required_inputs.iter().any(|s| s == "web_port_active"));
    }
}
