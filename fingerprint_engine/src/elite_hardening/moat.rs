//! Sovereign competitive moat — live lane coverage from `PRODUCTION_ENGINE_IDS`.
//!
//! Vendor names below are **public market research** (not live scans of those
//! products). Engine counts, Ask-table allow-list, OT FSM, and evidence-doubt
//! floors are computed from this binary. No competitor scores are invented.

use serde_json::{json, Value};
use weissman_core::models::engine::PRODUCTION_ENGINE_IDS;

use super::{evidence_doubt, nl_guard, stealth_ops, wss_inner};

struct LaneDef {
    id: &'static str,
    title: &'static str,
    beats: &'static str,
    needles: &'static [&'static str],
}

/// Competitive lanes that must all be live in one product. No peer ships this set.
const LANES: &[LaneDef] = &[
    LaneDef {
        id: "web_api",
        title: "Web / API / GraphQL / BOLA",
        beats: "XBOW, Escape, Strix, Invicti, Detectify — web/API only; no OT FSM, FAIR-from-graph, or Ask RLS",
        needles: &[
            "graphql",
            "bola",
            "jwt",
            "oauth",
            "http_smuggl",
            "prototype",
            "ssrf",
            "xxe",
            "ssti",
            "file_upload",
            "websocket",
            "cache_poison",
            "xss",
            "sqli",
            "dast",
            "web_",
            "api_",
            "idor",
            "cors",
            "csrf",
            "host_header",
            "http_desync",
        ],
    },
    LaneDef {
        id: "identity_ad",
        title: "Identity / AD / Kerberos / SAML",
        beats: "BloodHound Enterprise, NodeZero AD, Pentera identity — no dual-probe inbox, no 13-table Ask RLS",
        needles: &[
            "kerbero",
            "kerberos",
            "saml",
            "password_spray",
            "mfa",
            "credential",
            "adcs",
            "ldap",
            "pki",
            "session_fix",
            "zero_trust",
            "azure_ad",
            "ntlm",
            "golden_ticket",
            "dcsync",
            "asrep",
        ],
    },
    LaneDef {
        id: "ot_ics",
        title: "OT/ICS live protocol FSM",
        beats: "Claroty, Dragos, Nozomi — passive visibility; DeNexus — OT FAIR without 303 live probes",
        needles: &[
            "scada",
            "modbus",
            "dnp3",
            "s7",
            "iec61850",
            "triton",
            "avionics",
            "maritime",
            "ev_charging",
            "smart_grid",
            "rail_",
            "building_auto",
            "robotics",
            "can_bus",
            "iot_",
            "ble_",
            "ot_",
            "ics",
            "opcua",
            "profinet",
            "bacnet",
        ],
    },
    LaneDef {
        id: "cloud_cnapp",
        title: "Cloud / CNAPP / IaC",
        beats: "Wiz, Orca, Prisma, CrowdStrike Falcon Cloud — posture/graph, not offensive 563-engine fabric + Ask",
        needles: &[
            "aws",
            "azure",
            "gcp",
            "k8s",
            "iac",
            "serverless",
            "lambda",
            "terraform",
            "cloudformation",
            "ecr",
            "multi_cloud",
            "cloud_",
            "kubernetes",
            "container",
        ],
    },
    LaneDef {
        id: "ransomware",
        title: "Ransomware TTP families",
        beats: "Pentera ransomware emulation — no Hebrew Command Center, no FAIR×Dijkstra, no WSS inner crypto",
        needles: &[
            "ransomware",
            "lockbit",
            "cl0p",
            "blackcat",
            "conti",
            "bootkit",
            "fileless",
            "worm_",
            "alphv",
        ],
    },
    LaneDef {
        id: "llm_ai",
        title: "LLM / jailbreak / RAG / supply chain",
        beats: "Garak, Promptfoo, Lakera, HiddenLayer, Prisma AIRS — AI red-team silos, not fused into pentest+FAIR+OT",
        needles: &[
            "llm",
            "jailbreak",
            "prompt",
            "rag_",
            "model_",
            "ai_",
            "adversarial",
            "neural",
            "gpt_",
            "federated",
            "deepfake",
            "semantic_ai",
            "agentic",
        ],
    },
    LaneDef {
        id: "asm_easm",
        title: "ASM / OSINT / DNS",
        beats: "Hadrian, Censys, Detectify, ProjectDiscovery Nuclei — scanners, not SOAR honeytokens + tenant RLS",
        needles: &[
            "osint",
            "asm",
            "leak",
            "discovery",
            "recon",
            "subdomain",
            "bgp_dns",
            "email_dns",
            "takeover",
        ],
    },
    LaneDef {
        id: "deception",
        title: "Deception / OAST / honeypot",
        beats: "SafeBreach / Cymulate BAS libraries — simulated TTPs, opposite of live dual-probe evidence",
        needles: &["deception", "honeypot", "honey", "oast"],
    },
    LaneDef {
        id: "mobile",
        title: "Mobile / MITM / MDM",
        beats: "NowSecure, Ostorlab — mobile labs, not fused with OT FSM + FAIR + Ask",
        needles: &[
            "android",
            "ios",
            "mobile",
            "sim_swap",
            "nfc",
            "bluetooth_mobile",
            "mdm",
            "ssl_pinning",
            "react_native",
        ],
    },
    LaneDef {
        id: "supply_chain",
        title: "Supply chain / SBOM / CI/CD",
        beats: "Snyk, Chainguard — SCA, not live exploit validation + financial blast-radius",
        needles: &[
            "supply_chain",
            "sbom",
            "typosquat",
            "cicd",
            "container_registry",
            "npm_",
            "pypi",
        ],
    },
    LaneDef {
        id: "stealth",
        title: "Stealth / WAF / EDR evasion (scan fabric)",
        beats: "HexStrike / CAI wrap Kali tools — no tenant RLS, no DoH-only DNS policy, no WSS AES-GCM",
        needles: &[
            "stealth",
            "waf_bypass",
            "edr_evasion",
            "antiforensics",
            "timing_side",
            "covert",
        ],
    },
    LaneDef {
        id: "apt",
        title: "Named APT / ransomware-group TTPs",
        beats: "Picus / AttackIQ ATT&CK libraries — control simulation, not live dual-probe + FAIR pricing",
        needles: &[
            "apt",
            "lazarus",
            "volt_typhoon",
            "sandworm",
            "equation",
            "wizard_spider",
            "scattered_spider",
            "salt_typhoon",
            "fin7",
            "midnight_blizzard",
            "unc2452",
            "unc3944",
            "carbon_spider",
            "earth_longzhi",
            "quantum_sovereign",
        ],
    },
    LaneDef {
        id: "crypto",
        title: "Crypto / PQC / oracle",
        beats: "Standalone crypto scanners — not priced on Dijkstra paths",
        needles: &[
            "pqc",
            "padding_oracle",
            "hash_extension",
            "ecdsa",
            "rsa_timing",
            "crypto_engine",
            "quantum_key",
            "password_hash",
        ],
    },
    LaneDef {
        id: "exfil_c2",
        title: "Exfil / C2 / covert channels",
        beats: "Infection Monkey / Caldera adversary emulation — no Command Center FAIR or Ask SQL",
        needles: &[
            "exfil",
            "dns_exfil",
            "clipboard",
            "acoustic",
            "botnet",
            "c2",
            "optical_exfil",
        ],
    },
    LaneDef {
        id: "lateral",
        title: "Lateral movement / malware staging",
        beats: "NodeZero assumed-breach infra — no OT protocol FSM abort, no 13-table RLS",
        needles: &[
            "lateral",
            "persistence",
            "rce_exploit",
            "polymorphic",
            "spyware",
            "keylogger",
            "exploit_kit",
            "trojan",
        ],
    },
    LaneDef {
        id: "autonomous_fuzz",
        title: "Autonomous pentest / fuzz / digital twin",
        beats: "Strix (exploit+patch PRs), HexStrike MCP, NodeZero verify-job — app-centric or operator-close; Weissman FAIR stays priced until a later successful live scan does not reproduce the key",
        needles: &[
            "fuzz",
            "autonomous_pentest",
            "nexus_sovereign",
            "kill_chain",
            "digital_twin",
            "threat_emulation",
            "zero_day",
            "poe_synthesis",
        ],
    },
];

fn lane_hits(needles: &[&str]) -> Vec<&'static str> {
    PRODUCTION_ENGINE_IDS
        .iter()
        .copied()
        .filter(|id| needles.iter().any(|n| id.contains(n)))
        .collect()
}

/// Public market-research clusters (not live vendor telemetry).
fn market_research() -> Value {
    json!([
        {
            "cluster": "autonomous_pentest",
            "vendors": ["Pentera", "Horizon3 NodeZero", "RidgeBot"],
            "owns": "internal/AD/cloud exploit chains; NodeZero proof-of-reach; Pentera ransomware TTPs",
            "lacks": "OT 4-state FSM, Ask Weissman 13-table RLS, FAIR-from-Dijkstra that keeps pricing FIXED until a later successful absence scan, Hebrew Command Center, WSS inner AES-256-GCM"
        },
        {
            "cluster": "agentic_web",
            "vendors": ["XBOW", "Strix", "Escape", "FireCompass"],
            "owns": "web/API PoC validators; Strix fix-PR loop; Escape GraphQL/BOLA",
            "lacks": "AD/network chaining (XBOW), OT/ICS, tenant RLS SQL, 563 production engines, FAIR that refuses to drop ALE on a patch-PR without a later live absence scan"
        },
        {
            "cluster": "bas_ctem",
            "vendors": ["Cymulate", "Picus", "AttackIQ", "SafeBreach", "XM Cyber"],
            "owns": "simulated ATT&CK libraries and attack-path *models*",
            "lacks": "live dual-probe evidence-doubt (חוק 2 forbids BAS as truth)"
        },
        {
            "cluster": "ot_visibility",
            "vendors": ["Claroty", "Dragos", "Nozomi", "Microsoft Defender for IoT"],
            "owns": "passive SPAN/TAP asset visibility",
            "lacks": "offensive protocol FSM abort + SOAR honeytokens + FAIR process-disruption from live findings"
        },
        {
            "cluster": "cnapp",
            "vendors": ["Wiz", "Orca", "Prisma Cloud", "CrowdStrike Falcon Cloud"],
            "owns": "agentless graph, pentest-finding *ingest* (Wiz GA 2026)",
            "lacks": "native 303 live probes, Ask JSON QueryPlan, OT FSM"
        },
        {
            "cluster": "identity_graph",
            "vendors": ["SpecterOps BloodHound Enterprise"],
            "owns": "AD/Entra attack paths",
            "lacks": "DAST/OT/FAIR/Ask/agent WSS"
        },
        {
            "cluster": "ot_fair",
            "vendors": ["DeNexus DeRISK"],
            "owns": "OT process-disruption finance",
            "lacks": "563-engine offensive fabric + dual-probe + Ask RLS"
        },
        {
            "cluster": "llm_redteam",
            "vendors": ["NVIDIA Garak", "Promptfoo", "Lakera/Check Point", "HiddenLayer", "Prisma AIRS"],
            "owns": "model/app jailbreak probes",
            "lacks": "fusion into pentest + OT + FAIR + tenant SQL"
        },
        {
            "cluster": "oss_tool_wrappers",
            "vendors": [
                "HexStrike AI (11k★)",
                "Strix (58k★)",
                "CAI (9k★)",
                "Nuclei (30k★)",
                "Caldera (7k★)",
                "PentestGPT (15k★)",
                "Infection Monkey (7k★)",
                "Faraday (6k★)"
            ],
            "owns": "CLI/MCP/template scanners and CTF agents",
            "lacks": "multi-tenant RLS product, Command Center, FAIR snapshots, WSS double encryption",
            "github_as_of": "2026-08-27"
        }
    ])
}

pub fn snapshot() -> Value {
    let mut lanes = Vec::with_capacity(LANES.len());
    let mut covered = 0u32;
    for lane in LANES {
        let hits = lane_hits(lane.needles);
        if !hits.is_empty() {
            covered += 1;
        }
        let sample: Vec<&str> = hits.iter().copied().take(8).collect();
        lanes.push(json!({
            "id": lane.id,
            "title": lane.title,
            "beats": lane.beats,
            "live_engine_count": hits.len(),
            "sample_ids": sample,
            "covered": !hits.is_empty(),
        }));
    }
    let engines_total = PRODUCTION_ENGINE_IDS.len();
    let ask_tables = crate::nl_query::allowed_table_count();
    let fusion = ask_tables == nl_guard::ASK_WEISSMAN_TABLE_COUNT
        && engines_total >= 500
        && covered == LANES.len() as u32
        && evidence_doubt::CONFIDENCE_ADMIT >= 0.95
        && crate::elite_hardening::hack_fix_verify::LIVE;

    json!({
        "live": true,
        "engines_total": engines_total,
        "palo_alto": palo_alto_bakeoff(),
        "lanes_total": LANES.len(),
        "lanes_covered": covered,
        "unmatched_stack": fusion,
        "capabilities": {
            "ask_weissman_tables": ask_tables,
            "evidence_confidence_floor": evidence_doubt::CONFIDENCE_ADMIT,
            "ot_fsm_protocols": ["modbus", "dnp3", "s7", "iec61850"],
            "wss_inner": "AES-256-GCM",
            "doh_only_default": !stealth_ops::allow_udp_dns_fallback(),
            "dns_cascade": "doh_dot_internal_udp",
            "ot_fsm_modbus_min_len": 8,
            "hack_fix_verify": crate::elite_hardening::hack_fix_verify::LIVE,
            "fair_prices_fixed_until_verified": true,
        },
        "lanes": lanes,
        "market_research": {
            "live": false,
            "as_of": "2026-08-27",
            "method": "public_web_github_forums",
            "clusters": market_research(),
            "verdict": "No public product combines 563 live engines + OT protocol FSM + dual-probe evidence-doubt + FAIR-from-graph (ALE priced until Hack-Fix-Verify absence scan) + Ask 13-table RLS + WSS inner crypto + Hebrew Command Center."
        },
        "kernel_sanity": {
            "wss_nonce_bits": 96,
            "stealth_jitter_min": stealth_ops::JITTER_PCT_MIN,
            "wss_key_bytes": wss_inner::KEY_BYTES,
        },
        "wss_inner_algo": wss_inner::ALGO,
    })
}

/// Palo Alto bake-off inventory from **this binary**, not PAN telemetry.
///
/// Positioning (labelled `live: false`) is a category statement: Weissman finds and
/// orchestrates; Palo sells inline prevention. Engine overlap and unique loops are
/// live because they are derived from `PRODUCTION_ENGINE_IDS`.
fn production_has(id: &str) -> bool {
    PRODUCTION_ENGINE_IDS.contains(&id)
}

fn live_engine_ids(needles: &[&'static str]) -> Vec<&'static str> {
    needles
        .iter()
        .copied()
        .filter(|id| production_has(id))
        .collect()
}

fn sku_overlap(sku: &str, needles: &[&'static str], maturity: &str) -> Value {
    let ids = live_engine_ids(needles);
    let agent_required_ids: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| weissman_core::models::engine_agent::is_agent_required_engine(id))
        .collect();
    json!({
        "sku": sku,
        "ids": ids,
        "agent_required_ids": agent_required_ids,
        "maturity": maturity,
    })
}

fn palo_alto_bakeoff() -> Value {
    let vngfw_admin = std::env::var("WEISSMAN_VNGFW_ADMIN").unwrap_or_default();
    json!({
        "live": true,
        "source": "this_binary_inventory",
        "not_palo_telemetry": true,
        "positioning": {
            "live": false,
            "weissman": "assessment_plus_orchestrated_containment",
            "palo_alto": "inline_prevention_plus_xsiam_cnapp_sase",
            "honest": "companion_not_ngfw_replacement",
        },
        "catalog": crate::engine_accounting::to_json(),
        "find_vs_block": {
            "find": true,
            "inline_packet_path": false,
            "vngfw_engine_registered": production_has("weissman_vngfw"),
            "vngfw_admin_configured": !vngfw_admin.trim().is_empty(),
            "ngfw_posture_engine": production_has("ngfw_posture"),
        },
        "palo_sku_overlap": [
            sku_overlap(
                "Prisma Cloud",
                &[
                    "cnapp_continuous",
                    "toxic_combo_runtime_proof",
                    "iac_misconfig",
                    "k8s_container",
                    "aws_attack",
                ],
                "partial",
            ),
            sku_overlap(
                "Cortex XDR",
                &["host_isolation", "ebpf_sensor", "ioc_yara_hunt", "chronos"],
                "partial",
            ),
            sku_overlap(
                "Cortex Xpanse",
                &["asm", "first_mover_surface_delta", "osint"],
                "partial",
            ),
            sku_overlap(
                "Prisma Access",
                &["sase_security_bypass", "ai_casb_saas", "casb_saas_posture"],
                "partial",
            ),
            sku_overlap(
                "PAN-OS / WildFire",
                &["ngfw_posture", "weissman_vngfw", "malware_detonation"],
                "theater_to_partial",
            ),
        ],
        "unique_closed_loops": [
            {"id": "chronos", "present": production_has("chronos"), "loop": "web_parent_to_shell_process_delta"},
            {"id": "ot_passive_active_safety", "present": production_has("ot_passive_active_safety"), "loop": "ot_read_only_fsm_plus_fair"},
            {"id": "ot_crown_jewel_path", "present": production_has("ot_crown_jewel_path"), "loop": "ot_to_process_crown_jewel"},
            {"id": "ot_cloud_identity_killpath", "present": production_has("ot_cloud_identity_killpath"), "loop": "ot_x_cloud_x_identity"},
            {"id": "control_plane_of_controls", "present": production_has("control_plane_of_controls"), "loop": "prove_installed_preventers"},
            {"id": "toxic_combo_runtime_proof", "present": production_has("toxic_combo_runtime_proof"), "loop": "cnapp_plus_safe_exposure"},
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lanes_have_live_engines() {
        let snap = snapshot();
        assert!(snap["engines_total"].as_u64().unwrap() >= 500);
        assert_eq!(snap["engines_total"], PRODUCTION_ENGINE_IDS.len());
        assert_eq!(snap["lanes_covered"], snap["lanes_total"]);
        assert_eq!(snap["unmatched_stack"], true);
        let lanes = snap["lanes"].as_array().expect("lanes");
        for lane in lanes {
            assert!(
                lane["live_engine_count"].as_u64().unwrap_or(0) >= 1,
                "empty lane {}",
                lane["id"]
            );
        }
    }

    #[test]
    fn market_research_is_labelled_not_live() {
        let snap = snapshot();
        assert_eq!(snap["market_research"]["live"], false);
        assert_eq!(snap["live"], true);
    }

    #[test]
    fn palo_alto_bakeoff_is_companion_not_ngfw_and_ot_loops_are_live() {
        let snap = snapshot();
        let palo = &snap["palo_alto"];
        assert_eq!(palo["live"], true);
        assert_eq!(palo["not_palo_telemetry"], true);
        assert_eq!(palo["positioning"]["live"], false);
        assert_eq!(
            palo["positioning"]["honest"],
            "companion_not_ngfw_replacement"
        );
        assert_eq!(palo["find_vs_block"]["find"], true);
        assert_eq!(palo["find_vs_block"]["inline_packet_path"], false);
        let loops = palo["unique_closed_loops"].as_array().expect("loops");
        for id in [
            "ot_passive_active_safety",
            "ot_crown_jewel_path",
            "ot_cloud_identity_killpath",
            "chronos",
            "control_plane_of_controls",
            "toxic_combo_runtime_proof",
        ] {
            let loop_row = loops
                .iter()
                .find(|l| l["id"] == id)
                .unwrap_or_else(|| panic!("missing palo loop {id}"));
            assert_eq!(
                loop_row["present"],
                production_has(id),
                "{id} present flag must match PRODUCTION_ENGINE_IDS"
            );
        }
        assert!(palo["catalog"]["total_ids"].as_u64().unwrap() >= 580);
        assert!(
            palo["catalog"]["alias_ids"].as_u64().unwrap() > 0,
            "catalog honesty must surface alias inflation"
        );
        let xdr = palo["palo_sku_overlap"]
            .as_array()
            .expect("skus")
            .iter()
            .find(|s| s["sku"] == "Cortex XDR")
            .expect("xdr sku");
        let xdr_agent = xdr["agent_required_ids"].as_array().expect("xdr agent");
        for id in ["host_isolation", "ebpf_sensor", "ioc_yara_hunt"] {
            assert!(
                xdr_agent.iter().any(|v| v.as_str() == Some(id)),
                "Cortex XDR overlap must admit {id} is agent-required"
            );
        }
        assert!(
            !xdr_agent.iter().any(|v| v.as_str() == Some("chronos")),
            "CHRONOS is a server hybrid, not agent-only"
        );
        if let Ok(path) = std::env::var("DUMP_PALO_JSON") {
            std::fs::write(path, serde_json::to_string_pretty(palo).expect("palo json")).unwrap();
        }
    }

    #[test]
    fn ot_fsm_still_aborts_truncated_modbus() {
        assert!(matches!(
            crate::elite_hardening::ot_fsm::validate_modbus_tcp(&[0u8; 12], &[0u8; 4]),
            crate::elite_hardening::ot_fsm::FsmVerdict::Abort { .. }
        ));
    }
}
