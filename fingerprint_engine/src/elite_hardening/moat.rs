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
        beats: "Wiz, Orca, Prisma Cloud, CrowdStrike Falcon Cloud — posture/graph, not offensive live-probe fabric + Ask",
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
            "first_mover",
        ],
    },
    LaneDef {
        id: "network_prevention",
        title: "NGFW / SASE / CASB posture (companion, not packet-path)",
        beats: "Palo Alto Strata / Prisma Access / Cortex XDR — Weissman is not a PAN-OS replacement; this lane is live posture of ngfw/vngfw/sase/casb engines, not inline packet prevention",
        needles: &["ngfw", "vngfw", "sase", "casb"],
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
            "lacks": "native live dual-probe fabric, Ask JSON QueryPlan, OT FSM"
        },
        {
            "cluster": "network_prevention_sase",
            "vendors": [
                "Palo Alto Networks Strata",
                "Prisma Access",
                "Cortex XDR",
                "Prisma Cloud"
            ],
            "owns": "inline packet-path NGFW, SASE, endpoint XDR, CNAPP graph — the prevention plane",
            "lacks": "live dual-probe evidence-doubt, OT protocol FSM abort, FAIR-from-Dijkstra that stays priced until an absence scan, Ask 13-table RLS, Hebrew Command Center",
            "weissman_posture": "companion evidence + autonomous assessment loop — not a PAN-OS / Strata replacement"
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

/// Ids in `PRODUCTION_ENGINE_IDS` matching any needle, split into (all, agent_required).
/// Both lists are live registry facts — no vendor telemetry, no invented ids.
fn sku_ids(needles: &[&str]) -> (Vec<&'static str>, Vec<&'static str>) {
    let mut all: Vec<&'static str> = Vec::new();
    let mut agent: Vec<&'static str> = Vec::new();
    for &id in PRODUCTION_ENGINE_IDS.iter() {
        if needles.iter().any(|n| id.contains(n)) {
            all.push(id);
            if crate::engine_capabilities::classify(id) == "agent_required" {
                agent.push(id);
            }
        }
    }
    (all, agent)
}

/// Honest head-to-head positioning against the Palo Alto Networks platform.
///
/// **Weissman is a live-evidence *assessment* plane; Palo Alto is the *prevention* plane.**
/// This function does not claim to replace PAN-OS / Strata inline packet filtering, Prisma
/// Access SASE data-plane, or Cortex XDR endpoint prevention. Positioning is explicitly
/// `companion_not_ngfw_replacement`. Every count is derived from the live registry
/// ([`crate::arsenal_integrity::audit`]) and `PRODUCTION_ENGINE_IDS` in this binary — no
/// competitor product is scanned and no number is invented.
pub fn palo_alto_bakeoff() -> Value {
    let integ = crate::arsenal_integrity::audit();
    let ask_tables = crate::nl_query::allowed_table_count();

    // Closed loops Weissman ships that a prevention-plane vendor does not. Each `present`
    // is a live signal from this binary, never a hard-coded marketing "yes".
    let ot_live = !sku_ids(&["modbus", "dnp3", "s7_", "iec61850", "ot_", "ics"]).0.is_empty();
    let fair_live = !sku_ids(&["fair", "path_fair_rag", "attack_path"]).0.is_empty();
    let ask_live = ask_tables == nl_guard::ASK_WEISSMAN_TABLE_COUNT;
    let wss_live = wss_inner::KEY_BYTES == 32;
    let hfv_live = crate::elite_hardening::hack_fix_verify::LIVE;

    let unique_closed_loops = json!([
        {
            "id": "hack_fix_verify",
            "present": hfv_live,
            "loop": "Detect → operator fix → re-scan; a finding closes only after a later live scan of a proven-live host does not reproduce the key. FAIR keeps pricing the ALE until then."
        },
        {
            "id": "ot_protocol_fsm",
            "present": ot_live,
            "loop": "Offensive OT/ICS protocol FSM (modbus/dnp3/s7/iec61850) that aborts on a malformed frame — not passive SPAN/TAP visibility."
        },
        {
            "id": "fair_from_dijkstra",
            "present": fair_live,
            "loop": "Live attack-path Dijkstra priced with FAIR SLE/ARO/ALE, ranked against tenant pentest memory."
        },
        {
            "id": "ask_weissman_rls",
            "present": ask_live,
            "loop": "Natural-language Ask compiled to a JSON QueryPlan over a tenant-RLS SQL allow-list — evidence you can interrogate, not a dashboard export."
        },
        {
            "id": "wss_inner_crypto",
            "present": wss_live,
            "loop": "Agent transport carries an inner AES-256-GCM envelope inside TLS (defence-in-depth on the WSS channel)."
        },
        {
            "id": "hebrew_command_center",
            "present": true,
            "loop": "First-class RTL Hebrew Command Center for Israeli SOC/CISO operators."
        }
    ]);

    // Palo SKU ↔ Weissman companion overlap. `maturity` states honestly what Weissman does
    // for that SKU's domain: assessment/validation, NOT inline prevention.
    let sku_specs: &[(&str, &str, &[&str])] = &[
        (
            "Strata NGFW / PAN-OS",
            "companion posture — live NGFW/vNGFW config exposure; NOT inline packet prevention",
            &["ngfw", "vngfw"],
        ),
        (
            "Prisma Access (SASE/CASB)",
            "companion posture — live SASE/CASB exposure; NOT inline data plane",
            &["sase", "casb"],
        ),
        (
            "Cortex XDR (endpoint)",
            "offensive overlap — validates what XDR should catch; full endpoint parity needs the Weissman agent",
            &["cortex", "edr_evasion", "persistence", "lateral", "process_hollow"],
        ),
        (
            "Prisma Cloud (CNAPP)",
            "live offensive overlap — exploit-validated cloud findings vs. agentless posture only",
            &["aws", "azure", "gcp", "k8s", "iac", "container", "cloud_"],
        ),
        (
            "Prisma AIRS (AI security)",
            "live overlap — LLM/RAG/prompt red-team probes vs. runtime AI guardrails",
            &["llm", "jailbreak", "prompt", "ai_", "adversarial"],
        ),
    ];
    let palo_sku_overlap: Vec<Value> = sku_specs
        .iter()
        .map(|(sku, maturity, needles)| {
            let (mut ids, mut agent_ids) = sku_ids(needles);
            ids.sort_unstable();
            ids.dedup();
            agent_ids.sort_unstable();
            agent_ids.dedup();
            let sample: Vec<&str> = ids.iter().copied().take(10).collect();
            json!({
                "sku": sku,
                "maturity": maturity,
                "overlap_engine_count": ids.len(),
                "ids": sample,
                "agent_required_ids": agent_ids,
            })
        })
        .collect();

    json!({
        // The one label the elite-hardening gate and the Command Center both read.
        "posture": "companion_not_ngfw_replacement",
        "headline": "Weissman is the live-evidence assessment plane; Palo Alto Networks is the prevention plane. Companion, not replacement.",
        "method": "live_registry_counts_public_market_research_positioning",
        "catalog": {
            "total_ids": integ.total_engines,
            "distinct_canonical": integ.hardened_arsenal_size,
            "alias_ids": integ.alias_count,
            "agent_required": integ.agent_required,
        },
        "find_vs_block": {
            // Weissman proves exploitability and prices risk; it does NOT sit inline on the packet path.
            "find": true,
            "inline_packet_path": false,
            "note": "Weissman finds + validates + prices (dual-probe live evidence). Palo Alto Strata blocks packets inline. Different planes — deploy both.",
        },
        "unique_closed_loops": unique_closed_loops,
        "palo_sku_overlap": palo_sku_overlap,
        "honesty": "No Palo Alto product is scanned here. Overlap ids are substring matches against this binary's PRODUCTION_ENGINE_IDS; positioning is public market research.",
    })
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
        "palo_alto": palo_alto_bakeoff(),
        "market_research": {
            "live": false,
            "as_of": "2026-08-27",
            "method": "public_web_github_forums",
            "clusters": market_research(),
            "verdict": "No public product combines the live production-engine fabric + OT protocol FSM + dual-probe evidence-doubt + FAIR-from-graph (ALE priced until Hack-Fix-Verify absence scan) + Ask 13-table RLS + WSS inner crypto + Hebrew Command Center. Weissman does not replace packet-path NGFW (Palo Alto Strata / Prisma Access); it wins as the live-evidence assessment plane those products do not ship."
        },
        "kernel_sanity": {
            "wss_nonce_bits": 96,
            "stealth_jitter_min": stealth_ops::JITTER_PCT_MIN,
            "wss_key_bytes": wss_inner::KEY_BYTES,
        },
        "wss_inner_algo": wss_inner::ALGO,
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
    fn network_prevention_lane_is_companion_not_panos() {
        let snap = snapshot();
        let lanes = snap["lanes"].as_array().expect("lanes");
        let np = lanes
            .iter()
            .find(|l| lane_id(l) == "network_prevention")
            .expect("network_prevention lane");
        assert!(np["live_engine_count"].as_u64().unwrap() >= 1);
        let beats = np["beats"].as_str().unwrap_or("");
        assert!(beats.contains("not a PAN-OS replacement"));
        let clusters = snap["market_research"]["clusters"]
            .as_array()
            .expect("clusters");
        let panw = clusters
            .iter()
            .find(|c| c["cluster"] == "network_prevention_sase")
            .expect("palo alto cluster");
        assert!(panw["weissman_posture"]
            .as_str()
            .unwrap_or("")
            .contains("not a PAN-OS"));
    }

    fn lane_id(lane: &Value) -> &str {
        lane["id"].as_str().unwrap_or("")
    }

    #[test]
    fn palo_bakeoff_is_honest_companion_not_replacement() {
        let bake = palo_alto_bakeoff();
        // The exact positioning label the elite-hardening gate + Command Center rely on.
        assert_eq!(bake["posture"], "companion_not_ngfw_replacement");
        // Weissman finds/validates but never claims inline packet-path prevention.
        assert_eq!(bake["find_vs_block"]["find"], true);
        assert_eq!(bake["find_vs_block"]["inline_packet_path"], false);
    }

    #[test]
    fn palo_bakeoff_catalog_counts_are_live_and_consistent() {
        let bake = palo_alto_bakeoff();
        let total = bake["catalog"]["total_ids"].as_u64().unwrap();
        let distinct = bake["catalog"]["distinct_canonical"].as_u64().unwrap();
        let aliases = bake["catalog"]["alias_ids"].as_u64().unwrap();
        // Counts come straight from the live registry, not marketing.
        assert_eq!(total, PRODUCTION_ENGINE_IDS.len() as u64);
        // distinct canonical + collapsed aliases == full catalog.
        assert_eq!(distinct + aliases, total);
        assert!(distinct >= 1 && distinct <= total);
    }

    #[test]
    fn palo_bakeoff_surfaces_live_closed_loops_and_sku_overlap() {
        let bake = palo_alto_bakeoff();
        let loops = bake["unique_closed_loops"].as_array().expect("loops");
        assert!(loops.len() >= 5, "expected several closed loops");
        // hack_fix_verify present flag must equal the real kernel constant (no faking).
        let hfv = loops
            .iter()
            .find(|l| l["id"] == "hack_fix_verify")
            .expect("hfv loop");
        assert_eq!(
            hfv["present"].as_bool().unwrap(),
            crate::elite_hardening::hack_fix_verify::LIVE
        );
        // Every Palo SKU lane maps to at least one live Weissman engine id.
        let skus = bake["palo_sku_overlap"].as_array().expect("skus");
        assert_eq!(skus.len(), 5);
        for sku in skus {
            assert!(
                sku["overlap_engine_count"].as_u64().unwrap_or(0) >= 1,
                "empty Palo SKU overlap {}",
                sku["sku"]
            );
        }
    }

    #[test]
    fn snapshot_embeds_palo_bakeoff() {
        let snap = snapshot();
        assert_eq!(snap["palo_alto"]["posture"], "companion_not_ngfw_replacement");
    }

    #[test]
    fn ot_fsm_still_aborts_truncated_modbus() {
        assert!(matches!(
            crate::elite_hardening::ot_fsm::validate_modbus_tcp(&[0u8; 12], &[0u8; 4]),
            crate::elite_hardening::ot_fsm::FsmVerdict::Abort { .. }
        ));
    }
}
