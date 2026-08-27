//! MITRE ATT&CK coverage map (Detection-as-Code).
//!
//! A declarative matrix mapping the platform's production engine fleet to the ATT&CK
//! techniques each engine surfaces, grouped by tactic. Exposed at `/api/attack-coverage`
//! so a SOC / CISO sees a live, evidence-backed coverage matrix — "which adversary
//! techniques can Weissman detect, and with which engines" — plus per-tactic rollups.
//!
//! Every entry is backed by a real engine (the technique ID is what that engine emits in
//! its findings' `mitre_attack` field). This is curated against the actual engine
//! implementations, not aspirational.

use serde_json::{json, Value};

pub struct Technique {
    pub id: &'static str,
    pub name: &'static str,
    pub tactic: &'static str,
    pub engines: &'static [&'static str],
}

/// The platform's ATT&CK coverage, curated from the live engine implementations.
pub const COVERAGE: &[Technique] = &[
    // ── Reconnaissance ──────────────────────────────────────────────────────
    Technique {
        id: "T1595",
        name: "Active Scanning",
        tactic: "Reconnaissance",
        engines: &["asm", "discovery_engine", "network_baseline_anomaly"],
    },
    Technique {
        id: "T1592",
        name: "Gather Victim Host Information",
        tactic: "Reconnaissance",
        engines: &["osint", "asm"],
    },
    Technique {
        id: "T1589",
        name: "Gather Victim Identity Information",
        tactic: "Reconnaissance",
        engines: &["leak_hunter", "osint"],
    },
    Technique {
        id: "T1596",
        name: "Search Open Technical Databases",
        tactic: "Reconnaissance",
        engines: &["iot_shodan_scan", "darkweb_intel"],
    },
    // ── Resource Development ────────────────────────────────────────────────
    Technique {
        id: "T1588.005",
        name: "Obtain Capabilities: Exploits",
        tactic: "Resource Development",
        engines: &["exploit_synthesis_engine", "model_inversion_attack"],
    },
    Technique {
        id: "T1583.003",
        name: "Acquire Infrastructure: Virtual Private Server",
        tactic: "Resource Development",
        engines: &["multi_cloud_pivot"],
    },
    // ── Initial Access ──────────────────────────────────────────────────────
    Technique {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        engines: &[
            "advanced_web_engines",
            "graphql_attack",
            "ssrf_advanced",
            "xxe",
            "ssti",
            "file_upload",
            "deserialization_net",
            "apt28_techniques",
            "iot_firmware",
            "scada_ics",
        ],
    },
    Technique {
        id: "T1566",
        name: "Phishing",
        tactic: "Initial Access",
        engines: &["spear_phishing_engine", "vishing_engine", "smishing_engine"],
    },
    Technique {
        id: "T1133",
        name: "External Remote Services",
        tactic: "Initial Access",
        engines: &["kerberoasting", "rdp_attack_engine", "iot_firmware"],
    },
    Technique {
        id: "T1078",
        name: "Valid Accounts",
        tactic: "Initial Access",
        engines: &[
            "mfa_bypass_engine",
            "zero_trust_bypass",
            "midnight_blizzard_ttps",
        ],
    },
    Technique {
        id: "T1195",
        name: "Supply Chain Compromise",
        tactic: "Initial Access",
        engines: &[
            "supply_chain",
            "npm_package_attack",
            "pypi_supply_chain",
            "docker_image_poison",
            "sbom_analyzer",
        ],
    },
    // ── Execution ───────────────────────────────────────────────────────────
    Technique {
        id: "T1059.008",
        name: "Command and Scripting Interpreter: Network/LLM",
        tactic: "Execution",
        engines: &[
            "llm_jailbreak",
            "prompt_injection_chain",
            "autonomous_ai_escape",
        ],
    },
    // ── Persistence ─────────────────────────────────────────────────────────
    Technique {
        id: "T1505.003",
        name: "Server Software Component: Web Shell",
        tactic: "Persistence",
        engines: &["file_upload", "rce_exploit_engine"],
    },
    Technique {
        id: "T1136",
        name: "Create Account",
        tactic: "Persistence",
        engines: &["identity_auto_harvest"],
    },
    // ── Privilege Escalation ────────────────────────────────────────────────
    Technique {
        id: "T1068",
        name: "Exploitation for Privilege Escalation",
        tactic: "Privilege Escalation",
        engines: &["cloud_iam_escalation", "kubernetes_rbac_escape"],
    },
    // ── Defense Evasion ─────────────────────────────────────────────────────
    Technique {
        id: "T1562",
        name: "Impair Defenses",
        tactic: "Defense Evasion",
        engines: &["edr_evasion", "waf_bypass"],
    },
    Technique {
        id: "T1556",
        name: "Modify Authentication Process",
        tactic: "Defense Evasion",
        engines: &[
            "mfa_bypass_engine",
            "padding_oracle_attack",
            "hash_extension_attack",
        ],
    },
    Technique {
        id: "T1606.001",
        name: "Forge Web Credentials: Web Cookies/JWT",
        tactic: "Defense Evasion",
        engines: &["identity_session_oauth", "jwt_attack"],
    },
    // ── Credential Access ───────────────────────────────────────────────────
    Technique {
        id: "T1558.003",
        name: "Steal/Forge Kerberos Tickets: Kerberoasting",
        tactic: "Credential Access",
        engines: &["kerberoasting", "kerberos_attack_suite"],
    },
    Technique {
        id: "T1110",
        name: "Brute Force",
        tactic: "Credential Access",
        engines: &["password_spray", "credential_stuffing"],
    },
    Technique {
        id: "T1552",
        name: "Unsecured Credentials",
        tactic: "Credential Access",
        engines: &[
            "aws_attack",
            "secrets_manager_attack",
            "leak_hunter",
            "ai_supply_chain_attack",
        ],
    },
    Technique {
        id: "T1539",
        name: "Steal Web Session Cookie",
        tactic: "Credential Access",
        engines: &["session_fixation_adv", "identity_session_oauth"],
    },
    Technique {
        id: "T1557.001",
        name: "Adversary-in-the-Middle: LLMNR/NBT-NS/NTLM Relay",
        tactic: "Credential Access",
        engines: &["smb_netbios", "kerberoasting"],
    },
    // ── Discovery ───────────────────────────────────────────────────────────
    Technique {
        id: "T1046",
        name: "Network Service Discovery",
        tactic: "Discovery",
        engines: &["asm", "snmp_exploitation", "ot_ics", "kerberoasting"],
    },
    Technique {
        id: "T1087.002",
        name: "Account Discovery: Domain Account",
        tactic: "Discovery",
        engines: &["kerberoasting", "ldap_injection_engine"],
    },
    // ── Lateral Movement ────────────────────────────────────────────────────
    Technique {
        id: "T1021.001",
        name: "Remote Services: RDP",
        tactic: "Lateral Movement",
        engines: &["rdp_attack_engine", "lateral_movement_engine"],
    },
    Technique {
        id: "T1021.002",
        name: "Remote Services: SMB",
        tactic: "Lateral Movement",
        engines: &["smb_netbios", "worm_propagation"],
    },
    Technique {
        id: "T1210",
        name: "Exploitation of Remote Services",
        tactic: "Lateral Movement",
        engines: &["equation_group_ttps", "worm_propagation"],
    },
    // ── Collection ──────────────────────────────────────────────────────────
    Technique {
        id: "T1213",
        name: "Data from Information Repositories",
        tactic: "Collection",
        engines: &["swagger_abuse", "odata_injection", "soap_injection"],
    },
    // ── Command and Control ─────────────────────────────────────────────────
    Technique {
        id: "T1071",
        name: "Application Layer Protocol",
        tactic: "Command and Control",
        engines: &[
            "network_covert_channel",
            "https_c2_masquerade",
            "advanced_c2_covert_exfil",
        ],
    },
    Technique {
        id: "T1071.004",
        name: "Application Layer Protocol: DNS",
        tactic: "Command and Control",
        engines: &[
            "botnet_c2_engine",
            "dns_tunneling_c2",
            "advanced_c2_covert_exfil",
        ],
    },
    Technique {
        id: "T1090.003",
        name: "Proxy: Multi-hop Proxy (Tor)",
        tactic: "Command and Control",
        engines: &["tor_exit_attack", "advanced_c2_covert_exfil"],
    },
    Technique {
        id: "T1095",
        name: "Non-Application Layer Protocol",
        tactic: "Command and Control",
        engines: &["icmp_covert", "advanced_c2_covert_exfil"],
    },
    Technique {
        id: "T1572",
        name: "Protocol Tunneling",
        tactic: "Command and Control",
        engines: &["dns_tunneling_c2", "advanced_c2_covert_exfil"],
    },
    Technique {
        id: "T1571",
        name: "Non-Standard Port",
        tactic: "Command and Control",
        engines: &["advanced_c2_covert_exfil"],
    },
    Technique {
        id: "T1027.003",
        name: "Obfuscated Files or Information: Steganography",
        tactic: "Defense Evasion",
        engines: &["steganography_c2", "advanced_c2_covert_exfil"],
    },
    // ── Exfiltration ────────────────────────────────────────────────────────
    Technique {
        id: "T1041",
        name: "Exfiltration Over C2 Channel",
        tactic: "Exfiltration",
        engines: &[
            "http_covert_exfil",
            "cloud_exfil_engine",
            "advanced_c2_covert_exfil",
        ],
    },
    Technique {
        id: "T1567",
        name: "Exfiltration Over Web Service",
        tactic: "Exfiltration",
        engines: &["cloud_data_exfil", "database_exfil"],
    },
    // ── Impact ──────────────────────────────────────────────────────────────
    Technique {
        id: "T1486",
        name: "Data Encrypted for Impact (Ransomware)",
        tactic: "Impact",
        engines: &[
            "conti_ransomware_ttps",
            "lockbit_techniques",
            "blackcat_alphv_ttps",
            "cl0p_techniques",
        ],
    },
    Technique {
        id: "T1498",
        name: "Network Denial of Service",
        tactic: "Impact",
        engines: &["ntp_amplification", "llm_dos_attack"],
    },
    Technique {
        id: "T1499",
        name: "Endpoint Denial of Service",
        tactic: "Impact",
        engines: &["api_rate_limit_bypass"],
    },
    // ── Mobile (ATT&CK Mobile) ──────────────────────────────────────────────
    Technique {
        id: "T1416",
        name: "URI Hijacking (Mobile)",
        tactic: "Initial Access",
        engines: &["android_intent_attack", "ios_url_scheme_attack"],
    },
    Technique {
        id: "T1635",
        name: "Steal Application Access Token (Mobile)",
        tactic: "Credential Access",
        engines: &["mobile_banking_trojan"],
    },
];

/// Canonical ATT&CK Enterprise tactic order (for stable matrix rendering).
const TACTIC_ORDER: &[&str] = &[
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
];

#[must_use]
pub fn catalog() -> &'static [Technique] {
    COVERAGE
}

/// Look up a technique's curated metadata by ATT&CK id. Tries an exact match first, then falls
/// back to the base technique id (so a finding reporting `T1059` still resolves against a curated
/// sub-technique like `T1059.008`). Returns `None` for ids not in the catalog.
#[must_use]
pub fn lookup(id: &str) -> Option<&'static Technique> {
    if let Some(t) = COVERAGE.iter().find(|t| t.id == id) {
        return Some(t);
    }
    let base = id.split('.').next().unwrap_or(id);
    COVERAGE
        .iter()
        .find(|t| t.id.split('.').next() == Some(base))
}

/// `(tactic, technique_count)` rollup in canonical tactic order (covered tactics only).
#[must_use]
pub fn tactic_rollup() -> Vec<(&'static str, usize)> {
    TACTIC_ORDER
        .iter()
        .filter_map(|t| {
            let n = COVERAGE.iter().filter(|x| x.tactic == *t).count();
            if n > 0 {
                Some((*t, n))
            } else {
                None
            }
        })
        .collect()
}

/// Full coverage matrix as JSON for `/api/attack-coverage`.
#[must_use]
pub fn coverage_json() -> Value {
    let tactics: Vec<Value> = tactic_rollup()
        .into_iter()
        .map(|(tactic, count)| {
            let techniques: Vec<Value> = COVERAGE
                .iter()
                .filter(|t| t.tactic == tactic)
                .map(|t| {
                    json!({
                        "id": t.id,
                        "name": t.name,
                        "engines": t.engines,
                        "engine_count": t.engines.len(),
                    })
                })
                .collect();
            json!({ "tactic": tactic, "technique_count": count, "techniques": techniques })
        })
        .collect();
    json!({
        "framework": "MITRE ATT&CK",
        "tactics": tactics,
        "totals": {
            "techniques_covered": COVERAGE.len(),
            "tactics_covered": tactic_rollup().len(),
            "engine_references": COVERAGE.iter().map(|t| t.engines.len()).sum::<usize>(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_well_formed() {
        assert!(
            COVERAGE.len() >= 30,
            "coverage matrix should be substantial"
        );
        for t in COVERAGE {
            assert!(
                t.id.starts_with('T'),
                "technique id must be ATT&CK form: {}",
                t.id
            );
            assert!(!t.name.is_empty());
            assert!(
                !t.engines.is_empty(),
                "{} must map to at least one engine",
                t.id
            );
            assert!(
                TACTIC_ORDER.contains(&t.tactic),
                "unknown tactic: {}",
                t.tactic
            );
        }
    }

    #[test]
    fn rollup_sums_to_catalog_and_json_shapes() {
        let total: usize = tactic_rollup().iter().map(|(_, n)| n).sum();
        assert_eq!(total, COVERAGE.len());
        let j = coverage_json();
        assert_eq!(
            j["totals"]["techniques_covered"].as_u64().unwrap() as usize,
            COVERAGE.len()
        );
        assert!(
            j["tactics"].as_array().unwrap().len() >= 10,
            "broad tactic coverage"
        );
        assert_eq!(j["framework"], "MITRE ATT&CK");
    }
}
