//! The complete arsenal catalog — the system's authoritative inventory of *every* engine it has.
//!
//! Where [`crate::attack_coverage`] is a curated ATT&CK subset, this module enumerates the entire
//! production engine fleet from the canonical registry (`production_engine_ids`) and attaches, per
//! engine, exactly the metadata the platform can vouch for:
//!
//!   * **kind / remote_detection** — from [`crate::engine_capabilities`] (real_probe / alias /
//!     agent_required / special), so the operator knows what each engine actually does at runtime.
//!   * **agent_required / critical_infra / alias canonical** — authoritative flags from the registry.
//!   * **ATT&CK techniques + tactics** — inverted from the curated coverage map (best-effort; empty
//!     when the engine isn't mapped — never invented).
//!   * **category** — a transparent, rule-based grouping over the engine id using the registry's own
//!     category vocabulary. This is a heuristic aid for browsing, not an authoritative claim.
//!
//! Everything here is pure and deterministic. This is what makes the platform self-aware of its
//! full arsenal rather than a hand-picked slice of it.

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use weissman_core::models::engine::{production_engine_ids, resolve_engine_id};

/// Registry category vocabulary (mirrors `FULL_ENGINE_REGISTRY_ORDER` section headers).
pub const CATEGORIES: [&str; 12] = [
    "Recon & OSINT",
    "Web / API",
    "AI / LLM",
    "Cloud / Infra",
    "OT / ICS / IoT",
    "Mobile",
    "Stealth / Evasion",
    "Crypto / Identity",
    "Network / Protocol",
    "Supply Chain",
    "APT / Top-Tier",
    "Other",
];

fn has_any(id: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| id.contains(n))
}

/// Heuristic category for an engine id, using the registry's category vocabulary. Ordered
/// most-specific first so multi-keyword ids land in the most meaningful bucket. Best-effort by
/// design; the authoritative fields on each entry are `kind`, the flags, and `techniques`.
#[must_use]
pub fn category_of(id: &str) -> &'static str {
    if has_any(
        id,
        &[
            "apt",
            "ttps",
            "lazarus",
            "sandworm",
            "fin7",
            "conti",
            "lockbit",
            "blackcat",
            "alphv",
            "cl0p",
            "clop",
            "blizzard",
            "equation",
            "turla",
            "kimsuky",
            "ransomware",
            "actor",
        ],
    ) {
        return "APT / Top-Tier";
    }
    if has_any(
        id,
        &[
            "llm",
            "prompt",
            "ai_",
            "_ai",
            "model_",
            "_ml",
            "ml_",
            "rag",
            "agentic",
            "neural",
            "watermark",
            "deepfake",
            "inversion",
            "jailbreak",
            "adversarial",
        ],
    ) {
        return "AI / LLM";
    }
    if has_any(
        id,
        &[
            "aws",
            "azure",
            "gcp",
            "cloud",
            "kubernetes",
            "k8s",
            "docker",
            "container",
            "iac",
            "terraform",
            "s3_",
            "iam",
            "serverless",
            "lambda",
            "eks",
            "devops",
        ],
    ) {
        return "Cloud / Infra";
    }
    if has_any(
        id,
        &[
            "ot_",
            "_ot",
            "ics",
            "scada",
            "modbus",
            "bacnet",
            "iot",
            "firmware",
            "plc",
            "dnp3",
            "profinet",
            "rtu",
            "industrial",
        ],
    ) {
        return "OT / ICS / IoT";
    }
    if has_any(
        id,
        &[
            "supply_chain",
            "npm",
            "pypi",
            "sbom",
            "dependency",
            "package",
        ],
    ) {
        return "Supply Chain";
    }
    if has_any(
        id,
        &["android", "ios_", "mobile", "app_store", "apk", "smishing"],
    ) {
        return "Mobile";
    }
    if has_any(
        id,
        &[
            "jwt",
            "oauth",
            "oidc",
            "saml",
            "kerberos",
            "kerberoast",
            "ntlm",
            "crypto",
            "tls_",
            "_tls",
            "pki",
            "certificate",
            "cert_",
            "identity",
            "mfa",
            "password",
            "credential",
            "hash",
            "pqc",
            "padding_oracle",
            "session",
        ],
    ) {
        return "Crypto / Identity";
    }
    if has_any(
        id,
        &[
            "dns",
            "bgp",
            "arp",
            "smb",
            "netbios",
            "snmp",
            "network",
            "protocol",
            "packet",
            "rdp",
            "ftp",
            "smtp",
            "ntp",
            "tor",
            "proxy",
            "port",
            "bluetooth",
            "ble_",
            "rf",
            "wifi",
        ],
    ) {
        return "Network / Protocol";
    }
    if has_any(
        id,
        &[
            "evasion",
            "bypass",
            "stealth",
            "antiforensic",
            "anti_debug",
            "obfuscat",
            "av_bypass",
            "edr",
            "rootkit",
            "bootkit",
            "covert",
            "exfil",
        ],
    ) {
        return "Stealth / Evasion";
    }
    if has_any(
        id,
        &[
            "web",
            "api",
            "graphql",
            "http",
            "ssrf",
            "xxe",
            "ssti",
            "xss",
            "sql",
            "bola",
            "idor",
            "cache_poison",
            "smuggling",
            "cors",
            "csrf",
            "upload",
            "websocket",
            "deserial",
            "prototype_pollution",
            "rest",
            "soap",
            "odata",
            "swagger",
            "waf",
        ],
    ) {
        return "Web / API";
    }
    if has_any(
        id,
        &[
            "osint",
            "asm",
            "recon",
            "discovery",
            "leak",
            "darkweb",
            "shodan",
            "subdomain",
            "attack_surface",
            "brand",
            "impersonation",
            "footprint",
            "enum",
        ],
    ) {
        return "Recon & OSINT";
    }
    "Other"
}

/// Invert the curated ATT&CK coverage map to `engine_id -> (technique ids, tactics)`.
#[must_use]
pub fn engine_technique_map() -> BTreeMap<String, (Vec<String>, Vec<String>)> {
    let mut map: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    for t in crate::attack_coverage::catalog() {
        for eng in t.engines {
            let entry = map.entry((*eng).to_string()).or_default();
            if !entry.0.iter().any(|x| x == t.id) {
                entry.0.push(t.id.to_string());
            }
            if !entry.1.iter().any(|x| x == t.tactic) {
                entry.1.push(t.tactic.to_string());
            }
        }
    }
    map
}

/// One engine in the arsenal, with everything the platform authoritatively knows about it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ArsenalEntry {
    pub id: String,
    pub category: String,
    /// real_probe / alias / agent_required / special.
    pub kind: String,
    /// True when the engine detects from a remote scan with no endpoint agent.
    pub remote_detection: bool,
    pub agent_required: bool,
    pub critical_infra: bool,
    /// For aliases, the canonical engine this id resolves to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical: Option<String>,
    pub techniques: Vec<String>,
    pub tactics: Vec<String>,
}

/// Build the full arsenal catalog over every production engine id. Deterministic (registry order).
#[must_use]
pub fn catalog() -> Vec<ArsenalEntry> {
    let tech_map = engine_technique_map();
    production_engine_ids()
        .iter()
        .map(|&id| {
            let kind = crate::engine_capabilities::classify(id);
            let canonical = if kind == "alias" {
                Some(resolve_engine_id(id).to_string())
            } else {
                None
            };
            // Techniques are keyed on the canonical engine (aliases share detection logic).
            let key = canonical.clone().unwrap_or_else(|| id.to_string());
            let (techniques, tactics) = tech_map.get(&key).cloned().unwrap_or_default();
            ArsenalEntry {
                id: id.to_string(),
                category: category_of(id).to_string(),
                kind: kind.to_string(),
                remote_detection: crate::engine_capabilities::detects_remotely(kind, id),
                agent_required: weissman_core::models::engine_agent::is_agent_required_engine(id),
                critical_infra: crate::critical_infra::is_critical_infra_engine(id),
                canonical,
                techniques,
                tactics,
            }
        })
        .collect()
}

/// Summary rollups over the arsenal (counts by category and kind, plus totals).
#[must_use]
pub fn summary() -> Value {
    let entries = catalog();
    let mut by_category: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut mapped = 0usize;
    let mut agent = 0usize;
    let mut critical = 0usize;
    for e in &entries {
        *by_category.entry(e.category.clone()).or_insert(0) += 1;
        *by_kind.entry(e.kind.clone()).or_insert(0) += 1;
        if !e.techniques.is_empty() {
            mapped += 1;
        }
        if e.agent_required {
            agent += 1;
        }
        if e.critical_infra {
            critical += 1;
        }
    }
    json!({
        "ok": true,
        "engine_count": entries.len(),
        "attack_mapped_engines": mapped,
        "agent_required_engines": agent,
        "critical_infra_engines": critical,
        "by_category": by_category,
        "by_kind": by_kind,
        "engines": entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_covers_every_production_engine() {
        let entries = catalog();
        assert_eq!(entries.len(), production_engine_ids().len());
        assert!(
            entries.len() >= 300,
            "the arsenal should be large, got {}",
            entries.len()
        );
    }

    #[test]
    fn every_entry_is_classified_and_categorized() {
        for e in catalog() {
            assert!(!e.id.is_empty());
            assert!(
                CATEGORIES.contains(&e.category.as_str()),
                "unknown category: {}",
                e.category
            );
            assert!(
                matches!(
                    e.kind.as_str(),
                    "real_probe" | "alias" | "agent_required" | "special"
                ),
                "unknown kind: {}",
                e.kind
            );
        }
    }

    #[test]
    fn category_rules_bucket_known_engines() {
        assert_eq!(category_of("apt28_techniques"), "APT / Top-Tier");
        assert_eq!(category_of("aws_attack"), "Cloud / Infra");
        assert_eq!(category_of("graphql_attack"), "Web / API");
        assert_eq!(category_of("jwt_attack"), "Crypto / Identity");
        assert_eq!(category_of("bgp_dns_hijacking"), "Network / Protocol");
        assert_eq!(category_of("llm_jailbreak"), "AI / LLM");
        assert_eq!(category_of("scada_ics"), "OT / ICS / IoT");
        assert_eq!(category_of("osint"), "Recon & OSINT");
        assert_eq!(category_of("npm_package_attack"), "Supply Chain");
        assert_eq!(category_of("android_intent_attack"), "Mobile");
    }

    #[test]
    fn technique_map_inverts_coverage() {
        let m = engine_technique_map();
        // advanced_web_engines covers T1190 (Exploit Public-Facing Application) in the catalog.
        let awe = m
            .get("advanced_web_engines")
            .expect("advanced_web_engines mapped");
        assert!(awe.0.iter().any(|t| t == "T1190"));
    }

    #[test]
    fn summary_totals_are_consistent() {
        let s = summary();
        let n = s["engine_count"].as_u64().unwrap() as usize;
        let cat_sum: usize = s["by_category"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_u64().unwrap() as usize)
            .sum();
        let kind_sum: usize = s["by_kind"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_u64().unwrap() as usize)
            .sum();
        assert_eq!(cat_sum, n);
        assert_eq!(kind_sum, n);
        assert!(s["attack_mapped_engines"].as_u64().unwrap() >= 1);
    }
}
