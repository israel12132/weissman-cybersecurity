//! P2 APT emulation profiles — named TTP playbooks that seed Campaign Fabric (P0)
//! through the Proof gate (P1).
//!
//! Profiles only map techniques the platform can actually dispatch via
//! [`crate::adversary_campaign::engine_for_technique`] / `engine_dispatch`.
//! They never invent MITRE coverage, never open shells, and never drop
//! ransomware or OT process-disruption payloads.

use crate::attack_chain_planner::{self, Fact, Technique};
use serde_json::{json, Value};
use std::collections::HashSet;
use weissman_core::models::engine::is_production_engine_id;

/// Stable profile ids (URL / API / i18n key suffix).
pub const PROFILE_IDS: &[&str] = &[
    "ransomware-affiliate",
    "cloud-credential-thief",
    "web-initial-access",
    "insider-pathing",
    "supply-chain-adjacent",
    "ot-curious",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileStage {
    pub id: &'static str,
    pub mitre_tactic: &'static str,
    pub techniques: &'static [&'static str],
}

#[derive(Debug, Clone, Copy)]
pub struct AptProfile {
    pub id: &'static str,
    pub family: &'static str,
    pub goal_fact: &'static str,
    pub mitre: &'static [&'static str],
    pub preferred_techniques: &'static [&'static str],
    pub preferred_engines: &'static [&'static str],
    pub extra_technique_ids: &'static [&'static str],
    pub stages: &'static [ProfileStage],
    pub detection_surfaces: &'static [&'static str],
    pub requires_industrial_ot: bool,
    pub roe_notes: &'static str,
    pub honest_coverage: &'static str,
}

const STAGE_IA: ProfileStage = ProfileStage {
    id: "initial_access",
    mitre_tactic: "TA0001",
    techniques: &["valid_accounts", "exploit_rce_web", "identity_spray"],
};
const STAGE_EXEC: ProfileStage = ProfileStage {
    id: "execution",
    mitre_tactic: "TA0002",
    techniques: &["exploit_rce_web", "exploit_sqli_web"],
};
const STAGE_PRIV: ProfileStage = ProfileStage {
    id: "privilege",
    mitre_tactic: "TA0004",
    techniques: &["privilege_escalation", "cloud_iam_abuse"],
};
const STAGE_LAT: ProfileStage = ProfileStage {
    id: "lateral",
    mitre_tactic: "TA0008",
    techniques: &["lateral_movement", "reach_crown_jewel"],
};
const STAGE_COLL: ProfileStage = ProfileStage {
    id: "collection",
    mitre_tactic: "TA0009",
    techniques: &["abuse_authz", "exfiltrate_db"],
};
const STAGE_EXFIL: ProfileStage = ProfileStage {
    id: "exfiltration",
    mitre_tactic: "TA0010",
    techniques: &["exfiltrate_crown_jewel", "exfiltrate_db"],
};
const STAGE_IMPACT: ProfileStage = ProfileStage {
    id: "impact",
    mitre_tactic: "TA0040",
    techniques: &["exfiltrate_crown_jewel", "reach_crown_jewel"],
};
const STAGE_CRED: ProfileStage = ProfileStage {
    id: "credential_access",
    mitre_tactic: "TA0006",
    techniques: &["exploit_ssrf_metadata", "identity_spray", "valid_accounts"],
};
const STAGE_SUPPLY: ProfileStage = ProfileStage {
    id: "supply_recon",
    mitre_tactic: "TA0001",
    techniques: &["supply_chain_adjacent"],
};
const STAGE_OT: ProfileStage = ProfileStage {
    id: "ot_recon",
    mitre_tactic: "TA0102",
    techniques: &["ot_passive_recon"],
};

const PROFILES: &[AptProfile] = &[
    AptProfile {
        id: "ransomware-affiliate",
        family: "ransomware_affiliate",
        goal_fact: "impact:objective",
        mitre: &["T1078", "T1110.003", "T1190", "T1068", "T1021", "T1567"],
        preferred_techniques: &[
            "identity_spray",
            "valid_accounts",
            "exploit_rce_web",
            "privilege_escalation",
            "lateral_movement",
            "reach_crown_jewel",
            "exfiltrate_crown_jewel",
        ],
        preferred_engines: &[
            "password_spray",
            "credential_stuffing",
            "rce_exploit_engine",
            "host_privilege_escalation",
            "lateral_movement",
            "kill_chain",
            "cloud_data_exfil",
        ],
        extra_technique_ids: &["identity_spray"],
        stages: &[STAGE_IA, STAGE_PRIV, STAGE_LAT, STAGE_IMPACT],
        detection_surfaces: &["waf", "edr", "mfa"],
        requires_industrial_ot: false,
        roe_notes: "Authorized tenant/client scope only. Dual-approval and execution_scope_pin still apply. Council HITL may propose allow-listed techniques only. No auto external disclosure.",
        honest_coverage: "Does not encrypt, wipe, inhibit backup, or drop ransomware. Agent-required ransomware_emulation is not campaign-dispatched. Impact is modeled as crown-jewel reach plus cloud_data_exfil — the production engines already on the P0 map.",
    },
    AptProfile {
        id: "cloud-credential-thief",
        family: "cloud_credential_thief",
        goal_fact: "cred:leaked",
        mitre: &["T1552.005", "T1078", "T1078.004", "T1110.003"],
        preferred_techniques: &[
            "exploit_ssrf_metadata",
            "identity_spray",
            "valid_accounts",
            "cloud_iam_abuse",
        ],
        preferred_engines: &[
            "ssrf_advanced",
            "password_spray",
            "credential_stuffing",
            "cloud_iam_escalation",
        ],
        extra_technique_ids: &["identity_spray", "cloud_iam_abuse"],
        stages: &[STAGE_CRED, STAGE_PRIV],
        detection_surfaces: &["waf", "mfa"],
        requires_industrial_ot: false,
        roe_notes: "Read-only cloud/identity probes. No role mutation, no key creation, no shell. Metadata SSRF and IAM misconfig confirmation stay inside authorized scope.",
        honest_coverage: "Does not steal live cloud keys or assume attacker IAM. cloud_iam_escalation is a read-only alias onto aws_attack. Privilege facts still require proof_status=proven.",
    },
    AptProfile {
        id: "web-initial-access",
        family: "web_initial_access",
        goal_fact: "access:foothold",
        mitre: &["T1190"],
        preferred_techniques: &["exploit_rce_web", "exploit_sqli_web", "abuse_authz"],
        preferred_engines: &["rce_exploit_engine", "sqli_advanced", "bola_idor"],
        extra_technique_ids: &[],
        stages: &[STAGE_EXEC, STAGE_COLL],
        detection_surfaces: &["waf"],
        requires_industrial_ot: false,
        roe_notes: "Web/API engines only. Safe-proof adapters are GET-only. No xp_cmdshell, no DROP DATABASE, no outfile dumps.",
        honest_coverage: "Maps to rce_exploit_engine, sqli_advanced, and bola_idor — the same production probes P0 already dispatches. Does not claim XSS-to-RCE or unmapped 0-days.",
    },
    AptProfile {
        id: "insider-pathing",
        family: "insider_pathing",
        goal_fact: "access:crown_jewel",
        mitre: &["T1078", "T1190", "T1068", "T1021"],
        preferred_techniques: &[
            "valid_accounts",
            "abuse_authz",
            "identity_spray",
            "privilege_escalation",
            "lateral_movement",
            "reach_crown_jewel",
        ],
        preferred_engines: &[
            "credential_stuffing",
            "bola_idor",
            "password_spray",
            "host_privilege_escalation",
            "lateral_movement",
            "kill_chain",
        ],
        extra_technique_ids: &["identity_spray"],
        stages: &[STAGE_IA, STAGE_COLL, STAGE_PRIV, STAGE_LAT],
        detection_surfaces: &["mfa", "edr"],
        requires_industrial_ot: false,
        roe_notes: "Models an authorized insider-like path (valid accounts / IDOR), not malware on a workstation. No impersonation of a named employee. Tenant + client RLS still pin scope.",
        honest_coverage: "No insider-agent implant and no mailbox/EDR bypass. Pathing is STRIPS over credential_stuffing, bola_idor, host_privilege_escalation, and lateral_movement.",
    },
    AptProfile {
        id: "supply-chain-adjacent",
        family: "supply_chain_adjacent",
        goal_fact: "access:foothold",
        mitre: &["T1195", "T1190"],
        preferred_techniques: &[
            "supply_chain_adjacent",
            "exploit_rce_web",
            "valid_accounts",
        ],
        preferred_engines: &["supply_chain", "rce_exploit_engine", "credential_stuffing"],
        extra_technique_ids: &["supply_chain_adjacent"],
        stages: &[STAGE_SUPPLY, STAGE_EXEC],
        detection_surfaces: &["waf"],
        requires_industrial_ot: false,
        roe_notes: "Harvests exposed manifests/SBOMs already on the authorized target. Does not poison registries or push packages. Novel findings stay in-product.",
        honest_coverage: "Does not emulate SolarWinds-style implant or CI worker takeover. supply_chain harvests proven components; foothold still requires a later evidenced exploit technique plus proof.",
    },
    AptProfile {
        id: "ot-curious",
        family: "ot_curious",
        goal_fact: "access:internal",
        mitre: &["T0843", "T1046", "T1021"],
        preferred_techniques: &[
            "ot_passive_recon",
            "lateral_movement",
            "reach_crown_jewel",
        ],
        preferred_engines: &["scada_ics", "lateral_movement", "kill_chain"],
        extra_technique_ids: &["ot_passive_recon"],
        stages: &[STAGE_OT, STAGE_LAT],
        detection_surfaces: &["ot_roe", "edr"],
        requires_industrial_ot: true,
        roe_notes: "Passive OT/ICS fingerprinting only (scada_ics). industrial_ot_enabled is required for deeper OT. Dual-approval / critical-infra contract still apply to high-risk OT engines — this profile does not dispatch them.",
        honest_coverage: "Does not run ot_sis_triton_attack, SIS, or any process-disruption / safety-function probe. Discovery is protocol/banner fingerprinting. Lateral/crown-jewel steps still require proven privilege facts.",
    },
];

/// Extra STRIPS operators that exist only when a profile opts in.
/// They are **not** in [`attack_chain_planner::default_technique_library`] so generic
/// P0 campaigns cannot spray or mint OT facts by accident.
pub fn extra_technique(id: &str) -> Option<Technique> {
    Some(match id {
        "identity_spray" => Technique::new(
            "identity_spray",
            "Password-spray / login-surface posture (synthetic probes)",
            "T1110.003",
            &["service:web"],
            &["cred:leaked"],
            6,
        ),
        "cloud_iam_abuse" => Technique::new(
            "cloud_iam_abuse",
            "Cloud IAM / identity misconfig (read-only)",
            "T1078.004",
            &["cloud:exposed"],
            &["access:privileged"],
            5,
        ),
        "supply_chain_adjacent" => Technique::new(
            "supply_chain_adjacent",
            "Supply-chain adjacent: exposed manifests / typosquat evidence",
            "T1195",
            &["service:web"],
            &["supply:exposed"],
            2,
        ),
        "ot_passive_recon" => Technique::new(
            "ot_passive_recon",
            "OT/ICS passive fingerprint (no process disruption)",
            "T0843",
            &["service:web"],
            &["ot:exposed"],
            3,
        ),
        _ => return None,
    })
}

/// Production engine for a profile extra (or `None` if unknown / not production).
#[must_use]
pub fn extra_engine_for_technique(technique_id: &str) -> Option<&'static str> {
    let engine = match technique_id {
        "identity_spray" => "password_spray",
        "cloud_iam_abuse" => "cloud_iam_escalation",
        "supply_chain_adjacent" => "supply_chain",
        "ot_passive_recon" => "scada_ics",
        _ => return None,
    };
    if is_production_engine_id(engine) {
        Some(engine)
    } else {
        None
    }
}

#[must_use]
pub fn get(id: &str) -> Option<&'static AptProfile> {
    let id = id.trim();
    if id.is_empty() {
        return None;
    }
    PROFILES.iter().find(|p| p.id == id)
}

impl AptProfile {
    #[must_use]
    pub fn to_json(self) -> Value {
        json!({
            "id": self.id,
            "family": self.family,
            "goal_fact": self.goal_fact,
            "mitre": self.mitre,
            "preferred_techniques": self.preferred_techniques,
            "preferred_engines": self.preferred_engines,
            "extra_technique_ids": self.extra_technique_ids,
            "stages": self.stages.iter().map(|s| json!({
                "id": s.id,
                "mitre_tactic": s.mitre_tactic,
                "techniques": s.techniques,
            })).collect::<Vec<_>>(),
            "detection_surfaces": self.detection_surfaces,
            "requires_industrial_ot": self.requires_industrial_ot,
            "roe_notes": self.roe_notes,
            "honest_coverage": self.honest_coverage,
            "stub": false,
            "disclose_externally": false,
            "council_hitl_required": true,
            "safety_rails_no_shells": true,
            "probe_executor": "engine_dispatch",
            "privilege_facts_require_proven": true,
        })
    }
}

#[must_use]
pub fn catalog_json() -> Value {
    json!(PROFILES.iter().map(|p| p.to_json()).collect::<Vec<_>>())
}

/// Default STRIPS library plus this profile's extras, with preferred techniques cheaper.
#[must_use]
pub fn technique_library_for(profile_id: &str) -> Vec<Technique> {
    let mut lib = attack_chain_planner::default_technique_library();
    let Some(p) = get(profile_id) else {
        return lib;
    };
    for id in p.extra_technique_ids {
        if let Some(t) = extra_technique(id) {
            if extra_engine_for_technique(id).is_some() {
                lib.push(t);
            }
        }
    }
    apply_preferred_costs(&mut lib, p.preferred_techniques);
    lib
}

/// Library used when `profile_stub` has a known `profile_id`.
#[must_use]
pub fn technique_library_from_stub(profile_stub: &Value) -> Vec<Technique> {
    let id = profile_stub
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    technique_library_for(id)
}

#[must_use]
pub fn preferred_engines_from_stub(profile_stub: &Value) -> Vec<String> {
    if let Some(arr) = profile_stub
        .get("preferred_engines")
        .and_then(Value::as_array)
    {
        return arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .filter(|id| is_production_engine_id(id))
            .collect();
    }
    if let Some(p) = profile_stub
        .get("profile_id")
        .and_then(Value::as_str)
        .and_then(get)
    {
        return p
            .preferred_engines
            .iter()
            .filter(|id| is_production_engine_id(id))
            .map(|s| (*s).to_string())
            .collect();
    }
    Vec::new()
}

/// Lower cost for preferred techniques (rank 0 cheapest). Others become backups,
/// never removed — the planner still cannot invent capability.
pub fn apply_preferred_costs(lib: &mut [Technique], preferred: &[&str]) {
    let n = preferred.len() as u32;
    for t in lib.iter_mut() {
        if let Some(rank) = preferred.iter().position(|id| *id == t.id) {
            let boost = 3u32.saturating_mul(n.saturating_sub(rank as u32));
            t.cost = t.cost.saturating_sub(boost).max(1);
        } else {
            t.cost = t.cost.saturating_add(12);
        }
    }
}

/// First profile extra whose preconditions are met, that is productive, and not yet used.
/// Used to gather evidence (supply-chain / OT recon) without inventing a path to the goal.
#[must_use]
pub fn next_gather_technique(
    profile_id: &str,
    facts: &HashSet<Fact>,
    already: &HashSet<String>,
) -> Option<Technique> {
    let p = get(profile_id)?;
    for id in p.preferred_techniques {
        if already.contains(*id) {
            continue;
        }
        let extra = extra_technique(id);
        if extra.is_some() && extra_engine_for_technique(id).is_none() {
            continue;
        }
        let t = extra.or_else(|| {
            attack_chain_planner::default_technique_library()
                .into_iter()
                .find(|t| t.id == *id)
        })?;
        if t.applicable(facts) && t.effects.iter().any(|e| !facts.contains(e)) {
            return Some(t);
        }
    }
    None
}

#[must_use]
pub fn profile_id_from_stub(profile_stub: &Value) -> String {
    profile_stub
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Classify a control surface from proof/job text. Unknown unless the signal is present.
#[must_use]
pub fn classify_control_surface(reason: &str) -> &'static str {
    let h = reason.to_ascii_lowercase();
    if h.contains("industrial_ot")
        || h.contains("ot/ics")
        || h.contains("critical_infra")
        || h.contains("ot_roe")
        || h.contains("roe_mode")
    {
        return "ot_roe";
    }
    if h.contains("mfa")
        || h.contains("2fa")
        || h.contains("totp")
        || h.contains("step-up")
        || h.contains("webauthn")
    {
        return "mfa";
    }
    if h.contains("edr")
        || h.contains("endpoint")
        || h.contains("agent-required")
        || h.contains("agent_required")
    {
        return "edr";
    }
    if h.contains("waf")
        || h.contains("cloudflare")
        || h.contains("akamai")
        || h.contains("http 403")
        || h.contains("http 406")
        || h.contains("http 429")
        || h.contains("status 403")
        || h.contains("status 406")
        || h.contains("status 429")
    {
        return "waf";
    }
    if h.contains("proof") || h.contains("unproven") || h.contains("confirmation-grade") {
        return "proof_gate";
    }
    "unknown"
}

#[must_use]
pub fn choke_technique(technique_id: &str) -> bool {
    matches!(
        technique_id,
        "privilege_escalation" | "lateral_movement" | "reach_crown_jewel" | "cloud_iam_abuse"
    )
}

/// Stage progress overlay for the Command Center (proven / blocked / in_progress / pending).
#[must_use]
pub fn stage_progress(profile: &AptProfile, steps: &[Value]) -> Value {
    json!(profile
        .stages
        .iter()
        .map(|st| {
            let members: Vec<&Value> = steps
                .iter()
                .filter(|s| {
                    s.get("technique_id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| st.techniques.contains(&id))
                })
                .collect();
            let status = if members.is_empty() {
                "pending"
            } else if members.iter().any(|s| {
                s.get("proof_status").and_then(Value::as_str) == Some("failed_proof")
                    || s.get("status").and_then(Value::as_str) == Some("failed")
            }) {
                "blocked"
            } else if members
                .iter()
                .any(|s| s.get("proof_status").and_then(Value::as_str) == Some("proven"))
                && members.iter().all(|s| {
                    let stt = s.get("status").and_then(Value::as_str).unwrap_or("");
                    let ps = s.get("proof_status").and_then(Value::as_str).unwrap_or("");
                    matches!(stt, "succeeded" | "skipped") && (ps == "proven" || stt == "skipped")
                        || stt == "skipped"
                })
            {
                "proven"
            } else if members.iter().all(|s| {
                s.get("proof_status").and_then(Value::as_str) == Some("proven")
                    || s.get("status").and_then(Value::as_str) == Some("skipped")
            }) {
                "proven"
            } else if members.iter().any(|s| {
                matches!(
                    s.get("status").and_then(Value::as_str),
                    Some("dispatched" | "succeeded" | "planned")
                )
            }) {
                "in_progress"
            } else {
                "pending"
            };
            json!({
                "id": st.id,
                "mitre_tactic": st.mitre_tactic,
                "techniques": st.techniques,
                "status": status,
            })
        })
        .collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_named_profiles_with_honest_engines() {
        assert_eq!(PROFILE_IDS.len(), 6);
        assert_eq!(PROFILES.len(), 6);
        for p in PROFILES {
            assert!(PROFILE_IDS.contains(&p.id));
            assert!(crate::adversary_campaign::is_allowed_goal(p.goal_fact));
            assert!(!p.mitre.is_empty());
            assert!(!p.preferred_techniques.is_empty());
            assert!(!p.roe_notes.is_empty());
            assert!(
                p.honest_coverage.contains("not")
                    || p.honest_coverage.contains("Does not")
                    || p.honest_coverage.contains("No "),
                "profile {} must state what it does not claim",
                p.id
            );
            for eng in p.preferred_engines {
                assert!(
                    is_production_engine_id(eng),
                    "profile {} engine {eng} is not production",
                    p.id
                );
            }
            for id in p.preferred_techniques {
                let mapped = extra_engine_for_technique(id)
                    .or_else(|| crate::adversary_campaign::engine_for_technique(id));
                assert!(
                    mapped.is_some(),
                    "profile {} technique {id} has no production engine",
                    p.id
                );
            }
        }
    }

    #[test]
    fn extras_are_not_in_default_library() {
        let default: HashSet<_> = attack_chain_planner::default_technique_library()
            .into_iter()
            .map(|t| t.id)
            .collect();
        for id in [
            "identity_spray",
            "cloud_iam_abuse",
            "supply_chain_adjacent",
            "ot_passive_recon",
        ] {
            assert!(!default.contains(id));
            assert!(extra_technique(id).is_some());
            assert!(extra_engine_for_technique(id).is_some());
        }
    }

    #[test]
    fn ransomware_does_not_dispatch_encryptor() {
        let p = get("ransomware-affiliate").unwrap();
        assert!(!p
            .preferred_engines
            .iter()
            .any(|e| *e == "ransomware_emulation"
                || *e == "ransomware_sim"
                || *e == "conti_ransomware_ttps"));
        assert!(p.honest_coverage.contains("encrypt"));
    }

    #[test]
    fn ot_curious_does_not_dispatch_triton() {
        let p = get("ot-curious").unwrap();
        assert!(!p
            .preferred_engines
            .iter()
            .any(|e| *e == "ot_sis_triton_attack"));
        assert!(p.requires_industrial_ot);
        assert!(p.honest_coverage.contains("ot_sis_triton"));
    }

    #[test]
    fn preferred_costs_prefer_web_rce_over_sqli_when_both_evidenced() {
        let findings = vec![serde_json::json!({
            "finding_id": "1",
            "type": "web",
            "title": "RCE and SQL injection on https://app.example",
            "severity": "high",
            "target": "https://app.example",
        })];
        let web = technique_library_for("web-initial-access");
        let (asset, chain, _) =
            attack_chain_planner::plan_strongest_asset_with(&findings, "access:foothold", &web)
                .expect("path");
        assert_eq!(asset, "app.example");
        assert_eq!(chain.steps[0].technique_id, "exploit_rce_web");
    }

    #[test]
    fn generic_library_unchanged_without_profile() {
        let a = technique_library_for("");
        let b = attack_chain_planner::default_technique_library();
        assert_eq!(a.len(), b.len());
        assert_eq!(a[0].cost, b[0].cost);
    }

    #[test]
    fn gather_supply_chain_when_only_web_observed() {
        let facts: HashSet<Fact> = ["service:web".into()].into_iter().collect();
        let already = HashSet::new();
        let t = next_gather_technique("supply-chain-adjacent", &facts, &already).unwrap();
        assert_eq!(t.id, "supply_chain_adjacent");
        assert!(t.effects.contains(&"supply:exposed".to_string()));
    }

    #[test]
    fn classify_surfaces_need_measurable_signal() {
        assert_eq!(classify_control_surface("HTTP 403 from WAF"), "waf");
        assert_eq!(classify_control_surface("MFA challenge page"), "mfa");
        assert_eq!(classify_control_surface("agent_required: edr"), "edr");
        assert_eq!(
            classify_control_surface("industrial_ot_enabled is false"),
            "ot_roe"
        );
        assert_eq!(
            classify_control_surface("step completed without confirmation-grade evidence"),
            "proof_gate"
        );
        assert_eq!(classify_control_surface("timeout"), "unknown");
    }

    #[test]
    fn stage_progress_marks_failed_proof_blocked() {
        let p = get("web-initial-access").unwrap();
        let steps = vec![json!({
            "technique_id": "exploit_rce_web",
            "status": "succeeded",
            "proof_status": "failed_proof",
        })];
        let stages = stage_progress(p, &steps);
        let exec = stages
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == "execution")
            .unwrap();
        assert_eq!(exec["status"], "blocked");
    }

    #[test]
    fn unknown_profile_id_is_none() {
        assert!(get("lazarus-hidden-cobra").is_none());
        assert!(get("").is_none());
    }
}
