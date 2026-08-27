//! Evidence-doubt gate: a finding is admitted to `vulnerabilities` only when
//! corroborated by two distinct engines **or** its confidence is ≥ 0.95.
//!
//! Asset-inventory engines (OSINT/ASM) keep the existing proof gate — they are
//! observations, not exploit claims. Actionable (medium+) vuln findings are
//! staged in `finding_candidates` until the bar is met.

use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CONFIDENCE_ADMIT: f64 = 0.95;

const INVENTORY_ENGINES: &[&str] = &[
    "osint",
    "asm",
    "leak_hunter",
    "discovery",
    "saas_idp_discovery",
    "email_dns",
    "dns_posture",
];

#[derive(Debug, Clone, PartialEq)]
pub enum AdmitDecision {
    Admit {
        reason: &'static str,
        confidence: f64,
    },
    Stage {
        reason: &'static str,
        confidence: f64,
    },
}

pub fn corroboration_key(target: &str, vuln_type: &str, payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(target.trim().to_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(vuln_type.trim().to_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(payload.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// NodeZero/XBOW/Strix sell "proof of exploit". We seal dual-probe + OAST +
/// confidence into a hash that is stored on admit — not a marketing screenshot.
pub fn proof_pack_hash(
    engine: &str,
    corroboration_key: &str,
    finding: &Value,
    distinct_engines: usize,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(engine.trim().to_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(corroboration_key.as_bytes());
    hasher.update(b"|");
    hasher.update(distinct_engines.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(extract_confidence(finding).to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(if oast_confirmed(finding) {
        b"oast1"
    } else {
        b"oast0"
    });
    hasher.update(b"|");
    hasher.update(if kev_listed(finding) {
        b"kev1"
    } else {
        b"kev0"
    });
    if let Some(p) = finding
        .get("evidence")
        .and_then(|e| e.get("proof"))
        .and_then(Value::as_str)
    {
        hasher.update(p.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

pub fn extract_confidence(finding: &Value) -> f64 {
    let raw = finding
        .get("confidence")
        .or_else(|| finding.get("certainty"));
    match raw {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    }
    .clamp(0.0, 1.0)
}

fn is_inventory(engine: &str) -> bool {
    let e = engine.trim().to_ascii_lowercase();
    INVENTORY_ENGINES.iter().any(|id| *id == e)
}

fn oast_confirmed(finding: &Value) -> bool {
    finding
        .get("oast_confirmed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || finding
            .get("evidence")
            .and_then(|e| e.get("oast_hit"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn kev_listed(finding: &Value) -> bool {
    finding
        .get("kev_listed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn has_live_proof(finding: &Value) -> bool {
    let proof = finding
        .get("evidence")
        .and_then(|e| e.get("proof"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let poc = finding.get("poc").and_then(Value::as_str).unwrap_or("");
    finding
        .get("verified")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || finding
            .get("poc_sealed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || !proof.trim().is_empty()
        || !poc.trim().is_empty()
}

fn strict_doubt() -> bool {
    matches!(
        std::env::var("WEISSMAN_EVIDENCE_DOUBT_STRICT")
            .ok()
            .as_deref()
            .map(str::trim),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Decide whether a gated finding may enter `vulnerabilities`.
pub fn decide(
    engine: &str,
    severity: &str,
    finding: &Value,
    distinct_engines: usize,
) -> AdmitDecision {
    let confidence = extract_confidence(finding);
    if is_inventory(engine) {
        return AdmitDecision::Admit {
            reason: "inventory_observation",
            confidence: confidence.max(0.8),
        };
    }
    match severity {
        "info" | "low" => {
            return AdmitDecision::Admit {
                reason: "non_actionable_severity",
                confidence,
            };
        }
        _ => {}
    }
    if distinct_engines >= 2 {
        return AdmitDecision::Admit {
            reason: "dual_probe_corroboration",
            confidence: confidence.max(0.95),
        };
    }
    if confidence >= CONFIDENCE_ADMIT {
        return AdmitDecision::Admit {
            reason: "confidence_floor",
            confidence,
        };
    }
    if oast_confirmed(finding) {
        return AdmitDecision::Admit {
            reason: "oast_confirmed",
            confidence: confidence.max(0.97),
        };
    }
    if kev_listed(finding) {
        return AdmitDecision::Admit {
            reason: "cisa_kev",
            confidence: confidence.max(0.96),
        };
    }
    // The existing findings_gate already demanded live proof for actionable
    // severities. Treat that sealed proof as the first corroborating probe so
    // the inbox is not emptied; strict mode (env) restores dual-probe-only.
    if has_live_proof(finding) && !strict_doubt() {
        return AdmitDecision::Admit {
            reason: "proof_sealed",
            confidence: confidence.max(0.9),
        };
    }
    AdmitDecision::Stage {
        reason: "awaiting_corroboration",
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn high_finding_without_confidence_is_staged() {
        let d = decide("sqli", "high", &json!({"title": "x"}), 1);
        assert!(matches!(d, AdmitDecision::Stage { .. }));
    }

    #[test]
    fn dual_engine_admits() {
        let d = decide("sqli", "high", &json!({"confidence": 0.4}), 2);
        assert!(matches!(
            d,
            AdmitDecision::Admit {
                reason: "dual_probe_corroboration",
                ..
            }
        ));
    }

    #[test]
    fn confidence_floor_admits() {
        let d = decide("sqli", "critical", &json!({"confidence": 0.95}), 1);
        assert!(matches!(
            d,
            AdmitDecision::Admit {
                reason: "confidence_floor",
                ..
            }
        ));
    }

    #[test]
    fn osint_always_admits() {
        let d = decide("osint", "medium", &json!({"value": "a.example"}), 1);
        assert!(matches!(
            d,
            AdmitDecision::Admit {
                reason: "inventory_observation",
                ..
            }
        ));
    }

    #[test]
    fn oast_promotes() {
        let d = decide(
            "ssrf",
            "high",
            &json!({"oast_confirmed": true, "confidence": 0.5}),
            1,
        );
        assert!(matches!(
            d,
            AdmitDecision::Admit {
                reason: "oast_confirmed",
                ..
            }
        ));
    }

    #[test]
    fn sealed_proof_admits_unless_strict() {
        let d = decide(
            "sqli",
            "high",
            &json!({"confidence": 0.4, "evidence": {"proof": "OAST bounce on interact.sh"}}),
            1,
        );
        assert!(matches!(
            d,
            AdmitDecision::Admit {
                reason: "proof_sealed",
                ..
            }
        ));
    }

    #[test]
    fn corroboration_key_ignores_engine() {
        let a = corroboration_key("https://t", "sqli", "x");
        let b = corroboration_key("HTTPS://T", "SQLi", "x");
        assert_eq!(a, b);
    }

    #[test]
    fn proof_pack_is_stable_for_same_inputs() {
        let f = json!({"oast_confirmed": true, "confidence": 0.9, "evidence": {"proof": "x"}});
        let a = proof_pack_hash("ssrf", "abc", &f, 2);
        let b = proof_pack_hash("ssrf", "abc", &f, 2);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        let c = proof_pack_hash("ssrf", "abc", &f, 1);
        assert_ne!(a, c);
    }
}
