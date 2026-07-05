//! Classify analytical / meta-engine outputs so they are not persisted or surfaced
//! as critical vulnerabilities (CVSS 9.5). Executive summaries, posture scores,
//! belief-fusion chains, and similar synthesis artifacts are informational.

use serde_json::{json, Value};

/// Meta/analytical finding kinds that must never inherit actionable severities.
const META_CATEGORIES: &[&str] = &[
    "executive",
    "attack_surface",
    "posture",
    "meta",
    "summary",
    "analytical",
    "synthesis",
    "chain_summary",
];

/// Engines whose primary output is cross-engine synthesis (title patterns still apply
/// for mixed engines like `autonomous_pentest` that also emit real vulns).
const META_ENGINE_IDS: &[&str] = &[
    "risk_superposition_collapse",
    "pipeline_to_runtime_risk",
    "attack_chain_planner",
    "cognitive_starvation",
    "digital_twin",
    "external_exposure_supreme",
];

/// Title substrings (case-insensitive) that identify meta/analytical artifacts.
const META_TITLE_PATTERNS: &[&str] = &[
    "executive summary",
    "attack surface score",
    "superposition posture",
    "toxic collapse",
    "collapse →",
    "collapse ->",
    "financial collapse",
    "analytical summary",
    "posture score",
    "belief fusion",
    "fused via",
    "kill chain summary",
    "blast radius",
    "deployment complete",
    "nexus sovereign swarm",
    "resilience score",
    "resistance score",
    "detection resilience",
    "hijack-resistance",
    "toxic combination",
    "toxic chain",
];

fn lc(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

fn field_str(f: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = f.get(*k).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    String::new()
}

fn title_has_belief_percent(title: &str) -> bool {
    let t = lc(title);
    if !t.contains("belief") {
        return false;
    }
    // "belief 72%" or "belief 72.5%"
    t.contains("belief") && t.contains('%')
        || t.contains("max belief")
        || t.contains("collapsed belief")
}

/// Returns true when the finding is an analytical/meta artifact, not a confirmed vuln.
#[must_use]
pub fn is_meta_analytical_finding(engine: &str, raw: &Value) -> bool {
    let title = field_str(raw, &["title", "name", "summary"]);
    let category = field_str(raw, &["category", "phase", "finding_kind", "kind"]);
    let finding_type = field_str(raw, &["type", "vuln_type"]);
    let kind_flag = raw
        .get("finding_kind")
        .or_else(|| raw.get("meta"))
        .and_then(Value::as_str)
        .map(|s| lc(s))
        .unwrap_or_default();

    if kind_flag == "meta_analytical" || kind_flag == "meta" || kind_flag == "analytical" {
        return true;
    }

    let cat_lc = lc(&category);
    if META_CATEGORIES.iter().any(|c| cat_lc == *c) {
        return true;
    }

    let title_lc = lc(&title);
    if META_TITLE_PATTERNS
        .iter()
        .any(|p| title_lc.contains(&lc(p)))
    {
        return true;
    }

    if title_has_belief_percent(&title) {
        return true;
    }

    // Synthesis engines: posture / collapse / fusion titles only (not every row).
    if META_ENGINE_IDS.contains(&engine) {
        if title_lc.contains("posture")
            || title_lc.contains("collapse")
            || title_lc.contains("fusion")
            || title_lc.contains("superposition")
            || title_lc.contains("belief")
            || title_lc.contains("financial")
            || finding_type == engine
        {
            return true;
        }
    }

    false
}

/// Severity + CVSS for meta findings — always within 0..=3.9.
#[must_use]
pub fn meta_severity_and_cvss(title: &str, category: &str) -> (&'static str, f64) {
    let title_lc = lc(title);
    let cat_lc = lc(category);

    if title_lc.contains("executive summary") || cat_lc == "executive" {
        return ("info", 0.5);
    }
    if title_lc.contains("attack surface score") || cat_lc == "attack_surface" {
        return ("low", 2.5);
    }
    if title_lc.contains("superposition posture") {
        return ("info", 1.0);
    }
    if title_lc.contains("toxic collapse")
        || title_lc.contains("collapse →")
        || title_lc.contains("collapse ->")
    {
        return ("low", 3.0);
    }
    if title_has_belief_percent(&title) {
        return ("info", 1.5);
    }
    if title_lc.contains("financial collapse") {
        return ("low", 2.0);
    }
    if title_lc.contains("resilience score") || title_lc.contains("resistance score") {
        return ("info", 1.5);
    }
    if title_lc.contains("toxic combination") || title_lc.contains("toxic chain") {
        return ("low", 2.5);
    }
    ("info", 1.0)
}

/// Varied MITRE mapping for meta/analytical outputs (avoid blanket T1595).
#[must_use]
pub fn meta_mitre_technique(engine: &str, title: &str, category: &str) -> &'static str {
    let title_lc = lc(title);
    let cat_lc = lc(category);

    if title_lc.contains("executive summary") || cat_lc == "executive" {
        return "T1591"; // Gather Victim Org Information
    }
    if title_lc.contains("attack surface score") || cat_lc == "attack_surface" {
        return "T1590"; // Gather Victim Network Information
    }
    if title_lc.contains("superposition posture") {
        return "T1592"; // Gather Victim Host Information
    }
    if title_lc.contains("toxic collapse") {
        return "T1596"; // Search Open Technical Databases
    }
    if title_lc.contains("collapse →") || title_lc.contains("collapse ->") {
        return "T1597"; // Search Closed Sources
    }
    if title_has_belief_percent(&title) || title_lc.contains("fusion") {
        return "T1590";
    }
    if title_lc.contains("financial collapse") {
        return "T1565"; // Data Manipulation (FAIR / financial modeling)
    }
    if title_lc.contains("kill chain") {
        return "T1591";
    }
    match engine {
        "risk_superposition_collapse" => "T1592",
        "autonomous_pentest" => "T1590",
        "pipeline_to_runtime_risk" => "T1591",
        "digital_twin" => "T1592",
        _ => "T1596",
    }
}

/// Downgrade severity, CVSS, and MITRE on meta findings in-place. Returns true if adjusted.
pub fn apply_meta_finding_policy(engine: &str, raw: &mut Value) -> bool {
    if !is_meta_analytical_finding(engine, raw) {
        return false;
    }

    let title = field_str(raw, &["title", "name", "summary"]);
    let category = field_str(raw, &["category", "phase", "finding_kind", "kind"]);
    let (sev, cvss) = meta_severity_and_cvss(&title, &category);
    let mitre = meta_mitre_technique(engine, &title, &category);

    if let Some(obj) = raw.as_object_mut() {
        let original_severity = obj.get("severity").cloned().unwrap_or(Value::Null);
        obj.insert("severity".to_string(), json!(sev));
        obj.insert("cvss_score".to_string(), json!(cvss));
        obj.insert("cvss".to_string(), json!(cvss));
        obj.insert("mitre_attack".to_string(), json!(mitre));
        obj.insert("finding_kind".to_string(), json!("meta_analytical"));
        obj.insert(
            "meta_downgraded".to_string(),
            json!({
                "reason": "analytical_synthesis",
                "original_severity": original_severity,
            }),
        );
        // Cap any score/risk fields engines may have set from belief fusion.
        if let Some(score) = obj.get("score").and_then(Value::as_f64) {
            if score > 3.9 {
                obj.insert("analytical_score".to_string(), json!(score));
                obj.insert("score".to_string(), json!(cvss));
            }
        }
    }
    true
}

/// Resolve engine_id for API responses: raw_data fields, then DB source column.
#[must_use]
pub fn resolve_engine_id(source: &str, raw_data: &Value) -> String {
    for key in ["engine_id", "engine"] {
        if let Some(s) = raw_data.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    if let Some(inner) = raw_data.get("raw") {
        for key in ["engine_id", "engine"] {
            if let Some(s) = inner.get(key).and_then(Value::as_str) {
                let t = s.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
    }
    if let Some(ev) = raw_data.get("evidence") {
        if let Some(s) = ev.get("engine_id").and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    source.trim().to_string()
}

/// Read-path normalization for legacy rows persisted before meta downgrade.
#[must_use]
pub fn normalize_meta_display(
    engine: &str,
    title: &str,
    severity: &str,
    cvss: f64,
    mitre: &str,
    raw_data: &Value,
) -> (String, f64, String) {
    let probe = json!({
        "title": title,
        "category": raw_data.get("category").or_else(|| raw_data.get("phase")),
        "finding_kind": raw_data.get("finding_kind"),
        "type": raw_data.get("type"),
    });
    if !is_meta_analytical_finding(engine, &probe) {
        return (severity.to_string(), cvss, mitre.to_string());
    }
    let category = field_str(&probe, &["category", "phase", "finding_kind"]);
    let (sev, meta_cvss) = meta_severity_and_cvss(title, &category);
    let meta_mitre = meta_mitre_technique(engine, title, &category);
    (sev.to_string(), meta_cvss.min(3.9), meta_mitre.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_executive_summary() {
        let f =
            json!({"title": "Executive summary — autonomous pentest run", "severity": "critical"});
        assert!(is_meta_analytical_finding("autonomous_pentest", &f));
    }

    #[test]
    fn detects_superposition_posture() {
        let f = json!({"title": "Superposition posture: D (42/100) — 3 chains, max belief 88%", "severity": "critical"});
        assert!(is_meta_analytical_finding(
            "risk_superposition_collapse",
            &f
        ));
    }

    #[test]
    fn detects_toxic_collapse() {
        let f = json!({"title": "Toxic collapse: SSRF+IDOR (belief 72%)", "severity": "high"});
        assert!(is_meta_analytical_finding(
            "risk_superposition_collapse",
            &f
        ));
    }

    #[test]
    fn does_not_downgrade_real_vuln() {
        let f = json!({
            "title": "Auth bypass differential via X-Forwarded-For on /admin",
            "severity": "critical",
            "category": "validation"
        });
        assert!(!is_meta_analytical_finding("autonomous_pentest", &f));
    }

    #[test]
    fn apply_policy_caps_severity_and_cvss() {
        let mut f = json!({
            "title": "Executive summary — autonomous pentest run",
            "severity": "critical",
            "cvss_score": 9.5,
            "mitre_attack": "T1595"
        });
        assert!(apply_meta_finding_policy("autonomous_pentest", &mut f));
        assert_eq!(f["severity"], "info");
        assert!(f["cvss_score"].as_f64().unwrap() <= 3.9);
        assert_ne!(f["mitre_attack"], "T1595");
    }

    #[test]
    fn attack_surface_score_is_low_not_critical() {
        let mut f = json!({
            "title": "Attack surface score (observed vectors)",
            "severity": "critical",
            "category": "attack_surface"
        });
        apply_meta_finding_policy("autonomous_pentest", &mut f);
        assert_eq!(f["severity"], "low");
        assert!(f["cvss_score"].as_f64().unwrap() >= 2.0);
        assert!(f["cvss_score"].as_f64().unwrap() <= 3.9);
    }

    #[test]
    fn mitre_variety_not_all_t1595() {
        let cases = [
            ("Executive summary — run", "executive", "T1591"),
            (
                "Attack surface score (observed vectors)",
                "attack_surface",
                "T1590",
            ),
            ("Superposition posture: A", "", "T1592"),
            ("Toxic collapse: x", "", "T1596"),
            ("Collapse → goal: x", "", "T1597"),
        ];
        for (title, cat, expected) in cases {
            let m = meta_mitre_technique("risk_superposition_collapse", title, cat);
            assert_eq!(m, expected, "title={title}");
            assert_ne!(m, "T1595");
        }
    }

    #[test]
    fn resolve_engine_id_from_raw_data() {
        let raw = json!({"engine": "risk_superposition_collapse"});
        assert_eq!(
            resolve_engine_id("asm", &raw),
            "risk_superposition_collapse"
        );
    }

    #[test]
    fn resolve_engine_id_falls_back_to_source() {
        let raw = json!({});
        assert_eq!(
            resolve_engine_id("autonomous_pentest", &raw),
            "autonomous_pentest"
        );
    }

    #[test]
    fn detects_resilience_score_artifact() {
        let f = json!({"title": "Detection resilience score: 0/100 for tesla.com", "severity": "critical"});
        assert!(is_meta_analytical_finding("edr_evasion", &f));
    }

    #[test]
    fn detects_toxic_chain_synthesis() {
        let f = json!({"title": "Toxic chain: weak email auth + public cloud exposure", "severity": "critical"});
        assert!(is_meta_analytical_finding("external_exposure_supreme", &f));
    }

    #[test]
    fn gcs_bucket_stays_actionable() {
        let f = json!({"title": "Publicly-listable GCS bucket: www-test", "severity": "critical"});
        assert!(!is_meta_analytical_finding("gcp_attack", &f));
    }
}
