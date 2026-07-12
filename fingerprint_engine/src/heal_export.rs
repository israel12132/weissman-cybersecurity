//! Machine-readable exports of a completed auto-heal, so the heal *proof* plugs straight into CI and
//! compliance pipelines:
//!
//! - [`to_report_json`] — a stable, structured JSON view of the same data the HTML report renders.
//! - [`to_sarif`] — a SARIF 2.1.0 document (GitHub code-scanning / most SAST dashboards ingest it),
//!   describing the finding, its severity, the verified fix, and the tamper-evident attestation.
//!
//! Both are **pure functions** over [`HealReportData`] and are unit-tested; the handler loads the data
//! once and can serve HTML, JSON, or SARIF from it.

use serde_json::{json, Value};

use crate::remediation_report::HealReportData;

/// GitHub code-scanning's `security-severity` numeric band (0..10).
fn severity_num(sev: &str) -> f64 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 9.5,
        "high" => 8.0,
        "medium" => 5.5,
        "low" => 3.0,
        _ => 0.0,
    }
}

/// SARIF result level for a finding severity.
fn sarif_level(sev: &str) -> &'static str {
    match sev.to_ascii_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// Stable, structured JSON view of a completed heal (schema `weissman-heal-report/v1`).
pub fn to_report_json(d: &HealReportData) -> Value {
    json!({
        "schema": "weissman-heal-report/v1",
        "job_id": d.job_id,
        "generated_at": d.generated_at,
        "finding": {
            "id": d.finding_id,
            "title": d.title,
            "severity": d.severity,
            "cwe": d.cwe,
        },
        "verdict": d.verdict,
        "verification_status": d.verification_status,
        "attempts": d.attempts,
        "attestation": {
            "enabled": d.attestation_enabled,
            "verified": d.receipt_verified,
            "digest": d.digest,
            "algorithm": if d.attestation_enabled { "HMAC-SHA256" } else { "" },
        },
        "delivery": {
            "channel": d.channel,
            "status": d.status,
            "pr_url": d.pr_url,
            "branch": d.branch_name,
        },
        "change": {
            "unified_diff": d.unified_diff,
            "changed_files": d.changed_files,
            "deleted_paths": d.deleted_paths,
        },
        // Advisory governance disposition + bilingual rationale, or null when not evaluated.
        "governance": d.governance,
        // Bilingual brief (he/en) verbatim, or null when none was generated.
        "brief": d.brief,
    })
}

/// SARIF 2.1.0 document for the finding + its verified auto-heal.
pub fn to_sarif(d: &HealReportData) -> Value {
    let rule_id = if d.cwe.trim().is_empty() {
        "weissman-auto-heal".to_string()
    } else {
        d.cwe.trim().to_string()
    };

    let (problem_en, problem_he, root_en, fix_en, fix_he) = d
        .brief
        .as_ref()
        .map(|b| {
            (
                b.problem.en.clone(),
                b.problem.he.clone(),
                b.root_cause.en.clone(),
                b.fix_explanation.en.clone(),
                b.fix_explanation.he.clone(),
            )
        })
        .unwrap_or_default();

    let short = if problem_en.trim().is_empty() {
        d.title.clone()
    } else {
        problem_en
    };
    let full = if root_en.trim().is_empty() {
        short.clone()
    } else {
        root_en
    };
    let message = if fix_en.trim().is_empty() {
        format!("{short} — auto-heal verdict: {}", d.verdict)
    } else {
        format!("{short} — auto-heal verdict: {}. Fix: {fix_en}", d.verdict)
    };

    let locations: Vec<Value> = if d.changed_files.is_empty() {
        // No repo files changed (e.g. a virtual-patch / WAF rule): anchor the result to a logical
        // location so it still surfaces in code scanning rather than emitting an empty locations array.
        let name = if d.finding_id.trim().is_empty() {
            if d.channel.trim().is_empty() {
                "auto-heal".to_string()
            } else {
                d.channel.clone()
            }
        } else {
            d.finding_id.clone()
        };
        vec![json!({ "logicalLocations": [{ "fullyQualifiedName": name, "kind": "resource" }] })]
    } else {
        d.changed_files
            .iter()
            .map(|p| json!({ "physicalLocation": { "artifactLocation": { "uri": p } } }))
            .collect()
    };

    // Rule — attach helpUri only when a real PR/MR URL exists (SARIF wants a uri, not an empty string).
    let mut rule = json!({
        "id": rule_id,
        "name": if d.title.trim().is_empty() { rule_id.clone() } else { d.title.clone() },
        "shortDescription": { "text": if short.trim().is_empty() { rule_id.clone() } else { short.clone() } },
        "fullDescription": { "text": full },
        "properties": {
            "security-severity": format!("{:.1}", severity_num(&d.severity)),
            "tags": ["security", "auto-heal"],
        },
    });
    // helpUri only for a real http(s) URL (never a non-URI / javascript: value).
    if let Some(u) = d
        .pr_url
        .as_ref()
        .map(|u| u.trim())
        .filter(|u| u.starts_with("https://") || u.starts_with("http://"))
    {
        rule["helpUri"] = json!(u);
    }

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "Weissman Auto-Heal",
                "informationUri": "https://github.com/israel12132/weissman-cybersecurity",
                "version": "1",
                "rules": [rule],
            }},
            "results": [{
                "ruleId": rule_id,
                "level": sarif_level(&d.severity),
                "message": { "text": message },
                "locations": locations,
                "partialFingerprints": { "weissmanFindingId": d.finding_id },
                "properties": {
                    "verdict": d.verdict,
                    "verificationStatus": d.verification_status,
                    "attested": d.receipt_verified,
                    "attestationEnabled": d.attestation_enabled,
                    "receiptDigest": d.digest,
                    "channel": d.channel,
                    "prUrl": d.pr_url,
                    "attempts": d.attempts,
                    "unifiedDiff": d.unified_diff,
                    "he": { "problem": problem_he, "fix": fix_he },
                    "governance": d.governance,
                    "generatedAt": d.generated_at,
                },
            }],
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heal_policy::PolicyDecision;
    use crate::remediation_brief::{Bilingual, RemediationBrief};

    fn bi(en: &str, he: &str) -> Bilingual {
        Bilingual {
            en: en.to_string(),
            he: he.to_string(),
        }
    }

    fn data() -> HealReportData {
        HealReportData {
            job_id: "job-1".into(),
            finding_id: "F-1".into(),
            title: "Login SQLi".into(),
            severity: "high".into(),
            cwe: "CWE-89".into(),
            status: "completed".into(),
            verdict: "fixed".into(),
            verification_status: "verified_fixed".into(),
            channel: "github_pr".into(),
            pr_url: Some("https://github.com/o/r/pull/7".into()),
            branch_name: Some("auto-heal/F-1".into()),
            attempts: 2,
            receipt: "aa".into(),
            digest: "0123456789abcdef".into(),
            attestation_enabled: true,
            receipt_verified: true,
            unified_diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-bad\n+good\n".into(),
            changed_files: vec!["src/x.rs".into()],
            deleted_paths: vec![],
            brief: Some(RemediationBrief {
                problem: bi("SQL injection in login.", "הזרקת SQL בהתחברות."),
                root_cause: bi("Unparameterized query.", "שאילתה לא פרמטרית."),
                fix_explanation: bi("Use bound parameters.", "שימוש בפרמטרים קשורים."),
                severity: "high".into(),
                cwe: "CWE-89".into(),
                ..Default::default()
            }),
            generated_at: "2026-07-11T00:00:00Z".into(),
            governance: Some(PolicyDecision {
                disposition: "open_for_review".into(),
                reason_en: "Open for review — severity exceeds the auto-merge threshold; a human should merge.".into(),
                reason_he: "פתוח לסקירה".into(),
            }),
        }
    }

    #[test]
    fn report_json_has_stable_shape() {
        let j = to_report_json(&data());
        assert_eq!(j["schema"], "weissman-heal-report/v1");
        assert_eq!(j["finding"]["id"], "F-1");
        assert_eq!(j["finding"]["cwe"], "CWE-89");
        assert_eq!(j["verdict"], "fixed");
        assert_eq!(j["attestation"]["verified"], true);
        assert_eq!(j["attestation"]["algorithm"], "HMAC-SHA256");
        assert_eq!(j["change"]["changed_files"][0], "src/x.rs");
        // Bilingual brief round-trips.
        assert_eq!(j["brief"]["problem"]["he"], "הזרקת SQL בהתחברות.");
        // Advisory governance is present.
        assert_eq!(j["governance"]["disposition"], "open_for_review");
    }

    #[test]
    fn report_json_attestation_algorithm_blank_when_disabled() {
        let mut d = data();
        d.attestation_enabled = false;
        d.receipt_verified = false;
        let j = to_report_json(&d);
        assert_eq!(j["attestation"]["enabled"], false);
        assert_eq!(j["attestation"]["algorithm"], "");
    }

    #[test]
    fn sarif_is_well_formed() {
        let s = to_sarif(&data());
        assert_eq!(s["version"], "2.1.0");
        assert_eq!(s["runs"][0]["tool"]["driver"]["name"], "Weissman Auto-Heal");
        assert_eq!(s["runs"][0]["tool"]["driver"]["rules"][0]["id"], "CWE-89");
        assert_eq!(
            s["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"],
            "8.0"
        );
        assert_eq!(
            s["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"],
            "https://github.com/o/r/pull/7"
        );
        let res = &s["runs"][0]["results"][0];
        assert_eq!(res["ruleId"], "CWE-89");
        assert_eq!(res["level"], "error");
        assert_eq!(res["partialFingerprints"]["weissmanFindingId"], "F-1");
        assert_eq!(res["properties"]["attested"], true);
        assert_eq!(
            res["properties"]["governance"]["disposition"],
            "open_for_review"
        );
        assert_eq!(res["properties"]["he"]["problem"], "הזרקת SQL בהתחברות.");
        assert_eq!(
            res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/x.rs"
        );
    }

    #[test]
    fn sarif_level_maps_severity() {
        let mut d = data();
        d.severity = "medium".into();
        assert_eq!(to_sarif(&d)["runs"][0]["results"][0]["level"], "warning");
        d.severity = "low".into();
        assert_eq!(to_sarif(&d)["runs"][0]["results"][0]["level"], "note");
        d.severity = "critical".into();
        assert_eq!(to_sarif(&d)["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn sarif_without_pr_url_omits_help_uri_and_no_brief_ok() {
        let mut d = data();
        d.pr_url = None;
        d.cwe = String::new();
        d.brief = None;
        let s = to_sarif(&d);
        assert!(s["runs"][0]["tool"]["driver"]["rules"][0]
            .get("helpUri")
            .is_none());
        // Falls back to a stable rule id and the finding title.
        assert_eq!(
            s["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "weissman-auto-heal"
        );
        assert_eq!(s["runs"][0]["results"][0]["ruleId"], "weissman-auto-heal");
    }

    #[test]
    fn sarif_uses_logical_location_when_no_files_changed() {
        let mut d = data();
        d.changed_files = vec![]; // e.g. a virtual-patch / WAF rule
        let s = to_sarif(&d);
        let loc = &s["runs"][0]["results"][0]["locations"][0];
        assert!(loc.get("physicalLocation").is_none());
        assert_eq!(loc["logicalLocations"][0]["fullyQualifiedName"], "F-1");
    }

    #[test]
    fn sarif_help_uri_rejects_non_http_url() {
        let mut d = data();
        d.pr_url = Some("javascript:alert(1)".into());
        let s = to_sarif(&d);
        assert!(s["runs"][0]["tool"]["driver"]["rules"][0]
            .get("helpUri")
            .is_none());
    }
}
