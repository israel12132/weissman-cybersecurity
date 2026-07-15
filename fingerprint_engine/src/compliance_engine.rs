//! Maps live findings (vulnerabilities, agentless cloud rules) to regulatory frameworks using
//! the `compliance_mappings` catalog. Computes per-framework posture as % of mapped controls
//! not currently violated by at least one finding.

use serde::Serialize;
use serde_json::Value as JsonValue;
use sqlx::Executor;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ComplianceMappingRow {
    pub id: i64,
    pub framework: String,
    pub control_id: String,
    pub control_title: String,
    pub rule_key: String,
    pub cloud_rule_id: Option<String>,
    pub vuln_source_contains: Option<String>,
    pub vuln_title_contains: Option<String>,
    pub vuln_min_severity: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FrameworkPosture {
    pub framework: String,
    pub compliance_percent: u8,
    pub total_mapped_controls: usize,
    pub violated_controls: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompliancePostureResponse {
    pub frameworks: Vec<FrameworkPosture>,
    pub violations_preview: Vec<JsonValue>,
}

pub fn severity_rank(s: &str) -> i32 {
    match s.to_lowercase().as_str() {
        "critical" | "crit" => 4,
        "high" => 3,
        "medium" | "med" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// True if this mapping row is intended for cloud findings and matches `rule_id`.
pub fn mapping_matches_cloud_row(m: &ComplianceMappingRow, cloud_rule_id: &str) -> bool {
    match m.cloud_rule_id.as_deref() {
        Some(r) if !r.is_empty() => r == cloud_rule_id,
        _ => false,
    }
}

/// True if vulnerability fields satisfy this mapping (ignores rows that only define cloud rules).
pub fn mapping_matches_vulnerability(
    m: &ComplianceMappingRow,
    source: &str,
    title: &str,
    severity: &str,
) -> bool {
    if m.cloud_rule_id
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false)
        && m.vuln_source_contains
            .as_deref()
            .map(|s| s.is_empty())
            .unwrap_or(true)
        && m.vuln_title_contains
            .as_deref()
            .map(|s| s.is_empty())
            .unwrap_or(true)
        && m.vuln_min_severity
            .as_deref()
            .map(|s| s.is_empty())
            .unwrap_or(true)
    {
        return false;
    }
    let src_l = source.to_lowercase();
    let tit_l = title.to_lowercase();
    if let Some(ref sub) = m.vuln_source_contains {
        if !sub.is_empty() && !src_l.contains(&sub.to_lowercase()) {
            return false;
        }
    }
    if let Some(ref sub) = m.vuln_title_contains {
        if !sub.is_empty() && !tit_l.contains(&sub.to_lowercase()) {
            return false;
        }
    }
    if let Some(ref min_sev) = m.vuln_min_severity {
        if !min_sev.is_empty() && severity_rank(severity) < severity_rank(min_sev) {
            return false;
        }
    }
    let has_vuln_signal = m
        .vuln_source_contains
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false)
        || m.vuln_title_contains
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
        || m.vuln_min_severity
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
    has_vuln_signal
}

/// Load all compliance mappings (global catalog).
pub async fn load_mappings<'e, E>(e: E) -> Result<Vec<ComplianceMappingRow>, sqlx::Error>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as::<_, ComplianceMappingRow>(
        r#"SELECT id, framework, control_id, control_title, rule_key,
            NULLIF(trim(cloud_rule_id), '') AS cloud_rule_id,
            NULLIF(trim(vuln_source_contains), '') AS vuln_source_contains,
            NULLIF(trim(vuln_title_contains), '') AS vuln_title_contains,
            NULLIF(trim(vuln_min_severity), '') AS vuln_min_severity
            FROM compliance_mappings ORDER BY id"#,
    )
    .fetch_all(e)
    .await
}

/// Compute % compliant per framework: 100 * (1 - violated_distinct_controls / total_distinct_controls).
/// A control (framework, control_id) is violated if any mapping row for that control matches a finding.
pub fn compute_posture(
    mappings: &[ComplianceMappingRow],
    cloud_rule_ids: &[String],
    vulnerabilities: &[(String, String, String)],
) -> Vec<FrameworkPosture> {
    let cloud_set: HashSet<&str> = cloud_rule_ids.iter().map(|s| s.as_str()).collect();

    type ControlKey = (String, String);
    let mut controls_per_fw: HashMap<String, HashSet<ControlKey>> = HashMap::new();
    let mut violated_controls: HashMap<String, HashSet<ControlKey>> = HashMap::new();

    for m in mappings {
        let ck = (m.framework.clone(), m.control_id.clone());
        controls_per_fw
            .entry(m.framework.clone())
            .or_default()
            .insert(ck.clone());

        let cloud_hit = m
            .cloud_rule_id
            .as_deref()
            .map(|r| cloud_set.contains(r))
            .unwrap_or(false);
        let vuln_hit = vulnerabilities
            .iter()
            .any(|(src, tit, sev)| mapping_matches_vulnerability(m, src, tit, sev));

        if cloud_hit || vuln_hit {
            violated_controls
                .entry(m.framework.clone())
                .or_default()
                .insert(ck);
        }
    }

    let mut keys: Vec<String> = controls_per_fw.keys().cloned().collect();
    keys.sort();
    keys.into_iter()
        .map(|fw| {
            let total = controls_per_fw.get(&fw).map(|s| s.len()).unwrap_or(0);
            let vio = violated_controls.get(&fw).map(|s| s.len()).unwrap_or(0);
            let pct = if total == 0 {
                100u8
            } else {
                let ratio = (total.saturating_sub(vio)) as f64 / total as f64;
                (ratio * 100.0).round().clamp(0.0, 100.0) as u8
            };
            FrameworkPosture {
                framework: fw.clone(),
                compliance_percent: pct,
                total_mapped_controls: total,
                violated_controls: vio,
            }
        })
        .collect()
}

/// Map UI framework slug (e.g. `soc2`, `pci-dss`) to the catalog `framework` column value.
pub fn normalize_framework_slug(slug: &str) -> Option<String> {
    let s = slug.trim().to_lowercase().replace('_', "-");
    match s.as_str() {
        "soc2" | "soc-2" => Some("SOC2".into()),
        "iso27001" | "iso-27001" => Some("ISO27001".into()),
        "gdpr" => Some("GDPR".into()),
        "nis2" => Some("NIS2".into()),
        "pci" | "pci-dss" => Some("PCI".into()),
        "iec62443" => Some("IEC62443".into()),
        "csa-ccm" => Some("CSA-CCM".into()),
        "cis" => Some("CIS".into()),
        "nist" | "nist-csf" => Some("NIST".into()),
        "hipaa" => Some("HIPAA".into()),
        "fedramp" => Some("FedRAMP".into()),
        _ => None,
    }
}

pub fn framework_display_name(slug: &str) -> &'static str {
    match slug.trim().to_lowercase().replace('_', "-").as_str() {
        "iso27001" | "iso-27001" => "ISO/IEC 27001:2022",
        "soc2" | "soc-2" => "SOC 2 Type II",
        "nis2" => "NIS 2 Directive",
        "gdpr" => "GDPR",
        "iec62443" => "IEC 62443",
        "pci" | "pci-dss" => "PCI DSS 4.0",
        "csa-ccm" => "CSA CCM",
        "cis" => "CIS Benchmarks",
        "nist" | "nist-csf" => "NIST CSF",
        "hipaa" => "HIPAA",
        "fedramp" => "FedRAMP",
        _ => "Compliance Framework",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlStatusRow {
    pub control_id: String,
    pub control_title: String,
    pub status: String,
}

/// Per-control compliance derived from mapped findings (cloud rules + vulnerabilities).
pub fn compute_control_statuses(
    mappings: &[ComplianceMappingRow],
    framework_db: &str,
    cloud_rule_ids: &[String],
    vulnerabilities: &[(String, String, String)],
) -> Vec<ControlStatusRow> {
    let cloud_set: HashSet<&str> = cloud_rule_ids.iter().map(|s| s.as_str()).collect();
    let fw_upper = framework_db.to_uppercase();

    type ControlKey = (String, String);
    let mut violated: HashMap<ControlKey, bool> = HashMap::new();

    for m in mappings {
        if m.framework.to_uppercase() != fw_upper {
            continue;
        }
        let ck = (m.control_id.clone(), m.control_title.clone());
        let cloud_hit = m
            .cloud_rule_id
            .as_deref()
            .map(|r| cloud_set.contains(r))
            .unwrap_or(false);
        let vuln_hit = vulnerabilities
            .iter()
            .any(|(src, tit, sev)| mapping_matches_vulnerability(m, src, tit, sev));
        let entry = violated.entry(ck).or_insert(false);
        if cloud_hit || vuln_hit {
            *entry = true;
        }
    }

    let mut out: Vec<ControlStatusRow> = violated
        .into_iter()
        .map(
            |((control_id, control_title), is_violated)| ControlStatusRow {
                control_id,
                control_title,
                status: if is_violated {
                    "non-compliant".into()
                } else {
                    "compliant".into()
                },
            },
        )
        .collect();
    out.sort_by(|a, b| a.control_id.cmp(&b.control_id));
    out
}

/// Deterministic integrity verdict for a framework's slice of the `compliance_mappings`
/// catalog. `consistent == false` means at least one control is orphaned and any official
/// report derived from this catalog must be blocked or flagged.
#[derive(Debug, Clone, Serialize)]
pub struct MappingIntegrity {
    /// True only when every mapped control has at least one actionable rule.
    pub consistent: bool,
    /// Distinct controls seen in the catalog for this framework.
    pub total_controls: usize,
    /// Controls that exist in the catalog but have no actionable rule (sorted, deduplicated).
    pub orphaned_controls: Vec<String>,
}

/// A mapping row is *actionable* when it carries at least one predicate that can ever match a
/// live finding — a cloud rule id or a vulnerability signal (source/title/min-severity). A row
/// with none of these is structurally dead: it contributes a control to the catalog but can
/// never be evaluated, so that control is always reported "compliant" regardless of reality.
pub fn mapping_row_is_actionable(m: &ComplianceMappingRow) -> bool {
    let has_cloud = m
        .cloud_rule_id
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let has_vuln = m
        .vuln_source_contains
        .as_deref()
        .map(|s| !s.is_empty())
        .unwrap_or(false)
        || m.vuln_title_contains
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
        || m.vuln_min_severity
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
    has_cloud || has_vuln
}

/// Deterministic integrity audit of the `compliance_mappings` catalog for one framework.
///
/// A control is **orphaned** when it appears in the catalog but every one of its mapping rows
/// is structurally dead (see [`mapping_row_is_actionable`]). Such a control can never be
/// violated by any finding, so it is silently reported as compliant — false audit assurance
/// ("silent rot"). The audit is a pure function of the catalog: identical input always yields
/// an identical verdict, with `orphaned_controls` sorted for stable reporting.
pub fn compute_mapping_integrity(
    mappings: &[ComplianceMappingRow],
    framework_db: &str,
) -> MappingIntegrity {
    let fw_upper = framework_db.to_uppercase();
    // control_id -> whether it has at least one actionable mapping row.
    let mut actionable: HashMap<String, bool> = HashMap::new();
    for m in mappings {
        if m.framework.to_uppercase() != fw_upper {
            continue;
        }
        let entry = actionable.entry(m.control_id.clone()).or_insert(false);
        if mapping_row_is_actionable(m) {
            *entry = true;
        }
    }
    let total_controls = actionable.len();
    let mut orphaned_controls: Vec<String> = actionable
        .into_iter()
        .filter_map(|(id, ok)| if ok { None } else { Some(id) })
        .collect();
    orphaned_controls.sort();
    MappingIntegrity {
        consistent: orphaned_controls.is_empty(),
        total_controls,
        orphaned_controls,
    }
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ComplianceControlMappingRow {
    pub id: i64,
    pub framework: String,
    pub control_id: String,
    pub control_title: String,
    pub control_family: String,
    pub engine_id: Option<String>,
    pub evidence_type: String,
    pub evidence_source: String,
    pub live_only: bool,
    pub mapping_notes: String,
}

pub async fn load_control_mappings(
    pool: &sqlx::PgPool,
    framework: Option<&str>,
) -> Result<Vec<ComplianceControlMappingRow>, sqlx::Error> {
    if let Some(fw) = framework.filter(|s| !s.trim().is_empty()) {
        sqlx::query_as::<_, ComplianceControlMappingRow>(
            r#"SELECT id, framework, control_id, control_title, control_family,
                      engine_id, evidence_type, evidence_source, live_only, mapping_notes
                 FROM compliance_control_mappings
                WHERE framework = $1
                ORDER BY framework, control_id, evidence_type"#,
        )
        .bind(fw)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, ComplianceControlMappingRow>(
            r#"SELECT id, framework, control_id, control_title, control_family,
                      engine_id, evidence_type, evidence_source, live_only, mapping_notes
                 FROM compliance_control_mappings
                ORDER BY framework, control_id, evidence_type"#,
        )
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        id: i64,
        framework: &str,
        control_id: &str,
        cloud: Option<&str>,
        vsrc: Option<&str>,
    ) -> ComplianceMappingRow {
        ComplianceMappingRow {
            id,
            framework: framework.to_string(),
            control_id: control_id.to_string(),
            control_title: format!("Control {control_id}"),
            rule_key: format!("rk-{id}"),
            cloud_rule_id: cloud.map(str::to_string),
            vuln_source_contains: vsrc.map(str::to_string),
            vuln_title_contains: None,
            vuln_min_severity: None,
        }
    }

    #[test]
    fn integrity_consistent_when_every_control_is_actionable() {
        let mappings = vec![
            row(1, "SOC2", "CC6.1", Some("s3-public-acl"), None),
            row(2, "SOC2", "CC7.2", None, Some("nuclei")),
        ];
        let v = compute_mapping_integrity(&mappings, "SOC2");
        assert!(v.consistent, "all controls actionable => consistent");
        assert_eq!(v.total_controls, 2);
        assert!(v.orphaned_controls.is_empty());
    }

    #[test]
    fn integrity_flags_orphaned_control_with_only_dead_rows() {
        // CC6.1 is actionable; CC9.9 has only a structurally-dead row (no cloud id, no vuln signal).
        let mappings = vec![
            row(1, "SOC2", "CC6.1", Some("s3-public-acl"), None),
            row(2, "SOC2", "CC9.9", None, None),
            row(3, "SOC2", "CC9.9", Some(""), Some("")), // empty strings are also dead
        ];
        let v = compute_mapping_integrity(&mappings, "SOC2");
        assert!(
            !v.consistent,
            "an orphaned control must make the catalog inconsistent"
        );
        assert_eq!(v.total_controls, 2);
        assert_eq!(v.orphaned_controls, vec!["CC9.9".to_string()]);
    }

    #[test]
    fn integrity_control_is_saved_by_any_single_actionable_row() {
        // A control with a mix of dead and actionable rows is NOT orphaned.
        let mappings = vec![
            row(1, "ISO27001", "A.8.1", None, None),
            row(2, "ISO27001", "A.8.1", Some("iam-mfa-missing"), None),
        ];
        let v = compute_mapping_integrity(&mappings, "ISO27001");
        assert!(v.consistent);
        assert!(v.orphaned_controls.is_empty());
    }

    #[test]
    fn integrity_is_framework_scoped_and_deterministic() {
        let mappings = vec![
            row(1, "SOC2", "CC6.1", Some("s3-public-acl"), None),
            row(2, "GDPR", "Art.32", None, None), // orphaned, but a different framework
        ];
        let soc2 = compute_mapping_integrity(&mappings, "soc2"); // case-insensitive
        assert!(soc2.consistent, "GDPR rot must not affect SOC2 verdict");
        let gdpr_a = compute_mapping_integrity(&mappings, "GDPR");
        let gdpr_b = compute_mapping_integrity(&mappings, "GDPR");
        assert!(!gdpr_a.consistent);
        assert_eq!(
            gdpr_a.orphaned_controls, gdpr_b.orphaned_controls,
            "verdict must be deterministic"
        );
    }
}
