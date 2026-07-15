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

/// Normalise an optional `engine_id` cell into `Some(non-empty trimmed)` or `None`.
/// The catalog stores evidence-only controls with a NULL or blank `engine_id`.
fn engine_binding(engine_id: &Option<String>) -> Option<&str> {
    engine_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Per-framework rollup of the live control-mapping catalog. Structural only: counts controls,
/// how many are backed by a live engine vs evidence-only, and how many engine bindings are
/// "orphaned" (reference an `engine_id` the platform registry no longer knows about).
#[derive(Debug, Clone, Serialize)]
pub struct FrameworkControlCoverage {
    pub framework: String,
    /// Distinct `control_id`s mapped for this framework.
    pub total_controls: usize,
    /// Raw mapping rows for this framework (a control may have several evidence rows).
    pub total_mappings: usize,
    /// Distinct controls with at least one engine-backed evidence row.
    pub engine_backed_controls: usize,
    /// Distinct controls whose evidence is entirely non-engine (audit chain, RLS, policy, …).
    pub evidence_only_controls: usize,
    /// Mapping rows flagged `live_only` (evidence produced only by a live scan, never assumed).
    pub live_only_mappings: usize,
    /// Distinct engines referenced by this framework's mappings.
    pub distinct_engines: usize,
    /// Engine-backed rows whose `engine_id` is not a known platform engine.
    pub orphaned_engine_mappings: usize,
}

/// A mapping row whose `engine_id` no longer resolves to a known platform engine.
/// These are the rot that "live" mappings accumulate when the engine fleet changes underneath.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OrphanedEngineMapping {
    pub id: i64,
    pub framework: String,
    pub control_id: String,
    pub engine_id: String,
}

/// Summarise control-mapping coverage per framework. `is_known_engine` decides whether an
/// engine binding still resolves to a real platform engine (pass
/// `weissman_core::models::engine::is_known_engine_id`). Deterministic: frameworks sorted by name.
pub fn summarize_control_coverage<F>(
    mappings: &[ComplianceControlMappingRow],
    is_known_engine: F,
) -> Vec<FrameworkControlCoverage>
where
    F: Fn(&str) -> bool,
{
    // Per framework: control_id -> whether any row for it is engine-backed.
    let mut controls: HashMap<String, HashMap<String, bool>> = HashMap::new();
    let mut total_mappings: HashMap<String, usize> = HashMap::new();
    let mut live_only: HashMap<String, usize> = HashMap::new();
    let mut engines: HashMap<String, HashSet<String>> = HashMap::new();
    let mut orphaned: HashMap<String, usize> = HashMap::new();

    for m in mappings {
        *total_mappings.entry(m.framework.clone()).or_default() += 1;
        if m.live_only {
            *live_only.entry(m.framework.clone()).or_default() += 1;
        }
        let has_engine = engine_binding(&m.engine_id);
        let entry = controls
            .entry(m.framework.clone())
            .or_default()
            .entry(m.control_id.clone())
            .or_insert(false);
        if let Some(eng) = has_engine {
            *entry = true;
            engines
                .entry(m.framework.clone())
                .or_default()
                .insert(eng.to_string());
            if !is_known_engine(eng) {
                *orphaned.entry(m.framework.clone()).or_default() += 1;
            }
        }
    }

    let mut frameworks: Vec<String> = controls.keys().cloned().collect();
    frameworks.sort();
    frameworks
        .into_iter()
        .map(|fw| {
            let per_control = controls.get(&fw);
            let total_controls = per_control.map(HashMap::len).unwrap_or(0);
            let engine_backed_controls = per_control
                .map(|c| c.values().filter(|v| **v).count())
                .unwrap_or(0);
            FrameworkControlCoverage {
                total_controls,
                total_mappings: total_mappings.get(&fw).copied().unwrap_or(0),
                engine_backed_controls,
                evidence_only_controls: total_controls.saturating_sub(engine_backed_controls),
                live_only_mappings: live_only.get(&fw).copied().unwrap_or(0),
                distinct_engines: engines.get(&fw).map(HashSet::len).unwrap_or(0),
                orphaned_engine_mappings: orphaned.get(&fw).copied().unwrap_or(0),
                framework: fw,
            }
        })
        .collect()
}

/// Return every mapping row that binds a control to an engine the platform no longer knows.
/// Deterministic order (framework, control_id, id). An empty result means the live mapping
/// catalog is fully consistent with the current engine registry.
pub fn find_orphaned_engine_mappings<F>(
    mappings: &[ComplianceControlMappingRow],
    is_known_engine: F,
) -> Vec<OrphanedEngineMapping>
where
    F: Fn(&str) -> bool,
{
    let mut out: Vec<OrphanedEngineMapping> = mappings
        .iter()
        .filter_map(|m| {
            let eng = engine_binding(&m.engine_id)?;
            if is_known_engine(eng) {
                return None;
            }
            Some(OrphanedEngineMapping {
                id: m.id,
                framework: m.framework.clone(),
                control_id: m.control_id.clone(),
                engine_id: eng.to_string(),
            })
        })
        .collect();
    out.sort_by(|a, b| {
        a.framework
            .cmp(&b.framework)
            .then(a.control_id.cmp(&b.control_id))
            .then(a.id.cmp(&b.id))
    });
    out
}

#[cfg(test)]
mod control_coverage_tests {
    use super::*;

    fn row(
        id: i64,
        framework: &str,
        control_id: &str,
        engine_id: Option<&str>,
        live_only: bool,
    ) -> ComplianceControlMappingRow {
        ComplianceControlMappingRow {
            id,
            framework: framework.to_string(),
            control_id: control_id.to_string(),
            control_title: format!("{control_id} title"),
            control_family: "Fam".to_string(),
            engine_id: engine_id.map(|s| s.to_string()),
            evidence_type: "engine_scan".to_string(),
            evidence_source: "engines".to_string(),
            live_only,
            mapping_notes: String::new(),
        }
    }

    // Only `tls_posture` is a "known" engine in these tests.
    fn known(id: &str) -> bool {
        id == "tls_posture"
    }

    #[test]
    fn coverage_counts_distinct_controls_and_engine_backing() {
        let mappings = vec![
            // Two evidence rows for the same control -> one distinct engine-backed control.
            row(1, "ISO27001", "A.8.15", Some("tls_posture"), true),
            row(2, "ISO27001", "A.8.15", None, false),
            // Evidence-only control (no engine).
            row(3, "ISO27001", "A.5.15", None, true),
            // Different framework.
            row(4, "CIS", "CIS-8.2", None, false),
        ];
        let cov = summarize_control_coverage(&mappings, known);
        assert_eq!(cov.len(), 2, "two frameworks");
        // Sorted: CIS before ISO27001.
        assert_eq!(cov[0].framework, "CIS");
        assert_eq!(cov[1].framework, "ISO27001");

        let iso = &cov[1];
        assert_eq!(iso.total_controls, 2);
        assert_eq!(iso.total_mappings, 3);
        assert_eq!(iso.engine_backed_controls, 1);
        assert_eq!(iso.evidence_only_controls, 1);
        assert_eq!(iso.live_only_mappings, 2);
        assert_eq!(iso.distinct_engines, 1);
        assert_eq!(iso.orphaned_engine_mappings, 0);
    }

    #[test]
    fn blank_engine_id_is_treated_as_evidence_only() {
        let mappings = vec![
            row(1, "NIST", "AC-7", Some("   "), false),
            row(2, "NIST", "AU-9", Some(""), false),
        ];
        let cov = summarize_control_coverage(&mappings, known);
        assert_eq!(cov[0].engine_backed_controls, 0);
        assert_eq!(cov[0].evidence_only_controls, 2);
        assert_eq!(cov[0].distinct_engines, 0);
        assert!(find_orphaned_engine_mappings(&mappings, known).is_empty());
    }

    #[test]
    fn orphaned_engine_bindings_are_flagged() {
        let mappings = vec![
            row(1, "NIST", "SC-8", Some("tls_posture"), true), // known
            row(2, "NIST", "SC-8", Some("retired_engine"), true), // orphan, same control
            row(3, "NIST", "AC-2", Some("ghost_engine"), true), // orphan, other control
        ];
        let orphans = find_orphaned_engine_mappings(&mappings, known);
        assert_eq!(orphans.len(), 2);
        // Sorted by (framework, control_id, id): AC-2 then SC-8.
        assert_eq!(orphans[0].control_id, "AC-2");
        assert_eq!(orphans[0].engine_id, "ghost_engine");
        assert_eq!(orphans[1].control_id, "SC-8");
        assert_eq!(orphans[1].engine_id, "retired_engine");

        let cov = summarize_control_coverage(&mappings, known);
        assert_eq!(cov[0].framework, "NIST");
        assert_eq!(cov[0].orphaned_engine_mappings, 2);
        assert_eq!(cov[0].distinct_engines, 3);
    }

    #[test]
    fn empty_input_yields_empty_output() {
        assert!(summarize_control_coverage(&[], known).is_empty());
        assert!(find_orphaned_engine_mappings(&[], known).is_empty());
    }
}
