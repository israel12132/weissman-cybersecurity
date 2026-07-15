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
    /// Engine-backed rows whose `engine_id` no longer resolves to a known platform engine.
    /// Informational only — a stale engine reference is a data-quality signal, NOT a compliance
    /// inconsistency, and never gates report generation (see `find_orphaned_controls`).
    pub stale_engine_references: usize,
}

/// A mapping row whose `engine_id` no longer resolves to a known platform engine — a dangling
/// reference left behind when the engine fleet changes underneath the catalog. This is a
/// non-blocking data-quality diagnostic: an offensive engine that is simply unmapped to GRC is
/// architecturally valid, so a stale reference never voids a compliance artifact on its own.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StaleEngineReference {
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
    let mut stale: HashMap<String, usize> = HashMap::new();

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
                *stale.entry(m.framework.clone()).or_default() += 1;
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
                stale_engine_references: stale.get(&fw).copied().unwrap_or(0),
                framework: fw,
            }
        })
        .collect()
}

/// Return every mapping row that binds a control to an engine the platform no longer knows.
/// Deterministic order (framework, control_id, id). Non-blocking diagnostic only — see the
/// `StaleEngineReference` doc for why a stale engine reference does not void a compliance report.
pub fn find_stale_engine_references<F>(
    mappings: &[ComplianceControlMappingRow],
    is_known_engine: F,
) -> Vec<StaleEngineReference>
where
    F: Fn(&str) -> bool,
{
    let mut out: Vec<StaleEngineReference> = mappings
        .iter()
        .filter_map(|m| {
            let eng = engine_binding(&m.engine_id)?;
            if is_known_engine(eng) {
                return None;
            }
            Some(StaleEngineReference {
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

/// A compliance requirement (framework control) the report asserts on but which has **no covering
/// row** in the live control-mapping catalog. This is the state that voids a compliance artifact:
/// a control claimed as assessed while nothing in the platform actually produces evidence for it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OrphanedControl {
    pub control_id: String,
    pub control_title: String,
}

/// True if `mapped_id` covers the requirement `control_id`, by exact match or control-family
/// containment in either direction (a family control `A.8` is covered by a sub-control `A.8.15`,
/// and a sub-control `164.312(a)` is covered by a family mapping `164.312`). Dotted or space
/// separators are both accepted so catalogs seeded at different granularities still reconcile.
fn control_covered(control_id: &str, mapped_id: &str) -> bool {
    let a = control_id.trim();
    let b = mapped_id.trim();
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a == b {
        return true;
    }
    let is_child = |child: &str, parent: &str| {
        child.len() > parent.len()
            && child.starts_with(parent)
            && matches!(child.as_bytes()[parent.len()], b'.' | b' ' | b'(')
    };
    is_child(b, a) || is_child(a, b)
}

/// Detect orphaned controls for a single framework.
///
/// `expected` is the framework's canonical control set (the requirements a report asserts on).
/// `mapping_control_ids` are the `control_id`s present in `compliance_control_mappings` for that
/// framework. A control is orphaned when no mapping covers it (see [`control_covered`]).
///
/// Enforcement scope: if `mapping_control_ids` is empty the framework is **not onboarded** to live
/// control mapping and makes no live claim, so nothing is orphaned. Only a framework that is
/// partially mapped — some requirements covered, others not — yields orphaned controls and is
/// therefore "inconsistent". Deterministic order (control_id).
pub fn find_orphaned_controls(
    expected: &[(String, String)],
    mapping_control_ids: &[String],
) -> Vec<OrphanedControl> {
    if mapping_control_ids.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<OrphanedControl> = expected
        .iter()
        .filter(|(id, _)| {
            !mapping_control_ids
                .iter()
                .any(|mapped| control_covered(id, mapped))
        })
        .map(|(id, title)| OrphanedControl {
            control_id: id.clone(),
            control_title: title.clone(),
        })
        .collect();
    out.sort_by(|a, b| a.control_id.cmp(&b.control_id));
    out
}

/// Enforcement decision for an official compliance artifact (PDF report / evidence pack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportGate {
    /// Control mappings are consistent — emit the artifact normally.
    Allow,
    /// Orphaned controls present and the caller has not acknowledged — refuse (HTTP 409).
    Block,
    /// Orphaned controls present but the caller explicitly acknowledged — emit, visibly voided.
    Watermark,
}

/// Gate an artifact on control-mapping consistency. Orphaned controls are the *only* trigger;
/// engine-side diagnostics never reach this function. `acknowledged` corresponds to the explicit
/// `acknowledge_inconsistent=true` opt-in that downgrades a hard block to a watermarked copy.
pub fn report_gate(orphaned_controls: &[OrphanedControl], acknowledged: bool) -> ReportGate {
    if orphaned_controls.is_empty() {
        ReportGate::Allow
    } else if acknowledged {
        ReportGate::Watermark
    } else {
        ReportGate::Block
    }
}

/// Reverse of [`normalize_framework_slug`]: map a catalog `framework` column value back to the UI
/// slug whose canonical control set is known, so a per-framework coverage row can be reconciled
/// against its expected requirements. Returns `None` for catalog frameworks with no UI slug
/// (e.g. `STIG`, `NIST800-53`) — those are not reconciled against a static control set.
pub fn framework_slug_for_db(db_framework: &str) -> Option<&'static str> {
    match db_framework.trim().to_uppercase().as_str() {
        "ISO27001" => Some("iso27001"),
        "SOC2" => Some("soc2"),
        "NIS2" => Some("nis2"),
        "GDPR" => Some("gdpr"),
        "IEC62443" => Some("iec62443"),
        "PCI" => Some("pci"),
        "CSA-CCM" => Some("csa-ccm"),
        "CIS" => Some("cis"),
        "NIST" => Some("nist"),
        "HIPAA" => Some("hipaa"),
        "FEDRAMP" => Some("fedramp"),
        _ => None,
    }
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
        assert_eq!(iso.stale_engine_references, 0);
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
        assert!(find_stale_engine_references(&mappings, known).is_empty());
    }

    #[test]
    fn stale_engine_references_are_flagged_but_never_gate() {
        let mappings = vec![
            row(1, "NIST", "SC-8", Some("tls_posture"), true), // known
            row(2, "NIST", "SC-8", Some("retired_engine"), true), // stale, same control
            row(3, "NIST", "AC-2", Some("ghost_engine"), true), // stale, other control
        ];
        let stale = find_stale_engine_references(&mappings, known);
        assert_eq!(stale.len(), 2);
        // Sorted by (framework, control_id, id): AC-2 then SC-8.
        assert_eq!(stale[0].control_id, "AC-2");
        assert_eq!(stale[0].engine_id, "ghost_engine");
        assert_eq!(stale[1].control_id, "SC-8");
        assert_eq!(stale[1].engine_id, "retired_engine");

        let cov = summarize_control_coverage(&mappings, known);
        assert_eq!(cov[0].framework, "NIST");
        assert_eq!(cov[0].stale_engine_references, 2);
        assert_eq!(cov[0].distinct_engines, 3);
    }

    #[test]
    fn empty_input_yields_empty_output() {
        assert!(summarize_control_coverage(&[], known).is_empty());
        assert!(find_stale_engine_references(&[], known).is_empty());
    }

    fn expected(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn control_covered_matches_families_in_both_directions() {
        assert!(control_covered("A.8", "A.8.15")); // family covered by sub-control
        assert!(control_covered("A.8.5", "A.8")); // sub-control covered by family
        assert!(control_covered("164.312(a)", "164.312(a)")); // exact
        assert!(control_covered("164.312(a)", "164.312")); // HIPAA sub-control covered by family
        assert!(!control_covered("A.8", "A.85")); // not a dotted child — no false match
        assert!(!control_covered("A.9", "A.8.15"));
        assert!(!control_covered("", "A.8"));
    }

    #[test]
    fn unmapped_framework_yields_no_orphans() {
        // Empty mapping catalog => framework not onboarded => nothing is orphaned.
        let iso = expected(&[("A.5", "Org"), ("A.8", "Assets"), ("A.9", "Access")]);
        assert!(find_orphaned_controls(&iso, &[]).is_empty());
    }

    #[test]
    fn partially_mapped_framework_flags_the_gaps() {
        // ISO27001 seed maps A.5.* and A.8.*; A.9/A.10 have no covering mapping.
        let iso = expected(&[
            ("A.5", "Org"),
            ("A.8", "Assets"),
            ("A.9", "Access"),
            ("A.10", "Crypto"),
        ]);
        let mapped = vec![
            "A.5.15".to_string(),
            "A.8.15".to_string(),
            "A.8.5".to_string(),
        ];
        let orphans = find_orphaned_controls(&iso, &mapped);
        assert_eq!(orphans.len(), 2);
        assert_eq!(orphans[0].control_id, "A.10"); // sorted by control_id
        assert_eq!(orphans[1].control_id, "A.9");
    }

    #[test]
    fn fully_mapped_framework_has_no_orphans() {
        let fw = expected(&[("A.5", "Org"), ("A.8", "Assets")]);
        let mapped = vec!["A.5.15".to_string(), "A.8.15".to_string()];
        assert!(find_orphaned_controls(&fw, &mapped).is_empty());
    }

    #[test]
    fn report_gate_transitions() {
        let none: Vec<OrphanedControl> = vec![];
        let some = vec![OrphanedControl {
            control_id: "A.9".into(),
            control_title: "Access".into(),
        }];
        assert_eq!(report_gate(&none, false), ReportGate::Allow);
        assert_eq!(report_gate(&none, true), ReportGate::Allow);
        assert_eq!(report_gate(&some, false), ReportGate::Block);
        assert_eq!(report_gate(&some, true), ReportGate::Watermark);
    }

    #[test]
    fn framework_slug_roundtrips_for_ui_frameworks() {
        assert_eq!(framework_slug_for_db("ISO27001"), Some("iso27001"));
        assert_eq!(framework_slug_for_db("cis"), Some("cis"));
        // Catalog-only frameworks with no UI control set are not reconciled.
        assert_eq!(framework_slug_for_db("NIST800-53"), None);
        assert_eq!(framework_slug_for_db("STIG"), None);
    }

    // --- Proof that the seeded catalog clears the enforcement gate ---
    //
    // These read the real migration SQL at compile time, so a future edit that drops a mapping and
    // re-orphans a control fails the build rather than silently re-arming the 409 in production.
    const PHASE2_SQL: &str =
        include_str!("../migrations/20260702120000_security_hardening_phase2.sql");
    const ISO_CIS_COMPLETION_SQL: &str = include_str!(
        "../migrations/20260715120000_compliance_control_mappings_iso_cis_completion.sql"
    );

    /// Extract seeded `control_id`s for a framework from a migration's `VALUES` rows. Each row is a
    /// single line of the form `('FRAMEWORK', 'CONTROL_ID', ...`.
    fn ids_for(sql: &str, framework: &str) -> Vec<String> {
        let needle = format!("('{framework}', '");
        sql.lines()
            .filter_map(|l| {
                let rest = l.trim().strip_prefix(&needle)?;
                let end = rest.find('\'')?;
                Some(rest[..end].to_string())
            })
            .collect()
    }

    fn seeded_control_ids(framework: &str) -> Vec<String> {
        let mut v = ids_for(PHASE2_SQL, framework);
        v.extend(ids_for(ISO_CIS_COMPLETION_SQL, framework));
        v
    }

    #[test]
    fn iso27001_catalog_fully_maps_its_controls_and_allows() {
        // Mirrors static_framework_controls("iso27001").
        let controls = expected(&[
            ("A.5", "Organizational controls"),
            ("A.8", "Asset management"),
            ("A.9", "Access control"),
            ("A.10", "Cryptography"),
            ("A.12", "Operations security"),
            ("A.13", "Communications security"),
        ]);
        let ids = seeded_control_ids("ISO27001");
        assert!(
            !ids.is_empty(),
            "ISO27001 must be onboarded to live mapping"
        );
        let orphans = find_orphaned_controls(&controls, &ids);
        assert!(orphans.is_empty(), "ISO27001 still orphaned: {orphans:?}");
        assert_eq!(report_gate(&orphans, false), ReportGate::Allow);
    }

    #[test]
    fn cis_catalog_fully_maps_its_controls_and_allows() {
        // Mirrors static_framework_controls("cis").
        let controls = expected(&[
            ("CIS 1", "Inventory and control of enterprise assets"),
            ("CIS 3", "Data protection"),
            ("CIS 6", "Access control management"),
        ]);
        let ids = seeded_control_ids("CIS");
        assert!(!ids.is_empty(), "CIS must be onboarded to live mapping");
        let orphans = find_orphaned_controls(&controls, &ids);
        assert!(orphans.is_empty(), "CIS still orphaned: {orphans:?}");
        assert_eq!(report_gate(&orphans, false), ReportGate::Allow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(
        framework: &str,
        control_id: &str,
        control_title: &str,
        cloud_rule_id: Option<&str>,
        vuln_source_contains: Option<&str>,
        vuln_title_contains: Option<&str>,
        vuln_min_severity: Option<&str>,
    ) -> ComplianceMappingRow {
        ComplianceMappingRow {
            id: 1,
            framework: framework.to_string(),
            control_id: control_id.to_string(),
            control_title: control_title.to_string(),
            rule_key: "rk".to_string(),
            cloud_rule_id: cloud_rule_id.map(|s| s.to_string()),
            vuln_source_contains: vuln_source_contains.map(|s| s.to_string()),
            vuln_title_contains: vuln_title_contains.map(|s| s.to_string()),
            vuln_min_severity: vuln_min_severity.map(|s| s.to_string()),
        }
    }

    #[test]
    fn severity_rank_ordering() {
        assert_eq!(severity_rank("critical"), 4);
        assert_eq!(severity_rank("CRIT"), 4);
        assert_eq!(severity_rank("high"), 3);
        assert_eq!(severity_rank("Medium"), 2);
        assert_eq!(severity_rank("med"), 2);
        assert_eq!(severity_rank("low"), 1);
        assert_eq!(severity_rank("info"), 0);
        assert_eq!(severity_rank(""), 0);
    }

    #[test]
    fn mapping_matches_cloud_row_behavior() {
        let m = row("SOC2", "CC1", "t", Some("s3_public"), None, None, None);
        assert!(mapping_matches_cloud_row(&m, "s3_public"));
        assert!(!mapping_matches_cloud_row(&m, "other_rule"));

        let empty = row("SOC2", "CC1", "t", Some(""), None, None, None);
        assert!(!mapping_matches_cloud_row(&empty, "s3_public"));

        let none = row("SOC2", "CC1", "t", None, None, None, None);
        assert!(!mapping_matches_cloud_row(&none, "s3_public"));
    }

    #[test]
    fn mapping_matches_vulnerability_source_filter() {
        let m = row("SOC2", "CC1", "t", None, Some("nuclei"), None, None);
        assert!(mapping_matches_vulnerability(&m, "nuclei-scan", "anything", "low"));
        assert!(!mapping_matches_vulnerability(&m, "zap", "anything", "low"));
    }

    #[test]
    fn mapping_matches_vulnerability_min_severity_filter() {
        let m = row("SOC2", "CC1", "t", None, None, None, Some("high"));
        assert!(mapping_matches_vulnerability(&m, "src", "title", "critical"));
        assert!(mapping_matches_vulnerability(&m, "src", "title", "high"));
        assert!(!mapping_matches_vulnerability(&m, "src", "title", "low"));
    }

    #[test]
    fn mapping_matches_vulnerability_cloud_only_row_is_excluded() {
        let m = row("SOC2", "CC1", "t", Some("s3_public"), None, None, None);
        assert!(!mapping_matches_vulnerability(&m, "src", "title", "critical"));
    }

    #[test]
    fn mapping_matches_vulnerability_no_signal_is_false() {
        let m = row("SOC2", "CC1", "t", None, None, None, None);
        assert!(!mapping_matches_vulnerability(&m, "src", "title", "critical"));
    }

    #[test]
    fn mapping_matches_vulnerability_title_filter_case_insensitive() {
        let m = row("SOC2", "CC1", "t", None, None, Some("SQL"), None);
        assert!(mapping_matches_vulnerability(&m, "src", "Blind sql injection", "low"));
        assert!(!mapping_matches_vulnerability(&m, "src", "xss reflected", "low"));
    }

    #[test]
    fn compute_posture_basic_percentages() {
        let mappings = vec![
            row("SOC2", "CC1", "Access", Some("s3_public"), None, None, None),
            row("SOC2", "CC2", "Logging", None, None, Some("sql"), None),
        ];
        let cloud_rule_ids = vec!["s3_public".to_string()];
        let vulns: Vec<(String, String, String)> = vec![];

        let out = compute_posture(&mappings, &cloud_rule_ids, &vulns);
        assert_eq!(out.len(), 1);
        let p = &out[0];
        assert_eq!(p.framework, "SOC2");
        assert_eq!(p.total_mapped_controls, 2);
        assert_eq!(p.violated_controls, 1);
        assert_eq!(p.compliance_percent, 50);
    }

    #[test]
    fn compute_posture_no_violations_is_full_compliance() {
        let mappings = vec![row("ISO27001", "A.5", "Policy", None, None, Some("sql"), None)];
        let out = compute_posture(&mappings, &[], &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].compliance_percent, 100);
        assert_eq!(out[0].violated_controls, 0);
    }

    #[test]
    fn compute_posture_empty_mappings() {
        assert!(compute_posture(&[], &[], &[]).is_empty());
    }

    #[test]
    fn compute_control_statuses_marks_and_sorts() {
        let mappings = vec![
            row("SOC2", "CC2", "Logging", None, None, Some("sql"), None),
            row("SOC2", "CC1", "Access", Some("s3_public"), None, None, None),
            row("ISO27001", "A.5", "Other", Some("s3_public"), None, None, None),
        ];
        let cloud_rule_ids = vec!["s3_public".to_string()];
        let vulns: Vec<(String, String, String)> = vec![];

        let out = compute_control_statuses(&mappings, "soc2", &cloud_rule_ids, &vulns);
        assert_eq!(out.len(), 2);
        // sorted by control_id: CC1 then CC2
        assert_eq!(out[0].control_id, "CC1");
        assert_eq!(out[0].status, "non-compliant");
        assert_eq!(out[1].control_id, "CC2");
        assert_eq!(out[1].status, "compliant");
    }

    #[test]
    fn normalize_framework_slug_known_and_unknown() {
        assert_eq!(normalize_framework_slug("soc2").as_deref(), Some("SOC2"));
        assert_eq!(normalize_framework_slug("SOC_2").as_deref(), Some("SOC2"));
        assert_eq!(normalize_framework_slug("pci-dss").as_deref(), Some("PCI"));
        assert_eq!(normalize_framework_slug("nist-csf").as_deref(), Some("NIST"));
        assert_eq!(normalize_framework_slug("  iso27001 ").as_deref(), Some("ISO27001"));
        assert_eq!(normalize_framework_slug("unknown"), None);
    }

    #[test]
    fn framework_display_name_mapping() {
        assert_eq!(framework_display_name("iso27001"), "ISO/IEC 27001:2022");
        assert_eq!(framework_display_name("soc-2"), "SOC 2 Type II");
        assert_eq!(framework_display_name("pci_dss"), "PCI DSS 4.0");
        assert_eq!(framework_display_name("mystery"), "Compliance Framework");
    }

    #[test]
    fn framework_posture_serializes() {
        let p = FrameworkPosture {
            framework: "SOC2".to_string(),
            compliance_percent: 75,
            total_mapped_controls: 4,
            violated_controls: 1,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["framework"], "SOC2");
        assert_eq!(v["compliance_percent"], 75);
        assert_eq!(v["total_mapped_controls"], 4);
        assert_eq!(v["violated_controls"], 1);
    }
}
