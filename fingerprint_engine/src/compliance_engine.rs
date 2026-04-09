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
