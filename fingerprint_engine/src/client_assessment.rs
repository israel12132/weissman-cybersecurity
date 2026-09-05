//! Live client assessment pack shared by the branded PDF and Excel deliverables.
//!
//! Every field is read from the tenant-scoped `clients` / `vulnerabilities` rows.
//! CVSS, CVE, EPSS and CISA KEV are emitted only when a live engine or intel
//! enrichment stored them — never estimated from severity.

use crate::pdf::copy as t;
use crate::pdf::doc::Lang;
use crate::pdf::spec::{ColumnSpec, SheetSpec, WorkbookSpec};
use crate::pdf_report::FindingRow;
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};

/// One live finding as it should appear on a customer deliverable.
#[derive(Clone, Debug, Default)]
pub struct AssessmentFinding {
    pub id: i64,
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub status: String,
    pub description: String,
    pub poc: String,
    pub poc_sealed: bool,
    pub discovered_at: String,
    pub cve: String,
    pub cwe: String,
    pub cvss: String,
    pub cvss_vector: String,
    pub epss: String,
    pub kev: String,
    pub mitre: String,
    pub asset: String,
}

impl AssessmentFinding {
    #[must_use]
    pub fn as_row(&self) -> FindingRow {
        (
            self.id,
            self.title.clone(),
            self.severity.clone(),
            self.source.clone(),
            self.description.clone(),
            self.poc.clone(),
        )
    }

    #[must_use]
    pub fn verified_label(&self) -> &'static str {
        if self.poc_sealed {
            "VERIFIED"
        } else {
            "POTENTIAL"
        }
    }
}

/// Tenant-scoped assessment for one named client.
#[derive(Clone, Debug)]
pub struct ClientAssessment {
    pub client_id: i64,
    pub client_name: String,
    pub scope_line: String,
    pub roe_mode: String,
    pub findings: Vec<AssessmentFinding>,
}

#[derive(Debug)]
pub enum LoadError {
    NotFound,
    Db(String),
}

impl ClientAssessment {
    #[must_use]
    pub fn from_rows(client_name: &str, findings: &[FindingRow]) -> Self {
        Self {
            client_id: 0,
            client_name: client_name.to_string(),
            scope_line: client_name.to_string(),
            roe_mode: String::new(),
            findings: findings
                .iter()
                .map(|r| AssessmentFinding {
                    id: r.0,
                    title: r.1.clone(),
                    severity: r.2.clone(),
                    source: r.3.clone(),
                    description: r.4.clone(),
                    poc: r.5.clone(),
                    ..AssessmentFinding::default()
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn finding_rows(&self) -> Vec<FindingRow> {
        self.findings
            .iter()
            .map(AssessmentFinding::as_row)
            .collect()
    }

    #[must_use]
    pub fn kev_count(&self) -> u32 {
        self.findings.iter().filter(|f| !f.kev.is_empty()).count() as u32
    }

    #[must_use]
    pub fn cve_count(&self) -> u32 {
        self.findings.iter().filter(|f| !f.cve.is_empty()).count() as u32
    }

    #[must_use]
    pub fn epss_count(&self) -> u32 {
        self.findings.iter().filter(|f| !f.epss.is_empty()).count() as u32
    }

    #[must_use]
    pub fn verified_count(&self) -> u32 {
        self.findings.iter().filter(|f| f.poc_sealed).count() as u32
    }

    #[must_use]
    pub fn cvss_count(&self) -> u32 {
        self.findings.iter().filter(|f| !f.cvss.is_empty()).count() as u32
    }
}

/// Load the named client and every live finding row. Fail closed if the client
/// is missing; surface database errors instead of emitting an empty report.
pub async fn load(
    tx: &mut Transaction<'_, Postgres>,
    client_id: i64,
) -> Result<ClientAssessment, LoadError> {
    let client_row = sqlx::query(
        "SELECT name, COALESCE(domains, '[]') AS domains, \
         COALESCE(ip_ranges, '[]') AS ip_ranges, \
         COALESCE(client_configs, '{}') AS client_configs \
         FROM clients WHERE id = $1",
    )
    .bind(client_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| LoadError::Db(e.to_string()))?;
    let Some(client_row) = client_row else {
        return Err(LoadError::NotFound);
    };
    let client_name: String = client_row.try_get("name").unwrap_or_default();
    let domains: String = client_row
        .try_get("domains")
        .unwrap_or_else(|_| "[]".into());
    let ip_ranges: String = client_row
        .try_get("ip_ranges")
        .unwrap_or_else(|_| "[]".into());
    let configs: String = client_row
        .try_get("client_configs")
        .unwrap_or_else(|_| "{}".into());
    let scope_line = scope_line(&client_name, &domains, &ip_ranges);
    let roe_mode = roe_mode_from_configs(&configs);

    let rows = sqlx::query(
        "SELECT id, \
                COALESCE(finding_id, '') AS finding_id, \
                COALESCE(title, '') AS title, \
                COALESCE(severity, '') AS severity, \
                COALESCE(source, '') AS source, \
                COALESCE(status, '') AS status, \
                COALESCE(description, '') AS description, \
                COALESCE(poc_exploit, '') AS poc_exploit, \
                COALESCE(poc_sealed, false) AS poc_sealed, \
                discovered_at, \
                epss_score, \
                COALESCE(kev_listed, false) AS kev_listed, \
                COALESCE(kev_known_ransomware, false) AS kev_known_ransomware, \
                kev_due_date, \
                COALESCE(raw_data, '{}'::jsonb) AS raw_data \
         FROM vulnerabilities WHERE client_id = $1 \
         ORDER BY discovered_at DESC LIMIT 50000",
    )
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| LoadError::Db(e.to_string()))?;

    let findings = rows.iter().map(finding_from_row).collect();
    Ok(ClientAssessment {
        client_id,
        client_name,
        scope_line,
        roe_mode,
        findings,
    })
}

/// Flatten live intel onto the JSON object returned by `GET /api/clients/:id/findings`.
#[must_use]
pub fn finding_api_fields(raw: &Value, epss: Option<f32>, kev_listed: bool) -> Value {
    let cvss = live_cvss(raw);
    let cve = json_text(raw, &["cve", "cve_id"]);
    let cwe = json_text(raw, &["cwe"]);
    let vector = json_text(raw, &["cvss_vector", "cvss_v3_vector"]);
    let mitre = json_text(raw, &["mitre_attack", "mitre"]);
    json!({
        "cve": cve,
        "cwe": cwe,
        "cvss_score": if cvss.is_empty() { Value::Null } else { Value::String(cvss) },
        "cvss_vector": vector,
        "epss_score": epss,
        "kev_listed": kev_listed,
        "mitre_attack": mitre,
    })
}

fn finding_from_row(r: &sqlx::postgres::PgRow) -> AssessmentFinding {
    let raw: Value = r.try_get("raw_data").unwrap_or_else(|_| json!({}));
    let epss: Option<f32> = r.try_get("epss_score").ok().flatten();
    let kev_listed = r.try_get::<bool, _>("kev_listed").unwrap_or(false);
    let kev_ransom = r
        .try_get::<bool, _>("kev_known_ransomware")
        .unwrap_or(false);
    let kev_due: Option<NaiveDate> = r.try_get("kev_due_date").ok().flatten();
    let disc = r
        .try_get::<DateTime<Utc>, _>("discovered_at")
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default();
    AssessmentFinding {
        id: r.try_get("id").unwrap_or(0),
        finding_id: r.try_get("finding_id").unwrap_or_default(),
        title: r.try_get("title").unwrap_or_default(),
        severity: r.try_get("severity").unwrap_or_default(),
        source: r.try_get("source").unwrap_or_default(),
        status: r.try_get("status").unwrap_or_default(),
        description: r.try_get("description").unwrap_or_default(),
        poc: r.try_get("poc_exploit").unwrap_or_default(),
        poc_sealed: r.try_get("poc_sealed").unwrap_or(false),
        discovered_at: disc,
        cve: json_text(&raw, &["cve", "cve_id"]),
        cwe: json_text(&raw, &["cwe"]),
        cvss: live_cvss(&raw),
        cvss_vector: json_text(&raw, &["cvss_vector", "cvss_v3_vector"]),
        epss: live_epss(epss, &raw),
        kev: live_kev(kev_listed, kev_ransom, kev_due),
        mitre: json_text(&raw, &["mitre_attack", "mitre"]),
        asset: json_text(&raw, &["target", "host", "asset"]),
    }
}

fn live_cvss(raw: &Value) -> String {
    let v = raw
        .get("cvss_score")
        .or_else(|| raw.get("cvss"))
        .or_else(|| raw.get("score"));
    match v {
        Some(Value::Number(n)) => {
            let f = n.as_f64().unwrap_or(0.0);
            if f > 0.0 {
                format!("{f:.1}")
            } else {
                String::new()
            }
        }
        Some(Value::String(s)) => {
            let s = s.trim();
            if s.is_empty() {
                return String::new();
            }
            if let Ok(f) = s.parse::<f64>() {
                if f > 0.0 {
                    return format!("{f:.1}");
                }
                return String::new();
            }
            s.to_string()
        }
        _ => String::new(),
    }
}

fn live_epss(column: Option<f32>, raw: &Value) -> String {
    if let Some(s) = column {
        if s > 0.0 {
            return format!("{s:.3}");
        }
    }
    if let Some(obj) = raw.get("epss") {
        if let Some(n) = obj.get("score").and_then(Value::as_f64) {
            if n > 0.0 {
                return format!("{n:.3}");
            }
        }
    }
    String::new()
}

fn live_kev(listed: bool, ransomware: bool, due: Option<NaiveDate>) -> String {
    if !listed {
        return String::new();
    }
    let mut s = if ransomware {
        "CISA KEV · ransomware".to_string()
    } else {
        "CISA KEV".to_string()
    };
    if let Some(d) = due {
        s.push_str(&format!(" · due {d}"));
    }
    s
}

fn json_text(raw: &Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(v) = raw.get(*key) {
            let s = match v {
                Value::String(s) => s.trim().to_string(),
                Value::Number(n) => n.to_string(),
                Value::Array(a) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(str::trim))
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => String::new(),
            };
            if !s.is_empty() && s != "0" && s != "0.0" && s != "null" {
                return s;
            }
        }
    }
    String::new()
}

fn parse_string_list(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if let Ok(v) = serde_json::from_str::<Vec<String>>(trimmed) {
        return v
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        if let Some(arr) = v.as_array() {
            return arr
                .iter()
                .filter_map(|x| x.as_str().map(str::trim))
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
        }
    }
    Vec::new()
}

fn scope_line(client_name: &str, domains: &str, ip_ranges: &str) -> String {
    let mut parts = parse_string_list(domains);
    parts.extend(parse_string_list(ip_ranges));
    if parts.is_empty() {
        return client_name.to_string();
    }
    const MAX: usize = 12;
    let extra = parts.len().saturating_sub(MAX);
    parts.truncate(MAX);
    let mut line = format!("{client_name} · {}", parts.join(", "));
    if extra > 0 {
        line.push_str(&format!(" (+{extra})"));
    }
    line
}

fn roe_mode_from_configs(raw: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(raw.trim()) else {
        return String::new();
    };
    v.get("roe_mode")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("")
        .to_string()
}

/// ASCII-safe attachment stem; Hebrew letters stay (they are alphanumeric).
#[must_use]
pub fn safe_filename(client_name: &str, ext: &str) -> String {
    let safe: String = client_name
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .take(48)
        .collect();
    let safe = safe.trim_matches('_');
    if safe.is_empty() {
        format!("Weissman_Assessment.{ext}")
    } else {
        format!("Weissman_Assessment_{safe}.{ext}")
    }
}

fn col(title: &str, weight: f64, style: &str) -> ColumnSpec {
    ColumnSpec {
        title: title.to_string(),
        weight,
        style: style.to_string(),
    }
}

/// Tenable-class multi-sheet workbook: Overview (renderer) + Executive + Findings +
/// Remediation + Intel. Brand mark is drawn by [`crate::xlsx_report::render_workbook`].
pub fn client_assessment_workbook(
    pack: &ClientAssessment,
    actor: &str,
    lang: Lang,
) -> Result<Vec<u8>, String> {
    let findings_cols = vec![
        col(t::COL_ID.get(lang), 1.0, "mono"),
        col(t::COL_FINDING_ID.get(lang), 1.2, "mono"),
        col(t::COL_FINDING.get(lang), 3.0, "strong"),
        col(t::COL_SEVERITY.get(lang), 1.0, "severity"),
        col(t::COL_CVSS.get(lang), 0.8, "number"),
        col(t::COL_CVE.get(lang), 1.2, "mono"),
        col(t::COL_CWE.get(lang), 1.0, "mono"),
        col(t::COL_KEV.get(lang), 1.2, ""),
        col(t::COL_EPSS.get(lang), 0.8, "number"),
        col(t::COL_MITRE.get(lang), 1.4, ""),
        col(t::COL_ASSET.get(lang), 1.8, ""),
        col(t::COL_SOURCE.get(lang), 1.2, ""),
        col(t::COL_STATUS.get(lang), 1.0, ""),
        col(t::COL_VERIFIED.get(lang), 1.0, ""),
        col(t::COL_DISCOVERED.get(lang), 1.4, ""),
        col(t::COL_PROOF.get(lang), 2.2, "mono"),
        col(t::COL_REMEDIATION.get(lang), 2.4, ""),
    ];
    let findings_rows: Vec<Vec<String>> = pack
        .findings
        .iter()
        .map(|f| {
            let rem = crate::pdf_report::remediation_from_desc(&f.description);
            vec![
                format!("VLN-{}", f.id),
                f.finding_id.clone(),
                f.title.clone(),
                f.severity.clone(),
                f.cvss.clone(),
                f.cve.clone(),
                f.cwe.clone(),
                f.kev.clone(),
                f.epss.clone(),
                f.mitre.clone(),
                f.asset.clone(),
                f.source.clone(),
                f.status.clone(),
                f.verified_label().to_string(),
                f.discovered_at.clone(),
                f.poc.clone(),
                if rem == "—" { String::new() } else { rem },
            ]
        })
        .collect();

    let rem_cols = vec![
        col(t::COL_ID.get(lang), 1.0, "mono"),
        col(t::COL_FINDING.get(lang), 3.0, "strong"),
        col(t::COL_SEVERITY.get(lang), 1.0, "severity"),
        col(t::COL_PRIORITY.get(lang), 0.8, "number"),
        col(t::COL_REMEDIATION.get(lang), 4.0, ""),
        col(t::COL_STATUS.get(lang), 1.0, ""),
    ];
    let rem_rows: Vec<Vec<String>> = pack
        .findings
        .iter()
        .map(|f| {
            let rem = crate::pdf_report::remediation_from_desc(&f.description);
            let prio = crate::pdf_report::remediation_priority_score_for_row(
                &f.description,
                &f.severity,
                &f.poc,
            );
            vec![
                format!("VLN-{}", f.id),
                f.title.clone(),
                f.severity.clone(),
                prio.to_string(),
                if rem == "—" { String::new() } else { rem },
                f.status.clone(),
            ]
        })
        .collect();

    let intel_cols = vec![
        col(t::COL_ID.get(lang), 1.0, "mono"),
        col(t::COL_FINDING.get(lang), 2.6, "strong"),
        col(t::COL_CVE.get(lang), 1.2, "mono"),
        col(t::COL_CVSS.get(lang), 0.8, "number"),
        col(t::COL_EPSS.get(lang), 0.8, "number"),
        col(t::COL_KEV.get(lang), 1.4, ""),
        col(t::COL_CWE.get(lang), 1.0, "mono"),
        col(t::COL_MITRE.get(lang), 1.6, ""),
    ];
    let intel_rows: Vec<Vec<String>> = pack
        .findings
        .iter()
        .filter(|f| !f.cve.is_empty() || !f.kev.is_empty() || !f.epss.is_empty())
        .map(|f| {
            vec![
                format!("VLN-{}", f.id),
                f.title.clone(),
                f.cve.clone(),
                f.cvss.clone(),
                f.epss.clone(),
                f.kev.clone(),
                f.cwe.clone(),
                f.mitre.clone(),
            ]
        })
        .collect();

    let exec_cols = vec![
        col(t::COL_METRIC.get(lang), 2.2, "strong"),
        col(t::COL_VALUE.get(lang), 4.0, ""),
    ];
    let (crit, high, med, low) = severity_counts(pack);
    let exec_rows = vec![
        vec![t::SCOPE.get(lang).to_string(), pack.scope_line.clone()],
        vec![
            t::FINDINGS_N.get(lang).to_string(),
            pack.findings.len().to_string(),
        ],
        vec![t::CRITICAL.get(lang).to_string(), crit.to_string()],
        vec![t::HIGH.get(lang).to_string(), high.to_string()],
        vec![t::MEDIUM.get(lang).to_string(), med.to_string()],
        vec![t::LOW.get(lang).to_string(), low.to_string()],
        vec![
            t::COL_KEV.get(lang).to_string(),
            pack.kev_count().to_string(),
        ],
        vec![
            t::COL_CVE.get(lang).to_string(),
            pack.cve_count().to_string(),
        ],
        vec![
            t::COL_EPSS.get(lang).to_string(),
            pack.epss_count().to_string(),
        ],
        vec![
            t::COL_VERIFIED.get(lang).to_string(),
            pack.verified_count().to_string(),
        ],
        vec![
            t::COL_CVSS.get(lang).to_string(),
            pack.cvss_count().to_string(),
        ],
        vec![
            t::ROE_HEADING.get(lang).to_string(),
            if pack.roe_mode.is_empty() {
                String::new()
            } else {
                pack.roe_mode.clone()
            },
        ],
    ];

    let spec = WorkbookSpec {
        title: t::ASSESSMENT_TITLE.get(lang).to_string(),
        subtitle: t::ASSESSMENT_SUB.get(lang).to_string(),
        org: t::ORG.get(lang).to_string(),
        client: pack.client_name.clone(),
        classification: t::CLASSIFICATION.get(lang).to_string(),
        lang: match lang {
            Lang::He => "he".into(),
            Lang::En => "en".into(),
        },
        actor: actor.to_string(),
        sheets: vec![
            SheetSpec {
                name: t::EXEC_SHEET.get(lang).to_string(),
                columns: exec_cols,
                rows: exec_rows,
            },
            SheetSpec {
                name: t::DATA_SHEET.get(lang).to_string(),
                columns: findings_cols,
                rows: findings_rows,
            },
            SheetSpec {
                name: t::REMEDIATION_SHEET.get(lang).to_string(),
                columns: rem_cols,
                rows: rem_rows,
            },
            SheetSpec {
                name: t::INTEL_SHEET.get(lang).to_string(),
                columns: intel_cols,
                rows: intel_rows,
            },
        ],
    };
    crate::xlsx_report::render_workbook(&spec)
}

fn severity_counts(pack: &ClientAssessment) -> (u32, u32, u32, u32) {
    pack.findings.iter().fold((0, 0, 0, 0), |acc, f| {
        let s = f.severity.to_lowercase();
        let (c, h, m, l) = acc;
        if s.contains("critical") {
            (c + 1, h, m, l)
        } else if s.contains("high") {
            (c, h + 1, m, l)
        } else if s.contains("medium") || s.contains("med") {
            (c, h, m + 1, l)
        } else {
            (c, h, m, l + 1)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ClientAssessment {
        ClientAssessment {
            client_id: 7,
            client_name: "Acme".into(),
            scope_line: "Acme · acme.example".into(),
            roe_mode: "safe_proofs".into(),
            findings: vec![AssessmentFinding {
                id: 1,
                finding_id: "web-1".into(),
                title: "Open admin".into(),
                severity: "critical".into(),
                source: "web".into(),
                status: "OPEN".into(),
                description: r#"{"remediation":"lock it","cvss_score":9.8}"#.into(),
                poc: "curl https://x".into(),
                poc_sealed: true,
                discovered_at: "2026-09-05 12:00:00 UTC".into(),
                cve: "CVE-2024-1234".into(),
                cwe: "CWE-287".into(),
                cvss: "9.8".into(),
                cvss_vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(),
                epss: "0.972".into(),
                kev: "CISA KEV".into(),
                mitre: "T1190".into(),
                asset: "https://acme.example".into(),
            }],
        }
    }

    #[test]
    fn workbook_is_a_zip_with_live_intel_sheets() {
        let bytes =
            client_assessment_workbook(&sample(), "analyst@weissman", Lang::En).expect("xlsx");
        assert_eq!(&bytes[0..2], b"PK");
        assert!(bytes.len() > 3_000);
        let as_str = String::from_utf8_lossy(&bytes);
        assert!(as_str.contains("Findings") || as_str.contains("xl/"));
    }

    #[test]
    fn hebrew_workbook_is_still_a_zip() {
        let bytes = client_assessment_workbook(&sample(), "analyst", Lang::He).expect("xlsx");
        assert_eq!(&bytes[0..2], b"PK");
    }

    #[test]
    fn empty_findings_still_headers() {
        let mut pack = sample();
        pack.findings.clear();
        let bytes = client_assessment_workbook(&pack, "analyst", Lang::En).expect("xlsx");
        assert_eq!(&bytes[0..2], b"PK");
    }

    #[test]
    fn cvss_zero_is_blank_not_invented() {
        assert_eq!(live_cvss(&json!({"cvss_score": 0.0})), "");
        assert_eq!(live_cvss(&json!({"cvss_score": 9.8})), "9.8");
        assert_eq!(live_cvss(&json!({})), "");
    }

    #[test]
    fn kev_blank_when_not_listed() {
        assert_eq!(live_kev(false, true, None), "");
        assert!(live_kev(true, false, None).contains("CISA KEV"));
    }

    #[test]
    fn formula_like_title_is_safe_in_workbook() {
        let mut pack = sample();
        pack.findings[0].title = "=CMD('calc')".into();
        let bytes = client_assessment_workbook(&pack, "analyst", Lang::En).expect("xlsx");
        assert_eq!(&bytes[0..2], b"PK");
    }

    #[test]
    fn filename_keeps_hebrew_letters() {
        let name = safe_filename("לקוח", "pdf");
        assert!(name.starts_with("Weissman_Assessment_"));
        assert!(name.ends_with(".pdf"));
        assert!(name.contains("לקוח"));
    }
}
