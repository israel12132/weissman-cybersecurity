//! Central PDF intelligence: collect every live report artifact and compose a
//! professional board/regulator pack from real findings + compliance mappings.
//!
//! Live-only. An empty corpus is a visible failure, never a fake PDF.

use crate::compliance_engine::{self, FrameworkPosture};
use crate::pdf_report::{self, IntelligencePackSection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

#[derive(Debug, Clone, Serialize)]
pub struct PdfCorpusItem {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub client_id: Option<i64>,
    pub created_at: Option<String>,
    pub pdf_path: Option<String>,
    pub finding_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PdfIntelligenceSnapshot {
    pub ok: bool,
    pub live: bool,
    pub client_id: Option<i64>,
    pub client_name: Option<String>,
    pub org_name: String,
    pub corpus: Vec<PdfCorpusItem>,
    pub findings: FindingsRollup,
    pub frameworks: Vec<FrameworkPosture>,
    pub empty_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct FindingsRollup {
    pub total: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComposeRequest {
    pub client_id: Option<i64>,
    pub title: Option<String>,
    #[serde(default)]
    pub sections: Vec<ComposeSectionSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ComposeSectionSpec {
    pub id: String,
    #[serde(default)]
    pub enabled: bool,
}

pub fn default_section_catalog() -> Value {
    json!([
        {"id": "cover", "enabled": true, "label": "Cover & classification"},
        {"id": "executive", "enabled": true, "label": "Executive briefing"},
        {"id": "findings", "enabled": true, "label": "Live findings"},
        {"id": "nist_csf", "enabled": true, "label": "NIST CSF 2.0"},
        {"id": "iso27001", "enabled": true, "label": "ISO/IEC 27001:2022"},
        {"id": "soc2", "enabled": true, "label": "SOC 2"},
        {"id": "gdpr", "enabled": true, "label": "GDPR"},
        {"id": "pci", "enabled": true, "label": "PCI DSS 4.0"},
        {"id": "hipaa", "enabled": true, "label": "HIPAA"},
        {"id": "cis", "enabled": false, "label": "CIS Controls"},
        {"id": "nis2", "enabled": false, "label": "NIS2"},
        {"id": "dora", "enabled": false, "label": "DORA"},
        {"id": "iec62443", "enabled": false, "label": "IEC 62443"},
        {"id": "mitre", "enabled": true, "label": "MITRE ATT&CK coverage"},
        {"id": "reports", "enabled": true, "label": "Report run ledger"}
    ])
}

pub async fn load_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<PdfIntelligenceSnapshot, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("db: {e}"))?;

    let org_name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "Weissman tenant".to_string());

    let client_name: Option<String> = if let Some(cid) = client_id {
        sqlx::query_scalar("SELECT name FROM clients WHERE id = $1")
            .bind(cid)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    let report_rows = if let Some(cid) = client_id {
        sqlx::query(
            r#"SELECT rr.id, rr.created_at, rr.pdf_path,
                      (SELECT COUNT(*)::bigint FROM vulnerabilities v WHERE v.run_id = rr.id)::bigint AS n
                 FROM report_runs rr
                WHERE EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.run_id = rr.id AND v.client_id = $1)
                ORDER BY rr.created_at DESC
                LIMIT 100"#,
        )
        .bind(cid)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default()
    } else {
        sqlx::query(
            r#"SELECT rr.id, rr.created_at, rr.pdf_path,
                      (SELECT COUNT(*)::bigint FROM vulnerabilities v WHERE v.run_id = rr.id)::bigint AS n
                 FROM report_runs rr
                ORDER BY rr.created_at DESC
                LIMIT 100"#,
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default()
    };

    let mut corpus: Vec<PdfCorpusItem> = report_rows
        .into_iter()
        .map(|r| PdfCorpusItem {
            id: format!("run:{}", r.try_get::<i64, _>("id").unwrap_or(0)),
            kind: "report_run".into(),
            title: format!(
                "Report run #{}",
                r.try_get::<i64, _>("id").unwrap_or(0)
            ),
            client_id,
            created_at: r
                .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                .ok()
                .map(|d| d.to_rfc3339()),
            pdf_path: r.try_get::<Option<String>, _>("pdf_path").ok().flatten(),
            finding_count: r.try_get::<i64, _>("n").unwrap_or(0),
        })
        .collect();

    corpus.insert(
        0,
        PdfCorpusItem {
            id: "executive".into(),
            kind: "executive".into(),
            title: "Executive / board briefing (live)".into(),
            client_id,
            created_at: Some(chrono::Utc::now().to_rfc3339()),
            pdf_path: Some("/api/reports/executive".into()),
            finding_count: 0,
        },
    );
    if client_id.is_some() {
        corpus.insert(
            1,
            PdfCorpusItem {
                id: "evidence_pack".into(),
                kind: "evidence_pack".into(),
                title: "Auditor evidence pack (SHA-256)".into(),
                client_id,
                created_at: Some(chrono::Utc::now().to_rfc3339()),
                pdf_path: Some(format!(
                    "/api/compliance/evidence-pack/{}",
                    client_id.unwrap()
                )),
                finding_count: 0,
            },
        );
    }

    const SEV_AGG: &str = "COUNT(*)::bigint AS total, \
         COUNT(*) FILTER (WHERE lower(severity) LIKE '%critical%')::bigint AS critical, \
         COUNT(*) FILTER (WHERE lower(severity) NOT LIKE '%critical%' AND lower(severity) LIKE '%high%')::bigint AS high, \
         COUNT(*) FILTER (WHERE lower(severity) NOT LIKE '%critical%' AND lower(severity) NOT LIKE '%high%' AND lower(severity) LIKE '%med%')::bigint AS medium, \
         COUNT(*) FILTER (WHERE lower(severity) NOT LIKE '%critical%' AND lower(severity) NOT LIKE '%high%' AND lower(severity) NOT LIKE '%med%')::bigint AS low";

    let sev = if let Some(cid) = client_id {
        sqlx::query(&format!("SELECT {SEV_AGG} FROM vulnerabilities WHERE client_id = $1"))
            .bind(cid)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten()
    } else {
        sqlx::query(&format!("SELECT {SEV_AGG} FROM vulnerabilities"))
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten()
    };
    let findings = if let Some(r) = sev {
        FindingsRollup {
            total: r.try_get("total").unwrap_or(0),
            critical: r.try_get("critical").unwrap_or(0),
            high: r.try_get("high").unwrap_or(0),
            medium: r.try_get("medium").unwrap_or(0),
            low: r.try_get("low").unwrap_or(0),
        }
    } else {
        FindingsRollup::default()
    };

    let mappings = compliance_engine::load_mappings(&mut *tx)
        .await
        .unwrap_or_default();
    let cloud_rules: Vec<String> = if let Some(cid) = client_id {
        sqlx::query_scalar("SELECT rule_id FROM cloud_scan_findings WHERE client_id = $1")
            .bind(cid)
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    } else {
        sqlx::query_scalar("SELECT rule_id FROM cloud_scan_findings")
            .fetch_all(&mut *tx)
            .await
            .unwrap_or_default()
    };
    let vuln_tuples: Vec<(String, String, String)> = if let Some(cid) = client_id {
        sqlx::query(
            "SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities WHERE client_id = $1 LIMIT 2000",
        )
        .bind(cid)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| {
            Some((
                r.try_get::<String, _>("source").ok()?,
                r.try_get::<String, _>("title").ok()?,
                r.try_get::<String, _>("severity").ok()?,
            ))
        })
        .collect()
    } else {
        sqlx::query(
            "SELECT COALESCE(source,'') AS source, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity FROM vulnerabilities LIMIT 2000",
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| {
            Some((
                r.try_get::<String, _>("source").ok()?,
                r.try_get::<String, _>("title").ok()?,
                r.try_get::<String, _>("severity").ok()?,
            ))
        })
        .collect()
    };
    let frameworks = compliance_engine::compute_posture(&mappings, &cloud_rules, &vuln_tuples);
    let _ = tx.commit().await;

    let empty = findings.total == 0 && corpus.iter().all(|c| c.kind != "report_run");
    Ok(PdfIntelligenceSnapshot {
        ok: true,
        live: true,
        client_id,
        client_name,
        org_name,
        corpus,
        findings,
        frameworks,
        empty_reason: if empty {
            Some(
                "No live report runs or findings for this scope. Run engines, then return — Weissman will not fabricate a pack."
                    .into(),
            )
        } else {
            None
        },
    })
}

pub fn compose_bytes(snap: &PdfIntelligenceSnapshot, req: &ComposeRequest) -> Result<Vec<u8>, String> {
    if let Some(reason) = &snap.empty_reason {
        return Err(reason.clone());
    }
    let enabled: Vec<String> = if req.sections.is_empty() {
        default_section_catalog()
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter(|s| s.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false))
            .filter_map(|s| s.get("id").and_then(|v| v.as_str()).map(|x| x.to_string()))
            .collect()
    } else {
        req.sections
            .iter()
            .filter(|s| s.enabled)
            .map(|s| s.id.clone())
            .collect()
    };

    let mut sections: Vec<IntelligencePackSection> = Vec::new();
    if enabled.iter().any(|id| id == "executive" || id == "cover") {
        sections.push(IntelligencePackSection {
            id: "executive".into(),
            title: "Executive briefing".into(),
            lines: vec![
                format!(
                    "Live findings: {} (C {} / H {} / M {} / L {})",
                    snap.findings.total,
                    snap.findings.critical,
                    snap.findings.high,
                    snap.findings.medium,
                    snap.findings.low
                ),
                format!("Report artifacts in corpus: {}", snap.corpus.len()),
            ],
        });
    }
    if enabled.iter().any(|id| id == "findings") {
        sections.push(IntelligencePackSection {
            id: "findings".into(),
            title: "Live findings roll-up".into(),
            lines: vec![
                format!("Total stored vulnerabilities: {}", snap.findings.total),
                "Severity counts derived from the vulnerabilities table — not estimates.".into(),
            ],
        });
    }
    for fw in &snap.frameworks {
        if !enabled.iter().any(|id| section_matches_framework(id, &fw.framework)) {
            continue;
        }
        sections.push(IntelligencePackSection {
            id: slug.clone(),
            title: format!(
                "{} — {}% mapped controls holding",
                fw.framework, fw.compliance_percent
            ),
            lines: vec![
                format!(
                    "Mapped controls: {}  |  Violated: {}",
                    fw.total_mapped_controls, fw.violated_controls
                ),
                "Posture computed from live compliance_mappings against stored findings.".into(),
            ],
        });
    }
    if enabled.iter().any(|id| id == "reports") {
        let mut lines: Vec<String> = snap
            .corpus
            .iter()
            .take(40)
            .map(|c| {
                format!(
                    "{}  {}  findings={}  {}",
                    c.kind,
                    c.title,
                    c.finding_count,
                    c.created_at.clone().unwrap_or_default()
                )
            })
            .collect();
        if lines.is_empty() {
            lines.push("No report_runs rows yet.".into());
        }
        sections.push(IntelligencePackSection {
            id: "reports".into(),
            title: "Report run ledger".into(),
            lines,
        });
    }

    let title = req
        .title
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("Unified intelligence pack");
    pdf_report::build_intelligence_pack_pdf(
        &snap.org_name,
        snap.client_name.as_deref(),
        title,
        snap.findings.critical as u32,
        snap.findings.high as u32,
        snap.findings.medium as u32,
        snap.findings.low as u32,
        &sections,
    )
}

fn section_matches_framework(section_id: &str, framework: &str) -> bool {
    let fw_l = framework.to_ascii_lowercase();
    if let Some(slug) = crate::compliance_engine::framework_slug_for_db(framework) {
        if section_id == slug {
            return true;
        }
    }
    match section_id {
        "nist_csf" | "nist" => fw_l.contains("nist"),
        "iso27001" => fw_l.contains("iso"),
        "soc2" => fw_l.contains("soc"),
        "pci" => fw_l.contains("pci"),
        "iec62443" => fw_l.contains("62443") || fw_l.contains("iec"),
        "mitre" => fw_l.contains("mitre") || fw_l.contains("att&ck") || fw_l.contains("attack"),
        "dora" => fw_l.contains("dora"),
        other => {
            let compact = other.replace('_', "");
            fw_l.contains(other) || fw_l.contains(&compact)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_catalog_covers_tier1_frameworks() {
        let v = default_section_catalog();
        let ids: Vec<&str> = v
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x.get("id").and_then(|i| i.as_str()))
            .collect();
        for need in ["nist_csf", "iso27001", "soc2", "gdpr", "pci", "hipaa", "mitre"] {
            assert!(ids.contains(&need), "missing {need}");
        }
    }

    #[test]
    fn section_ids_match_live_catalog_framework_names() {
        assert!(section_matches_framework("nist_csf", "NIST"));
        assert!(section_matches_framework("iso27001", "ISO27001"));
        assert!(section_matches_framework("soc2", "SOC2"));
        assert!(section_matches_framework("pci", "PCI"));
        assert!(!section_matches_framework("hipaa", "SOC2"));
    }

    #[test]
    fn compose_fails_closed_when_empty() {
        let snap = PdfIntelligenceSnapshot {
            ok: true,
            live: true,
            client_id: Some(1),
            client_name: Some("Acme".into()),
            org_name: "T".into(),
            corpus: vec![],
            findings: FindingsRollup::default(),
            frameworks: vec![],
            empty_reason: Some("No live report runs".into()),
        };
        let err = compose_bytes(&snap, &ComposeRequest { client_id: Some(1), title: None, sections: vec![] })
            .unwrap_err();
        assert!(err.contains("No live"));
    }

    #[test]
    fn compose_emits_pdf_magic_from_live_rollup() {
        let snap = PdfIntelligenceSnapshot {
            ok: true,
            live: true,
            client_id: Some(1),
            client_name: Some("Acme".into()),
            org_name: "Weissman".into(),
            corpus: vec![PdfCorpusItem {
                id: "run:1".into(),
                kind: "report_run".into(),
                title: "Run 1".into(),
                client_id: Some(1),
                created_at: None,
                pdf_path: None,
                finding_count: 3,
            }],
            findings: FindingsRollup {
                total: 3,
                critical: 1,
                high: 1,
                medium: 1,
                low: 0,
            },
            frameworks: vec![],
            empty_reason: None,
        };
        let bytes = compose_bytes(
            &snap,
            &ComposeRequest {
                client_id: Some(1),
                title: Some("Board pack".into()),
                sections: vec![
                    ComposeSectionSpec { id: "executive".into(), enabled: true },
                    ComposeSectionSpec { id: "findings".into(), enabled: true },
                    ComposeSectionSpec { id: "reports".into(), enabled: true },
                ],
            },
        )
        .expect("compose");
        assert!(bytes.starts_with(b"%PDF-1.4"));
    }
}
