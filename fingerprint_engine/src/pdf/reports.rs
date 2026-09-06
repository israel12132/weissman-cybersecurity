//! Product reports built on [`ReportDoc`] — client assessment, board briefing, compliance
//! packet, fuzzer anomaly sidecar. Public signatures live in `pdf_report` so existing
//! callers keep compiling; this module is the implementation.

use super::charts::{Chart, Slice};
use super::copy as t;
use super::doc::{Block, Callout, DocMeta, Lang, Metric, ReportDoc, Section, Tone};
use super::layout::{CellStyle, Column, Table};
use super::theme;
use crate::pdf_report::{
    discovery_noise_count, remediation_from_desc, remediation_priority_score_for_row,
    should_include_in_detailed_findings, CryptoProof, FindingRow,
};
use chrono::TimeZone;
use chrono_tz::Asia::Jerusalem;

fn israel_now() -> String {
    Jerusalem
        .from_utc_datetime(&chrono::Utc::now().naive_utc())
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}

fn org() -> String {
    t::ORG.get(Lang::En).to_string()
}

fn count_severity(findings: &[FindingRow]) -> (i64, i64, i64, i64, i32) {
    let (critical, high, medium, low_info) =
        findings
            .iter()
            .fold((0i64, 0i64, 0i64, 0i64), |acc, (_, _, sev, _, _, _)| {
                let s = sev.to_lowercase();
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
            });
    let score = (100 - critical * 25 - high * 15 - medium * 5)
        .max(0)
        .min(100) as i32;
    (critical, high, medium, low_info, score)
}

fn avg_priority(findings: &[FindingRow]) -> i32 {
    if findings.is_empty() {
        return 0;
    }
    let sum: i32 = findings
        .iter()
        .map(|(_, _, sev, _, desc, poc)| remediation_priority_score_for_row(desc, sev, poc))
        .sum();
    sum / findings.len() as i32
}

fn efficiency(lang: Lang, severity: &str) -> &'static str {
    let s = severity.to_lowercase();
    if s.contains("critical") {
        t::HIGH_IMPACT.get(lang)
    } else if s.contains("high") {
        t::HIGH_MODERATE.get(lang)
    } else {
        t::MODERATE_EASY.get(lang)
    }
}

fn base_meta(lang: Lang, title: &str, subtitle: &str, client: &str) -> DocMeta {
    DocMeta {
        title: title.to_string(),
        subtitle: subtitle.to_string(),
        org: org(),
        client: client.to_string(),
        classification: t::CLASSIFICATION.get(lang).to_string(),
        doc_id: String::new(),
        lang,
        control_fields: vec![(t::GENERATED.get(lang).to_string(), israel_now())],
        integrity_hash: None,
        verify_url: None,
        watermark: None,
    }
}

/// Client executive security assessment (tuple rows — tests and legacy callers).
pub fn client_assessment(
    client_name: &str,
    findings: &[FindingRow],
    crypto_proof: Option<&CryptoProof>,
    lang: Lang,
) -> Result<Vec<u8>, String> {
    let pack = crate::client_assessment::ClientAssessment::from_rows(client_name, findings);
    client_assessment_live(&pack, crypto_proof, lang)
}

/// Client executive security assessment from a live pack (logo chrome, live intel).
pub fn client_assessment_live(
    pack: &crate::client_assessment::ClientAssessment,
    crypto_proof: Option<&CryptoProof>,
    lang: Lang,
) -> Result<Vec<u8>, String> {
    let rows = pack.finding_rows();
    let findings = rows.as_slice();
    let client_name = pack.client_name.as_str();
    let (critical, high, medium, low_info, score) = count_severity(findings);
    let avg_rp = avg_priority(findings);
    let mut meta = base_meta(
        lang,
        t::ASSESSMENT_TITLE.get(lang),
        t::ASSESSMENT_SUB.get(lang),
        client_name,
    );
    meta.doc_id = crate::client_assessment::assessment_doc_id(pack);
    meta.control_fields.push((
        t::DOC_ID.get(lang).to_string(),
        meta.doc_id.clone(),
    ));
    meta.control_fields.push((
        t::PREPARED_FOR.get(lang).to_string(),
        client_name.to_string(),
    ));
    meta.control_fields
        .push((t::SCOPE.get(lang).to_string(), pack.scope_line.clone()));
    meta.control_fields.push((
        t::FINDINGS_N.get(lang).to_string(),
        findings.len().to_string(),
    ));
    meta.control_fields.push((
        t::VERIFIED.get(lang).to_string(),
        pack.verified_count().to_string(),
    ));
    if !pack.roe_mode.is_empty() {
        meta.control_fields
            .push((t::ROE_HEADING.get(lang).to_string(), pack.roe_mode.clone()));
    }
    if let Some((hash, _, url)) = crypto_proof {
        meta.integrity_hash = Some(hash.clone());
        meta.verify_url = Some(url.clone());
    }

    let slices = vec![
        Slice::new(t::CRITICAL.get(lang), critical as f64, theme::SEV_CRITICAL),
        Slice::new(t::HIGH.get(lang), high as f64, theme::SEV_HIGH),
        Slice::new(t::MEDIUM.get(lang), medium as f64, theme::SEV_MEDIUM),
        Slice::new(t::LOW.get(lang), low_info as f64, theme::SEV_LOW),
    ];

    let mut exec = Section::new(t::EXEC_SUMMARY.get(lang))
        .with(Block::Callout(Callout::new(
            Tone::Brand,
            t::BLUF.get(lang),
            bluf_paragraph(pack, critical, high, lang),
        )))
        .with(Block::Metrics(vec![
            Metric::new(t::CRITICAL.get(lang), critical.to_string(), Tone::Bad),
            Metric::new(t::HIGH.get(lang), high.to_string(), Tone::Warn),
            Metric::new(t::MEDIUM.get(lang), medium.to_string(), Tone::Warn),
            Metric::new(t::LOW.get(lang), low_info.to_string(), Tone::Brand),
            Metric::new(
                t::COL_PRIORITY.get(lang),
                format!("{avg_rp}/100"),
                Tone::Neutral,
            ),
            Metric::new(
                t::COL_KEV.get(lang),
                pack.kev_count().to_string(),
                if pack.kev_count() > 0 {
                    Tone::Bad
                } else {
                    Tone::Neutral
                },
            ),
        ]))
        .with(Block::Chart(Chart::Donut {
            slices: slices.clone(),
            caption: t::SEVERITY_MIX.get(lang).to_string(),
        }))
        .with(Block::Chart(Chart::RiskMatrix {
            cells: risk_cells(findings),
            caption: String::new(),
        }))
        .with(Block::Paragraph(t::POSTURE_NOTE.get(lang).to_string()));

    let discovery_n = discovery_noise_count(findings);
    if discovery_n > 0 {
        exec.push(Block::Callout(Callout::new(
            Tone::Neutral,
            t::DISCOVERY.get(lang),
            format!("{}: {discovery_n}", t::DISCOVERY.get(lang)),
        )));
    }

    let detailed: Vec<&FindingRow> = findings
        .iter()
        .filter(|f| should_include_in_detailed_findings(f))
        .collect();
    let mut ranked = detailed.clone();
    ranked.sort_by(|a, b| {
        theme::severity_rank(&a.2)
            .cmp(&theme::severity_rank(&b.2))
            .then_with(|| {
                remediation_priority_score_for_row(&b.4, &b.2, &b.5)
                    .cmp(&remediation_priority_score_for_row(&a.4, &a.2, &a.5))
            })
    });

    let mut roadmap = Section::new(t::REMEDIATION.get(lang))
        .on_new_page()
        .with(Block::Paragraph(t::REMEDIATION_INTRO.get(lang).to_string()));
    for (idx, (id, title, severity, _src, desc, _poc)) in ranked.iter().take(3).enumerate() {
        let rem = remediation_from_desc(desc);
        let action = if rem != "—" {
            rem
        } else {
            format!("Remediate VLN-{id}")
        };
        roadmap.push(Block::Callout(Callout::new(
            Tone::from_severity(severity),
            format!("{} {} — VLN-{id}", t::PRIORITY.get(lang), idx + 1),
            format!(
                "{}: {severity} — {title}\n{}: {action}\n{}: {}",
                t::THREAT.get(lang),
                t::ACTION.get(lang),
                t::EFFICIENCY.get(lang),
                efficiency(lang, severity)
            ),
        )));
    }

    let mut findings_sec = Section::new(t::FINDINGS.get(lang))
        .on_new_page()
        .with(Block::Paragraph(t::REGISTER_INTRO.get(lang).to_string()));
    if pack.findings.is_empty() {
        findings_sec.push(Block::Callout(Callout::new(
            Tone::Neutral,
            "",
            t::NO_FINDINGS.get(lang),
        )));
    } else {
        let table_rows: Vec<Vec<String>> = pack
            .findings
            .iter()
            .map(|f| {
                let rem = remediation_from_desc(&f.description);
                vec![
                    format!("VLN-{}", f.id),
                    f.title.clone(),
                    f.severity.clone(),
                    dash(&f.cvss),
                    dash(&f.cvss_vector),
                    dash(&f.cve),
                    dash(&f.cwe),
                    dash(&f.kev),
                    dash(&f.epss),
                    dash(&f.mitre),
                    dash(&f.asset),
                    dash(&f.status),
                    if rem == "—" { String::new() } else { rem },
                ]
            })
            .collect();
        findings_sec.push(Block::Table(
            Table::new(vec![
                Column::new(t::COL_ID.get(lang), 0.9).styled(CellStyle::Mono),
                Column::new(t::COL_FINDING.get(lang), 2.0).styled(CellStyle::Strong),
                Column::new(t::COL_SEVERITY.get(lang), 0.8).styled(CellStyle::Severity),
                Column::new(t::COL_CVSS.get(lang), 0.6).styled(CellStyle::Number),
                Column::new(t::COL_VECTOR.get(lang), 1.4).styled(CellStyle::Mono),
                Column::new(t::COL_CVE.get(lang), 1.0).styled(CellStyle::Mono),
                Column::new(t::COL_CWE.get(lang), 0.8).styled(CellStyle::Mono),
                Column::new(t::COL_KEV.get(lang), 0.9).styled(CellStyle::Muted),
                Column::new(t::COL_EPSS.get(lang), 0.6).styled(CellStyle::Number),
                Column::new(t::COL_MITRE.get(lang), 1.0).styled(CellStyle::Mono),
                Column::new(t::COL_ASSET.get(lang), 1.4),
                Column::new(t::COL_STATUS.get(lang), 0.8),
                Column::new(t::COL_REMEDIATION.get(lang), 1.6),
            ])
            .with_rows(table_rows),
        ));
    }
    if !detailed.is_empty() {
        findings_sec.push(Block::Paragraph(t::PROOF_FILTER.get(lang).to_string()));
        let proof_rows: Vec<Vec<String>> = detailed
            .iter()
            .map(|(id, title, severity, source, desc, poc)| {
                vec![
                    format!("VLN-{id}"),
                    title.clone(),
                    severity.clone(),
                    source.clone(),
                    if poc.trim().is_empty() {
                        "—".to_string()
                    } else {
                        poc.clone()
                    },
                    {
                        let rem = remediation_from_desc(desc);
                        if rem == "—" {
                            String::new()
                        } else {
                            rem
                        }
                    },
                ]
            })
            .collect();
        findings_sec.push(Block::Table(
            Table::new(vec![
                Column::new(t::COL_ID.get(lang), 1.0).styled(CellStyle::Mono),
                Column::new(t::COL_FINDING.get(lang), 2.4).styled(CellStyle::Strong),
                Column::new(t::COL_SEVERITY.get(lang), 0.9).styled(CellStyle::Severity),
                Column::new(t::COL_SOURCE.get(lang), 1.0).styled(CellStyle::Muted),
                Column::new(t::COL_PROOF.get(lang), 2.4).styled(CellStyle::Mono),
                Column::new(t::COL_REMEDIATION.get(lang), 2.0),
            ])
            .with_rows(proof_rows),
        ));
    }

    let mut integrity = Section::new(t::INTEGRITY.get(lang)).on_new_page();
    if let Some((hash, _, url)) = crypto_proof {
        integrity.push(Block::KeyValues(vec![
            (t::SHA256.get(lang).to_string(), hash.clone()),
            (t::VERIFY.get(lang).to_string(), url.clone()),
        ]));
        integrity.push(Block::Mono(vec![hash.clone()]));
    } else {
        integrity.push(Block::Paragraph(t::INTEGRITY_NONE.get(lang).to_string()));
    }
    integrity.push(Block::Paragraph(t::DISTRIBUTION.get(lang).to_string()));

    let intel_tone = if pack.kev_count() > 0 {
        Tone::Bad
    } else if pack.epss_count() > 0 || pack.cve_count() > 0 {
        Tone::Warn
    } else {
        Tone::Neutral
    };
    let mut scope_sec = Section::new(t::SCOPE_HEADING.get(lang)).with(Block::KeyValues(vec![(
        t::SCOPE.get(lang).to_string(),
        pack.scope_line.clone(),
    )]));
    if !pack.roe_mode.is_empty() {
        scope_sec.push(Block::KeyValues(vec![(
            t::ROE_HEADING.get(lang).to_string(),
            pack.roe_mode.clone(),
        )]));
    }

    let bytes = ReportDoc::new(meta)
        .with_hero(Chart::Gauge {
            score,
            caption: t::SECURITY_SCORE.get(lang).to_string(),
        })
        .with_section(exec)
        .with_section(scope_sec)
        .with_section(roadmap)
        .with_section(
            Section::new(t::THREAT_INTEL.get(lang)).with(Block::Callout(Callout::new(
                intel_tone,
                t::THREAT_INTEL.get(lang),
                intel_paragraph(pack, lang),
            ))),
        )
        .with_section(findings_sec)
        .with_section(finding_narratives(pack, lang))
        .with_section(
            Section::new(t::METHODOLOGY.get(lang))
                .with(Block::Paragraph(t::METHOD_BODY.get(lang).to_string()))
                .with(Block::Paragraph(t::METHOD_STANDARDS.get(lang).to_string())),
        )
        .with_section(integrity)
        .render();
    Ok(bytes)
}

fn bluf_paragraph(
    pack: &crate::client_assessment::ClientAssessment,
    critical: i64,
    high: i64,
    lang: Lang,
) -> String {
    match lang {
        Lang::He => format!(
            "שורה תחתונה עבור {}: {} ממצאים חיים, מהם {} קריטיים ו-{} גבוהים. {} נושאים הוכחת-פריצה חתומה. {} רשומים ב-CISA KEV. יש לפעול לפי עדיפויות 1–3 במפת הדרכים.",
            pack.client_name,
            pack.findings.len(),
            critical,
            high,
            pack.verified_count(),
            pack.kev_count(),
        ),
        Lang::En => format!(
            "Bottom line for {}: {} live findings, of which {} are critical and {} are high. {} carry sealed proof-of-breach. {} are listed in CISA KEV. Act first on Priority 1–3 in the remediation roadmap.",
            pack.client_name,
            pack.findings.len(),
            critical,
            high,
            pack.verified_count(),
            pack.kev_count(),
        ),
    }
}

fn intel_paragraph(pack: &crate::client_assessment::ClientAssessment, lang: Lang) -> String {
    if pack.kev_count() == 0 && pack.epss_count() == 0 && pack.cve_count() == 0 {
        return t::INTEL_NONE.get(lang).to_string();
    }
    match lang {
        Lang::He => format!(
            "העשרת מודיעין חיה על ממצאי הלקוח: {} CISA KEV, {} FIRST EPSS, {} CVE, {} ציוני CVSS. התאים מתמלאים רק מנתוני מנוע וקטלוג שנרשמו.",
            pack.kev_count(),
            pack.epss_count(),
            pack.cve_count(),
            pack.cvss_count(),
        ),
        Lang::En => format!(
            "Live enrichment on this client's findings: {} CISA Known Exploited Vulnerabilities, {} FIRST EPSS scores, {} CVE identifiers, {} CVSS scores. Intel cells are populated only from recorded engine and catalog data.",
            pack.kev_count(),
            pack.epss_count(),
            pack.cve_count(),
            pack.cvss_count(),
        ),
    }
}

fn dash(s: &str) -> String {
    let s = s.trim();
    if s.is_empty() {
        "—".into()
    } else {
        s.to_string()
    }
}

fn clip_chars(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        chars.into_iter().take(max).collect::<String>() + "…"
    }
}

fn finding_narratives(
    pack: &crate::client_assessment::ClientAssessment,
    lang: Lang,
) -> Section {
    let mut sec = Section::new(t::NARRATIVES.get(lang))
        .on_new_page()
        .with(Block::Paragraph(t::NARRATIVE_INTRO.get(lang).to_string()));
    if pack.findings.is_empty() {
        return sec;
    }
    let mut ranked: Vec<&crate::client_assessment::AssessmentFinding> =
        pack.findings.iter().collect();
    ranked.sort_by(|a, b| {
        theme::severity_rank(&a.severity)
            .cmp(&theme::severity_rank(&b.severity))
            .then_with(|| {
                let ka = if a.kev.is_empty() { 1 } else { 0 };
                let kb = if b.kev.is_empty() { 1 } else { 0 };
                ka.cmp(&kb)
            })
    });
    for f in ranked.into_iter().take(12) {
        let rem = remediation_from_desc(&f.description);
        let narrative = crate::client_assessment::human_description(&f.description);
        let mut intel = Vec::new();
        if !f.cvss.is_empty() {
            intel.push(format!("CVSS {}", f.cvss));
        }
        if !f.cvss_vector.is_empty() {
            intel.push(f.cvss_vector.clone());
        }
        if !f.cve.is_empty() {
            intel.push(f.cve.clone());
        }
        if !f.cwe.is_empty() {
            intel.push(f.cwe.clone());
        }
        if !f.kev.is_empty() {
            intel.push(f.kev.clone());
        }
        if !f.epss.is_empty() {
            intel.push(format!("EPSS {}", f.epss));
        }
        if !f.mitre.is_empty() {
            intel.push(f.mitre.clone());
        }
        let mut body = String::new();
        if !f.asset.is_empty() {
            body.push_str(&format!("{}: {}\n", t::COL_ASSET.get(lang), f.asset));
        }
        if !intel.is_empty() {
            body.push_str(&format!(
                "{}: {}\n",
                t::THREAT_INTEL.get(lang),
                intel.join(" · ")
            ));
        }
        if !narrative.is_empty() {
            body.push_str(&format!(
                "{}: {}\n",
                t::COL_DESCRIPTION.get(lang),
                narrative
            ));
        }
        if !f.poc.trim().is_empty() {
            body.push_str(&format!(
                "{}: {}\n",
                t::EVIDENCE.get(lang),
                clip_chars(f.poc.trim(), 700)
            ));
        }
        if rem != "—" {
            body.push_str(&format!("{}: {rem}\n", t::ACTION.get(lang)));
        }
        body.push_str(&format!(
            "{}: {} · {}",
            t::COL_STATUS.get(lang),
            dash(&f.status),
            f.verified_label()
        ));
        sec.push(Block::Callout(Callout::new(
            Tone::from_severity(&f.severity),
            format!("VLN-{} — {} ({})", f.id, f.title, f.severity),
            body,
        )));
    }
    sec
}

fn risk_cells(findings: &[FindingRow]) -> [[u32; 5]; 5] {
    let mut cells = [[0u32; 5]; 5];
    for (_, _, sev, _, _, poc) in findings {
        let impact = match theme::severity_rank(sev) {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 3,
            _ => 4,
        };
        let likelihood = if !poc.trim().is_empty() { 4 } else { 2 };
        cells[impact][likelihood] = cells[impact][likelihood].saturating_add(1);
    }
    cells
}

/// Board / CISO briefing — aggregate counts, no PoC payloads.
pub fn board_briefing(
    org_label: &str,
    client_opt: Option<&str>,
    critical: u32,
    high: u32,
    medium: u32,
    low: u32,
    cloud_finding_count: usize,
    soc2_pct: u8,
    iso_pct: u8,
    gdpr_pct: u8,
    lang: Lang,
) -> Result<Vec<u8>, String> {
    let total = critical + high + medium + low;
    let score = (100u32.saturating_sub(critical * 25 + high * 15 + medium * 5)).min(100) as i32;
    let mut meta = base_meta(
        lang,
        t::BOARD_TITLE.get(lang),
        t::BOARD_SUB.get(lang),
        client_opt.unwrap_or(""),
    );
    meta.control_fields
        .push((t::ORGANIZATION.get(lang).to_string(), org_label.to_string()));
    if let Some(c) = client_opt {
        meta.control_fields
            .push((t::SCOPE.get(lang).to_string(), c.to_string()));
    }

    let slices = vec![
        Slice::new(
            t::CRITICAL.get(lang),
            f64::from(critical),
            theme::SEV_CRITICAL,
        ),
        Slice::new(t::HIGH.get(lang), f64::from(high), theme::SEV_HIGH),
        Slice::new(t::MEDIUM.get(lang), f64::from(medium), theme::SEV_MEDIUM),
        Slice::new(t::LOW.get(lang), f64::from(low), theme::SEV_LOW),
    ];

    let bytes = ReportDoc::new(meta)
        .with_hero(Chart::Gauge {
            score,
            caption: t::SECURITY_SCORE.get(lang).to_string(),
        })
        .with_section(
            Section::new(t::RISK_POSTURE.get(lang))
                .with(Block::Metrics(vec![
                    Metric::new(t::CRITICAL.get(lang), critical.to_string(), Tone::Bad),
                    Metric::new(t::HIGH.get(lang), high.to_string(), Tone::Warn),
                    Metric::new(t::MEDIUM.get(lang), medium.to_string(), Tone::Warn),
                    Metric::new(t::LOW.get(lang), low.to_string(), Tone::Brand),
                    Metric::new(
                        t::CLOUD_MISCONFIG.get(lang),
                        cloud_finding_count.to_string(),
                        Tone::Neutral,
                    ),
                    Metric::new(t::FINDINGS_N.get(lang), total.to_string(), Tone::Neutral),
                ]))
                .with(Block::Chart(Chart::Donut {
                    slices,
                    caption: t::SEVERITY_MIX.get(lang).to_string(),
                })),
        )
        .with_section(
            Section::new(t::COMPLIANCE_POSTURE.get(lang))
                .with(Block::Chart(Chart::Bars {
                    slices: vec![
                        Slice::new("SOC 2", f64::from(soc2_pct), theme::BRAND),
                        Slice::new("ISO 27001", f64::from(iso_pct), theme::CYAN),
                        Slice::new("GDPR", f64::from(gdpr_pct), theme::SKY),
                    ],
                    caption: t::ALIGNMENT.get(lang).to_string(),
                }))
                .with(Block::KeyValues(vec![
                    ("SOC 2".into(), format!("{soc2_pct}%")),
                    ("ISO 27001".into(), format!("{iso_pct}%")),
                    ("GDPR Art. 32".into(), format!("{gdpr_pct}%")),
                ]))
                .with(Block::Paragraph(t::METHOD_BODY.get(lang).to_string())),
        )
        .render();
    Ok(bytes)
}

/// Framework compliance audit. When `invalid_orphans` is `Some`, the document is VOID.
pub fn compliance_audit(
    org_label: &str,
    framework_label: &str,
    compliance_pct: u8,
    controls: &[(String, String, bool)],
    invalid_orphans: Option<&[(String, String)]>,
    lang: Lang,
) -> Result<Vec<u8>, String> {
    let mut meta = base_meta(
        lang,
        t::COMPLIANCE_TITLE.get(lang),
        t::COMPLIANCE_SUB.get(lang),
        org_label,
    );
    meta.control_fields
        .push((t::ORGANIZATION.get(lang).to_string(), org_label.to_string()));
    meta.control_fields.push((
        t::FRAMEWORK.get(lang).to_string(),
        framework_label.to_string(),
    ));
    let compliant = controls.iter().filter(|(_, _, ok)| *ok).count();
    let non_compliant = controls.len().saturating_sub(compliant);

    // Keep VOID markers in the uncompressed Info dictionary so existing tests (and a
    // human opening the raw bytes) can see the document is voided without decompressing
    // content streams.
    if let Some(orphans) = invalid_orphans {
        meta.watermark = Some("INVALID - INCONSISTENT STATE".into());
        meta.classification = "VOID".into();
        // ASCII hyphens (not em dashes) so Info /Subject and /Keywords stay
        // literal PDF strings — auditors grep VOID markers without inflating streams.
        let listed: String = orphans
            .iter()
            .map(|(id, title)| format!("UNMAPPED: {id} - {title}"))
            .collect::<Vec<_>>()
            .join("; ");
        meta.subtitle = format!("REPORT VOID - {listed}");
        meta.doc_id = "VOID".into();
    }

    let mut exec = Section::new(t::EXEC_SUMMARY.get(lang)).with(Block::Metrics(vec![
        Metric::new(
            t::ALIGNMENT.get(lang),
            format!("{compliance_pct}%"),
            if compliance_pct >= 80 {
                Tone::Good
            } else if compliance_pct >= 50 {
                Tone::Warn
            } else {
                Tone::Bad
            },
        ),
        Metric::new(t::COMPLIANT.get(lang), compliant.to_string(), Tone::Good),
        Metric::new(
            t::NON_COMPLIANT.get(lang),
            non_compliant.to_string(),
            Tone::Bad,
        ),
    ]));
    if let Some(orphans) = invalid_orphans {
        exec.push(Block::Callout(Callout::new(
            Tone::Bad,
            t::VOID_BANNER.get(lang),
            t::VOID_BODY.get(lang),
        )));
        let rows: Vec<Vec<String>> = orphans
            .iter()
            .map(|(id, title)| vec![id.clone(), title.clone(), t::UNMAPPED.get(lang).to_string()])
            .collect();
        exec.push(Block::Table(
            Table::new(vec![
                Column::new(t::COL_CONTROL.get(lang), 1.2).styled(CellStyle::Mono),
                Column::new(t::COL_TITLE.get(lang), 3.0).styled(CellStyle::Strong),
                Column::new(t::COL_STATUS.get(lang), 1.4).styled(CellStyle::Severity),
            ])
            .with_rows(rows),
        ));
        exec.push(Block::Paragraph(t::VOID_FOOTER.get(lang).to_string()));
    }

    let rows: Vec<Vec<String>> = controls
        .iter()
        .map(|(id, title, ok)| {
            vec![
                id.clone(),
                title.clone(),
                if *ok {
                    t::COMPLIANT.get(lang)
                } else {
                    t::NON_COMPLIANT.get(lang)
                }
                .to_string(),
            ]
        })
        .collect();

    let bytes = ReportDoc::new(meta)
        .with_hero(Chart::Gauge {
            score: i32::from(compliance_pct),
            caption: t::ALIGNMENT.get(lang).to_string(),
        })
        .with_section(exec)
        .with_section(
            Section::new(t::CONTROL_ASSESSMENT.get(lang))
                .on_new_page()
                .with(Block::Table(
                    Table::new(vec![
                        Column::new(t::COL_CONTROL.get(lang), 1.2).styled(CellStyle::Mono),
                        Column::new(t::COL_TITLE.get(lang), 3.4).styled(CellStyle::Strong),
                        Column::new(t::COL_STATUS.get(lang), 1.4).styled(CellStyle::Severity),
                    ])
                    .with_rows(rows),
                ))
                .with(Block::Paragraph(t::METHOD_BODY.get(lang).to_string())),
        )
        .render();
    Ok(bytes)
}

/// Fuzzer anomaly sidecar — one branded report instead of a Helvetica dump.
pub fn anomaly_report(
    target_url: &str,
    anomaly_type: &str,
    baseline_vs_anomaly: &str,
    severity: &str,
    remediation: &str,
) -> Vec<u8> {
    let lang = Lang::En;
    let mut meta = base_meta(
        lang,
        t::ANOMALY_TITLE.get(lang),
        "Live fuzzer finding — evidence captured at the moment of divergence.",
        target_url,
    );
    meta.control_fields
        .push(("Target".into(), target_url.to_string()));
    meta.control_fields
        .push(("Anomaly".into(), anomaly_type.to_string()));

    ReportDoc::new(meta)
        .with_section(
            Section::new("Anomaly")
                .with(Block::Metrics(vec![
                    Metric::new(
                        t::COL_SEVERITY.get(lang),
                        severity.to_uppercase(),
                        Tone::from_severity(severity),
                    ),
                    Metric::new("Type", anomaly_type, Tone::Neutral),
                ]))
                .with(Block::KeyValues(vec![
                    ("Target URL".into(), target_url.to_string()),
                    ("Anomaly type".into(), anomaly_type.to_string()),
                    ("Severity".into(), severity.to_string()),
                ]))
                .with(Block::Heading("Baseline vs anomaly".into()))
                .with(Block::Mono(vec![baseline_vs_anomaly.to_string()]))
                .with(Block::Heading("Recommended remediation".into()))
                .with(Block::Paragraph(remediation.to_string())),
        )
        .render()
}

/// One-pager used when a caller only needs a receipt, not a full assessment.
pub fn minimal(client_name: &str, findings_count: usize) -> Vec<u8> {
    let lang = Lang::En;
    let mut meta = base_meta(
        lang,
        t::ASSESSMENT_TITLE.get(lang),
        "Receipt of live report generation.",
        client_name,
    );
    meta.control_fields.push((
        t::FINDINGS_N.get(lang).to_string(),
        findings_count.to_string(),
    ));
    ReportDoc::new(meta)
        .with_section(
            Section::new(t::EXEC_SUMMARY.get(lang)).with(Block::Metrics(vec![Metric::new(
                t::FINDINGS_N.get(lang),
                findings_count.to_string(),
                Tone::Brand,
            )])),
        )
        .render()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: i64, title: &str, sev: &str, src: &str, desc: &str, poc: &str) -> FindingRow {
        (
            id,
            title.to_string(),
            sev.to_string(),
            src.to_string(),
            desc.to_string(),
            poc.to_string(),
        )
    }

    #[test]
    fn client_assessment_is_a_valid_pdf() {
        let findings = vec![row(
            1,
            "Open admin",
            "critical",
            "web",
            r#"{"remediation":"lock it"}"#,
            "curl https://x",
        )];
        let bytes = client_assessment("Acme", &findings, None, Lang::En).unwrap();
        assert!(bytes.starts_with(b"%PDF-1."));
        assert!(bytes.windows(5).any(|w| w == b"%%EOF"));
    }

    #[test]
    fn hebrew_client_assessment_embeds_rtl_language_tag() {
        let bytes = client_assessment("לקוח", &[], None, Lang::He).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("/Lang (he-IL)"));
    }

    #[test]
    fn client_assessment_does_not_invent_industry_average_or_apt() {
        let src = include_str!("reports.rs");
        let fake_avg = format!("{}.0", 65);
        let apt = format!("APT{}", 28);
        assert!(
            !src.contains(&fake_avg),
            "must not invent an industry-average score"
        );
        assert!(!src.contains(&apt));
        assert!(!src.contains(&format!("FIN{}", 7)));
        assert!(!src.contains(&["Laz", "arus"].concat()));
        let invented = format!("{} {}", "invented", "apt");
        assert!(!src.to_ascii_lowercase().contains(&invented));
    }

    #[test]
    fn live_pack_pdf_carries_document_id_and_intel() {
        let pack = crate::client_assessment::ClientAssessment {
            client_id: 7,
            client_name: "Acme".into(),
            scope_line: "Acme · acme.example".into(),
            roe_mode: "safe_proofs".into(),
            findings: vec![crate::client_assessment::AssessmentFinding {
                id: 1,
                finding_id: "web-1".into(),
                title: "Open admin".into(),
                severity: "critical".into(),
                source: "web".into(),
                status: "OPEN".into(),
                description: r#"{"description":"Admin console on the internet","remediation":"lock it"}"#.into(),
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
        };
        let bytes = client_assessment_live(&pack, None, Lang::En).unwrap();
        assert!(bytes.starts_with(b"%PDF-1."));
        assert!(crate::client_assessment::assessment_doc_id(&pack).starts_with("WSM-ASR-7-"));
    }

    #[test]
    fn voided_compliance_report_is_marked_in_the_info_dictionary() {
        let orphans = vec![("A.9".to_string(), "Access control".to_string())];
        let bytes = compliance_audit(
            "Acme",
            "ISO/IEC 27001:2022",
            80,
            &[("A.5".into(), "Org".into(), true)],
            Some(&orphans),
            Lang::En,
        )
        .unwrap();
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("INVALID - INCONSISTENT STATE"));
        assert!(body.contains("REPORT VOID"));
        assert!(body.contains("UNMAPPED: A.9"));
        assert!(body.contains("/Keywords (VOID)"));
    }
}
