//! Minimal OOXML (.xlsx) writer — STORE zip, no third-party spreadsheet crate.
//! Excel / LibreOffice open uncompressed workbooks. UTF-8 inline strings support Hebrew.

use super::{BoardPack, PackLang};

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\u{0000}'..='\u{0008}' | '\u{000B}' | '\u{000C}' | '\u{000E}'..='\u{001F}' => {}
            _ => out.push(c),
        }
    }
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn dos_time() -> (u16, u16) {
    // 2026-09-11 00:00 — fixed so tests are deterministic.
    let date = ((2026u16 - 1980) << 9) | (9 << 5) | 11;
    (0, date)
}

struct ZipFile {
    name: String,
    data: Vec<u8>,
}

fn build_zip(files: &[ZipFile]) -> Vec<u8> {
    let (dostime, dosdate) = dos_time();
    let mut local = Vec::new();
    let mut central = Vec::new();
    for f in files {
        let name = f.name.as_bytes();
        let crc = crc32(&f.data);
        let sz = f.data.len() as u32;
        let offset = local.len() as u32;
        local.extend_from_slice(b"PK\x03\x04");
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // STORE
        local.extend_from_slice(&dostime.to_le_bytes());
        local.extend_from_slice(&dosdate.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&sz.to_le_bytes());
        local.extend_from_slice(&sz.to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name);
        local.extend_from_slice(&f.data);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&dostime.to_le_bytes());
        central.extend_from_slice(&dosdate.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&sz.to_le_bytes());
        central.extend_from_slice(&sz.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let cd_off = local.len() as u32;
    let cd_sz = central.len() as u32;
    let n = files.len() as u16;
    let mut out = local;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&cd_sz.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn col_letter(mut n: usize) -> String {
    // 0-based → A, B, … Z, AA
    let mut s = String::new();
    n += 1;
    while n > 0 {
        n -= 1;
        s.insert(0, (b'A' + (n % 26) as u8) as char);
        n /= 26;
    }
    s
}

fn inline_cell(col: usize, row: usize, val: &str) -> String {
    let r = format!("{}{}", col_letter(col), row);
    format!(
        r#"<c r="{r}" t="inlineStr"><is><t xml:space="preserve">{}</t></is></c>"#,
        xml_escape(val)
    )
}

fn row_xml(row: usize, cells: &[&str]) -> String {
    let inner: String = cells
        .iter()
        .enumerate()
        .map(|(i, v)| inline_cell(i, row, v))
        .collect();
    format!(r#"<row r="{row}">{inner}</row>"#)
}

fn sheet_xml(rows: &[Vec<String>]) -> String {
    let body: String = rows
        .iter()
        .enumerate()
        .map(|(i, cols)| {
            let refs: Vec<&str> = cols.iter().map(|s| s.as_str()).collect();
            row_xml(i + 1, &refs)
        })
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{body}</sheetData></worksheet>"#
    )
}

struct SheetSpec {
    name: String,
    path: String,
    rows: Vec<Vec<String>>,
}

fn s<T: ToString>(v: T) -> String {
    v.to_string()
}

pub fn render_xlsx(pack: &BoardPack) -> Result<Vec<u8>, String> {
    let he = pack.lang == PackLang::He;
    let sheets = build_sheets(pack, he);
    if sheets.is_empty() {
        return Err("no sheets".into());
    }

    let content_types = {
        let overrides: String = sheets
            .iter()
            .map(|sh| {
                format!(
                    r#"<Override PartName="/{}" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>"#,
                    sh.path
                )
            })
            .collect();
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
{overrides}
</Types>"#
        )
    };

    let rels_root = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#;

    let wb_sheets: String = sheets
        .iter()
        .enumerate()
        .map(|(i, sh)| {
            format!(
                r#"<sheet name="{}" sheetId="{}" r:id="rId{}"/>"#,
                xml_escape(&sh.name),
                i + 1,
                i + 1
            )
        })
        .collect();
    let workbook = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>{wb_sheets}</sheets>
</workbook>"#
    );

    let wb_rels: String = sheets
        .iter()
        .enumerate()
        .map(|(i, sh)| {
            let target = sh.path.strip_prefix("xl/").unwrap_or(&sh.path);
            format!(
                r#"<Relationship Id="rId{}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="{}"/>"#,
                i + 1,
                xml_escape(target)
            )
        })
        .collect();
    let workbook_rels = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{wb_rels}</Relationships>"#
    );

    let mut files = vec![
        ZipFile {
            name: "[Content_Types].xml".into(),
            data: content_types.into_bytes(),
        },
        ZipFile {
            name: "_rels/.rels".into(),
            data: rels_root.as_bytes().to_vec(),
        },
        ZipFile {
            name: "xl/workbook.xml".into(),
            data: workbook.into_bytes(),
        },
        ZipFile {
            name: "xl/_rels/workbook.xml.rels".into(),
            data: workbook_rels.into_bytes(),
        },
    ];
    for sh in &sheets {
        files.push(ZipFile {
            name: sh.path.clone(),
            data: sheet_xml(&sh.rows).into_bytes(),
        });
    }
    Ok(build_zip(&files))
}

fn build_sheets(pack: &BoardPack, he: bool) -> Vec<SheetSpec> {
    let n = |en: &str, he_s: &str| -> String {
        if he {
            he_s.to_string()
        } else {
            en.to_string()
        }
    };

    let mut sheets = Vec::new();

    // 1. Executive
    sheets.push(SheetSpec {
        name: n("Executive", "מנהלים"),
        path: "xl/worksheets/sheet1.xml".into(),
        rows: vec![
            vec![n(
                "Weissman Threat-Informed Board Pack",
                "חבילת דירקטוריון מודעת-איום — וייסמן",
            )],
            vec![n("Client", "לקוח"), pack.client_name.clone()],
            vec![n("Client ID", "מזהה לקוח"), s(pack.client_id)],
            vec![
                n("Generated (Israel)", "נוצר (ישראל)"),
                pack.generated_at.clone(),
            ],
            vec![n("Classification", "סיווג"), "CONFIDENTIAL".into()],
            vec![],
            vec![n("KPI", "מדד"), n("Value", "ערך")],
            vec![n("Findings", "ממצאים"), s(pack.findings.len())],
            vec![n("KEV listed", "ברשימת KEV"), s(pack.kev_count)],
            vec![n("BOD 26-04 P0", "BOD 26-04 P0"), s(pack.bod_p0)],
            vec![n("BOD 26-04 P1", "BOD 26-04 P1"), s(pack.bod_p1)],
            vec![n("ALE USD", "ALE דולר"), s(pack.ale_usd)],
            vec![n("SLE USD", "SLE דולר"), s(pack.sle_usd)],
            vec![n("Path ALE USD", "ALE נתיב דולר"), s(pack.path_ale_usd)],
            vec![
                n("Crown-jewel USD", "נכסי כתר דולר"),
                s(pack.crown_jewel_usd),
            ],
            vec![n("Attack paths", "נתיבי תקיפה"), s(pack.paths.len())],
            vec![
                n("ATT&CK techniques", "טכניקות ATT&CK"),
                s(pack.techniques.len()),
            ],
            vec![
                n("First-mover added", "נכסים חדשים"),
                s(pack.first_mover_added),
            ],
            vec![
                n("First-mover removed", "נכסים שהוסרו"),
                s(pack.first_mover_removed),
            ],
            vec![
                n("Leak / paste findings", "ממצאי דלף/פייסט"),
                s(pack.leak_count),
            ],
            vec![
                n("FAIR snapshot", "צילום FAIR"),
                if pack.fair_present {
                    n("live", "חי")
                } else {
                    n("none yet — honest empty", "אין עדיין — ריק אמיתי")
                },
            ],
            vec![
                n("Attack-path snapshot", "צילום נתיב תקיפה"),
                if pack.paths_present {
                    n("live", "חי")
                } else {
                    n("none yet — honest empty", "אין עדיין — ריק אמיתי")
                },
            ],
        ],
    });

    // 2. BOD 26-04
    let mut bod_rows = vec![vec![
        n("ID", "מזהה"),
        n("Title", "כותרת"),
        n("Severity", "חומרה"),
        n("Tier", "דרגה"),
        n("SLA", "SLA"),
        n("Public exposed", "חשיפה ציבורית"),
        n("KEV", "KEV"),
        n(
            "Automatable (EPSS/KEV/verified proxy)",
            "אוטומטי (פרוקסי EPSS/KEV/מאומת)",
        ),
        n("Total impact", "השפעה מלאה"),
        n("EPSS", "EPSS"),
        n("CVE", "CVE"),
    ]];
    for f in &pack.findings {
        if matches!(f.bod.tier(), super::bod::BodTier::P4) {
            continue;
        }
        bod_rows.push(vec![
            s(f.id),
            f.title.clone(),
            f.severity.clone(),
            f.bod.tier().as_str().to_string(),
            f.bod.tier().sla().to_string(),
            s(f.bod.public_exposed),
            s(f.bod.kev),
            s(f.bod.automatable),
            s(f.bod.total_impact),
            f.epss.map(|e| format!("{e:.4}")).unwrap_or_default(),
            f.cve.clone(),
        ]);
    }
    if bod_rows.len() == 1 {
        bod_rows.push(vec![n(
            "No P0–P3 findings (live empty).",
            "אין ממצאי P0–P3 (ריק חי).",
        )]);
    }
    sheets.push(SheetSpec {
        name: n("BOD-26-04", "BOD-26-04"),
        path: "xl/worksheets/sheet2.xml".into(),
        rows: bod_rows,
    });

    // 3. TTP overlay
    let mut ttp = vec![vec![
        n("Technique", "טכניקה"),
        n("Name", "שם"),
        n("Tactic", "טקטיקה"),
        n("Findings", "ממצאים"),
        n("Critical", "קריטי"),
        n("High", "גבוה"),
        n("Medium", "בינוני"),
        n("Low", "נמוך"),
        n("Info", "מידע"),
    ]];
    for t in &pack.techniques {
        ttp.push(vec![
            t.technique.clone(),
            t.name.clone().unwrap_or_default(),
            t.tactic.clone(),
            s(t.count),
            s(t.critical),
            s(t.high),
            s(t.medium),
            s(t.low),
            s(t.info),
        ]);
    }
    if ttp.len() == 1 {
        ttp.push(vec![n(
            "No ATT&CK-mapped live findings.",
            "אין ממצאים ממופים ל-ATT&CK.",
        )]);
    }
    sheets.push(SheetSpec {
        name: n("TTP Overlay", "שכבת TTP"),
        path: "xl/worksheets/sheet3.xml".into(),
        rows: ttp,
    });

    // 4. Attack paths
    let mut paths = vec![vec![
        n("Entry", "כניסה"),
        n("Jewel", "כתר"),
        n("Hops", "קפיצות"),
        n("Score", "ציון"),
        n("ALE USD", "ALE דולר"),
        n("KEV hops", "קפיצות KEV"),
        n("MITRE", "MITRE"),
        n("Root cause", "שורש"),
    ]];
    for p in &pack.paths {
        paths.push(vec![
            s(p.entry),
            s(p.jewel),
            s(p.hops),
            s(p.path_score),
            s(p.ale_usd),
            s(p.kev_hops),
            p.mitre_technique_id.clone(),
            p.root_cause.clone(),
        ]);
    }
    if paths.len() == 1 {
        paths.push(vec![n(
            pack.paths_message.as_str(),
            pack.paths_message.as_str(),
        )]);
    }
    sheets.push(SheetSpec {
        name: n("Attack Paths", "נתיבי תקיפה"),
        path: "xl/worksheets/sheet4.xml".into(),
        rows: paths,
    });

    // 5. Findings (no PoC column — board edition)
    let mut findings = vec![vec![
        n("ID", "מזהה"),
        n("Title", "כותרת"),
        n("Severity", "חומרה"),
        n("Source", "מקור"),
        n("Status", "סטטוס"),
        n("CVE", "CVE"),
        n("MITRE", "MITRE"),
        n("CVSS", "CVSS"),
        n("EPSS", "EPSS"),
        n("KEV", "KEV"),
        n("KEV ransomware", "כופר KEV"),
        n("KEV due", "יעד KEV"),
        n("Verified", "מאומת"),
        n("BOD tier", "דרגת BOD"),
        n("Target", "יעד"),
    ]];
    for f in pack.findings.iter().take(4000) {
        findings.push(vec![
            s(f.id),
            f.title.clone(),
            f.severity.clone(),
            f.source.clone(),
            f.status.clone(),
            f.cve.clone(),
            f.mitre.clone(),
            f.cvss.map(|c| format!("{c:.1}")).unwrap_or_default(),
            f.epss.map(|e| format!("{e:.4}")).unwrap_or_default(),
            s(f.kev_listed),
            s(f.kev_ransomware),
            f.kev_due.clone(),
            s(f.verified),
            f.bod.tier().as_str().to_string(),
            f.target.clone(),
        ]);
    }
    sheets.push(SheetSpec {
        name: n("Findings", "ממצאים"),
        path: "xl/worksheets/sheet5.xml".into(),
        rows: findings,
    });

    // 6. First mover
    sheets.push(SheetSpec {
        name: n("First Mover", "יתרון ראשון"),
        path: "xl/worksheets/sheet6.xml".into(),
        rows: vec![
            vec![n("Message", "הודעה"), pack.first_mover_message.clone()],
            vec![n("Added hosts", "מארחים שנוספו"), s(pack.first_mover_added)],
            vec![
                n("Removed hosts", "מארחים שהוסרו"),
                s(pack.first_mover_removed),
            ],
            vec![
                n("Changed hosts", "מארחים שהשתנו"),
                s(pack.first_mover_changed),
            ],
            vec![
                n("Current count", "ספירה נוכחית"),
                s(pack.first_mover_current),
            ],
            vec![
                n("Previous count", "ספירה קודמת"),
                s(pack.first_mover_previous),
            ],
        ],
    });

    // 7. Leak / paste (live engines only — not a dark-web crawl)
    let mut leak = vec![vec![
        n("ID", "מזהה"),
        n("Title", "כותרת"),
        n("Severity", "חומרה"),
        n("Source", "מקור"),
        n("Target", "יעד"),
    ]];
    for f in pack
        .findings
        .iter()
        .filter(|f| super::is_leak_source(&f.source))
    {
        leak.push(vec![
            s(f.id),
            f.title.clone(),
            f.severity.clone(),
            f.source.clone(),
            f.target.clone(),
        ]);
    }
    if leak.len() == 1 {
        leak.push(vec![n(
            "No live leak_hunter / dark_web_monitor / typosquatting findings.",
            "אין ממצאי leak_hunter / dark_web_monitor / typosquatting חיים.",
        )]);
    }
    sheets.push(SheetSpec {
        name: n("Leak Exposure", "חשיפת דלף"),
        path: "xl/worksheets/sheet7.xml".into(),
        rows: leak,
    });

    // 8. Sources / provenance
    sheets.push(SheetSpec {
        name: n("Sources", "מקורות"),
        path: "xl/worksheets/sheet8.xml".into(),
        rows: vec![
            vec![n("Source", "מקור"), n("URL / note", "כתובת / הערה")],
            vec![
                "CISA BOD 26-04".into(),
                "https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk".into(),
            ],
            vec![
                "CISA KEV catalog".into(),
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".into(),
            ],
            vec![
                "FIRST EPSS".into(),
                "https://www.first.org/epss/ — automatable proxy, not a CISA-certified flag".into(),
            ],
            vec![
                "MITRE ATT&CK".into(),
                "Public enterprise technique catalog via Weissman attack_coverage".into(),
            ],
            vec![
                "Live findings".into(),
                "PostgreSQL vulnerabilities (tenant RLS) — no demo rows".into(),
            ],
            vec![
                "FAIR / attack paths".into(),
                pack.fair_note.clone(),
            ],
            vec![
                "Dark web".into(),
                "Paste/leak engines only (leak_hunter, dark_web_monitor, typosquatting). No Tor crawl.".into(),
            ],
            vec![
                "PDF typeface".into(),
                "Helvetica (PDF board edition is English). This workbook is UTF-8 for Hebrew.".into(),
            ],
        ],
    });

    sheets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_pack::{BoardPack, PackLang};

    #[test]
    fn xlsx_is_zip_and_has_sheets() {
        let pack = BoardPack::empty_demo(1, "Acme", PackLang::En);
        let bytes = render_xlsx(&pack).expect("xlsx");
        assert!(bytes.starts_with(b"PK\x03\x04"), "zip local header");
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("Executive") || body.contains("sheet1"));
        assert!(body.contains("BOD 26-04") || body.contains("BOD-26-04"));
    }

    #[test]
    fn hebrew_sheet_names_utf8() {
        let pack = BoardPack::empty_demo(1, "לקוח", PackLang::He);
        let bytes = render_xlsx(&pack).expect("xlsx");
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.contains("מנהלים"));
    }
}
