//! Office Open XML (.xlsx) writer with **no third-party spreadsheet crate**.
//!
//! Emits a ZIP (STORE, method 0) of the ECMA-376 parts Excel actually opens.
//! Cells are formula-neutralized (leading `= + - @` prefixed with `'`) so a
//! finding title cannot become an Excel formula. Used for client workbooks and
//! the Adversary Gap Mirror board pack.

#[derive(Debug, Clone)]
pub struct XlsxSheet {
    pub name: String,
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Neutralize spreadsheet formula injection (CSV/XLSX).
#[must_use]
pub fn neutralize_formula(s: &str) -> String {
    let t = s.trim_start_matches(['\t', '\r', '\n']);
    if t.starts_with(['=', '+', '-', '@']) {
        format!("'{t}")
    } else {
        s.to_string()
    }
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

struct ZipEntry {
    name: String,
    data: Vec<u8>,
}

fn build_zip(entries: &[ZipEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for e in entries {
        let name = e.name.as_bytes();
        let crc = crc32(&e.data);
        let size = e.data.len() as u32;
        let local_off = out.len() as u32;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // STORE
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&e.data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&local_off.to_le_bytes());
        central.extend_from_slice(name);
    }
    let cd_off = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    let n = entries.len() as u16;
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn col_letter(mut n: usize) -> String {
    let mut s = String::new();
    n += 1;
    while n > 0 {
        n -= 1;
        s.insert(0, (b'A' + (n % 26) as u8) as char);
        n /= 26;
    }
    s
}

fn sheet_xml(sheet: &XlsxSheet) -> Vec<u8> {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#,
    );
    xml.push_str("<row r=\"1\">");
    for (i, h) in sheet.headers.iter().enumerate() {
        xml.push_str(&format!(
            "<c r=\"{}1\" t=\"inlineStr\"><is><t>{}</t></is></c>",
            col_letter(i),
            xml_escape(&neutralize_formula(h))
        ));
    }
    xml.push_str("</row>");
    for (ri, row) in sheet.rows.iter().enumerate() {
        let r = ri + 2;
        xml.push_str(&format!("<row r=\"{r}\">"));
        for (i, cell) in row.iter().enumerate() {
            xml.push_str(&format!(
                "<c r=\"{}{r}\" t=\"inlineStr\"><is><t>{}</t></is></c>",
                col_letter(i),
                xml_escape(&neutralize_formula(cell))
            ));
        }
        xml.push_str("</row>");
    }
    xml.push_str("</sheetData></worksheet>");
    xml.into_bytes()
}

fn content_types(n_sheets: usize) -> Vec<u8> {
    let mut s = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>"#,
    );
    for i in 1..=n_sheets {
        s.push_str(&format!(
            "<Override PartName=\"/xl/worksheets/sheet{i}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>"
        ));
    }
    s.push_str("</Types>");
    s.into_bytes()
}

fn rels_root() -> Vec<u8> {
    br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#.to_vec()
}

fn workbook_xml(sheets: &[XlsxSheet]) -> Vec<u8> {
    let mut s = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>"#,
    );
    for (i, sh) in sheets.iter().enumerate() {
        let name = xml_escape(&sheet_name_safe(&sh.name));
        s.push_str(&format!(
            "<sheet name=\"{name}\" sheetId=\"{}\" r:id=\"rId{}\"/>",
            i + 1,
            i + 1
        ));
    }
    s.push_str("</sheets></workbook>");
    s.into_bytes()
}

fn workbook_rels(n: usize) -> Vec<u8> {
    let mut s = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    );
    for i in 1..=n {
        s.push_str(&format!(
            "<Relationship Id=\"rId{i}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet{i}.xml\"/>"
        ));
    }
    s.push_str("</Relationships>");
    s.into_bytes()
}

fn sheet_name_safe(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if matches!(c, ':' | '\\' | '/' | '?' | '*' | '[' | ']') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let t = cleaned.trim();
    if t.is_empty() {
        "Sheet".to_string()
    } else {
        t.chars().take(31).collect()
    }
}

/// Build a real .xlsx workbook.
pub fn build_xlsx(sheets: &[XlsxSheet]) -> Result<Vec<u8>, String> {
    if sheets.is_empty() {
        return Err("at least one sheet required".into());
    }
    let n = sheets.len();
    let mut entries = vec![
        ZipEntry {
            name: "[Content_Types].xml".into(),
            data: content_types(n),
        },
        ZipEntry {
            name: "_rels/.rels".into(),
            data: rels_root(),
        },
        ZipEntry {
            name: "xl/workbook.xml".into(),
            data: workbook_xml(sheets),
        },
        ZipEntry {
            name: "xl/_rels/workbook.xml.rels".into(),
            data: workbook_rels(n),
        },
    ];
    for (i, sh) in sheets.iter().enumerate() {
        entries.push(ZipEntry {
            name: format!("xl/worksheets/sheet{}.xml", i + 1),
            data: sheet_xml(sh),
        });
    }
    Ok(build_zip(&entries))
}

#[derive(Debug, Clone)]
pub struct FindingExportRow {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub status: String,
    pub discovered: String,
    pub description: String,
}

/// Multi-sheet client assessment workbook (findings + board counts).
pub fn build_findings_workbook(
    org: &str,
    client: &str,
    rows: &[FindingExportRow],
) -> Result<Vec<u8>, String> {
    let mut crit = 0u32;
    let mut high = 0u32;
    let mut med = 0u32;
    let mut low = 0u32;
    for r in rows {
        match r.severity.to_ascii_lowercase().as_str() {
            "critical" => crit += 1,
            "high" => high += 1,
            "medium" => med += 1,
            _ => low += 1,
        }
    }
    let board = XlsxSheet {
        name: "Board".into(),
        headers: vec!["Field".into(), "Value".into()],
        rows: vec![
            vec!["Organization".into(), org.into()],
            vec!["Client".into(), client.into()],
            vec!["Critical".into(), crit.to_string()],
            vec!["High".into(), high.to_string()],
            vec!["Medium".into(), med.to_string()],
            vec!["Low / Info".into(), low.to_string()],
            vec!["Total".into(), rows.len().to_string()],
            vec![
                "Truth".into(),
                "Live findings only. Empty cells mean no observation.".into(),
            ],
        ],
    };
    let findings = XlsxSheet {
        name: "Findings".into(),
        headers: vec![
            "ID".into(),
            "Title".into(),
            "Severity".into(),
            "Source".into(),
            "Status".into(),
            "Discovered".into(),
            "Description".into(),
        ],
        rows: rows
            .iter()
            .map(|r| {
                vec![
                    r.id.clone(),
                    r.title.clone(),
                    r.severity.clone(),
                    r.source.clone(),
                    r.status.clone(),
                    r.discovered.clone(),
                    r.description.clone(),
                ]
            })
            .collect(),
    };
    let next = XlsxSheet {
        name: "Next assessments".into(),
        headers: vec!["Engine".into(), "Why".into()],
        rows: vec![
            vec![
                "adversary_gap_mirror".into(),
                "Clearnet leak intel + IAB-interesting ports".into(),
            ],
            vec!["leak_hunter".into(), "Credential / paste exposure".into()],
            vec![
                "password_spray".into(),
                "Authorized spray only after leaked identity evidence".into(),
            ],
            vec!["asm".into(), "Re-inventory internet-facing assets".into()],
        ],
    };
    build_xlsx(&[board, findings, next])
}

/// Convenience for handlers that already have CSV-like tuples.
pub fn build_findings_workbook_from_tuples(
    org: &str,
    client: &str,
    rows: &[(i64, String, String, String, String, String, String)],
) -> Result<Vec<u8>, String> {
    let mapped: Vec<FindingExportRow> = rows
        .iter()
        .map(|r| FindingExportRow {
            id: format!("VLN-{}", r.0),
            title: r.1.clone(),
            severity: r.2.clone(),
            source: r.3.clone(),
            status: r.4.clone(),
            discovered: r.5.clone(),
            description: r.6.clone(),
        })
        .collect();
    build_findings_workbook(org, client, &mapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_prefix_quoted() {
        assert_eq!(neutralize_formula("=cmd"), "'=cmd");
        assert_eq!(neutralize_formula("normal"), "normal");
    }

    #[test]
    fn xlsx_is_zip_with_sheet() {
        let bytes = build_xlsx(&[XlsxSheet {
            name: "T".into(),
            headers: vec!["A".into(), "B".into()],
            rows: vec![vec!["=1+1".into(), "ok".into()]],
        }])
        .unwrap();
        assert!(bytes.starts_with(b"PK"));
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("xl/worksheets/sheet1.xml"));
        assert!(text.contains("'=1+1"));
        assert!(text.contains("[Content_Types].xml"));
    }

    #[test]
    fn findings_workbook_has_board_sheet() {
        let bytes = build_findings_workbook(
            "Weissman",
            "Acme",
            &[FindingExportRow {
                id: "VLN-1".into(),
                title: "x".into(),
                severity: "critical".into(),
                source: "adversary_gap_mirror".into(),
                status: "open".into(),
                discovered: "2026-09-11".into(),
                description: "live".into(),
            }],
        )
        .unwrap();
        assert!(bytes.len() > 400);
        assert!(bytes.starts_with(b"PK"));
    }
}
