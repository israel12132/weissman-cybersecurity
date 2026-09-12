//! Native OOXML (XLSX) board pack — no third-party spreadsheet crate.
//!
//! Workbook sheets are built from live `vulnerabilities` rows only. Cells that
//! Excel would treat as formulas are neutralized. The ZIP container is a
//! self-contained PKZIP writer (deflate via `flate2`).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;

const ADVERSARY_SOURCES: &[&str] = &[
    "leak_hunter",
    "darkweb_intel",
    "dark_web_monitor",
    "typosquatting_monitor",
    "adversary_exposure_delta",
    "threat_intel_fusion",
];

/// One live finding row for the board workbook / JSON summary.
#[derive(Debug, Clone, Default)]
pub struct BoardFinding {
    pub id: i64,
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub status: String,
    pub client_id: String,
    pub client_name: String,
    pub description: String,
    pub poc_exploit: String,
    pub generated_patch: String,
    pub poc_sealed: bool,
    pub discovered_at: String,
}

impl BoardFinding {
    pub fn mitre(&self) -> String {
        json_str_field(&self.description, &["mitre_attack", "mitre", "technique"])
    }

    pub fn remediation(&self) -> String {
        let from_json = json_str_field(
            &self.description,
            &["remediation", "remediation_snippet", "fix"],
        );
        if !from_json.is_empty() {
            return from_json;
        }
        if !self.generated_patch.trim().is_empty() {
            return self.generated_patch.clone();
        }
        String::new()
    }

    pub fn is_adversary(&self) -> bool {
        is_adversary_source(&self.source)
    }
}

#[must_use]
pub fn is_adversary_source(source: &str) -> bool {
    let s = source.trim().to_ascii_lowercase();
    ADVERSARY_SOURCES.iter().any(|x| *x == s)
}

/// Prefix cells Excel would evaluate as formulas.
#[must_use]
pub fn neutralize_formula(s: &str) -> String {
    let s = s.trim_start_matches('\u{feff}');
    let first = s.chars().next();
    if matches!(first, Some('=' | '+' | '-' | '@' | '\t' | '\r')) {
        format!("'{s}")
    } else {
        s.to_string()
    }
}

fn json_str_field(desc: &str, keys: &[&str]) -> String {
    let trimmed = desc.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
        return String::new();
    };
    for k in keys {
        if let Some(s) = v.get(*k).and_then(Value::as_str) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    String::new()
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\u{0009}' | '\u{000A}' | '\u{000D}' => out.push(ch),
            c if ch.is_control() => {
                let _ = c;
            }
            c => out.push(c),
        }
    }
    out
}

fn cell_text(s: &str) -> String {
    let mut t = neutralize_formula(s);
    if t.chars().count() > 32767 {
        t = t.chars().take(32767).collect();
    }
    t
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

fn deflate_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).map_err(|e| e.to_string())?;
    enc.finish().map_err(|e| e.to_string())
}

struct ZipEntry {
    name: String,
    data: Vec<u8>,
}

fn build_zip(files: &[ZipEntry]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count: u16 = 0;
    for f in files {
        let name_bytes = f.name.as_bytes();
        if name_bytes.len() > u16::MAX as usize {
            return Err("zip name too long".into());
        }
        let crc = crc32(&f.data);
        let compressed = deflate_bytes(&f.data)?;
        let local_off = out.len() as u32;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&compressed);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&8u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        central.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&local_off.to_le_bytes());
        central.extend_from_slice(name_bytes);
        count = count.saturating_add(1);
    }
    let cd_off = out.len() as u32;
    let cd_len = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
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

fn inline_cell(col: usize, row: usize, text: &str, header: bool) -> String {
    let r = format!("{}{}", col_letter(col), row);
    let style = if header { r#" s="1""# } else { "" };
    format!(
        r#"<c r="{r}" t="inlineStr"{style}><is><t xml:space="preserve">{}</t></is></c>"#,
        xml_escape(&cell_text(text))
    )
}

fn sheet_xml(headers: &[&str], rows: &[Vec<String>]) -> String {
    let last_col = headers.len().saturating_sub(1);
    let last_row = 1 + rows.len();
    let dim = format!("A1:{}{}", col_letter(last_col), last_row.max(1));
    let mut body = String::from(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#);
    body.push_str(
        r#"<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref=""#,
    );
    body.push_str(&dim);
    body.push_str(r#""/><sheetData>"#);
    body.push_str(r#"<row r="1">"#);
    for (i, h) in headers.iter().enumerate() {
        body.push_str(&inline_cell(i, 1, h, true));
    }
    body.push_str("</row>");
    for (idx, row) in rows.iter().enumerate() {
        let r = idx + 2;
        body.push_str(&format!(r#"<row r="{r}">"#));
        for (c, val) in row.iter().enumerate() {
            body.push_str(&inline_cell(c, r, val, false));
        }
        body.push_str("</row>");
    }
    body.push_str("</sheetData>");
    if last_row >= 1 {
        body.push_str(&format!(
            r#"<autoFilter ref="A1:{}{}"/>"#,
            col_letter(last_col),
            last_row
        ));
    }
    body.push_str("</worksheet>");
    body
}

fn severity_counts(findings: &[BoardFinding]) -> (u32, u32, u32, u32, u32) {
    let mut c = (0, 0, 0, 0, 0);
    for f in findings {
        match f.severity.to_ascii_lowercase().as_str() {
            "critical" => c.0 += 1,
            "high" => c.1 += 1,
            "medium" => c.2 += 1,
            "low" => c.3 += 1,
            _ => c.4 += 1,
        }
    }
    c
}

/// Build a live-only board JSON summary (no fabricated findings).
pub fn board_pack_json(
    org_label: &str,
    client_id: Option<i64>,
    client_label: &str,
    findings: &[BoardFinding],
) -> Value {
    let (critical, high, medium, low, info) = severity_counts(findings);
    let verified = findings.iter().filter(|f| f.poc_sealed).count();
    let adversary = findings.iter().filter(|f| f.is_adversary()).count();
    let remediations = findings
        .iter()
        .filter(|f| !f.remediation().is_empty())
        .count();
    let mut sources: serde_json::Map<String, Value> = serde_json::Map::new();
    for f in findings {
        let key = if f.source.trim().is_empty() {
            "unknown".to_string()
        } else {
            f.source.clone()
        };
        let n = sources.get(&key).and_then(Value::as_u64).unwrap_or(0);
        sources.insert(key, json!(n + 1));
    }
    let xlsx_path = match client_id {
        Some(id) => format!("/api/clients/{id}/export/xlsx"),
        None => "/api/findings/export/xlsx".to_string(),
    };
    let csv_path = match client_id {
        Some(id) => format!("/api/clients/{id}/export/csv"),
        None => "/api/findings/export/csv".to_string(),
    };
    let pdf_path = client_id.map(|id| format!("/api/clients/{id}/report/pdf"));
    json!({
        "live": true,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "org": org_label,
        "client_id": client_id,
        "client_name": client_label,
        "totals": {
            "findings": findings.len(),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
            "verified": verified,
            "adversary_indexed": adversary,
            "remediation_ready": remediations,
        },
        "sources": sources,
        "exports": {
            "xlsx": xlsx_path,
            "csv": csv_path,
            "pdf": pdf_path,
        },
        "legal_intel_note": "Adversary-index rows come from legal clearnet OSINT (urlscan, abuse.ch when keyed, IntelX/HIBP/OTX when keyed). Tor marketplaces are not crawled.",
    })
}

/// Build a true OOXML workbook (PKZIP magic `PK`).
pub fn build_board_xlsx(
    org_label: &str,
    client_label: &str,
    findings: &[BoardFinding],
) -> Result<Vec<u8>, String> {
    let (critical, high, medium, low, info) = severity_counts(findings);
    let verified = findings.iter().filter(|f| f.poc_sealed).count();
    let adversary: Vec<&BoardFinding> = findings.iter().filter(|f| f.is_adversary()).collect();
    let generated = chrono::Utc::now().to_rfc3339();

    let exec_headers = ["Metric", "Value"];
    let exec_rows = vec![
        vec!["Organization".into(), org_label.to_string()],
        vec!["Client".into(), client_label.to_string()],
        vec!["Generated (UTC)".into(), generated.clone()],
        vec!["Live findings only".into(), "true".into()],
        vec!["Total findings".into(), findings.len().to_string()],
        vec!["Critical".into(), critical.to_string()],
        vec!["High".into(), high.to_string()],
        vec!["Medium".into(), medium.to_string()],
        vec!["Low".into(), low.to_string()],
        vec!["Info".into(), info.to_string()],
        vec!["Verified (poc_sealed)".into(), verified.to_string()],
        vec!["Adversary-indexed".into(), adversary.len().to_string()],
        vec![
            "Legal OSINT note".into(),
            "Clearnet indexes only (urlscan / abuse.ch / IntelX / HIBP / OTX). No Tor marketplace crawl.".into(),
        ],
    ];

    let findings_headers = [
        "ID",
        "Finding ID",
        "Title",
        "Severity",
        "Source",
        "Status",
        "Verified",
        "Client",
        "MITRE",
        "Discovered",
        "Description",
    ];
    let findings_rows: Vec<Vec<String>> = findings
        .iter()
        .map(|f| {
            vec![
                format!("VLN-{}", f.id),
                f.finding_id.clone(),
                f.title.clone(),
                f.severity.clone(),
                f.source.clone(),
                f.status.clone(),
                if f.poc_sealed {
                    "VERIFIED".into()
                } else {
                    "POTENTIAL".into()
                },
                if f.client_name.is_empty() {
                    f.client_id.clone()
                } else {
                    f.client_name.clone()
                },
                f.mitre(),
                f.discovered_at.clone(),
                f.description.clone(),
            ]
        })
        .collect();

    let rem_headers = [
        "ID",
        "Title",
        "Severity",
        "Source",
        "Remediation",
        "Generated patch",
    ];
    let rem_rows: Vec<Vec<String>> = findings
        .iter()
        .filter(|f| !f.remediation().is_empty() || !f.generated_patch.trim().is_empty())
        .map(|f| {
            vec![
                format!("VLN-{}", f.id),
                f.title.clone(),
                f.severity.clone(),
                f.source.clone(),
                f.remediation(),
                f.generated_patch.clone(),
            ]
        })
        .collect();

    let adv_headers = [
        "ID",
        "Title",
        "Severity",
        "Source",
        "Target evidence",
        "Discovered",
    ];
    let adv_rows: Vec<Vec<String>> = adversary
        .iter()
        .map(|f| {
            vec![
                format!("VLN-{}", f.id),
                f.title.clone(),
                f.severity.clone(),
                f.source.clone(),
                f.description.clone(),
                f.discovered_at.clone(),
            ]
        })
        .collect();

    let mitre_headers = ["MITRE", "Count", "Highest severity", "Sample finding"];
    let mut mitre_map: std::collections::BTreeMap<String, (u32, String, String)> =
        std::collections::BTreeMap::new();
    for f in findings {
        let m = f.mitre();
        if m.is_empty() {
            continue;
        }
        let entry = mitre_map
            .entry(m)
            .or_insert((0, f.severity.clone(), f.title.clone()));
        entry.0 += 1;
        let rank = |s: &str| match s.to_ascii_lowercase().as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        if rank(&f.severity) > rank(&entry.1) {
            entry.1 = f.severity.clone();
            entry.2 = f.title.clone();
        }
    }
    let mitre_rows: Vec<Vec<String>> = mitre_map
        .into_iter()
        .map(|(k, (n, sev, title))| vec![k, n.to_string(), sev, title])
        .collect();

    let sheets: [(&str, String); 5] = [
        ("Executive", sheet_xml(&exec_headers, &exec_rows)),
        ("Findings", sheet_xml(&findings_headers, &findings_rows)),
        ("Remediation", sheet_xml(&rem_headers, &rem_rows)),
        ("AdversaryIntel", sheet_xml(&adv_headers, &adv_rows)),
        ("MITRE", sheet_xml(&mitre_headers, &mitre_rows)),
    ];

    let mut content_types = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>"#,
    );
    for i in 1..=sheets.len() {
        content_types.push_str(&format!(
            r#"<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>"#
        ));
    }
    content_types.push_str("</Types>");

    let rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;

    let mut wb_rels = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    );
    for i in 1..=sheets.len() {
        wb_rels.push_str(&format!(
            r#"<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>"#
        ));
    }
    let styles_id = sheets.len() + 1;
    wb_rels.push_str(&format!(
        r#"<Relationship Id="rId{styles_id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>"#
    ));

    let mut workbook = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>"#,
    );
    for (i, (name, _)) in sheets.iter().enumerate() {
        let sid = i + 1;
        workbook.push_str(&format!(
            r#"<sheet name="{name}" sheetId="{sid}" r:id="rId{sid}"/>"#
        ));
    }
    workbook.push_str("</sheets></workbook>");

    let styles = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border/></borders><cellXfs count="2"><xf fontId="0" fillId="0" borderId="0"/><xf fontId="1" fillId="0" borderId="0" applyFont="1"/></cellXfs></styleSheet>"#;

    let mut files = vec![
        ZipEntry {
            name: "[Content_Types].xml".into(),
            data: content_types.into_bytes(),
        },
        ZipEntry {
            name: "_rels/.rels".into(),
            data: rels.as_bytes().to_vec(),
        },
        ZipEntry {
            name: "xl/workbook.xml".into(),
            data: workbook.into_bytes(),
        },
        ZipEntry {
            name: "xl/_rels/workbook.xml.rels".into(),
            data: wb_rels.into_bytes(),
        },
        ZipEntry {
            name: "xl/styles.xml".into(),
            data: styles.as_bytes().to_vec(),
        },
    ];
    for (i, (_, xml)) in sheets.iter().enumerate() {
        files.push(ZipEntry {
            name: format!("xl/worksheets/sheet{}.xml", i + 1),
            data: xml.as_bytes().to_vec(),
        });
    }
    build_zip(&files)
}

/// SHA-256 hex of workbook bytes (audit stamp for the JSON sidecar).
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    #[test]
    fn formula_prefix_is_neutralized() {
        assert_eq!(neutralize_formula("=cmd"), "'=cmd");
        assert_eq!(neutralize_formula("+1+1"), "'+1+1");
        assert_eq!(neutralize_formula("normal"), "normal");
        assert_eq!(neutralize_formula("2026-09-11"), "2026-09-11");
    }

    #[test]
    fn adversary_sources_are_explicit() {
        assert!(is_adversary_source("darkweb_intel"));
        assert!(is_adversary_source("adversary_exposure_delta"));
        assert!(!is_adversary_source("asm"));
    }

    #[test]
    fn empty_workbook_is_valid_xlsx() {
        let bytes = build_board_xlsx("Weissman", "All clients", &[]).expect("xlsx");
        assert!(bytes.starts_with(b"PK"), "must be a ZIP/OOXML container");
        assert!(bytes.len() > 200);
        let hash = sha256_hex(&bytes);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn workbook_contains_executive_sheet_xml() {
        let f = BoardFinding {
            id: 7,
            finding_id: "CVE-2024-0001".into(),
            title: "=HYPERLINK(http://evil)".into(),
            severity: "critical".into(),
            source: "darkweb_intel".into(),
            status: "OPEN".into(),
            client_id: "1".into(),
            client_name: "Acme".into(),
            description: r#"{"mitre_attack":"T1597","remediation":"Rotate creds"}"#.into(),
            poc_exploit: String::new(),
            generated_patch: String::new(),
            poc_sealed: true,
            discovered_at: "2026-09-11".into(),
        };
        let bytes = build_board_xlsx("Weissman", "Acme", &[f]).expect("xlsx");
        // Inflate first local-file payload after the header to prove XML is present.
        assert!(inflate_contains(&bytes, "Executive"));
        assert!(inflate_contains(&bytes, "'=HYPERLINK"));
        assert!(inflate_contains(&bytes, "T1597"));
        let summary = board_pack_json(
            "Weissman",
            Some(1),
            "Acme",
            &[BoardFinding {
                id: 7,
                finding_id: "CVE-2024-0001".into(),
                title: "x".into(),
                severity: "critical".into(),
                source: "darkweb_intel".into(),
                status: "OPEN".into(),
                client_id: "1".into(),
                client_name: "Acme".into(),
                description: String::new(),
                poc_exploit: String::new(),
                generated_patch: String::new(),
                poc_sealed: true,
                discovered_at: String::new(),
            }],
        );
        assert_eq!(summary["live"], true);
        assert_eq!(summary["totals"]["critical"], 1);
        assert_eq!(summary["totals"]["adversary_indexed"], 1);
        assert_eq!(summary["exports"]["xlsx"], "/api/clients/1/export/xlsx");
    }

    fn inflate_contains(zip: &[u8], needle: &str) -> bool {
        // Walk local file headers and inflate each payload.
        let mut i = 0usize;
        while i + 30 <= zip.len() && &zip[i..i + 4] == [0x50, 0x4b, 0x03, 0x04] {
            let method = u16::from_le_bytes([zip[i + 8], zip[i + 9]]);
            let comp_len = u32::from_le_bytes(zip[i + 18..i + 22].try_into().unwrap()) as usize;
            let name_len = u16::from_le_bytes([zip[i + 26], zip[i + 27]]) as usize;
            let extra = u16::from_le_bytes([zip[i + 28], zip[i + 29]]) as usize;
            let data_start = i + 30 + name_len + extra;
            if data_start + comp_len > zip.len() {
                break;
            }
            let payload = &zip[data_start..data_start + comp_len];
            let mut decoded = Vec::new();
            if method == 8 {
                let mut d = DeflateDecoder::new(payload);
                let _ = d.read_to_end(&mut decoded);
            } else {
                decoded.extend_from_slice(payload);
            }
            if String::from_utf8_lossy(&decoded).contains(needle) {
                return true;
            }
            i = data_start + comp_len;
        }
        false
    }
}
