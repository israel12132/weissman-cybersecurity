//! Minimal OOXML (.xlsx) writer. Stored ZIP (no extra crate) + inlineStr cells.
//! Excel, LibreOffice, and Google Sheets open this. No CSV-disguised-as-Excel.

#[derive(Debug, Clone)]
pub enum Cell {
    Text(String),
    Int(i64),
    Float(f64),
    Empty,
}

impl From<&str> for Cell {
    fn from(s: &str) -> Self {
        Cell::Text(s.to_string())
    }
}

impl From<String> for Cell {
    fn from(s: String) -> Self {
        Cell::Text(s)
    }
}

impl From<i64> for Cell {
    fn from(n: i64) -> Self {
        Cell::Int(n)
    }
}

impl From<i32> for Cell {
    fn from(n: i32) -> Self {
        Cell::Int(n as i64)
    }
}

impl From<usize> for Cell {
    fn from(n: usize) -> Self {
        Cell::Int(n as i64)
    }
}

impl From<f64> for Cell {
    fn from(n: f64) -> Self {
        Cell::Float(n)
    }
}

#[derive(Debug, Clone)]
pub struct Sheet {
    pub name: String,
    pub rows: Vec<Vec<Cell>>,
}

impl Sheet {
    pub fn new(name: impl Into<String>, rows: Vec<Vec<Cell>>) -> Self {
        Self {
            name: sanitize_sheet_name(name.into()),
            rows,
        }
    }
}

/// Build a valid XLSX workbook. Empty `sheets` yields one empty "Sheet1".
pub fn build_xlsx(sheets: &[Sheet]) -> Result<Vec<u8>, String> {
    let sheets: Vec<Sheet> = if sheets.is_empty() {
        vec![Sheet::new("Sheet1", vec![])]
    } else {
        sheets.to_vec()
    };
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();

    let mut content_overrides = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
"#,
    );
    let mut wb_rels = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
"#,
    );
    let mut workbook_sheets = String::new();
    for (i, sheet) in sheets.iter().enumerate() {
        let n = i + 1;
        content_overrides.push_str(&format!(
            r#"  <Override PartName="/xl/worksheets/sheet{n}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
"#
        ));
        wb_rels.push_str(&format!(
            r#"  <Relationship Id="rId{n}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{n}.xml"/>
"#
        ));
        workbook_sheets.push_str(&format!(
            r#"    <sheet name="{}" sheetId="{n}" r:id="rId{n}"/>
"#,
            xml_escape(&sheet.name)
        ));
        files.push((
            format!("xl/worksheets/sheet{n}.xml"),
            worksheet_xml(&sheet.rows).into_bytes(),
        ));
    }
    let styles_rid = sheets.len() + 1;
    wb_rels.push_str(&format!(
        r#"  <Relationship Id="rId{styles_rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>
"#
    ));
    content_overrides.push_str("</Types>\n");

    files.push(("[Content_Types].xml".into(), content_overrides.into_bytes()));
    files.push((
        "_rels/.rels".into(),
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
"#
        .to_vec(),
    ));
    files.push(("xl/_rels/workbook.xml.rels".into(), wb_rels.into_bytes()));
    files.push((
        "xl/workbook.xml".into(),
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
{workbook_sheets}  </sheets>
</workbook>
"#
        )
        .into_bytes(),
    ));
    files.push((
        "xl/styles.xml".into(),
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font></fonts>
  <fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
</styleSheet>
"#
        .to_vec(),
    ));

    zip_store(&files)
}

fn worksheet_xml(rows: &[Vec<Cell>]) -> String {
    let mut out = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
"#,
    );
    for (ri, row) in rows.iter().enumerate() {
        let r = ri + 1;
        out.push_str(&format!("    <row r=\"{r}\">\n"));
        for (ci, cell) in row.iter().enumerate() {
            let addr = cell_ref(ci, r as u32);
            match cell {
                Cell::Empty => {}
                Cell::Int(n) => out.push_str(&format!("      <c r=\"{addr}\"><v>{n}</v></c>\n")),
                Cell::Float(n) => {
                    if n.is_finite() {
                        out.push_str(&format!("      <c r=\"{addr}\"><v>{n}</v></c>\n"));
                    }
                }
                Cell::Text(s) => {
                    let t = neutralize_formula(&strip_xml_unsafe(s));
                    out.push_str(&format!(
                        "      <c r=\"{addr}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">{}</t></is></c>\n",
                        xml_escape(&t)
                    ));
                }
            }
        }
        out.push_str("    </row>\n");
    }
    out.push_str("  </sheetData>\n</worksheet>\n");
    out
}

fn cell_ref(col0: usize, row1: u32) -> String {
    let mut n = col0;
    let mut letters = Vec::new();
    loop {
        letters.push((b'A' + (n % 26) as u8) as char);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    letters.reverse();
    format!("{}{row1}", letters.into_iter().collect::<String>())
}

fn sanitize_sheet_name(name: String) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '\\' | '/' | '?' | '*' | '[' | ']' | ':' => ' ',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect();
    let t = cleaned.trim();
    let s = if t.is_empty() { "Sheet" } else { t };
    s.chars().take(31).collect()
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

fn strip_xml_unsafe(s: &str) -> String {
    s.chars()
        .filter(|c| {
            let u = *c as u32;
            *c == '\t' || *c == '\n' || *c == '\r' || u >= 0x20
        })
        .collect()
}

/// Neutralize spreadsheet formula injection (=, +, -, @, tab, CR).
pub fn neutralize_formula(s: &str) -> String {
    let t = s.trim_start_matches('\u{feff}');
    if t.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{t}")
    } else {
        t.to_string()
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
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

fn zip_store(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let name_b = name.as_bytes();
        if name_b.len() > 0xFFFF {
            return Err("xlsx part name too long".into());
        }
        let crc = crc32(data);
        let local_off = buf.len() as u32;
        // local file header
        buf.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        buf.extend_from_slice(&20u16.to_le_bytes()); // version
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // stored
        buf.extend_from_slice(&0u16.to_le_bytes()); // time
        buf.extend_from_slice(&0u16.to_le_bytes()); // date
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra
        buf.extend_from_slice(name_b);
        buf.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // ver made by
        central.extend_from_slice(&20u16.to_le_bytes()); // ver needed
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // int attr
        central.extend_from_slice(&0u32.to_le_bytes()); // ext attr
        central.extend_from_slice(&local_off.to_le_bytes());
        central.extend_from_slice(name_b);
    }
    let cd_off = buf.len() as u32;
    buf.extend_from_slice(&central);
    let cd_len = central.len() as u32;
    let n = files.len() as u16;
    buf.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&n.to_le_bytes());
    buf.extend_from_slice(&n.to_le_bytes());
    buf.extend_from_slice(&cd_len.to_le_bytes());
    buf.extend_from_slice(&cd_off.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_refs_match_excel() {
        assert_eq!(cell_ref(0, 1), "A1");
        assert_eq!(cell_ref(25, 2), "Z2");
        assert_eq!(cell_ref(26, 1), "AA1");
    }

    #[test]
    fn formula_injection_is_quoted() {
        assert_eq!(neutralize_formula("=1+1"), "'=1+1");
        assert_eq!(neutralize_formula("ok"), "ok");
    }

    #[test]
    fn xlsx_is_zip_with_workbook_and_sheets() {
        let bytes = build_xlsx(&[
            Sheet::new(
                "Executive",
                vec![
                    vec![Cell::from("KPI"), Cell::from("Value")],
                    vec![Cell::from("Critical"), Cell::from(3i64)],
                    vec![Cell::from("=cmd"), Cell::from("safe")],
                ],
            ),
            Sheet::new("Findings", vec![vec![Cell::from("id"), Cell::from("title")]]),
        ])
        .expect("xlsx");
        assert!(bytes.starts_with(b"PK"), "ZIP local header");
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("xl/workbook.xml"));
        assert!(s.contains("Executive"));
        assert!(s.contains("Findings"));
        assert!(s.contains("inlineStr"));
        assert!(
            s.contains("&apos;=cmd"),
            "formula prefix must be quoted then XML-escaped"
        );
        assert!(s.contains("[Content_Types].xml"));
    }

    #[test]
    fn empty_workbook_still_valid() {
        let bytes = build_xlsx(&[]).expect("empty");
        assert!(bytes.starts_with(b"PK"));
        assert!(String::from_utf8_lossy(&bytes).contains("Sheet1"));
    }
}
