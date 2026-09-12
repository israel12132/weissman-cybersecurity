//! First-party Office Open XML workbook writer (no `rust_xlsxwriter` / lopdf tree).
//!
//! Emits a stored (uncompressed) ZIP of SpreadsheetML so client "Excel" downloads
//! are real `.xlsx` files — not CSV labeled as Excel. Unicode (including Hebrew)
//! is written as UTF-8 shared strings. Formula-injection prefixes are neutralized.

use sha2::{Digest, Sha256};

const MIME_XLSX: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

#[must_use]
pub fn xlsx_content_type() -> &'static str {
    MIME_XLSX
}

#[derive(Debug, Clone, Default)]
pub struct BoardFinding {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub proof: String,
    pub mitre: String,
    pub cve: String,
    pub kev: bool,
    pub ransomware: bool,
    pub status: String,
    pub discovered: String,
}

#[derive(Debug, Clone, Default)]
pub struct BoardWorkbook {
    pub client_name: String,
    pub generated_at: String,
    pub integrity_hash: String,
    pub findings: Vec<BoardFinding>,
}

/// Neutralize Excel/Sheets formula injection (`=`, `+`, `-`, `@`, tab, CR, LF).
#[must_use]
pub fn formula_guard(s: &str) -> String {
    let t = s.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n', '\u{00a0}']);
    if t.starts_with(['=', '+', '-', '@', '\t', '\r', '\n']) {
        format!("'{t}")
    } else {
        t.to_string()
    }
}

#[must_use]
pub fn extract_cve(text: &str) -> String {
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut i = 0;
    while i + 13 <= bytes.len() {
        if &bytes[i..i + 4] == b"CVE-" {
            let year = &bytes[i + 4..i + 8];
            if year.iter().all(|b| b.is_ascii_digit()) && bytes[i + 8] == b'-' {
                let mut j = i + 9;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                let n = j - (i + 9);
                if (4..=7).contains(&n) {
                    return upper[i..j].to_string();
                }
            }
        }
        i += 1;
    }
    String::new()
}

#[must_use]
pub fn extract_mitre(text: &str) -> String {
    let upper = text.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        if bytes[i] == b'T' && bytes[i + 1].is_ascii_digit() {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let digits = j - (i + 1);
            if (4..=5).contains(&digits) {
                if j + 4 <= bytes.len()
                    && bytes[j] == b'.'
                    && bytes[j + 1..j + 4].iter().all(|b| b.is_ascii_digit())
                {
                    return upper[i..j + 4].to_string();
                }
                return upper[i..j].to_string();
            }
        }
        i += 1;
    }
    String::new()
}

#[must_use]
pub fn looks_like_kev(text: &str) -> bool {
    let l = text.to_ascii_lowercase();
    l.contains("cisa kev")
        || l.contains("known exploited")
        || l.contains("knownransomwarecampaignuse")
        || l.contains("\"kev\":true")
        || l.contains("kev catalog")
}

#[must_use]
pub fn looks_like_ransomware(text: &str) -> bool {
    let l = text.to_ascii_lowercase();
    l.contains("ransomware") || l.contains("knownransomware")
}

pub fn enrich_finding(f: &mut BoardFinding) {
    if f.cve.is_empty() {
        f.cve = extract_cve(&format!("{} {}", f.title, f.description));
    }
    if f.mitre.is_empty() {
        f.mitre = extract_mitre(&format!("{} {}", f.title, f.description));
    }
    if !f.kev {
        f.kev = looks_like_kev(&format!("{} {}", f.title, f.description));
    }
    if !f.ransomware {
        f.ransomware = looks_like_ransomware(&format!("{} {}", f.title, f.description));
    }
}

/// Build a real OOXML workbook. Always starts with ZIP magic `PK`.
pub fn build_client_board_xlsx(wb: &BoardWorkbook) -> Result<Vec<u8>, String> {
    let mut findings = wb.findings.clone();
    for f in &mut findings {
        enrich_finding(f);
    }

    let mut crit = 0u32;
    let mut high = 0u32;
    let mut med = 0u32;
    let mut low = 0u32;
    let mut kev_n = 0u32;
    let mut ransom_n = 0u32;
    for f in &findings {
        let s = f.severity.to_ascii_lowercase();
        if s.contains("critical") {
            crit += 1;
        } else if s.contains("high") {
            high += 1;
        } else if s.contains("medium") || s.contains("med") {
            med += 1;
        } else {
            low += 1;
        }
        if f.kev {
            kev_n += 1;
        }
        if f.ransomware {
            ransom_n += 1;
        }
    }

    let mut strings = SharedStrings::new();
    let overview = sheet_overview(
        &mut strings,
        wb,
        findings.len(),
        crit,
        high,
        med,
        low,
        kev_n,
        ransom_n,
    );
    let findings_sheet = sheet_findings(&mut strings, &findings);
    let attack_sheet = sheet_attack(&mut strings, &findings);
    let paths_sheet = sheet_paths(&mut strings, &findings);
    let remed_sheet = sheet_remediation(&mut strings, &findings);
    let intel_sheet = sheet_intel(&mut strings, &findings);

    let files = [
        ("[Content_Types].xml", content_types_xml()),
        ("_rels/.rels", rels_root()),
        ("xl/workbook.xml", workbook_xml()),
        ("xl/_rels/workbook.xml.rels", workbook_rels()),
        ("xl/styles.xml", styles_xml()),
        ("xl/sharedStrings.xml", strings.to_xml()),
        ("xl/worksheets/sheet1.xml", overview),
        ("xl/worksheets/sheet2.xml", findings_sheet),
        ("xl/worksheets/sheet3.xml", attack_sheet),
        ("xl/worksheets/sheet4.xml", paths_sheet),
        ("xl/worksheets/sheet5.xml", remed_sheet),
        ("xl/worksheets/sheet6.xml", intel_sheet),
    ];

    zip_store(&files)
}

fn content_types_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet4.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet5.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet6.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
</Types>"#
    .to_string()
}

fn rels_root() -> String {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"#
        .to_string()
}

fn workbook_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Overview" sheetId="1" r:id="rId1"/>
    <sheet name="Findings" sheetId="2" r:id="rId2"/>
    <sheet name="ATTACK" sheetId="3" r:id="rId3"/>
    <sheet name="AttackPaths" sheetId="4" r:id="rId4"/>
    <sheet name="Remediation" sheetId="5" r:id="rId5"/>
    <sheet name="Intel" sheetId="6" r:id="rId6"/>
  </sheets>
</workbook>"#
        .to_string()
}

fn workbook_rels() -> String {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet4.xml"/>
  <Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet5.xml"/>
  <Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet6.xml"/>
  <Relationship Id="rId7" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  <Relationship Id="rId8" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
</Relationships>"#
        .to_string()
}

fn styles_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font><sz val="11"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><name val="Calibri"/><color rgb="FFFFFFFF"/></font>
  </fonts>
  <fills count="3">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF0F172A"/><bgColor indexed="64"/></patternFill></fill>
  </fills>
  <borders count="1"><border/></borders>
  <cellStyleXfs count="1"><xf/></cellStyleXfs>
  <cellXfs count="2">
    <xf xfId="0"/>
    <xf xfId="0" fontId="1" fillId="2" applyFont="1" applyFill="1"/>
  </cellXfs>
</styleSheet>"#
        .to_string()
}

struct SharedStrings {
    items: Vec<String>,
    index: std::collections::HashMap<String, usize>,
}

impl SharedStrings {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            index: std::collections::HashMap::new(),
        }
    }

    fn intern(&mut self, s: &str) -> usize {
        let guarded = formula_guard(s);
        let clipped: String = guarded.chars().take(32_767).collect();
        if let Some(&i) = self.index.get(&clipped) {
            return i;
        }
        let i = self.items.len();
        self.index.insert(clipped.clone(), i);
        self.items.push(clipped);
        i
    }

    fn to_xml(&self) -> String {
        let mut out = String::from(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main""#,
        );
        out.push_str(&format!(
            r#" count="{}" uniqueCount="{}">"#,
            self.items.len(),
            self.items.len()
        ));
        for s in &self.items {
            out.push_str("<si><t xml:space=\"preserve\">");
            out.push_str(&xml_escape(s));
            out.push_str("</t></si>");
        }
        out.push_str("</sst>");
        out
    }
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\u{01}'..='\u{08}' | '\u{0B}' | '\u{0C}' | '\u{0E}'..='\u{1F}' => out.push(' '),
            _ => out.push(ch),
        }
    }
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

struct SheetBuf {
    rows: String,
    row: usize,
}

impl SheetBuf {
    fn new() -> Self {
        Self {
            rows: String::new(),
            row: 1,
        }
    }

    fn header(&mut self, ss: &mut SharedStrings, cols: &[&str]) {
        self.row_cells(ss, cols, true);
    }

    fn row_cells(&mut self, ss: &mut SharedStrings, cols: &[&str], header: bool) {
        self.rows.push_str(&format!(r#"<row r="{}">"#, self.row));
        for (i, c) in cols.iter().enumerate() {
            let idx = ss.intern(c);
            let cell = format!("{}{}", col_letter(i), self.row);
            let style = if header { r#" s="1""# } else { "" };
            self.rows
                .push_str(&format!(r#"<c r="{cell}" t="s"{style}><v>{idx}</v></c>"#));
        }
        self.rows.push_str("</row>");
        self.row += 1;
    }

    fn finish(self) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{}</sheetData></worksheet>"#,
            self.rows
        )
    }
}

fn sheet_overview(
    ss: &mut SharedStrings,
    wb: &BoardWorkbook,
    total: usize,
    crit: u32,
    high: u32,
    med: u32,
    low: u32,
    kev_n: u32,
    ransom_n: u32,
) -> String {
    let mut sh = SheetBuf::new();
    sh.header(
        ss,
        &[
            "Weissman Board Pack",
            "Live evidence only — no fabricated APT names or industry averages",
        ],
    );
    sh.row_cells(ss, &["Client", &wb.client_name], false);
    sh.row_cells(ss, &["Generated (Israel time)", &wb.generated_at], false);
    sh.row_cells(ss, &["Integrity hash", &wb.integrity_hash], false);
    sh.row_cells(ss, &["Findings", &total.to_string()], false);
    sh.row_cells(ss, &["Critical", &crit.to_string()], false);
    sh.row_cells(ss, &["High", &high.to_string()], false);
    sh.row_cells(ss, &["Medium", &med.to_string()], false);
    sh.row_cells(ss, &["Low / Info", &low.to_string()], false);
    sh.row_cells(ss, &["KEV-tagged rows", &kev_n.to_string()], false);
    sh.row_cells(
        ss,
        &["Ransomware-signal rows", &ransom_n.to_string()],
        false,
    );
    sh.row_cells(
        ss,
        &[
            "Notes",
            "Sheets: Overview, Findings, ATTACK, AttackPaths, Remediation, Intel. CSV remains available at /export/csv.",
        ],
        false,
    );
    sh.finish()
}

fn sheet_findings(ss: &mut SharedStrings, findings: &[BoardFinding]) -> String {
    let mut sh = SheetBuf::new();
    sh.header(
        ss,
        &[
            "ID",
            "Title",
            "Severity",
            "Source",
            "MITRE",
            "CVE",
            "KEV",
            "Ransomware",
            "Status",
            "Discovered",
            "Proof",
            "Description",
        ],
    );
    for f in findings {
        let id = format!("VLN-{}", f.id);
        sh.row_cells(
            ss,
            &[
                &id,
                &f.title,
                &f.severity,
                &f.source,
                &f.mitre,
                &f.cve,
                if f.kev { "yes" } else { "no" },
                if f.ransomware { "yes" } else { "no" },
                &f.status,
                &f.discovered,
                &f.proof,
                &f.description,
            ],
            false,
        );
    }
    sh.finish()
}

fn sheet_attack(ss: &mut SharedStrings, findings: &[BoardFinding]) -> String {
    let mut sh = SheetBuf::new();
    sh.header(
        ss,
        &["Technique", "Finding count", "Example finding", "Sources"],
    );
    let mut map: std::collections::BTreeMap<
        String,
        (u32, String, std::collections::BTreeSet<String>),
    > = std::collections::BTreeMap::new();
    for f in findings {
        let tech = if f.mitre.is_empty() {
            "UNMAPPED".to_string()
        } else {
            f.mitre.clone()
        };
        let e = map
            .entry(tech)
            .or_insert((0, f.title.clone(), std::collections::BTreeSet::new()));
        e.0 += 1;
        e.2.insert(f.source.clone());
    }
    for (tech, (n, title, srcs)) in map {
        let joined = srcs.into_iter().collect::<Vec<_>>().join(", ");
        sh.row_cells(ss, &[&tech, &n.to_string(), &title, &joined], false);
    }
    sh.finish()
}

fn sheet_paths(ss: &mut SharedStrings, findings: &[BoardFinding]) -> String {
    let mut sh = SheetBuf::new();
    sh.header(ss, &["ID", "Source", "Path / hop evidence", "Severity"]);
    let chain = grounded_kill_chain(findings);
    if let Some(ref chain) = chain {
        sh.row_cells(
            ss,
            &["CHAIN", "credential_ransomware_fusion", chain, "critical"],
            false,
        );
    }
    let mut wrote = u32::from(chain.is_some());
    for f in findings {
        let hay = format!("{} {} {}", f.title, f.description, f.proof);
        let is_path = f.source.to_ascii_lowercase().contains("attack_path")
            || hay.contains("->")
            || hay.to_ascii_lowercase().contains("choke")
            || hay.to_ascii_lowercase().contains("crown jewel")
            || hay.to_ascii_lowercase().contains("internet_exposed");
        if is_path {
            let id = format!("VLN-{}", f.id);
            sh.row_cells(ss, &[&id, &f.source, &hay, &f.severity], false);
            wrote += 1;
        }
    }
    if wrote == 0 {
        sh.row_cells(
            ss,
            &[
                "—",
                "live",
                "No attack-path hop evidence in this client's persisted findings. Run attack_path / kill-chain engines to populate this sheet.",
                "info",
            ],
            false,
        );
    }
    sh.finish()
}

/// Grounded hop string from live KEV / HIBP / URLhaus / IntelX evidence — never invented actors.
#[must_use]
pub fn grounded_kill_chain(findings: &[BoardFinding]) -> Option<String> {
    let blob = |f: &BoardFinding| {
        format!("{} {} {} {}", f.title, f.description, f.proof, f.source).to_ascii_lowercase()
    };
    let mut hops: Vec<&str> = Vec::new();
    if findings
        .iter()
        .any(|f| f.kev || f.ransomware || blob(f).contains("cisa kev"))
    {
        hops.push("CISA KEV ransomware/product");
    }
    if findings.iter().any(|f| {
        let h = blob(f);
        h.contains("hibp") || h.contains("have i been pwned") || h.contains("haveibeenpwned")
    }) {
        hops.push("HIBP credential exposure");
    }
    if findings.iter().any(|f| blob(f).contains("urlhaus")) {
        hops.push("URLhaus malware URLs");
    }
    if findings.iter().any(|f| {
        let h = blob(f);
        h.contains("intelx") || h.contains("intelligence x")
    }) {
        hops.push("IntelX indexed records");
    }
    if hops.len() >= 2 {
        Some(hops.join(" -> "))
    } else {
        None
    }
}

fn sheet_remediation(ss: &mut SharedStrings, findings: &[BoardFinding]) -> String {
    let mut sh = SheetBuf::new();
    sh.header(ss, &["Priority", "ID", "Title", "Severity", "Action"]);
    let mut ranked: Vec<&BoardFinding> = findings.iter().collect();
    ranked.sort_by_key(|f| {
        let s = f.severity.to_ascii_lowercase();
        let w = if s.contains("critical") {
            0
        } else if s.contains("high") {
            1
        } else if s.contains("medium") {
            2
        } else {
            3
        };
        (w, f.id)
    });
    for (i, f) in ranked.iter().take(50).enumerate() {
        let id = format!("VLN-{}", f.id);
        let action = if f.description.is_empty() {
            format!("Remediate {} ({})", f.title, f.source)
        } else {
            f.description.chars().take(240).collect()
        };
        sh.row_cells(
            ss,
            &[&(i + 1).to_string(), &id, &f.title, &f.severity, &action],
            false,
        );
    }
    sh.finish()
}

fn sheet_intel(ss: &mut SharedStrings, findings: &[BoardFinding]) -> String {
    let mut sh = SheetBuf::new();
    sh.header(ss, &["ID", "Source", "Title", "KEV", "Ransomware", "Proof"]);
    let mut wrote = 0u32;
    for f in findings {
        let src = f.source.to_ascii_lowercase();
        let intel = src.contains("hibp")
            || src.contains("darkweb")
            || src.contains("dark_web")
            || src.contains("leak")
            || src.contains("threat_intel")
            || src.contains("credential_ransomware")
            || src.contains("typosquat")
            || f.kev
            || f.ransomware;
        if intel {
            let id = format!("VLN-{}", f.id);
            sh.row_cells(
                ss,
                &[
                    &id,
                    &f.source,
                    &f.title,
                    if f.kev { "yes" } else { "no" },
                    if f.ransomware { "yes" } else { "no" },
                    &f.proof,
                ],
                false,
            );
            wrote += 1;
        }
    }
    if wrote == 0 {
        sh.row_cells(
            ss,
            &[
                "—",
                "live",
                "No HIBP / KEV / leak / fusion findings persisted for this client yet.",
                "no",
                "no",
                "Run credential_ransomware_fusion against an authorized domain.",
            ],
            false,
        );
    }
    sh.finish()
}

fn zip_store(files: &[(&str, String)]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut central = Vec::new();
    let mut count: u16 = 0;
    for (name, body) in files {
        let data = body.as_bytes();
        let crc = crc32(data);
        let offset = buf.len() as u32;
        let name_b = name.as_bytes();
        // Local file header
        buf.extend_from_slice(b"PK\x03\x04");
        buf.extend_from_slice(&20u16.to_le_bytes());
        buf.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 flag
        buf.extend_from_slice(&0u16.to_le_bytes()); // store
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(name_b);
        buf.extend_from_slice(data);

        // Central directory
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0x0800u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_b);
        count += 1;
    }
    let cd_offset = buf.len() as u32;
    let cd_size = central.len() as u32;
    buf.extend_from_slice(&central);
    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    if buf.len() < 30 {
        return Err("xlsx zip too small".into());
    }
    Ok(buf)
}

/// SHA-256 hex of the workbook bytes (for Content-Digest / audit).
#[must_use]
pub fn workbook_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        crc = CRC_TABLE[idx] ^ (crc >> 8);
    }
    !crc
}

const CRC_TABLE: [u32; 256] = make_crc_table();

const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            if c & 1 == 1 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formula_guard_prefixes_formula_cells() {
        assert_eq!(formula_guard("=1+1"), "'=1+1");
        assert_eq!(formula_guard("+cmd"), "'+cmd");
        assert_eq!(formula_guard(" =HYPERLINK(x)"), "'=HYPERLINK(x)");
        assert_eq!(formula_guard("safe"), "safe");
        assert_eq!(formula_guard("CVE-2024-1234"), "CVE-2024-1234");
    }

    #[test]
    fn extracts_cve_and_mitre() {
        assert_eq!(extract_cve("see CVE-2024-12345 in KEV"), "CVE-2024-12345");
        assert_eq!(extract_mitre("maps to T1555.003 cookie theft"), "T1555.003");
        assert_eq!(extract_mitre("T1190 only"), "T1190");
        assert!(looks_like_kev("CISA KEV listed CVE-2024-1234"));
        assert!(looks_like_ransomware("knownRansomwareCampaignUse=Known"));
    }

    #[test]
    fn workbook_is_real_ooxml_zip() {
        let bytes = build_client_board_xlsx(&BoardWorkbook {
            client_name: "וויסמן".into(),
            generated_at: "2026-09-12 00:00:00".into(),
            integrity_hash: "abc".into(),
            findings: vec![
                BoardFinding {
                    id: 7,
                    title: "=HYPERLINK(http://evil)".into(),
                    severity: "critical".into(),
                    source: "credential_ransomware_fusion".into(),
                    description: "CISA KEV ransomware product match T1190 CVE-2024-21762".into(),
                    proof: "GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json HTTP 200".into(),
                    ..Default::default()
                },
                BoardFinding {
                    id: 8,
                    title: "HIBP public catalog lists example.com".into(),
                    severity: "high".into(),
                    source: "credential_ransomware_fusion".into(),
                    proof: "GET https://haveibeenpwned.com/api/v3/breaches HTTP 200".into(),
                    ..Default::default()
                },
            ],
        })
        .expect("xlsx");
        if let Ok(p) = std::env::var("WEISSMAN_XLSX_DUMP") {
            std::fs::write(&p, &bytes).expect("dump xlsx");
        }
        assert!(bytes.starts_with(b"PK"), "must be ZIP");
        let as_str = String::from_utf8_lossy(&bytes);
        assert!(as_str.contains("Overview"));
        assert!(as_str.contains("Findings"));
        assert!(as_str.contains("ATTACK"));
        assert!(as_str.contains("AttackPaths"));
        assert!(as_str.contains("Remediation"));
        assert!(as_str.contains("Intel"));
        assert!(as_str.contains("sharedStrings"));
        assert!(
            as_str.contains("וויסמן") || as_str.contains("&#"),
            "hebrew client name must survive"
        );
        assert!(
            as_str.contains("'=HYPERLINK")
                || as_str.contains("&apos;=HYPERLINK")
                || as_str.contains("&#39;=HYPERLINK")
                || as_str.contains("&apos;")
                || bytes.windows(12).any(|w| w == b"'=HYPERLINK"),
            "formula injection must be neutralized"
        );
        assert!(!as_str.contains("APT28"));
        assert!(!as_str.contains("Industry Avg"));
        assert!(
            as_str.contains("CHAIN") || as_str.contains("HIBP credential"),
            "two live legs must write a grounded kill-chain hop"
        );
    }

    #[test]
    fn grounded_kill_chain_needs_two_live_legs() {
        let kev = BoardFinding {
            title: "CISA KEV product match".into(),
            kev: true,
            ransomware: true,
            ..Default::default()
        };
        let hibp = BoardFinding {
            title: "HIBP public catalog lists Adobe".into(),
            proof: "GET https://haveibeenpwned.com/api/v3/breaches HTTP 200".into(),
            ..Default::default()
        };
        assert!(grounded_kill_chain(&[kev.clone()]).is_none());
        let chain = grounded_kill_chain(&[kev, hibp]).expect("chain");
        assert!(chain.contains("->"));
        assert!(chain.contains("CISA KEV"));
        assert!(chain.contains("HIBP"));
        assert!(!chain.contains("APT28"));
    }
}
