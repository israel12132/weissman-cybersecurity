//! Native PDF-1.4 board pack (Helvetica). English only — Hebrew lives in the XLSX + UI.

use super::{BoardPack, PackFinding};
use chrono::TimeZone;
use chrono_tz::Asia::Jerusalem;

const PAGE_W: f64 = 612.0;
const PAGE_H: f64 = 792.0;
const MARGIN: f64 = 50.0;
const PAGE_BREAK_Y: f64 = 72.0;

fn pdf_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

fn ascii_line(s: &str, max: usize) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_ascii() { c } else { '?' })
        .collect();
    let t = cleaned.trim();
    let chars: Vec<char> = t.chars().collect();
    if chars.len() <= max {
        t.to_string()
    } else {
        format!("{}...", chars.into_iter().take(max).collect::<String>())
    }
}

fn israel_now() -> String {
    Jerusalem
        .from_utc_datetime(&chrono::Utc::now().naive_utc())
        .format("%Y-%m-%d %H:%M %Z")
        .to_string()
}

struct PdfBuilder {
    page_streams: Vec<String>,
    current: String,
    y: f64,
}

impl PdfBuilder {
    fn new() -> Self {
        Self {
            page_streams: Vec::new(),
            current: String::new(),
            y: PAGE_H - MARGIN,
        }
    }

    fn ensure(&mut self, need: f64) {
        if self.y - need < PAGE_BREAK_Y {
            self.new_page();
        }
    }

    fn new_page(&mut self) {
        if !self.current.is_empty() {
            self.page_streams.push(std::mem::take(&mut self.current));
        }
        self.y = PAGE_H - MARGIN;
        self.header_bar();
    }

    fn header_bar(&mut self) {
        self.set_fill(0.05, 0.55, 0.62);
        self.rect(0.0, PAGE_H - 18.0, PAGE_W, 18.0);
        self.set_fill(0.95, 0.98, 0.99);
        self.text_at(
            MARGIN,
            PAGE_H - 13.0,
            8,
            "WEISSMAN  |  THREAT-INFORMED BOARD PACK  |  CONFIDENTIAL",
        );
        self.y = PAGE_H - 36.0;
    }

    fn set_fill(&mut self, r: f64, g: f64, b: f64) {
        self.current.push_str(&format!("{r:.3} {g:.3} {b:.3} rg\n"));
    }

    fn rect(&mut self, x: f64, y: f64, w: f64, h: f64) {
        self.current
            .push_str(&format!("{x:.1} {y:.1} {w:.1} {h:.1} re f\n"));
    }

    fn text_at(&mut self, x: f64, y: f64, size: i32, s: &str) {
        self.current.push_str(&format!(
            "BT /F1 {size} Tf {x:.1} {y:.1} Td ({}) Tj ET\n",
            pdf_escape(s)
        ));
    }

    fn line(&mut self, size: i32, s: &str) {
        self.ensure(size as f64 + 6.0);
        self.text_at(MARGIN, self.y, size, s);
        self.y -= size as f64 + 5.0;
    }

    fn heading(&mut self, s: &str) {
        self.ensure(28.0);
        self.set_fill(0.07, 0.55, 0.62);
        self.line(13, s);
        self.set_fill(0.12, 0.14, 0.18);
    }

    fn kv(&mut self, k: &str, v: &str) {
        self.ensure(16.0);
        self.set_fill(0.35, 0.40, 0.45);
        self.text_at(MARGIN, self.y, 9, k);
        self.set_fill(0.10, 0.12, 0.16);
        self.text_at(MARGIN + 160.0, self.y, 9, &ascii_line(v, 70));
        self.y -= 14.0;
    }

    fn finish(mut self) -> Vec<String> {
        if !self.current.is_empty() {
            self.page_streams.push(std::mem::take(&mut self.current));
        }
        if self.page_streams.is_empty() {
            self.page_streams.push(String::new());
        }
        self.page_streams
    }
}

fn serialize_pdf(streams: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets: Vec<usize> = vec![0];
    out.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");
    offsets.push(out.len());
    out.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offsets.push(out.len());
    let n = streams.len();
    let page_objects: Vec<usize> = (0..n).map(|i| 3 + i * 2).collect();
    let contents_objects: Vec<usize> = (0..n).map(|i| 4 + i * 2).collect();
    let pages_refs: String = page_objects.iter().map(|i| format!("{i} 0 R ")).collect();
    out.extend_from_slice(
        format!(
            "2 0 obj\n<< /Type /Pages /Kids [ {}] /Count {n} >>\nendobj\n",
            pages_refs.trim()
        )
        .as_bytes(),
    );
    offsets.push(out.len());
    let font_obj = 3 + 2 * n;
    for (i, stream_body) in streams.iter().enumerate() {
        out.extend_from_slice(
            format!(
                "{} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources << /Font << /F1 {} 0 R >> >> >>\nendobj\n",
                page_objects[i], contents_objects[i], font_obj
            )
            .as_bytes(),
        );
        offsets.push(out.len());
        out.extend_from_slice(
            format!(
                "{} 0 obj\n<< /Length {} >>\nstream\n{}\nendstream\nendobj\n",
                contents_objects[i],
                stream_body.len(),
                stream_body
            )
            .as_bytes(),
        );
        offsets.push(out.len());
    }
    out.extend_from_slice(
        format!(
            "{font_obj} 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        )
        .as_bytes(),
    );
    offsets.push(out.len());
    let xref_start = out.len();
    let num_objs = font_obj;
    out.extend_from_slice(b"xref\n");
    out.extend_from_slice(format!("0 {} \n", num_objs + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for off in offsets.iter().skip(1).take(num_objs) {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n",
            num_objs + 1
        )
        .as_bytes(),
    );
    out
}

fn finding_line(f: &PackFinding) -> String {
    ascii_line(
        &format!(
            "[{}] {} | {} | {} | KEV={} EPSS={} BOD={}",
            f.severity,
            f.title,
            f.source,
            if f.cve.is_empty() { "-" } else { &f.cve },
            f.kev_listed,
            f.epss
                .map(|e| format!("{e:.2}"))
                .unwrap_or_else(|| "-".into()),
            f.bod.tier().as_str()
        ),
        108,
    )
}

pub fn render_pdf(pack: &BoardPack) -> Result<Vec<u8>, String> {
    let mut b = PdfBuilder::new();
    b.header_bar();
    b.set_fill(0.07, 0.09, 0.12);
    b.line(22, "Threat-Informed Board Pack");
    b.set_fill(0.07, 0.55, 0.62);
    b.line(
        11,
        "Live findings x MITRE ATT&CK x CISA KEV x BOD 26-04 x FAIR $",
    );
    b.set_fill(0.12, 0.14, 0.18);
    b.kv("Prepared for", &ascii_line(&pack.client_name, 60));
    b.kv("Client ID", &pack.client_id.to_string());
    b.kv("Generated", &pack.generated_at);
    b.kv("Document", "WSM-TIBP");
    b.kv("Classification", "CONFIDENTIAL — authorized client only");
    b.kv(
        "Typeface note",
        "PDF is Helvetica/English. Hebrew + UTF-8 tables are in the Excel pack.",
    );

    b.y -= 8.0;
    b.heading("1. Bottom line up front");
    b.kv("Live findings", &pack.findings.len().to_string());
    b.kv("CISA KEV listed", &pack.kev_count.to_string());
    b.kv("BOD 26-04 P0 (4/4 factors)", &pack.bod_p0.to_string());
    b.kv("BOD 26-04 P1 (3/4 factors)", &pack.bod_p1.to_string());
    b.kv("Annualised loss (ALE USD)", &format_usd(pack.ale_usd));
    b.kv("Worst single loss (SLE USD)", &format_usd(pack.sle_usd));
    b.kv("Path ALE USD", &format_usd(pack.path_ale_usd));
    b.kv("Crown-jewel value USD", &format_usd(pack.crown_jewel_usd));
    b.kv(
        "ATT&CK techniques exposed",
        &pack.techniques.len().to_string(),
    );
    b.kv("Attack paths (snapshot)", &pack.paths.len().to_string());
    b.kv(
        "First-mover added hosts",
        &pack.first_mover_added.to_string(),
    );
    b.kv("Leak/paste engine hits", &pack.leak_count.to_string());
    b.line(
        9,
        &ascii_line(
            &format!(
                "FAIR: {}. Paths: {}.",
                if pack.fair_present {
                    "live snapshot"
                } else {
                    "none yet (honest empty — not estimated)"
                },
                if pack.paths_present {
                    "live Dijkstra snapshot"
                } else {
                    "none yet (honest empty)"
                }
            ),
            110,
        ),
    );

    b.heading("2. CISA BOD 26-04 triage (public guidance)");
    b.line(
        9,
        "Factors: public exposure, KEV, automatable proxy (EPSS>=0.40 or verified or KEV), total impact (critical/high or CVSS>=9).",
    );
    b.line(
        9,
        "Highest band (all four): 3 calendar days + forensic triage. Empty P0 is a real empty, not a demo.",
    );
    let mut shown = 0usize;
    for f in pack.findings.iter().filter(|f| {
        matches!(
            f.bod.tier(),
            super::bod::BodTier::P0 | super::bod::BodTier::P1
        )
    }) {
        b.line(8, &finding_line(f));
        shown += 1;
        if shown >= 18 {
            b.line(8, "... additional P0/P1 rows are in the Excel pack.");
            break;
        }
    }
    if shown == 0 {
        b.line(9, "No P0/P1 findings in the live tenant dataset.");
    }

    b.heading("3. Adversary TTP overlay (MITRE ATT&CK)");
    if pack.techniques.is_empty() {
        b.line(9, "No ATT&CK-mapped live findings for this client.");
    } else {
        for t in pack.techniques.iter().take(18) {
            b.line(
                8,
                &ascii_line(
                    &format!(
                        "{}  {}  tactic={}  n={}  crit={} high={}",
                        t.technique,
                        t.name.clone().unwrap_or_default(),
                        t.tactic,
                        t.count,
                        t.critical,
                        t.high
                    ),
                    110,
                ),
            );
        }
    }

    b.heading("4. Crown-jewel attack paths (FAIR-priced)");
    b.line(9, &ascii_line(&pack.paths_message, 110));
    for p in pack.paths.iter().take(8) {
        b.line(
            8,
            &ascii_line(
                &format!(
                    "entry={} jewel={} hops={} score={} ALE=${} KEV-hops={} {}",
                    p.entry,
                    p.jewel,
                    p.hops,
                    p.path_score,
                    p.ale_usd,
                    p.kev_hops,
                    p.mitre_technique_id
                ),
                110,
            ),
        );
    }

    b.heading("5. First-mover surface delta");
    b.line(9, &ascii_line(&pack.first_mover_message, 110));
    b.kv("Added", &pack.first_mover_added.to_string());
    b.kv("Removed", &pack.first_mover_removed.to_string());
    b.kv("Changed", &pack.first_mover_changed.to_string());

    b.heading("6. Leak / paste exposure (live engines, not a Tor crawl)");
    b.kv("Hits", &pack.leak_count.to_string());
    let mut leak_n = 0usize;
    for f in pack
        .findings
        .iter()
        .filter(|f| super::is_leak_source(&f.source))
        .take(12)
    {
        b.line(8, &finding_line(f));
        leak_n += 1;
    }
    if leak_n == 0 {
        b.line(
            9,
            "No leak_hunter / dark_web_monitor / typosquatting findings in the live DB.",
        );
    }

    b.heading("7. Methodology and provenance");
    b.line(8, "CISA BOD 26-04 implementation guidance (public).");
    b.line(
        8,
        "CISA Known Exploited Vulnerabilities catalog (public JSON feed, mirrored).",
    );
    b.line(
        8,
        "FIRST.org EPSS as automatable proxy — not a CISA-certified automatable flag.",
    );
    b.line(8, "MITRE ATT&CK via Weissman attack_coverage catalog.");
    b.line(
        8,
        "Findings: tenant-RLS PostgreSQL. Empty cells mean absence, never invented APT names.",
    );
    b.line(8, "Board edition omits proof-of-concept payloads.");
    b.line(
        8,
        &format!("Generated {} | (c) Weissman Cybersecurity", israel_now()),
    );

    let streams = b.finish();
    Ok(serialize_pdf(&streams))
}

fn format_usd(n: i64) -> String {
    let neg = n < 0;
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    let body: String = out.chars().rev().collect();
    if neg {
        format!("-${body}")
    } else {
        format!("${body}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board_pack::{BoardPack, PackLang};

    #[test]
    fn pdf_magic_and_helvetica() {
        let pack = BoardPack::empty_demo(9, "Board Co", PackLang::En);
        let bytes = render_pdf(&pack).expect("pdf");
        let body = String::from_utf8_lossy(&bytes);
        assert!(body.starts_with("%PDF-1.4"));
        assert!(body.contains("/BaseFont /Helvetica"));
        assert!(body.contains("BOD 26-04"));
        assert!(body.contains("honest empty") || body.contains("none yet"));
    }
}
