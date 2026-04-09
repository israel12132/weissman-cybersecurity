//! Board-level PDF using `genpdf` when Liberation Sans (Helvetica-metrics) fonts are available;
//! otherwise falls back to `pdf_report::build_executive_board_pdf` (embedded Helvetica streams).

use genpdf::elements::Paragraph;
use genpdf::fonts::{Builtin, FontData, FontFamily};
use genpdf::style::{Style, StyledString};
use genpdf::{Document, SimplePageDecorator};
use std::io::Cursor;

#[derive(Debug, Clone)]
pub struct ExecutiveBoardParams {
    pub org_label: String,
    pub client_label: Option<String>,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub cloud_finding_count: usize,
    pub soc2_pct: u8,
    pub iso_pct: u8,
    pub gdpr_pct: u8,
}

fn try_genpdf_font_family() -> Option<FontFamily<FontData>> {
    let dirs: Vec<String> = std::env::var("WEISSMAN_GENPDF_FONT_DIR")
        .map(|s| vec![s])
        .unwrap_or_default()
        .into_iter()
        .chain(
            [
                "/usr/share/fonts/truetype/liberation",
                "/usr/share/fonts/liberation",
            ]
            .iter()
            .map(|s| s.to_string()),
        )
        .filter(|s| !s.is_empty())
        .collect();
    for d in dirs {
        if let Ok(ff) = genpdf::fonts::from_files(&d, "LiberationSans", Some(Builtin::Helvetica)) {
            return Some(ff);
        }
    }
    None
}

fn paragraph_line(text: &str, bold: bool) -> Paragraph {
    let st = if bold {
        Style::new().bold()
    } else {
        Style::new()
    };
    Paragraph::new(StyledString::new(text.to_string(), st))
}

fn render_with_genpdf(
    family: FontFamily<FontData>,
    p: &ExecutiveBoardParams,
) -> Result<Vec<u8>, String> {
    let mut doc = Document::new(family);
    doc.set_title("Weissman Executive Board Report");
    let mut dec = SimplePageDecorator::new();
    dec.set_margins(18);
    doc.set_page_decorator(dec);
    doc.push(paragraph_line(
        "WEISSMAN — EXECUTIVE / BOARD BRIEFING",
        true,
    ));
    doc.push(paragraph_line(
        &format!("Organization: {}", p.org_label),
        false,
    ));
    if let Some(ref c) = p.client_label {
        doc.push(paragraph_line(&format!("Scope (client): {}", c), false));
    }
    doc.push(paragraph_line(" ", false));
    doc.push(paragraph_line("Risk posture (application & cloud)", true));
    doc.push(paragraph_line(
        &format!(
            "Critical: {}  |  High: {}  |  Medium: {}  |  Low / Info: {}",
            p.critical, p.high, p.medium, p.low
        ),
        false,
    ));
    doc.push(paragraph_line(
        &format!(
            "Agentless cloud misconfigurations (latest scan): {}",
            p.cloud_finding_count
        ),
        false,
    ));
    doc.push(paragraph_line(" ", false));
    doc.push(paragraph_line(
        "Continuous compliance (mapped controls)",
        true,
    ));
    doc.push(paragraph_line(
        &format!("SOC 2 (mapped): {}% aligned", p.soc2_pct),
        false,
    ));
    doc.push(paragraph_line(
        &format!("ISO 27001 (mapped): {}% aligned", p.iso_pct),
        false,
    ));
    doc.push(paragraph_line(
        &format!("GDPR (mapped): {}% aligned", p.gdpr_pct),
        false,
    ));
    doc.push(paragraph_line(" ", false));
    doc.push(paragraph_line(
        "Confidential — authorized risk and audit distribution only.",
        false,
    ));
    let mut buf = Vec::new();
    let mut c = Cursor::new(&mut buf);
    doc.render(&mut c).map_err(|e| e.to_string())?;
    Ok(buf)
}

pub fn render_executive_board_pdf(p: &ExecutiveBoardParams) -> Result<Vec<u8>, String> {
    if let Some(family) = try_genpdf_font_family() {
        if let Ok(bytes) = render_with_genpdf(family, p) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }
    }
    crate::pdf_report::build_executive_board_pdf(
        &p.org_label,
        p.client_label.as_deref(),
        p.critical,
        p.high,
        p.medium,
        p.low,
        p.cloud_finding_count,
        p.soc2_pct,
        p.iso_pct,
        p.gdpr_pct,
    )
}
