//! JSON document / workbook specs accepted by `POST /api/export/*` and `weissman-docgen`.
//!
//! The frontend never generates PDF/XLSX itself for customer-facing exports: it posts this
//! shape and the server renders through the same engines as the named report endpoints.

use super::charts::{Chart, Slice};
use super::doc::{Block, Callout, DocMeta, Lang, Metric, ReportDoc, Section, Tone};
use super::layout::{CellStyle, Column, Table};
use super::theme;
use serde::{Deserialize, Serialize};

const MAX_SECTIONS: usize = 40;
const MAX_BLOCKS: usize = 80;
const MAX_ROWS: usize = 5_000;
const MAX_COLS: usize = 32;
const MAX_CELL: usize = 8_192;
const MAX_TITLE: usize = 240;

/// A complete printable document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentSpec {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub classification: String,
    #[serde(default)]
    pub doc_id: String,
    #[serde(default)]
    pub lang: String,
    #[serde(default)]
    pub control_fields: Vec<(String, String)>,
    #[serde(default)]
    pub integrity_hash: Option<String>,
    #[serde(default)]
    pub verify_url: Option<String>,
    #[serde(default)]
    pub watermark: Option<String>,
    #[serde(default)]
    pub hero: Option<ChartSpec>,
    #[serde(default)]
    pub sections: Vec<SectionSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionSpec {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub start_on_new_page: bool,
    #[serde(default)]
    pub blocks: Vec<BlockSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BlockSpec {
    Heading {
        text: String,
    },
    Paragraph {
        text: String,
    },
    Bullets {
        items: Vec<String>,
    },
    KeyValues {
        rows: Vec<(String, String)>,
    },
    Metrics {
        items: Vec<MetricSpec>,
    },
    Table {
        columns: Vec<ColumnSpec>,
        rows: Vec<Vec<String>>,
        #[serde(default)]
        note: Option<String>,
    },
    Chart {
        chart: ChartSpec,
    },
    Callout {
        tone: String,
        title: String,
        body: String,
    },
    Mono {
        lines: Vec<String>,
    },
    Divider,
    Spacer {
        height: f64,
    },
    PageBreak,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSpec {
    pub label: String,
    pub value: String,
    #[serde(default)]
    pub tone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnSpec {
    pub title: String,
    #[serde(default = "one")]
    pub weight: f64,
    #[serde(default)]
    pub style: String,
}

fn one() -> f64 {
    1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChartSpec {
    Gauge {
        score: i32,
        #[serde(default)]
        caption: String,
    },
    Donut {
        slices: Vec<SliceSpec>,
        #[serde(default)]
        caption: String,
    },
    Bars {
        slices: Vec<SliceSpec>,
        #[serde(default)]
        caption: String,
    },
    Columns {
        slices: Vec<SliceSpec>,
        #[serde(default)]
        caption: String,
    },
    RiskMatrix {
        cells: [[u32; 5]; 5],
        #[serde(default)]
        caption: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceSpec {
    pub label: String,
    pub value: f64,
    #[serde(default)]
    pub color: String,
}

/// A complete workbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkbookSpec {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub classification: String,
    #[serde(default)]
    pub doc_id: String,
    #[serde(default)]
    pub lang: String,
    #[serde(default)]
    pub actor: String,
    #[serde(default)]
    pub control_fields: Vec<(String, String)>,
    #[serde(default)]
    pub sheets: Vec<SheetSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SheetSpec {
    pub name: String,
    pub columns: Vec<ColumnSpec>,
    #[serde(default)]
    pub rows: Vec<Vec<String>>,
}

fn clip(s: &str, max: usize) -> String {
    let stripped = strip_markup(s);
    let s = stripped.trim();
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        chars.into_iter().take(max).collect()
    }
}

/// Drop HTML/script markup so exported documents never carry raw XSS payloads.
fn strip_markup(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let lower = s.to_ascii_lowercase();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if lower[i..].starts_with("<script") {
            if let Some(end) = lower[i..].find("</script>") {
                i += end + 9;
                continue;
            }
        }
        if bytes[i] == b'<' {
            while i < bytes.len() && bytes[i] != b'>' {
                i += 1;
            }
            i += 1;
            continue;
        }
        let ch = s[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn tone(raw: &str) -> Tone {
    match raw.trim().to_ascii_lowercase().as_str() {
        "good" | "ok" => Tone::Good,
        "warn" | "warning" | "amber" => Tone::Warn,
        "bad" | "critical" | "danger" => Tone::Bad,
        "brand" => Tone::Brand,
        _ => Tone::Neutral,
    }
}

fn cell_style(raw: &str) -> CellStyle {
    match raw.trim().to_ascii_lowercase().as_str() {
        "strong" => CellStyle::Strong,
        "muted" => CellStyle::Muted,
        "mono" => CellStyle::Mono,
        "severity" => CellStyle::Severity,
        "number" => CellStyle::Number,
        _ => CellStyle::Text,
    }
}

fn slice_color(raw: &str) -> theme::Rgb {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" | "rose" => theme::SEV_CRITICAL,
        "high" | "amber" => theme::SEV_HIGH,
        "medium" => theme::SEV_MEDIUM,
        "low" | "brand" => theme::SEV_LOW,
        "ok" | "green" => theme::OK,
        "cyan" => theme::CYAN,
        _ => theme::BRAND,
    }
}

fn to_chart(spec: &ChartSpec) -> Chart {
    match spec {
        ChartSpec::Gauge { score, caption } => Chart::Gauge {
            score: *score,
            caption: clip(caption, MAX_TITLE),
        },
        ChartSpec::Donut { slices, caption } => Chart::Donut {
            slices: slices.iter().take(24).map(to_slice).collect(),
            caption: clip(caption, MAX_TITLE),
        },
        ChartSpec::Bars { slices, caption } => Chart::Bars {
            slices: slices.iter().take(24).map(to_slice).collect(),
            caption: clip(caption, MAX_TITLE),
        },
        ChartSpec::Columns { slices, caption } => Chart::Columns {
            slices: slices.iter().take(24).map(to_slice).collect(),
            caption: clip(caption, MAX_TITLE),
        },
        ChartSpec::RiskMatrix { cells, caption } => Chart::RiskMatrix {
            cells: *cells,
            caption: clip(caption, MAX_TITLE),
        },
    }
}

fn to_slice(s: &SliceSpec) -> Slice {
    Slice::new(clip(&s.label, 80), s.value, slice_color(&s.color))
}

fn to_table(columns: &[ColumnSpec], rows: &[Vec<String>], note: Option<&str>) -> Table {
    let cols: Vec<Column> = columns
        .iter()
        .take(MAX_COLS)
        .map(|c| Column::new(clip(&c.title, 80), c.weight).styled(cell_style(&c.style)))
        .collect();
    let data: Vec<Vec<String>> = rows
        .iter()
        .take(MAX_ROWS)
        .map(|r| r.iter().take(MAX_COLS).map(|c| clip(c, MAX_CELL)).collect())
        .collect();
    let mut table = Table::new(cols).with_rows(data);
    if let Some(n) = note {
        table = table.note(clip(n, MAX_TITLE));
    }
    table
}

impl DocumentSpec {
    /// Validate caps and convert to a [`ReportDoc`].
    pub fn to_report(&self) -> Result<ReportDoc, String> {
        if self.sections.len() > MAX_SECTIONS {
            return Err(format!("too many sections (max {MAX_SECTIONS})"));
        }
        let lang = Lang::parse(&self.lang);
        let mut meta = DocMeta {
            title: clip(&self.title, MAX_TITLE),
            subtitle: clip(&self.subtitle, MAX_TITLE),
            org: clip(
                if self.org.is_empty() {
                    "Weissman Cybersecurity"
                } else {
                    &self.org
                },
                120,
            ),
            client: clip(&self.client, 160),
            classification: clip(
                if self.classification.is_empty() {
                    "Confidential"
                } else {
                    &self.classification
                },
                40,
            ),
            doc_id: clip(&self.doc_id, 64),
            lang,
            control_fields: self
                .control_fields
                .iter()
                .take(20)
                .map(|(k, v)| (clip(k, 80), clip(v, 240)))
                .collect(),
            integrity_hash: self.integrity_hash.as_ref().map(|s| clip(s, 128)),
            verify_url: self.verify_url.as_ref().map(|s| clip(s, 240)),
            watermark: self.watermark.as_ref().map(|s| clip(s, 80)),
        };
        if meta.title.is_empty() {
            meta.title = "Weissman Export".into();
        }
        let mut doc = ReportDoc::new(meta);
        if let Some(hero) = &self.hero {
            doc.hero = Some(to_chart(hero));
        }
        for section in self.sections.iter().take(MAX_SECTIONS) {
            if section.blocks.len() > MAX_BLOCKS {
                return Err(format!("too many blocks in section '{}'", section.title));
            }
            let mut s = Section::new(clip(&section.title, MAX_TITLE));
            if section.start_on_new_page {
                s = s.on_new_page();
            }
            for block in &section.blocks {
                s.push(to_block(block)?);
            }
            doc.push(s);
        }
        Ok(doc)
    }

    pub fn render_pdf(&self) -> Result<Vec<u8>, String> {
        Ok(self.to_report()?.render())
    }
}

fn to_block(block: &BlockSpec) -> Result<Block, String> {
    Ok(match block {
        BlockSpec::Heading { text } => Block::Heading(clip(text, MAX_TITLE)),
        BlockSpec::Paragraph { text } => Block::Paragraph(clip(text, MAX_CELL)),
        BlockSpec::Bullets { items } => {
            Block::Bullets(items.iter().take(80).map(|i| clip(i, MAX_CELL)).collect())
        }
        BlockSpec::KeyValues { rows } => Block::KeyValues(
            rows.iter()
                .take(40)
                .map(|(k, v)| (clip(k, 80), clip(v, MAX_CELL)))
                .collect(),
        ),
        BlockSpec::Metrics { items } => Block::Metrics(
            items
                .iter()
                .take(12)
                .map(|m| Metric::new(clip(&m.label, 80), clip(&m.value, 80), tone(&m.tone)))
                .collect(),
        ),
        BlockSpec::Table {
            columns,
            rows,
            note,
        } => {
            if columns.len() > MAX_COLS {
                return Err(format!("too many columns (max {MAX_COLS})"));
            }
            if rows.len() > MAX_ROWS {
                return Err(format!("too many rows (max {MAX_ROWS})"));
            }
            Block::Table(to_table(columns, rows, note.as_deref()))
        }
        BlockSpec::Chart { chart } => Block::Chart(to_chart(chart)),
        BlockSpec::Callout {
            tone: tn,
            title,
            body,
        } => Block::Callout(Callout::new(
            tone(tn),
            clip(title, MAX_TITLE),
            clip(body, MAX_CELL),
        )),
        BlockSpec::Mono { lines } => {
            Block::Mono(lines.iter().take(200).map(|l| clip(l, MAX_CELL)).collect())
        }
        BlockSpec::Divider => Block::Divider,
        BlockSpec::Spacer { height } => Block::Spacer(*height),
        BlockSpec::PageBreak => Block::PageBreak,
    })
}

impl WorkbookSpec {
    pub fn sanitized(&self) -> Result<Self, String> {
        if self.sheets.len() > 16 {
            return Err("too many sheets (max 16)".into());
        }
        let mut out = self.clone();
        out.title = clip(&self.title, MAX_TITLE);
        if out.title.is_empty() {
            out.title = "Weissman Export".into();
        }
        out.subtitle = clip(&self.subtitle, MAX_TITLE);
        out.org = clip(&self.org, 120);
        out.client = clip(&self.client, 160);
        out.classification = clip(&self.classification, 40);
        out.doc_id = clip(&self.doc_id, 64);
        out.lang = clip(&self.lang, 8);
        out.actor = clip(&self.actor, 120);
        out.control_fields = self
            .control_fields
            .iter()
            .take(24)
            .map(|(k, v)| (clip(k, 80), clip(v, 240)))
            .collect();
        out.sheets = self
            .sheets
            .iter()
            .take(16)
            .map(|s| {
                if s.columns.len() > MAX_COLS {
                    return Err(format!("too many columns on sheet '{}'", s.name));
                }
                if s.rows.len() > MAX_ROWS {
                    return Err(format!("too many rows on sheet '{}'", s.name));
                }
                Ok(SheetSpec {
                    name: clip(&s.name, 31),
                    columns: s.columns.iter().take(MAX_COLS).cloned().collect(),
                    rows: s
                        .rows
                        .iter()
                        .take(MAX_ROWS)
                        .map(|r| r.iter().take(MAX_COLS).map(|c| clip(c, MAX_CELL)).collect())
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if out.sheets.is_empty() {
            return Err("workbook has no sheets".into());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_minimal_document() {
        let spec = DocumentSpec {
            title: "Panel export".into(),
            subtitle: String::new(),
            org: String::new(),
            client: "Acme".into(),
            classification: String::new(),
            doc_id: String::new(),
            lang: "en".into(),
            control_fields: vec![],
            integrity_hash: None,
            verify_url: None,
            watermark: None,
            hero: None,
            sections: vec![SectionSpec {
                title: "Rows".into(),
                start_on_new_page: false,
                blocks: vec![BlockSpec::Table {
                    columns: vec![ColumnSpec {
                        title: "Name".into(),
                        weight: 1.0,
                        style: String::new(),
                    }],
                    rows: vec![vec!["alpha".into()]],
                    note: None,
                }],
            }],
        };
        let pdf = spec.render_pdf().expect("render");
        assert!(pdf.starts_with(b"%PDF-1."));
    }

    #[test]
    fn rejects_oversized_tables() {
        let spec = DocumentSpec {
            title: "x".into(),
            subtitle: String::new(),
            org: String::new(),
            client: String::new(),
            classification: String::new(),
            doc_id: String::new(),
            lang: String::new(),
            control_fields: vec![],
            integrity_hash: None,
            verify_url: None,
            watermark: None,
            hero: None,
            sections: vec![SectionSpec {
                title: "t".into(),
                start_on_new_page: false,
                blocks: vec![BlockSpec::Table {
                    columns: (0..40)
                        .map(|i| ColumnSpec {
                            title: format!("c{i}"),
                            weight: 1.0,
                            style: String::new(),
                        })
                        .collect(),
                    rows: vec![],
                    note: None,
                }],
            }],
        };
        assert!(spec.render_pdf().is_err());
    }

    #[test]
    fn strip_markup_drops_script_and_event_handler_payloads() {
        assert_eq!(super::strip_markup("XSS <script>alert(1)</script>"), "XSS ");
        assert_eq!(super::strip_markup("<img src=x onerror=alert(1)>"), "");
        assert!(!super::strip_markup("ok <b>bold</b>").contains('<'));
        assert!(!super::strip_markup("<script>alert(1)</script>").contains("alert(1)"));
    }

    #[test]
    fn workbook_requires_at_least_one_sheet() {
        let spec = WorkbookSpec {
            title: "x".into(),
            subtitle: String::new(),
            org: String::new(),
            client: String::new(),
            classification: String::new(),
            lang: String::new(),
            actor: String::new(),
            doc_id: String::new(),
            control_fields: vec![],
            sheets: vec![],
        };
        assert!(spec.sanitized().is_err());
    }
}
