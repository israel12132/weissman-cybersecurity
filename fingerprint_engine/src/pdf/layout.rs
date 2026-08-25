//! Table layout: proportional columns, wrapped cells, severity chips and page-aware
//! pagination that repeats the header on every continuation page.

use super::canvas::{Align, Canvas, FontStyle};
use super::theme::{self, Rgb};

/// How a cell's value should be presented.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CellStyle {
    /// Regular body text.
    Text,
    /// Emphasised body text (identifiers, primary column).
    Strong,
    /// Secondary text.
    Muted,
    /// Monospace — hashes, ids, evidence.
    Mono,
    /// Rendered as a coloured severity pill.
    Severity,
    /// Right-aligned number, coloured by magnitude relative to the column maximum.
    Number,
}

/// One table column.
#[derive(Clone, Debug)]
pub struct Column {
    pub title: String,
    /// Relative share of the table width. Weights are normalised across the table.
    pub weight: f64,
    pub align: Align,
    pub style: CellStyle,
}

impl Column {
    #[must_use]
    pub fn new(title: impl Into<String>, weight: f64) -> Self {
        Self {
            title: title.into(),
            weight: weight.max(0.01),
            align: Align::Start,
            style: CellStyle::Text,
        }
    }

    #[must_use]
    pub fn styled(mut self, style: CellStyle) -> Self {
        self.style = style;
        if matches!(style, CellStyle::Number) {
            self.align = Align::End;
        }
        self
    }

    #[must_use]
    pub fn aligned(mut self, align: Align) -> Self {
        self.align = align;
        self
    }
}

/// A rendered table. Rows shorter than the column list are padded with blanks.
#[derive(Clone, Debug, Default)]
pub struct Table {
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<String>>,
    /// Alternating row tint; off for very short tables reads cleaner.
    pub zebra: bool,
    /// Optional note printed under the table (for example a truncation notice).
    pub note: Option<String>,
}

impl Table {
    #[must_use]
    pub fn new(columns: Vec<Column>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            zebra: true,
            note: None,
        }
    }

    #[must_use]
    pub fn with_rows(mut self, rows: Vec<Vec<String>>) -> Self {
        self.rows = rows;
        self
    }

    #[must_use]
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Absolute column widths for a table occupying `total_w` points.
    fn widths(&self, total_w: f64) -> Vec<f64> {
        let sum: f64 = self.columns.iter().map(|c| c.weight).sum();
        if sum <= 0.0 {
            let even = total_w / self.columns.len().max(1) as f64;
            return vec![even; self.columns.len()];
        }
        self.columns
            .iter()
            .map(|c| total_w * c.weight / sum)
            .collect()
    }
}

const CELL_PAD_X: f64 = 6.0;
const CELL_PAD_Y: f64 = 5.0;
const HEADER_H: f64 = 20.0;
const BODY_SIZE: f64 = 8.5;
const HEADER_SIZE: f64 = 8.0;
const LEADING: f64 = 11.0;

fn cell_font(style: CellStyle) -> FontStyle {
    match style {
        CellStyle::Mono => FontStyle::Mono,
        CellStyle::Strong => FontStyle::SansBold,
        _ => FontStyle::Sans,
    }
}

fn cell_color(style: CellStyle) -> Rgb {
    match style {
        CellStyle::Muted => theme::MUTED,
        CellStyle::Strong => theme::INK,
        _ => theme::BODY,
    }
}

/// Draw the header band and return the y of its bottom edge.
fn draw_header(canvas: &mut Canvas, x: f64, widths: &[f64], columns: &[Column]) -> f64 {
    let total: f64 = widths.iter().sum();
    let top = canvas.y;
    canvas.fill_rect(x, top - HEADER_H, total, HEADER_H, theme::BRAND_DEEP);
    let baseline = top - HEADER_H + (HEADER_H - HEADER_SIZE) / 2.0 + HEADER_SIZE * 0.15;
    for (i, col) in columns.iter().enumerate() {
        let cx = column_x(canvas, x, widths, i);
        let inner = widths[i] - CELL_PAD_X * 2.0;
        let label = canvas.ellipsize(&col.title, FontStyle::SansBold, HEADER_SIZE, inner);
        canvas.text_in(
            cx + CELL_PAD_X,
            inner,
            baseline,
            HEADER_SIZE,
            FontStyle::SansBold,
            theme::PAPER,
            col.align,
            &label,
        );
    }
    canvas.y = top - HEADER_H;
    canvas.y
}

/// Left edge of column `i`. In a right-to-left document the columns are laid out mirrored so
/// the primary column stays on the reading edge.
fn column_x(canvas: &Canvas, x: f64, widths: &[f64], i: usize) -> f64 {
    if canvas.is_rtl() {
        let total: f64 = widths.iter().sum();
        let after: f64 = widths.iter().take(i + 1).sum();
        x + total - after
    } else {
        x + widths.iter().take(i).sum::<f64>()
    }
}

/// Render `table` starting at the canvas cursor, breaking across pages as needed.
pub fn draw_table(canvas: &mut Canvas, x: f64, total_w: f64, table: &Table) {
    if table.columns.is_empty() {
        return;
    }
    let widths = table.widths(total_w);
    // A header alone at the bottom of a page reads as an error; keep it with a first row.
    canvas.ensure(HEADER_H + 24.0);
    draw_header(canvas, x, &widths, &table.columns);

    let max_number: f64 = table
        .rows
        .iter()
        .flat_map(|r| {
            table
                .columns
                .iter()
                .enumerate()
                .filter(|(_, c)| c.style == CellStyle::Number)
                .filter_map(move |(i, _)| r.get(i))
                .filter_map(|v| v.replace(['%', ',', ' '], "").parse::<f64>().ok())
        })
        .fold(0.0_f64, f64::max);

    for (row_index, row) in table.rows.iter().enumerate() {
        // Pre-wrap so the row height is known before deciding on a page break.
        let wrapped: Vec<Vec<String>> = table
            .columns
            .iter()
            .enumerate()
            .map(|(i, col)| {
                let value = row.get(i).map(String::as_str).unwrap_or("");
                let inner = widths[i] - CELL_PAD_X * 2.0;
                match col.style {
                    CellStyle::Severity => vec![value.trim().to_uppercase()],
                    _ => {
                        let lines = canvas.wrap(value, cell_font(col.style), BODY_SIZE, inner);
                        // Cap runaway descriptions so one row cannot swallow a page.
                        if lines.len() > 6 {
                            let mut cut: Vec<String> = lines.into_iter().take(6).collect();
                            if let Some(last) = cut.last_mut() {
                                last.push('…');
                            }
                            cut
                        } else {
                            lines
                        }
                    }
                }
            })
            .collect();
        let line_count = wrapped.iter().map(Vec::len).max().unwrap_or(1).max(1);
        let row_h = line_count as f64 * LEADING + CELL_PAD_Y * 2.0;

        if canvas.ensure(row_h) {
            draw_header(canvas, x, &widths, &table.columns);
        }

        let top = canvas.y;
        if table.zebra && row_index % 2 == 1 {
            canvas.fill_rect(x, top - row_h, total_w, row_h, theme::LINE_SOFT);
        }

        for (i, col) in table.columns.iter().enumerate() {
            let cx = column_x(canvas, x, &widths, i);
            let inner = widths[i] - CELL_PAD_X * 2.0;
            let lines = &wrapped[i];
            if col.style == CellStyle::Severity {
                let label = lines.first().cloned().unwrap_or_default();
                if !label.is_empty() {
                    let chip_h = 12.0;
                    canvas.chip(
                        cx + CELL_PAD_X,
                        top - CELL_PAD_Y - chip_h,
                        chip_h,
                        &label,
                        theme::severity_color(&label),
                    );
                }
                continue;
            }
            let color = if col.style == CellStyle::Number {
                let v = lines
                    .first()
                    .and_then(|s| s.replace(['%', ',', ' '], "").parse::<f64>().ok())
                    .unwrap_or(0.0);
                if max_number > 0.0 && v >= max_number * 0.75 {
                    theme::SEV_HIGH
                } else {
                    theme::BODY
                }
            } else {
                cell_color(col.style)
            };
            for (n, line) in lines.iter().enumerate() {
                let baseline = top - CELL_PAD_Y - BODY_SIZE - n as f64 * LEADING;
                canvas.text_in(
                    cx + CELL_PAD_X,
                    inner,
                    baseline,
                    BODY_SIZE,
                    cell_font(col.style),
                    color,
                    col.align,
                    line,
                );
            }
        }
        canvas.line(x, top - row_h, x + total_w, top - row_h, theme::LINE, 0.4);
        canvas.y = top - row_h;
    }

    if let Some(note) = &table.note {
        canvas.y -= 4.0;
        canvas.line_at_cursor(
            x,
            total_w,
            7.5,
            11.0,
            FontStyle::Sans,
            theme::FAINT,
            Align::Start,
            note,
        );
    }
    canvas.y -= 6.0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::canvas::CONTENT_TOP;

    fn sample_table(rows: usize) -> Table {
        let cols = vec![
            Column::new("ID", 1.0).styled(CellStyle::Mono),
            Column::new("Finding", 4.0).styled(CellStyle::Strong),
            Column::new("Severity", 1.2).styled(CellStyle::Severity),
            Column::new("Count", 1.0).styled(CellStyle::Number),
        ];
        let data = (0..rows)
            .map(|i| {
                vec![
                    format!("VLN-{i}"),
                    format!("Finding number {i} with a reasonably descriptive title"),
                    if i % 2 == 0 { "critical" } else { "low" }.to_string(),
                    (i * 3).to_string(),
                ]
            })
            .collect();
        Table::new(cols).with_rows(data)
    }

    #[test]
    fn widths_are_proportional_to_weights_and_sum_to_the_table_width() {
        let t = sample_table(1);
        let w = t.widths(720.0);
        assert_eq!(w.len(), 4);
        assert!((w.iter().sum::<f64>() - 720.0).abs() < 1e-6);
        assert!(w[1] > w[0], "the 4x column must be widest");
    }

    #[test]
    fn zero_weight_columns_fall_back_to_an_even_split() {
        let t = Table::new(vec![
            Column {
                title: "a".into(),
                weight: 0.0,
                align: Align::Start,
                style: CellStyle::Text,
            },
            Column {
                title: "b".into(),
                weight: 0.0,
                align: Align::Start,
                style: CellStyle::Text,
            },
        ]);
        // Column::new clamps, but a directly constructed column can still be zero.
        let w = t.widths(100.0);
        assert!((w[0] - w[1]).abs() < 1e-9);
    }

    #[test]
    fn number_columns_default_to_end_alignment() {
        let c = Column::new("Count", 1.0).styled(CellStyle::Number);
        assert_eq!(c.align, Align::End);
    }

    #[test]
    fn empty_table_draws_nothing() {
        let mut c = Canvas::new(false);
        draw_table(&mut c, 50.0, 495.0, &Table::default());
        assert!(c.finish()[0].is_empty());
    }

    #[test]
    fn header_band_is_painted_and_advances_the_cursor() {
        let mut c = Canvas::new(false);
        let before = c.y;
        draw_table(&mut c, 50.0, 495.0, &sample_table(1));
        assert!(c.y < before - HEADER_H);
        let page = &c.finish()[0];
        assert!(page.contains(" re f"), "header band fill expected");
    }

    #[test]
    fn long_tables_paginate_and_repeat_the_header() {
        let mut c = Canvas::new(false);
        draw_table(&mut c, 50.0, 495.0, &sample_table(120));
        let pages = c.finish();
        assert!(pages.len() > 1, "120 rows must span multiple pages");
        // Every page carries a header band drawn in the deep brand colour.
        let brand = format!(
            "{:.4} {:.4} {:.4} rg",
            theme::BRAND_DEEP.0,
            theme::BRAND_DEEP.1,
            theme::BRAND_DEEP.2
        );
        for (i, p) in pages.iter().enumerate() {
            assert!(
                p.contains(&brand),
                "page {i} is missing the repeated header"
            );
        }
    }

    #[test]
    fn rows_never_overflow_the_bottom_margin() {
        let mut c = Canvas::new(false);
        draw_table(&mut c, 50.0, 495.0, &sample_table(60));
        assert!(c.y >= 0.0, "cursor ran off the page: {}", c.y);
    }

    #[test]
    fn note_is_rendered_under_the_table() {
        let mut c = Canvas::new(false);
        let t = sample_table(2).note("Showing 2 of 900 findings");
        let before = c.y;
        draw_table(&mut c, 50.0, 495.0, &t);
        assert!(c.y < before);
        assert!(!c.used_sans.is_empty());
    }

    #[test]
    fn short_rows_are_padded_rather_than_panicking() {
        let mut c = Canvas::new(false);
        let t = Table::new(vec![Column::new("A", 1.0), Column::new("B", 1.0)])
            .with_rows(vec![vec!["only-one".to_string()]]);
        draw_table(&mut c, 50.0, 495.0, &t);
        assert!(!c.finish()[0].is_empty());
    }

    #[test]
    fn rtl_documents_mirror_the_column_order() {
        let widths = [100.0, 200.0, 100.0];
        let ltr = Canvas::new(false);
        let rtl = Canvas::new(true);
        assert_eq!(column_x(&ltr, 50.0, &widths, 0), 50.0);
        // In RTL the first column sits at the right-hand end of the table.
        assert_eq!(column_x(&rtl, 50.0, &widths, 0), 50.0 + 400.0 - 100.0);
        assert_eq!(column_x(&rtl, 50.0, &widths, 2), 50.0);
    }

    #[test]
    fn oversized_cell_text_is_capped_at_six_lines() {
        let mut c = Canvas::new(false);
        let long = "word ".repeat(400);
        let t = Table::new(vec![Column::new("Detail", 1.0)]).with_rows(vec![vec![long]]);
        let before = c.y;
        draw_table(&mut c, 50.0, 495.0, &t);
        // Six lines plus padding, well under a full page.
        assert!(before - c.y < CONTENT_TOP / 2.0);
    }
}
