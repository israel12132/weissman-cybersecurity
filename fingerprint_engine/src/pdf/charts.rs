//! Vector charts drawn directly into the content stream — no raster images, so output stays
//! small, sharp at any zoom, and reproducible byte-for-byte.

use super::canvas::{Align, Canvas, FontStyle};
use super::theme::{self, Rgb};

/// One labelled datum.
#[derive(Clone, Debug)]
pub struct Slice {
    pub label: String,
    pub value: f64,
    pub color: Rgb,
}

impl Slice {
    #[must_use]
    pub fn new(label: impl Into<String>, value: f64, color: Rgb) -> Self {
        Self {
            label: label.into(),
            value: value.max(0.0),
            color,
        }
    }
}

/// The chart shapes a report can embed.
#[derive(Clone, Debug)]
pub enum Chart {
    /// Posture score 0–100 as a semicircular gauge with a banded track.
    Gauge { score: i32, caption: String },
    /// Severity mix as a donut with a legend.
    Donut { slices: Vec<Slice>, caption: String },
    /// Horizontal ranked bars — the most readable form for named categories.
    Bars { slices: Vec<Slice>, caption: String },
    /// Vertical columns over time.
    Columns { slices: Vec<Slice>, caption: String },
    /// 5x5 likelihood/impact risk matrix; `cells[impact][likelihood]`.
    RiskMatrix {
        cells: [[u32; 5]; 5],
        caption: String,
    },
}

impl Chart {
    /// Height this chart will occupy, so the flow layout can page-break before drawing.
    #[must_use]
    pub fn height(&self) -> f64 {
        match self {
            Chart::Gauge { .. } => 132.0,
            Chart::Donut { slices, .. } => 150.0_f64.max(40.0 + slices.len() as f64 * 14.0),
            Chart::Bars { slices, .. } => 34.0 + slices.len() as f64 * 18.0,
            Chart::Columns { .. } => 150.0,
            Chart::RiskMatrix { .. } => 190.0,
        }
    }

    fn caption(&self) -> &str {
        match self {
            Chart::Gauge { caption, .. }
            | Chart::Donut { caption, .. }
            | Chart::Bars { caption, .. }
            | Chart::Columns { caption, .. }
            | Chart::RiskMatrix { caption, .. } => caption,
        }
    }
}

/// Render `chart` at the canvas cursor across `w` points, advancing the cursor.
pub fn draw(canvas: &mut Canvas, x: f64, w: f64, chart: &Chart) {
    let h = chart.height();
    canvas.ensure(h + 6.0);
    let top = canvas.y;
    match chart {
        Chart::Gauge { score, .. } => gauge(canvas, x, top, w, *score),
        Chart::Donut { slices, .. } => donut(canvas, x, top, w, slices),
        Chart::Bars { slices, .. } => bars(canvas, x, top, w, slices),
        Chart::Columns { slices, .. } => columns(canvas, x, top, w, slices),
        Chart::RiskMatrix { cells, .. } => risk_matrix(canvas, x, top, w, cells),
    }
    canvas.y = top - h;
    let caption = chart.caption();
    if !caption.is_empty() {
        canvas.line_at_cursor(
            x,
            w,
            7.5,
            12.0,
            FontStyle::Sans,
            theme::FAINT,
            Align::Center,
            caption,
        );
    }
    canvas.y -= 4.0;
}

/// Colour for a posture score: red below 40, amber to 70, green above.
#[must_use]
pub fn score_color(score: i32) -> Rgb {
    if score < 40 {
        theme::SEV_CRITICAL
    } else if score < 70 {
        theme::AMBER
    } else {
        theme::OK
    }
}

fn gauge(canvas: &mut Canvas, x: f64, top: f64, w: f64, score: i32) {
    let score = score.clamp(0, 100);
    let cx = x + w / 2.0;
    let r = 54.0;
    let cy = top - r - 24.0;

    // Track, then a coloured sweep proportional to the score.
    canvas.donut_segment(cx, cy, r, r - 13.0, 180.0, 360.0, theme::LINE);
    let sweep = 180.0 * f64::from(score) / 100.0;
    if sweep > 0.2 {
        canvas.donut_segment(
            cx,
            cy,
            r,
            r - 13.0,
            180.0,
            180.0 + sweep,
            score_color(score),
        );
    }
    // Tick marks at each quartile keep the reading honest.
    for q in 0..=4 {
        let angle = (180.0 + 45.0 * f64::from(q)) * std::f64::consts::PI / 180.0;
        canvas.line(
            cx + (r + 2.0) * angle.cos(),
            cy + (r + 2.0) * angle.sin(),
            cx + (r + 6.0) * angle.cos(),
            cy + (r + 6.0) * angle.sin(),
            theme::FAINT,
            0.6,
        );
    }
    let value = score.to_string();
    let size = 30.0;
    let tw = canvas.measure(&value, FontStyle::SansBold, size);
    canvas.text(
        cx - tw / 2.0,
        cy + 6.0,
        size,
        FontStyle::SansBold,
        theme::INK,
        &value,
    );
    let sub = "/ 100";
    let sw = canvas.measure(sub, FontStyle::Sans, 9.0);
    canvas.text(
        cx - sw / 2.0,
        cy - 8.0,
        9.0,
        FontStyle::Sans,
        theme::MUTED,
        sub,
    );
}

fn donut(canvas: &mut Canvas, x: f64, top: f64, w: f64, slices: &[Slice]) {
    let total: f64 = slices.iter().map(|s| s.value).sum();
    let r = 52.0;
    let cx = x + r + 16.0;
    let cy = top - r - 12.0;

    if total <= 0.0 {
        canvas.donut_segment(cx, cy, r, r - 20.0, 0.0, 360.0, theme::LINE);
    } else {
        let mut angle = 90.0;
        for s in slices.iter().filter(|s| s.value > 0.0) {
            let sweep = 360.0 * s.value / total;
            canvas.donut_segment(cx, cy, r, r - 20.0, angle, angle + sweep, s.color);
            angle += sweep;
        }
    }
    let center = format!("{}", total.round() as i64);
    let cw = canvas.measure(&center, FontStyle::SansBold, 20.0);
    canvas.text(
        cx - cw / 2.0,
        cy - 4.0,
        20.0,
        FontStyle::SansBold,
        theme::INK,
        &center,
    );

    // Legend, one row per slice with its share.
    let lx = cx + r + 24.0;
    let lw = (x + w - lx).max(60.0);
    let mut ly = top - 16.0;
    for s in slices {
        canvas.round_rect(lx, ly - 7.0, 8.0, 8.0, 2.0, s.color);
        let pct = if total > 0.0 {
            s.value / total * 100.0
        } else {
            0.0
        };
        let label = format!("{}  —  {}  ({:.0}%)", s.label, s.value.round() as i64, pct);
        let label = canvas.ellipsize(&label, FontStyle::Sans, 8.5, lw - 14.0);
        canvas.text(
            lx + 13.0,
            ly - 6.0,
            8.5,
            FontStyle::Sans,
            theme::BODY,
            &label,
        );
        ly -= 14.0;
    }
}

fn bars(canvas: &mut Canvas, x: f64, top: f64, w: f64, slices: &[Slice]) {
    let max = slices.iter().map(|s| s.value).fold(0.0_f64, f64::max);
    let label_w = (w * 0.32).min(190.0);
    let value_w = 46.0;
    let track_w = (w - label_w - value_w - 12.0).max(40.0);
    let mut y = top - 14.0;
    for s in slices {
        let label = canvas.ellipsize(&s.label, FontStyle::Sans, 8.5, label_w - 6.0);
        canvas.text_in(
            x,
            label_w - 6.0,
            y - 8.0,
            8.5,
            FontStyle::Sans,
            theme::BODY,
            Align::Start,
            &label,
        );
        canvas.round_rect(x + label_w, y - 10.0, track_w, 10.0, 2.0, theme::LINE_SOFT);
        if max > 0.0 && s.value > 0.0 {
            let bw = (track_w * s.value / max).max(2.0);
            canvas.round_rect(x + label_w, y - 10.0, bw, 10.0, 2.0, s.color);
        }
        canvas.text_in(
            x + label_w + track_w + 6.0,
            value_w,
            y - 8.0,
            8.5,
            FontStyle::SansBold,
            theme::INK,
            Align::End,
            &format_value(s.value),
        );
        y -= 18.0;
    }
}

fn columns(canvas: &mut Canvas, x: f64, top: f64, w: f64, slices: &[Slice]) {
    let max = slices.iter().map(|s| s.value).fold(0.0_f64, f64::max);
    let plot_h = 96.0;
    let base_y = top - plot_h - 18.0;
    // Baseline plus two gridlines give the eye a scale without clutter.
    for step in 0..=2 {
        let gy = base_y + plot_h * f64::from(step) / 2.0;
        canvas.line(x, gy, x + w, gy, theme::LINE, 0.4);
    }
    let n = slices.len().max(1);
    let slot = w / n as f64;
    let bar_w = (slot * 0.55).min(34.0);
    for (i, s) in slices.iter().enumerate() {
        let cx = x + slot * (i as f64 + 0.5);
        let h = if max > 0.0 {
            (plot_h * s.value / max).max(1.5)
        } else {
            1.5
        };
        canvas.round_rect(cx - bar_w / 2.0, base_y, bar_w, h, 2.0, s.color);
        canvas.text_in(
            cx - slot / 2.0,
            slot,
            base_y + h + 4.0,
            7.5,
            FontStyle::SansBold,
            theme::INK,
            Align::Center,
            &format_value(s.value),
        );
        let label = canvas.ellipsize(&s.label, FontStyle::Sans, 7.5, slot - 4.0);
        canvas.text_in(
            cx - slot / 2.0,
            slot,
            base_y - 11.0,
            7.5,
            FontStyle::Sans,
            theme::MUTED,
            Align::Center,
            &label,
        );
    }
}

fn risk_matrix(canvas: &mut Canvas, x: f64, top: f64, w: f64, cells: &[[u32; 5]; 5]) {
    let axis_pad = 62.0;
    let grid_w = (w - axis_pad).min(300.0);
    let cell = grid_w / 5.0;
    let grid_x = x + axis_pad;
    let grid_top = top - 14.0;
    let max = cells.iter().flatten().copied().max().unwrap_or(0);

    let impact_labels = ["Severe", "Major", "Moderate", "Minor", "Low"];
    let likelihood_labels = ["Rare", "Unlikely", "Possible", "Likely", "Certain"];

    for (row, impacts) in cells.iter().enumerate() {
        let cy = grid_top - (row as f64 + 1.0) * cell;
        canvas.text_in(
            x,
            axis_pad - 8.0,
            cy + cell / 2.0 - 3.0,
            7.0,
            FontStyle::Sans,
            theme::MUTED,
            Align::End,
            impact_labels[row],
        );
        for (col, &count) in impacts.iter().enumerate() {
            let cx = grid_x + col as f64 * cell;
            // Base tint encodes inherent risk position; saturation encodes population.
            let inherent = (row as f64 * 0.5 + col as f64 * 0.5) / 4.0;
            let base = if inherent > 0.72 {
                theme::SEV_CRITICAL
            } else if inherent > 0.5 {
                theme::SEV_HIGH
            } else if inherent > 0.28 {
                theme::SEV_MEDIUM
            } else {
                theme::SEV_LOW
            };
            let strength = if max > 0 {
                f64::from(count) / f64::from(max)
            } else {
                0.0
            };
            canvas.fill_rect(
                cx,
                cy,
                cell - 1.5,
                cell - 1.5,
                base.tint(0.88 - strength * 0.75),
            );
            if count > 0 {
                let fill = base.tint(0.88 - strength * 0.75);
                canvas.text_in(
                    cx,
                    cell - 1.5,
                    cy + cell / 2.0 - 4.0,
                    8.5,
                    FontStyle::SansBold,
                    fill.on_color(),
                    Align::Center,
                    &count.to_string(),
                );
            }
        }
    }
    for (col, label) in likelihood_labels.iter().enumerate() {
        canvas.text_in(
            grid_x + col as f64 * cell,
            cell - 1.5,
            grid_top - 5.0 * cell - 11.0,
            7.0,
            FontStyle::Sans,
            theme::MUTED,
            Align::Center,
            label,
        );
    }
    canvas.text_in(
        grid_x,
        grid_w,
        grid_top + 3.0,
        7.5,
        FontStyle::SansBold,
        theme::INK_SOFT,
        Align::Start,
        "Impact (rows) x Likelihood (columns)",
    );
}

/// Compact numeric label: integers stay exact, large values get a thousands suffix.
fn format_value(v: f64) -> String {
    if v >= 1_000_000.0 {
        format!("{:.1}M", v / 1_000_000.0)
    } else if v >= 10_000.0 {
        format!("{:.1}k", v / 1_000.0)
    } else if (v - v.round()).abs() < 0.05 {
        format!("{}", v.round() as i64)
    } else {
        format!("{v:.1}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slices() -> Vec<Slice> {
        vec![
            Slice::new("Critical", 4.0, theme::SEV_CRITICAL),
            Slice::new("High", 11.0, theme::SEV_HIGH),
            Slice::new("Medium", 23.0, theme::SEV_MEDIUM),
            Slice::new("Low", 8.0, theme::SEV_LOW),
        ]
    }

    #[test]
    fn score_color_bands_are_ordered() {
        assert_eq!(score_color(10), theme::SEV_CRITICAL);
        assert_eq!(score_color(39), theme::SEV_CRITICAL);
        assert_eq!(score_color(40), theme::AMBER);
        assert_eq!(score_color(69), theme::AMBER);
        assert_eq!(score_color(70), theme::OK);
    }

    #[test]
    fn negative_values_are_clamped_at_construction() {
        assert_eq!(Slice::new("x", -5.0, theme::BRAND).value, 0.0);
    }

    #[test]
    fn every_chart_reports_a_positive_height() {
        let charts = [
            Chart::Gauge {
                score: 72,
                caption: String::new(),
            },
            Chart::Donut {
                slices: slices(),
                caption: String::new(),
            },
            Chart::Bars {
                slices: slices(),
                caption: String::new(),
            },
            Chart::Columns {
                slices: slices(),
                caption: String::new(),
            },
            Chart::RiskMatrix {
                cells: [[0; 5]; 5],
                caption: String::new(),
            },
        ];
        for c in &charts {
            assert!(c.height() > 20.0, "implausible height for {c:?}");
        }
    }

    #[test]
    fn drawing_advances_the_cursor_by_at_least_the_reported_height() {
        for chart in [
            Chart::Gauge {
                score: 72,
                caption: "Posture".into(),
            },
            Chart::Donut {
                slices: slices(),
                caption: "Severity".into(),
            },
            Chart::Bars {
                slices: slices(),
                caption: "Top engines".into(),
            },
            Chart::Columns {
                slices: slices(),
                caption: "Trend".into(),
            },
            Chart::RiskMatrix {
                cells: [[1; 5]; 5],
                caption: "Risk".into(),
            },
        ] {
            let mut c = Canvas::new(false);
            let before = c.y;
            let h = chart.height();
            draw(&mut c, 50.0, 495.0, &chart);
            assert!(before - c.y >= h, "cursor did not clear {chart:?}");
            assert!(!c.finish()[0].is_empty());
        }
    }

    #[test]
    fn gauge_clamps_out_of_range_scores() {
        for score in [-40, 0, 50, 100, 400] {
            let mut c = Canvas::new(false);
            draw(
                &mut c,
                50.0,
                495.0,
                &Chart::Gauge {
                    score,
                    caption: String::new(),
                },
            );
            assert!(!c.finish()[0].is_empty());
        }
    }

    #[test]
    fn donut_with_no_data_draws_an_empty_track() {
        let mut c = Canvas::new(false);
        let empty = vec![Slice::new("None", 0.0, theme::LINE)];
        draw(
            &mut c,
            50.0,
            495.0,
            &Chart::Donut {
                slices: empty,
                caption: String::new(),
            },
        );
        assert!(c.finish()[0].contains("h f"));
    }

    #[test]
    fn charts_with_no_slices_do_not_panic() {
        for chart in [
            Chart::Donut {
                slices: vec![],
                caption: String::new(),
            },
            Chart::Bars {
                slices: vec![],
                caption: String::new(),
            },
            Chart::Columns {
                slices: vec![],
                caption: String::new(),
            },
        ] {
            let mut c = Canvas::new(false);
            draw(&mut c, 50.0, 495.0, &chart);
        }
    }

    #[test]
    fn risk_matrix_renders_counts_for_populated_cells() {
        let mut cells = [[0u32; 5]; 5];
        cells[0][4] = 7;
        let mut c = Canvas::new(false);
        draw(
            &mut c,
            50.0,
            495.0,
            &Chart::RiskMatrix {
                cells,
                caption: String::new(),
            },
        );
        assert!(!c.used_sans.is_empty(), "cell counts must be typeset");
    }

    #[test]
    fn value_labels_are_compact() {
        assert_eq!(format_value(0.0), "0");
        assert_eq!(format_value(42.0), "42");
        assert_eq!(format_value(42.42), "42.4");
        assert_eq!(format_value(12_000.0), "12.0k");
        assert_eq!(format_value(3_400_000.0), "3.4M");
    }
}
