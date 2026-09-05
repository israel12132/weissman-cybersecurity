//! Low-level content-stream painter: pages, text, vector primitives.
//!
//! Everything above this module (tables, charts, page chrome, the document flow) works in
//! terms of these primitives, so page geometry, bidi handling and glyph accounting are
//! decided exactly once.

use super::bidi::{self, Dir};
use super::fonts::{mono_font, sans_font};
use super::theme::Rgb;
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// A4 portrait, matching `--page-w: 210mm` in the briefing stylesheet.
pub const PAGE_W: f64 = 595.28;
pub const PAGE_H: f64 = 841.89;
pub const MARGIN_X: f64 = 50.0;
/// Band reserved at the top of every body page for the running header.
pub const HEADER_H: f64 = 52.0;
/// Band reserved at the bottom for the footer rule, page number and classification.
pub const FOOTER_H: f64 = 46.0;
pub const CONTENT_W: f64 = PAGE_W - 2.0 * MARGIN_X;
pub const CONTENT_TOP: f64 = PAGE_H - HEADER_H;
pub const CONTENT_BOTTOM: f64 = FOOTER_H;

/// Which embedded face to set text in. Bold weights are synthesised by stroking the fill.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FontStyle {
    Sans,
    SansBold,
    Mono,
    MonoBold,
}

impl FontStyle {
    fn is_mono(self) -> bool {
        matches!(self, FontStyle::Mono | FontStyle::MonoBold)
    }

    fn is_bold(self) -> bool {
        matches!(self, FontStyle::SansBold | FontStyle::MonoBold)
    }

    fn resource(self) -> &'static str {
        if self.is_mono() {
            "F2"
        } else {
            "F1"
        }
    }
}

/// Horizontal placement inside a box. `Start`/`End` follow the document direction, so a
/// Hebrew report right-aligns its labels without every call site knowing about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Align {
    Start,
    Center,
    End,
}

/// Collects per-page content streams and the glyphs the document has used.
pub struct Canvas {
    pages: Vec<String>,
    cur: String,
    /// Current baseline cursor, in PDF user space (origin bottom-left).
    pub y: f64,
    rtl: bool,
    pub used_sans: BTreeSet<u16>,
    pub used_mono: BTreeSet<u16>,
}

impl Canvas {
    #[must_use]
    pub fn new(rtl: bool) -> Self {
        Self {
            pages: Vec::new(),
            cur: String::new(),
            y: CONTENT_TOP,
            rtl,
            used_sans: BTreeSet::new(),
            used_mono: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn is_rtl(&self) -> bool {
        self.rtl
    }

    fn base_dir(&self) -> Dir {
        if self.rtl {
            Dir::Rtl
        } else {
            Dir::Ltr
        }
    }

    /// Zero-based index of the page currently being painted.
    #[must_use]
    pub fn page_index(&self) -> usize {
        self.pages.len()
    }

    /// Start a new page. A leading call on an untouched canvas is a no-op so documents never
    /// open with a blank sheet.
    pub fn new_page(&mut self) {
        if self.cur.is_empty() && self.pages.is_empty() {
            self.y = CONTENT_TOP;
            return;
        }
        self.pages.push(std::mem::take(&mut self.cur));
        self.y = CONTENT_TOP;
    }

    /// Break to a new page when `need` points would overflow the content area.
    /// Returns `true` when a break happened.
    pub fn ensure(&mut self, need: f64) -> bool {
        if self.y - need < CONTENT_BOTTOM {
            self.new_page();
            true
        } else {
            false
        }
    }

    /// Remaining vertical space on the current page.
    #[must_use]
    pub fn space_left(&self) -> f64 {
        (self.y - CONTENT_BOTTOM).max(0.0)
    }

    /// Finish painting and return one content stream per page.
    #[must_use]
    pub fn finish(mut self) -> Vec<String> {
        if !self.cur.is_empty() {
            self.pages.push(std::mem::take(&mut self.cur));
        }
        if self.pages.is_empty() {
            self.pages.push(String::new());
        }
        self.pages
    }

    /// Raw operator escape hatch for callers that need an op this module does not model.
    pub fn raw(&mut self, ops: &str) {
        self.cur.push_str(ops);
    }

    // ---- measurement -------------------------------------------------------------------

    /// Width of `text` at `size` points in `style`.
    #[must_use]
    pub fn measure(&self, text: &str, style: FontStyle, size: f64) -> f64 {
        let font = if style.is_mono() {
            mono_font()
        } else {
            sans_font()
        };
        font.text_width(text, size)
    }

    /// Greedy word wrap to `max_w`, hard-splitting tokens that cannot fit on their own line.
    #[must_use]
    pub fn wrap(&self, text: &str, style: FontStyle, size: f64, max_w: f64) -> Vec<String> {
        let mut lines = Vec::new();
        if max_w <= 0.0 {
            return lines;
        }
        for raw_line in text.split('\n') {
            let mut current = String::new();
            for word in raw_line.split_whitespace() {
                let candidate = if current.is_empty() {
                    word.to_string()
                } else {
                    format!("{current} {word}")
                };
                if self.measure(&candidate, style, size) <= max_w {
                    current = candidate;
                    continue;
                }
                if !current.is_empty() {
                    lines.push(std::mem::take(&mut current));
                }
                // A single token longer than the column is split on character boundaries.
                if self.measure(word, style, size) > max_w {
                    let mut chunk = String::new();
                    for ch in word.chars() {
                        let mut probe = chunk.clone();
                        probe.push(ch);
                        if self.measure(&probe, style, size) > max_w && !chunk.is_empty() {
                            lines.push(std::mem::take(&mut chunk));
                        }
                        chunk.push(ch);
                    }
                    current = chunk;
                } else {
                    current = word.to_string();
                }
            }
            lines.push(current);
        }
        // A trailing empty line only appears for input ending in a newline; drop it.
        while lines.len() > 1 && lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
        lines
    }

    /// Truncate to `max_w`, appending an ellipsis when the text does not fit.
    #[must_use]
    pub fn ellipsize(&self, text: &str, style: FontStyle, size: f64, max_w: f64) -> String {
        if self.measure(text, style, size) <= max_w {
            return text.to_string();
        }
        let ellipsis = "…";
        let budget = max_w - self.measure(ellipsis, style, size);
        if budget <= 0.0 {
            return String::new();
        }
        let mut out = String::new();
        for ch in text.chars() {
            let mut probe = out.clone();
            probe.push(ch);
            if self.measure(&probe, style, size) > budget {
                break;
            }
            out = probe;
        }
        out.push_str(ellipsis);
        out
    }

    // ---- text --------------------------------------------------------------------------

    /// Paint `text` with its left edge at `x` and baseline at `y`.
    pub fn text(&mut self, x: f64, y: f64, size: f64, style: FontStyle, color: Rgb, text: &str) {
        if text.is_empty() {
            return;
        }
        let visual = bidi::to_visual(text, self.base_dir());
        let hex = if style.is_mono() {
            mono_font().encode(&visual, &mut self.used_mono)
        } else {
            sans_font().encode(&visual, &mut self.used_sans)
        };
        let _ = write!(
            self.cur,
            "q\n{:.4} {:.4} {:.4} rg\n",
            color.0, color.1, color.2
        );
        if style.is_bold() {
            // Text render mode 2 fills then strokes the outline: a faithful synthetic bold
            // for faces that ship a single weight.
            let _ = write!(
                self.cur,
                "{:.4} {:.4} {:.4} RG\n{:.3} w\n2 Tr\n",
                color.0,
                color.1,
                color.2,
                size * 0.035
            );
        }
        let _ = write!(
            self.cur,
            "BT\n/{} {:.2} Tf\n1 0 0 1 {:.2} {:.2} Tm\n{} Tj\nET\nQ\n",
            style.resource(),
            size,
            x,
            y,
            hex
        );
    }

    /// Paint `text` aligned inside the box `[x, x + w]`.
    #[allow(clippy::too_many_arguments)]
    pub fn text_in(
        &mut self,
        x: f64,
        w: f64,
        y: f64,
        size: f64,
        style: FontStyle,
        color: Rgb,
        align: Align,
        text: &str,
    ) {
        let tw = self.measure(text, style, size);
        let resolved = match (align, self.rtl) {
            (Align::Start, false) | (Align::End, true) => 0.0,
            (Align::Start, true) | (Align::End, false) => w - tw,
            (Align::Center, _) => (w - tw) / 2.0,
        };
        self.text(x + resolved.max(0.0), y, size, style, color, text);
    }

    /// Paint one line at the cursor and advance it by `leading`.
    #[allow(clippy::too_many_arguments)]
    pub fn line_at_cursor(
        &mut self,
        x: f64,
        w: f64,
        size: f64,
        leading: f64,
        style: FontStyle,
        color: Rgb,
        align: Align,
        text: &str,
    ) {
        self.ensure(leading);
        let baseline = self.y - size;
        self.text_in(x, w, baseline, size, style, color, align, text);
        self.y -= leading;
    }

    // ---- vector primitives --------------------------------------------------------------

    pub fn fill_rect(&mut self, x: f64, y: f64, w: f64, h: f64, color: Rgb) {
        let _ = write!(
            self.cur,
            "q\n{:.4} {:.4} {:.4} rg\n{:.2} {:.2} {:.2} {:.2} re f\nQ\n",
            color.0, color.1, color.2, x, y, w, h
        );
    }

    pub fn stroke_rect(&mut self, x: f64, y: f64, w: f64, h: f64, color: Rgb, width: f64) {
        let _ = write!(
            self.cur,
            "q\n{:.4} {:.4} {:.4} RG\n{:.2} w\n{:.2} {:.2} {:.2} {:.2} re S\nQ\n",
            color.0, color.1, color.2, width, x, y, w, h
        );
    }

    pub fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, color: Rgb, width: f64) {
        let _ = write!(
            self.cur,
            "q\n{:.4} {:.4} {:.4} RG\n{:.2} w\n{:.2} {:.2} m {:.2} {:.2} l S\nQ\n",
            color.0, color.1, color.2, width, x1, y1, x2, y2
        );
    }

    /// Rounded rectangle, approximating each corner with a Bezier arc.
    pub fn round_rect(&mut self, x: f64, y: f64, w: f64, h: f64, r: f64, color: Rgb) {
        let r = r.min(w / 2.0).min(h / 2.0).max(0.0);
        let k = r * 0.5523;
        let _ = write!(
            self.cur,
            "q\n{:.4} {:.4} {:.4} rg\n",
            color.0, color.1, color.2
        );
        let _ = write!(self.cur, "{:.2} {:.2} m\n", x + r, y);
        let _ = write!(self.cur, "{:.2} {:.2} l\n", x + w - r, y);
        let _ = write!(
            self.cur,
            "{:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c\n",
            x + w - r + k,
            y,
            x + w,
            y + r - k,
            x + w,
            y + r
        );
        let _ = write!(self.cur, "{:.2} {:.2} l\n", x + w, y + h - r);
        let _ = write!(
            self.cur,
            "{:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c\n",
            x + w,
            y + h - r + k,
            x + w - r + k,
            y + h,
            x + w - r,
            y + h
        );
        let _ = write!(self.cur, "{:.2} {:.2} l\n", x + r, y + h);
        let _ = write!(
            self.cur,
            "{:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c\n",
            x + r - k,
            y + h,
            x,
            y + h - r + k,
            x,
            y + h - r
        );
        let _ = write!(self.cur, "{:.2} {:.2} l\n", x, y + r);
        let _ = write!(
            self.cur,
            "{:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c\n",
            x,
            y + r - k,
            x + r - k,
            y,
            x + r,
            y
        );
        self.cur.push_str("h f\nQ\n");
    }

    /// Filled pie slice from `a1` to `a2` degrees (0 = east, counter-clockwise).
    pub fn arc_fill(&mut self, cx: f64, cy: f64, r: f64, a1: f64, a2: f64, color: Rgb) {
        let _ = write!(
            self.cur,
            "q\n{:.4} {:.4} {:.4} rg\n",
            color.0, color.1, color.2
        );
        self.arc_path(cx, cy, r, a1, a2, true);
        let _ = write!(self.cur, "{:.2} {:.2} l h f\nQ\n", cx, cy);
    }

    pub fn circle_fill(&mut self, cx: f64, cy: f64, r: f64, color: Rgb) {
        self.arc_fill(cx, cy, r, 0.0, 360.0, color);
    }

    /// Filled annulus segment — the primitive behind severity donuts.
    #[allow(clippy::too_many_arguments)]
    pub fn donut_segment(
        &mut self,
        cx: f64,
        cy: f64,
        r_outer: f64,
        r_inner: f64,
        a1: f64,
        a2: f64,
        color: Rgb,
    ) {
        if (a2 - a1).abs() < 0.01 {
            return;
        }
        let _ = write!(
            self.cur,
            "q\n{:.4} {:.4} {:.4} rg\n",
            color.0, color.1, color.2
        );
        self.arc_path(cx, cy, r_outer, a1, a2, true);
        self.arc_path(cx, cy, r_inner, a2, a1, false);
        self.cur.push_str("h f\nQ\n");
    }

    /// Emit an arc as Bezier segments. `move_first` starts a new subpath, otherwise the arc
    /// continues from the current point with a straight join.
    fn arc_path(&mut self, cx: f64, cy: f64, r: f64, a1: f64, a2: f64, move_first: bool) {
        let to_rad = std::f64::consts::PI / 180.0;
        let start = a1 * to_rad;
        let end = a2 * to_rad;
        let x0 = cx + r * start.cos();
        let y0 = cy + r * start.sin();
        if move_first {
            let _ = write!(self.cur, "{:.3} {:.3} m\n", x0, y0);
        } else {
            let _ = write!(self.cur, "{:.3} {:.3} l\n", x0, y0);
        }
        let sweep = end - start;
        let steps = (sweep.abs() / (std::f64::consts::PI / 2.0)).ceil().max(1.0) as i32;
        let step = sweep / f64::from(steps);
        // Control-point distance for a Bezier approximation of a circular arc of `step`.
        let k = 4.0 / 3.0 * (step / 4.0).tan();
        for i in 0..steps {
            let t1 = start + step * f64::from(i);
            let t2 = t1 + step;
            let _ = write!(
                self.cur,
                "{:.3} {:.3} {:.3} {:.3} {:.3} {:.3} c\n",
                cx + r * (t1.cos() - k * t1.sin()),
                cy + r * (t1.sin() + k * t1.cos()),
                cx + r * (t2.cos() + k * t2.sin()),
                cy + r * (t2.sin() - k * t2.cos()),
                cx + r * t2.cos(),
                cy + r * t2.sin()
            );
        }
    }

    /// Rounded pill with centred label — used for severity and status badges.
    pub fn chip(&mut self, x: f64, y: f64, h: f64, label: &str, bg: Rgb) -> f64 {
        let size = h * 0.55;
        let pad = h * 0.5;
        let w = self.measure(label, FontStyle::SansBold, size) + pad * 2.0;
        self.round_rect(x, y, w, h, h / 2.0, bg);
        let baseline = y + (h - size) / 2.0 + size * 0.12;
        self.text(
            x + pad,
            baseline,
            size,
            FontStyle::SansBold,
            bg.on_color(),
            label,
        );
        w
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::theme;

    #[test]
    fn new_canvas_starts_at_content_top_with_no_pages() {
        let c = Canvas::new(false);
        assert_eq!(c.y, CONTENT_TOP);
        assert_eq!(c.page_index(), 0);
    }

    #[test]
    fn leading_new_page_does_not_create_a_blank_sheet() {
        let mut c = Canvas::new(false);
        c.new_page();
        c.new_page();
        assert_eq!(c.page_index(), 0);
        c.text(50.0, 700.0, 11.0, FontStyle::Sans, theme::INK, "hello");
        c.new_page();
        assert_eq!(c.page_index(), 1);
    }

    #[test]
    fn ensure_breaks_only_when_the_content_would_overflow() {
        let mut c = Canvas::new(false);
        c.text(50.0, 700.0, 11.0, FontStyle::Sans, theme::INK, "x");
        assert!(!c.ensure(20.0));
        assert_eq!(c.page_index(), 0);
        assert!(c.ensure(PAGE_H));
        assert_eq!(c.page_index(), 1);
        assert_eq!(c.y, CONTENT_TOP);
    }

    #[test]
    fn finish_collects_the_pending_page() {
        let mut c = Canvas::new(false);
        c.text(50.0, 700.0, 11.0, FontStyle::Sans, theme::INK, "a");
        c.new_page();
        c.text(50.0, 700.0, 11.0, FontStyle::Sans, theme::INK, "b");
        let pages = c.finish();
        assert_eq!(pages.len(), 2);
        assert!(pages[0].contains("Tj"));
        assert!(pages[1].contains("Tj"));
    }

    #[test]
    fn finish_always_yields_at_least_one_page() {
        assert_eq!(Canvas::new(false).finish().len(), 1);
    }

    #[test]
    fn text_emits_identity_h_hex_and_tracks_glyphs() {
        let mut c = Canvas::new(false);
        c.text(50.0, 700.0, 11.0, FontStyle::Sans, theme::INK, "Weissman");
        assert!(!c.used_sans.is_empty());
        assert!(c.used_mono.is_empty());
        let page = &c.finish()[0];
        assert!(page.contains("/F1 11.00 Tf"));
        assert!(page.contains(" Tj"), "must show text: {page}");
        assert!(
            page.contains('<') && page.contains('>'),
            "hex string expected"
        );
        // Literal text must never reach the stream: that was the Latin-1-only failure mode.
        assert!(!page.contains("(Weissman)"));
    }

    #[test]
    fn mono_text_uses_the_second_font_resource() {
        let mut c = Canvas::new(false);
        c.text(50.0, 700.0, 9.0, FontStyle::Mono, theme::INK, "deadbeef");
        assert!(!c.used_mono.is_empty());
        assert!(c.finish()[0].contains("/F2 9.00 Tf"));
    }

    #[test]
    fn bold_style_switches_to_stroke_and_fill_render_mode() {
        let mut c = Canvas::new(false);
        c.text(50.0, 700.0, 11.0, FontStyle::SansBold, theme::INK, "Bold");
        assert!(c.finish()[0].contains("2 Tr"));
    }

    #[test]
    fn empty_text_emits_nothing() {
        let mut c = Canvas::new(false);
        c.text(50.0, 700.0, 11.0, FontStyle::Sans, theme::INK, "");
        assert!(c.finish()[0].is_empty());
    }

    #[test]
    fn hebrew_text_is_reordered_before_encoding() {
        let mut c = Canvas::new(true);
        c.text(50.0, 700.0, 11.0, FontStyle::Sans, theme::INK, "שלום");
        // Reordering happens upstream of encoding, so the glyph set is unchanged but present.
        assert_eq!(c.used_sans.len(), 4);
    }

    #[test]
    fn measure_is_monotonic_in_length_and_size() {
        let c = Canvas::new(false);
        assert!(c.measure("ab", FontStyle::Sans, 10.0) > c.measure("a", FontStyle::Sans, 10.0));
        assert!(c.measure("a", FontStyle::Sans, 20.0) > c.measure("a", FontStyle::Sans, 10.0));
    }

    #[test]
    fn wrap_respects_the_column_width() {
        let c = Canvas::new(false);
        let text = "Weissman Cybersecurity external attack surface assessment report";
        let lines = c.wrap(text, FontStyle::Sans, 10.0, 120.0);
        assert!(lines.len() > 1);
        for l in &lines {
            assert!(
                c.measure(l, FontStyle::Sans, 10.0) <= 120.5,
                "line overflows: {l}"
            );
        }
        // No words may be lost.
        let rejoined = lines.join(" ");
        assert_eq!(
            rejoined.split_whitespace().count(),
            text.split_whitespace().count()
        );
    }

    #[test]
    fn wrap_hard_splits_an_oversized_token() {
        let c = Canvas::new(false);
        let lines = c.wrap(&"A".repeat(400), FontStyle::Sans, 10.0, 60.0);
        assert!(lines.len() > 1);
        for l in &lines {
            assert!(c.measure(l, FontStyle::Sans, 10.0) <= 60.5);
        }
    }

    #[test]
    fn wrap_preserves_explicit_newlines() {
        let c = Canvas::new(false);
        assert_eq!(c.wrap("one\ntwo", FontStyle::Sans, 10.0, 500.0).len(), 2);
    }

    #[test]
    fn ellipsize_shortens_only_when_needed() {
        let c = Canvas::new(false);
        assert_eq!(c.ellipsize("short", FontStyle::Sans, 10.0, 200.0), "short");
        let cut = c.ellipsize(
            "a very long finding title indeed",
            FontStyle::Sans,
            10.0,
            50.0,
        );
        assert!(cut.ends_with('…'));
        assert!(c.measure(&cut, FontStyle::Sans, 10.0) <= 50.5);
    }

    #[test]
    fn text_in_aligns_end_to_the_left_when_rtl() {
        let mut ltr = Canvas::new(false);
        ltr.text_in(
            0.0,
            200.0,
            700.0,
            10.0,
            FontStyle::Sans,
            theme::INK,
            Align::Start,
            "x",
        );
        let ltr_page = ltr.finish().remove(0);
        let mut rtl = Canvas::new(true);
        rtl.text_in(
            0.0,
            200.0,
            700.0,
            10.0,
            FontStyle::Sans,
            theme::INK,
            Align::Start,
            "x",
        );
        let rtl_page = rtl.finish().remove(0);
        // Start-aligned text sits at x≈0 in LTR and near the right edge in RTL.
        assert!(ltr_page.contains("1 0 0 1 0.00 700.00 Tm"));
        assert!(!rtl_page.contains("1 0 0 1 0.00 700.00 Tm"));
    }

    #[test]
    fn line_at_cursor_advances_by_the_leading() {
        let mut c = Canvas::new(false);
        let before = c.y;
        c.line_at_cursor(
            50.0,
            200.0,
            10.0,
            16.0,
            FontStyle::Sans,
            theme::INK,
            Align::Start,
            "x",
        );
        assert!((before - c.y - 16.0).abs() < 1e-9);
    }

    #[test]
    fn vector_primitives_emit_expected_operators() {
        let mut c = Canvas::new(false);
        c.fill_rect(10.0, 10.0, 20.0, 20.0, theme::BRAND);
        c.stroke_rect(10.0, 10.0, 20.0, 20.0, theme::LINE, 0.5);
        c.line(0.0, 0.0, 10.0, 10.0, theme::LINE, 0.5);
        c.round_rect(0.0, 0.0, 40.0, 12.0, 6.0, theme::BRAND);
        c.circle_fill(50.0, 50.0, 10.0, theme::CYAN);
        c.donut_segment(50.0, 50.0, 20.0, 10.0, 0.0, 90.0, theme::SEV_HIGH);
        let page = &c.finish()[0];
        assert!(page.contains(" re f"));
        assert!(page.contains(" re S"));
        assert!(page.contains(" l S"));
        assert!(page.contains(" c\n"), "bezier segments expected");
        assert!(page.contains("h f"));
    }

    #[test]
    fn zero_width_donut_segment_is_skipped() {
        let mut c = Canvas::new(false);
        c.donut_segment(50.0, 50.0, 20.0, 10.0, 30.0, 30.0, theme::SEV_LOW);
        assert!(c.finish()[0].is_empty());
    }

    #[test]
    fn chip_returns_its_measured_width() {
        let mut c = Canvas::new(false);
        let w = c.chip(10.0, 10.0, 14.0, "CRITICAL", theme::SEV_CRITICAL);
        assert!(w > 14.0, "chip must be wider than its padding: {w}");
    }
}
