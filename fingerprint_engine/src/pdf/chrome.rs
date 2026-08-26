//! Page furniture: the brand mark, cover page, running header/footer and table of contents.

use super::canvas::{Align, Canvas, FontStyle, CONTENT_TOP, MARGIN_X, PAGE_H, PAGE_W};
use super::charts::{self, Chart};
use super::theme;

/// One line in the table of contents / outline tree.
#[derive(Clone, Debug)]
pub struct TocEntry {
    pub title: String,
    /// 0 = section, 1 = sub-heading.
    pub level: u8,
    /// Index of the body page the entry starts on, before cover/TOC pages are prepended.
    pub body_page: usize,
    /// Baseline the destination should scroll to.
    pub y: f64,
}

/// Draw the Weissman shield mark. `size` is the height of the shield in points; the glyph is
/// the same vector art as the product logo, ported from `frontend/public/logo.svg`.
pub fn shield(canvas: &mut Canvas, x: f64, y: f64, size: f64, body: theme::Rgb, mark: theme::Rgb) {
    let s = size / 64.0;
    // SVG uses a y-down space; flip into PDF's y-up space anchored at (x, y).
    let px = |sx: f64| x + sx * s;
    let py = |sy: f64| y + (64.0 - sy) * s;

    let mut ops = String::new();
    ops.push_str(&format!(
        "q\n{:.4} {:.4} {:.4} rg\n",
        body.0, body.1, body.2
    ));
    ops.push_str(&format!("{:.2} {:.2} m\n", px(32.0), py(6.0)));
    ops.push_str(&format!("{:.2} {:.2} l\n", px(56.0), py(14.0)));
    ops.push_str(&format!("{:.2} {:.2} l\n", px(56.0), py(32.0)));
    ops.push_str(&format!(
        "{:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c\n",
        px(56.0),
        py(46.0),
        px(32.0),
        py(58.0),
        px(32.0),
        py(58.0)
    ));
    ops.push_str(&format!(
        "{:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c\n",
        px(32.0),
        py(58.0),
        px(8.0),
        py(46.0),
        px(8.0),
        py(32.0)
    ));
    ops.push_str(&format!("{:.2} {:.2} l\n", px(8.0), py(14.0)));
    ops.push_str("h f\nQ\n");

    // The inner zig-zag doubles as a "W" and a verification check.
    ops.push_str(&format!(
        "q\n{:.4} {:.4} {:.4} RG\n{:.2} w\n1 J\n1 j\n",
        mark.0,
        mark.1,
        mark.2,
        3.0 * s
    ));
    ops.push_str(&format!("{:.2} {:.2} m\n", px(18.0), py(28.0)));
    for (sx, sy) in [(26.0, 40.0), (34.0, 22.0), (42.0, 40.0), (50.0, 24.0)] {
        ops.push_str(&format!("{:.2} {:.2} l\n", px(sx), py(sy)));
    }
    ops.push_str("S\nQ\n");
    canvas.raw(&ops);
}

/// Brand lockup: shield plus wordmark, drawn with its baseline block starting at `(x, y)`.
pub fn lockup(canvas: &mut Canvas, x: f64, y: f64, size: f64, on_dark: bool) {
    let (shield_body, shield_mark, word, sub) = if on_dark {
        (
            theme::CYAN,
            theme::BRAND_DEEP,
            theme::PAPER,
            theme::BRAND_BRIGHT,
        )
    } else {
        (theme::BRAND, theme::PAPER, theme::INK, theme::BRAND)
    };
    shield(canvas, x, y, size, shield_body, shield_mark);
    let tx = x + size * 1.12;
    canvas.text(
        tx,
        y + size * 0.52,
        size * 0.34,
        FontStyle::SansBold,
        word,
        "WEISSMAN",
    );
    canvas.text(
        tx,
        y + size * 0.24,
        size * 0.17,
        FontStyle::Mono,
        sub,
        "CYBERSECURITY",
    );
}

/// Cover page: brand band, title block, document-control grid and an optional hero chart.
pub fn draw_cover(canvas: &mut Canvas, meta: &super::doc::DocMeta, hero: Option<&Chart>) {
    let band_h = 268.0;
    let band_y = PAGE_H - band_h;
    canvas.fill_rect(0.0, band_y, PAGE_W, band_h, theme::BRAND_DEEP);
    // Accent rules give the band depth without a gradient (which would need a shading dict).
    canvas.fill_rect(0.0, band_y, PAGE_W, 4.0, theme::BRAND_BRIGHT);
    canvas.fill_rect(0.0, band_y + 4.0, PAGE_W * 0.42, 1.5, theme::CYAN);

    lockup(canvas, MARGIN_X, PAGE_H - 96.0, 46.0, true);

    if !meta.classification.is_empty() {
        let label = meta.classification.to_uppercase();
        let w = canvas.measure(&label, FontStyle::SansBold, 8.0) + 18.0;
        canvas.round_rect(
            PAGE_W - MARGIN_X - w,
            PAGE_H - 88.0,
            w,
            18.0,
            9.0,
            theme::BRAND_BRIGHT,
        );
        canvas.text_in(
            PAGE_W - MARGIN_X - w,
            w,
            PAGE_H - 82.0,
            8.0,
            FontStyle::SansBold,
            theme::BRAND_DEEP,
            Align::Center,
            &label,
        );
    }

    let inner = PAGE_W - MARGIN_X * 2.0;
    let mut y = band_y + 132.0;
    for line in canvas.wrap(&meta.title, FontStyle::SansBold, 27.0, inner) {
        canvas.text_in(
            MARGIN_X,
            inner,
            y,
            27.0,
            FontStyle::SansBold,
            theme::PAPER,
            Align::Start,
            &line,
        );
        y -= 32.0;
    }
    if !meta.subtitle.is_empty() {
        for line in canvas.wrap(&meta.subtitle, FontStyle::Sans, 12.0, inner) {
            canvas.text_in(
                MARGIN_X,
                inner,
                y,
                12.0,
                FontStyle::Sans,
                theme::BRAND_BRIGHT,
                Align::Start,
                &line,
            );
            y -= 16.0;
        }
    }
    if !meta.client.is_empty() {
        canvas.text_in(
            MARGIN_X,
            inner,
            band_y + 34.0,
            15.0,
            FontStyle::SansBold,
            theme::PAPER,
            Align::Start,
            &meta.client,
        );
    }

    // Document control grid — the block an auditor looks for first.
    canvas.y = band_y - 42.0;
    let label_w = inner * 0.34;
    for (k, v) in &meta.control_fields {
        canvas.ensure(18.0);
        let row_y = canvas.y;
        canvas.text_in(
            MARGIN_X,
            label_w,
            row_y,
            8.5,
            FontStyle::SansBold,
            theme::MUTED,
            Align::Start,
            k,
        );
        let value_x = if canvas.is_rtl() {
            MARGIN_X
        } else {
            MARGIN_X + label_w
        };
        let value_w = inner - label_w;
        let value = canvas.ellipsize(v, FontStyle::Sans, 9.5, value_w);
        canvas.text_in(
            value_x,
            value_w,
            row_y,
            9.5,
            FontStyle::Sans,
            theme::INK,
            Align::Start,
            &value,
        );
        canvas.y -= 17.0;
        canvas.line(
            MARGIN_X,
            canvas.y + 5.0,
            MARGIN_X + inner,
            canvas.y + 5.0,
            theme::LINE,
            0.4,
        );
    }

    if let Some(chart) = hero {
        canvas.y -= 18.0;
        charts::draw(canvas, MARGIN_X, inner, chart);
    }

    // Integrity seal, anchored to the bottom of the cover.
    if let Some(hash) = &meta.integrity_hash {
        let seal_h = 44.0;
        let seal_y = 96.0;
        canvas.round_rect(MARGIN_X, seal_y, inner, seal_h, 6.0, theme::INK.tint(0.94));
        canvas.fill_rect(MARGIN_X, seal_y, 3.0, seal_h, theme::BRAND);
        canvas.text(
            MARGIN_X + 14.0,
            seal_y + seal_h - 16.0,
            8.0,
            FontStyle::SansBold,
            theme::BRAND_STRONG,
            "CRYPTOGRAPHIC INTEGRITY SEAL",
        );
        let short = canvas.ellipsize(hash, FontStyle::Mono, 7.5, inner - 28.0);
        canvas.text(
            MARGIN_X + 14.0,
            seal_y + 14.0,
            7.5,
            FontStyle::Mono,
            theme::BODY,
            &short,
        );
        if let Some(url) = &meta.verify_url {
            let short = canvas.ellipsize(url, FontStyle::Mono, 6.5, inner - 28.0);
            canvas.text(
                MARGIN_X + 14.0,
                seal_y + 4.0,
                6.5,
                FontStyle::Mono,
                theme::MUTED,
                &short,
            );
        }
    }

    canvas.line(MARGIN_X, 70.0, PAGE_W - MARGIN_X, 70.0, theme::LINE, 0.6);
    canvas.text_in(
        MARGIN_X,
        inner,
        56.0,
        7.5,
        FontStyle::Sans,
        theme::MUTED,
        Align::Start,
        &meta.footer_note(),
    );
}

/// Clickable region of one contents row, reported so the writer can emit a link annotation.
#[derive(Clone, Copy, Debug)]
pub struct TocLink {
    /// Page index within the contents canvas.
    pub page: usize,
    /// `[x0, y0, x1, y1]` in PDF user space.
    pub rect: [f64; 4],
    /// Index into the entry list this row points at.
    pub entry: usize,
}

/// Table of contents. Returns the row rectangles so the writer can make them clickable.
pub fn draw_toc(
    canvas: &mut Canvas,
    heading: &str,
    entries: &[TocEntry],
    page_offset: usize,
) -> Vec<TocLink> {
    let mut links = Vec::with_capacity(entries.len());
    let inner = PAGE_W - MARGIN_X * 2.0;
    canvas.y = CONTENT_TOP - 8.0;
    canvas.line_at_cursor(
        MARGIN_X,
        inner,
        18.0,
        30.0,
        FontStyle::SansBold,
        theme::INK,
        Align::Start,
        heading,
    );
    canvas.line(
        MARGIN_X,
        canvas.y + 8.0,
        MARGIN_X + 54.0,
        canvas.y + 8.0,
        theme::BRAND,
        2.0,
    );
    canvas.y -= 10.0;

    for (index, entry) in entries.iter().enumerate() {
        canvas.ensure(17.0);
        let indent = f64::from(entry.level) * 16.0;
        let baseline = canvas.y - 9.0;
        links.push(TocLink {
            page: canvas.page_index(),
            rect: [MARGIN_X, baseline - 3.0, MARGIN_X + inner, baseline + 10.0],
            entry: index,
        });
        let page_label = (entry.body_page + page_offset + 1).to_string();
        let (style, color, size) = if entry.level == 0 {
            (FontStyle::SansBold, theme::INK, 9.5)
        } else {
            (FontStyle::Sans, theme::BODY, 9.0)
        };
        let num_w = canvas.measure(&page_label, FontStyle::Sans, 9.0);
        let title_w = inner - indent - num_w - 14.0;
        let title = canvas.ellipsize(&entry.title, style, size, title_w);
        canvas.text_in(
            MARGIN_X + indent,
            title_w,
            baseline,
            size,
            style,
            color,
            Align::Start,
            &title,
        );

        // Dotted leader between the title and its page number.
        let measured = canvas.measure(&title, style, size);
        let (dot_start, dot_end) = if canvas.is_rtl() {
            (
                MARGIN_X + num_w + 8.0,
                MARGIN_X + inner - indent - measured - 6.0,
            )
        } else {
            (
                MARGIN_X + indent + measured + 6.0,
                MARGIN_X + inner - num_w - 8.0,
            )
        };
        if dot_end > dot_start {
            let mut dx = dot_start;
            while dx < dot_end {
                canvas.fill_rect(dx, baseline + 2.0, 1.0, 1.0, theme::LINE);
                dx += 4.0;
            }
        }
        canvas.text_in(
            MARGIN_X,
            inner,
            baseline,
            9.0,
            FontStyle::Sans,
            theme::MUTED,
            Align::End,
            &page_label,
        );
        canvas.y -= 17.0;
    }
    links
}

/// Running header for a body page.
pub fn draw_header(canvas: &mut Canvas, meta: &super::doc::DocMeta) {
    let inner = PAGE_W - MARGIN_X * 2.0;
    let y = PAGE_H - 34.0;
    shield(canvas, MARGIN_X, y - 4.0, 18.0, theme::BRAND, theme::PAPER);
    let title = canvas.ellipsize(&meta.title, FontStyle::SansBold, 8.5, inner * 0.55);
    canvas.text(
        MARGIN_X + 24.0,
        y + 1.0,
        8.5,
        FontStyle::SansBold,
        theme::INK_SOFT,
        &title,
    );
    let right = if meta.client.is_empty() {
        meta.org.clone()
    } else {
        format!("{} · {}", meta.org, meta.client)
    };
    let right = canvas.ellipsize(&right, FontStyle::Sans, 8.0, inner * 0.4);
    canvas.text_in(
        MARGIN_X,
        inner,
        y + 1.0,
        8.0,
        FontStyle::Sans,
        theme::MUTED,
        Align::End,
        &right,
    );
    canvas.line(
        MARGIN_X,
        y - 10.0,
        PAGE_W - MARGIN_X,
        y - 10.0,
        theme::LINE,
        0.6,
    );
    canvas.line(
        MARGIN_X,
        y - 10.0,
        MARGIN_X + 46.0,
        y - 10.0,
        theme::BRAND,
        1.4,
    );
}

/// Running footer with the classification, document id and `Page X of Y`.
pub fn draw_footer(canvas: &mut Canvas, meta: &super::doc::DocMeta, page: usize, total: usize) {
    let inner = PAGE_W - MARGIN_X * 2.0;
    let y = 30.0;
    canvas.line(
        MARGIN_X,
        y + 14.0,
        PAGE_W - MARGIN_X,
        y + 14.0,
        theme::LINE,
        0.5,
    );
    let left = canvas.ellipsize(&meta.footer_note(), FontStyle::Sans, 7.0, inner * 0.62);
    canvas.text(MARGIN_X, y, 7.0, FontStyle::Sans, theme::FAINT, &left);
    canvas.text_in(
        MARGIN_X,
        inner,
        y,
        7.5,
        FontStyle::SansBold,
        theme::MUTED,
        Align::End,
        &meta.page_label(page, total),
    );
}

/// Full-page diagonal watermark, stamped beneath the content of every page.
pub fn watermark_ops(canvas: &mut Canvas, text: &str) {
    let len = text.chars().count().max(1) as f64;
    let size = (900.0 / (len * 0.55)).clamp(22.0, 64.0);
    let width = canvas.measure(text, FontStyle::SansBold, size);
    let c = std::f64::consts::FRAC_1_SQRT_2;
    let half = width * c / 2.0;
    // Rotate 45° about the page centre via the text matrix.
    let tx = PAGE_W / 2.0 - half;
    let ty = PAGE_H / 2.0 - half;
    let visual = super::bidi::to_visual(
        text,
        if canvas.is_rtl() {
            super::bidi::Dir::Rtl
        } else {
            super::bidi::Dir::Ltr
        },
    );
    let hex = super::fonts::sans_font().encode(&visual, &mut canvas.used_sans);
    let color = theme::SEV_CRITICAL.tint(0.72);
    canvas.raw(&format!(
        "q\n{:.4} {:.4} {:.4} rg\nBT /F1 {:.0} Tf {:.4} {:.4} {:.4} {:.4} {:.2} {:.2} Tm {} Tj ET\nQ\n",
        color.0, color.1, color.2, size, c, c, -c, c, tx, ty, hex
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::doc::{DocMeta, Lang};

    fn meta() -> DocMeta {
        DocMeta {
            title: "External Attack Surface Assessment".into(),
            subtitle: "Live evidence-backed findings".into(),
            org: "Weissman Cybersecurity".into(),
            client: "Acme Industries".into(),
            classification: "Confidential".into(),
            doc_id: "WSM-2026-0001".into(),
            lang: Lang::En,
            control_fields: vec![
                ("Generated".into(), "2026-08-25 10:00:00 IDT".into()),
                ("Scope".into(), "acme.example".into()),
            ],
            integrity_hash: Some("a".repeat(64)),
            verify_url: Some("https://verify.example/WSM-2026-0001".into()),
            watermark: None,
        }
    }

    #[test]
    fn shield_emits_a_filled_path_and_a_stroked_mark() {
        let mut c = Canvas::new(false);
        shield(&mut c, 50.0, 700.0, 40.0, theme::BRAND, theme::PAPER);
        let page = &c.finish()[0];
        assert!(page.contains("h f"), "shield body must be filled");
        assert!(page.contains(" c\n"), "shield uses bezier shoulders");
        assert!(page.contains("S\nQ"), "inner mark must be stroked");
        assert!(
            page.contains("1 J") && page.contains("1 j"),
            "round caps and joins"
        );
    }

    #[test]
    fn lockup_typesets_the_wordmark() {
        let mut c = Canvas::new(false);
        lockup(&mut c, 50.0, 700.0, 40.0, true);
        assert!(!c.used_sans.is_empty());
        assert!(
            !c.used_mono.is_empty(),
            "the CYBERSECURITY line is monospace"
        );
    }

    #[test]
    fn cover_fits_on_one_page_and_carries_the_seal() {
        let mut c = Canvas::new(false);
        draw_cover(&mut c, &meta(), None);
        let pages = c.finish();
        assert_eq!(
            pages.len(),
            1,
            "the cover must never spill onto a second page"
        );
        assert!(!pages[0].is_empty());
    }

    #[test]
    fn cover_with_a_hero_chart_still_fits_on_one_page() {
        let mut c = Canvas::new(false);
        let hero = Chart::Gauge {
            score: 68,
            caption: "Security posture".into(),
        };
        draw_cover(&mut c, &meta(), Some(&hero));
        assert_eq!(c.finish().len(), 1);
    }

    #[test]
    fn cover_without_optional_fields_is_safe() {
        let mut m = meta();
        m.subtitle = String::new();
        m.client = String::new();
        m.classification = String::new();
        m.integrity_hash = None;
        m.verify_url = None;
        m.control_fields.clear();
        let mut c = Canvas::new(false);
        draw_cover(&mut c, &m, None);
        assert_eq!(c.finish().len(), 1);
    }

    #[test]
    fn toc_page_numbers_include_the_front_matter_offset() {
        let entries = vec![
            TocEntry {
                title: "Executive Summary".into(),
                level: 0,
                body_page: 0,
                y: 700.0,
            },
            TocEntry {
                title: "Detailed Findings".into(),
                level: 1,
                body_page: 3,
                y: 700.0,
            },
        ];
        let mut c = Canvas::new(false);
        draw_toc(&mut c, "Contents", &entries, 2);
        // body page 3 + 2 front-matter pages + 1 for one-based numbering = 6.
        assert!(!c.used_sans.is_empty());
        let mut probe = Canvas::new(false);
        probe.text(0.0, 0.0, 9.0, FontStyle::Sans, theme::MUTED, "6");
        let six: Vec<u16> = probe.used_sans.into_iter().collect();
        assert!(
            six.iter().all(|g| c.used_sans.contains(g)),
            "page 6 must be typeset"
        );
    }

    #[test]
    fn long_toc_paginates() {
        let entries: Vec<TocEntry> = (0..90)
            .map(|i| TocEntry {
                title: format!("Section {i}"),
                level: 0,
                body_page: i,
                y: 700.0,
            })
            .collect();
        let mut c = Canvas::new(false);
        draw_toc(&mut c, "Contents", &entries, 1);
        assert!(c.finish().len() > 1);
    }

    #[test]
    fn header_and_footer_stay_inside_their_bands() {
        let mut c = Canvas::new(false);
        let before = c.y;
        draw_header(&mut c, &meta());
        draw_footer(&mut c, &meta(), 3, 12);
        // Chrome paints at absolute coordinates and must not disturb the flow cursor.
        assert_eq!(c.y, before);
        assert!(!c.finish()[0].is_empty());
    }

    #[test]
    fn watermark_is_rotated_about_the_page_centre() {
        let mut c = Canvas::new(false);
        watermark_ops(&mut c, "VOID");
        let page = &c.finish()[0];
        assert!(page.contains("Tm"), "watermark uses a text matrix");
        assert!(
            page.contains("-0.7071"),
            "45 degree rotation expected: {page}"
        );
    }
}
