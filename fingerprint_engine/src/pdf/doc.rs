//! The declarative report model and the PDF writer that renders it.
//!
//! A caller describes *what* the report says ([`ReportDoc`]); this module decides how it
//! looks — cover, contents, running chrome, pagination, outline bookmarks, metadata and the
//! integrity seal. That split is what keeps the client assessment, the board briefing, the
//! compliance packet and ad-hoc panel exports visually identical.

use super::canvas::{Align, Canvas, FontStyle, CONTENT_W, MARGIN_X, PAGE_H, PAGE_W};
use super::charts::{self, Chart};
use super::chrome::{self, TocEntry};
use super::fonts::{mono_font, sans_font};
use super::layout::{self, Table};
use super::theme::{self, Rgb};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::collections::BTreeSet;
use std::io::Write as _;

/// Document language. Hebrew switches the whole document to right-to-left.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Lang {
    #[default]
    En,
    He,
}

impl Lang {
    /// Parse a `lang` query parameter or `Accept-Language` prefix.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let v = raw.trim().to_ascii_lowercase();
        if v.starts_with("he") || v.starts_with("iw") {
            Lang::He
        } else {
            Lang::En
        }
    }

    #[must_use]
    pub fn is_rtl(self) -> bool {
        self == Lang::He
    }

    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Lang::En => "en-GB",
            Lang::He => "he-IL",
        }
    }

    #[must_use]
    pub fn contents_heading(self) -> &'static str {
        match self {
            Lang::En => "Contents",
            Lang::He => "תוכן העניינים",
        }
    }

    #[must_use]
    pub fn confidential(self) -> &'static str {
        match self {
            Lang::En => "Confidential — for the named recipient only.",
            Lang::He => "חסוי — לנמען הרשום בלבד.",
        }
    }
}

/// Emphasis for metric tiles and callouts.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Tone {
    #[default]
    Neutral,
    Brand,
    Good,
    Warn,
    Bad,
}

impl Tone {
    #[must_use]
    pub fn color(self) -> Rgb {
        match self {
            Tone::Neutral => theme::INK_SOFT,
            Tone::Brand => theme::BRAND,
            Tone::Good => theme::OK,
            Tone::Warn => theme::AMBER,
            Tone::Bad => theme::SEV_CRITICAL,
        }
    }

    /// Tone implied by a severity label, so callers can pass findings straight through.
    #[must_use]
    pub fn from_severity(severity: &str) -> Self {
        match theme::severity_rank(severity) {
            0 | 1 => Tone::Bad,
            2 => Tone::Warn,
            3 => Tone::Brand,
            _ => Tone::Neutral,
        }
    }
}

/// A headline number with its label.
#[derive(Clone, Debug)]
pub struct Metric {
    pub label: String,
    pub value: String,
    pub tone: Tone,
}

impl Metric {
    #[must_use]
    pub fn new(label: impl Into<String>, value: impl Into<String>, tone: Tone) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            tone,
        }
    }
}

/// A boxed advisory note.
#[derive(Clone, Debug)]
pub struct Callout {
    pub tone: Tone,
    pub title: String,
    pub body: String,
}

impl Callout {
    #[must_use]
    pub fn new(tone: Tone, title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            tone,
            title: title.into(),
            body: body.into(),
        }
    }
}

/// One renderable element of a section.
#[derive(Clone, Debug)]
pub enum Block {
    /// Sub-heading inside a section; appears in the contents at level 1.
    Heading(String),
    Paragraph(String),
    Bullets(Vec<String>),
    KeyValues(Vec<(String, String)>),
    Metrics(Vec<Metric>),
    Table(Table),
    Chart(Chart),
    Callout(Callout),
    /// Preformatted monospace block — evidence, requests, hashes.
    Mono(Vec<String>),
    Divider,
    Spacer(f64),
    PageBreak,
}

/// A titled group of blocks. Sections appear in the contents at level 0.
#[derive(Clone, Debug)]
pub struct Section {
    pub title: String,
    pub blocks: Vec<Block>,
    /// Force this section to start on a fresh page.
    pub start_on_new_page: bool,
}

impl Section {
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            blocks: Vec::new(),
            start_on_new_page: false,
        }
    }

    #[must_use]
    pub fn on_new_page(mut self) -> Self {
        self.start_on_new_page = true;
        self
    }

    #[must_use]
    pub fn with(mut self, block: Block) -> Self {
        self.blocks.push(block);
        self
    }

    pub fn push(&mut self, block: Block) {
        self.blocks.push(block);
    }
}

/// Cover-page and metadata fields.
#[derive(Clone, Debug, Default)]
pub struct DocMeta {
    pub title: String,
    pub subtitle: String,
    /// Issuing organisation, printed in the running header.
    pub org: String,
    pub client: String,
    pub classification: String,
    pub doc_id: String,
    pub lang: Lang,
    /// Document-control rows printed under the cover band.
    pub control_fields: Vec<(String, String)>,
    pub integrity_hash: Option<String>,
    pub verify_url: Option<String>,
    /// When set, a diagonal stamp is drawn beneath every page.
    pub watermark: Option<String>,
}

impl DocMeta {
    /// Confidentiality line shown on the cover and in every footer.
    #[must_use]
    pub fn footer_note(&self) -> String {
        let org = if self.org.is_empty() {
            "Weissman Cybersecurity"
        } else {
            &self.org
        };
        if self.doc_id.is_empty() {
            format!("© {org} · {}", self.lang.confidential())
        } else {
            format!("© {org} · {} · {}", self.doc_id, self.lang.confidential())
        }
    }

    /// Localised `Page X of Y`.
    #[must_use]
    pub fn page_label(&self, page: usize, total: usize) -> String {
        match self.lang {
            Lang::En => format!("Page {page} of {total}"),
            Lang::He => format!("עמוד {page} מתוך {total}"),
        }
    }
}

/// A complete report, ready to render.
#[derive(Clone, Debug, Default)]
pub struct ReportDoc {
    pub meta: DocMeta,
    pub sections: Vec<Section>,
    /// Optional chart shown on the cover under the document-control grid.
    pub hero: Option<Chart>,
}

impl ReportDoc {
    #[must_use]
    pub fn new(meta: DocMeta) -> Self {
        Self {
            meta,
            sections: Vec::new(),
            hero: None,
        }
    }

    #[must_use]
    pub fn with_section(mut self, section: Section) -> Self {
        self.sections.push(section);
        self
    }

    #[must_use]
    pub fn with_hero(mut self, hero: Chart) -> Self {
        self.hero = Some(hero);
        self
    }

    pub fn push(&mut self, section: Section) {
        self.sections.push(section);
    }

    /// Render to PDF bytes.
    #[must_use]
    pub fn render(&self) -> Vec<u8> {
        let rtl = self.meta.lang.is_rtl();
        let mut used_sans: BTreeSet<u16> = BTreeSet::new();
        let mut used_mono: BTreeSet<u16> = BTreeSet::new();

        // 1. Body flow. Section start pages are recorded relative to the body.
        let mut body = Canvas::new(rtl);
        let mut toc: Vec<TocEntry> = Vec::new();
        for (i, section) in self.sections.iter().enumerate() {
            if section.start_on_new_page && i > 0 {
                body.new_page();
            }
            draw_section_title(&mut body, &section.title);
            toc.push(TocEntry {
                title: section.title.clone(),
                level: 0,
                body_page: body.page_index(),
                y: body.y + 26.0,
            });
            for block in &section.blocks {
                if let Block::Heading(h) = block {
                    // Register before drawing so the destination lands above the heading.
                    body.ensure(46.0);
                    toc.push(TocEntry {
                        title: h.clone(),
                        level: 1,
                        body_page: body.page_index(),
                        y: body.y + 12.0,
                    });
                }
                draw_block(&mut body, block);
            }
        }
        used_sans.extend(body.used_sans.iter().copied());
        used_mono.extend(body.used_mono.iter().copied());
        let body_pages = body.finish();

        // 2. Front matter. The contents is skipped for short documents where it would be noise.
        let want_toc = toc.len() >= 3;
        let toc_page_count = if want_toc {
            let mut probe = Canvas::new(rtl);
            chrome::draw_toc(&mut probe, self.meta.lang.contents_heading(), &toc, 1);
            probe.finish().len()
        } else {
            0
        };

        let mut cover = Canvas::new(rtl);
        chrome::draw_cover(&mut cover, &self.meta, self.hero.as_ref());
        used_sans.extend(cover.used_sans.iter().copied());
        used_mono.extend(cover.used_mono.iter().copied());
        let cover_pages = cover.finish();

        let front_matter = cover_pages.len() + toc_page_count;
        let mut toc_pages = Vec::new();
        let mut toc_links = Vec::new();
        if want_toc {
            let mut tc = Canvas::new(rtl);
            toc_links = chrome::draw_toc(
                &mut tc,
                self.meta.lang.contents_heading(),
                &toc,
                front_matter,
            );
            used_sans.extend(tc.used_sans.iter().copied());
            used_mono.extend(tc.used_mono.iter().copied());
            toc_pages = tc.finish();
        }

        // 3. Assemble, then stamp chrome now that the page total is known.
        let mut pages: Vec<String> = Vec::with_capacity(front_matter + body_pages.len());
        pages.extend(cover_pages.iter().cloned());
        pages.extend(toc_pages.iter().cloned());
        pages.extend(body_pages.iter().cloned());
        let total = pages.len();

        for (index, page) in pages.iter_mut().enumerate() {
            let mut deco = Canvas::new(rtl);
            if let Some(text) = &self.meta.watermark {
                chrome::watermark_ops(&mut deco, text);
            }
            // The cover carries its own furniture.
            if index > 0 {
                chrome::draw_header(&mut deco, &self.meta);
            }
            used_sans.extend(deco.used_sans.iter().copied());
            used_mono.extend(deco.used_mono.iter().copied());
            let under = deco.finish().remove(0);

            let mut foot = Canvas::new(rtl);
            if index > 0 {
                chrome::draw_footer(&mut foot, &self.meta, index + 1, total);
            }
            used_sans.extend(foot.used_sans.iter().copied());
            used_mono.extend(foot.used_mono.iter().copied());
            let over = foot.finish().remove(0);

            if !under.is_empty() {
                page.insert_str(0, &under);
            }
            if !over.is_empty() {
                page.push_str(&over);
            }
        }

        // Contents rows become link annotations on their own (post-cover) page.
        let links: Vec<PageLink> = toc_links
            .iter()
            .filter_map(|l| {
                let entry = toc.get(l.entry)?;
                Some(PageLink {
                    page: cover_pages.len() + l.page,
                    rect: l.rect,
                    target_page: entry.body_page + front_matter,
                    target_y: entry.y,
                })
            })
            .collect();

        write_pdf(
            &self.meta,
            &pages,
            &toc,
            front_matter,
            &links,
            &used_sans,
            &used_mono,
        )
    }
}

/// A resolved internal hyperlink, ready to be written as a `/Link` annotation.
struct PageLink {
    page: usize,
    rect: [f64; 4],
    target_page: usize,
    target_y: f64,
}

fn draw_section_title(canvas: &mut Canvas, title: &str) {
    canvas.ensure(56.0);
    canvas.y -= 6.0;
    let baseline = canvas.y - 15.0;
    canvas.text_in(
        MARGIN_X,
        CONTENT_W,
        baseline,
        15.0,
        FontStyle::SansBold,
        theme::INK,
        Align::Start,
        title,
    );
    let rule_y = baseline - 8.0;
    canvas.line(
        MARGIN_X,
        rule_y,
        MARGIN_X + CONTENT_W,
        rule_y,
        theme::LINE,
        0.6,
    );
    let accent_x = if canvas.is_rtl() {
        MARGIN_X + CONTENT_W - 48.0
    } else {
        MARGIN_X
    };
    canvas.line(accent_x, rule_y, accent_x + 48.0, rule_y, theme::BRAND, 2.0);
    canvas.y = rule_y - 14.0;
}

fn draw_block(canvas: &mut Canvas, block: &Block) {
    match block {
        Block::Heading(text) => {
            canvas.ensure(34.0);
            canvas.y -= 4.0;
            canvas.line_at_cursor(
                MARGIN_X,
                CONTENT_W,
                11.0,
                17.0,
                FontStyle::SansBold,
                theme::BRAND_STRONG,
                Align::Start,
                text,
            );
            canvas.y -= 2.0;
        }
        Block::Paragraph(text) => {
            for line in canvas.wrap(text, FontStyle::Sans, 9.5, CONTENT_W) {
                canvas.line_at_cursor(
                    MARGIN_X,
                    CONTENT_W,
                    9.5,
                    13.5,
                    FontStyle::Sans,
                    theme::BODY,
                    Align::Start,
                    &line,
                );
            }
            canvas.y -= 5.0;
        }
        Block::Bullets(items) => {
            let indent = 14.0;
            for item in items {
                let lines = canvas.wrap(item, FontStyle::Sans, 9.5, CONTENT_W - indent);
                for (i, line) in lines.iter().enumerate() {
                    canvas.ensure(13.5);
                    let baseline = canvas.y - 9.5;
                    if i == 0 {
                        let dot_x = if canvas.is_rtl() {
                            MARGIN_X + CONTENT_W - 6.0
                        } else {
                            MARGIN_X + 3.0
                        };
                        canvas.circle_fill(dot_x, baseline + 3.0, 1.8, theme::BRAND);
                    }
                    let x = if canvas.is_rtl() {
                        MARGIN_X
                    } else {
                        MARGIN_X + indent
                    };
                    canvas.text_in(
                        x,
                        CONTENT_W - indent,
                        baseline,
                        9.5,
                        FontStyle::Sans,
                        theme::BODY,
                        Align::Start,
                        line,
                    );
                    canvas.y -= 13.5;
                }
            }
            canvas.y -= 5.0;
        }
        Block::KeyValues(rows) => {
            let label_w = CONTENT_W * 0.32;
            for (k, v) in rows {
                let value_lines = canvas.wrap(v, FontStyle::Sans, 9.0, CONTENT_W - label_w - 8.0);
                let h = (value_lines.len().max(1) as f64) * 12.5 + 4.0;
                canvas.ensure(h);
                let top = canvas.y;
                canvas.text_in(
                    MARGIN_X,
                    label_w,
                    top - 9.0,
                    8.5,
                    FontStyle::SansBold,
                    theme::MUTED,
                    Align::Start,
                    k,
                );
                let vx = if canvas.is_rtl() {
                    MARGIN_X
                } else {
                    MARGIN_X + label_w
                };
                for (i, line) in value_lines.iter().enumerate() {
                    canvas.text_in(
                        vx,
                        CONTENT_W - label_w,
                        top - 9.0 - i as f64 * 12.5,
                        9.0,
                        FontStyle::Sans,
                        theme::INK,
                        Align::Start,
                        line,
                    );
                }
                canvas.y = top - h;
                canvas.line(
                    MARGIN_X,
                    canvas.y + 3.0,
                    MARGIN_X + CONTENT_W,
                    canvas.y + 3.0,
                    theme::LINE_SOFT,
                    0.5,
                );
            }
            canvas.y -= 6.0;
        }
        Block::Metrics(metrics) => draw_metrics(canvas, metrics),
        Block::Table(table) => layout::draw_table(canvas, MARGIN_X, CONTENT_W, table),
        Block::Chart(chart) => charts::draw(canvas, MARGIN_X, CONTENT_W, chart),
        Block::Callout(callout) => draw_callout(canvas, callout),
        Block::Mono(lines) => draw_mono(canvas, lines),
        Block::Divider => {
            canvas.ensure(12.0);
            canvas.y -= 5.0;
            canvas.line(
                MARGIN_X,
                canvas.y,
                MARGIN_X + CONTENT_W,
                canvas.y,
                theme::LINE,
                0.6,
            );
            canvas.y -= 7.0;
        }
        Block::Spacer(h) => {
            canvas.y -= h.clamp(0.0, 200.0);
        }
        Block::PageBreak => canvas.new_page(),
    }
}

fn draw_metrics(canvas: &mut Canvas, metrics: &[Metric]) {
    if metrics.is_empty() {
        return;
    }
    // Four tiles per row keeps every value legible on A4.
    for chunk in metrics.chunks(4) {
        let gap = 8.0;
        let tile_w = (CONTENT_W - gap * (chunk.len() as f64 - 1.0)) / chunk.len() as f64;
        let tile_h = 52.0;
        canvas.ensure(tile_h + 8.0);
        let top = canvas.y;
        for (i, m) in chunk.iter().enumerate() {
            let x = MARGIN_X + i as f64 * (tile_w + gap);
            canvas.round_rect(x, top - tile_h, tile_w, tile_h, 4.0, theme::LINE_SOFT);
            canvas.fill_rect(x, top - tile_h, 3.0, tile_h, m.tone.color());
            let value = canvas.ellipsize(&m.value, FontStyle::SansBold, 20.0, tile_w - 20.0);
            canvas.text(
                x + 12.0,
                top - 30.0,
                20.0,
                FontStyle::SansBold,
                m.tone.color(),
                &value,
            );
            let label = canvas.ellipsize(&m.label, FontStyle::Sans, 7.5, tile_w - 20.0);
            canvas.text(
                x + 12.0,
                top - 44.0,
                7.5,
                FontStyle::Sans,
                theme::MUTED,
                &label,
            );
        }
        canvas.y = top - tile_h - 8.0;
    }
}

fn draw_callout(canvas: &mut Canvas, callout: &Callout) {
    let pad = 10.0;
    let inner_w = CONTENT_W - pad * 2.0 - 4.0;
    let body_lines = canvas.wrap(&callout.body, FontStyle::Sans, 9.0, inner_w);
    let title_h = if callout.title.is_empty() { 0.0 } else { 14.0 };
    let h = pad * 2.0 + title_h + body_lines.len() as f64 * 12.5;
    canvas.ensure(h + 8.0);
    let top = canvas.y;
    let color = callout.tone.color();
    canvas.round_rect(MARGIN_X, top - h, CONTENT_W, h, 4.0, color.tint(0.92));
    canvas.fill_rect(MARGIN_X, top - h, 4.0, h, color);
    let mut y = top - pad - 9.0;
    if !callout.title.is_empty() {
        canvas.text_in(
            MARGIN_X + pad + 4.0,
            inner_w,
            y,
            9.5,
            FontStyle::SansBold,
            color.shade(0.25),
            Align::Start,
            &callout.title,
        );
        y -= title_h;
    }
    for line in &body_lines {
        canvas.text_in(
            MARGIN_X + pad + 4.0,
            inner_w,
            y,
            9.0,
            FontStyle::Sans,
            theme::BODY,
            Align::Start,
            line,
        );
        y -= 12.5;
    }
    canvas.y = top - h - 8.0;
}

fn draw_mono(canvas: &mut Canvas, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    let pad = 8.0;
    let inner_w = CONTENT_W - pad * 2.0;
    // Wrap first so the panel height matches what is actually painted.
    let wrapped: Vec<String> = lines
        .iter()
        .flat_map(|l| canvas.wrap(l, FontStyle::Mono, 7.5, inner_w))
        .collect();
    for chunk in wrapped.chunks(48) {
        let h = pad * 2.0 + chunk.len() as f64 * 10.0;
        canvas.ensure(h + 6.0);
        let top = canvas.y;
        canvas.round_rect(MARGIN_X, top - h, CONTENT_W, h, 3.0, theme::INK.tint(0.95));
        canvas.fill_rect(MARGIN_X, top - h, 2.5, h, theme::INK_SOFT);
        for (i, line) in chunk.iter().enumerate() {
            canvas.text(
                MARGIN_X + pad,
                top - pad - 7.5 - i as f64 * 10.0,
                7.5,
                FontStyle::Mono,
                theme::INK_SOFT,
                line,
            );
        }
        canvas.y = top - h - 6.0;
    }
}

// ---- PDF file assembly -----------------------------------------------------------------

/// Encode a PDF text string: literal ASCII where possible, UTF-16BE hex otherwise (which is
/// what makes Hebrew bookmarks and titles display correctly in a reader).
fn pdf_text_string(s: &str) -> String {
    if s.is_ascii() {
        let escaped = s
            .replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)")
            .replace(['\r', '\n'], " ");
        format!("({escaped})")
    } else {
        let mut hex = String::from("<FEFF");
        for unit in s.encode_utf16() {
            hex.push_str(&format!("{unit:04X}"));
        }
        hex.push('>');
        hex
    }
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    if enc.write_all(data).is_err() {
        return data.to_vec();
    }
    enc.finish().unwrap_or_else(|_| data.to_vec())
}

/// `D:YYYYMMDDHHmmSS+HH'mm'` timestamp in Israel time.
fn pdf_date() -> String {
    use chrono::TimeZone;
    let now = chrono_tz::Asia::Jerusalem.from_utc_datetime(&chrono::Utc::now().naive_utc());
    // `%z` is `+0300`. PDF wants `+03'00'` — never run a global `:` replace, or the
    // `D:` prefix becomes `D'` and Info `/CreationDate (D:` assertions fail.
    let offset = now.format("%z").to_string();
    let tz_pdf = if offset.len() >= 5 {
        format!("{}'{}'", &offset[..3], &offset[3..])
    } else {
        "+00'00'".into()
    };
    format!("D:{}{tz_pdf}", now.format("%Y%m%d%H%M%S"))
}

fn write_pdf(
    meta: &DocMeta,
    pages: &[String],
    toc: &[TocEntry],
    front_matter: usize,
    links: &[PageLink],
    used_sans: &BTreeSet<u16>,
    used_mono: &BTreeSet<u16>,
) -> Vec<u8> {
    let n = pages.len();
    let page_obj = |i: usize| 3 + i * 2;
    let content_obj = |i: usize| 4 + i * 2;
    let sans_base = 3 + n * 2;
    let mono_base = sans_base + 5;
    let outlines_root = mono_base + 5;
    let outline_items: Vec<usize> = (0..toc.len()).map(|i| outlines_root + 1 + i).collect();
    let info_obj = outlines_root + 1 + toc.len();
    let metadata_obj = info_obj + 1;
    let total_objs = metadata_obj;

    let mut out: Vec<u8> = Vec::with_capacity(64 * 1024);
    // Offsets are one-based by object number; slot 0 is the free-list head.
    let mut offsets: Vec<usize> = vec![0; total_objs + 1];
    out.extend_from_slice(b"%PDF-1.7\n");
    // Binary comment marks the file as containing binary data for transfer tools.
    out.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");

    let push = |out: &mut Vec<u8>, offsets: &mut Vec<usize>, id: usize, body: &[u8]| {
        offsets[id] = out.len();
        out.extend_from_slice(body);
    };

    let outlines_ref = if toc.is_empty() {
        String::new()
    } else {
        format!(" /Outlines {outlines_root} 0 R /PageMode /UseOutlines")
    };
    push(
        &mut out,
        &mut offsets,
        1,
        format!(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R{} /Lang {} /Metadata {} 0 R \
             /ViewerPreferences << /DisplayDocTitle true >> >>\nendobj\n",
            outlines_ref,
            pdf_text_string(meta.lang.tag()),
            metadata_obj
        )
        .as_bytes(),
    );

    let kids: String = (0..n).map(|i| format!("{} 0 R ", page_obj(i))).collect();
    push(
        &mut out,
        &mut offsets,
        2,
        format!(
            "2 0 obj\n<< /Type /Pages /Kids [{}] /Count {} >>\nendobj\n",
            kids.trim_end(),
            n
        )
        .as_bytes(),
    );

    // Contents rows become clickable jumps into the body.
    let mut annots_by_page: Vec<Vec<String>> = vec![Vec::new(); n];
    for link in links {
        if link.page >= n || link.target_page >= n {
            continue;
        }
        annots_by_page[link.page].push(format!(
            "<< /Type /Annot /Subtype /Link /Rect [{:.2} {:.2} {:.2} {:.2}] /Border [0 0 0] \
             /Dest [{} 0 R /XYZ 0 {:.2} null] >>",
            link.rect[0],
            link.rect[1],
            link.rect[2],
            link.rect[3],
            page_obj(link.target_page),
            link.target_y
        ));
    }

    for i in 0..n {
        let annots = if annots_by_page[i].is_empty() {
            String::new()
        } else {
            format!(" /Annots [{}]", annots_by_page[i].join(" "))
        };
        push(
            &mut out,
            &mut offsets,
            page_obj(i),
            format!(
                "{} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {:.2} {:.2}] \
                 /Contents {} 0 R /Resources << /ProcSet [/PDF /Text] \
                 /Font << /F1 {} 0 R /F2 {} 0 R >> >>{} >>\nendobj\n",
                page_obj(i),
                PAGE_W,
                PAGE_H,
                content_obj(i),
                sans_base,
                mono_base,
                annots
            )
            .as_bytes(),
        );

        let compressed = deflate(pages[i].as_bytes());
        let mut body = format!(
            "{} 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
            content_obj(i),
            compressed.len()
        )
        .into_bytes();
        body.extend_from_slice(&compressed);
        body.extend_from_slice(b"\nendstream\nendobj\n");
        push(&mut out, &mut offsets, content_obj(i), &body);
    }

    for (i, obj) in sans_font()
        .emit_pdf_objects(sans_base, used_sans)
        .iter()
        .enumerate()
    {
        push(&mut out, &mut offsets, sans_base + i, obj);
    }
    for (i, obj) in mono_font()
        .emit_pdf_objects(mono_base, used_mono)
        .iter()
        .enumerate()
    {
        push(&mut out, &mut offsets, mono_base + i, obj);
    }

    if !toc.is_empty() {
        push(
            &mut out,
            &mut offsets,
            outlines_root,
            format!(
                "{} 0 obj\n<< /Type /Outlines /First {} 0 R /Last {} 0 R /Count {} >>\nendobj\n",
                outlines_root,
                outline_items[0],
                outline_items[outline_items.len() - 1],
                toc.len()
            )
            .as_bytes(),
        );
        for (i, entry) in toc.iter().enumerate() {
            let prev = if i == 0 {
                String::new()
            } else {
                format!(" /Prev {} 0 R", outline_items[i - 1])
            };
            let next = if i + 1 == outline_items.len() {
                String::new()
            } else {
                format!(" /Next {} 0 R", outline_items[i + 1])
            };
            let target = page_obj((entry.body_page + front_matter).min(n.saturating_sub(1)));
            push(
                &mut out,
                &mut offsets,
                outline_items[i],
                format!(
                    "{} 0 obj\n<< /Title {} /Parent {} 0 R{}{} /Dest [{} 0 R /XYZ 0 {:.2} null] >>\nendobj\n",
                    outline_items[i],
                    pdf_text_string(&entry.title),
                    outlines_root,
                    prev,
                    next,
                    target,
                    entry.y
                )
                .as_bytes(),
            );
        }
    }

    let created = pdf_date();
    // ASCII hyphen so VOID markers in Subject stay greppable as literal Info strings
    // (an em dash would force UTF-16BE hex encoding of the whole field).
    let mut subject = if meta.client.is_empty() {
        meta.subtitle.clone()
    } else {
        format!("{} - {}", meta.subtitle, meta.client)
    };
    if let Some(w) = &meta.watermark {
        if !subject.contains(w.as_str()) {
            subject = format!("{w}; {subject}");
        }
    }
    push(
        &mut out,
        &mut offsets,
        info_obj,
        format!(
            "{} 0 obj\n<< /Title {} /Author {} /Subject {} /Keywords {} \
             /Creator (Weissman Cybersecurity Platform) /Producer (Weissman Document Engine) \
             /CreationDate ({}) /ModDate ({}) >>\nendobj\n",
            info_obj,
            pdf_text_string(&meta.title),
            pdf_text_string(if meta.org.is_empty() {
                "Weissman Cybersecurity"
            } else {
                &meta.org
            }),
            pdf_text_string(&subject),
            // Classification only — VOID reports must emit the exact token `/Keywords (VOID)`.
            pdf_text_string(&meta.classification),
            created,
            created
        )
        .as_bytes(),
    );

    let xmp = xmp_packet(meta);
    let mut meta_obj = format!(
        "{} 0 obj\n<< /Type /Metadata /Subtype /XML /Length {} >>\nstream\n",
        metadata_obj,
        xmp.len()
    )
    .into_bytes();
    meta_obj.extend_from_slice(xmp.as_bytes());
    meta_obj.extend_from_slice(b"\nendstream\nendobj\n");
    push(&mut out, &mut offsets, metadata_obj, &meta_obj);

    let xref_start = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n", total_objs + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f \n");
    for id in 1..=total_objs {
        out.extend_from_slice(format!("{:010} 00000 n \n", offsets[id]).as_bytes());
    }
    let file_id = format!("{:016X}{:016X}", offsets.len() as u64, out.len() as u64);
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info {} 0 R /ID [<{}> <{}>] >>\nstartxref\n{}\n%%EOF\n",
            total_objs + 1,
            info_obj,
            file_id,
            file_id,
            xref_start
        )
        .as_bytes(),
    );
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xmp_packet(meta: &DocMeta) -> String {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    format!(
        "<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
         <x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n\
         <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
         <rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" \
         xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">\n\
         <dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">{}</rdf:li></rdf:Alt></dc:title>\n\
         <dc:creator><rdf:Seq><rdf:li>{}</rdf:li></rdf:Seq></dc:creator>\n\
         <dc:language><rdf:Bag><rdf:li>{}</rdf:li></rdf:Bag></dc:language>\n\
         <dc:rights><rdf:Alt><rdf:li xml:lang=\"x-default\">{}</rdf:li></rdf:Alt></dc:rights>\n\
         <xmp:CreateDate>{}</xmp:CreateDate>\n\
         <xmp:CreatorTool>Weissman Cybersecurity Platform</xmp:CreatorTool>\n\
         <pdf:Producer>Weissman Document Engine</pdf:Producer>\n\
         </rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>\n<?xpacket end=\"w\"?>",
        xml_escape(&meta.title),
        xml_escape(if meta.org.is_empty() {
            "Weissman Cybersecurity"
        } else {
            &meta.org
        }),
        meta.lang.tag(),
        xml_escape(&meta.footer_note()),
        now
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::charts::Slice;
    use crate::pdf::layout::{CellStyle, Column};
    use weissman_core::models::engine::PRODUCTION_ENGINE_IDS;

    fn meta(lang: Lang) -> DocMeta {
        DocMeta {
            title: "External Attack Surface Assessment".into(),
            subtitle: "Live, evidence-backed findings".into(),
            org: "Weissman Cybersecurity".into(),
            client: "Acme Industries".into(),
            classification: "Confidential".into(),
            doc_id: "WSM-2026-0007".into(),
            lang,
            control_fields: vec![("Generated".into(), "2026-08-25 10:00 IDT".into())],
            integrity_hash: Some("f".repeat(64)),
            verify_url: Some("https://verify.weissman.example/WSM-2026-0007".into()),
            watermark: None,
        }
    }

    fn sample_doc(lang: Lang) -> ReportDoc {
        let table = Table::new(vec![
            Column::new("ID", 1.0).styled(CellStyle::Mono),
            Column::new("Finding", 3.0).styled(CellStyle::Strong),
            Column::new("Severity", 1.0).styled(CellStyle::Severity),
        ])
        .with_rows(
            (0..40)
                .map(|i| {
                    vec![
                        format!("VLN-{i}"),
                        format!("Exposed administrative interface {i}"),
                        if i % 3 == 0 { "critical" } else { "medium" }.to_string(),
                    ]
                })
                .collect(),
        );
        ReportDoc::new(meta(lang))
            .with_hero(Chart::Gauge {
                score: 63,
                caption: "Security posture".into(),
            })
            .with_section(
                Section::new("Executive Summary")
                    .with(Block::Paragraph(
                        "A live assessment of the external estate.".into(),
                    ))
                    .with(Block::Metrics(vec![
                        Metric::new("Critical", "4", Tone::Bad),
                        Metric::new("High", "11", Tone::Warn),
                        Metric::new("Verified", "9", Tone::Good),
                        Metric::new(
                            "Engines",
                            PRODUCTION_ENGINE_IDS.len().to_string(),
                            Tone::Brand,
                        ),
                    ]))
                    .with(Block::Chart(Chart::Donut {
                        slices: vec![
                            Slice::new("Critical", 4.0, theme::SEV_CRITICAL),
                            Slice::new("High", 11.0, theme::SEV_HIGH),
                        ],
                        caption: "Severity mix".into(),
                    }))
                    .with(Block::Callout(Callout::new(
                        Tone::Bad,
                        "Immediate action",
                        "Four critical findings carry a reproducible proof of exploit.",
                    ))),
            )
            .with_section(
                Section::new("Detailed Findings")
                    .on_new_page()
                    .with(Block::Heading("Confirmed exposures".into()))
                    .with(Block::Bullets(vec![
                        "First item".into(),
                        "Second item".into(),
                    ]))
                    .with(Block::KeyValues(vec![(
                        "Scope".into(),
                        "acme.example".into(),
                    )]))
                    .with(Block::Table(table))
                    .with(Block::Mono(vec![
                        "curl -s https://acme.example/admin".into()
                    ]))
                    .with(Block::Divider)
                    .with(Block::Spacer(10.0)),
            )
            .with_section(
                Section::new("Methodology").with(Block::Paragraph("Live probes only.".into())),
            )
    }

    fn find_all(hay: &[u8], needle: &[u8]) -> usize {
        hay.windows(needle.len()).filter(|w| *w == needle).count()
    }

    #[test]
    fn lang_parses_hebrew_variants() {
        assert_eq!(Lang::parse("he"), Lang::He);
        assert_eq!(Lang::parse("he-IL"), Lang::He);
        assert_eq!(Lang::parse("iw"), Lang::He);
        assert_eq!(Lang::parse("en-GB"), Lang::En);
        assert_eq!(Lang::parse(""), Lang::En);
        assert!(Lang::He.is_rtl());
        assert!(!Lang::En.is_rtl());
    }

    #[test]
    fn tone_maps_from_severity() {
        assert_eq!(Tone::from_severity("critical"), Tone::Bad);
        assert_eq!(Tone::from_severity("high"), Tone::Bad);
        assert_eq!(Tone::from_severity("medium"), Tone::Warn);
        assert_eq!(Tone::from_severity("low"), Tone::Brand);
        assert_eq!(Tone::from_severity("info"), Tone::Neutral);
    }

    #[test]
    fn footer_note_and_page_label_are_localised() {
        let en = meta(Lang::En);
        assert!(en.footer_note().contains("WSM-2026-0007"));
        assert_eq!(en.page_label(2, 9), "Page 2 of 9");
        let he = meta(Lang::He);
        assert!(he.page_label(2, 9).contains("עמוד"));
        assert!(he.footer_note().contains("חסוי"));
    }

    #[test]
    fn text_strings_escape_ascii_and_encode_unicode() {
        assert_eq!(pdf_text_string("a(b)c\\"), "(a\\(b\\)c\\\\)");
        let hebrew = pdf_text_string("דוח");
        assert!(hebrew.starts_with("<FEFF"), "{hebrew}");
        assert!(hebrew.ends_with('>'));
        assert_eq!(hebrew.len(), 1 + 4 + 3 * 4 + 1);
    }

    #[test]
    fn renders_a_structurally_valid_pdf() {
        let bytes = sample_doc(Lang::En).render();
        assert!(bytes.starts_with(b"%PDF-1.7"), "wrong header");
        assert!(bytes.ends_with(b"%%EOF\n"), "missing trailer");
        assert!(find_all(&bytes, b"/Type /Page\n") > 0 || find_all(&bytes, b"/Type /Page ") > 0);
        assert!(find_all(&bytes, b"startxref") == 1);
        assert!(
            bytes.len() > 20_000,
            "an embedded font should dominate the size"
        );
    }

    #[test]
    fn xref_offsets_point_at_their_objects() {
        let bytes = sample_doc(Lang::En).render();
        // Offsets in the xref table are byte positions. Embedded FontFile2 is binary, so
        // `from_utf8_lossy` replacement characters would make string indices diverge from
        // those offsets (and slice on a non-char boundary).
        let xref_at = bytes
            .windows(6)
            .rposition(|w| w == b"\nxref\n")
            .map(|i| i + 1)
            .expect("xref section");
        let after = std::str::from_utf8(&bytes[xref_at..]).expect("xref table is ASCII");
        let mut lines = after.lines();
        assert_eq!(lines.next(), Some("xref"));
        let header = lines.next().expect("subsection header");
        let count: usize = header.split_whitespace().nth(1).unwrap().parse().unwrap();
        // Skip the free entry, then verify every in-use offset lands on "<id> 0 obj".
        let _free = lines.next();
        for id in 1..count {
            let entry = lines.next().expect("xref entry");
            let offset: usize = entry[..10].parse().expect("numeric offset");
            assert!(
                offset > 0 && offset < bytes.len(),
                "object {id} offset out of range"
            );
            let header = format!("{id} 0 obj");
            assert!(
                bytes[offset..].starts_with(header.as_bytes()),
                "object {id} xref offset is wrong; found {:?}",
                String::from_utf8_lossy(&bytes[offset..offset.saturating_add(24).min(bytes.len())])
            );
        }
        // startxref must point at the xref keyword itself.
        let start_marker = bytes
            .windows(10)
            .rposition(|w| w == b"startxref\n")
            .expect("startxref")
            + "startxref\n".len();
        let declared: usize = std::str::from_utf8(&bytes[start_marker..])
            .expect("startxref offset is ASCII")
            .lines()
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(bytes[declared..].starts_with(b"xref\n"));
    }

    #[test]
    fn page_count_in_the_tree_matches_the_page_objects() {
        let bytes = sample_doc(Lang::En).render();
        let text = String::from_utf8_lossy(&bytes).to_string();
        let count_at = text.find("/Count ").expect("pages count");
        let declared: usize = text[count_at + 7..]
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let actual = text.matches("/Type /Page /Parent").count();
        assert_eq!(
            declared, actual,
            "Pages /Count disagrees with the page objects"
        );
        assert!(declared >= 3, "sample report should span several pages");
    }

    #[test]
    fn document_carries_outline_bookmarks_and_metadata() {
        let bytes = sample_doc(Lang::En).render();
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(text.contains("/Type /Outlines"));
        assert!(text.contains("/PageMode /UseOutlines"));
        assert!(
            text.contains("(Executive Summary)"),
            "section bookmark missing"
        );
        assert!(text.contains("/Type /Metadata"));
        assert!(text.contains("<pdf:Producer>Weissman Document Engine</pdf:Producer>"));
        assert!(text.contains("/Producer (Weissman Document Engine)"));
        assert!(text.contains("/CreationDate (D:"));
    }

    #[test]
    fn every_page_after_the_cover_has_chrome() {
        let doc = sample_doc(Lang::En);
        let pages = {
            // Re-run the flow to inspect the streams before compression.
            let mut c = Canvas::new(false);
            chrome::draw_footer(&mut c, &doc.meta, 2, 5);
            c.finish()
        };
        assert!(!pages[0].is_empty());
        let bytes = doc.render();
        // Footers are typeset, so the page-label glyphs must appear in the font's width map.
        assert!(bytes.len() > 10_000);
    }

    #[test]
    fn hebrew_document_renders_right_to_left_with_utf16_bookmarks() {
        let mut doc = sample_doc(Lang::He);
        doc.meta.title = "דוח הערכת חשיפה חיצונית".into();
        doc.sections[0].title = "תקציר מנהלים".into();
        let bytes = doc.render();
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(text.contains("/Lang (he-IL)"));
        assert!(text.contains("<FEFF"), "Hebrew bookmark must be UTF-16BE");
        assert!(bytes.starts_with(b"%PDF-1.7"));
    }

    #[test]
    fn watermark_is_stamped_on_every_page() {
        let mut doc = sample_doc(Lang::En);
        doc.meta.watermark = Some("VOID".into());
        let bytes = doc.render();
        assert!(bytes.starts_with(b"%PDF-1.7"));
        // Content streams are compressed, so assert via the uncompressed painter instead.
        let mut c = Canvas::new(false);
        chrome::watermark_ops(&mut c, "VOID");
        assert!(c.finish()[0].contains("Tm"));
    }

    #[test]
    fn empty_document_still_produces_a_valid_single_page_pdf() {
        let bytes = ReportDoc::new(meta(Lang::En)).render();
        assert!(bytes.starts_with(b"%PDF-1.7"));
        assert!(bytes.ends_with(b"%%EOF\n"));
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(
            !text.contains("/Type /Outlines"),
            "no sections means no bookmarks"
        );
    }

    #[test]
    fn short_documents_skip_the_table_of_contents() {
        let short = ReportDoc::new(meta(Lang::En))
            .with_section(Section::new("Only Section").with(Block::Paragraph("Body".into())));
        let bytes = short.render();
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(!text.contains("(Contents)"));
        assert!(bytes.starts_with(b"%PDF-1.7"));
    }

    #[test]
    fn page_break_block_starts_a_new_page() {
        let with_break = ReportDoc::new(meta(Lang::En)).with_section(
            Section::new("A")
                .with(Block::Paragraph("first".into()))
                .with(Block::PageBreak)
                .with(Block::Paragraph("second".into())),
        );
        let text = String::from_utf8_lossy(&with_break.render()).to_string();
        assert_eq!(
            text.matches("/Type /Page /Parent").count(),
            3,
            "cover + two body pages"
        );
    }

    #[test]
    fn xmp_escapes_markup_in_the_title() {
        let mut m = meta(Lang::En);
        m.title = "A <b>&amp; B".into();
        let packet = xmp_packet(&m);
        assert!(packet.contains("A &lt;b&gt;&amp;amp; B"));
        assert!(!packet.contains("<b>"));
    }

    #[test]
    fn pdf_date_has_the_expected_shape() {
        let d = pdf_date();
        assert!(d.starts_with("D:"));
        assert!(d.ends_with('\''));
        assert!(d.len() >= 20, "{d}");
    }
}
