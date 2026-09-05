//! TrueType parsing and PDF CID-font embedding for the Weissman document engine.
//!
//! The product previously drew every report with the base-14 `Helvetica` alias, which caps
//! output at Latin-1 and makes Hebrew physically unrepresentable. This module reads the
//! shipped TrueType files, measures real glyph advances, and emits a `Type0` / `CIDFontType2`
//! font with `Identity-H` encoding plus a `ToUnicode` CMap, so a rendered report is both
//! typographically correct and still selectable/searchable in a PDF reader.
//!
//! Only the tables required for layout and embedding are parsed (`head`, `hhea`, `maxp`,
//! `hmtx`, `cmap`, `OS/2`, `post`). Hebrew needs no cursive shaping, so a direct
//! codepoint → glyph-id mapping is sufficient; visual ordering is handled by [`super::bidi`].

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

fn be_u16(d: &[u8], off: usize) -> u16 {
    if off + 2 > d.len() {
        return 0;
    }
    u16::from_be_bytes([d[off], d[off + 1]])
}

fn be_i16(d: &[u8], off: usize) -> i16 {
    be_u16(d, off) as i16
}

fn be_u32(d: &[u8], off: usize) -> u32 {
    if off + 4 > d.len() {
        return 0;
    }
    u32::from_be_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

/// A parsed TrueType face plus everything the PDF writer needs to embed it.
pub struct TtfFont {
    data: &'static [u8],
    /// PostScript-safe name used as `/BaseFont`.
    pub base_name: String,
    pub units_per_em: u16,
    pub ascent: i16,
    pub descent: i16,
    pub cap_height: i16,
    pub bbox: [i16; 4],
    pub italic_angle: f64,
    pub stem_v: i32,
    pub fixed_pitch: bool,
    num_glyphs: u16,
    /// Unicode scalar → glyph id.
    cmap: HashMap<u32, u16>,
    /// Glyph id → first Unicode scalar that maps to it (for the `ToUnicode` CMap).
    reverse: BTreeMap<u16, u32>,
    /// Advance widths in font units, indexed by glyph id.
    advances: Vec<u16>,
}

impl TtfFont {
    /// Parse the subset of tables the engine needs. Returns `None` when the file is not a
    /// usable TrueType outline font, so a caller can fall back rather than emit a broken PDF.
    #[must_use]
    pub fn parse(data: &'static [u8], base_name: &str, fixed_pitch: bool) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let num_tables = be_u16(data, 4) as usize;
        let mut tables: HashMap<[u8; 4], (usize, usize)> = HashMap::new();
        for i in 0..num_tables {
            let rec = 12 + i * 16;
            if rec + 16 > data.len() {
                break;
            }
            let tag = [data[rec], data[rec + 1], data[rec + 2], data[rec + 3]];
            let off = be_u32(data, rec + 8) as usize;
            let len = be_u32(data, rec + 12) as usize;
            if off <= data.len() {
                tables.insert(tag, (off, len));
            }
        }

        let (head_off, _) = *tables.get(b"head")?;
        let units_per_em = be_u16(data, head_off + 18);
        if units_per_em == 0 {
            return None;
        }
        let bbox = [
            be_i16(data, head_off + 36),
            be_i16(data, head_off + 38),
            be_i16(data, head_off + 40),
            be_i16(data, head_off + 42),
        ];

        let (hhea_off, _) = *tables.get(b"hhea")?;
        let ascent = be_i16(data, hhea_off + 4);
        let descent = be_i16(data, hhea_off + 6);
        let num_h_metrics = be_u16(data, hhea_off + 34) as usize;

        let (maxp_off, _) = *tables.get(b"maxp")?;
        let num_glyphs = be_u16(data, maxp_off + 4);
        if num_glyphs == 0 {
            return None;
        }

        let (hmtx_off, _) = *tables.get(b"hmtx")?;
        let mut advances = Vec::with_capacity(num_glyphs as usize);
        let mut last = units_per_em / 2;
        for gid in 0..num_glyphs as usize {
            if gid < num_h_metrics {
                last = be_u16(data, hmtx_off + gid * 4);
            }
            advances.push(last);
        }

        // OS/2 carries cap height (v2+) and weight class; both are optional refinements.
        let mut cap_height = (ascent as f64 * 0.7) as i16;
        let mut weight_class = 400u16;
        if let Some(&(os2_off, os2_len)) = tables.get(b"OS/2") {
            weight_class = be_u16(data, os2_off + 4).clamp(100, 900);
            let version = be_u16(data, os2_off);
            if version >= 2 && os2_len >= 90 {
                let ch = be_i16(data, os2_off + 88);
                if ch > 0 {
                    cap_height = ch;
                }
            }
        }
        let italic_angle = tables
            .get(b"post")
            .map(|&(off, _)| f64::from(be_u32(data, off + 4) as i32) / 65536.0)
            .unwrap_or(0.0);
        // Widely used approximation: stem thickness tracks the square of relative weight.
        let stem_v = (50.0 + (f64::from(weight_class) / 100.0).powi(2) * 3.0).round() as i32;

        let (cmap_off, _) = *tables.get(b"cmap")?;
        let (cmap, reverse) = parse_cmap(data, cmap_off);
        if cmap.is_empty() {
            return None;
        }

        Some(Self {
            data,
            base_name: sanitize_base_name(base_name),
            units_per_em,
            ascent,
            descent,
            cap_height,
            bbox,
            italic_angle,
            stem_v,
            fixed_pitch,
            num_glyphs,
            cmap,
            reverse,
            advances,
        })
    }

    /// Glyph id for `ch`, falling back to the space glyph and finally `.notdef`.
    #[must_use]
    pub fn gid(&self, ch: char) -> u16 {
        if let Some(&g) = self.cmap.get(&(ch as u32)) {
            return g;
        }
        // Unmapped codepoints render as a space rather than a `.notdef` box, which reads far
        // better in a customer-facing document than a row of tofu.
        self.cmap.get(&0x20).copied().unwrap_or(0)
    }

    /// Advance width of `gid` in font units.
    #[must_use]
    pub fn advance(&self, gid: u16) -> u16 {
        self.advances
            .get(gid as usize)
            .copied()
            .unwrap_or(self.units_per_em / 2)
    }

    /// Width of `text` when set at `size` points.
    #[must_use]
    pub fn text_width(&self, text: &str, size: f64) -> f64 {
        let upem = f64::from(self.units_per_em);
        text.chars()
            .map(|c| f64::from(self.advance(self.gid(c))) / upem * size)
            .sum()
    }

    /// `Identity-H` hex string (`<0048...>`) for `text`, recording the glyphs it uses so the
    /// writer can emit a `W` array and `ToUnicode` map covering exactly what the document needs.
    #[must_use]
    pub fn encode(&self, text: &str, used: &mut BTreeSet<u16>) -> String {
        let mut out = String::with_capacity(text.len() * 4 + 2);
        out.push('<');
        for ch in text.chars() {
            let gid = self.gid(ch);
            used.insert(gid);
            out.push_str(&format!("{gid:04X}"));
        }
        out.push('>');
        out
    }

    /// Scale a font-unit metric into PDF glyph space (1000 units per em).
    fn to_glyph_space(&self, v: i32) -> i32 {
        (f64::from(v) * 1000.0 / f64::from(self.units_per_em)).round() as i32
    }

    /// Emit the five PDF objects for this font, numbered `base_id..base_id + 4`:
    /// `Type0`, `CIDFontType2`, `FontDescriptor`, `FontFile2` and `ToUnicode`.
    #[must_use]
    pub fn emit_pdf_objects(&self, base_id: usize, used: &BTreeSet<u16>) -> Vec<Vec<u8>> {
        let type0 = format!(
            "{} 0 obj\n<< /Type /Font /Subtype /Type0 /BaseFont /{} /Encoding /Identity-H \
             /DescendantFonts [{} 0 R] /ToUnicode {} 0 R >>\nendobj\n",
            base_id,
            self.base_name,
            base_id + 1,
            base_id + 4
        );

        let cid_font = format!(
            "{} 0 obj\n<< /Type /Font /Subtype /CIDFontType2 /BaseFont /{} \
             /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> \
             /FontDescriptor {} 0 R /DW {} /W [{}] /CIDToGIDMap /Identity >>\nendobj\n",
            base_id + 1,
            self.base_name,
            base_id + 2,
            self.to_glyph_space(i32::from(self.units_per_em / 2)),
            self.widths_array(used)
        );

        // Nonsymbolic (32) for text faces; add FixedPitch (1) for the monospace face.
        let flags = if self.fixed_pitch { 33 } else { 32 };
        let descriptor = format!(
            "{} 0 obj\n<< /Type /FontDescriptor /FontName /{} /Flags {} \
             /FontBBox [{} {} {} {}] /ItalicAngle {:.1} /Ascent {} /Descent {} /CapHeight {} \
             /StemV {} /FontFile2 {} 0 R >>\nendobj\n",
            base_id + 2,
            self.base_name,
            flags,
            self.to_glyph_space(i32::from(self.bbox[0])),
            self.to_glyph_space(i32::from(self.bbox[1])),
            self.to_glyph_space(i32::from(self.bbox[2])),
            self.to_glyph_space(i32::from(self.bbox[3])),
            self.italic_angle,
            self.to_glyph_space(i32::from(self.ascent)),
            self.to_glyph_space(i32::from(self.descent)),
            self.to_glyph_space(i32::from(self.cap_height)),
            self.stem_v,
            base_id + 3
        );

        let compressed = deflate(self.data);
        let mut font_file = format!(
            "{} 0 obj\n<< /Length {} /Length1 {} /Filter /FlateDecode >>\nstream\n",
            base_id + 3,
            compressed.len(),
            self.data.len()
        )
        .into_bytes();
        font_file.extend_from_slice(&compressed);
        font_file.extend_from_slice(b"\nendstream\nendobj\n");

        let cmap_body = self.to_unicode_cmap(used);
        let mut to_unicode = format!(
            "{} 0 obj\n<< /Length {} >>\nstream\n",
            base_id + 4,
            cmap_body.len()
        )
        .into_bytes();
        to_unicode.extend_from_slice(cmap_body.as_bytes());
        to_unicode.extend_from_slice(b"\nendstream\nendobj\n");

        vec![
            type0.into_bytes(),
            cid_font.into_bytes(),
            descriptor.into_bytes(),
            font_file,
            to_unicode,
        ]
    }

    /// `W` array covering only the glyphs the document actually used, collapsing consecutive
    /// glyph ids into a single `first [w w w]` run.
    fn widths_array(&self, used: &BTreeSet<u16>) -> String {
        let mut out = String::new();
        let mut run_start: Option<u16> = None;
        let mut run: Vec<i32> = Vec::new();
        let mut prev: Option<u16> = None;
        let flush = |start: Option<u16>, run: &mut Vec<i32>, out: &mut String| {
            if let Some(s) = start {
                if !run.is_empty() {
                    out.push_str(&format!("{} [", s));
                    for (i, w) in run.iter().enumerate() {
                        if i > 0 {
                            out.push(' ');
                        }
                        out.push_str(&w.to_string());
                    }
                    out.push_str("] ");
                }
            }
            run.clear();
        };
        for &gid in used {
            if gid >= self.num_glyphs {
                continue;
            }
            let contiguous = prev.is_some_and(|p| gid == p + 1);
            if !contiguous {
                flush(run_start, &mut run, &mut out);
                run_start = Some(gid);
            }
            run.push(self.to_glyph_space(i32::from(self.advance(gid))));
            prev = Some(gid);
        }
        flush(run_start, &mut run, &mut out);
        out.trim_end().to_string()
    }

    /// `ToUnicode` CMap so copy/paste and text extraction from the PDF return real text.
    fn to_unicode_cmap(&self, used: &BTreeSet<u16>) -> String {
        let mut pairs: Vec<(u16, u32)> = used
            .iter()
            .filter_map(|g| self.reverse.get(g).map(|&u| (*g, u)))
            .collect();
        pairs.sort_unstable();

        let mut body = String::from(
            "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
             /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
             /CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n\
             1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
        );
        // `bfchar` sections are capped at 100 entries by the PDF spec.
        for chunk in pairs.chunks(100) {
            body.push_str(&format!("{} beginbfchar\n", chunk.len()));
            for (gid, cp) in chunk {
                body.push_str(&format!("<{:04X}> <{}>\n", gid, utf16_be_hex(*cp)));
            }
            body.push_str("endbfchar\n");
        }
        body.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
        body
    }
}

/// UTF-16BE hex for a scalar, expanding to a surrogate pair above the BMP.
fn utf16_be_hex(cp: u32) -> String {
    if cp > 0xFFFF {
        let v = cp - 0x1_0000;
        let hi = 0xD800 + (v >> 10);
        let lo = 0xDC00 + (v & 0x3FF);
        format!("{hi:04X}{lo:04X}")
    } else {
        format!("{cp:04X}")
    }
}

/// `/BaseFont` names are PDF name objects: keep them to a conservative ASCII subset.
fn sanitize_base_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if cleaned.is_empty() {
        "WeissmanText".to_string()
    } else {
        cleaned
    }
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    // Writing to an in-memory Vec cannot fail; fall back to the raw bytes defensively.
    if enc.write_all(data).is_err() {
        return data.to_vec();
    }
    enc.finish().unwrap_or_else(|_| data.to_vec())
}

/// Pick the best available `cmap` subtable and build both mapping directions.
fn parse_cmap(data: &[u8], cmap_off: usize) -> (HashMap<u32, u16>, BTreeMap<u16, u32>) {
    let num_tables = be_u16(data, cmap_off + 2) as usize;
    let mut best: Option<(u32, usize)> = None;
    for i in 0..num_tables {
        let rec = cmap_off + 4 + i * 8;
        if rec + 8 > data.len() {
            break;
        }
        let platform = be_u16(data, rec);
        let encoding = be_u16(data, rec + 2);
        let offset = cmap_off + be_u32(data, rec + 4) as usize;
        // Prefer full Unicode (3,10) over BMP (3,1) over the legacy Unicode platform (0,x).
        let score = match (platform, encoding) {
            (3, 10) => 4,
            (0, 4 | 6) => 3,
            (3, 1) => 2,
            (0, _) => 1,
            _ => 0,
        };
        if score > 0 && best.is_none_or(|(s, _)| score > s) {
            best = Some((score, offset));
        }
    }
    let Some((_, off)) = best else {
        return (HashMap::new(), BTreeMap::new());
    };

    let mut map = HashMap::new();
    match be_u16(data, off) {
        4 => parse_cmap_format4(data, off, &mut map),
        12 => parse_cmap_format12(data, off, &mut map),
        _ => {}
    }
    let mut reverse = BTreeMap::new();
    for (&cp, &gid) in &map {
        reverse.entry(gid).or_insert(cp);
    }
    (map, reverse)
}

fn parse_cmap_format4(data: &[u8], off: usize, map: &mut HashMap<u32, u16>) {
    let seg_count = (be_u16(data, off + 6) / 2) as usize;
    if seg_count == 0 {
        return;
    }
    let end_codes = off + 14;
    let start_codes = end_codes + seg_count * 2 + 2;
    let id_deltas = start_codes + seg_count * 2;
    let id_range_offsets = id_deltas + seg_count * 2;

    for seg in 0..seg_count {
        let end = be_u16(data, end_codes + seg * 2);
        let start = be_u16(data, start_codes + seg * 2);
        if start > end {
            continue;
        }
        let delta = be_u16(data, id_deltas + seg * 2);
        let range_offset_pos = id_range_offsets + seg * 2;
        let range_offset = be_u16(data, range_offset_pos);
        for c in start..=end {
            if c == 0xFFFF {
                continue;
            }
            let gid = if range_offset == 0 {
                c.wrapping_add(delta)
            } else {
                let idx =
                    range_offset_pos + range_offset as usize + 2 * (c.wrapping_sub(start)) as usize;
                let g = be_u16(data, idx);
                if g == 0 {
                    continue;
                }
                g.wrapping_add(delta)
            };
            if gid != 0 {
                map.insert(u32::from(c), gid);
            }
        }
    }
}

fn parse_cmap_format12(data: &[u8], off: usize, map: &mut HashMap<u32, u16>) {
    let n_groups = be_u32(data, off + 12) as usize;
    for g in 0..n_groups {
        let rec = off + 16 + g * 12;
        if rec + 12 > data.len() {
            break;
        }
        let start = be_u32(data, rec);
        let end = be_u32(data, rec + 4);
        let start_gid = be_u32(data, rec + 8);
        if start > end || end.saturating_sub(start) > 0x1_0000 {
            continue;
        }
        for c in start..=end {
            let gid = start_gid + (c - start);
            if gid != 0 && gid <= u32::from(u16::MAX) {
                map.insert(c, gid as u16);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdf::fonts::{mono_font, sans_font};

    #[test]
    fn sans_font_parses_and_reports_sane_metrics() {
        let f = sans_font();
        assert!(f.units_per_em >= 1000, "unexpected upem {}", f.units_per_em);
        assert!(f.ascent > 0 && f.descent < 0);
        assert!(f.cap_height > 0);
    }

    #[test]
    fn sans_font_covers_latin_and_hebrew() {
        let f = sans_font();
        // A real mapping, not the space fallback, is required for both scripts.
        let space = f.gid(' ');
        for ch in ['W', 'e', 'i', '0', '9'] {
            assert_ne!(f.gid(ch), space, "latin {ch} unmapped");
        }
        for ch in ['א', 'ב', 'ש', 'ם', 'ת'] {
            assert_ne!(f.gid(ch), space, "hebrew {ch} unmapped");
        }
    }

    #[test]
    fn unmapped_codepoint_falls_back_to_space() {
        let f = sans_font();
        // A CJK ideograph is outside the Latin/Hebrew face coverage.
        assert_eq!(f.gid('漢'), f.gid(' '));
    }

    #[test]
    fn text_width_scales_with_size_and_length() {
        let f = sans_font();
        let one = f.text_width("Weissman", 10.0);
        let double = f.text_width("Weissman", 20.0);
        assert!((double - one * 2.0).abs() < 0.001);
        assert!(f.text_width("WeissmanWeissman", 10.0) > one);
    }

    #[test]
    fn mono_font_advances_are_uniform() {
        let f = mono_font();
        let a = f.advance(f.gid('i'));
        let b = f.advance(f.gid('W'));
        assert_eq!(a, b, "monospace face must have a single advance");
    }

    #[test]
    fn encode_emits_identity_h_hex_and_records_glyphs() {
        let f = sans_font();
        let mut used = BTreeSet::new();
        let hex = f.encode("Wi", &mut used);
        assert!(hex.starts_with('<') && hex.ends_with('>'));
        assert_eq!(hex.len(), 2 + 8, "two glyphs = eight hex digits");
        assert_eq!(used.len(), 2);
    }

    #[test]
    fn widths_array_collapses_contiguous_glyph_runs() {
        let f = sans_font();
        let used: BTreeSet<u16> = [10u16, 11, 12, 40].into_iter().collect();
        let w = f.widths_array(&used);
        assert!(w.starts_with("10 ["), "expected a run starting at 10: {w}");
        assert!(w.contains("40 ["), "expected a separate run at 40: {w}");
    }

    #[test]
    fn to_unicode_cmap_is_well_formed() {
        let f = sans_font();
        let mut used = BTreeSet::new();
        let _ = f.encode("שלום Weissman", &mut used);
        let cmap = f.to_unicode_cmap(&used);
        assert!(cmap.contains("begincmap") && cmap.contains("endcmap"));
        assert!(cmap.contains("beginbfchar"));
        assert!(
            cmap.contains("<05E9>"),
            "hebrew shin must round-trip: {cmap}"
        );
    }

    #[test]
    fn emits_five_linked_font_objects() {
        let f = sans_font();
        let mut used = BTreeSet::new();
        let _ = f.encode("Weissman", &mut used);
        let objs = f.emit_pdf_objects(20, &used);
        assert_eq!(objs.len(), 5);
        let type0 = String::from_utf8_lossy(&objs[0]).to_string();
        assert!(type0.contains("/Subtype /Type0"));
        assert!(type0.contains("/Encoding /Identity-H"));
        assert!(type0.contains("[21 0 R]"), "descendant link: {type0}");
        assert!(type0.contains("24 0 R"), "tounicode link: {type0}");
        let cid = String::from_utf8_lossy(&objs[1]).to_string();
        assert!(cid.contains("/CIDToGIDMap /Identity"));
        // FontFile2 must carry both the deflated length and the original length.
        let file = String::from_utf8_lossy(&objs[3]).to_string();
        assert!(file.contains("/Filter /FlateDecode"));
        assert!(file.contains(&format!("/Length1 {}", f.data.len())));
    }

    #[test]
    fn utf16_hex_handles_bmp_and_astral() {
        assert_eq!(utf16_be_hex(0x05D0), "05D0");
        assert_eq!(utf16_be_hex(0x1_F600), "D83DDE00");
    }

    #[test]
    fn base_name_is_sanitized() {
        assert_eq!(sanitize_base_name("Assistant Regular"), "AssistantRegular");
        assert_eq!(sanitize_base_name("()<>"), "WeissmanText");
    }
}
