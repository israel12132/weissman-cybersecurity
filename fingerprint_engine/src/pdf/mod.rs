//! The Weissman document engine: board-grade PDF generation with no third-party PDF crate.
//!
//! Reports are described declaratively ([`doc::ReportDoc`] → [`doc::Section`] → [`doc::Block`])
//! and rendered by a shared pipeline that supplies the cover, running header and footer,
//! table of contents, outline bookmarks and integrity seal. Every report the product emits —
//! client assessment, board briefing, compliance packet, evidence pack, ad-hoc panel export —
//! goes through this one path, so they are typographically identical and bilingual by default.

pub mod bidi;
pub mod canvas;
pub mod charts;
pub mod chrome;
pub mod copy;
pub mod doc;
pub mod font;
pub mod fonts;
pub mod layout;
pub mod reports;
pub mod spec;
pub mod theme;

pub use doc::{Block, Callout, DocMeta, Lang, Metric, ReportDoc, Section};
pub use layout::{Column, Table};

/// Resolve report language from an explicit `lang` query and the `Accept-Language` header.
#[must_use]
pub fn lang_from_parts(query_lang: Option<&str>, accept_language: Option<&str>) -> Lang {
    if let Some(v) = query_lang.map(str::trim).filter(|s| !s.is_empty()) {
        return Lang::parse(v);
    }
    if let Some(v) = accept_language {
        if let Some(tag) = v.split(',').next() {
            return Lang::parse(tag);
        }
    }
    Lang::En
}
