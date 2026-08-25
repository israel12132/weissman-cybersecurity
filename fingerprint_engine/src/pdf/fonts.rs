//! The typefaces embedded in every Weissman document.
//!
//! Both faces ship in-tree (`fingerprint_engine/assets/fonts`, SIL Open Font License — see the
//! `LICENSE.md` beside them) so report generation never depends on host fonts and produces
//! byte-identical output on any machine. `Assistant` carries both Latin and Hebrew, which is
//! what makes bilingual reports possible at all; `JetBrains Mono` sets hashes, identifiers and
//! evidence excerpts where column alignment matters.

use super::font::TtfFont;
use std::sync::OnceLock;

static SANS_BYTES: &[u8] = include_bytes!("../../assets/fonts/Assistant.ttf");
static MONO_BYTES: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono.ttf");

/// Body/heading face — Latin + Hebrew.
pub fn sans_font() -> &'static TtfFont {
    static F: OnceLock<TtfFont> = OnceLock::new();
    F.get_or_init(|| {
        TtfFont::parse(SANS_BYTES, "Assistant", false)
            .expect("bundled Assistant.ttf must parse; it is a build artifact of this crate")
    })
}

/// Monospace face for hashes, ids and evidence.
pub fn mono_font() -> &'static TtfFont {
    static F: OnceLock<TtfFont> = OnceLock::new();
    F.get_or_init(|| {
        TtfFont::parse(MONO_BYTES, "JetBrainsMono", true)
            .expect("bundled JetBrainsMono.ttf must parse; it is a build artifact of this crate")
    })
}
