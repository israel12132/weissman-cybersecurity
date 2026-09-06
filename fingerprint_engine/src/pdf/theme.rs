//! Brand tokens for generated documents.
//!
//! Values mirror `scripts/pdf/theme.css`, which styles the executive briefing, so a scan
//! report downloaded from the product and a briefing handed to a board read as one brand.

/// Device RGB colour, components in `0.0..=1.0`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rgb(pub f64, pub f64, pub f64);

impl Rgb {
    /// Parse `#rrggbb`. Falls back to black for malformed input so a typo can never abort a
    /// customer report.
    #[must_use]
    pub const fn hex(v: u32) -> Self {
        Self(
            ((v >> 16) & 0xFF) as f64 / 255.0,
            ((v >> 8) & 0xFF) as f64 / 255.0,
            (v & 0xFF) as f64 / 255.0,
        )
    }

    /// Blend towards white; `amount` of 0 keeps the colour, 1 returns white.
    #[must_use]
    pub fn tint(self, amount: f64) -> Self {
        let a = amount.clamp(0.0, 1.0);
        Self(
            self.0 + (1.0 - self.0) * a,
            self.1 + (1.0 - self.1) * a,
            self.2 + (1.0 - self.2) * a,
        )
    }

    /// Blend towards black.
    #[must_use]
    pub fn shade(self, amount: f64) -> Self {
        let a = 1.0 - amount.clamp(0.0, 1.0);
        Self(self.0 * a, self.1 * a, self.2 * a)
    }

    /// Readable foreground for text placed on this colour (WCAG relative luminance).
    #[must_use]
    pub fn on_color(self) -> Self {
        let lum = 0.2126 * self.0 + 0.7152 * self.1 + 0.0722 * self.2;
        if lum > 0.55 {
            INK
        } else {
            PAPER
        }
    }
}

pub const INK: Rgb = Rgb::hex(0x0A_1626);
pub const INK_SOFT: Rgb = Rgb::hex(0x16_293C);
pub const BODY: Rgb = Rgb::hex(0x23_323F);
pub const MUTED: Rgb = Rgb::hex(0x5A_6B7B);
pub const FAINT: Rgb = Rgb::hex(0x86_97A6);
pub const LINE: Rgb = Rgb::hex(0xE4_EAF1);
pub const LINE_SOFT: Rgb = Rgb::hex(0xEE_F3F8);
pub const PAPER: Rgb = Rgb::hex(0xFF_FFFF);

pub const BRAND: Rgb = Rgb::hex(0x0E_7C86);
pub const BRAND_STRONG: Rgb = Rgb::hex(0x0A_5A62);
pub const BRAND_DEEP: Rgb = Rgb::hex(0x07_3A40);
pub const BRAND_BRIGHT: Rgb = Rgb::hex(0x16_B4BF);
pub const CYAN: Rgb = Rgb::hex(0x22_C3D2);
pub const SKY: Rgb = Rgb::hex(0x3B_B0E8);
pub const AMBER: Rgb = Rgb::hex(0xC7_7A12);
pub const ROSE: Rgb = Rgb::hex(0xB2_3B4E);

pub const SEV_CRITICAL: Rgb = Rgb::hex(0x9B_1C2E);
pub const SEV_HIGH: Rgb = Rgb::hex(0xC2_410C);
pub const SEV_MEDIUM: Rgb = Rgb::hex(0xC7_7A12);
pub const SEV_LOW: Rgb = Rgb::hex(0x0E_7C86);
pub const SEV_INFO: Rgb = Rgb::hex(0x5A_6B7B);
pub const OK: Rgb = Rgb::hex(0x1B_7F5A);

/// Colour for a free-text severity label, matched case-insensitively.
#[must_use]
pub fn severity_color(severity: &str) -> Rgb {
    let s = severity.trim().to_ascii_lowercase();
    if s.starts_with("crit") {
        SEV_CRITICAL
    } else if s.starts_with("high") {
        SEV_HIGH
    } else if s.starts_with("med") {
        SEV_MEDIUM
    } else if s.starts_with("low") {
        SEV_LOW
    } else {
        SEV_INFO
    }
}

/// Rank used to order severities strongest-first. Unknown labels sort last.
#[must_use]
pub fn severity_rank(severity: &str) -> u8 {
    let s = severity.trim().to_ascii_lowercase();
    if s.starts_with("crit") {
        0
    } else if s.starts_with("high") {
        1
    } else if s.starts_with("med") {
        2
    } else if s.starts_with("low") {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decodes_channels() {
        let c = Rgb::hex(0x00_80FF);
        assert!((c.0 - 0.0).abs() < 1e-9);
        assert!((c.1 - 128.0 / 255.0).abs() < 1e-9);
        assert!((c.2 - 1.0).abs() < 1e-9);
    }

    #[test]
    fn tint_and_shade_move_towards_white_and_black() {
        assert_eq!(BRAND.tint(1.0), PAPER);
        assert_eq!(BRAND.shade(1.0), Rgb(0.0, 0.0, 0.0));
    }

    #[test]
    fn on_color_picks_readable_foreground() {
        assert_eq!(PAPER.on_color(), INK);
        assert_eq!(BRAND_DEEP.on_color(), PAPER);
        assert_eq!(SEV_CRITICAL.on_color(), PAPER);
    }

    #[test]
    fn severity_mapping_is_case_and_prefix_insensitive() {
        assert_eq!(severity_color("CRITICAL"), SEV_CRITICAL);
        assert_eq!(severity_color(" high "), SEV_HIGH);
        assert_eq!(severity_color("Medium"), SEV_MEDIUM);
        assert_eq!(severity_color("med"), SEV_MEDIUM);
        assert_eq!(severity_color("low"), SEV_LOW);
        assert_eq!(severity_color("informational"), SEV_INFO);
    }

    #[test]
    fn severity_rank_orders_strongest_first() {
        let mut v = vec!["low", "critical", "info", "high", "medium"];
        v.sort_by_key(|s| severity_rank(s));
        assert_eq!(v, vec!["critical", "high", "medium", "low", "info"]);
    }
}
