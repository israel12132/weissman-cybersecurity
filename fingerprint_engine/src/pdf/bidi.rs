//! Logical → visual reordering for mixed Hebrew/Latin text.
//!
//! PDF has no bidirectional layout engine: a text-showing operator paints glyphs strictly
//! left to right in the order given. Hebrew therefore has to be reordered by the producer.
//! This is a focused implementation of the Unicode Bidirectional Algorithm (UAX #9) rules
//! W (numbers), N1/N2 (neutrals), L1 (trailing whitespace) and L2 (run reversal) — enough for
//! the report vocabulary of Hebrew, Latin, digits and punctuation, which need no cursive
//! shaping. Explicit embedding controls (RLE/LRE/PDF/RLI…) are intentionally not supported;
//! report content is plain text.

/// Paragraph / run direction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    Ltr,
    Rtl,
}

impl Dir {
    #[must_use]
    pub fn is_rtl(self) -> bool {
        self == Dir::Rtl
    }
}

/// Bidi character class, collapsed to the four categories the report vocabulary needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    /// Strong left-to-right.
    L,
    /// Strong right-to-left (Hebrew / Arabic).
    R,
    /// Numeric — always rendered left-to-right, even inside an RTL run.
    Num,
    /// Neutral or weak (whitespace, punctuation, symbols).
    N,
}

fn classify(c: char) -> Class {
    let cp = c as u32;
    match cp {
        // European digits and Arabic-Indic digits (must precede the Arabic block).
        0x0030..=0x0039 | 0x0660..=0x0669 | 0x06F0..=0x06F9 => Class::Num,
        // Hebrew, Hebrew presentation forms.
        0x0590..=0x05FF | 0xFB1D..=0xFB4F => Class::R,
        // Arabic and its presentation forms (shaping is out of scope, ordering is not).
        0x0600..=0x06FF | 0x0700..=0x074F | 0x0750..=0x077F | 0xFB50..=0xFDFF | 0xFE70..=0xFEFF => {
            Class::R
        }
        _ => {
            if c.is_alphabetic() {
                Class::L
            } else {
                Class::N
            }
        }
    }
}

/// `true` when the string contains at least one strong right-to-left character.
#[must_use]
pub fn contains_rtl(s: &str) -> bool {
    s.chars().any(|c| classify(c) == Class::R)
}

/// Paragraph direction from the first strong character (UAX #9 rule P2/P3).
#[must_use]
pub fn base_direction(s: &str) -> Dir {
    for c in s.chars() {
        match classify(c) {
            Class::L => return Dir::Ltr,
            Class::R => return Dir::Rtl,
            _ => {}
        }
    }
    Dir::Ltr
}

/// Mirrored form of a paired character, used when it resolves to an RTL level.
fn mirror(c: char) -> char {
    match c {
        '(' => ')',
        ')' => '(',
        '[' => ']',
        ']' => '[',
        '{' => '}',
        '}' => '{',
        '<' => '>',
        '>' => '<',
        '\u{00AB}' => '\u{00BB}',
        '\u{00BB}' => '\u{00AB}',
        '\u{2039}' => '\u{203A}',
        '\u{203A}' => '\u{2039}',
        other => other,
    }
}

/// Reorder one line from logical to visual order.
///
/// The result is meant to be handed straight to a PDF text-showing operator. Pure-LTR input
/// is returned untouched, so the overwhelmingly common English path costs one scan.
#[must_use]
pub fn to_visual(text: &str, base: Dir) -> String {
    if base == Dir::Ltr && !contains_rtl(text) {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n == 0 {
        return String::new();
    }
    let classes: Vec<Class> = chars.iter().map(|&c| classify(c)).collect();
    let base_level: u8 = if base.is_rtl() { 1 } else { 0 };
    // An LTR run inside an RTL paragraph nests one level deeper than the paragraph.
    let ltr_level: u8 = if base_level == 0 { 0 } else { 2 };
    let mut levels = vec![base_level; n];

    // W-rules: strong characters take their own direction; numbers stay left-to-right but
    // ride along with the surrounding strong context.
    let mut context = base;
    for i in 0..n {
        match classes[i] {
            Class::L => {
                levels[i] = ltr_level;
                context = Dir::Ltr;
            }
            Class::R => {
                levels[i] = 1;
                context = Dir::Rtl;
            }
            Class::Num => {
                levels[i] = if context.is_rtl() { 2 } else { ltr_level };
            }
            Class::N => {}
        }
    }

    // N1/N2: a run of neutrals between matching directions joins them, otherwise it falls
    // back to the paragraph direction. Numbers count as RTL for this purpose.
    let dir_of = |c: Class| match c {
        Class::L => Some(Dir::Ltr),
        Class::R | Class::Num => Some(Dir::Rtl),
        Class::N => None,
    };
    let mut i = 0;
    while i < n {
        if classes[i] != Class::N {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && classes[i] == Class::N {
            i += 1;
        }
        let before = (0..start).rev().find_map(|j| dir_of(classes[j]));
        let after = (i..n).find_map(|j| dir_of(classes[j]));
        let level = match (before, after) {
            (Some(a), Some(b)) if a == b => {
                if a.is_rtl() {
                    1
                } else {
                    ltr_level
                }
            }
            _ => base_level,
        };
        for slot in levels.iter_mut().take(i).skip(start) {
            *slot = level;
        }
    }

    // L1: trailing whitespace resets to the paragraph level so alignment stays predictable.
    for j in (0..n).rev() {
        if chars[j].is_whitespace() {
            levels[j] = base_level;
        } else {
            break;
        }
    }

    // L2: reverse contiguous runs, from the deepest level down to the lowest odd level.
    let mut visual = chars;
    let mut visual_levels = levels;
    let max_level = visual_levels.iter().copied().max().unwrap_or(base_level);
    let lowest_odd = visual_levels.iter().copied().filter(|l| l % 2 == 1).min();
    if let Some(lowest) = lowest_odd {
        for level in (lowest..=max_level).rev() {
            let mut i = 0;
            while i < n {
                if visual_levels[i] >= level {
                    let start = i;
                    while i < n && visual_levels[i] >= level {
                        i += 1;
                    }
                    visual[start..i].reverse();
                    visual_levels[start..i].reverse();
                } else {
                    i += 1;
                }
            }
        }
    }

    // L4: mirror paired punctuation that ended up in a right-to-left run.
    for (c, level) in visual.iter_mut().zip(visual_levels.iter()) {
        if level % 2 == 1 {
            *c = mirror(*c);
        }
    }
    visual.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pure_latin_is_untouched() {
        assert_eq!(
            to_visual("Weissman Cybersecurity", Dir::Ltr),
            "Weissman Cybersecurity"
        );
    }

    #[test]
    fn detects_rtl_content() {
        assert!(contains_rtl("דוח"));
        assert!(!contains_rtl("report 2026"));
        assert!(contains_rtl("report דוח"));
    }

    #[test]
    fn base_direction_uses_first_strong_character() {
        assert_eq!(base_direction("  \"דוח\""), Dir::Rtl);
        assert_eq!(base_direction("  (Report) דוח"), Dir::Ltr);
        assert_eq!(base_direction("2026 —"), Dir::Ltr);
    }

    #[test]
    fn hebrew_word_is_reversed_for_visual_order() {
        // "שלום" painted left-to-right must appear as its glyphs in reverse.
        assert_eq!(to_visual("שלום", Dir::Rtl), "םולש");
    }

    #[test]
    fn hebrew_word_order_reverses_but_latin_run_stays_readable() {
        let out = to_visual("דוח Weissman אבטחה", Dir::Rtl);
        // The embedded Latin token keeps its own left-to-right spelling.
        assert!(out.contains("Weissman"), "latin run corrupted: {out}");
        // Hebrew words are emitted reversed, and the later word comes first visually.
        assert!(out.starts_with("החטבא"), "rtl word order wrong: {out}");
        assert!(out.ends_with("חוד"), "rtl word order wrong: {out}");
    }

    #[test]
    fn digits_stay_left_to_right_inside_hebrew() {
        let out = to_visual("סה\"כ 1234 ממצאים", Dir::Rtl);
        assert!(out.contains("1234"), "digits must not be reversed: {out}");
    }

    #[test]
    fn numbers_ride_with_the_rtl_run_in_an_ltr_paragraph() {
        let out = to_visual("Total שלום 123", Dir::Ltr);
        assert!(out.starts_with("Total "), "ltr prefix must lead: {out}");
        assert!(out.contains("123"), "digits preserved: {out}");
        assert!(out.contains("םולש"), "hebrew reversed: {out}");
    }

    #[test]
    fn brackets_are_mirrored_in_rtl_runs() {
        let out = to_visual("(דוח)", Dir::Rtl);
        // The opening paren, now at the right-hand end, must render as an opening paren there.
        assert_eq!(out, "(חוד)");
    }

    #[test]
    fn neutrals_between_matching_directions_join_the_run() {
        let out = to_visual("אב, גד", Dir::Rtl);
        assert_eq!(out, "דג ,בא");
    }

    #[test]
    fn trailing_whitespace_keeps_base_level() {
        let out = to_visual("דוח  ", Dir::Rtl);
        assert!(out.ends_with("חוד"), "trailing space must not lead: {out}");
    }

    #[test]
    fn empty_and_neutral_only_input_is_safe() {
        assert_eq!(to_visual("", Dir::Rtl), "");
        assert_eq!(to_visual("---", Dir::Ltr), "---");
        assert_eq!(to_visual("---", Dir::Rtl), "---");
    }

    #[test]
    fn round_trips_character_count() {
        for s in ["דוח Weissman 2026", "שלום עולם", "mixed טקסט 42 text"] {
            for dir in [Dir::Ltr, Dir::Rtl] {
                assert_eq!(
                    to_visual(s, dir).chars().count(),
                    s.chars().count(),
                    "reordering must not add or drop characters"
                );
            }
        }
    }
}
