//! Homoglyph folding, invisible-unicode strip, entropy, nested Base64/Hex decode.

use std::borrow::Cow;

pub struct Normalized {
    pub folded: String,
    pub homoglyphs: bool,
    pub invisible: bool,
}

/// Strip C0 controls (keep \n \t), zero-width / bidi overrides, and fold lookalikes.
/// JSON `\uXXXX` is unfolded and the stream is NFC-normalised first so a prompt
/// of `\u0073ystem prompt` cannot skip the Aho-Corasick needles.
#[must_use]
pub fn normalize(raw: &str) -> Normalized {
    use unicode_normalization::UnicodeNormalization;
    let unescaped = unescape_json_escapes(raw);
    let nfc: String = unescaped.nfc().collect();
    let mut out = String::with_capacity(nfc.len());
    let mut homoglyphs = false;
    let mut invisible = false;
    for ch in nfc.chars() {
        if is_invisible(ch) {
            invisible = true;
            continue;
        }
        if ch.is_control() && ch != '\n' && ch != '\t' {
            invisible = true;
            continue;
        }
        let folded = fold_homoglyph(ch);
        if folded != ch {
            homoglyphs = true;
        }
        out.push(folded);
    }
    Normalized {
        folded: out,
        homoglyphs,
        invisible,
    }
}

fn is_invisible(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}'
            | '\u{180E}' | '\u{2066}'..='\u{2069}' | '\u{202A}'..='\u{202E}' | '\u{200E}' | '\u{200F}'
    )
}

fn fold_homoglyph(ch: char) -> char {
    match ch {
        'А' | 'а' => 'a', // Cyrillic A
        'В' | 'в' => 'b',
        'Е' | 'е' => 'e',
        'К' | 'к' => 'k',
        'М' | 'м' => 'm',
        'Н' | 'н' => 'h',
        'О' | 'о' => 'o',
        'Р' | 'р' => 'p',
        'С' | 'с' => 'c',
        'Т' | 'т' => 't',
        'У' | 'у' => 'y',
        'Х' | 'х' => 'x',
        'І' | 'і' => 'i',
        'Ѕ' | 'ѕ' => 's',
        'Α' | 'α' => 'a', // Greek
        'Β' | 'β' => 'b',
        'Ε' | 'ε' => 'e',
        'Ι' | 'ι' => 'i',
        'Κ' | 'κ' => 'k',
        'Μ' | 'μ' => 'm',
        'Ν' | 'ν' => 'n',
        'Ο' | 'ο' => 'o',
        'Ρ' | 'ρ' => 'p',
        'Τ' | 'τ' => 't',
        'Χ' | 'χ' => 'x',
        'Υ' | 'υ' => 'y',
        '０'..='９' => char::from_u32(u32::from(ch) - 0xFF10 + u32::from('0')).unwrap_or(ch),
        'Ａ'..='Ｚ' => char::from_u32(u32::from(ch) - 0xFF21 + u32::from('A')).unwrap_or(ch),
        'ａ'..='ｚ' => char::from_u32(u32::from(ch) - 0xFF41 + u32::from('a')).unwrap_or(ch),
        other => other,
    }
}

/// Shannon entropy over bytes, bits/byte. Empty → 0.
#[must_use]
pub fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut hist = [0u32; 256];
    for b in bytes {
        hist[*b as usize] += 1;
    }
    let n = bytes.len() as f32;
    let mut h = 0.0f32;
    for c in hist {
        if c == 0 {
            continue;
        }
        let p = c as f32 / n;
        h -= p * p.log2();
    }
    h
}

/// Recursively peel Base64 / Hex layers. Always includes `seed` as layer 0.
#[must_use]
pub fn recursive_decode(seed: &str, max_depth: u8) -> Vec<String> {
    let mut out = Vec::with_capacity((max_depth as usize) + 1);
    out.push(seed.to_string());
    let mut current = Cow::Borrowed(seed);
    for _ in 0..max_depth {
        if let Some(decoded) = try_decode_layer(current.as_ref()) {
            if decoded == current.as_ref() || decoded.is_empty() {
                break;
            }
            out.push(decoded.clone());
            current = Cow::Owned(decoded);
        } else {
            break;
        }
    }
    out
}

fn try_decode_layer(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() < 8 {
        return None;
    }
    if looks_like_hex(t) {
        if let Some(text) = decode_hex_utf8(t) {
            return Some(text);
        }
    }
    if looks_like_base64(t) {
        if let Some(text) = decode_base64_utf8(t) {
            return Some(text);
        }
    }
    // Scan for an embedded base64/hex blob (payload smuggling inside prose).
    extract_embedded_blob(t)
}

fn looks_like_hex(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    compact.len() >= 16
        && compact.len() % 2 == 0
        && compact.bytes().all(|b| b.is_ascii_hexdigit())
}

fn looks_like_base64(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 16 || compact.len() % 4 != 0 {
        return false;
    }
    compact.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'-' || b == b'_'
    })
}

fn decode_hex_utf8(s: &str) -> Option<String> {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = decode_hex_bytes(&compact)?;
    String::from_utf8(bytes).ok().filter(|t| is_mostly_text(t))
}

fn decode_hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_base64_utf8(s: &str) -> Option<String> {
    let compact: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let bytes = decode_base64_bytes(&compact)?;
    String::from_utf8(bytes).ok().filter(|t| is_mostly_text(t))
}

fn decode_base64_bytes(s: &str) -> Option<Vec<u8>> {
    // Standard alphabet decode without extra crates (base64 is already a dep, but
    // keeping this path allocation-light and independent of padding quirks).
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }
    let raw = s.as_bytes();
    if raw.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < raw.len() || i < raw.len() {
        let b0 = *raw.get(i)?;
        let b1 = *raw.get(i + 1).unwrap_or(&b'A');
        let b2 = *raw.get(i + 2).unwrap_or(&b'=');
        let b3 = *raw.get(i + 3).unwrap_or(&b'=');
        let v0 = val(b0)?;
        let v1 = val(b1)?;
        let v2 = val(b2)?;
        let v3 = val(b3)?;
        out.push((v0 << 2) | (v1 >> 4));
        if b2 != b'=' {
            out.push((v1 << 4) | (v2 >> 2));
        }
        if b3 != b'=' {
            out.push((v2 << 6) | v3);
        }
        i += 4;
        if i >= raw.len() {
            break;
        }
    }
    Some(out)
}

fn extract_embedded_blob(s: &str) -> Option<String> {
    // Longest whitespace-free token that decodes as base64 or hex.
    let mut best: Option<String> = None;
    for token in s.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\'')) {
        if token.len() < 24 {
            continue;
        }
        if let Some(d) = decode_base64_utf8(token).or_else(|| decode_hex_utf8(token)) {
            if best.as_ref().map(|b| d.len() > b.len()).unwrap_or(true) {
                best = Some(d);
            }
        }
    }
    best
}

fn is_mostly_text(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
        .count();
    printable * 100 / s.chars().count().max(1) >= 85
}

/// Decode JSON-style `\uXXXX` / `\\n` sequences without requiring well-formed JSON.
#[must_use]
pub fn unescape_json_escapes(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                'u' if i + 5 < chars.len() => {
                    let hex: String = chars[i + 2..i + 6].iter().collect();
                    if let Ok(cp) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                            i += 6;
                            continue;
                        }
                    }
                    out.push(chars[i]);
                    i += 1;
                }
                'n' => {
                    out.push('\n');
                    i += 2;
                }
                't' => {
                    out.push('\t');
                    i += 2;
                }
                'r' => {
                    out.push('\r');
                    i += 2;
                }
                '"' | '\\' | '/' => {
                    out.push(chars[i + 1]);
                    i += 2;
                }
                _ => {
                    out.push(chars[i]);
                    i += 1;
                }
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// NFC + homoglyph fold + JSON-escape unfold. Used by inspect_output so a
/// truncated/invalid JSON completion cannot skip leak detection, and `\u0073ystem`
/// cannot hide `system` from the automaton. Shares [`normalize`] so Ask input
/// and planner output use the same stream.
#[must_use]
pub fn unfold_output_stream(raw: &str) -> String {
    normalize(raw).folded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zwsp_and_folds_cyrillic() {
        let n = normalize("іgnore\u{200B} previous");
        assert!(n.invisible);
        assert!(n.homoglyphs);
        assert!(n.folded.to_ascii_lowercase().contains("ignore"));
    }

    #[test]
    fn entropy_high_for_random() {
        let randish = "7f3a9c2e8b1d4f6a0c9e5b7d2a8f1c3e";
        assert!(shannon_entropy(randish.as_bytes()) > 3.5);
        assert!(shannon_entropy(b"aaaaaaaa") < 0.5);
    }

    #[test]
    fn decodes_base64_layer() {
        let layers = recursive_decode("aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==", 4);
        assert!(layers.iter().any(|l| l.to_ascii_lowercase().contains("ignore previous")));
    }

    #[test]
    fn unescapes_json_unicode_system() {
        let raw = r#"\u0073\u0079\u0073\u0074\u0065\u006d prompt:"#;
        let u = unescape_json_escapes(raw);
        assert!(u.to_ascii_lowercase().contains("system prompt:"));
        let folded = unfold_output_stream(raw);
        assert!(folded.to_ascii_lowercase().contains("system prompt:"));
    }
}
