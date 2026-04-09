//! Best-effort repair for small-model JSON (Qwen / Llama): markdown fences, outer object slicing with
//! brace balancing (fixes `first {` + `last }` grabbing wrong span), and a few trailing-comma passes.

use regex::Regex;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::LazyLock;

static TRAIL_COMMA_BEFORE_BRACE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r",\s*}").expect("regex"));
static TRAIL_COMMA_BEFORE_BRACKET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r",\s*]").expect("regex"));

/// Strip ``` / ```json fences and return the first block that looks like JSON.
#[must_use]
pub fn strip_fences_and_trim(raw: &str) -> String {
    let t = raw.trim();
    if !t.contains("```") {
        return t.to_string();
    }
    for block in t.split("```") {
        let b = block.trim();
        let b = b.strip_prefix("json").unwrap_or(b).trim();
        if b.starts_with('{') || b.starts_with('[') {
            return b.to_string();
        }
    }
    t.to_string()
}

/// Extract the first `{` … `}` span with proper string/escape awareness (nested objects safe).
#[must_use]
pub fn extract_balanced_object(raw: &str) -> Option<String> {
    let s = raw.trim();
    let start = s.find('{')?;
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for i in start..bytes.len() {
        let b = bytes[i];
        if in_str {
            if esc {
                esc = false;
                continue;
            }
            if b == b'\\' {
                esc = true;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(s[start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn relax_trailing_commas(mut s: String) -> String {
    for _ in 0..12 {
        let next = TRAIL_COMMA_BEFORE_BRACE.replace_all(&s, "}");
        let next = TRAIL_COMMA_BEFORE_BRACKET.replace_all(&next, "]");
        if next == s {
            break;
        }
        s = next.to_string();
    }
    s
}

/// Deserialize model output into `T`: strict parse, then fence strip, balanced extract, trailing-comma relax.
pub fn deserialize_llm_json<T: DeserializeOwned>(raw: &str) -> Result<T, String> {
    let t = strip_fences_and_trim(raw);
    if let Ok(v) = serde_json::from_str::<T>(&t) {
        return Ok(v);
    }
    if let Some(obj) = extract_balanced_object(&t) {
        if let Ok(v) = serde_json::from_str::<T>(&obj) {
            return Ok(v);
        }
        let relaxed = relax_trailing_commas(obj);
        if let Ok(v) = serde_json::from_str::<T>(&relaxed) {
            return Ok(v);
        }
    }
    Err("LLM output is not valid JSON for the expected schema".into())
}

/// [`Value`] helper for PoE-style parsers.
#[inline]
pub fn parse_value_from_llm(raw: &str) -> Result<Value, String> {
    deserialize_llm_json(raw)
}
