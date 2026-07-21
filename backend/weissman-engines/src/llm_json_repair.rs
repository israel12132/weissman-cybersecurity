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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Demo {
        name: String,
        count: u32,
    }

    #[test]
    fn strip_fences_returns_inner_json_block() {
        let raw = "```json\n{\"name\":\"a\",\"count\":1}\n```";
        assert_eq!(strip_fences_and_trim(raw), "{\"name\":\"a\",\"count\":1}");
    }

    #[test]
    fn strip_fences_noop_without_fences() {
        assert_eq!(strip_fences_and_trim("  {\"x\":1}  "), "{\"x\":1}");
    }

    #[test]
    fn extract_balanced_object_ignores_braces_inside_strings() {
        let raw = "prefix {\"a\":{\"b\":\"}\"}} suffix";
        assert_eq!(
            extract_balanced_object(raw).unwrap(),
            "{\"a\":{\"b\":\"}\"}}"
        );
    }

    #[test]
    fn extract_balanced_object_none_when_unbalanced() {
        assert!(extract_balanced_object("{\"a\":1").is_none());
    }

    #[test]
    fn deserialize_strict_json() {
        let v: Demo = deserialize_llm_json("{\"name\":\"a\",\"count\":2}").unwrap();
        assert_eq!(
            v,
            Demo {
                name: "a".into(),
                count: 2
            }
        );
    }

    #[test]
    fn deserialize_recovers_from_fences_and_trailing_comma() {
        let raw = "here you go:\n```json\n{\"name\":\"z\",\"count\":3,}\n```\nthanks";
        let v: Demo = deserialize_llm_json(raw).unwrap();
        assert_eq!(
            v,
            Demo {
                name: "z".into(),
                count: 3
            }
        );
    }

    #[test]
    fn deserialize_errors_on_garbage() {
        let r: Result<Demo, String> = deserialize_llm_json("not json at all");
        assert!(r.is_err());
    }

    #[test]
    fn parse_value_reads_generic_object() {
        let v = parse_value_from_llm("{\"k\": [1,2,3]}").unwrap();
        assert_eq!(v["k"][2], serde_json::json!(3));
    }
}
