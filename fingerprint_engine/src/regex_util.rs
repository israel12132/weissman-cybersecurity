//! Regex helpers: compile-once patterns use `OnceLock`; fallbacks avoid panic.

use regex::Regex;
use std::sync::OnceLock;

/// Empty intersection — matches no string (valid and stable in the `regex` crate).
const NEVER_PATTERNS: [&str; 3] = [r"[^\s\S]", r"a^", r".\A"];

static NEVER_MATCHES: OnceLock<Regex> = OnceLock::new();

fn compile_never_matches() -> Regex {
    for p in NEVER_PATTERNS {
        match Regex::new(p) {
            Ok(r) => return r,
            Err(e) => tracing::error!(target: "security_audit", "regex_util: pattern {p:?} rejected: {e}"),
        }
    }
    tracing::error!(target: "security_audit", "regex_util: all never-match patterns rejected");
    unreachable!("regex_util: NEVER_PATTERNS must include at least one valid pattern")
}

/// Returns a cloned regex that never matches any input (safe fallback when dynamic patterns fail).
#[inline]
pub fn never_matches() -> Regex {
    NEVER_MATCHES.get_or_init(compile_never_matches).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_matches_matches_nothing() {
        let r = never_matches();
        assert!(!r.is_match("hello"));
        assert!(!r.is_match(""));
        assert!(!r.is_match("any\nstring\t"));
    }
}
