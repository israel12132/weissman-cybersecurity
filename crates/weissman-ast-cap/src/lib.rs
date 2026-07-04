//! Cap and flatten AST mutation lines in WASM — O(n) single pass, minimal allocations.

#[cfg(feature = "wasm")]
mod wasm_exports;

#[cfg(feature = "wasm")]
pub use wasm_exports::*;

/// Core cap logic (shared with native tests).
pub fn cap_mutation_lines(lines: &[&str], max_nodes: usize, max_bytes: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for line in lines.iter().take(max_nodes) {
        let len = line.len();
        if bytes.saturating_add(len) > max_bytes {
            break;
        }
        bytes = bytes.saturating_add(len);
        out.push((*line).to_string());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_by_byte_budget() {
        let lines = vec!["aaaa", "bbbb", "cccc"];
        let capped = cap_mutation_lines(&lines, 100, 10);
        assert_eq!(capped.len(), 2);
    }
}
