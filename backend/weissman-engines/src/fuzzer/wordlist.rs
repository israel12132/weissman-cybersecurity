//! Fallback paths when no OpenAPI. Recursive expansion appends high-yield segments
//! to prefixes that returned a non-404 response. Seed lists live in `discovery_corpus`.

use crate::discovery_corpus;

/// Given path prefixes that responded with something other than “gone”, synthesize child paths
/// for a deeper crawl (deduplicated). `max_total == 0` means no cap.
#[must_use]
pub fn expand_recursive_directory_paths(seed_paths: &[String], max_total: usize) -> Vec<String> {
    let cap = if max_total == 0 {
        usize::MAX
    } else {
        max_total
    };
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::<String>::new();
    for seed in seed_paths {
        let base = seed.trim();
        if base.is_empty() {
            continue;
        }
        let norm = if base.starts_with('/') {
            base.to_string()
        } else {
            format!("/{base}")
        };
        let norm = norm.trim_end_matches('/').to_string();
        for suf in discovery_corpus::recursive_dir_suffixes() {
            let child = format!("{norm}/{suf}");
            if seen.insert(child.clone()) {
                out.push(child);
            }
            if out.len() >= cap {
                return out;
            }
        }
    }
    out
}

/// Public-knowledge HTTP path seed (unbounded corpus; tens of thousands of unique paths).
#[must_use]
pub fn expanded_path_wordlist() -> Vec<String> {
    discovery_corpus::expanded_path_wordlist()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_normalizes_and_dedups() {
        let seeds = vec!["api".to_string(), "/api/".to_string()];
        let out = expand_recursive_directory_paths(&seeds, 1000);
        assert!(out.contains(&"/api/v1".to_string()));
        let v1s = out.iter().filter(|p| p.as_str() == "/api/v1").count();
        assert_eq!(v1s, 1);
    }

    #[test]
    fn expand_respects_cap() {
        let seeds = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let out = expand_recursive_directory_paths(&seeds, 5);
        assert_eq!(out.len(), 5);
    }

    #[test]
    fn expand_skips_blank_seeds() {
        let seeds = vec!["  ".to_string(), String::new()];
        let out = expand_recursive_directory_paths(&seeds, 100);
        assert!(out.is_empty());
    }

    #[test]
    fn expand_zero_means_unlimited() {
        let seeds = vec!["a".to_string(), "b".to_string()];
        let capped = expand_recursive_directory_paths(&seeds, 5);
        let uncapped = expand_recursive_directory_paths(&seeds, 0);
        assert_eq!(capped.len(), 5);
        assert!(uncapped.len() > capped.len());
    }

    #[test]
    fn wordlist_has_known_paths() {
        let w = expanded_path_wordlist();
        assert!(w.contains(&"/graphql".to_string()));
        assert!(w.contains(&"/.env".to_string()));
        assert!(w.len() > 1_000);
    }
}
