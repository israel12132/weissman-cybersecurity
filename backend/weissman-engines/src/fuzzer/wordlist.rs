//! Fallback paths when no OpenAPI (Juice Shop, generic REST).
//! Recursive expansion appends high-yield segments to prefixes that returned a non-404 response.

/// Segments appended to “live” path prefixes for a second discovery wave (BFS-style, one level).
const RECURSIVE_DIR_SUFFIXES: &[&str] = &[
    "v1",
    "v2",
    "v3",
    "internal",
    "private",
    "admin",
    "debug",
    "test",
    "staging",
    "graphql",
    "swagger",
    "docs",
    "openapi.json",
    "api",
    "rest",
    "ws",
    "actuator",
    "actuator/health",
    "health",
    "metrics",
    "users",
    "user",
    "login",
    "signin",
    "signup",
    "register",
    "config",
    "backup",
    "uploads",
    "static",
    "assets",
    "api-docs",
    "v2/api-docs",
];

/// Given path prefixes that responded with something other than “gone”, synthesize child paths
/// for a deeper crawl (deduplicated, capped).
#[must_use]
pub fn expand_recursive_directory_paths(seed_paths: &[String], max_total: usize) -> Vec<String> {
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
            format!("/{}", base)
        };
        let norm = norm.trim_end_matches('/').to_string();
        for suf in RECURSIVE_DIR_SUFFIXES {
            let child = format!("{}/{}", norm, suf);
            if seen.insert(child.clone()) {
                out.push(child);
            }
            if out.len() >= max_total {
                return out;
            }
        }
    }
    out
}

/// Expanded path wordlist (same as legacy `pipeline_context::expanded_path_wordlist`).
#[must_use]
pub fn expanded_path_wordlist() -> Vec<String> {
    let paths: Vec<&str> = vec![
        "",
        "/",
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v1/users",
        "/rest",
        "/rest/user/login",
        "/rest/user/registration",
        "/rest/products",
        "/rest/basket/1",
        "/api/Users",
        "/api/Users/1",
        "/api/Users/2",
        "/api/Addresss",
        "/admin",
        "/admin/login",
        "/ftp",
        "/config",
        "/config/config.json",
        "/graphql",
        "/swagger",
        "/openapi.json",
        "/api-docs",
        "/v2/api-docs",
        "/login",
        "/register",
        "/health",
        "/metrics",
        "/actuator",
        "/actuator/health",
        "/.env",
        "/debug",
        "/api/Challenges",
        "/api/Feedbacks",
        "/api/SecurityQuestions",
    ];
    paths.into_iter().map(String::from).collect()
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
    fn wordlist_has_known_paths() {
        let w = expanded_path_wordlist();
        assert!(w.contains(&"/graphql".to_string()));
        assert!(w.contains(&"/.env".to_string()));
        assert!(w.len() > 20);
    }
}
