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
