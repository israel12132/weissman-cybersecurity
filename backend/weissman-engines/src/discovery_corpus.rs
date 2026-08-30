//! Public-knowledge HTTP path and DNS prefix corpora.
//!
//! Seed files under `shared/discovery/` are generated from well-known URIs, CMS
//! panels, actuators, identity endpoints, and REST resource combinators so live
//! LLM generation does not spend tokens reinventing `/graphql` and `staging-api`.
//! The runtime corpus still grows without bound via `intel.discovery_knowledge`.

use std::sync::OnceLock;

const HTTP_PATHS_SEED: &str = include_str!("../../../shared/discovery/http_paths.txt");
const SUBDOMAIN_SEED: &str = include_str!("../../../shared/discovery/subdomain_prefixes.txt");
const RECURSIVE_SEED: &str = include_str!("../../../shared/discovery/recursive_suffixes.txt");

fn parse_lines(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in raw.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        if seen.insert(s.to_string()) {
            out.push(s.to_string());
        }
    }
    out
}

fn paths_lock() -> &'static [String] {
    static V: OnceLock<Vec<String>> = OnceLock::new();
    V.get_or_init(|| parse_lines(HTTP_PATHS_SEED))
}

fn subdomains_lock() -> &'static [String] {
    static V: OnceLock<Vec<String>> = OnceLock::new();
    V.get_or_init(|| parse_lines(SUBDOMAIN_SEED))
}

fn suffixes_lock() -> &'static [String] {
    static V: OnceLock<Vec<String>> = OnceLock::new();
    V.get_or_init(|| parse_lines(RECURSIVE_SEED))
}

/// Full public HTTP path seed (tens of thousands of unique paths). No cap.
#[must_use]
pub fn all_http_paths() -> &'static [String] {
    paths_lock()
}

/// Full public DNS subdomain-prefix seed. No cap.
#[must_use]
pub fn all_subdomain_prefixes() -> &'static [String] {
    subdomains_lock()
}

/// Child segments appended under live (non-404) prefixes.
#[must_use]
pub fn recursive_dir_suffixes() -> &'static [String] {
    suffixes_lock()
}

/// Same as [`all_http_paths`] as an owned vec (pipeline / fuzzer entry).
#[must_use]
pub fn expanded_path_wordlist() -> Vec<String> {
    all_http_paths().to_vec()
}

/// High-value leak/exposure paths (dotfiles, actuators, git, swagger) for ASM probes.
#[must_use]
pub fn sensitive_exposure_paths() -> Vec<String> {
    all_http_paths()
        .iter()
        .filter(|p| is_sensitive_exposure_path(p))
        .cloned()
        .collect()
}

#[must_use]
pub fn is_sensitive_exposure_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains(".env")
        || p.contains(".git")
        || p.contains("actuator")
        || p.contains("heapdump")
        || p.contains("swagger")
        || p.contains("openapi")
        || p.contains("graphql")
        || p.contains("phpinfo")
        || p.contains("server-status")
        || p.contains("wp-config")
        || p.contains("backup")
        || p.contains(".sql")
        || p.contains("phpmyadmin")
        || p.contains("adminer")
        || p.contains("debug/pprof")
        || p.contains(".well-known")
        || p.contains("telescope")
        || p.contains("h2-console")
        || p.contains("jolokia")
        || p.contains("wp-json/wp/v2/users")
        || p.contains("terraform.tfstate")
        || p.contains("id_rsa")
        || p.contains("docker-compose")
        || p.contains("kubeconfig")
        || p.contains("/.aws/")
        || p.contains("elmah")
        || p.contains("trace.axd")
}

/// Normalize a path candidate from LLM / crawl / seed into `/foo` form.
#[must_use]
pub fn normalize_http_path(raw: &str) -> Option<String> {
    let mut s = raw
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`');
    s = s.trim_start_matches('*').trim();
    if s.is_empty() || s.starts_with('#') || s.starts_with("//") {
        return None;
    }
    if let Some(rest) = s.strip_prefix("http://") {
        s = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
    }
    let s = s.split(['?', '#', ' ']).next().unwrap_or(s).trim();
    if s.is_empty() || s.len() > 500 {
        return None;
    }
    let path = if s.starts_with('/') {
        s.to_string()
    } else if s.contains('.') && !s.contains('/') {
        return None;
    } else {
        format!("/{s}")
    };
    if path == "//" || path.contains("://") {
        return None;
    }
    Some(path)
}

/// Normalize a DNS prefix (`api`, `staging-app`). Rejects empty / dotted FQDNs.
#[must_use]
pub fn normalize_subdomain_prefix(raw: &str) -> Option<String> {
    let s = raw
        .trim()
        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .trim_start_matches('*')
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if s.is_empty() || s.len() > 80 || s.starts_with('#') {
        return None;
    }
    if s.contains("://") || s.contains('/') || s.contains(' ') {
        return None;
    }
    // Nested labels like `dev.api` are useful; full FQDNs are not prefixes.
    if s.matches('.').count() >= 2 {
        return None;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return None;
    }
    if s.starts_with('.') || s.starts_with('-') || s.ends_with('-') {
        return None;
    }
    Some(s)
}

/// Probe budget for HTTP existence checks. `0` (default) means no software cap.
#[must_use]
pub fn discovery_probe_budget() -> usize {
    std::env::var("WEISSMAN_DISCOVERY_PROBE_BUDGET")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_paths_include_high_value() {
        let p = all_http_paths();
        assert!(p.len() > 5_000, "got {}", p.len());
        assert!(p.iter().any(|x| x == "/graphql"));
        assert!(p.iter().any(|x| x == "/.env"));
        assert!(p.iter().any(|x| x == "/actuator/heapdump"));
        assert!(p.iter().any(|x| x == "/.well-known/openid-configuration"));
        assert!(p.iter().any(|x| x == "/api/Challenges"));
    }

    #[test]
    fn seed_subdomains_include_high_value() {
        let s = all_subdomain_prefixes();
        assert!(s.len() > 2_000, "got {}", s.len());
        assert!(s.iter().any(|x| x == "www"));
        assert!(s.iter().any(|x| x == "api"));
        assert!(s.iter().any(|x| x == "staging-api"));
        assert!(s.iter().any(|x| x == "autodiscover"));
        assert!(s.iter().any(|x| x == "okta"));
    }

    #[test]
    fn normalize_path_and_prefix() {
        assert_eq!(normalize_http_path("graphql").as_deref(), Some("/graphql"));
        assert_eq!(normalize_http_path("/.env?x=1").as_deref(), Some("/.env"));
        assert!(normalize_http_path("").is_none());
        assert_eq!(normalize_subdomain_prefix("API").as_deref(), Some("api"));
        assert!(normalize_subdomain_prefix("https://evil").is_none());
    }

    #[test]
    fn sensitive_filter_hits_dotfiles() {
        assert!(is_sensitive_exposure_path("/.env"));
        assert!(is_sensitive_exposure_path("/actuator/heapdump"));
        assert!(!is_sensitive_exposure_path("/api/v1/users/1"));
    }
}
