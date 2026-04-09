//! Weissman-cybersecurity: Fast subdomain enumeration (multi-threaded DNS).
//! Used by recon_engine.py for attack surface discovery.

use std::sync::Arc;
use tokio::sync::Semaphore;

const DEFAULT_CONCURRENCY: usize = 200;

/// Default subdomain prefixes for brute-forcing (kept in sync with Python COMMON_SUBDOMAINS).
pub const DEFAULT_SUBDOMAINS: &[&str] = &[
    "www",
    "mail",
    "ftp",
    "admin",
    "api",
    "dev",
    "staging",
    "test",
    "beta",
    "app",
    "portal",
    "secure",
    "vpn",
    "git",
    "jenkins",
    "ci",
    "cdn",
    "static",
    "assets",
    "blog",
    "shop",
    "store",
    "support",
    "help",
    "docs",
    "wiki",
    "status",
    "monitor",
    "mx",
    "smtp",
    "ns1",
    "ns2",
    "webmail",
    "email",
    "cloud",
    "aws",
    "azure",
    "internal",
    "intranet",
    "extranet",
    "demo",
    "sandbox",
    "backup",
    "db",
    "mysql",
    "redis",
    "elastic",
    "kibana",
    "grafana",
    "prometheus",
    "gitlab",
    "jira",
];

/// Resolve one hostname; returns Some(hostname) if it resolves.
async fn resolve_one(host: &str) -> Option<String> {
    let host = host.trim().to_lowercase();
    if host.is_empty() {
        return None;
    }
    // lookup_host resolves the hostname (port can be any; we use 80 for HTTP)
    let addr = format!("{}:80", host);
    let addrs: Vec<_> = match tokio::net::lookup_host(addr.as_str()).await {
        Ok(iter) => iter.collect(),
        Err(_) => return None,
    };
    if addrs.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Enumerate subdomains for `domain` using `wordlist`. Uses a semaphore to limit concurrency.
/// Returns list of resolved subdomain hostnames (e.g. "www.example.com").
pub async fn enum_subdomains(domain: &str, wordlist: &[String], concurrency: usize) -> Vec<String> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() || wordlist.is_empty() {
        return vec![];
    }
    let sem = Arc::new(Semaphore::new(concurrency.min(500)));
    let mut handles = Vec::with_capacity(wordlist.len());
    for sub in wordlist {
        let sub = sub.trim().to_lowercase();
        if sub.is_empty() {
            continue;
        }
        let host = format!("{}.{}", sub, domain);
        let sem_clone = Arc::clone(&sem);
        let permit = sem_clone.acquire_owned().await;
        let handle = tokio::spawn(async move {
            let _permit = permit;
            resolve_one(&host).await
        });
        handles.push(handle);
    }
    let mut out = Vec::new();
    for h in handles {
        if let Ok(Some(host)) = h.await {
            out.push(host);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Run subdomain enumeration with default wordlist; returns JSON array of strings.
pub async fn enum_subdomains_default(domain: &str) -> Vec<String> {
    let wordlist: Vec<String> = DEFAULT_SUBDOMAINS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    enum_subdomains(domain, &wordlist, DEFAULT_CONCURRENCY).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_enum_empty_domain() {
        let r = enum_subdomains_default("").await;
        assert!(r.is_empty());
    }
}
