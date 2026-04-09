//! Weissman-cybersecurity: Fast subdomain enumeration (multi-threaded DNS).
//! Used by recon_engine.py for attack surface discovery.

use std::sync::Arc;
use tokio::sync::Semaphore;

const DEFAULT_CONCURRENCY: usize = 200;

/// Default subdomain prefixes for brute-forcing (kept in sync with Python COMMON_SUBDOMAINS).
pub const DEFAULT_SUBDOMAINS: &[&str] = &[
    // Core web
    "www",
    "mail",
    "ftp",
    "smtp",
    "webmail",
    "email",
    "mx",
    "ns1",
    "ns2",
    // Admin / management
    "admin",
    "admin2",
    "superadmin",
    "root",
    "manage",
    "management",
    "portal",
    "console",
    "dashboard",
    "panel",
    "cpanel",
    "plesk",
    "webadmin",
    // API / app
    "api",
    "api2",
    "api-v2",
    "v1",
    "v2",
    "v3",
    "app",
    "app2",
    "apps",
    "service",
    "services",
    "gateway",
    "backend",
    // Dev / staging / test environments
    "dev",
    "dev2",
    "development",
    "staging",
    "stage",
    "stg",
    "test",
    "testing",
    "qa",
    "uat",
    "preprod",
    "pre-prod",
    "beta",
    "alpha",
    "sandbox",
    "demo",
    "lab",
    "labs",
    "local",
    "legacy",
    "old",
    "new",
    // Static / media
    "cdn",
    "static",
    "assets",
    "media",
    "images",
    "img",
    "files",
    "upload",
    "uploads",
    "content",
    "resources",
    "download",
    "downloads",
    // VCS / CI-CD
    "git",
    "gitlab",
    "github",
    "jenkins",
    "ci",
    "cd",
    "deploy",
    "build",
    "sonar",
    "nexus",
    "artifactory",
    "registry",
    // Documentation / community
    "docs",
    "wiki",
    "help",
    "support",
    "kb",
    "blog",
    "forum",
    "community",
    // Monitoring / observability
    "monitor",
    "monitoring",
    "status",
    "kibana",
    "grafana",
    "prometheus",
    "metrics",
    "logs",
    "alertmanager",
    "datadog",
    "newrelic",
    "jaeger",
    "zipkin",
    // Security tools
    "vault",
    "consul",
    "secrets",
    "auth",
    "sso",
    "login",
    "idp",
    "iam",
    "ldap",
    "ad",
    // Cloud / infra
    "cloud",
    "aws",
    "azure",
    "gcp",
    "k8s",
    "kubernetes",
    "cluster",
    "node",
    "worker",
    "traefik",
    "nginx",
    "proxy",
    "forward",
    "lb",
    "loadbalancer",
    // Database / messaging
    "db",
    "mysql",
    "postgres",
    "redis",
    "elastic",
    "kafka",
    "rabbit",
    "queue",
    "mq",
    // Business / payment
    "shop",
    "store",
    "payments",
    "pay",
    "billing",
    "checkout",
    "cart",
    "orders",
    "invoice",
    // Internal / extranet
    "internal",
    "intranet",
    "extranet",
    "vpn",
    "remote",
    "secure",
    // Misc
    "backup",
    "archive",
    "crm",
    "erp",
    "hr",
    "jira",
    "confluence",
    "slack",
    "chat",
    "video",
    "meet",
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
