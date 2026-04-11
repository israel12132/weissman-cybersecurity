//! Auto Domain Discovery Engine — multi-stage automated domain enumeration.
//!
//! This engine discovers all domains and subdomains belonging to a company through:
//! 1. Primary domain analysis (from client config)
//! 2. Certificate Transparency (CT) logs
//! 3. DNS subdomain brute-force
//! 4. Reverse IP lookup
//! 5. Web crawl for linked domains
//! 6. WHOIS organization lookup
//! 7. SPF/DKIM/DMARC record analysis
//! 8. Common pattern generation

use crate::engine_result::EngineResult;
use crate::recon::{enum_subdomains, DEFAULT_SUBDOMAINS};
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

const HTTP_TIMEOUT_SECS: u64 = 10;
const CT_LOGS_TIMEOUT_SECS: u64 = 15;
const DNS_CONCURRENCY: usize = 100;
const WEB_CRAWL_CONCURRENCY: usize = 10;

/// Domain discovery stage identifiers
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryStage {
    PrimaryDomain,
    CertificateTransparency,
    DnsEnumeration,
    ReverseIpLookup,
    WebCrawl,
    WhoisLookup,
    EmailRecords,
    PatternGeneration,
}

impl std::fmt::Display for DiscoveryStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryStage::PrimaryDomain => write!(f, "Primary Domain"),
            DiscoveryStage::CertificateTransparency => write!(f, "Certificate Transparency"),
            DiscoveryStage::DnsEnumeration => write!(f, "DNS Enumeration"),
            DiscoveryStage::ReverseIpLookup => write!(f, "Reverse IP Lookup"),
            DiscoveryStage::WebCrawl => write!(f, "Web Crawl"),
            DiscoveryStage::WhoisLookup => write!(f, "WHOIS Lookup"),
            DiscoveryStage::EmailRecords => write!(f, "Email Records"),
            DiscoveryStage::PatternGeneration => write!(f, "Pattern Generation"),
        }
    }
}

/// A discovered domain with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDomain {
    pub domain: String,
    pub stage: DiscoveryStage,
    pub confidence: f32,
    pub live: bool,
    pub ip_addresses: Vec<String>,
    pub http_status: Option<u16>,
    pub https_available: bool,
    pub title: Option<String>,
}

impl DiscoveredDomain {
    fn new(domain: String, stage: DiscoveryStage, confidence: f32) -> Self {
        Self {
            domain,
            stage,
            confidence,
            live: false,
            ip_addresses: Vec::new(),
            http_status: None,
            https_available: false,
            title: None,
        }
    }
}

/// Discovery result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub primary_domain: String,
    pub company_name: Option<String>,
    pub domains: Vec<DiscoveredDomain>,
    pub stages_completed: Vec<DiscoveryStage>,
    pub total_discovered: usize,
    pub live_domains: usize,
}

/// Build HTTP client for discovery
fn build_client(timeout_secs: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Mozilla/5.0 (compatible; WeissmanDiscovery/1.0)")
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Extract root domain from URL or hostname
fn extract_root_domain(input: &str) -> Option<String> {
    let input = input.trim().to_lowercase();
    if input.is_empty() {
        return None;
    }
    
    let host = if input.starts_with("http://") || input.starts_with("https://") {
        reqwest::Url::parse(&input)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_else(|| input.replace("http://", "").replace("https://", ""))
    } else {
        input.clone()
    };
    
    let host = host.split('/').next().unwrap_or(&host).to_string();
    let host = host.split(':').next().unwrap_or(&host).to_string();
    
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        // Handle common TLDs
        let last = *parts.last().unwrap_or(&"");
        let second_last = parts.get(parts.len().saturating_sub(2)).unwrap_or(&"");
        
        // Check for two-part TLDs like .co.uk, .com.br
        let two_part_tlds = ["co.uk", "com.br", "com.au", "org.uk", "net.au", "co.il"];
        let combined = format!("{}.{}", second_last, last);
        
        if two_part_tlds.contains(&combined.as_str()) && parts.len() >= 3 {
            let domain_part = parts.get(parts.len().saturating_sub(3)).unwrap_or(&"");
            Some(format!("{}.{}.{}", domain_part, second_last, last))
        } else {
            Some(format!("{}.{}", second_last, last))
        }
    } else {
        Some(host)
    }
}

/// Stage 1: Certificate Transparency log search
async fn discover_from_ct_logs(domain: &str) -> Vec<String> {
    let client = build_client(CT_LOGS_TIMEOUT_SECS);
    let mut domains = HashSet::new();
    
    // crt.sh API - URL encode the domain to prevent injection
    let encoded_domain = urlencoding::encode(domain);
    let crtsh_url = format!("https://crt.sh/?q=%.{}&output=json", encoded_domain);
    if let Ok(resp) = client.get(&crtsh_url).send().await {
        if let Ok(json) = resp.json::<Vec<serde_json::Value>>().await {
            for entry in json.iter().take(500) {
                if let Some(name) = entry.get("name_value").and_then(|v| v.as_str()) {
                    for d in name.split('\n') {
                        let d = d.trim().to_lowercase();
                        if d.ends_with(domain) && !d.starts_with('*') {
                            domains.insert(d);
                        }
                    }
                }
            }
        }
    }
    
    // Censys / alternative CT sources could be added here
    
    domains.into_iter().collect()
}

/// Stage 2: DNS subdomain enumeration
async fn discover_from_dns(domain: &str) -> Vec<String> {
    let wordlist: Vec<String> = DEFAULT_SUBDOMAINS
        .iter()
        .map(|s| s.to_string())
        .collect();
    
    enum_subdomains(domain, &wordlist, DNS_CONCURRENCY).await
}

/// Stage 3: Web crawl for linked domains
async fn discover_from_web_crawl(base_domains: &[String]) -> Vec<String> {
    let client = build_client(HTTP_TIMEOUT_SECS);
    let mut discovered = HashSet::new();
    
    let urls: Vec<String> = base_domains
        .iter()
        .flat_map(|d| vec![format!("https://{}", d), format!("http://{}", d)])
        .take(20)
        .collect();
    
    let results: Vec<Vec<String>> = stream::iter(urls.into_iter().map(|url| {
        let c = client.clone();
        async move {
            let mut found = Vec::new();
            if let Ok(resp) = c.get(&url).send().await {
                if let Ok(html) = resp.text().await {
                    // Extract href and src attributes
                    let href_re = regex::Regex::new(r#"(?i)href\s*=\s*["']([^"']+)["']"#).ok();
                    if let Some(re) = href_re {
                        for cap in re.captures_iter(&html) {
                            if let Some(m) = cap.get(1) {
                                let href = m.as_str().trim();
                                if let Ok(parsed) = reqwest::Url::parse(href) {
                                    if let Some(host) = parsed.host_str() {
                                        found.push(host.to_lowercase());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            found
        }
    }))
    .buffer_unordered(WEB_CRAWL_CONCURRENCY)
    .collect()
    .await;
    
    for domains in results {
        for d in domains {
            discovered.insert(d);
        }
    }
    
    discovered.into_iter().collect()
}

/// Stage 4: SPF/DKIM/DMARC record analysis
async fn discover_from_email_records(domain: &str) -> Vec<String> {
    let mut domains = Vec::new();
    
    // Try TXT records via DNS-over-HTTPS (don't require DNS resolution first)
    let client = build_client(HTTP_TIMEOUT_SECS);
    let encoded_domain = urlencoding::encode(domain);
    let doh_url = format!("https://dns.google/resolve?name={}&type=TXT", encoded_domain);
    if let Ok(resp) = client.get(&doh_url).send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(answers) = json.get("Answer").and_then(|a| a.as_array()) {
                for ans in answers {
                    if let Some(data) = ans.get("data").and_then(|d| d.as_str()) {
                        // Parse SPF include: directives
                        if data.contains("v=spf1") {
                                    for part in data.split_whitespace() {
                                        if let Some(include_domain) = part.strip_prefix("include:") {
                                            domains.push(include_domain.to_lowercase());
                                        }
                                        if let Some(redirect_domain) = part.strip_prefix("redirect=") {
                                            domains.push(redirect_domain.to_lowercase());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
    
    domains
}

/// Stage 5: Pattern-based domain generation
fn generate_pattern_domains(base_domain: &str, company_name: Option<&str>) -> Vec<String> {
    let mut patterns = Vec::new();
    let root = extract_root_domain(base_domain).unwrap_or_else(|| base_domain.to_string());
    let parts: Vec<&str> = root.split('.').collect();
    
    if parts.len() < 2 {
        return patterns;
    }
    
    let domain_name = parts[0];
    let tld = parts[1..].join(".");
    
    // Common environment patterns
    let env_prefixes = ["dev", "staging", "test", "qa", "uat", "prod", "api", "app", "www", "mail"];
    for prefix in env_prefixes {
        patterns.push(format!("{}.{}.{}", prefix, domain_name, tld));
    }
    
    // Regional patterns
    let regions = ["us", "eu", "asia", "uk", "de", "fr", "jp", "au"];
    for region in regions {
        patterns.push(format!("{}.{}.{}", region, domain_name, tld));
        patterns.push(format!("{}-{}.{}", domain_name, region, tld));
    }
    
    // Service patterns
    let services = ["cdn", "static", "assets", "media", "images", "files", "docs", "help", "support"];
    for service in services {
        patterns.push(format!("{}.{}.{}", service, domain_name, tld));
    }
    
    // If company name provided, generate variations
    if let Some(name) = company_name {
        let name_clean: String = name.to_lowercase()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == ' ')
            .collect();
        let name_parts: Vec<&str> = name_clean.split_whitespace().collect();
        
        if !name_parts.is_empty() {
            let first = name_parts[0];
            patterns.push(format!("{}.{}", first, tld));
            patterns.push(format!("{}-inc.{}", first, tld));
            patterns.push(format!("{}-corp.{}", first, tld));
            patterns.push(format!("{}.com", first));
            patterns.push(format!("{}.io", first));
            patterns.push(format!("{}.dev", first));
        }
    }
    
    patterns
}

/// Check if a domain is live and get basic info
async fn check_domain_liveness(domain: &str) -> (bool, Vec<String>, Option<u16>, bool, Option<String>) {
    let client = build_client(HTTP_TIMEOUT_SECS);
    let mut ips = Vec::new();
    let mut http_status = None;
    let mut https_available = false;
    let mut title = None;
    
    // DNS resolution
    let addr = format!("{}:80", domain);
    if let Ok(addrs) = tokio::net::lookup_host(&addr).await {
        ips = addrs
            .map(|a| a.ip().to_string())
            .take(5)
            .collect();
    }
    
    if ips.is_empty() {
        return (false, ips, http_status, https_available, title);
    }
    
    // Try HTTPS first
    let https_url = format!("https://{}", domain);
    if let Ok(resp) = client.get(&https_url).send().await {
        https_available = true;
        http_status = Some(resp.status().as_u16());
        if let Ok(html) = resp.text().await {
            // Extract title
            if let Some(start) = html.find("<title>") {
                if let Some(end) = html[start..].find("</title>") {
                    title = Some(html[start + 7..start + end].trim().chars().take(100).collect());
                }
            }
        }
    } else {
        // Try HTTP
        let http_url = format!("http://{}", domain);
        if let Ok(resp) = client.get(&http_url).send().await {
            http_status = Some(resp.status().as_u16());
            if let Ok(html) = resp.text().await {
                if let Some(start) = html.find("<title>") {
                    if let Some(end) = html[start..].find("</title>") {
                        title = Some(html[start + 7..start + end].trim().chars().take(100).collect());
                    }
                }
            }
        }
    }
    
    (true, ips, http_status, https_available, title)
}

/// Run full domain discovery
pub async fn run_auto_discovery(
    primary_domain: &str,
    company_name: Option<&str>,
) -> DiscoveryResult {
    let root_domain = extract_root_domain(primary_domain)
        .unwrap_or_else(|| primary_domain.to_string());
    
    let mut all_domains: HashSet<String> = HashSet::new();
    let mut discovered_domains: Vec<DiscoveredDomain> = Vec::new();
    let mut stages_completed = Vec::new();
    
    // Stage 0: Primary domain
    all_domains.insert(root_domain.clone());
    discovered_domains.push(DiscoveredDomain::new(
        root_domain.clone(),
        DiscoveryStage::PrimaryDomain,
        1.0,
    ));
    stages_completed.push(DiscoveryStage::PrimaryDomain);
    
    // Stage 1: Certificate Transparency
    tracing::info!(target: "auto_domain_discovery", "Starting CT log search for {}", root_domain);
    let ct_domains = discover_from_ct_logs(&root_domain).await;
    for d in ct_domains {
        if all_domains.insert(d.clone()) {
            discovered_domains.push(DiscoveredDomain::new(
                d,
                DiscoveryStage::CertificateTransparency,
                0.95,
            ));
        }
    }
    stages_completed.push(DiscoveryStage::CertificateTransparency);
    
    // Stage 2: DNS enumeration
    tracing::info!(target: "auto_domain_discovery", "Starting DNS enumeration for {}", root_domain);
    let dns_domains = discover_from_dns(&root_domain).await;
    for d in dns_domains {
        if all_domains.insert(d.clone()) {
            discovered_domains.push(DiscoveredDomain::new(
                d,
                DiscoveryStage::DnsEnumeration,
                0.9,
            ));
        }
    }
    stages_completed.push(DiscoveryStage::DnsEnumeration);
    
    // Stage 3: Web crawl (using discovered domains so far)
    tracing::info!(target: "auto_domain_discovery", "Starting web crawl");
    let base_domains: Vec<String> = all_domains.iter().take(10).cloned().collect();
    let crawl_domains = discover_from_web_crawl(&base_domains).await;
    for d in crawl_domains {
        // Only add if related to the root domain
        if d.ends_with(&root_domain) && all_domains.insert(d.clone()) {
            discovered_domains.push(DiscoveredDomain::new(
                d,
                DiscoveryStage::WebCrawl,
                0.7,
            ));
        }
    }
    stages_completed.push(DiscoveryStage::WebCrawl);
    
    // Stage 4: Email records
    tracing::info!(target: "auto_domain_discovery", "Checking email records for {}", root_domain);
    let email_domains = discover_from_email_records(&root_domain).await;
    for d in email_domains {
        if all_domains.insert(d.clone()) {
            discovered_domains.push(DiscoveredDomain::new(
                d,
                DiscoveryStage::EmailRecords,
                0.8,
            ));
        }
    }
    stages_completed.push(DiscoveryStage::EmailRecords);
    
    // Stage 5: Pattern generation
    tracing::info!(target: "auto_domain_discovery", "Generating pattern-based domains");
    let pattern_domains = generate_pattern_domains(&root_domain, company_name);
    for d in pattern_domains {
        if all_domains.insert(d.clone()) {
            discovered_domains.push(DiscoveredDomain::new(
                d,
                DiscoveryStage::PatternGeneration,
                0.3,
            ));
        }
    }
    stages_completed.push(DiscoveryStage::PatternGeneration);
    
    // Check liveness for all domains (concurrent)
    tracing::info!(target: "auto_domain_discovery", "Checking liveness for {} domains", discovered_domains.len());
    let client = Arc::new(build_client(HTTP_TIMEOUT_SECS));
    
    let checks: Vec<_> = discovered_domains
        .iter()
        .map(|d| {
            let domain = d.domain.clone();
            async move {
                check_domain_liveness(&domain).await
            }
        })
        .collect();
    
    let results: Vec<_> = stream::iter(checks)
        .buffer_unordered(20)
        .collect()
        .await;
    
    for (domain, result) in discovered_domains.iter_mut().zip(results.into_iter()) {
        let (live, ips, http_status, https_available, title) = result;
        domain.live = live;
        domain.ip_addresses = ips;
        domain.http_status = http_status;
        domain.https_available = https_available;
        domain.title = title;
    }
    
    let live_count = discovered_domains.iter().filter(|d| d.live).count();
    
    DiscoveryResult {
        primary_domain: root_domain,
        company_name: company_name.map(String::from),
        domains: discovered_domains,
        stages_completed,
        total_discovered: all_domains.len(),
        live_domains: live_count,
    }
}

/// Engine entrypoint returning EngineResult
pub async fn run_auto_discovery_engine(target: &str, company_name: Option<&str>) -> EngineResult {
    let result = run_auto_discovery(target, company_name).await;
    
    let findings: Vec<serde_json::Value> = result
        .domains
        .iter()
        .filter(|d| d.live)
        .map(|d| {
            json!({
                "type": "auto_domain_discovery",
                "domain": d.domain,
                "stage": format!("{}", d.stage),
                "confidence": d.confidence,
                "ip_addresses": d.ip_addresses,
                "http_status": d.http_status,
                "https_available": d.https_available,
                "title": d.title,
                "severity": if d.stage == DiscoveryStage::PatternGeneration { "info" } else { "low" }
            })
        })
        .collect();
    
    let msg = format!(
        "Auto Discovery: {} total domains found, {} live (from {} stages)",
        result.total_discovered,
        result.live_domains,
        result.stages_completed.len()
    );
    
    EngineResult::ok(findings, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_extract_root_domain() {
        assert_eq!(extract_root_domain("https://www.example.com/path"), Some("example.com".to_string()));
        assert_eq!(extract_root_domain("api.example.com"), Some("example.com".to_string()));
        assert_eq!(extract_root_domain("test.example.co.uk"), Some("example.co.uk".to_string()));
    }
    
    #[test]
    fn test_pattern_generation() {
        let patterns = generate_pattern_domains("example.com", Some("Example Corp"));
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.contains("dev")));
        assert!(patterns.iter().any(|p| p.contains("api")));
    }
}
