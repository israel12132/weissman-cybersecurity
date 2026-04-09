//! Active tech stack fingerprinting: HTTP headers + HTML meta.
//! Enterprise-grade: async port scanner (configurable top-N ports, semaphore-limited),
//! stealth headers (random User-Agent, Accept, Accept-Language) to reduce WAF detection.

use futures::future::join_all;
use ipnetwork::IpNetwork;
use rand::seq::SliceRandom;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

const REQUEST_TIMEOUT_SECS: u64 = 10;
const PORT_SCAN_TIMEOUT_SECS: u64 = 2;
const MAX_IPS_PER_CIDR: usize = 256;
/// Max concurrent port probes per IP to avoid overloading the local stack.
const PORT_SCAN_CONCURRENCY: usize = 500;
/// Default number of ports to scan (top-N by prevalence). Can be set up to 1000.
const DEFAULT_TOP_PORTS: usize = 1000;

/// Realistic User-Agent pool to rotate (reduces WAF/bot detection).
static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
];

/// Top 200 most common TCP ports (nmap-style prevalence), then 201..1000 for configurable "top 1000".
fn top_ports_list() -> Vec<u16> {
    let mut ports = vec![
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995,
        993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179,
        1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666,
        646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513,
        9900, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070,
        5190, 3000, 5432, 3986, 13, 1029, 9, 6646, 49157, 1028, 873, 49158, 1024, 11, 1755, 34855,
        8082, 6002, 5050, 17, 19, 8031, 1041, 255, 1048, 1049, 41025, 1045, 1046, 1050, 1051, 1052,
        1053, 1054, 1055, 1060, 1064, 1065, 1066, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075,
        1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
        1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 1104, 1105,
        1106, 1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119, 1120,
        1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129, 1130, 1131, 1132, 1133, 1134, 1135,
        1136, 1137, 1138, 1139, 1140, 1141, 1142, 1143, 1144, 1145, 1146, 1147, 1148, 1149, 1150,
        1151, 1152, 1153, 1154, 1155, 1156, 1157, 1158, 1159, 1160, 1161, 1162, 1163, 1164, 1165,
        1166, 1167, 1168, 1169, 1170, 1171, 1172, 1173, 1174, 1175, 1176, 1177, 1178, 1179, 1180,
        1181, 1182, 1183, 1184, 1185, 1186, 1187, 1188, 1189, 1190, 1191, 1192, 1193, 1194, 1195,
        1196, 1197, 1198, 1199, 1200,
    ];
    while ports.len() < DEFAULT_TOP_PORTS {
        ports.push((ports.len() + 1) as u16);
    }
    ports.truncate(DEFAULT_TOP_PORTS);
    ports
}

/// Standard web ports for quick scan (no --deep). Enterprise --deep uses top 1000.
const STANDARD_WEB_PORTS: [u16; 3] = [80, 443, 8080];

/// Returns the first `limit` ports from the top-1000 list (max 1000).
/// When limit is 3 or less, returns standard web ports [80, 443, 8080] for fast default scan.
pub fn get_top_ports(limit: usize) -> Vec<u16> {
    if limit <= 3 {
        return STANDARD_WEB_PORTS.to_vec();
    }
    let all = top_ports_list();
    let n = limit.min(all.len());
    all.into_iter().take(n).collect()
}

fn random_ua() -> &'static str {
    USER_AGENTS
        .choose(&mut rand::thread_rng())
        .unwrap_or(&USER_AGENTS[0])
}

/// Stealth request headers to avoid WAF/bot detection.
fn stealth_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("User-Agent", random_ua()),
        (
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
        ("Accept-Language", "en-US,en;q=0.9"),
    ]
}

/// Load proxy list from PROXIES_LIST (comma-separated) or PROXIES_FILE (one per line). Pick random for rotation.
fn random_proxy() -> Option<String> {
    let list: Vec<String> = if let Ok(env_list) = std::env::var("PROXIES_LIST") {
        env_list
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    } else {
        vec![]
    };
    let list = if list.is_empty() {
        let path = std::env::var("PROXIES_FILE").ok()?;
        let content = std::fs::read_to_string(&path).ok()?;
        content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect::<Vec<_>>()
    } else {
        list
    };
    if list.is_empty() {
        return None;
    }
    list.choose(&mut rand::thread_rng()).cloned()
}

/// Builds an HTTP client with timeout, invalid cert acceptance, stealth headers, and optional proxy rotation.
fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    for (k, v) in stealth_headers() {
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::try_from(k),
            reqwest::header::HeaderValue::try_from(v),
        ) {
            headers.insert(name, value);
        }
    }
    let _ = std::env::var("WEISSMAN_REGION");
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .default_headers(headers);
    if let Some(proxy_url) = random_proxy() {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url.as_str()) {
            builder = builder.proxy(proxy);
        }
    }
    builder.build()
}

/// Normalizes a technology string for cross-referencing (lowercase, strip version).
fn normalize_tech(s: &str) -> String {
    let s = s.trim().to_lowercase();
    let s = s.as_str();
    if let Some(slash) = s.find('/') {
        s[..slash].trim().to_string()
    } else if let Some(space) = s.find(' ') {
        s[..space].trim().to_string()
    } else {
        s.to_string()
    }
}

fn from_server_header(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    let product = v
        .split('/')
        .next()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        });
    product
}

fn from_x_powered_by(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    Some(normalize_tech(v))
}

fn from_meta_generator(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let re = match Regex::new(
        r#"(?i)<meta\s+name\s*=\s*["']generator["']\s+content\s*=\s*["']([^"']+)["']"#,
    ) {
        Ok(r) => r,
        Err(_) => return out,
    };
    for cap in re.captures_iter(html) {
        if let Some(m) = cap.get(1) {
            let s = normalize_tech(m.as_str());
            if !s.is_empty() {
                out.push(s);
            }
        }
    }
    out
}

/// Scheme for a given port (https for 443, 8443, 9443, 10443; else http).
fn scheme_for_port(port: u16) -> &'static str {
    if matches!(port, 443 | 8443 | 9443 | 10443) {
        "https"
    } else {
        "http"
    }
}

/// Performs one HTTP GET with optional Module 2 stealth (jitter, proxy, identity morphing).
pub async fn scan_target_tech(url: &str) -> Vec<String> {
    scan_target_tech_with_stealth(url, None).await
}

/// With optional stealth config (used by ASM when Ghost Network is enabled).
pub async fn scan_target_tech_with_stealth(
    url: &str,
    stealth: Option<&crate::stealth_engine::StealthConfig>,
) -> Vec<String> {
    let url = url.trim();
    if url.is_empty() {
        return Vec::new();
    }

    let full_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };

    let client = match stealth {
        Some(s) => {
            crate::stealth_engine::apply_jitter(s);
            crate::stealth_engine::build_client(s, REQUEST_TIMEOUT_SECS)
        }
        None => match build_client() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        },
    };

    let mut req = client.get(&full_url);
    if let Some(s) = stealth {
        req = req.headers(crate::stealth_engine::random_morph_headers(s));
    }
    let response = match req.send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut techs: HashSet<String> = HashSet::new();

    if let Some(v) = response.headers().get("server") {
        if let Ok(s) = v.to_str() {
            if let Some(t) = from_server_header(s) {
                techs.insert(t);
            }
        }
    }

    if let Some(v) = response.headers().get("x-powered-by") {
        if let Ok(s) = v.to_str() {
            if let Some(t) = from_x_powered_by(s) {
                techs.insert(t);
            }
        }
    }

    if let Ok(body) = response.text().await {
        for t in from_meta_generator(&body) {
            techs.insert(t);
        }
    }

    let mut out: Vec<String> = techs.into_iter().collect();
    out.sort();
    out
}

/// Scans multiple URLs concurrently and returns a map: url -> list of detected techs.
pub async fn scan_targets_concurrent(urls: &[String]) -> HashMap<String, Vec<String>> {
    scan_targets_concurrent_with_stealth(urls, None).await
}

/// With optional stealth config (used by ASM when Ghost Network is enabled).
pub async fn scan_targets_concurrent_with_stealth(
    urls: &[String],
    stealth: Option<&crate::stealth_engine::StealthConfig>,
) -> HashMap<String, Vec<String>> {
    let stealth_owned = stealth.cloned();
    let handles: Vec<_> = urls
        .iter()
        .map(|url| {
            let u = url.clone();
            let st = stealth_owned.clone();
            tokio::spawn(async move {
                let techs = scan_target_tech_with_stealth(&u, st.as_ref()).await;
                (u, techs)
            })
        })
        .collect();

    let results = join_all(handles).await;
    let mut map = HashMap::new();
    for (url, techs) in results.into_iter().flatten() {
        map.insert(url, techs);
    }
    map
}

async fn port_open_with_semaphore(ip: IpAddr, port: u16, sem: Arc<Semaphore>) -> Option<u16> {
    let _permit = sem.acquire().await.ok()?;
    let addr = (ip, port);
    let ok = tokio::time::timeout(
        Duration::from_secs(PORT_SCAN_TIMEOUT_SECS),
        TcpStream::connect(addr),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);
    if ok {
        Some(port)
    } else {
        None
    }
}

/// High-performance async port scan: checks `ports` on `ip` with semaphore-limited concurrency.
/// Returns list of open ports.
pub async fn scan_ports_async(ip: IpAddr, ports: &[u16], max_concurrent: usize) -> Vec<u16> {
    if ports.is_empty() {
        return Vec::new();
    }
    let sem = Arc::new(Semaphore::new(max_concurrent.min(PORT_SCAN_CONCURRENCY)));
    let mut tasks = Vec::with_capacity(ports.len());
    for &port in ports {
        let sem = Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            port_open_with_semaphore(ip, port, sem).await
        }));
    }
    let results = join_all(tasks).await;
    let mut open = Vec::new();
    for res in results {
        if let Ok(Some(p)) = res {
            open.push(p);
        }
    }
    open.sort_unstable();
    open
}

/// Build URLs from an IP and list of open ports (scheme by port: 443/8443/9443/10443 -> https).
fn urls_from_open_ports(ip: IpAddr, open_ports: &[u16]) -> Vec<String> {
    let mut urls = Vec::new();
    for &port in open_ports {
        let scheme = scheme_for_port(port);
        if port == 80 {
            urls.push(format!("http://{}", ip));
        } else if port == 443 {
            urls.push(format!("https://{}", ip));
        } else {
            urls.push(format!("{}://{}:{}", scheme, ip, port));
        }
    }
    urls
}

/// Expand a CIDR string to a list of IPs (at most MAX_IPS_PER_CIDR).
fn cidr_to_ips(cidr: &str) -> Vec<IpAddr> {
    let cidr = cidr.trim();
    if cidr.is_empty() {
        return Vec::new();
    }
    let net: IpNetwork = match cidr.parse() {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    net.iter().take(MAX_IPS_PER_CIDR).collect()
}

/// Scan an IP range (CIDR): async scan of configurable top ports (default top 1000) with semaphore,
/// then fingerprint each discovered HTTP(S) service.
pub async fn scan_ip_range(cidr: &str) -> HashMap<String, Vec<String>> {
    scan_ip_range_with_port_limit(cidr, DEFAULT_TOP_PORTS).await
}

/// Scan an IP range with a custom port limit (e.g. top 100, 500, 1000).
pub async fn scan_ip_range_with_port_limit(
    cidr: &str,
    port_limit: usize,
) -> HashMap<String, Vec<String>> {
    let ips = cidr_to_ips(cidr);
    if ips.is_empty() {
        return HashMap::new();
    }
    let ports = get_top_ports(port_limit);
    let mut all_urls: Vec<String> = Vec::new();
    for ip in ips {
        let open = scan_ports_async(ip, &ports, PORT_SCAN_CONCURRENCY).await;
        all_urls.extend(urls_from_open_ports(ip, &open));
    }
    if all_urls.is_empty() {
        return HashMap::new();
    }
    scan_targets_concurrent(&all_urls).await
}

/// Scan multiple CIDR ranges and merge results into one map.
pub async fn scan_ip_ranges_concurrent(cidrs: &[String]) -> HashMap<String, Vec<String>> {
    scan_ip_ranges_concurrent_with_port_limit(cidrs, DEFAULT_TOP_PORTS).await
}

/// Scan multiple CIDRs with custom port limit.
pub async fn scan_ip_ranges_concurrent_with_port_limit(
    cidrs: &[String],
    port_limit: usize,
) -> HashMap<String, Vec<String>> {
    let mut merged = HashMap::new();
    for cidr in cidrs {
        let cidr = cidr.trim();
        if cidr.is_empty() {
            continue;
        }
        let result = scan_ip_range_with_port_limit(cidr, port_limit).await;
        for (url, techs) in result {
            merged.insert(url, techs);
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_tech() {
        assert_eq!(normalize_tech("nginx/1.18.0"), "nginx");
        assert_eq!(normalize_tech("PHP/8.1"), "php");
    }

    #[test]
    fn test_from_server_header() {
        assert_eq!(from_server_header("nginx/1.18.0"), Some("nginx".into()));
        assert_eq!(from_server_header("cloudflare"), Some("cloudflare".into()));
    }

    #[test]
    fn test_from_meta_generator() {
        let html = r#"<meta name="generator" content="WordPress 6.2">"#;
        let v = from_meta_generator(html);
        assert!(!v.is_empty());
        assert!(v.iter().any(|s| s.contains("wordpress")));
    }

    #[test]
    fn test_get_top_ports() {
        let p = get_top_ports(10);
        assert_eq!(p.len(), 10);
        assert!(p.contains(&80));
        assert!(p.contains(&443));
        let p1000 = get_top_ports(1000);
        assert_eq!(p1000.len(), 1000);
    }

    #[test]
    fn test_scheme_for_port() {
        assert_eq!(scheme_for_port(443), "https");
        assert_eq!(scheme_for_port(8443), "https");
        assert_eq!(scheme_for_port(80), "http");
        assert_eq!(scheme_for_port(8080), "http");
    }
}
