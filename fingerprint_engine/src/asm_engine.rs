//! ASM — External Attack Surface Management (EASM).
//!
//! A world-class, agentless external attack-surface engine in the spirit of the flagship EASM
//! products (Wiz, Palo Alto Cortex Xpanse, Microsoft Defender EASM, CrowdStrike Falcon Surface,
//! Censys). It discovers an organisation's internet-facing footprint and continuously measures its
//! exposure — every signal comes from a *real* probe (DNS, TLS, HTTP, TCP, Certificate Transparency),
//! nothing is fabricated.
//!
//! ## What it knows ("breadth")
//!   * **Asset discovery** — passive subdomain discovery via Certificate Transparency (crt.sh) plus
//!     active DNS brute-force, deduplicated into a live inventory.
//!   * **DNS intelligence** — A/AAAA/CNAME/MX/NS/TXT records, wildcard and dangling-record signals.
//!   * **Email-security posture** — SPF, DMARC, DKIM/MX hygiene (spoofability).
//!   * **Service exposure** — TCP port/service exposure with risk-rated classification.
//!   * **TLS / certificate posture** — protocol version, expiry, self-signed, SAN sprawl.
//!   * **HTTP posture** — security headers, version/tech disclosure, insecure cookies, redirects.
//!   * **Cloud footprint** — provider attribution (AWS/Azure/GCP/Cloudflare/…) and exposed storage.
//!   * **Subdomain takeover** — dangling CNAMEs pointing at reclaimable third-party services.
//!   * **Shadow IT signals** — dev/staging/admin/vpn/jenkins-style hosts in the live inventory.
//!   * **Well-known surfaces** — `security.txt`, cleartext HTTP without TLS upgrade.
//!   * **DNS hardening** — wildcard detection, CAA coverage gaps.
//!   * **RDAP / registration intel** — registrar, nameservers, domain lifecycle (live RDAP).
//!   * **IP → ASN enrichment** — Team Cymru DNS origin lookup for every apex A record.
//!   * **TCP service banners** — real post-connect reads (SSH, SMTP, HTTP, Redis, …).
//!   * **Sensitive path exposure** — read-only probes for high-value admin/API leaks.
//!   * **CORS misconfiguration** — reflects arbitrary `Origin` when misconfigured.
//!   * **robots.txt intelligence** — surfaces disallowed admin/backup paths for review.
//!   * **DKIM discovery** — live TXT lookups for common selector names.
//!
//! ## What it does ("depth")
//!   * Correlates every asset into an **Attack-Surface Graph** (nodes + edges) for the UI.
//!   * Synthesises **exposure attack paths** (toxic combinations) — e.g. internet DB + weak email,
//!     takeover-prone CNAME + admin subdomain, cleartext HTTP on production apex.
//!   * Computes an **Attack-Surface Score** (0–100 + grade), a **priority remediation queue**,
//!     and an exposure breakdown for executive reporting.
//!
//! Every knob is driven from the live scan request body (`POST /api/command-center/scan` →
//! [`EngineRunContext::job_params`]) so an operator can tune the entire assessment — ports, discovery
//! sources, per-module toggles, depth caps, timeouts, severity threshold — with no code change.
//!
//! MITRE: T1595 (Active Scanning), T1590 (Gather Victim Network Info), T1592 (Gather Victim Host
//! Info), T1190 (Exploit Public-Facing Application), T1583.001 (Acquire Infrastructure: Domains).

use crate::cloud_hunter;
use crate::engine_dispatch::EngineRunContext;
use crate::engine_result::{print_result, EngineResult};
use crate::fingerprint::scan_targets_concurrent_with_stealth;
use crate::recon::{enum_subdomains, enum_subdomains_default, DEFAULT_SUBDOMAINS};
use futures::future::join_all;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// Fast-fail dead ports; full connect attempt budget is still large when scanning many hosts in parallel upstream.
const PORT_TIMEOUT_MS: u64 = 500;
/// Default ports: classic attack surface plus common cloud / API / observability / dev ports.
pub const TOP_PORTS: [u16; 63] = [
    // Web / API / reverse proxies
    80, 443, 8080, 8443, 8008, 8888, 9443, 3000, 3001, 4200, 5000, 5001, 8000, 8001, 8181,
    // Monitoring / observability / admin UIs
    5601, 5602, 6333, 7474, 7687, 9090, 9091, // Classic insecure services
    22, 21, 23, 25, 53, 111, 135, 139, 445, 1433, 3389, 5900, // SQL databases
    3306, 5432, 1521, 1434, // NoSQL / cache / search
    27017, 6379, 9200, 9300, 5984, 11211, 28017, // Message queues / streaming
    5672, 15672, 4369, 9092, 2181, // Container / orchestration
    2375, 4243, 6443, 10250, 10255, 2376, // Service mesh / secrets / config
    8200, 8500, 8300, 8301, // Dev / CI / misc
    9000, 50000, 8161,
];

fn target_to_host(target: &str) -> Option<String> {
    let target = target.trim().to_lowercase();
    if target.is_empty() {
        return None;
    }
    if let Some(rest) = target.strip_prefix("http://") {
        return Some(rest.split('/').next().unwrap_or(rest).to_string());
    }
    if let Some(rest) = target.strip_prefix("https://") {
        return Some(rest.split('/').next().unwrap_or(rest).to_string());
    }
    Some(target.split('/').next().unwrap_or(&target).to_string())
}

async fn port_open(host: &str, port: u16, timeout_ms: u64) -> bool {
    let timeout = Duration::from_millis(timeout_ms);
    if let Ok(addr) = format!("{}:{}", host, port).parse::<SocketAddr>() {
        return matches!(
            tokio::time::timeout(timeout, TcpStream::connect(addr)).await,
            Ok(Ok(_))
        );
    }
    matches!(
        tokio::time::timeout(timeout, TcpStream::connect((host, port))).await,
        Ok(Ok(_))
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Backward-compatible entry points (preserved for existing callers).
// ─────────────────────────────────────────────────────────────────────────────

pub async fn run_asm_result(target: &str) -> EngineResult {
    run_asm_result_with_ports_and_subdomains(target, &TOP_PORTS, None, None).await
}

/// ASM with configurable ports, optional subdomain prefixes, and optional stealth (Ghost Network).
pub async fn run_asm_result_with_ports_and_subdomains(
    target: &str,
    ports: &[u16],
    subdomain_prefixes: Option<Vec<String>>,
    stealth: Option<&crate::stealth_engine::StealthConfig>,
) -> EngineResult {
    let host = match target_to_host(target) {
        Some(h) => h,
        None => return EngineResult::error("target required"),
    };

    let mut findings: Vec<serde_json::Value> = Vec::new();
    let mut graph_nodes: Option<Vec<cloud_hunter::GraphNode>> = None;
    let mut graph_edges: Option<Vec<cloud_hunter::GraphEdge>> = None;

    for (port, _svc, open) in scan_ports(&host, ports, PORT_TIMEOUT_MS).await {
        if !open {
            continue;
        }
        findings.push(json!({
            "type": "asm",
            "asset": "port",
            "title": format!("Exposed TCP port {} on host {}", port, host),
            "value": format!("{}:{}", host, port),
            "port": port,
            "severity": port_severity(port),
        }));
    }

    if host.contains('.') && host.parse::<std::net::IpAddr>().is_err() {
        let subs = if let Some(prefixes) = subdomain_prefixes {
            if prefixes.is_empty() {
                vec![]
            } else {
                enum_subdomains(&host, &prefixes, 200).await
            }
        } else {
            enum_subdomains_default(&host).await
        };
        let mut urls = vec![format!("https://{}", host), format!("http://{}", host)];
        for s in subs.iter().take(20) {
            urls.push(format!("https://{}", s));
            urls.push(format!("http://{}", s));
        }
        let fp = scan_targets_concurrent_with_stealth(&urls, stealth).await;
        for (url, techs) in fp {
            if !techs.is_empty() {
                let tech_join = techs.join(", ");
                findings.push(json!({
                    "type": "asm",
                    "asset": "fingerprint",
                    "title": format!(
                        "HTTP fingerprint {} — {}",
                        url,
                        tech_join.chars().take(160).collect::<String>()
                    ),
                    "value": url,
                    "tech_stack": techs,
                    "severity": "info"
                }));
            }
        }
        let (nodes, edges, cloud_findings) =
            cloud_hunter::run_cloud_hunter(&host, &subs, stealth).await;
        findings.extend(cloud_findings);
        graph_nodes = Some(nodes);
        graph_edges = Some(edges);
    }

    let msg = format!(
        "ASM: {} open ports, {} total findings",
        findings
            .iter()
            .filter(|f| f.get("asset").and_then(|a| a.as_str()) == Some("port"))
            .count(),
        findings.len()
    );
    if let (Some(nodes), Some(edges)) = (graph_nodes, graph_edges) {
        EngineResult::ok_with_graph(findings, msg, nodes, edges)
    } else {
        EngineResult::ok(findings, msg)
    }
}

/// ASM with configurable ports only (subdomains = default, no stealth).
pub async fn run_asm_result_with_ports(target: &str, ports: &[u16]) -> EngineResult {
    run_asm_result_with_ports_and_subdomains(target, ports, None, None).await
}

pub async fn run_asm(target: &str) {
    print_result(run_asm_result(target).await);
}

// ─────────────────────────────────────────────────────────────────────────────
// Parameter surface (typed view over job_params; supports nested `options{}`)
// ─────────────────────────────────────────────────────────────────────────────

struct Params<'a> {
    raw: &'a Value,
}

impl Params<'_> {
    fn lookup(&self, key: &str) -> Option<&Value> {
        if let Some(v) = self.raw.get(key) {
            return Some(v);
        }
        self.raw.get("options").and_then(|o| o.get(key))
    }

    fn str(&self, key: &str) -> Option<String> {
        self.lookup(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    fn str_or(&self, key: &str, default: &str) -> String {
        self.str(key).unwrap_or_else(|| default.to_string())
    }

    fn bool_or(&self, key: &str, default: bool) -> bool {
        match self.lookup(key) {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on" | "enabled"
            ),
            Some(Value::Number(n)) => n.as_i64().map(|x| x != 0).unwrap_or(default),
            _ => default,
        }
    }

    fn usize_or(&self, key: &str, default: usize) -> usize {
        match self.lookup(key) {
            Some(Value::Number(n)) => {
                usize::try_from(n.as_u64().unwrap_or(default as u64)).unwrap_or(default)
            }
            Some(Value::String(s)) => s.trim().parse().unwrap_or(default),
            _ => default,
        }
    }

    fn u64_or(&self, key: &str, default: u64) -> u64 {
        match self.lookup(key) {
            Some(Value::Number(n)) => n.as_u64().unwrap_or(default),
            Some(Value::String(s)) => s.trim().parse().unwrap_or(default),
            _ => default,
        }
    }

    fn list(&self, key: &str) -> Vec<String> {
        let mut out = Vec::new();
        match self.lookup(key) {
            Some(Value::Array(arr)) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        let t = s.trim().to_string();
                        if !t.is_empty() {
                            out.push(t);
                        }
                    }
                }
            }
            Some(Value::String(s)) => {
                for tok in s.split([',', ' ', ';', '\n', '\t']) {
                    let t = tok.trim().to_string();
                    if !t.is_empty() {
                        out.push(t);
                    }
                }
            }
            _ => {}
        }
        out
    }
}

/// Parse a ports spec: "top" | "all" | "1-1024" | "80,443,8080-8090". Empty → TOP_PORTS.
fn parse_ports(spec: &str) -> Vec<u16> {
    let s = spec.trim().to_ascii_lowercase();
    if s.is_empty() || s == "top" || s == "default" {
        return TOP_PORTS.to_vec();
    }
    if s == "all" {
        return (1..=1024u16).collect();
    }
    let mut out: BTreeSet<u16> = BTreeSet::new();
    for tok in s.split([',', ' ', ';']) {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if let Some((a, b)) = tok.split_once('-') {
            if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                for p in lo..=hi.min(lo.saturating_add(2000)) {
                    out.insert(p);
                }
            }
        } else if let Ok(p) = tok.parse::<u16>() {
            out.insert(p);
        }
    }
    if out.is_empty() {
        TOP_PORTS.to_vec()
    } else {
        out.into_iter().collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Service / port classification
// ─────────────────────────────────────────────────────────────────────────────

fn service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPCbind",
        135 => "MSRPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        1433 | 1434 => "MSSQL",
        1521 => "Oracle DB",
        2181 => "ZooKeeper",
        2375 | 2376 | 4243 => "Docker API",
        3000 | 3001 => "Node/Dev HTTP",
        3306 => "MySQL",
        3389 => "RDP",
        4200 => "Angular Dev",
        4369 => "Erlang EPMD",
        5000 | 5001 => "App HTTP",
        5432 | 5433 => "PostgreSQL",
        5601 | 5602 => "Kibana",
        5672 | 15672 => "RabbitMQ",
        5900 => "VNC",
        5984 => "CouchDB",
        6333 => "Qdrant",
        6379 => "Redis",
        6443 => "Kubernetes API",
        7474 | 7687 => "Neo4j",
        8000 | 8001 | 8008 | 8080 | 8081 | 8181 | 8888 => "HTTP-alt",
        8161 => "ActiveMQ",
        8200 => "Vault",
        8300 | 8301 | 8500 => "Consul",
        8443 | 9443 => "HTTPS-alt",
        9000 => "SonarQube/Portainer",
        9090 | 9091 => "Prometheus",
        9092 => "Kafka",
        9200 | 9300 => "Elasticsearch",
        10250 | 10255 => "Kubelet",
        11211 => "Memcached",
        27017 | 27018 | 28017 => "MongoDB",
        50000 => "Jenkins/DB2",
        _ => "TCP",
    }
}

fn port_severity(port: u16) -> &'static str {
    match port {
        // Cleartext databases / caches / search — critical when internet-reachable
        3306 | 5432 | 5433 | 1433 | 1434 | 1521 | 27017 | 27018 | 28017 | 6379 | 9200 | 9300
        | 5984 | 11211 => "critical",
        // Remote admin / orchestration / secrets — high
        22 | 23 | 3389 | 5900 | 445 | 135 | 139 | 2375 | 2376 | 4243 | 6443 | 10250 | 10255
        | 8200 | 8500 | 8300 | 8301 | 50000 | 8161 | 5672 | 15672 | 9092 | 2181 | 21 | 25 => "high",
        _ => "medium",
    }
}

/// Read a short service banner after TCP connect (SSH/SMTP send first; HTTP gets a minimal GET).
async fn grab_service_banner(host: &str, port: u16, timeout_ms: u64) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let connect_to = Duration::from_millis(timeout_ms);
    let mut stream = tokio::time::timeout(connect_to, TcpStream::connect((host, port)))
        .await
        .ok()?
        .ok()?;
    if matches!(port, 80 | 8080 | 8000 | 8443 | 8888) {
        let _ = tokio::time::timeout(
            Duration::from_millis(400),
            stream.write_all(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n"),
        )
        .await;
    }
    let mut buf = [0u8; 480];
    let n = tokio::time::timeout(Duration::from_millis(900), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let raw = String::from_utf8_lossy(&buf[..n]);
    let line = raw
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .chars()
        .take(220)
        .collect::<String>();
    if line.len() < 4 {
        return None;
    }
    Some(line)
}

async fn scan_ports(host: &str, ports: &[u16], timeout_ms: u64) -> Vec<(u16, &'static str, bool)> {
    let host_arc = std::sync::Arc::new(host.to_string());
    let checks: Vec<_> = ports
        .iter()
        .copied()
        .map(|port| {
            let h = host_arc.clone();
            async move {
                let open = port_open(h.as_str(), port, timeout_ms).await;
                (port, service_name(port), open)
            }
        })
        .collect();
    join_all(checks).await
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS intelligence
// ─────────────────────────────────────────────────────────────────────────────

fn build_resolver() -> Option<TokioResolver> {
    TokioResolver::builder_with_config(ResolverConfig::default(), TokioRuntimeProvider::default())
        .build()
        .ok()
}

async fn lookup_strings(resolver: &TokioResolver, host: &str, rt: RecordType) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(lookup) = resolver.lookup(host, rt).await else {
        return out;
    };
    for record in lookup.answers() {
        // RData implements Display for every record type (A/AAAA/CNAME/NS/MX/TXT/…); using it
        // keeps us resilient to per-variant accessor churn across hickory versions.
        let s = record
            .data
            .to_string()
            .trim()
            .trim_end_matches('.')
            .to_string();
        if !s.is_empty() {
            out.push(s);
        }
    }
    out.sort();
    out.dedup();
    out
}

struct DnsProfile {
    a: Vec<String>,
    aaaa: Vec<String>,
    cname: Vec<String>,
    mx: Vec<String>,
    ns: Vec<String>,
    txt: Vec<String>,
}

async fn dns_profile(resolver: &TokioResolver, host: &str) -> DnsProfile {
    DnsProfile {
        a: lookup_strings(resolver, host, RecordType::A).await,
        aaaa: lookup_strings(resolver, host, RecordType::AAAA).await,
        cname: lookup_strings(resolver, host, RecordType::CNAME).await,
        mx: lookup_strings(resolver, host, RecordType::MX).await,
        ns: lookup_strings(resolver, host, RecordType::NS).await,
        txt: lookup_strings(resolver, host, RecordType::TXT).await,
    }
}

/// Analyse SPF/DMARC posture from TXT/DMARC records. Pushes findings.
async fn analyse_email_posture(
    resolver: &TokioResolver,
    domain: &str,
    txt: &[String],
    mx: &[String],
    issues: &mut Vec<Value>,
) {
    let spf: Vec<&String> = txt
        .iter()
        .filter(|t| t.to_lowercase().contains("v=spf1"))
        .collect();
    if spf.is_empty() {
        if !mx.is_empty() {
            issues.push(asm_finding(
                "email_posture",
                "high",
                domain,
                "Domain has mail (MX) but no SPF record",
                "T1566",
                format!("{domain} publishes MX records but no SPF (v=spf1) TXT record — the domain is trivially spoofable."),
                "Publish an SPF record (e.g. \"v=spf1 include:_spf.provider.com -all\").",
            ));
        }
    } else {
        let joined = spf.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ");
        if joined.contains("+all") || joined.contains("?all") {
            issues.push(asm_finding(
                "email_posture",
                "high",
                domain,
                "SPF record uses a permissive 'all' qualifier",
                "T1566",
                format!("{domain} SPF allows unlisted senders ({joined}) — weak anti-spoofing."),
                "Use a strict SPF policy ending in \"-all\".",
            ));
        }
    }
    let dmarc_host = format!("_dmarc.{domain}");
    let dmarc = lookup_strings(resolver, &dmarc_host, RecordType::TXT).await;
    let dmarc_txt: Vec<&String> = dmarc
        .iter()
        .filter(|t| t.to_lowercase().contains("v=dmarc1"))
        .collect();
    if dmarc_txt.is_empty() {
        issues.push(asm_finding(
            "email_posture",
            "medium",
            domain,
            "No DMARC record published",
            "T1566",
            format!("{domain} has no _dmarc TXT policy — receivers cannot enforce anti-spoofing alignment."),
            "Publish a DMARC record and progress toward p=reject.",
        ));
    } else {
        let joined = dmarc_txt
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        if joined.contains("p=none") {
            issues.push(asm_finding(
                "email_posture",
                "low",
                domain,
                "DMARC policy is monitoring-only (p=none)",
                "T1566",
                format!("{domain} DMARC is p=none ({joined}); spoofed mail is not rejected."),
                "Move DMARC policy to p=quarantine, then p=reject.",
            ));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Passive discovery — Certificate Transparency (crt.sh)
// ─────────────────────────────────────────────────────────────────────────────

async fn crtsh_subdomains(client: &reqwest::Client, domain: &str, cap: usize) -> Vec<String> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let Ok(resp) = client.get(&url).send().await else {
        return vec![];
    };
    if !resp.status().is_success() {
        return vec![];
    }
    let Ok(body) = resp.text().await else {
        return vec![];
    };
    let Ok(entries) = serde_json::from_str::<Vec<Value>>(&body) else {
        return vec![];
    };
    let mut set: BTreeSet<String> = BTreeSet::new();
    for e in entries {
        if let Some(name) = e.get("name_value").and_then(Value::as_str) {
            for n in name.split('\n') {
                let n = n.trim().trim_start_matches("*.").to_lowercase();
                if n.ends_with(domain) && !n.is_empty() && !n.contains(' ') {
                    set.insert(n);
                }
            }
        }
        if set.len() >= cap * 4 {
            break;
        }
    }
    set.into_iter().take(cap).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP posture (security headers, disclosure, cookies)
// ─────────────────────────────────────────────────────────────────────────────

struct HttpPosture {
    #[allow(dead_code)] // set during probe; not read after refactor
    reachable: bool,
    status: u16,
    final_url: String,
    server: Option<String>,
    powered_by: Option<String>,
    missing_headers: Vec<&'static str>,
    insecure_cookie: bool,
    cloud_signals: Vec<&'static str>,
}

async fn http_posture(client: &reqwest::Client, url: &str) -> Option<HttpPosture> {
    let resp = client.get(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers = resp.headers();
    let get = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let server = get("server");
    let powered_by = get("x-powered-by");

    let mut missing: Vec<&'static str> = Vec::new();
    let present = |k: &str| headers.contains_key(k);
    if url.starts_with("https://") && !present("strict-transport-security") {
        missing.push("Strict-Transport-Security");
    }
    if !present("content-security-policy") {
        missing.push("Content-Security-Policy");
    }
    if !present("x-frame-options")
        && !get("content-security-policy")
            .map(|c| c.contains("frame-ancestors"))
            .unwrap_or(false)
    {
        missing.push("X-Frame-Options");
    }
    if !present("x-content-type-options") {
        missing.push("X-Content-Type-Options");
    }
    if !present("referrer-policy") {
        missing.push("Referrer-Policy");
    }
    if !present("permissions-policy") {
        missing.push("Permissions-Policy");
    }

    let insecure_cookie = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|c| {
            let cl = c.to_lowercase();
            url.starts_with("https://") && (!cl.contains("secure") || !cl.contains("httponly"))
        });

    // Cloud attribution from response headers.
    let mut cloud_signals: Vec<&'static str> = Vec::new();
    let hkeys: Vec<String> = headers.keys().map(|k| k.as_str().to_lowercase()).collect();
    let has = |needle: &str| hkeys.iter().any(|k| k.contains(needle));
    if has("cf-ray")
        || server
            .as_deref()
            .map(|s| s.to_lowercase().contains("cloudflare"))
            .unwrap_or(false)
    {
        cloud_signals.push("Cloudflare");
    }
    if has("x-amz-") || has("x-amzn-") {
        cloud_signals.push("AWS");
    }
    if has("x-azure-") || has("x-ms-") {
        cloud_signals.push("Azure");
    }
    if has("x-goog-") || has("x-guploader-uploadid") {
        cloud_signals.push("GCP");
    }
    if has("x-fastly") || server.as_deref() == Some("Varnish") {
        cloud_signals.push("Fastly");
    }
    if has("x-akamai-") || has("x-akamai-transformed") {
        cloud_signals.push("Akamai");
    }

    Some(HttpPosture {
        reachable: true,
        status,
        final_url,
        server,
        powered_by,
        missing_headers: missing,
        insecure_cookie,
        cloud_signals,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS / certificate posture (openssl, blocking probe guarded by timeouts)
// ─────────────────────────────────────────────────────────────────────────────

struct TlsInfo {
    protocol: String,
    issuer: String,
    subject: String,
    days_to_expiry: i32,
    expired: bool,
    self_signed: bool,
    weak_protocol: bool,
    san_count: usize,
}

fn name_cn(name: &openssl::x509::X509NameRef) -> String {
    name.entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn tls_probe_blocking(host: &str, port: u16, timeout_ms: u64) -> Option<TlsInfo> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use std::net::ToSocketAddrs;

    let timeout = Duration::from_millis(timeout_ms);
    let addr = format!("{host}:{port}").to_socket_addrs().ok()?.next()?;
    let tcp = std::net::TcpStream::connect_timeout(&addr, timeout).ok()?;
    tcp.set_read_timeout(Some(timeout)).ok()?;
    tcp.set_write_timeout(Some(timeout)).ok()?;

    let mut builder = SslConnector::builder(SslMethod::tls()).ok()?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let mut cfg = connector.configure().ok()?;
    cfg.set_use_server_name_indication(true);
    cfg.set_verify_hostname(false);
    let stream = cfg.connect(host, tcp).ok()?;

    let ssl = stream.ssl();
    let protocol = ssl.version_str().to_string();
    let cert = ssl.peer_certificate()?;
    let subject = name_cn(cert.subject_name());
    let issuer = name_cn(cert.issuer_name());
    let self_signed = !subject.is_empty() && subject == issuer;

    let now = openssl::asn1::Asn1Time::days_from_now(0).ok()?;
    let (days_to_expiry, expired) = match now.diff(cert.not_after()) {
        Ok(diff) => (diff.days, diff.days < 0),
        Err(_) => (0, false),
    };
    let san_count = cert
        .subject_alt_names()
        .map(|stack| stack.iter().count())
        .unwrap_or(0);
    let weak_protocol = matches!(protocol.as_str(), "SSLv3" | "TLSv1" | "TLSv1.1");

    drop(stream);
    Some(TlsInfo {
        protocol,
        issuer,
        subject,
        days_to_expiry,
        expired,
        self_signed,
        weak_protocol,
        san_count,
    })
}

async fn tls_posture(host: String, port: u16, timeout_ms: u64) -> Option<TlsInfo> {
    let fut = tokio::task::spawn_blocking(move || tls_probe_blocking(&host, port, timeout_ms));
    match tokio::time::timeout(Duration::from_millis(timeout_ms + 1500), fut).await {
        Ok(Ok(info)) => info,
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cloud attribution
// ─────────────────────────────────────────────────────────────────────────────

fn cloud_from_cname(cname: &str) -> Option<&'static str> {
    let c = cname.to_lowercase();
    let table: &[(&str, &str)] = &[
        ("amazonaws.com", "AWS"),
        ("cloudfront.net", "AWS CloudFront"),
        ("elb.amazonaws.com", "AWS ELB"),
        ("azurewebsites.net", "Azure"),
        ("azure-api.net", "Azure"),
        ("blob.core.windows.net", "Azure Blob"),
        ("trafficmanager.net", "Azure"),
        ("cloudapp.azure.com", "Azure"),
        ("googleusercontent.com", "GCP"),
        ("appspot.com", "GCP App Engine"),
        ("run.app", "GCP Cloud Run"),
        ("storage.googleapis.com", "GCP Storage"),
        ("cloudflare.net", "Cloudflare"),
        ("cdn.cloudflare.net", "Cloudflare"),
        ("fastly.net", "Fastly"),
        ("akamaiedge.net", "Akamai"),
        ("akamai.net", "Akamai"),
        ("herokudns.com", "Heroku"),
        ("netlify.app", "Netlify"),
        ("vercel-dns.com", "Vercel"),
        ("digitaloceanspaces.com", "DigitalOcean"),
    ];
    table
        .iter()
        .find(|(suf, _)| c.contains(suf))
        .map(|(_, p)| *p)
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding + scoring helpers
// ─────────────────────────────────────────────────────────────────────────────

fn asm_finding(
    asset: &str,
    severity: &str,
    value: impl Into<String>,
    title: impl Into<String>,
    mitre: &str,
    description: impl Into<String>,
    remediation: impl Into<String>,
) -> Value {
    json!({
        "type": "asm",
        "engine_id": "asm",
        "asset": asset,
        "severity": severity,
        "value": value.into(),
        "title": title.into(),
        "mitre_attack": mitre,
        "description": description.into(),
        "remediation": remediation.into(),
    })
}

/// Prefixes on discovered subdomains that usually indicate shadow IT / high-value targets.
const SHADOW_IT_PREFIXES: &[&str] = &[
    "dev",
    "development",
    "staging",
    "stage",
    "stg",
    "test",
    "testing",
    "qa",
    "uat",
    "sandbox",
    "preprod",
    "beta",
    "demo",
    "lab",
    "labs",
    "admin",
    "superadmin",
    "manage",
    "management",
    "console",
    "dashboard",
    "panel",
    "vpn",
    "remote",
    "internal",
    "intranet",
    "jenkins",
    "ci",
    "gitlab",
    "github",
    "kibana",
    "grafana",
    "prometheus",
    "vault",
    "consul",
    "backup",
    "old",
    "legacy",
    "mysql",
    "postgres",
    "redis",
    "elastic",
    "mongo",
    "db",
    "api-dev",
    "api-staging",
];

fn subdomain_label(host: &str, apex: &str) -> Option<String> {
    let h = host.trim().to_lowercase();
    let apex = apex.trim().to_lowercase();
    if h == apex {
        return None;
    }
    h.strip_suffix(&format!(".{apex}"))
        .and_then(|label| label.split('.').next())
        .map(str::to_string)
}

fn is_shadow_it_host(host: &str, apex: &str) -> Option<&'static str> {
    let label = subdomain_label(host, apex)?;
    SHADOW_IT_PREFIXES
        .iter()
        .find(|p| label == **p || label.starts_with(&format!("{}-", p)))
        .copied()
}

fn scan_shadow_it(subdomains: &[String], apex: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for sub in subdomains {
        if let Some(kind) = is_shadow_it_host(sub, apex) {
            if !seen.insert(sub.clone()) {
                continue;
            }
            out.push(asm_finding(
                "shadow_it",
                "medium",
                sub.clone(),
                format!("Shadow IT / non-prod host exposed: {sub}"),
                "T1584.001",
                format!(
                    "Subdomain '{sub}' matches the high-risk '{kind}' pattern — often unmanaged dev/staging/admin infrastructure on the public internet."
                ),
                "Confirm ownership; move non-production workloads off the public internet or gate with Zero Trust access.",
            ));
        }
    }
    out
}

async fn probe_cleartext_http(client: &reqwest::Client, host: &str) -> Option<Value> {
    let url = format!("http://{host}");
    let resp = client.get(&url).send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    if final_url.starts_with("https://") {
        return None;
    }
    if status >= 200 && status < 400 {
        return Some(asm_finding(
            "http_posture",
            "high",
            final_url,
            format!("Cleartext HTTP serves content on {host} (no HTTPS upgrade)"),
            "T1040",
            format!(
                "HTTP GET to {url} returned {status} without redirecting to HTTPS — credentials and session tokens may traverse in plaintext."
            ),
            "Enforce HTTPS everywhere (301 redirect + HSTS); disable plain HTTP at the load balancer.",
        ));
    }
    None
}

const WELLKNOWN_PATHS: &[(&str, &str)] = &[
    ("/.well-known/security.txt", "RFC 9116 security.txt"),
    ("/security.txt", "security.txt (root)"),
    ("/.well-known/change-password", "change-password well-known"),
];

async fn probe_wellknown(client: &reqwest::Client, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for (path, label) in WELLKNOWN_PATHS {
        let url = format!("https://{host}{path}");
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        if resp.status().as_u16() != 200 {
            continue;
        }
        let body = resp.text().await.unwrap_or_default();
        if body.len() < 8 {
            continue;
        }
        let sev = if path.contains("security.txt") {
            "info"
        } else {
            "low"
        };
        out.push(asm_finding(
            "wellknown",
            sev,
            url.clone(),
            format!("{label} published at {host}"),
            "T1590",
            format!(
                "{label} is reachable at {url} ({} bytes). Verify contacts and policy URLs are current.",
                body.len()
            ),
            "Keep security.txt current; use it to route researchers to your disclosure program.",
        ));
    }
    out
}

async fn rdap_domain_intel(client: &reqwest::Client, domain: &str) -> Vec<Value> {
    let url = format!("https://rdap.org/domain/{}", domain);
    let Ok(resp) = client
        .get(&url)
        .header("Accept", "application/rdap+json, application/json")
        .send()
        .await
    else {
        return Vec::new();
    };
    if !resp.status().is_success() {
        return Vec::new();
    }
    let Ok(body) = resp.json::<Value>().await else {
        return Vec::new();
    };
    let mut out = Vec::new();

    if let Some(ns) = body.get("nameservers").and_then(Value::as_array) {
        let names: Vec<String> = ns
            .iter()
            .filter_map(|n| {
                n.get("ldhName")
                    .and_then(Value::as_str)
                    .map(|s| s.trim_end_matches('.').to_lowercase())
            })
            .collect();
        if !names.is_empty() {
            out.push(asm_finding(
                "rdap",
                "info",
                domain,
                format!("RDAP nameserver delegation for {domain}"),
                "T1590.002",
                format!("Live RDAP lists nameservers: {}.", names.join(", ")),
                "Ensure every delegated nameserver is owned and monitored; remove stale NS glue.",
            ));
        }
    }

    if let Some(status) = body.get("status").and_then(Value::as_array) {
        let statuses: Vec<&str> = status.iter().filter_map(|s| s.as_str()).collect();
        if statuses.iter().any(|s| {
            matches!(
                *s,
                "client hold" | "clientHold" | "server hold" | "serverHold"
            )
        }) {
            out.push(asm_finding(
                "rdap",
                "high",
                domain,
                format!("RDAP hold status on {domain}"),
                "T1583.001",
                format!(
                    "Registration status flags: {:?} — the domain may be suspended or hijackable at the registrar.",
                    statuses
                ),
                "Verify registrar account security; confirm domain is in good standing.",
            ));
        }
    }

    if let Some(events) = body.get("events").and_then(Value::as_array) {
        for ev in events {
            let action = ev.get("eventAction").and_then(Value::as_str).unwrap_or("");
            let date = ev.get("eventDate").and_then(Value::as_str).unwrap_or("");
            if action.eq_ignore_ascii_case("expiration") && !date.is_empty() {
                out.push(asm_finding(
                    "rdap",
                    "medium",
                    domain,
                    format!("RDAP expiration date for {domain}"),
                    "T1590",
                    format!("Registrar RDAP reports expiration on {date}."),
                    "Enable auto-renew and registrar lock; monitor expiry 90+ days ahead.",
                ));
                break;
            }
        }
    }

    if let Some(entities) = body.get("entities").and_then(Value::as_array) {
        for ent in entities {
            let roles = ent.get("roles").and_then(Value::as_array);
            let is_registrar = roles
                .map(|rs| {
                    rs.iter()
                        .filter_map(Value::as_str)
                        .any(|r| r.eq_ignore_ascii_case("registrar"))
                })
                .unwrap_or(false);
            if !is_registrar {
                continue;
            }
            let handle = ent
                .get("handle")
                .and_then(Value::as_str)
                .or_else(|| {
                    ent.get("publicIds")
                        .and_then(Value::as_array)
                        .and_then(|a| a.first())
                        .and_then(|p| p.get("identifier"))
                        .and_then(Value::as_str)
                })
                .unwrap_or("unknown");
            out.push(asm_finding(
                "rdap",
                "info",
                domain,
                format!("RDAP registrar for {domain}"),
                "T1590",
                format!("Live RDAP attributes registration to registrar handle '{handle}'."),
                "Confirm registrar MFA and domain lock are enabled.",
            ));
            break;
        }
    }

    out
}

async fn cymru_asn_for_ip(resolver: &TokioResolver, ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    if parts.iter().any(|p| p.parse::<u8>().is_err()) {
        return None;
    }
    let query = format!(
        "{}.{}.{}.{}.origin.asn.cymru.com",
        parts[3], parts[2], parts[1], parts[0]
    );
    lookup_strings(resolver, &query, RecordType::TXT)
        .await
        .into_iter()
        .next()
}

const DKIM_SELECTORS: &[&str] = &[
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "mail",
    "dkim",
    "smtp",
    "mandrill",
    "sendgrid",
    "mailgun",
];

async fn probe_dkim_selectors(resolver: &TokioResolver, domain: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut found = Vec::new();
    for sel in DKIM_SELECTORS {
        let host = format!("{sel}._domainkey.{domain}");
        let txt = lookup_strings(resolver, &host, RecordType::TXT).await;
        if txt.iter().any(|t| t.to_uppercase().contains("V=DKIM1")) {
            found.push(sel.to_string());
        }
    }
    if found.is_empty() {
        out.push(asm_finding(
            "email_posture",
            "medium",
            domain,
            format!("No common DKIM selectors found for {domain}"),
            "T1566",
            format!(
                "Probed {} common DKIM selector names — none publish v=DKIM1 TXT records.",
                DKIM_SELECTORS.len()
            ),
            "Publish DKIM for all outbound mail paths; rotate selectors on provider migration.",
        ));
    } else {
        out.push(asm_finding(
            "email_posture",
            "info",
            domain,
            format!("DKIM selectors discovered for {domain}"),
            "T1566",
            format!("Live DKIM TXT at selector(s): {}.", found.join(", ")),
            "Monitor DKIM key rotation and align with DMARC (adkim=s).",
        ));
    }
    out
}

async fn probe_cors_misconfig(client: &reqwest::Client, host: &str) -> Option<Value> {
    let url = format!("https://{host}/");
    let probe_origin = "https://weissman-cors-probe.invalid";
    let resp = client
        .get(&url)
        .header("Origin", probe_origin)
        .send()
        .await
        .ok()?;
    let acao = resp
        .headers()
        .get("access-control-allow-origin")?
        .to_str()
        .ok()?;
    let creds = resp
        .headers()
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if acao == probe_origin {
        return Some(asm_finding(
            "cors",
            if creds { "critical" } else { "high" },
            url,
            format!("CORS reflects arbitrary Origin on {host}"),
            "T1190",
            format!(
                "Access-Control-Allow-Origin echoes attacker Origin '{probe_origin}'{}.",
                if creds {
                    " with Access-Control-Allow-Credentials: true"
                } else {
                    ""
                }
            ),
            "Never reflect Origin; whitelist trusted origins explicitly.",
        ));
    }
    if acao == "*" && creds {
        return Some(asm_finding(
            "cors",
            "high",
            url,
            format!("CORS wildcard with credentials on {host}"),
            "T1190",
            "Access-Control-Allow-Origin: * combined with Allow-Credentials — browsers may leak session data.".to_string(),
            "Remove Allow-Credentials or replace * with an explicit origin whitelist.",
        ));
    }
    if acao == "*" {
        return Some(asm_finding(
            "cors",
            "low",
            url,
            format!("Permissive CORS wildcard on {host}"),
            "T1190",
            "Access-Control-Allow-Origin: * permits any web origin to read responses.".to_string(),
            "Restrict CORS to required origins only.",
        ));
    }
    None
}

const SENSITIVE_PATHS: &[(&str, &str, &str)] = &[
    ("/.env", "critical", "Environment configuration file"),
    ("/.git/HEAD", "high", "Git repository metadata"),
    ("/actuator/health", "medium", "Spring Boot actuator"),
    ("/swagger-ui.html", "low", "Swagger UI"),
    ("/api/swagger.json", "medium", "OpenAPI specification"),
    ("/server-status", "medium", "Apache server-status"),
    ("/wp-config.php.bak", "high", "WordPress config backup"),
    ("/backup.sql", "critical", "SQL database backup"),
    ("/debug/pprof", "high", "Go pprof debug endpoint"),
    ("/phpinfo.php", "medium", "PHP info disclosure"),
];

async fn probe_sensitive_paths(client: &reqwest::Client, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for (path, sev, label) in SENSITIVE_PATHS {
        let url = format!("https://{host}{path}");
        let Ok(resp) = client.get(&url).send().await else {
            continue;
        };
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            continue;
        }
        let len = resp.content_length().unwrap_or(0);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if len == 0 && !ct.contains("text") && !ct.contains("json") && !ct.contains("xml") {
            continue;
        }
        let body_snip = resp.text().await.unwrap_or_default();
        if body_snip.len() < 4 {
            continue;
        }
        let looks_real = match *path {
            "/.env" => {
                body_snip.contains('=')
                    && (body_snip.contains("KEY")
                        || body_snip.contains("SECRET")
                        || body_snip.contains("PASSWORD"))
            }
            "/.git/HEAD" => body_snip.starts_with("ref:"),
            "/actuator/health" => body_snip.contains("status") || body_snip.contains("UP"),
            "/backup.sql" => body_snip.contains("INSERT") || body_snip.contains("CREATE TABLE"),
            "/phpinfo.php" => body_snip.contains("phpinfo") || body_snip.contains("PHP Version"),
            _ => body_snip.len() >= 16,
        };
        if !looks_real {
            continue;
        }
        out.push(asm_finding(
            "sensitive_path",
            sev,
            url.clone(),
            format!("Sensitive {label} reachable on {host}"),
            "T1190",
            format!("GET {url} returned HTTP {status} ({} bytes) — potential data exposure.", body_snip.len()),
            "Remove public access; authenticate admin surfaces; delete backup artifacts from web roots.",
        ));
    }
    out
}

const ROBOTS_SENSITIVE: &[&str] = &[
    "admin",
    "backup",
    "private",
    "internal",
    "staging",
    "dev",
    "api",
    "config",
    "secret",
    ".git",
    "wp-admin",
    "phpmyadmin",
    "database",
];

async fn harvest_robots_txt(client: &reqwest::Client, host: &str) -> Vec<Value> {
    let url = format!("https://{host}/robots.txt");
    let Ok(resp) = client.get(&url).send().await else {
        return Vec::new();
    };
    if resp.status().as_u16() != 200 {
        return Vec::new();
    }
    let body = resp.text().await.unwrap_or_default();
    if body.len() < 8 || !body.to_lowercase().contains("user-agent") {
        return Vec::new();
    }
    let mut flagged = Vec::new();
    for line in body.lines() {
        let l = line.trim().to_lowercase();
        if !l.starts_with("disallow:") {
            continue;
        }
        let path = l.trim_start_matches("disallow:").trim();
        if path.is_empty() || path == "/" {
            continue;
        }
        if ROBOTS_SENSITIVE.iter().any(|k| path.contains(k)) {
            flagged.push(path.to_string());
        }
    }
    flagged.sort();
    flagged.dedup();
    if flagged.is_empty() {
        return vec![asm_finding(
            "robots",
            "info",
            url.clone(),
            format!("robots.txt published on {host}"),
            "T1590",
            format!(
                "robots.txt is reachable ({} bytes) — no high-risk disallow paths flagged.",
                body.len()
            ),
            "Review robots.txt; do not rely on it for access control.",
        )];
    }
    vec![asm_finding(
        "robots",
        "medium",
        url,
        format!("robots.txt reveals sensitive paths on {host}"),
        "T1590",
        format!(
            "Disallow entries reference sensitive paths: {} — attackers use robots.txt for recon.",
            flagged.join(", ")
        ),
        "Protect sensitive paths with authentication; robots.txt is not a security control.",
    )]
}

fn extend_inventory_graph(
    nodes: &mut Vec<cloud_hunter::GraphNode>,
    edges: &mut Vec<cloud_hunter::GraphEdge>,
    apex: &str,
    subdomains: &[String],
    shadow: &BTreeSet<String>,
) {
    let apex_id = format!("asm:root:{apex}");
    if !nodes.iter().any(|n| n.id == apex_id) {
        nodes.push(cloud_hunter::GraphNode {
            id: apex_id.clone(),
            label: apex.to_string(),
            node_type: "root".to_string(),
            status: "secure".to_string(),
            cname_target: None,
            raw_finding: None,
        });
    }
    for sub in subdomains {
        let sid = format!("asm:sub:{sub}");
        if nodes.iter().any(|n| n.id == sid) {
            continue;
        }
        let status = if shadow.contains(sub) {
            "exposed"
        } else {
            "secure"
        };
        nodes.push(cloud_hunter::GraphNode {
            id: sid.clone(),
            label: sub.clone(),
            node_type: "subdomain".to_string(),
            status: status.to_string(),
            cname_target: None,
            raw_finding: None,
        });
        edges.push(cloud_hunter::GraphEdge {
            id: format!("asm:inv:{sub}"),
            from_id: apex_id.clone(),
            to_id: sid,
            edge_type: "INVENTORY".to_string(),
        });
    }
}

async fn dns_wildcard_detect(resolver: &TokioResolver, domain: &str) -> bool {
    let token = uuid::Uuid::new_v4()
        .to_string()
        .split('-')
        .next()
        .unwrap_or("rand")
        .to_string();
    let probe = format!("{token}-weissman-probe.{domain}");
    !lookup_strings(resolver, &probe, RecordType::A)
        .await
        .is_empty()
        || !lookup_strings(resolver, &probe, RecordType::AAAA)
            .await
            .is_empty()
}

async fn analyse_dns_hardening(resolver: &TokioResolver, domain: &str, findings: &mut Vec<Value>) {
    if dns_wildcard_detect(resolver, domain).await {
        findings.push(asm_finding(
            "dns",
            "medium",
            domain,
            format!("DNS wildcard detected for {domain}"),
            "T1590.002",
            format!(
                "A random label under {domain} resolves — wildcard DNS expands the takeover and phishing surface."
            ),
            "Remove wildcard A/AAAA records unless strictly required; monitor for unclaimed subdomains.",
        ));
    }
    let caa = lookup_strings(resolver, domain, RecordType::CAA).await;
    if caa.is_empty() {
        findings.push(asm_finding(
            "dns",
            "low",
            domain,
            format!("No CAA records for {domain}"),
            "T1588.004",
            "The apex domain publishes no CAA records — any public CA may issue certificates for your names.".to_string(),
            "Publish CAA records restricting issuance to your chosen CAs (e.g. letsencrypt.org, digicert.com).",
        ));
    } else {
        findings.push(asm_finding(
            "dns",
            "info",
            domain,
            format!("CAA policy published for {domain}"),
            "T1588.004",
            format!("CAA records: {caa:?}"),
            "Review CAA periodically when changing certificate authorities.",
        ));
    }
}

/// Internal signal tags for attack-path correlation.
fn finding_tags(f: &Value) -> BTreeSet<&'static str> {
    let mut tags = BTreeSet::new();
    let asset = f.get("asset").and_then(Value::as_str).unwrap_or("");
    let title = f
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
    let value = f
        .get("value")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();

    match asset {
        "port" if sev == "critical" => {
            tags.insert("critical_port");
        }
        "port" if sev == "high" => {
            tags.insert("high_port");
        }
        "shadow_it" => {
            tags.insert("shadow_it");
        }
        "email_posture" if sev == "high" || sev == "medium" => {
            tags.insert("weak_email");
        }
        "http_posture" if title.contains("cleartext") => {
            tags.insert("cleartext_http");
        }
        "tls_posture" if sev == "high" || title.contains("expired") || title.contains("weak") => {
            tags.insert("weak_tls");
        }
        "cors" if sev == "high" || sev == "critical" => {
            tags.insert("cors_misconfig");
        }
        "sensitive_path" => {
            tags.insert("sensitive_path");
        }
        "rdap" if title.contains("hold") => {
            tags.insert("rdap_hold");
        }
        "banner"
            if title.contains("version")
                || value.contains("openssh")
                || value.contains("redis") =>
        {
            tags.insert("banner_intel");
        }
        _ => {}
    }
    if asset == "cloud_hunter" || title.contains("takeover") {
        tags.insert("takeover_risk");
    }
    if value.contains("takeover") || title.contains("takeover") {
        tags.insert("takeover_risk");
    }
    tags
}

fn derive_exposure_attack_paths(findings: &[Value]) -> Vec<Value> {
    let mut tags = BTreeSet::new();
    for f in findings {
        tags.extend(finding_tags(f));
    }
    let mut paths = Vec::new();
    let has = |t: &str| tags.contains(t);

    if has("critical_port") && has("weak_email") {
        paths.push(asm_finding(
            "attack_path",
            "critical",
            "internet-db + spoofable-email",
            "Attack path: exposed datastore + spoofable email domain",
            "T1190",
            "An internet-reachable database/critical service coexists with weak SPF/DMARC — attackers can phish credentials and connect directly to the datastore.",
            "Fix email authentication (SPF/DMARC) and remove public exposure on data services immediately.",
        ));
    }
    if has("takeover_risk") && has("shadow_it") {
        paths.push(asm_finding(
            "attack_path",
            "critical",
            "takeover + shadow-it",
            "Attack path: subdomain takeover on shadow-IT host",
            "T1584.001",
            "A dangling CNAME on a dev/staging/admin-style subdomain lets an attacker claim the name and serve malware or harvest credentials.",
            "Remove dangling DNS immediately; decommission or privatise non-prod hosts.",
        ));
    }
    if has("cleartext_http") && has("weak_tls") {
        paths.push(asm_finding(
            "attack_path",
            "high",
            "cleartext + weak-tls",
            "Attack path: cleartext HTTP with weak TLS elsewhere",
            "T1040",
            "Plain HTTP serves live content while TLS on sibling hosts is weak or expired — session hijack and downgrade risk.",
            "Force HTTPS with HSTS; renew/fix certificates and disable deprecated TLS versions.",
        ));
    }
    if has("critical_port") && has("shadow_it") {
        paths.push(asm_finding(
            "attack_path",
            "critical",
            "shadow-it + exposed-service",
            "Attack path: shadow-IT host exposes a sensitive service",
            "T1190",
            "A non-production subdomain exposes a database or admin service to the internet — a common ransomware entry point.",
            "Remove public exposure; require VPN/Zero Trust for admin and data tiers.",
        ));
    }
    if has("high_port") && has("takeover_risk") {
        paths.push(asm_finding(
            "attack_path",
            "high",
            "takeover + admin-port",
            "Attack path: takeover chain into admin surface",
            "T1190",
            "Subdomain takeover risk combined with exposed admin ports (SSH/RDP/management) enables rapid lateral movement.",
            "Fix dangling DNS first, then restrict admin ports to known IP ranges.",
        ));
    }
    if has("cors_misconfig") && has("sensitive_path") {
        paths.push(asm_finding(
            "attack_path",
            "critical",
            "cors + sensitive-path",
            "Attack path: CORS misconfig enables cross-origin data theft",
            "T1190",
            "Reflective CORS on a host that also exposes sensitive paths lets a malicious site steal secrets from victim browsers.",
            "Fix CORS policy first; remove sensitive files from the public web root.",
        ));
    }
    if has("sensitive_path") && has("shadow_it") {
        paths.push(asm_finding(
            "attack_path",
            "critical",
            "shadow-it + sensitive-leak",
            "Attack path: shadow-IT host leaks sensitive artifacts",
            "T1190",
            "A non-production subdomain exposes configuration backups or admin endpoints — common breach entry for ransomware groups.",
            "Take the host offline or restrict by IP; rotate any exposed secrets immediately.",
        ));
    }
    if has("weak_email") && has("banner_intel") {
        paths.push(asm_finding(
            "attack_path",
            "high",
            "spoofable-email + service-banner",
            "Attack path: email spoofing plus fingerprinted services",
            "T1566",
            "Weak SPF/DMARC combined with version-disclosing service banners enables targeted phishing against known infrastructure.",
            "Harden email authentication and suppress service version banners.",
        ));
    }
    if has("rdap_hold") {
        paths.push(asm_finding(
            "attack_path",
            "high",
            "rdap-hold",
            "Attack path: domain registration hold / hijack window",
            "T1583.001",
            "Registrar hold or expiry signals increase hijack and impersonation risk for the entire brand surface.",
            "Secure registrar account with MFA; enable registry lock and auto-renew.",
        ));
    }
    paths
}

fn remediation_queue(findings: &[Value], limit: usize) -> Vec<Value> {
    let mut ranked: Vec<&Value> = findings
        .iter()
        .filter(|f| {
            f.get("asset").and_then(Value::as_str) != Some("report")
                && f.get("report").and_then(Value::as_bool) != Some(true)
        })
        .collect();
    ranked.sort_by(|a, b| {
        let sa = a.get("severity").and_then(Value::as_str).unwrap_or("info");
        let sb = b.get("severity").and_then(Value::as_str).unwrap_or("info");
        sev_rank(sb).cmp(&sev_rank(sa))
    });
    ranked
        .into_iter()
        .take(limit)
        .map(|f| {
            json!({
                "title": f.get("title").and_then(Value::as_str).unwrap_or(""),
                "severity": f.get("severity").and_then(Value::as_str).unwrap_or("info"),
                "asset": f.get("asset").and_then(Value::as_str).unwrap_or(""),
                "value": f.get("value").and_then(Value::as_str).unwrap_or(""),
                "remediation": f.get("remediation").and_then(Value::as_str).unwrap_or(""),
            })
        })
        .collect()
}

fn sev_rank(s: &str) -> u8 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn surface_grade(score: i32) -> &'static str {
    match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        55..=69 => "D",
        _ => "F",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main world-class EASM pipeline
// ─────────────────────────────────────────────────────────────────────────────

async fn build_client(timeout_ms: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.max(2000)))
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("weissman-asm/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Full, context-aware EASM assessment. Reads every knob from `ctx.job_params`.
pub async fn run_asm_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
    stealth: Option<&crate::stealth_engine::StealthConfig>,
) -> EngineResult {
    let host = match target_to_host(target) {
        Some(h) => h,
        None => return EngineResult::error("target required"),
    };
    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    let is_domain = host.contains('.') && !is_ip;

    let p = Params {
        raw: &ctx.job_params,
    };

    // ── Knobs ────────────────────────────────────────────────────────────────
    let do_ports = p.bool_or("port_scan", true);
    let do_subdomains = p.bool_or("subdomain_enum", true) && is_domain;
    let do_dns = p.bool_or("dns_intel", true) && is_domain;
    let do_http = p.bool_or("http_posture", true);
    let do_tls = p.bool_or("tls_posture", true);
    let do_cloud = p.bool_or("cloud_hunter", true) && is_domain;
    let do_fingerprint = p.bool_or("tech_fingerprint", true);
    let do_shadow_it = p.bool_or("shadow_it_scan", true) && is_domain;
    let do_wellknown = p.bool_or("wellknown_probe", true) && is_domain;
    let do_cleartext = p.bool_or("cleartext_http_probe", true);
    let do_attack_paths = p.bool_or("attack_path_correlation", true);
    let do_dns_hardening = p.bool_or("dns_hardening", true) && is_domain;
    let do_rdap = p.bool_or("rdap_intel", true) && is_domain;
    let do_asn = p.bool_or("ip_asn_enrichment", true);
    let do_banners = p.bool_or("banner_grab", true);
    let do_cors = p.bool_or("cors_probe", true);
    let do_sensitive = p.bool_or("sensitive_path_probe", true);
    let do_robots = p.bool_or("robots_harvest", true);
    let do_dkim = p.bool_or("dkim_probe", true) && is_domain;
    let subdomain_sources = p.str_or("subdomain_sources", "both").to_ascii_lowercase();
    let max_subdomains = p.usize_or("max_subdomains", 50).clamp(0, 500);
    let port_timeout = p
        .u64_or("port_timeout_ms", PORT_TIMEOUT_MS)
        .clamp(100, 5000);
    let http_timeout = p.u64_or("http_timeout_ms", 6000).clamp(1000, 30000);
    let threshold = p.str_or("severity_threshold", "info").to_ascii_lowercase();
    let max_findings = p.usize_or("max_findings", 800).clamp(1, 5000);

    // Ports: explicit param > ctx.asm_ports > TOP_PORTS
    let ports: Vec<u16> = match p.str("ports") {
        Some(spec) => parse_ports(&spec),
        None => ctx
            .asm_ports
            .clone()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| TOP_PORTS.to_vec()),
    };
    let custom_wordlist = p.list("subdomain_wordlist");

    let client = build_client(http_timeout).await;
    let resolver = build_resolver();

    let mut findings: Vec<Value> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // ── 1. Asset discovery (subdomains: passive CT + active brute) ────────────
    let mut subdomains: BTreeSet<String> = BTreeSet::new();
    if !ctx.recon_subdomains.is_empty() {
        subdomains.extend(ctx.recon_subdomains.iter().cloned());
    }
    if do_subdomains {
        if subdomain_sources == "passive" || subdomain_sources == "both" {
            let ct = crtsh_subdomains(&client, &host, max_subdomains.max(1) * 2).await;
            if !ct.is_empty() {
                notes.push(format!(
                    "Certificate Transparency surfaced {} name(s).",
                    ct.len()
                ));
            }
            subdomains.extend(ct);
        }
        if subdomain_sources == "bruteforce" || subdomain_sources == "both" {
            let static_list: Vec<String> = if custom_wordlist.is_empty() {
                DEFAULT_SUBDOMAINS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            } else {
                custom_wordlist.clone()
            };
            let wordlist = crate::live_knowledge_bus::merge_subdomain_wordlist(&host, static_list);
            let brute = enum_subdomains(&host, &wordlist, 200).await;
            subdomains.extend(brute);
        }
    }
    let subdomains: Vec<String> = subdomains.into_iter().take(max_subdomains).collect();
    if is_domain {
        findings.push(asm_finding(
            "inventory",
            "info",
            &host,
            format!("Discovered {} live subdomain asset(s)", subdomains.len()),
            "T1590",
            format!(
                "External asset discovery for {host} found {} subdomain(s) via {}.",
                subdomains.len(),
                subdomain_sources
            ),
            "Review the inventory for shadow IT and unmanaged assets; decommission what is unowned.",
        ));
    }

    // ── 2. DNS intelligence + email posture (apex) ────────────────────────────
    if do_dns {
        if let Some(r) = resolver.as_ref() {
            let prof = dns_profile(r, &host).await;
            findings.push(asm_finding(
                "dns",
                "info",
                &host,
                format!("DNS profile for {host}"),
                "T1590.002",
                format!(
                    "A={:?} AAAA={:?} CNAME={:?} MX={:?} NS={:?} TXT_records={}",
                    prof.a,
                    prof.aaaa,
                    prof.cname,
                    prof.mx,
                    prof.ns,
                    prof.txt.len()
                ),
                "Confirm every published record is intentional; remove stale entries.",
            ));
            analyse_email_posture(r, &host, &prof.txt, &prof.mx, &mut findings).await;
            if do_dkim {
                findings.extend(probe_dkim_selectors(r, &host).await);
            }
            if do_dns_hardening {
                analyse_dns_hardening(r, &host, &mut findings).await;
            }
            if do_asn {
                for ip in &prof.a {
                    if let Some(asn_txt) = cymru_asn_for_ip(r, ip).await {
                        findings.push(asm_finding(
                            "asn",
                            "info",
                            ip.clone(),
                            format!("ASN attribution for {ip}"),
                            "T1590",
                            format!("Team Cymru origin lookup: {asn_txt}"),
                            "Confirm the hosting ASN matches your approved cloud/on-prem providers.",
                        ));
                    }
                }
            }
        }
    }

    if do_rdap && is_domain {
        findings.extend(rdap_domain_intel(&client, &host).await);
    }

    if do_shadow_it && !subdomains.is_empty() {
        findings.extend(scan_shadow_it(&subdomains, &host));
    }

    if do_cleartext {
        if let Some(f) = probe_cleartext_http(&client, &host).await {
            findings.push(f);
        }
    }

    if do_wellknown {
        findings.extend(probe_wellknown(&client, &host).await);
        for sub in subdomains.iter().take(3) {
            findings.extend(probe_wellknown(&client, sub).await);
        }
    }

    // ── 3. Service exposure (apex + top subdomains) ──────────────────────────
    if do_ports {
        let mut scan_hosts: Vec<String> = vec![host.clone()];
        scan_hosts.extend(subdomains.iter().take(8).cloned());
        for sh in scan_hosts {
            for (port, svc, open) in scan_ports(&sh, &ports, port_timeout).await {
                if !open {
                    continue;
                }
                let sev = port_severity(port);
                findings.push(asm_finding(
                    "port",
                    sev,
                    format!("{sh}:{port}"),
                    format!("Exposed {svc} (TCP {port}) on {sh}"),
                    "T1190",
                    format!("{svc} is reachable on {sh}:{port} from the public internet."),
                    if sev == "critical" {
                        "Never expose datastores directly; place behind a private network/VPN and restrict by firewall."
                    } else {
                        "Restrict this service to known source ranges; expose only what must be public."
                    },
                ));
                if do_banners {
                    if let Some(banner) = grab_service_banner(&sh, port, port_timeout).await {
                        let banner_lower = banner.to_lowercase();
                        let banner_sev = if banner_lower.contains("redis")
                            || banner_lower.contains("mongodb")
                            || banner_lower.contains("mysql")
                            || banner_lower.contains("unauthorized")
                        {
                            "high"
                        } else if banner.chars().any(|c| c.is_ascii_digit()) {
                            "medium"
                        } else {
                            "info"
                        };
                        findings.push(asm_finding(
                            "banner",
                            banner_sev,
                            format!("{sh}:{port}"),
                            format!("Service banner on {sh}:{port}"),
                            "T1592.002",
                            format!("TCP banner: {banner}"),
                            "Suppress version banners; ensure unauthenticated services are not internet-facing.",
                        ));
                    }
                }
            }
        }
    }

    // ── 4. HTTP & TLS posture (apex + top subdomains) ────────────────────────
    let mut posture_hosts: Vec<String> = vec![host.clone()];
    posture_hosts.extend(subdomains.iter().take(6).cloned());
    for ph in &posture_hosts {
        if do_http {
            let url = format!("https://{ph}");
            if let Some(hp) = http_posture(&client, &url).await {
                if !hp.missing_headers.is_empty() {
                    let sev = if hp.missing_headers.contains(&"Strict-Transport-Security")
                        || hp.missing_headers.contains(&"Content-Security-Policy")
                    {
                        "medium"
                    } else {
                        "low"
                    };
                    findings.push(asm_finding(
                        "http_posture",
                        sev,
                        hp.final_url.clone(),
                        format!(
                            "Missing security headers on {ph} ({} of 6)",
                            hp.missing_headers.len()
                        ),
                        "T1190",
                        format!(
                            "{} returned HTTP {} and is missing: {}.",
                            hp.final_url,
                            hp.status,
                            hp.missing_headers.join(", ")
                        ),
                        "Add the missing response security headers at the web/proxy layer.",
                    ));
                }
                if let Some(server) = hp.server.as_deref() {
                    if server.chars().any(|c| c.is_ascii_digit()) {
                        findings.push(asm_finding(
                            "http_posture",
                            "low",
                            hp.final_url.clone(),
                            format!("Server version disclosed on {ph}"),
                            "T1592.002",
                            format!(
                                "Server header discloses '{server}', aiding targeted exploitation."
                            ),
                            "Suppress version banners (Server / X-Powered-By).",
                        ));
                    }
                }
                if hp.powered_by.is_some() {
                    findings.push(asm_finding(
                        "http_posture",
                        "low",
                        hp.final_url.clone(),
                        format!("X-Powered-By disclosed on {ph}"),
                        "T1592.002",
                        format!(
                            "X-Powered-By header discloses '{}'.",
                            hp.powered_by.unwrap_or_default()
                        ),
                        "Remove the X-Powered-By header.",
                    ));
                }
                if hp.insecure_cookie {
                    findings.push(asm_finding(
                        "http_posture",
                        "medium",
                        hp.final_url.clone(),
                        format!("Insecure cookie flags on {ph}"),
                        "T1539",
                        "A cookie over HTTPS is missing the Secure and/or HttpOnly attribute."
                            .to_string(),
                        "Set Secure, HttpOnly and SameSite on all session cookies.",
                    ));
                }
                for c in hp.cloud_signals {
                    findings.push(asm_finding(
                        "cloud_footprint",
                        "info",
                        ph,
                        format!("Cloud/CDN attribution for {ph}: {c}"),
                        "T1590",
                        format!("HTTP response headers attribute {ph} to {c}."),
                        "Confirm the asset is governed under your cloud security program.",
                    ));
                }
            }
            if do_cors {
                if let Some(f) = probe_cors_misconfig(&client, ph).await {
                    findings.push(f);
                }
            }
            if do_sensitive {
                findings.extend(probe_sensitive_paths(&client, ph).await);
            }
            if do_robots {
                findings.extend(harvest_robots_txt(&client, ph).await);
            }
        }
        if do_tls {
            if let Some(tls) = tls_posture(ph.clone(), 443, http_timeout).await {
                if tls.expired {
                    findings.push(asm_finding(
                        "tls_posture",
                        "high",
                        ph,
                        format!("Expired TLS certificate on {ph}"),
                        "T1190",
                        format!(
                            "Certificate for {ph} (CN={}, issuer={}) expired {} day(s) ago.",
                            tls.subject,
                            tls.issuer,
                            tls.days_to_expiry.abs()
                        ),
                        "Renew and automate certificate rotation (e.g. ACME).",
                    ));
                } else if tls.days_to_expiry <= 21 {
                    findings.push(asm_finding(
                        "tls_posture",
                        "medium",
                        ph,
                        format!("TLS certificate expiring soon on {ph}"),
                        "T1190",
                        format!(
                            "Certificate for {ph} expires in {} day(s).",
                            tls.days_to_expiry
                        ),
                        "Renew before expiry; automate rotation.",
                    ));
                }
                if tls.self_signed {
                    findings.push(asm_finding(
                        "tls_posture",
                        "medium",
                        ph,
                        format!("Self-signed TLS certificate on {ph}"),
                        "T1587.003",
                        format!(
                            "Certificate for {ph} appears self-signed (CN={}).",
                            tls.subject
                        ),
                        "Use a publicly-trusted CA-issued certificate.",
                    ));
                }
                if tls.weak_protocol {
                    findings.push(asm_finding(
                        "tls_posture",
                        "high",
                        ph,
                        format!("Weak TLS protocol negotiated on {ph}"),
                        "T1040",
                        format!(
                            "{ph} negotiated {} — a deprecated, attackable protocol.",
                            tls.protocol
                        ),
                        "Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2+ (prefer 1.3).",
                    ));
                }
                if tls.san_count > 100 {
                    findings.push(asm_finding(
                        "tls_posture",
                        "low",
                        ph,
                        format!("Certificate SAN sprawl on {ph}"),
                        "T1590",
                        format!("Certificate covers {} SAN entries — broad blast radius if the key leaks.", tls.san_count),
                        "Split large multi-SAN certificates to limit blast radius.",
                    ));
                }
            }
        }
    }

    // ── 5. Cloud attribution via CNAME / PTR (apex) ──────────────────────────
    if do_dns {
        if let Some(r) = resolver.as_ref() {
            for cname in lookup_strings(r, &host, RecordType::CNAME).await {
                if let Some(provider) = cloud_from_cname(&cname) {
                    findings.push(asm_finding(
                        "cloud_footprint",
                        "info",
                        &host,
                        format!("{host} → {provider} (via CNAME {cname})"),
                        "T1590",
                        format!("{host} is a CNAME to {cname}, attributed to {provider}."),
                        "Ensure the backing cloud resource is owned and monitored.",
                    ));
                }
            }
        }
    }

    // ── 6. Tech fingerprint ──────────────────────────────────────────────────
    if do_fingerprint {
        let mut urls = vec![format!("https://{}", host), format!("http://{}", host)];
        for s in subdomains.iter().take(10) {
            urls.push(format!("https://{}", s));
        }
        let fp = scan_targets_concurrent_with_stealth(&urls, stealth).await;
        for (url, techs) in fp {
            if !techs.is_empty() {
                findings.push(asm_finding(
                    "fingerprint",
                    "info",
                    url.clone(),
                    format!(
                        "Tech stack on {} — {}",
                        url,
                        techs.join(", ").chars().take(140).collect::<String>()
                    ),
                    "T1592.002",
                    format!("Detected technologies: {}.", techs.join(", ")),
                    "Track component versions for vulnerability management.",
                ));
            }
        }
    }

    // ── 7. Subdomain takeover + exposed storage (graph) ──────────────────────
    let mut graph_nodes: Option<Vec<cloud_hunter::GraphNode>> = None;
    let mut graph_edges: Option<Vec<cloud_hunter::GraphEdge>> = None;
    if do_cloud {
        let (mut nodes, mut edges, cloud_findings) =
            cloud_hunter::run_cloud_hunter(&host, &subdomains, stealth).await;
        findings.extend(cloud_findings);
        let shadow_set: BTreeSet<String> = findings
            .iter()
            .filter(|f| f.get("asset").and_then(Value::as_str) == Some("shadow_it"))
            .filter_map(|f| f.get("value").and_then(Value::as_str).map(String::from))
            .collect();
        extend_inventory_graph(&mut nodes, &mut edges, &host, &subdomains, &shadow_set);
        graph_nodes = Some(nodes);
        graph_edges = Some(edges);
    } else if is_domain && !subdomains.is_empty() {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let shadow_set: BTreeSet<String> = findings
            .iter()
            .filter(|f| f.get("asset").and_then(Value::as_str) == Some("shadow_it"))
            .filter_map(|f| f.get("value").and_then(Value::as_str).map(String::from))
            .collect();
        extend_inventory_graph(&mut nodes, &mut edges, &host, &subdomains, &shadow_set);
        if !nodes.is_empty() {
            graph_nodes = Some(nodes);
            graph_edges = Some(edges);
        }
    }

    if do_attack_paths {
        findings.extend(derive_exposure_attack_paths(&findings));
    }

    // ── 8. Threshold filter, scoring, report ─────────────────────────────────
    let min_rank = sev_rank(&threshold);
    findings.retain(|f| {
        let s = f.get("severity").and_then(Value::as_str).unwrap_or("info");
        s == "info" || sev_rank(s) >= min_rank
    });

    let report = build_surface_report(
        &findings,
        &host,
        subdomains.len(),
        &ports,
        &notes,
        &subdomains,
    );
    findings.sort_by(|a, b| {
        let sa = a.get("severity").and_then(Value::as_str).unwrap_or("info");
        let sb = b.get("severity").and_then(Value::as_str).unwrap_or("info");
        sev_rank(sb).cmp(&sev_rank(sa))
    });
    if findings.len() > max_findings {
        findings.truncate(max_findings);
    }
    let mut all: Vec<Value> = Vec::with_capacity(findings.len() + 1);
    all.push(report);
    all.extend(findings);

    let crit = all
        .iter()
        .filter(|f| f.get("severity").and_then(Value::as_str) == Some("critical"))
        .count();
    let msg = format!(
        "EASM scan of {host}: {} finding(s){}, {} subdomain(s)",
        all.len().saturating_sub(1),
        if crit > 0 {
            format!(", {crit} critical")
        } else {
            String::new()
        },
        subdomains.len()
    );

    if let (Some(nodes), Some(edges)) = (graph_nodes, graph_edges) {
        EngineResult::ok_with_graph(all, msg, nodes, edges)
    } else {
        EngineResult::ok(all, msg)
    }
}

fn build_surface_report(
    findings: &[Value],
    host: &str,
    subdomain_count: usize,
    ports: &[u16],
    notes: &[String],
    subdomain_inventory: &[String],
) -> Value {
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for s in ["critical", "high", "medium", "low", "info"] {
        counts.insert(s, 0);
    }
    let mut by_asset: BTreeMap<String, u32> = BTreeMap::new();
    let mut penalty = 0i32;
    let mut exposed_ports = 0u32;
    let mut takeovers = 0u32;
    let mut attack_paths = 0u32;
    let mut shadow_it = 0u32;
    let mut banners = 0u32;
    let mut sensitive_leaks = 0u32;
    for f in findings {
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("info");
        *counts.entry(sev).or_insert(0) += 1;
        let asset = f.get("asset").and_then(Value::as_str).unwrap_or("other");
        *by_asset.entry(asset.to_string()).or_insert(0) += 1;
        if asset == "port" {
            exposed_ports += 1;
        }
        if asset == "attack_path" {
            attack_paths += 1;
        }
        if asset == "shadow_it" {
            shadow_it += 1;
        }
        if asset == "banner" {
            banners += 1;
        }
        if asset == "sensitive_path" {
            sensitive_leaks += 1;
        }
        let title = f.get("title").and_then(Value::as_str).unwrap_or("");
        let subtype = f.get("subtype").and_then(Value::as_str).unwrap_or("");
        if title.to_lowercase().contains("takeover") || subtype.contains("takeover") {
            takeovers += 1;
        }
        penalty += match sev {
            "critical" => 15,
            "high" => 8,
            "medium" => 3,
            "low" => 1,
            _ => 0,
        };
    }
    let score = (100 - penalty).clamp(0, 100);
    let queue = remediation_queue(findings, 8);
    let path_summaries: Vec<Value> = findings
        .iter()
        .filter(|f| f.get("asset").and_then(Value::as_str) == Some("attack_path"))
        .map(|f| {
            json!({
                "title": f.get("title").and_then(Value::as_str).unwrap_or(""),
                "severity": f.get("severity").and_then(Value::as_str).unwrap_or("critical"),
                "value": f.get("value").and_then(Value::as_str).unwrap_or(""),
            })
        })
        .collect();

    json!({
        "type": "attack_surface_report",
        "engine_id": "asm",
        "asset": "report",
        "report": true,
        "title": format!("Attack Surface: grade {} ({}/100) for {}", surface_grade(score), score, host),
        "severity": if counts.get("critical").copied().unwrap_or(0) > 0 { "critical" }
                    else if counts.get("high").copied().unwrap_or(0) > 0 { "high" }
                    else { "info" },
        "mitre_attack": "T1595",
        "description": format!(
            "External attack-surface assessment of {host}: {} subdomain asset(s), {} exposed service(s), {} takeover risk(s), {} attack path(s), {} shadow-IT signal(s). Surface score {}/100 (grade {}).",
            subdomain_count, exposed_ports, takeovers, attack_paths, shadow_it, score, surface_grade(score)
        ),
        "surface_score": score,
        "grade": surface_grade(score),
        "host": host,
        "subdomain_count": subdomain_count,
        "exposed_services": exposed_ports,
        "takeover_risks": takeovers,
        "attack_paths": attack_paths,
        "shadow_it_signals": shadow_it,
        "service_banners": banners,
        "sensitive_path_hits": sensitive_leaks,
        "attack_path_summaries": path_summaries,
        "remediation_queue": queue,
        "subdomain_inventory": subdomain_inventory,
        "ports_scanned": ports.len(),
        "severity_counts": {
            "critical": counts.get("critical").copied().unwrap_or(0),
            "high": counts.get("high").copied().unwrap_or(0),
            "medium": counts.get("medium").copied().unwrap_or(0),
            "low": counts.get("low").copied().unwrap_or(0),
            "info": counts.get("info").copied().unwrap_or(0),
        },
        "exposure_by_asset": by_asset,
        "notes": notes,
        "remediation": "Reduce internet-facing exposure first (datastores, admin services), fix takeover risks, then harden TLS/HTTP posture.",
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — offline-safe (helpers only; no network).
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_variants() {
        assert_eq!(parse_ports("top"), TOP_PORTS.to_vec());
        assert_eq!(parse_ports(""), TOP_PORTS.to_vec());
        assert_eq!(parse_ports("80,443"), vec![80, 443]);
        let r = parse_ports("8080-8082,22");
        assert!(r.contains(&22) && r.contains(&8080) && r.contains(&8082));
    }

    #[test]
    fn port_classification() {
        assert_eq!(port_severity(3306), "critical");
        assert_eq!(port_severity(22), "high");
        assert_eq!(port_severity(80), "medium");
        assert_eq!(service_name(6379), "Redis");
        assert_eq!(service_name(443), "HTTPS");
    }

    #[test]
    fn cloud_attribution() {
        assert_eq!(cloud_from_cname("foo.s3.amazonaws.com"), Some("AWS"));
        assert_eq!(cloud_from_cname("app.azurewebsites.net"), Some("Azure"));
        assert_eq!(cloud_from_cname("example.com"), None);
    }

    #[test]
    fn shadow_it_detection() {
        assert!(is_shadow_it_host("dev.example.com", "example.com").is_some());
        assert!(is_shadow_it_host("staging-api.example.com", "example.com").is_some());
        assert!(is_shadow_it_host("www.example.com", "example.com").is_none());
    }

    #[test]
    fn attack_path_correlation() {
        let findings = vec![
            json!({"asset":"port","severity":"critical","title":"Exposed MySQL","value":"db.example.com:3306"}),
            json!({"asset":"email_posture","severity":"high","title":"No SPF","value":"example.com"}),
        ];
        let paths = derive_exposure_attack_paths(&findings);
        assert!(!paths.is_empty());
        assert_eq!(paths[0]["asset"], json!("attack_path"));
    }

    #[test]
    fn remediation_queue_orders_by_severity() {
        assert_eq!(surface_grade(95), "A");
        assert_eq!(surface_grade(40), "F");
        let findings = vec![
            json!({"asset":"port","severity":"critical","title":"Exposed MySQL"}),
            json!({"asset":"http_posture","severity":"low","title":"Missing headers"}),
        ];
        let report = build_surface_report(&findings, "example.com", 3, &TOP_PORTS, &[], &[]);
        assert_eq!(report["surface_score"], json!(100 - 15 - 1));
        assert_eq!(report["exposed_services"], json!(1));
        assert_eq!(report["severity"], json!("critical"));
    }

    #[test]
    fn target_host_parsing() {
        assert_eq!(
            target_to_host("https://example.com/path").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            target_to_host("EXAMPLE.com").as_deref(),
            Some("example.com")
        );
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let ctx = EngineRunContext::default();
        let r = run_asm_result_ctx("", &ctx, None).await;
        assert!(!r.success);
    }
}
