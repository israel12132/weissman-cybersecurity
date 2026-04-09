//! ASM: port scan (TCP) + CT subdomains + fingerprint + Module 3 cloud hunter (takeover, S3/Azure).
//! Module 2: fingerprint phase uses stealth. Module 3: graph nodes/edges for Attack Surface view.

use crate::cloud_hunter;
use crate::engine_result::{print_result, EngineResult};
use crate::fingerprint::scan_targets_concurrent_with_stealth;
use crate::recon::{enum_subdomains, enum_subdomains_default};
use futures::future::join_all;
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// Fast-fail dead ports; full connect attempt budget is still large when scanning many hosts in parallel upstream.
const PORT_TIMEOUT_MS: u64 = 350;
/// Default ports: classic attack surface plus common cloud / API / observability / dev ports.
pub const TOP_PORTS: [u16; 45] = [
    80, 443, 8080, 8443, 8008, 8888, 9443, 3000, 3001, 4200, 5000, 5001, 5601, 5602, 6333, 7474, 7687,
    22, 21, 25, 53, 111, 135, 139, 445, 1433, 3389, 5900,
    3306, 5432, 27017, 6379, 9200, 9300, 5984, 11211, 1521, 1434,
    9000, 9090, 9091, 6443, 10250, 2375, 4243,
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
    Some(target)
}

async fn port_open(host: &str, port: u16) -> bool {
    let addr: SocketAddr = match format!("{}:{}", host, port).parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    match tokio::time::timeout(
        Duration::from_millis(PORT_TIMEOUT_MS),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

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

    // Port scan — all probes in parallel (one target host; fan-out matches multi-core throughput).
    let host_arc = std::sync::Arc::new(host.clone());
    let checks: Vec<_> = ports
        .iter()
        .copied()
        .map(|port| {
            let h = host_arc.clone();
            async move {
                let open = port_open(h.as_str(), port).await;
                (port, open)
            }
        })
        .collect();
    for (port, open) in join_all(checks).await {
        if !open {
            continue;
        }
        let severity = if matches!(
            port,
            21 | 22 | 23 | 25 | 3306 | 5432 | 6379 | 1433 | 3389 | 5900 | 2375 | 10250
        ) {
            "high"
        } else {
            "medium"
        };
        findings.push(json!({
            "type": "asm",
            "asset": "port",
            "title": format!("Exposed TCP port {} on host {}", port, host),
            "value": format!("{}:{}", host, port),
            "port": port,
            "severity": severity
        }));
    }

    // Subdomain enum + fingerprint if it looks like a domain
    if host.contains('.') && !host.parse::<std::net::IpAddr>().is_ok() {
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

        // Module 3: Cloud Hunter — CNAME takeover + exposed S3/Azure; build graph nodes/edges
        let (nodes, edges, cloud_findings) =
            cloud_hunter::run_cloud_hunter(&host, &subs, stealth).await;
        for f in cloud_findings {
            findings.push(f);
        }
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
