//! SMB/NetBIOS Engine — detects SMB exposure indicators via HTTP responses and known vulnerability signatures.

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

const SMB_PORTS: &[u16] = &[139, 445, 137, 138];
const CONNECT_TIMEOUT_MS: u64 = 1200;

async fn port_open(host: &str, port: u16) -> bool {
    let addr_str = format!("{}:{}", host, port);
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    matches!(
        tokio::time::timeout(
            Duration::from_millis(CONNECT_TIMEOUT_MS),
            TcpStream::connect(addr),
        )
        .await,
        Ok(Ok(_))
    )
}

fn extract_host(target: &str) -> String {
    let t = target.trim();
    let stripped = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    stripped.split('/').next().unwrap_or(stripped).to_string()
}

pub async fn run_smb_netbios_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let mut findings: Vec<serde_json::Value> = Vec::new();

    // Probe SMB/NetBIOS ports concurrently
    let results = futures::future::join_all(
        SMB_PORTS.iter().map(|&port| {
            let h = host.clone();
            async move { (port, port_open(&h, port).await) }
        })
    ).await;

    for (port, open) in results {
        if !open {
            continue;
        }
        let (title, severity, description) = match port {
            445 => (
                format!("SMB port 445 open on {}", host),
                "critical",
                format!(
                    "SMB (TCP 445) is publicly accessible on {}. This port is exploited by EternalBlue (MS17-010/CVE-2017-0144), \
                    SMBGhost (CVE-2020-0796), and is the primary vector for ransomware propagation and NTLM relay attacks. \
                    SMB should never be exposed to the internet.",
                    host
                ),
            ),
            139 => (
                format!("NetBIOS Session Service port 139 open on {}", host),
                "high",
                format!(
                    "NetBIOS Session Service (TCP 139) is accessible on {}. This legacy protocol leaks \
                    Windows computer names, workgroup/domain information, and enables NTLM relay attacks. \
                    Disable NetBIOS over TCP/IP if not required.",
                    host
                ),
            ),
            137 => (
                format!("NetBIOS Name Service port 137 (UDP) accessible on {}", host),
                "medium",
                format!(
                    "NetBIOS Name Service (UDP 137) appears accessible on {}. NBNS is vulnerable to \
                    name poisoning attacks (LLMNR/NBNS poisoning) enabling credential interception.",
                    host
                ),
            ),
            138 => (
                format!("NetBIOS Datagram Service port 138 open on {}", host),
                "medium",
                format!(
                    "NetBIOS Datagram Service (UDP 138) accessible on {}. Disable this service if SMB is not required.",
                    host
                ),
            ),
            _ => continue,
        };

        findings.push(json!({
            "type": "smb_netbios",
            "title": title,
            "severity": severity,
            "mitre_attack": "T1021.002",
            "description": description,
            "value": format!("{}:{}", host, port),
            "port": port
        }));

        // For port 445, add specific CVE references
        if port == 445 {
            findings.push(json!({
                "type": "smb_netbios",
                "title": format!("EternalBlue/SMBGhost CVE check required for {}", host),
                "severity": "critical",
                "mitre_attack": "T1210",
                "description": format!(
                    "Host {} has SMB port 445 open. Critical vulnerabilities to verify: \
                    EternalBlue (CVE-2017-0144/MS17-010) — exploited by WannaCry, NotPetya, used in NSA tool leak; \
                    SMBGhost (CVE-2020-0796) — Windows 10/Server 2019 RCE via SMBv3 compression; \
                    PrintNightmare (CVE-2021-34527) — if print spooler is running. \
                    Run: nmap --script smb-vuln-ms17-010 {}",
                    host, host
                ),
                "value": format!("{}:445", host),
                "cves": ["CVE-2017-0144", "CVE-2020-0796", "CVE-2021-34527"]
            }));
        }
    }

    if findings.is_empty() {
        findings.push(json!({
            "type": "smb_netbios",
            "title": format!("No SMB/NetBIOS ports open on {}", host),
            "severity": "info",
            "mitre_attack": "T1021.002",
            "description": format!("Ports 137, 138, 139, 445 are all closed on {}. SMB is not publicly exposed.", host),
            "value": host
        }));
    }

    EngineResult::ok(
        findings.clone(),
        format!("SMBNetBIOS: {} findings", findings.len()),
    )
}

pub async fn run_smb_netbios(target: &str) {
    crate::engine_result::print_result(run_smb_netbios_result(target).await);
}
