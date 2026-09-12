//! **Ransomware preposition surface** — live TCP of backup/RDP/SMB/WinRM/AD.
//!
//! Evidence is open ports from the scan origin. No encryption, no wiper, no
//! credential spray. Closed ports yield `empty_ok`, never a fake critical.

use crate::engine_probes::{empty_ok, extract_host, finding, tcp_banner, tcp_scan};
use crate::engine_result::EngineResult;
use serde_json::json;

pub const ENGINE_ID: &str = "ransomware_preposition_surface";
const MITRE: &str = "T1021";

/// Ports that ransomware crews actually pre-position on — not a full nmap.
pub const PREPOSITION_PORTS: &[u16] = &[
    445, 3389, 5985, 5986, 139, 22, 88, 389, 636, 3268, 3269, 2049, 111, 10000, 3260,
];

const LATERAL: &[u16] = &[445, 3389, 5985, 5986, 139];
const IDENTITY: &[u16] = &[88, 389, 636, 3268, 3269];
const BACKUP: &[u16] = &[2049, 111, 10000, 3260];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepositionScore {
    pub severity: &'static str,
    pub title: String,
    pub reason: String,
}

/// Score from the observed open-port set. Pure — tests do not need a network.
#[must_use]
pub fn score_preposition(open: &[u16]) -> Option<PrepositionScore> {
    if open.is_empty() {
        return None;
    }
    let has = |p: u16| open.contains(&p);
    let lateral_n = LATERAL.iter().filter(|p| has(**p)).count();
    let ident_n = IDENTITY.iter().filter(|p| has(**p)).count();
    let backup_n = BACKUP.iter().filter(|p| has(**p)).count();

    if (has(445) && has(3389)) || (has(445) && has(88)) || lateral_n >= 3 {
        return Some(PrepositionScore {
            severity: "critical",
            title: "Ransomware preposition: SMB/RDP/WinRM reachable from scan origin".into(),
            reason: format!(
                "Open {:?} — lateral {} / identity {} / backup {}. This is the live preposition surface (T1021/T1486-prep), not a simulated encrypt.",
                open, lateral_n, ident_n, backup_n
            ),
        });
    }
    if lateral_n >= 1 && (ident_n >= 1 || backup_n >= 1) {
        return Some(PrepositionScore {
            severity: "high",
            title: "Ransomware preposition: lateral port plus identity or backup".into(),
            reason: format!(
                "Open {:?}. Pairing a file/admin protocol with Kerberos/LDAP or backup (NFS/NDMP/iSCSI) is how crews stage.",
                open
            ),
        });
    }
    if lateral_n >= 1 || ident_n >= 1 || backup_n >= 1 || has(22) {
        return Some(PrepositionScore {
            severity: if lateral_n >= 1 || ident_n >= 1 {
                "medium"
            } else {
                "low"
            },
            title: "Ransomware-relevant port open from scan origin".into(),
            reason: format!(
                "Open {:?}. Not a confirmed encrypt path — prove containment on these listeners.",
                open
            ),
        });
    }
    None
}

fn port_label(port: u16) -> &'static str {
    match port {
        445 => "SMB",
        3389 => "RDP",
        5985 => "WinRM",
        5986 => "WinRM-TLS",
        139 => "NetBIOS",
        22 => "SSH",
        88 => "Kerberos",
        389 => "LDAP",
        636 => "LDAPS",
        3268 => "GC",
        3269 => "GC-TLS",
        2049 => "NFS",
        111 => "portmap",
        10000 => "NDMP",
        3260 => "iSCSI",
        _ => "tcp",
    }
}

pub async fn run_ransomware_preposition_surface_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    if host.is_empty() {
        return EngineResult::error("target required");
    }

    let open = tcp_scan(&host, PREPOSITION_PORTS, 8).await;
    let mut findings = Vec::new();
    for port in &open {
        let banner = tcp_banner(&host, *port).await.unwrap_or_default();
        let label = port_label(*port);
        findings.push(finding(
            ENGINE_ID,
            &format!("{label}/{port} open on {host}"),
            if LATERAL.contains(port) || IDENTITY.contains(port) {
                "high"
            } else {
                "medium"
            },
            MITRE,
            &format!(
                "TCP connect from Weissman scan origin succeeded on {host}:{port} ({label}). Banner (truncated): {}",
                if banner.is_empty() {
                    "(none in 1.5s)".to_string()
                } else {
                    banner.chars().take(180).collect()
                }
            ),
            target,
        ));
        if let Some(obj) = findings.last_mut().and_then(|f| f.as_object_mut()) {
            obj.insert("port".into(), json!(port));
            obj.insert("protocol".into(), json!(label));
            obj.insert("asset".into(), json!("ransomware_preposition"));
        }
    }

    if let Some(score) = score_preposition(&open) {
        findings.insert(
            0,
            finding(
                ENGINE_ID,
                &score.title,
                score.severity,
                "T1486",
                &score.reason,
                target,
            ),
        );
    }

    if findings.is_empty() {
        empty_ok(ENGINE_ID, target)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("{ENGINE_ID}: open={}", open.len()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ports_not_a_finding() {
        assert!(score_preposition(&[]).is_none());
    }

    #[test]
    fn smb_plus_rdp_is_critical() {
        let s = score_preposition(&[445, 3389]).expect("score");
        assert_eq!(s.severity, "critical");
    }

    #[test]
    fn smb_plus_kerberos_is_critical() {
        let s = score_preposition(&[445, 88]).expect("score");
        assert_eq!(s.severity, "critical");
    }

    #[test]
    fn nfs_only_is_low() {
        let s = score_preposition(&[2049]).expect("score");
        assert_eq!(s.severity, "low");
    }

    #[test]
    fn rdp_plus_ldap_is_high() {
        let s = score_preposition(&[3389, 389]).expect("score");
        assert_eq!(s.severity, "high");
    }
}
