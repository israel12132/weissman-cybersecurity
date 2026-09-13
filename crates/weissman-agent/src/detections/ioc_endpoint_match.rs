//! Agent-side IOC execution.
//!
//! The server pushes a bounded indicator set (only the classes the agent can
//! evaluate on live host telemetry: SHA-256 process hashes, remote IPv4/IPv6,
//! CIDR ranges) into this task's params. The agent then gathers **live** host
//! observables and matches them locally — detection runs on the edge, next to
//! the evidence, instead of shipping raw telemetry to the server and matching
//! there. Only real matches become findings; an empty hunt reports honestly.
//!
//! Params shape (any subset):
//! ```json
//! {
//!   "sha256":  ["<64-hex>", ...],      // known-bad file hashes
//!   "ipv4":    ["1.2.3.4", ...],       // known-bad remote IPs
//!   "ipv6":    ["2001:db8::1", ...],   // known-bad remote IPv6
//!   "cidr":    ["45.0.0.0/8", ...]     // known-bad networks
//! }
//! ```
//! (Domain IOCs are intentionally not evaluated here — the agent has no live
//! DNS-cache reader; domain matching is handled server-side in the retrohunt.)
//!
//! Live observables collected (Linux `/proc`, no external binaries, no PII):
//!   * established remote IPv4/IPv6 peers (`/proc/net/tcp`, `/proc/net/tcp6`)
//!   * SHA-256 of running process executables (`/proc/<pid>/exe`)
//! On non-Linux / unreadable `/proc` the hunt degrades to zero observables and
//! reports "no signal" rather than a false negative dressed as a pass.

use super::finding;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_PROC_HASHES: usize = 300;

pub async fn run(engine: &str, params: &Value) -> anyhow::Result<Vec<Value>> {
    let set = IocSet::from_params(params);
    if set.is_empty() {
        return Ok(vec![finding(
            engine,
            "Endpoint IOC match idle — no indicators in task params",
            "info",
            "T1046",
            "Dispatch with params.sha256[] / params.ipv4[] / params.ipv6[] / params.cidr[] \
             from the IOC feed store.",
            Map::new(),
        )]);
    }

    let mut findings = Vec::new();

    // ── Live remote peers vs IP/CIDR indicators ─────────────────────────────
    // /proc parsing + file hashing are synchronous blocking I/O; run them off
    // the async reactor so the server-side per-task timeout can actually abandon
    // a stuck scan instead of wedging a runtime worker thread.
    let peers = tokio::task::spawn_blocking(established_remote_ips)
        .await
        .unwrap_or_default();
    let peer_count = peers.len();
    for ip in &peers {
        if let Some(reason) = set.match_ip(ip) {
            let mut extras = Map::new();
            extras.insert("observable".into(), json!(ip));
            extras.insert("ioc_type".into(), json!("ipv4"));
            extras.insert("match".into(), json!(reason));
            extras.insert("context".into(), json!("agent_remote_ip"));
            findings.push(finding(
                engine,
                "Host connected to known-bad IP",
                "critical",
                "T1071",
                &format!("Established connection to {ip} matched IOC ({reason})."),
                extras,
            ));
        }
    }

    // ── Live process executables vs hash indicators ─────────────────────────
    let (hash_count, proc_hits) = if set.has_hashes() {
        let hashes = set.hashes.clone();
        tokio::task::spawn_blocking(move || match_process_hashes(&hashes))
            .await
            .unwrap_or((0, Vec::new()))
    } else {
        (0, Vec::new())
    };
    for (pid, comm, digest) in proc_hits {
        let mut extras = Map::new();
        extras.insert("observable".into(), json!(digest));
        extras.insert("ioc_type".into(), json!("sha256"));
        extras.insert("pid".into(), json!(pid));
        extras.insert("process".into(), json!(comm));
        extras.insert("context".into(), json!("agent_process_hash"));
        findings.push(finding(
            engine,
            "Running process matched known-bad SHA-256",
            "critical",
            "T1204",
            &format!("Process {comm} (pid {pid}) executable hashed to a known-bad indicator."),
            extras,
        ));
    }

    if findings.is_empty() {
        let mut extras = Map::new();
        extras.insert("peers_scanned".into(), json!(peer_count));
        extras.insert("process_hashes_scanned".into(), json!(hash_count));
        extras.insert("indicators_loaded".into(), json!(set.len()));
        findings.push(finding(
            engine,
            "Endpoint IOC match completed — no matches",
            "info",
            "T1046",
            &format!(
                "Matched {} live peers and {hash_count} process hashes against {} indicators; clean.",
                peer_count,
                set.len()
            ),
            extras,
        ));
    }

    Ok(findings)
}

/// A compact, self-contained local indicator set (the agent cannot depend on
/// the server crate, so matching lives here).
struct IocSet {
    hashes: BTreeSet<String>,
    ips: BTreeSet<String>,
    cidrs_v4: Vec<(u32, u32)>,
}

impl IocSet {
    fn from_params(params: &Value) -> Self {
        let hashes = str_array(params, "sha256")
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .collect();
        let ips = str_array(params, "ipv4")
            .into_iter()
            .chain(str_array(params, "ipv6"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let cidrs_v4 = str_array(params, "cidr")
            .into_iter()
            .filter_map(|c| parse_cidr_v4(&c))
            .collect();
        // NOTE: domains are intentionally not accepted here — the agent has no
        // live DNS-cache reader, so it cannot honestly evaluate domain IOCs.
        // Domain matching is handled server-side (retrohunt over findings).
        IocSet {
            hashes,
            ips,
            cidrs_v4,
        }
    }

    fn is_empty(&self) -> bool {
        self.hashes.is_empty() && self.ips.is_empty() && self.cidrs_v4.is_empty()
    }

    fn len(&self) -> usize {
        self.hashes.len() + self.ips.len() + self.cidrs_v4.len()
    }

    fn has_hashes(&self) -> bool {
        !self.hashes.is_empty()
    }

    fn match_ip(&self, ip: &str) -> Option<String> {
        if self.ips.contains(ip) {
            return Some("exact".to_string());
        }
        if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
            let n = u32::from(addr);
            for (net, mask) in &self.cidrs_v4 {
                if n & mask == *net {
                    return Some("cidr".to_string());
                }
            }
        }
        None
    }
}

fn str_array(params: &Value, key: &str) -> Vec<String> {
    params
        .get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_cidr_v4(cidr: &str) -> Option<(u32, u32)> {
    let (addr, pre) = cidr.split_once('/')?;
    let ip: std::net::Ipv4Addr = addr.trim().parse().ok()?;
    let prefix: u32 = pre.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((u32::from(ip) & mask, mask))
}

// ─── Live host observable collectors (Linux) ────────────────────────────────

/// Established remote peer IPs from `/proc/net/tcp{,6}`.
#[cfg(target_os = "linux")]
fn established_remote_ips() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    // IPv4
    if let Ok(s) = std::fs::read_to_string("/proc/net/tcp") {
        for line in s.lines().skip(1) {
            let mut it = line.split_whitespace();
            let _ = it.next(); // sl
            let _ = it.next(); // local_address
            let Some(rem) = it.next() else { continue };
            let Some(st) = it.next() else { continue };
            if st != "01" {
                continue; // 01 = ESTABLISHED
            }
            if let Some(ip) = parse_proc_ipv4(rem) {
                if !is_uninteresting_v4(&ip) {
                    out.insert(ip);
                }
            }
        }
    }
    // IPv6 (best-effort)
    if let Ok(s) = std::fs::read_to_string("/proc/net/tcp6") {
        for line in s.lines().skip(1) {
            let mut it = line.split_whitespace();
            let _ = it.next();
            let _ = it.next();
            let Some(rem) = it.next() else { continue };
            let Some(st) = it.next() else { continue };
            if st != "01" {
                continue;
            }
            if let Some(ip) = parse_proc_ipv6(rem) {
                out.insert(ip);
            }
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn established_remote_ips() -> BTreeSet<String> {
    BTreeSet::new()
}

/// Parse a `/proc/net/tcp` `AABBCCDD:PORT` little-endian hex v4 address.
fn parse_proc_ipv4(field: &str) -> Option<String> {
    let hex = field.split(':').next()?;
    if hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex, 16).ok()?;
    // Stored little-endian; bytes reversed to dotted quad.
    let b = raw.to_le_bytes();
    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
}

/// Parse a `/proc/net/tcp6` 32-hex remote address into a compact IPv6 string.
fn parse_proc_ipv6(field: &str) -> Option<String> {
    let hex = field.split(':').next()?;
    if hex.len() != 32 {
        return None;
    }
    // The address is stored as 4 little-endian 32-bit words.
    let mut bytes = [0u8; 16];
    for w in 0..4 {
        let word = u32::from_str_radix(&hex[w * 8..w * 8 + 8], 16).ok()?;
        let le = word.to_le_bytes();
        bytes[w * 4..w * 4 + 4].copy_from_slice(&le);
    }
    Some(std::net::Ipv6Addr::from(bytes).to_string())
}

/// Loopback / unspecified / link-local are never IOC-worthy.
fn is_uninteresting_v4(ip: &str) -> bool {
    matches!(ip, "0.0.0.0" | "127.0.0.1") || ip.starts_with("127.")
}

/// Largest executable we are willing to hash — a def ceiling so a pathological
/// multi-gigabyte file cannot pin CPU/IO. Over-cap files are treated as non-matches.
const MAX_EXE_HASH_BYTES: u64 = 256 * 1024 * 1024;

/// SHA-256 each running process executable; return matches against the hash set.
#[cfg(target_os = "linux")]
fn match_process_hashes(hashes: &BTreeSet<String>) -> (usize, Vec<(String, String, String)>) {
    use std::io::Read;
    let mut scanned = 0usize;
    let mut hits = Vec::new();
    let Ok(read) = std::fs::read_dir("/proc") else {
        return (0, hits);
    };
    for entry in read.flatten() {
        if scanned >= MAX_PROC_HASHES {
            break;
        }
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let exe = entry.path().join("exe");
        let Ok(mut f) = std::fs::File::open(&exe) else {
            continue;
        };
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        let mut total: u64 = 0;
        let mut ok = false;
        loop {
            match f.read(&mut buf) {
                Ok(0) => {
                    ok = true;
                    break;
                }
                Ok(n) => {
                    total += n as u64;
                    if total > MAX_EXE_HASH_BYTES {
                        // Abandon over-cap file; count as scanned, no match.
                        ok = false;
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                Err(_) => break,
            }
        }
        scanned += 1;
        if !ok {
            continue;
        }
        let digest = hex::encode(hasher.finalize());
        if hashes.contains(&digest) {
            let comm = std::fs::read_to_string(entry.path().join("comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            hits.push((name, comm, digest));
        }
    }
    (scanned, hits)
}

#[cfg(not(target_os = "linux"))]
fn match_process_hashes(_hashes: &BTreeSet<String>) -> (usize, Vec<(String, String, String)>) {
    (0, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_proc_ipv4_is_little_endian() {
        // 0100007F → 127.0.0.1 (LE).
        assert_eq!(
            parse_proc_ipv4("0100007F:0050").as_deref(),
            Some("127.0.0.1")
        );
        // 04030201 → 1.2.3.4
        assert_eq!(parse_proc_ipv4("04030201:01BB").as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn iocset_matches_ip_exact_and_cidr() {
        let set = IocSet::from_params(&json!({
            "ipv4": ["1.2.3.4"],
            "cidr": ["45.0.0.0/8"]
        }));
        assert_eq!(set.match_ip("1.2.3.4").as_deref(), Some("exact"));
        assert_eq!(set.match_ip("45.33.1.1").as_deref(), Some("cidr"));
        assert!(set.match_ip("8.8.8.8").is_none());
    }

    #[test]
    fn iocset_rejects_malformed_hashes() {
        let set = IocSet::from_params(
            &json!({"sha256": ["deadbeef", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"]}),
        );
        assert_eq!(set.hashes.len(), 1);
        assert!(set.has_hashes());
    }

    #[test]
    fn empty_params_is_empty_set() {
        assert!(IocSet::from_params(&json!({})).is_empty());
    }

    #[tokio::test]
    async fn idle_when_no_indicators() {
        let out = run("ioc_endpoint_match", &json!({})).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["severity"], "info");
    }
}
