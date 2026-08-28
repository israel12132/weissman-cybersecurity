//! DNS fallback cascade: DoH → DoT → organisation-internal UDP.
//!
//! Public DoH (Cloudflare/Google) is blocked on a large fraction of enterprise
//! web gateways. Failing closed to "no DNS" bricks every active engine that
//! needs MX/TXT/CAA. Public UDP recursive (1.1.1.1 / 8.8.8.8) stays off unless
//! the lab flag `WEISSMAN_DNS_ALLOW_UDP=1` is set.
//!
//! Internal UDP is restricted to `WEISSMAN_DNS_INTERNAL_RESOLVERS` (comma-separated
//! IPs of the organisation's own resolvers). Well-known public anycast recursors
//! in that list are ignored so a misconfig cannot re-enable public UDP.

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::stealth_ops::{doh_lookup_detailed, strip_doh_txt, DohLookup};
use serde_json::{json, Value};

const DOT_UPSTREAMS: &[(&str, &str, u16)] = &[
    ("1.1.1.1", "cloudflare-dns.com", 853),
    ("8.8.8.8", "dns.google", 853),
    ("9.9.9.9", "dns.quad9.net", 853),
];

/// Public anycast recursors that must never be treated as "internal".
const PUBLIC_RECURSIVE_V4: &[[u8; 4]] = &[
    [1, 1, 1, 1],
    [1, 0, 0, 1],
    [8, 8, 8, 8],
    [8, 8, 4, 4],
    [9, 9, 9, 9],
    [9, 9, 9, 10],
    [208, 67, 222, 222],
    [208, 67, 220, 220],
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeResult {
    pub answers: Vec<String>,
    pub method: &'static str,
}

impl CascadeResult {
    fn empty() -> Self {
        Self {
            answers: Vec::new(),
            method: "none",
        }
    }
}

/// Production DNS lookup. Empty vec means every stage failed or the name has
/// no records — callers must not invent answers.
pub async fn lookup(name: &str, record_type: &str) -> Vec<String> {
    lookup_detailed(name, record_type).await.answers
}

pub async fn lookup_detailed(name: &str, record_type: &str) -> CascadeResult {
    let host = name.trim().trim_end_matches('.');
    if host.is_empty() {
        return CascadeResult::empty();
    }
    let rr = record_type.trim();

    match doh_lookup_detailed(host, rr).await {
        Ok(DohLookup {
            answers,
            definitive,
        }) if definitive || !answers.is_empty() => {
            return CascadeResult {
                answers,
                method: "doh",
            };
        }
        Ok(_) | Err(_) => {}
    }

    if let Some(dot) = dot_lookup(host, rr).await {
        if dot.definitive || !dot.answers.is_empty() {
            return CascadeResult {
                answers: dot.answers,
                method: "dot",
            };
        }
    }

    let internal = internal_udp_resolvers();
    if !internal.is_empty() {
        if let Some(answers) = udp_lookup_at(host, rr, &internal).await {
            // DoH and DoT both failed to produce a definitive answer. Falling
            // back to internal UDP is an approved last hop — and a SOC-visible
            // signal that TCP/853 may be jammed for eavesdropping.
            emit_udp_downgrade_soc(host, rr);
            return CascadeResult {
                answers,
                method: "udp_internal",
            };
        }
    }

    CascadeResult::empty()
}

pub fn is_well_known_public_recursive(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => PUBLIC_RECURSIVE_V4.iter().any(|o| v.octets() == *o),
        IpAddr::V6(v) => {
            // Cloudflare 2606:4700:4700::1111 / ::1001, Google 2001:4860:4860::8888 / ::8844
            let o = v.octets();
            (o.starts_with(&[0x26, 0x06, 0x47, 0x00, 0x47, 0x00]) && o[15] == 0x11)
                || (o.starts_with(&[0x20, 0x01, 0x48, 0x60, 0x48, 0x60]))
        }
    }
}

/// Organisation resolvers from `WEISSMAN_DNS_INTERNAL_RESOLVERS`. Public anycast
/// IPs are stripped so this cannot silently become public UDP.
pub fn internal_udp_resolvers() -> Vec<IpAddr> {
    let raw = match std::env::var("WEISSMAN_DNS_INTERNAL_RESOLVERS") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    raw.split([',', ' ', ';', '\n', '\t'])
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse::<IpAddr>().ok())
        .filter(|ip| !is_well_known_public_recursive(*ip))
        .collect()
}

pub const DNS_UDP_DOWNGRADE_EVENT: &str = "dns_dot_udp_downgrade";

/// SOC payload for a DoT (TCP/853) failure that caused internal-UDP fallback.
#[must_use]
pub fn udp_downgrade_soc_payload(name: &str, rr: &str) -> Value {
    json!({
        "event": DNS_UDP_DOWNGRADE_EVENT,
        "severity": "critical",
        "reason": "dot_port_853_failed_fell_back_to_internal_udp",
        "name": name,
        "rr": rr,
        "mitre": "T1040",
    })
}

/// Immediate High/Critical security event for SIEM when DNS is downgraded
/// from DoT to organisation-internal UDP after port 853 failed.
pub fn emit_udp_downgrade_soc(name: &str, rr: &str) {
    let payload = udp_downgrade_soc_payload(name, rr);
    tracing::error!(
        target: "security_event",
        event = DNS_UDP_DOWNGRADE_EVENT,
        severity = "critical",
        name = %name,
        rr = %rr,
        audit_json = %payload,
        "DNS DoT (TCP/853) failed; falling back to organisation-internal UDP — possible active network tampering or eavesdrop"
    );
}

struct DotLookup {
    answers: Vec<String>,
    definitive: bool,
}

async fn dot_lookup(name: &str, rr: &str) -> Option<DotLookup> {
    let qtype = rr_to_qtype(rr)?;
    let name = name.to_string();
    for &(ip, sni, port) in DOT_UPSTREAMS {
        let host = name.clone();
        let sni = sni.to_string();
        let ip_parsed: IpAddr = ip.parse().ok()?;
        let result = tokio::task::spawn_blocking(move || {
            dot_query_blocking(SocketAddr::new(ip_parsed, port), &sni, &host, qtype)
        })
        .await
        .ok()
        .flatten();
        if let Some(dot) = result {
            if dot.definitive || !dot.answers.is_empty() {
                return Some(dot);
            }
        }
    }
    None
}

fn dot_query_blocking(addr: SocketAddr, sni: &str, name: &str, qtype: u16) -> Option<DotLookup> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let mut builder = SslConnector::builder(SslMethod::tls()).ok()?;
    builder.set_verify(SslVerifyMode::PEER);
    let connector = builder.build();
    let stream = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let mut ssl = connector.connect(sni, stream).ok()?;
    let id = rand::random::<u16>();
    let q = encode_query(name, qtype, id);
    let mut framed = Vec::with_capacity(q.len() + 2);
    framed.extend_from_slice(&(q.len() as u16).to_be_bytes());
    framed.extend_from_slice(&q);
    std::io::Write::write_all(&mut ssl, &framed).ok()?;
    std::io::Write::flush(&mut ssl).ok()?;
    let mut len_buf = [0u8; 2];
    std::io::Read::read_exact(&mut ssl, &mut len_buf).ok()?;
    let n = u16::from_be_bytes(len_buf) as usize;
    if n < 12 || n > 4096 {
        return None;
    }
    let mut msg = vec![0u8; n];
    std::io::Read::read_exact(&mut ssl, &mut msg).ok()?;
    decode_answers(&msg, id, qtype)
}

async fn udp_lookup_at(name: &str, rr: &str, servers: &[IpAddr]) -> Option<Vec<String>> {
    let rtype = rr_to_record_type(rr)?;
    let mut ns = Vec::new();
    for ip in servers {
        ns.push(NameServerConfig::udp(*ip));
    }
    if ns.is_empty() {
        return None;
    }
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(1500);
    opts.attempts = 1;
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], ns),
        TokioRuntimeProvider::default(),
    )
    .with_options(opts)
    .build()
    .ok()?;
    let lookup = resolver.lookup(name, rtype).await.ok()?;
    let mut out = Vec::new();
    for record in lookup.answers() {
        let s = record
            .data
            .to_string()
            .trim()
            .trim_end_matches('.')
            .to_string();
        if !s.is_empty() {
            out.push(if rr.eq_ignore_ascii_case("TXT") {
                strip_doh_txt(&s)
            } else {
                s
            });
        }
    }
    Some(out)
}

pub fn rr_to_qtype(rr: &str) -> Option<u16> {
    Some(match rr.trim().to_ascii_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "NAPTR" => 35,
        "DS" => 43,
        "RRSIG" => 46,
        "NSEC" => 47,
        "DNSKEY" => 48,
        "TLSA" => 52,
        "CAA" => 257,
        _ => return None,
    })
}

fn rr_to_record_type(rr: &str) -> Option<RecordType> {
    Some(match rr.trim().to_ascii_uppercase().as_str() {
        "A" => RecordType::A,
        "NS" => RecordType::NS,
        "CNAME" => RecordType::CNAME,
        "SOA" => RecordType::SOA,
        "PTR" => RecordType::PTR,
        "MX" => RecordType::MX,
        "TXT" => RecordType::TXT,
        "AAAA" => RecordType::AAAA,
        "SRV" => RecordType::SRV,
        "NAPTR" => RecordType::NAPTR,
        "DS" => RecordType::DS,
        "RRSIG" => RecordType::RRSIG,
        "NSEC" => RecordType::NSEC,
        "DNSKEY" => RecordType::DNSKEY,
        "TLSA" => RecordType::TLSA,
        "CAA" => RecordType::CAA,
        _ => return None,
    })
}

pub fn encode_query(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&mut out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out
}

fn encode_name(out: &mut Vec<u8>, name: &str) {
    let n = name.trim().trim_end_matches('.');
    if n.is_empty() {
        out.push(0);
        return;
    }
    for label in n.split('.') {
        let b = label.as_bytes();
        let len = b.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&b[..len]);
    }
    out.push(0);
}

fn decode_answers(msg: &[u8], expect_id: u16, qtype: u16) -> Option<DotLookup> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    if id != expect_id {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let rcode = flags & 0x000F;
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qd {
        skip_name(msg, &mut pos)?;
        pos = pos.checked_add(4)?;
        if pos > msg.len() {
            return None;
        }
    }
    let mut answers = Vec::new();
    for _ in 0..an {
        skip_name(msg, &mut pos)?;
        if pos + 10 > msg.len() {
            break;
        }
        let atype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            break;
        }
        let rdata = &msg[pos..pos + rdlen];
        pos += rdlen;
        if atype != qtype && qtype != 0 {
            // CNAME in the answer section for an A query is still useful; skip others.
            if atype != 5 {
                continue;
            }
        }
        if let Some(s) = rdata_to_string(msg, atype, rdata) {
            answers.push(s);
        }
    }
    Some(DotLookup {
        answers,
        definitive: rcode == 0 || rcode == 3,
    })
}

fn skip_name(msg: &[u8], pos: &mut usize) -> Option<()> {
    let mut cursor = *pos;
    let mut hops = 0u8;
    loop {
        if cursor >= msg.len() {
            return None;
        }
        let len = msg[cursor];
        if len & 0xC0 == 0xC0 {
            if cursor + 1 >= msg.len() {
                return None;
            }
            *pos = cursor + 2;
            return Some(());
        }
        if len == 0 {
            *pos = cursor + 1;
            return Some(());
        }
        if len & 0xC0 != 0 {
            return None;
        }
        cursor = cursor.checked_add(1 + len as usize)?;
        hops += 1;
        if hops > 20 {
            return None;
        }
    }
}

fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut jumped = false;
    let mut end = start;
    let mut hops = 0u8;
    loop {
        if cursor >= msg.len() {
            return None;
        }
        let len = msg[cursor];
        if len & 0xC0 == 0xC0 {
            if cursor + 1 >= msg.len() {
                return None;
            }
            if !jumped {
                end = cursor + 2;
            }
            let ptr = (((len as usize) & 0x3F) << 8) | msg[cursor + 1] as usize;
            cursor = ptr;
            jumped = true;
            hops += 1;
            if hops > 10 {
                return None;
            }
            continue;
        }
        if len == 0 {
            if !jumped {
                end = cursor + 1;
            }
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        cursor += 1;
        if cursor + len as usize > msg.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&msg[cursor..cursor + len as usize]).into_owned());
        cursor += len as usize;
        hops += 1;
        if hops > 20 {
            return None;
        }
    }
    Some((labels.join("."), end))
}

fn rdata_to_string(msg: &[u8], atype: u16, rdata: &[u8]) -> Option<String> {
    match atype {
        1 if rdata.len() == 4 => Some(format!(
            "{}.{}.{}.{}",
            rdata[0], rdata[1], rdata[2], rdata[3]
        )),
        28 if rdata.len() == 16 => {
            let arr: [u8; 16] = rdata.try_into().ok()?;
            Some(std::net::Ipv6Addr::from(arr).to_string())
        }
        16 => {
            let mut out = String::new();
            let mut i = 0;
            while i < rdata.len() {
                let n = rdata[i] as usize;
                i += 1;
                if i + n > rdata.len() {
                    break;
                }
                out.push_str(&String::from_utf8_lossy(&rdata[i..i + n]));
                i += n;
            }
            Some(strip_doh_txt(&out))
        }
        15 if rdata.len() >= 3 => {
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let offset = rdata_offset(msg, rdata)?;
            let (ex, _) = read_name(msg, offset + 2)?;
            Some(format!("{} {}", pref, ex.trim_end_matches('.')))
        }
        5 | 2 | 12 => {
            let offset = rdata_offset(msg, rdata)?;
            let (n, _) = read_name(msg, offset)?;
            Some(n.trim_end_matches('.').to_string())
        }
        33 if rdata.len() >= 7 => {
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let offset = rdata_offset(msg, rdata)?;
            let (target, _) = read_name(msg, offset + 6)?;
            Some(format!("0 0 {} {}", port, target.trim_end_matches('.')))
        }
        6 => {
            let offset = rdata_offset(msg, rdata)?;
            let (mname, next) = read_name(msg, offset)?;
            let (_rname, after) = read_name(msg, next)?;
            if after + 20 > msg.len() {
                return Some(mname);
            }
            let minimum = u32::from_be_bytes(msg[after + 16..after + 20].try_into().ok()?);
            Some(format!("{mname} . 0 0 0 0 {minimum}"))
        }
        257 if rdata.len() >= 2 => {
            let tag_len = rdata[1] as usize;
            if 2 + tag_len > rdata.len() {
                return None;
            }
            let tag = String::from_utf8_lossy(&rdata[2..2 + tag_len]);
            let val = String::from_utf8_lossy(&rdata[2 + tag_len..]);
            Some(format!("{tag}={val}"))
        }
        _ => {
            if rdata.is_empty() {
                None
            } else {
                Some(hex::encode(rdata))
            }
        }
    }
}

fn rdata_offset(msg: &[u8], rdata: &[u8]) -> Option<usize> {
    let msg_start = msg.as_ptr() as usize;
    let rd_start = rdata.as_ptr() as usize;
    if rd_start < msg_start {
        return None;
    }
    let off = rd_start - msg_start;
    if off > msg.len() {
        return None;
    }
    Some(off)
}

/// Compile-time sanity: localhost is never classified as a public recursor.
#[allow(dead_code)]
pub fn localhost_v4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_public_anycast_as_internal() {
        assert!(is_well_known_public_recursive("1.1.1.1".parse().unwrap()));
        assert!(is_well_known_public_recursive("8.8.8.8".parse().unwrap()));
        assert!(is_well_known_public_recursive("9.9.9.9".parse().unwrap()));
        assert!(!is_well_known_public_recursive(
            "10.0.0.53".parse().unwrap()
        ));
        assert!(!is_well_known_public_recursive(
            "192.168.1.1".parse().unwrap()
        ));
        assert!(!is_well_known_public_recursive(localhost_v4()));
    }

    #[test]
    fn qtype_map_covers_email_posture() {
        assert_eq!(rr_to_qtype("TXT"), Some(16));
        assert_eq!(rr_to_qtype("MX"), Some(15));
        assert_eq!(rr_to_qtype("CAA"), Some(257));
        assert_eq!(rr_to_qtype("TLSA"), Some(52));
        assert!(rr_to_qtype("NOPE").is_none());
    }

    #[test]
    fn encode_query_has_header_and_name() {
        let q = encode_query("example.com", 1, 0xABCD);
        assert_eq!(&q[0..2], &[0xAB, 0xCD]);
        assert_eq!(q[12], 7); // "example"
        assert_eq!(&q[13..20], b"example");
    }

    #[test]
    fn decodes_a_record_noerror() {
        let q = encode_query("a.test", 1, 0x1111);
        // Build a response: copy header, set QR+NOERROR, ANCOUNT=1, skip question,
        // add an A answer with pointer to QNAME.
        let mut msg = q.clone();
        msg[2] = 0x81; // QR + RD
        msg[3] = 0x80; // RA, RCODE=0
        msg[6] = 0;
        msg[7] = 1; // ANCOUNT
                    // name pointer to offset 12
        msg.extend_from_slice(&[0xC0, 12]);
        msg.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        msg.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        msg.extend_from_slice(&60u32.to_be_bytes()); // TTL
        msg.extend_from_slice(&4u16.to_be_bytes()); // RDLEN
        msg.extend_from_slice(&[93, 184, 216, 34]);
        let decoded = decode_answers(&msg, 0x1111, 1).unwrap();
        assert!(decoded.definitive);
        assert_eq!(decoded.answers, vec!["93.184.216.34"]);
    }

    #[test]
    fn nxdomain_is_definitive_empty() {
        let q = encode_query("gone.test", 1, 0x2222);
        let mut msg = q;
        msg[2] = 0x81;
        msg[3] = 0x03; // NXDOMAIN
        let decoded = decode_answers(&msg, 0x2222, 1).unwrap();
        assert!(decoded.definitive);
        assert!(decoded.answers.is_empty());
    }

    #[test]
    fn udp_downgrade_soc_event_is_critical() {
        let p = udp_downgrade_soc_payload("mx.internal.test", "MX");
        assert_eq!(p["event"], DNS_UDP_DOWNGRADE_EVENT);
        assert_eq!(p["severity"], "critical");
        assert_eq!(p["reason"], "dot_port_853_failed_fell_back_to_internal_udp");
        assert_eq!(p["name"], "mx.internal.test");
        assert_eq!(p["rr"], "MX");
    }
}
