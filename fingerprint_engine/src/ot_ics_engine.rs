//! Phase 7: OT/ICS passive fingerprinting — Modbus TCP, EtherNet/IP (CIP), S7/ISO-on-TCP.
//! Read-only / exception-probing only; short timeouts to reduce load on fragile controllers.
//!
//! Concurrency: many **distinct IPs** in parallel (cap 50–100), but **one TCP probe at a time**
//! per IP (Modbus → ENIP → S7 sequentially) to avoid port-flooding a single PLC.

use futures::stream::{FuturesUnordered, StreamExt};
use ipnetwork::IpNetwork;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(1200);
const IO_TIMEOUT: Duration = Duration::from_millis(900);
pub const MODBUS_PORT: u16 = 502;
pub const ENIP_PORT: u16 = 44818;
pub const S7_PORT: u16 = 102;

/// Max concurrent **hosts** (each host runs its three probes one-after-another on one connection each).
fn max_concurrent_ips() -> usize {
    std::env::var("WEISSMAN_OT_IP_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64)
        .clamp(1, 128)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OtFingerprint {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub vendor_hint: String,
    pub confidence: f32,
    pub raw_excerpt_hex: String,
    pub metadata: Value,
}

fn to_hex_prefix(buf: &[u8], max: usize) -> String {
    let n = buf.len().min(max);
    buf[..n]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn modbus_exception_meaning(code: u8) -> &'static str {
    match code {
        0x01 => "illegal_function",
        0x02 => "illegal_data_address",
        0x03 => "illegal_data_value",
        0x04 => "slave_device_failure",
        0x05 => "acknowledge",
        0x06 => "slave_device_busy",
        0x08 => "memory_parity_error",
        0x0a => "gateway_path_unavailable",
        0x0b => "gateway_target_device_failed_to_respond",
        _ => "unknown_exception_code",
    }
}

/// Modbus TCP: MBAP + illegal function 0xFF — valid stack returns exception 0x81+ or echoes pattern.
async fn probe_modbus(host: &str) -> Option<OtFingerprint> {
    let addr = format!("{}:{}", host, MODBUS_PORT);
    let mut stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let _ = stream.set_nodelay(true);
    let pdu: [u8; 8] = [0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0xFF];
    match tokio::time::timeout(IO_TIMEOUT, stream.write_all(&pdu)).await {
        Ok(Ok(())) => {}
        _ => return None,
    }
    let mut resp = [0u8; 256];
    let n = match tokio::time::timeout(IO_TIMEOUT, stream.read(&mut resp)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };
    if n < 9 {
        return None;
    }
    let slice = resp.get(..n)?;
    let unit = *slice.get(6)?;
    let fc = *slice.get(7)?;
    let looks_exception = fc & 0x80 != 0;
    let looks_normal = !looks_exception && fc != 0xFF;
    if !looks_exception && !looks_normal && n < 8 {
        return None;
    }
    let conf = if looks_exception && unit == 0x01 {
        0.92f32
    } else if looks_exception {
        0.78
    } else {
        0.55
    };

    let mut meta = serde_json::Map::new();
    meta.insert("unit_id".into(), json!(unit));
    meta.insert("function_or_exception".into(), json!(fc));
    meta.insert("probe".into(), json!("illegal_function_0xff"));
    if looks_exception {
        if let Some(ec) = slice.get(8).copied() {
            meta.insert("exception_code".into(), json!(ec));
            meta.insert(
                "exception_meaning".into(),
                json!(modbus_exception_meaning(ec)),
            );
        }
    }

    Some(OtFingerprint {
        host: host.to_string(),
        port: MODBUS_PORT,
        protocol: "modbus_tcp".into(),
        vendor_hint: "Modbus/TCP stack (exception or response)".into(),
        confidence: conf,
        raw_excerpt_hex: to_hex_prefix(slice, 48),
        metadata: Value::Object(meta),
    })
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*buf.get(off)?, *buf.get(off + 1)?]))
}

/// Parse CIP List Identity (item type 0x000C) from encapsulation **data** (after 24-byte header).
fn parse_cip_identity_item(payload: &[u8]) -> Option<(u16, String, u8, u8)> {
    // ProtocolVersion(2) + sockaddr_in(16) + VendorId(2) + DeviceType(2) + ProductCode(2)
    // + Major(1) + Minor(1) + Status(2) + Serial(4) + SHORTSTRING ProductName
    const PREFIX: usize = 2 + 16 + 2 + 2 + 2 + 1 + 1 + 2 + 4;
    if payload.len() < PREFIX + 1 {
        return None;
    }
    let vendor_id = read_u16_le(payload, 18)?;
    let major = *payload.get(24)?;
    let minor = *payload.get(25)?;
    let name_len = *payload.get(PREFIX)? as usize;
    let start = PREFIX + 1;
    let end = start.checked_add(name_len)?;
    let name_bytes = payload.get(start..end)?;
    let product_name = String::from_utf8_lossy(name_bytes).into_owned();
    Some((vendor_id, product_name, major, minor))
}

/// Walk List Identity reply data: item count + typed items, or a single 0x0C item without count.
fn parse_enip_list_identity_data(data: &[u8]) -> Option<(u16, String, u8, u8)> {
    if data.len() < 4 {
        return None;
    }
    // Try: leading item count (UINT)
    let count = u16::from_le_bytes([data[0], data[1]]);
    if count > 0 && count <= 32 && data.len() >= 4 {
        let mut off = 2usize;
        for _ in 0..count {
            let item_type = read_u16_le(data, off)?;
            let item_len = read_u16_le(data, off + 2)? as usize;
            off = off.checked_add(4)?;
            let end = off.checked_add(item_len)?;
            let item_data = data.get(off..end)?;
            off = end;
            if item_type == 0x000c {
                if let Some(parsed) = parse_cip_identity_item(item_data) {
                    return Some(parsed);
                }
            }
        }
    }
    // Fallback: data starts with item type 0x000C (some stacks omit outer count)
    let t0 = read_u16_le(data, 0)?;
    if t0 == 0x000c {
        let ilen = read_u16_le(data, 2)? as usize;
        let end = 4usize.checked_add(ilen)?;
        let inner = data.get(4..end)?;
        return parse_cip_identity_item(inner);
    }
    None
}

/// EtherNet/IP: List Identity command 0x0063 (sessionless); parse CIP identity when present.
async fn probe_enip(host: &str) -> Option<OtFingerprint> {
    let addr = format!("{}:{}", host, ENIP_PORT);
    let mut stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let _ = stream.set_nodelay(true);
    let mut hdr = [0u8; 24];
    hdr[0] = 0x63;
    hdr[1] = 0x00;
    match tokio::time::timeout(IO_TIMEOUT, stream.write_all(&hdr)).await {
        Ok(Ok(())) => {}
        _ => return None,
    }
    let mut resp = [0u8; 512];
    let n = match tokio::time::timeout(IO_TIMEOUT, stream.read(&mut resp)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };
    if n < 24 {
        return None;
    }
    let slice = resp.get(..n)?;
    let cmd = u16::from_le_bytes([slice[0], slice[1]]);
    let status = slice
        .get(8..12)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0xFFFF_FFFF);
    let encap_data_len = u16::from_le_bytes([slice[2], slice[3]]) as usize;
    let data_start = 24usize;
    let data_cap = slice.len().saturating_sub(data_start);
    let take = encap_data_len.min(data_cap);
    let data = slice.get(data_start..data_start + take).unwrap_or(&[]);

    let mut meta = serde_json::Map::new();
    meta.insert("encapsulation_command".into(), json!(cmd));
    meta.insert("encapsulation_status".into(), json!(status));
    meta.insert("probe".into(), json!("list_identity_0x63"));

    let parsed = if cmd == 0x63 && status == 0 {
        parse_enip_list_identity_data(data)
    } else {
        None
    };

    let (vendor_hint, confidence) = if let Some((vid, ref pname, maj, min)) = parsed {
        meta.insert("vendor_id".into(), json!(vid));
        meta.insert("product_name".into(), json!(pname));
        meta.insert("firmware_major".into(), json!(maj));
        meta.insert("firmware_minor".into(), json!(min));
        meta.insert(
            "firmware_revision".into(),
            json!(format!("{maj}.{min}")),
        );
        let hint = if pname.is_empty() {
            format!("EtherNet/IP (vendor {vid})")
        } else {
            format!("EtherNet/IP: {pname}")
        };
        (hint, 0.92f32)
    } else {
        (
            "EtherNet/IP (CIP encapsulation response)".into(),
            if cmd == 0x63 { 0.88 } else { 0.62 },
        )
    };

    if cmd != 0x63 && cmd != 0x0064 {
        if n < 28 {
            return None;
        }
    }

    Some(OtFingerprint {
        host: host.to_string(),
        port: ENIP_PORT,
        protocol: "ethernet_ip_cip".into(),
        vendor_hint,
        confidence,
        raw_excerpt_hex: to_hex_prefix(slice, 64),
        metadata: Value::Object(meta),
    })
}

/// Best-effort parse of COTP parameters (TLV) in a Connection Confirm / similar PDU.
fn parse_cotp_tlv_params(bytes: &[u8]) -> Value {
    let mut arr = Vec::new();
    let mut i = 0usize;
    while i + 2 <= bytes.len() {
        let code = bytes[i];
        let len = bytes[i + 1] as usize;
        i = i.saturating_add(2);
        let end = i.saturating_add(len);
        if end > bytes.len() {
            break;
        }
        let val = &bytes[i..end];
        let mut o = serde_json::Map::new();
        o.insert("code".into(), json!(format!("0x{code:02x}")));
        o.insert("length".into(), json!(len));
        o.insert("hex".into(), json!(to_hex_prefix(val, 32)));
        if code == 0xc1 {
            o.insert("name".into(), json!("src_tsap"));
        } else if code == 0xc2 {
            o.insert("name".into(), json!("dst_tsap"));
        } else if code == 0xc0 {
            o.insert("name".into(), json!("tpdu_size"));
        }
        arr.push(Value::Object(o));
        i = end;
    }
    json!(arr)
}

/// If S7 (protocol 0x32) TPDU appears after COTP, pull module / SZL hints without panicking.
fn parse_s7_userdata_hints(tpdu: &[u8]) -> Value {
    let mut hints = serde_json::Map::new();
    if tpdu.len() < 12 {
        return Value::Object(hints);
    }
    // S7 header: 0x32, type, seq, par_len, data_len, error class/code...
    if tpdu.first().copied() != Some(0x32) {
        return Value::Object(hints);
    }
    hints.insert("s7_protocol_detected".into(), json!(true));
    // Parameter section often starts after fixed header; layout varies by PDU type.
    // Look for plausible SZL-ID pair (big-endian u16) in parameter blob: 0x0011, 0x0111, 0x001c, etc.
    for w in tpdu.windows(2) {
        let id = u16::from_be_bytes([w[0], w[1]]);
        match id {
            0x0011 | 0x0111 | 0x0124 | 0x0019 | 0x001c => {
                hints.insert("szl_id_hint".into(), json!(format!("0x{id:04x}")));
                break;
            }
            _ => {}
        }
    }
    // Module / component ID: scan for ASCII "CPU" or common order codes (heuristic)
    if let Ok(s) = std::str::from_utf8(tpdu) {
        for needle in ["CPU", "6ES7", "S7-", "IM15"] {
            if s.contains(needle) {
                hints.insert("module_id_string_hint".into(), json!(needle));
                break;
            }
        }
    }
    Value::Object(hints)
}

/// COTP parameters slice: bytes after fixed 6-octet header (PDU type, dst/src ref, class).
fn s7_cotp_params_slice(resp: &[u8]) -> Option<&[u8]> {
    let li = *resp.get(4)? as usize;
    if li < 6 {
        return None;
    }
    let cotp_end = 5usize.saturating_add(li);
    if cotp_end > resp.len() {
        return None;
    }
    resp.get(11..cotp_end)
}

/// S7 ISO-on-TCP: minimal TPKT + COTP Connection Request (CR).
async fn probe_s7(host: &str) -> Option<OtFingerprint> {
    let addr = format!("{}:{}", host, S7_PORT);
    let mut stream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let _ = stream.set_nodelay(true);
    let pkt: [u8; 22] = [
        0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01, 0x00,
        0xc2, 0x02, 0x01, 0x02, 0xc0, 0x01, 0x09,
    ];
    match tokio::time::timeout(IO_TIMEOUT, stream.write_all(&pkt)).await {
        Ok(Ok(())) => {}
        _ => return None,
    }
    let mut resp = [0u8; 256];
    let n = match tokio::time::timeout(IO_TIMEOUT, stream.read(&mut resp)).await {
        Ok(Ok(n)) => n,
        _ => return None,
    };
    if n < 7 {
        return None;
    }
    let slice = resp.get(..n)?;
    if slice.first().copied() != Some(0x03) {
        return None;
    }
    let tpkt_len = slice
        .get(2..4)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(|a| u16::from_be_bytes(a) as usize)
        .unwrap_or(0);
    let pdu_type = slice.get(5).copied();
    let cotp_cc = pdu_type == Some(0xd0) || pdu_type == Some(0xd6);

    let mut meta = serde_json::Map::new();
    meta.insert("tpkt_length_field".into(), json!(tpkt_len));
    meta.insert("probe".into(), json!("cotp_connection_request"));
    if let Some(pt) = pdu_type {
        meta.insert(
            "cotp_pdu_type".into(),
            json!(format!("0x{pt:02x}")),
        );
    }

    if let Some(params) = s7_cotp_params_slice(slice) {
        meta.insert("cotp_parameters".into(), parse_cotp_tlv_params(params));
    } else if slice.len() > 11 {
        if let Some(p) = slice.get(11..n) {
            meta.insert("cotp_parameters".into(), parse_cotp_tlv_params(p));
        }
    }

    // User data after COTP (if TPKT carries more than one TPDU — rare on CR reply)
    let li = slice.get(4).copied().unwrap_or(0) as usize;
    let cotp_end = 5usize.saturating_add(li);
    if cotp_end < n && cotp_end <= slice.len() {
        if let Some(tail) = slice.get(cotp_end..n) {
            let s7h = parse_s7_userdata_hints(tail);
            if s7h.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
                meta.insert("s7_hints".into(), s7h);
            }
        }
    }

    Some(OtFingerprint {
        host: host.to_string(),
        port: S7_PORT,
        protocol: "s7_iso_tcp".into(),
        vendor_hint: if cotp_cc {
            "S7 / ISO-on-TCP (COTP CC-like)"
        } else {
            "S7 / ISO-on-TCP (TPKT response)"
        }
        .into(),
        confidence: if cotp_cc { 0.85 } else { 0.58 },
        raw_excerpt_hex: to_hex_prefix(slice, 48),
        metadata: Value::Object(meta),
    })
}

/// Run all three probes **sequentially** on one host (single-IP safety).
async fn probe_host_passive_sequential(host: String) -> Vec<OtFingerprint> {
    let mut out = Vec::new();
    if let Some(fp) = probe_modbus(&host).await {
        out.push(fp);
    }
    if let Some(fp) = probe_enip(&host).await {
        out.push(fp);
    }
    if let Some(fp) = probe_s7(&host).await {
        out.push(fp);
    }
    out
}

/// Derive host list from client domains JSON and ip_ranges JSON (CIDR + single IPs). Capped.
pub fn resolve_scan_hosts(
    domains_json: &str,
    ip_ranges_json: &str,
    max_hosts: usize,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Ok(domains) = serde_json::from_str::<Vec<String>>(domains_json.trim()) {
        for d in domains {
            let h = d
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !h.is_empty() && !h.chars().all(|c| c.is_ascii_digit() || c == '.') {
                if !out.contains(&h) {
                    out.push(h);
                }
            }
        }
    }
    if let Ok(ranges) = serde_json::from_str::<Vec<String>>(ip_ranges_json.trim()) {
        for r in ranges {
            let r = r.trim();
            if r.is_empty() {
                continue;
            }
            if let Ok(net) = r.parse::<IpNetwork>() {
                match net {
                    IpNetwork::V4(n) => {
                        let base = n.network();
                        let prefix = n.prefix();
                        if prefix >= 30 {
                            for ip in n.iter().take(8) {
                                let s = ip.to_string();
                                if !out.contains(&s) {
                                    out.push(s);
                                }
                                if out.len() >= max_hosts {
                                    return out;
                                }
                            }
                        } else {
                            let s = base.to_string();
                            if !out.contains(&s) {
                                out.push(s);
                            }
                        }
                    }
                    IpNetwork::V6(_) => {}
                }
            } else if !out.contains(&r.to_string()) {
                out.push(r.to_string());
            }
            if out.len() >= max_hosts {
                break;
            }
        }
    }
    out.truncate(max_hosts);
    out
}

/// Passive probes: **parallel across IPs** (bounded), **strictly sequential per IP** (Modbus → ENIP → S7).
pub async fn scan_hosts_passive(hosts: &[String]) -> Vec<OtFingerprint> {
    let cap = max_concurrent_ips();
    let mut all = Vec::new();
    let mut in_flight = FuturesUnordered::new();
    let mut it = hosts.iter().cloned();

    for _ in 0..cap.min(hosts.len()) {
        if let Some(h) = it.next() {
            in_flight.push(probe_host_passive_sequential(h));
        }
    }

    while let Some(batch) = in_flight.next().await {
        all.extend(batch);
        if let Some(h) = it.next() {
            in_flight.push(probe_host_passive_sequential(h));
        }
    }

    all
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_enip_identity_single_item() {
        // Minimal synthetic: count=1, type=0x0C, len covers identity prefix + name "PLC"
        let mut d = Vec::new();
        d.extend_from_slice(&1u16.to_le_bytes()); // count
        d.extend_from_slice(&0x000cu16.to_le_bytes());
        let inner = {
            let mut v = vec![0u8; 36];
            v[18..20].copy_from_slice(&0x0102u16.to_le_bytes()); // vendor
            v[24] = 3;
            v[25] = 45;
            v[32] = 3; // SHORTSTRING len
            v[33..36].copy_from_slice(b"PLC");
            v
        };
        d.extend_from_slice(&(inner.len() as u16).to_le_bytes());
        d.extend_from_slice(&inner);
        let r = parse_enip_list_identity_data(&d).unwrap();
        assert_eq!(r.0, 0x0102);
        assert_eq!(r.1, "PLC");
        assert_eq!(r.2, 3);
        assert_eq!(r.3, 45);
    }
}
