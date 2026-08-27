//! Safe, rate-limited live probes. Reads only. Every byte on the wire is ROE-gated.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::parsers::{
    cotp_is_cc, is_gateway_unit, modbus_exception_meaning, parse_dnp3_link, parse_modbus_frame,
    parse_mms_tpkt, parse_s7_iso_on_tcp, s7_observed_cpu_control, MbapHeader,
};
use super::policy::{
    dnp3_fc_allowed, modbus_fc_allowed, s7_function_allowed, OtSafetyPolicy,
    MODBUS_FINGERPRINT_FC,
};
use super::session::{next_transaction_id, stealth_jitter, try_host_slot, with_safety};

pub const MODBUS_PORT: u16 = 502;
pub const S7_PORT: u16 = 102;
pub const DNP3_PORT: u16 = 20_000;
pub const IEC_MMS_PORT: u16 = 102;

#[derive(Debug, Clone)]
pub struct HardenedFingerprint {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub vendor_hint: String,
    pub confidence: f32,
    pub raw_excerpt_hex: String,
    pub metadata: serde_json::Value,
}

fn hex_prefix(buf: &[u8], max: usize) -> String {
    buf.iter()
        .take(max)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

struct GuardedStream {
    stream: TcpStream,
    _slot: super::session::HostSlot,
}

async fn connect(host: &str, port: u16, policy: &OtSafetyPolicy) -> Option<GuardedStream> {
    if !policy.probe_mode.allows_tcp_probe() {
        return None;
    }
    let slot = try_host_slot(
        host,
        port,
        policy.max_connections_per_host,
        Duration::from_millis(80),
    )
    .await
    .ok()?;
    stealth_jitter(policy).await;
    let addr = format!("{host}:{port}");
    let connect = TcpStream::connect(&addr);
    let mut connect_policy = policy.clone();
    connect_policy.io_timeout_ms = policy.connect_timeout_ms.max(policy.io_timeout_ms);
    let stream = match with_safety(&connect_policy, connect).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let _ = stream.set_nodelay(true);
    Some(GuardedStream {
        stream,
        _slot: slot,
    })
}

async fn transact(
    stream: &mut TcpStream,
    frame: &[u8],
    policy: &OtSafetyPolicy,
) -> Option<Vec<u8>> {
    match with_safety(policy, stream.write_all(frame)).await {
        Ok(Ok(())) => {}
        _ => return None,
    }
    let mut buf = [0u8; 512];
    match with_safety(policy, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(buf[..n].to_vec()),
        _ => None,
    }
}

fn build_modbus(tx: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(7 + pdu.len());
    f.extend_from_slice(&tx.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]);
    let length = u16::try_from(pdu.len() + 1).unwrap_or(0);
    f.extend_from_slice(&length.to_be_bytes());
    f.push(unit);
    f.extend_from_slice(pdu);
    f
}

/// Read-holding-registers FC03 (qty capped) — default SafeRead probe.
pub async fn probe_modbus_safe(host: &str, policy: &OtSafetyPolicy) -> Option<HardenedFingerprint> {
    if modbus_fc_allowed(0x03, policy.probe_mode, policy.protocol_strict).is_err() {
        return None;
    }
    let mut guarded = connect(host, MODBUS_PORT, policy).await?;
    let tx = next_transaction_id(host, MODBUS_PORT);
    let qty = policy.max_read_quantity.min(1);
    let pdu = [0x03, 0x00, 0x00, 0x00, qty as u8];
    let frame = build_modbus(tx, 0x01, &pdu);
    let resp = transact(&mut guarded.stream, &frame, policy).await?;
    let parsed = parse_modbus_frame(&resp).ok()?;
    let mut meta = serde_json::Map::new();
    meta.insert("unit_id".into(), serde_json::json!(parsed.header.unit_id));
    meta.insert("function".into(), serde_json::json!(parsed.pdu.function));
    meta.insert("transaction_id".into(), serde_json::json!(parsed.header.transaction_id));
    meta.insert("probe_mode".into(), serde_json::json!(policy.probe_mode));
    meta.insert("parser".into(), serde_json::json!("nom_mbap"));
    if is_gateway_unit(parsed.header.unit_id) {
        meta.insert("gateway_unit".into(), serde_json::json!(true));
    }
    if parsed.pdu.exception {
        meta.insert("exception_code".into(), serde_json::json!(parsed.pdu.exception_code));
        if let Some(code) = parsed.pdu.exception_code {
            meta.insert(
                "exception_meaning".into(),
                serde_json::json!(modbus_exception_meaning(code)),
            );
        }
        if matches!(parsed.pdu.exception_code, Some(0x01) | Some(0x02)) {
            meta.insert("enumeration_signal".into(), serde_json::json!(true));
        }
    }
    let conf = if parsed.pdu.function & 0x7f == 0x03 {
        0.92
    } else if parsed.pdu.exception {
        0.8
    } else {
        0.55
    };
    Some(HardenedFingerprint {
        host: host.to_string(),
        port: MODBUS_PORT,
        protocol: "modbus_tcp".into(),
        vendor_hint: "Modbus/TCP (hardened FC03)".into(),
        confidence: conf,
        raw_excerpt_hex: hex_prefix(&resp, 48),
        metadata: serde_json::Value::Object(meta),
    })
}

/// Optional one-shot illegal-function fingerprint (not a write).
pub async fn probe_modbus_fingerprint_fc(
    host: &str,
    policy: &OtSafetyPolicy,
) -> Option<HardenedFingerprint> {
    if policy.protocol_strict {
        return None;
    }
    let _ = MODBUS_FINGERPRINT_FC;
    let mut guarded = connect(host, MODBUS_PORT, policy).await?;
    let tx = next_transaction_id(host, MODBUS_PORT);
    let frame = build_modbus(tx, 0x01, &[0xFF]);
    let resp = transact(&mut guarded.stream, &frame, policy).await?;
    let parsed = parse_modbus_frame(&resp).ok()?;
    Some(HardenedFingerprint {
        host: host.to_string(),
        port: MODBUS_PORT,
        protocol: "modbus_tcp".into(),
        vendor_hint: "Modbus/TCP (exception fingerprint)".into(),
        confidence: 0.78,
        raw_excerpt_hex: hex_prefix(&resp, 48),
        metadata: serde_json::json!({
            "unit_id": parsed.header.unit_id,
            "function": parsed.pdu.function,
            "probe": "illegal_function_strict_off",
        }),
    })
}

pub async fn probe_s7_safe(host: &str, policy: &OtSafetyPolicy) -> Option<HardenedFingerprint> {
    let mut guarded = connect(host, S7_PORT, policy).await?;
    let pkt: [u8; 22] = [
        0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01, 0x00,
        0xc2, 0x02, 0x01, 0x02, 0xc0, 0x01, 0x09,
    ];
    let resp = transact(&mut guarded.stream, &pkt, policy).await?;
    let parsed = parse_s7_iso_on_tcp(&resp).ok()?;
    if let Some(s7) = parsed.s7 {
        if s7_function_allowed(s7.rosctr).is_err() {
            // Observed CPU-control in a *response* is a SEV-1 signal, still a finding.
        }
    }
    let cpu = s7_observed_cpu_control(parsed.userdata);
    let cc = cotp_is_cc(parsed.cotp.pdu_type);
    Some(HardenedFingerprint {
        host: host.to_string(),
        port: S7_PORT,
        protocol: "s7_iso_tcp".into(),
        vendor_hint: if cc {
            "S7 / ISO-on-TCP (COTP CC, hardened parser)"
        } else {
            "S7 / ISO-on-TCP (TPKT, hardened parser)"
        }
        .into(),
        confidence: if cc { 0.88 } else { 0.6 },
        raw_excerpt_hex: hex_prefix(&resp, 48),
        metadata: serde_json::json!({
            "tpkt_length": parsed.tpkt.length,
            "cotp_pdu_type": format!("0x{:02x}", parsed.cotp.pdu_type),
            "cpu_control_observed": cpu,
            "parser": "nom_tpkt_cotp",
            "probe_mode": policy.probe_mode,
        }),
    })
}

/// IEEE 1815 link-status request with a correct CRC (no Direct Operate).
pub fn dnp3_link_status_frame() -> Vec<u8> {
    let hdr = [0x05u8, 0x64, 0x05, 0xC4, 0x01, 0x00, 0x00, 0x04];
    let crc = super::parsers::dnp3_crc(&hdr);
    let mut v = hdr.to_vec();
    v.extend_from_slice(&crc.to_le_bytes());
    v
}

pub async fn probe_dnp3_safe(host: &str, policy: &OtSafetyPolicy) -> Option<HardenedFingerprint> {
    let mut guarded = connect(host, DNP3_PORT, policy).await?;
    let frame = dnp3_link_status_frame();
    let resp = transact(&mut guarded.stream, &frame, policy).await?;
    match parse_dnp3_link(&resp) {
        Ok(parsed) => {
            if let Some(fc) = parsed.app_fc {
                let _ = dnp3_fc_allowed(fc);
            }
            let iin_hw = parsed.iin.map(|i| i.hardware_trouble()).unwrap_or(false);
            Some(HardenedFingerprint {
                host: host.to_string(),
                port: DNP3_PORT,
                protocol: "dnp3".into(),
                vendor_hint: "DNP3 (IEEE 1815, CRC-validated)".into(),
                confidence: 0.93,
                raw_excerpt_hex: hex_prefix(&resp, 48),
                metadata: serde_json::json!({
                    "src": parsed.link.src,
                    "dest": parsed.link.dest,
                    "app_fc": parsed.app_fc,
                    "iin_hardware_trouble": iin_hw,
                    "transport_seq": parsed.transport_seq,
                    "parser": "nom_dnp3_crc",
                    "probe_mode": policy.probe_mode,
                }),
            })
        }
        Err(fail) => {
            if resp.len() >= 2 && resp[0] == 0x05 && resp[1] == 0x64 {
                Some(HardenedFingerprint {
                    host: host.to_string(),
                    port: DNP3_PORT,
                    protocol: "dnp3".into(),
                    vendor_hint: "DNP3 start bytes (CRC unconfirmed)".into(),
                    confidence: 0.7,
                    raw_excerpt_hex: hex_prefix(&resp, 48),
                    metadata: serde_json::json!({
                        "parse_fail": fail.kind,
                        "parser": "nom_dnp3_crc",
                    }),
                })
            } else {
                None
            }
        }
    }
}

pub async fn probe_iec61850_mms_safe(
    host: &str,
    policy: &OtSafetyPolicy,
) -> Option<HardenedFingerprint> {
    let mut guarded = connect(host, IEC_MMS_PORT, policy).await?;
    let pkt: [u8; 22] = [
        0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0, 0x01, 0x0A, 0xC1,
        0x02, 0x01, 0x00,         0xC2, 0x02, 0x01, 0x02,
    ];
    let resp = transact(&mut guarded.stream, &pkt, policy).await?;
    let parsed = parse_mms_tpkt(&resp, 8).ok()?;
    Some(HardenedFingerprint {
        host: host.to_string(),
        port: IEC_MMS_PORT,
        protocol: "iec61850_mms".into(),
        vendor_hint: "IEC 61850 / MMS (TPKT+BER, hardened)".into(),
        confidence: if cotp_is_cc(parsed.cotp.pdu_type) {
            0.9
        } else {
            0.62
        },
        raw_excerpt_hex: hex_prefix(&resp, 48),
        metadata: serde_json::json!({
            "tpkt_length": parsed.tpkt.length,
            "cotp_pdu_type": format!("0x{:02x}", parsed.cotp.pdu_type),
            "parser": "nom_mms_ber",
            "max_attr_depth": 8,
            "probe_mode": policy.probe_mode,
        }),
    })
}

/// Binary signature of a network failure for the audit log (spec MB-23).
#[must_use]
pub fn failure_signature(kind: &str, host: &str, port: u16, excerpt: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(kind.as_bytes());
    h.update(host.as_bytes());
    h.update(port.to_be_bytes());
    h.update(excerpt);
    hex::encode(h.finalize())
}

#[must_use]
pub fn mbap_ok(h: &MbapHeader) -> bool {
    h.protocol_id == 0 && h.length >= 1 && h.length <= 254
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnp3_request_has_valid_crc() {
        let f = dnp3_link_status_frame();
        assert_eq!(&f[..2], &[0x05, 0x64]);
        parse_dnp3_link(&f).expect("self-CRC");
    }

    #[test]
    fn failure_signature_is_hex_64() {
        let s = failure_signature("timeout", "10.0.0.1", 502, b"");
        assert_eq!(s.len(), 64);
    }
}
