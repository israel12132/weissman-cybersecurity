//! Advanced OT/ICS Engines — real TCP/UDP protocol fingerprint probes.
//! Passive surface checks delegate to `ot_ics_engine`; bus-level / physical attacks
//! require an enrolled endpoint agent (no HTTP stand-ins).

use crate::engine_probes::{
    agent_required_ok, empty_ok, extract_host, finding, http_client, http_get, join_url,
    normalize_url, status_indicates_presence, tcp_open, tcp_probe_response, udp_probe_response,
};
use crate::engine_result::{print_result, EngineResult};
use crate::ot_ics_engine::{
    probe_bacnet_read_property, probe_modbus_function_code, probe_opcua_discovery, OtFingerprint,
};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

fn ot_fingerprint_finding(fp: &OtFingerprint, engine_id: &str, target: &str) -> Value {
    let severity = if fp.confidence > 0.85 {
        "critical"
    } else if fp.confidence > 0.6 {
        "high"
    } else {
        "medium"
    };
    finding(
        engine_id,
        &format!(
            "{} on {}:{} ({})",
            fp.protocol, fp.host, fp.port, fp.vendor_hint
        ),
        severity,
        "T0843",
        &format!(
            "Protocol: {}, confidence {:.2}, excerpt: {}",
            fp.protocol, fp.confidence, fp.raw_excerpt_hex
        ),
        target,
    )
}

async fn agent_required_bus_attack(
    engine_id: &str,
    target: &str,
    title: &str,
    rationale: &str,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    agent_required_ok(engine_id, target, title, rationale)
}

// Modbus TCP — function-code 03 read probe (shared with ot_ics_engine).
pub async fn run_modbus_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    if let Some(fp) = probe_modbus_function_code(&host).await {
        return EngineResult::ok(
            vec![ot_fingerprint_finding(&fp, "modbus_attack", target)],
            "modbus_attack: Modbus/TCP function 03 response observed".to_string(),
        );
    }
    if tcp_open(&host, 502).await {
        return EngineResult::ok(
            vec![finding(
                "modbus_attack",
                "Port 502/tcp open (Modbus candidate)",
                "medium",
                "T0843",
                &format!(
                    "TCP {}:502 accepts connections but no FC03/readProperty confirmation.",
                    host
                ),
                target,
            )],
            "modbus_attack: port open, protocol unconfirmed".to_string(),
        );
    }
    empty_ok("modbus_attack", target)
}
cli_wrapper!(run_modbus_attack, run_modbus_attack_result);

pub async fn run_bacnet_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    if let Some(fp) = probe_bacnet_read_property(&host).await {
        return EngineResult::ok(
            vec![ot_fingerprint_finding(&fp, "bacnet_attack", t)],
            "bacnet_attack: BACnet/IP readProperty response observed".to_string(),
        );
    }
    empty_ok("bacnet_attack", t)
}
cli_wrapper!(run_bacnet_attack, run_bacnet_attack_result);

pub async fn run_opcua_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    if let Some(fp) = probe_opcua_discovery(&host).await {
        return EngineResult::ok(
            vec![ot_fingerprint_finding(&fp, "opcua_attack", t)],
            "opcua_attack: OPC-UA discovery handshake observed".to_string(),
        );
    }
    if tcp_open(&host, 4840).await {
        return EngineResult::ok(
            vec![finding(
                "opcua_attack",
                "Port 4840/tcp open (OPC-UA candidate)",
                "medium",
                "T0843",
                &format!(
                    "TCP {}:4840 accepts connections but HEL/ACK discovery was not confirmed.",
                    host
                ),
                t,
            )],
            "opcua_attack: port open, discovery unconfirmed".to_string(),
        );
    }
    empty_ok("opcua_attack", t)
}
cli_wrapper!(run_opcua_attack, run_opcua_attack_result);

/// Real, deep, **read-only** Modbus/TCP assessment: Read Device Identification (FC 0x2B/0x0E) +
/// holding-register reads (FC 0x03) across common unit ids. Confirms unauthenticated read exposure
/// and discloses device identity. Destructive writes (FC 0x05/0x06/0x0F/0x10) are NOT performed —
/// write-capability validation is an explicitly authorized on-segment action.
pub async fn run_modbus_exploit_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let Some(a) = crate::ot_ics_engine::modbus_deep_assess(&host).await else {
        if tcp_open(&host, 502).await {
            return EngineResult::ok(
                vec![finding(
                    "modbus_exploit",
                    "Port 502/tcp open (Modbus candidate, unconfirmed)",
                    "medium",
                    "T0843",
                    &format!("TCP {host}:502 accepts connections but no Modbus PDU was confirmed."),
                    target,
                )],
                "modbus_exploit: port open, protocol unconfirmed".to_string(),
            );
        }
        return empty_ok("modbus_exploit", target);
    };

    let mut findings: Vec<Value> = Vec::new();
    if !a.device_objects.is_empty() {
        let ident = a
            .device_objects
            .iter()
            .map(|(id, v)| {
                format!(
                    "{}={}",
                    crate::ot_ics_engine::modbus_device_id_label(*id),
                    v
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(finding(
            "modbus_exploit",
            "Modbus device identification exposed (unauthenticated)",
            "high",
            "T0888",
            &format!(
                "Unauthenticated Modbus Read Device Identification (FC 0x2B/0x0E) on {host}:502 returned: {ident}. Vendor/product/firmware are disclosed to any network peer."
            ),
            target,
        ));
    }
    if !a.read_ok_units.is_empty() {
        let severity = if a.device_objects.is_empty() {
            "high"
        } else {
            "critical"
        };
        findings.push(finding(
            "modbus_exploit",
            "Unauthenticated Modbus register read permitted",
            severity,
            "T0861",
            &format!(
                "Holding-register read (FC 0x03) succeeded without authentication on unit id(s) {:?} at {host}:502. Process data is readable. Write/coerce testing (FC 0x05/0x06/0x0F/0x10) is destructive and requires explicit authorized on-segment action — not performed by this engine.",
                a.read_ok_units
            ),
            target,
        ));
    }
    if findings.is_empty() {
        findings.push(finding(
            "modbus_exploit",
            "Modbus/TCP present (reads restricted)",
            "medium",
            "T0843",
            &format!(
                "Modbus/TCP confirmed on {host}:502 but holding-register reads returned exceptions on unit id(s) {:?}.",
                a.exception_units
            ),
            target,
        ));
    }
    EngineResult::ok(
        findings,
        format!("modbus_exploit: deep read-only Modbus assessment on {host}:502"),
    )
}
cli_wrapper!(run_modbus_exploit, run_modbus_exploit_result);

/// Read-only PLC protocol confirmations via S7comm (ISO-on-TCP), EtherNet/IP (CIP identity), and
/// Modbus function-code reads. Reuses the tested `ot_ics_engine` probes — no writes, no downloads.
async fn plc_protocol_confirmations(host: &str, engine_id: &str, target: &str) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(fp) = crate::ot_ics_engine::probe_s7(host).await {
        out.push(ot_fingerprint_finding(&fp, engine_id, target));
    }
    if let Some(fp) = crate::ot_ics_engine::probe_enip(host).await {
        out.push(ot_fingerprint_finding(&fp, engine_id, target));
    }
    if let Some(fp) = crate::ot_ics_engine::probe_modbus_function_code(host).await {
        out.push(ot_fingerprint_finding(&fp, engine_id, target));
    }
    out
}

/// Real read-only PLC fingerprint: confirms an exposed PLC engineering/runtime interface
/// (S7comm / EtherNet-IP CIP identity / Modbus). Logic download & runtime tampering — the actual
/// "logic bomb" — are destructive and remain an explicitly authorized on-segment action (not done).
pub async fn run_plc_logic_bomb_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let mut findings = plc_protocol_confirmations(&host, "plc_logic_bomb", target).await;
    if findings.is_empty() {
        return empty_ok("plc_logic_bomb", target);
    }
    findings.push(finding(
        "plc_logic_bomb",
        &format!("Exposed PLC engineering/runtime interface on {host} (unauthenticated protocol response)"),
        "high",
        "T0843",
        &format!(
            "Confirmed industrial control protocol(s) responding on {host}. An exposed, unauthenticated PLC engineering interface enables logic read and — with authorized on-segment access — logic-download tampering. No write/download was performed."
        ),
        target,
    ));
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("plc_logic_bomb: {n} PLC protocol signal(s) on {host}"),
    )
}
cli_wrapper!(run_plc_logic_bomb, run_plc_logic_bomb_result);

pub async fn run_lorawan_attack_result(target: &str) -> EngineResult {
    agent_required_bus_attack(
        "lorawan_attack",
        target,
        "LoRaWAN RF attacks require a radio-capable endpoint agent",
        "LoRaWAN join-abuse and downlink spoofing need local RF hardware — not reachable via HTTP management APIs.",
    )
    .await
}
cli_wrapper!(run_lorawan_attack, run_lorawan_attack_result);

pub async fn run_voltage_glitch_attack_result(target: &str) -> EngineResult {
    agent_required_bus_attack(
        "voltage_glitch_attack",
        target,
        "Voltage/clock glitching requires physical hardware access",
        "Fault injection against secure boot or crypto accelerators must run on a bench agent with a glitch rig.",
    )
    .await
}
cli_wrapper!(run_voltage_glitch_attack, run_voltage_glitch_attack_result);

pub async fn run_tpm_firmware_attack_result(target: &str) -> EngineResult {
    agent_required_bus_attack(
        "tpm_firmware_attack",
        target,
        "TPM/firmware bus attacks require a local hardware agent",
        "SPI/LPC TPM probing and firmware glitching cannot be inferred from remote HTTP or audit-only crypto scans.",
    )
    .await
}
cli_wrapper!(run_tpm_firmware_attack, run_tpm_firmware_attack_result);

pub async fn run_cold_boot_attack_result(target: &str) -> EngineResult {
    agent_required_bus_attack(
        "cold_boot_attack",
        target,
        "Cold-boot memory capture requires physical host access",
        "RAM remanence extraction runs on an enrolled agent with physical access to the target machine.",
    )
    .await
}
cli_wrapper!(run_cold_boot_attack, run_cold_boot_attack_result);

// ── HL7 / MLLP clinical interface — real read-only exposure probe ────────────────
// MLLP framing: <SB=0x0B> payload <EB=0x1C><CR=0x0D>. We send a benign HL7 message with an UNKNOWN
// trigger event so a real listener replies with an ACK/NACK (MSA segment), confirming an
// unauthenticated HL7 interface WITHOUT performing any clinical action (no ADT/ORM orders sent).
const MLLP_SB: u8 = 0x0B;
const MLLP_EB: u8 = 0x1C;
const MLLP_CR: u8 = 0x0D;

/// Wrap an HL7 payload in an MLLP frame. Pure — unit-tested.
pub fn build_mllp_frame(payload: &str) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 3);
    f.push(MLLP_SB);
    f.extend_from_slice(payload.as_bytes());
    f.push(MLLP_EB);
    f.push(MLLP_CR);
    f
}

/// Benign HL7 v2 probe: a minimal MSH with an unknown trigger so the listener NACKs (no clinical
/// effect). Field separator `|`, encoding chars `^~\&`.
fn hl7_probe_message() -> String {
    "MSH|^~\\&|WEISSMAN_SCAN|SECURITY|RECEIVER|FACILITY|20260101000000||ZZZ^ZZZ|WSCAN1|P|2.5"
        .to_string()
}

/// Does the response look like HL7/MLLP (framing or an MSH/MSA/ACK segment)? Pure — unit-tested.
pub fn looks_like_hl7(resp: &[u8]) -> bool {
    let mllp = resp.first() == Some(&MLLP_SB) || resp.contains(&MLLP_EB);
    let text = String::from_utf8_lossy(resp);
    let hl7 = text.contains("MSH|")
        || text.contains("MSA|")
        || text.contains("ACK^")
        || text.contains("|AA")
        || text.contains("|AE")
        || text.contains("|AR");
    mllp || hl7
}

pub async fn run_hospital_hl7_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let frame = build_mllp_frame(&hl7_probe_message());
    let mut findings: Vec<Value> = Vec::new();
    // Common MLLP listener ports (Mirth Connect, Cloverleaf, Rhapsody, generic HL7 interfaces).
    for &port in &[2575u16, 6661, 6662, 6663, 7777] {
        if !tcp_open(&host, port).await {
            continue;
        }
        let confirmed = tcp_probe_response(&host, port, &frame)
            .await
            .map(|b| looks_like_hl7(&b))
            .unwrap_or(false);
        if confirmed {
            findings.push(finding(
                "hospital_hl7_attack",
                &format!("Unauthenticated HL7/MLLP interface exposed on {host}:{port}"),
                "high",
                "T0883",
                &format!(
                    "MLLP listener on {host}:{port} replied to a benign HL7 probe with an HL7/ACK message — the clinical interface accepts unauthenticated messages (PHI exposure / message-injection risk). No ADT/ORM clinical orders were sent."
                ),
                target,
            ));
        } else {
            findings.push(finding(
                "hospital_hl7_attack",
                &format!("Port {port}/tcp open (HL7/MLLP candidate, unconfirmed) on {host}"),
                "medium",
                "T0883",
                &format!(
                    "TCP {host}:{port} accepts connections but no HL7/MLLP ACK was confirmed."
                ),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("hospital_hl7_attack", target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!("hospital_hl7_attack: {n} HL7/MLLP signal(s) on {host}"),
        )
    }
}
cli_wrapper!(run_hospital_hl7_attack, run_hospital_hl7_attack_result);

async fn port_probe_finding(
    target: &str,
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    ports: &[u16],
    note: &str,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    for &p in ports {
        if tcp_open(&host, p).await {
            findings.push(finding(
                engine_id,
                &format!("{} (port {}/tcp open)", title, p),
                severity,
                mitre,
                &format!("TCP {}:{} accepts connections. {}", host, p, note),
                target,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok(engine_id, target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("{}: {} open OT port(s)", engine_id, n))
    }
}

pub async fn run_dnp3_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    if tcp_open(&host, 20000).await {
        let probe: [u8; 12] = [
            0x05, 0x64, 0x05, 0xC9, 0x02, 0x00, 0x01, 0x00, 0xCB, 0x16, 0x00, 0x00,
        ];
        let resp = tcp_probe_response(&host, 20000, &probe).await;
        let confirmed = resp
            .as_deref()
            .map(|b| b.len() >= 2 && b[0] == 0x05 && b[1] == 0x64)
            .unwrap_or(false);
        findings.push(finding(
            "dnp3_attack",
            if confirmed {
                "DNP3 confirmed (start bytes 0x05 0x64 in reply)"
            } else {
                "Port 20000/tcp open (DNP3 candidate)"
            },
            "high",
            "T0843",
            &format!(
                "TCP {}:{} reachable. {}",
                host,
                20000,
                if confirmed {
                    "LINK_STATUS reply confirms DNP3."
                } else {
                    "No protocol confirmation."
                }
            ),
            t,
        ));
    }
    if findings.is_empty() {
        empty_ok("dnp3_attack", t)
    } else {
        EngineResult::ok(findings.clone(), format!("dnp3_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_dnp3_attack, run_dnp3_attack_result);

// ── MQTT (IoT broker) — real CONNECT/CONNACK probe ───────────────────────────────
/// Encode an MQTT "remaining length" variable-byte integer. Pure — unit-tested.
fn mqtt_encode_remaining_length(mut len: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
}

/// Build an MQTT v3.1.1 CONNECT packet (clean session, no credentials). Pure — unit-tested.
pub fn build_mqtt_connect(client_id: &str) -> Vec<u8> {
    let cid = client_id.as_bytes();
    // Variable header: protocol name "MQTT", level 4, connect flags 0x02 (clean session), keep-alive 60s.
    let mut var = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C];
    // Payload: client id (length-prefixed).
    var.push((cid.len() >> 8) as u8);
    var.push((cid.len() & 0xFF) as u8);
    var.extend_from_slice(cid);
    let mut pkt = vec![0x10]; // CONNECT control packet type
    mqtt_encode_remaining_length(var.len(), &mut pkt);
    pkt.extend_from_slice(&var);
    pkt
}

/// Parse the CONNACK return code from a broker response. Pure — unit-tested.
pub fn parse_mqtt_connack(resp: &[u8]) -> Option<u8> {
    // CONNACK: 0x20, remaining length 0x02, [session_present, return_code].
    if resp.len() >= 4 && resp[0] == 0x20 {
        Some(resp[3])
    } else {
        None
    }
}

fn mqtt_connack_meaning(code: u8) -> &'static str {
    match code {
        0x00 => "connection accepted (anonymous access permitted)",
        0x01 => "unacceptable protocol version",
        0x02 => "client identifier rejected",
        0x03 => "server unavailable",
        0x04 => "bad username or password",
        0x05 => "not authorized",
        _ => "unknown return code",
    }
}

pub async fn run_mqtt_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();

    // Plaintext MQTT (1883): send a real CONNECT and read the CONNACK return code.
    if tcp_open(&host, 1883).await {
        let pkt = build_mqtt_connect("weissman-scan");
        match tcp_probe_response(&host, 1883, &pkt)
            .await
            .as_deref()
            .and_then(parse_mqtt_connack)
        {
            Some(0x00) => findings.push(finding(
                "mqtt_attack",
                &format!("Anonymous MQTT broker access permitted on {host}:1883"),
                "high",
                "T0842",
                &format!(
                    "MQTT broker at {host}:1883 returned CONNACK 0x00 to an unauthenticated CONNECT — anonymous publish/subscribe is allowed (topic eavesdropping / message injection risk)."
                ),
                t,
            )),
            Some(code) => findings.push(finding(
                "mqtt_attack",
                &format!("MQTT broker confirmed on {host}:1883 (auth enforced)"),
                "medium",
                "T0842",
                &format!(
                    "MQTT broker at {host}:1883 responded with CONNACK 0x{code:02x} — {}.",
                    mqtt_connack_meaning(code)
                ),
                t,
            )),
            None => findings.push(finding(
                "mqtt_attack",
                &format!("Port 1883/tcp open (MQTT candidate, unconfirmed) on {host}"),
                "low",
                "T0842",
                &format!("TCP {host}:1883 accepts connections but no CONNACK was observed."),
                t,
            )),
        }
    }

    // TLS MQTT (8883): port presence only (a TLS handshake is required before MQTT).
    if tcp_open(&host, 8883).await {
        findings.push(finding(
            "mqtt_attack",
            &format!("Port 8883/tcp open (MQTT-over-TLS candidate) on {host}"),
            "low",
            "T0842",
            &format!("TCP {host}:8883 accepts connections (MQTT over TLS); CONNECT requires a TLS session."),
            t,
        ));
    }

    if findings.is_empty() {
        empty_ok("mqtt_attack", t)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!("mqtt_attack: {n} MQTT signal(s) on {host}"),
        )
    }
}
cli_wrapper!(run_mqtt_attack, run_mqtt_attack_result);

pub async fn run_coap_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    // CoAP GET empty confirmable message to /.well-known/core
    let coap_get: [u8; 4] = [0x40, 0x01, 0x01, 0x2e];
    for port in [5683u16, 5684] {
        if let Some(resp) = udp_probe_response(&host, port, &coap_get).await {
            findings.push(finding(
                "coap_attack",
                &format!("CoAP UDP response on {host}:{port}"),
                "medium",
                "T0809",
                &format!(
                    "CoAP datagram probe returned {} bytes on UDP/{port} — IoT device may expose /.well-known/core; review auth and resource enumeration.",
                    resp.len()
                ),
                t,
            ));
            break;
        }
    }
    if findings.is_empty() {
        port_probe_finding(
            t,
            "coap_attack",
            "CoAP IoT protocol port",
            "low",
            "T0809",
            &[5683, 5684],
            "CoAP UDP service (no CoAP response to probe).",
        )
        .await
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("coap_attack: {} signal(s)", findings.len()),
        )
    }
}
cli_wrapper!(run_coap_attack, run_coap_attack_result);

pub async fn run_zigbee_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let bases = [
        format!("http://{host}:8080"),
        format!("http://{host}:8888"),
        normalize_url(t),
    ];
    for base in bases {
        for path in ["/api/info", "/zigbee2mqtt", "/api/devices", "/api/config"] {
            let url = join_url(&base, path);
            if let Some(p) = http_get(&client, &url).await {
                if status_indicates_presence(p.status) {
                    let body = p.body.to_ascii_lowercase();
                    if body.contains("zigbee")
                        || body.contains("mqtt")
                        || body.contains("hue")
                        || body.contains("coordinator")
                    {
                        findings.push(finding(
                            "zigbee_attack",
                            "Zigbee/MQTT gateway HTTP API exposed",
                            "high",
                            "T0809",
                            &format!(
                                "{} ({}) — Zigbee2MQTT/Hue bridges expose device pairing over HTTP; validate network segmentation.",
                                p.final_url, p.status
                            ),
                            t,
                        ));
                        return EngineResult::ok(
                            findings.clone(),
                            format!("zigbee_attack: {} signal(s)", findings.len()),
                        );
                    }
                }
            }
        }
    }
    port_probe_finding(
        t,
        "zigbee_attack",
        "Zigbee gateway port",
        "low",
        "T0809",
        &[9999, 17754, 8080],
        "Zigbee2MQTT / Hue bridge TCP (no HTTP fingerprint).",
    )
    .await
}
cli_wrapper!(run_zigbee_attack, run_zigbee_attack_result);

pub async fn run_iec61850_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    if tcp_open(&host, 102).await {
        let probe: [u8; 22] = [
            0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0, 0x01, 0x0A,
            0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02,
        ];
        let resp = tcp_probe_response(&host, 102, &probe).await;
        let confirmed = resp
            .as_deref()
            .map(|b| b.len() >= 4 && b[0] == 0x03 && b[1] == 0x00)
            .unwrap_or(false);
        findings.push(finding(
            "iec61850_attack",
            if confirmed {
                "IEC 61850 / MMS confirmed (TPKT reply)"
            } else {
                "Port 102/tcp open (IEC 61850 candidate)"
            },
            "high",
            "T0843",
            &format!(
                "TCP {}:{} reachable. {}",
                host,
                102,
                if confirmed {
                    "ISO-TSAP CR/CC handshake confirms IEC 61850 / MMS."
                } else {
                    "No TPKT reply observed."
                }
            ),
            t,
        ));
    }
    if findings.is_empty() {
        empty_ok("iec61850_attack", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("iec61850_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_iec61850_attack, run_iec61850_attack_result);

pub async fn run_plc_logic_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    // Prefer real protocol confirmation (S7comm / ENIP / Modbus) over a bare port-open signal.
    let confirmations = plc_protocol_confirmations(&host, "plc_logic_attack", t).await;
    if !confirmations.is_empty() {
        let n = confirmations.len();
        return EngineResult::ok(
            confirmations,
            format!("plc_logic_attack: {n} confirmed PLC protocol(s) on {host}"),
        );
    }
    // No protocol confirmation — fall back to reporting open engineering ports as candidates.
    port_probe_finding(
        t,
        "plc_logic_attack",
        "PLC engineering port",
        "high",
        "T0843",
        &[44818, 102, 502, 9600],
        "Common PLC engineering/runtime ports.",
    )
    .await
}
cli_wrapper!(run_plc_logic_attack, run_plc_logic_attack_result);

pub async fn run_hmi_attack_result(t: &str) -> EngineResult {
    port_probe_finding(
        t,
        "hmi_attack",
        "HMI / SCADA web UI",
        "high",
        "T0822",
        &[80, 443, 8080, 8443],
        "Web-based HMI surfaces.",
    )
    .await
}
cli_wrapper!(run_hmi_attack, run_hmi_attack_result);

pub async fn run_satellite_comm_attack_result(t: &str) -> EngineResult {
    port_probe_finding(
        t,
        "satellite_comm_attack",
        "Satellite gateway management",
        "medium",
        "T0883",
        &[443, 8443, 8000],
        "VSAT gateway HTTP admin candidates.",
    )
    .await
}
cli_wrapper!(run_satellite_comm_attack, run_satellite_comm_attack_result);

pub async fn run_firmware_emulation_attack_result(t: &str) -> EngineResult {
    crate::iot_firmware_engine::run_iot_firmware_result(t).await
}
cli_wrapper!(
    run_firmware_emulation_attack,
    run_firmware_emulation_attack_result
);

pub async fn run_profinet_attack_result(t: &str) -> EngineResult {
    port_probe_finding(
        t,
        "profinet_attack",
        "PROFINET realtime port",
        "high",
        "T0843",
        &[34962, 34963, 34964],
        "PROFINET-IO endpoints.",
    )
    .await
}
cli_wrapper!(run_profinet_attack, run_profinet_attack_result);

pub async fn run_rfid_nfc_attack_result(t: &str) -> EngineResult {
    port_probe_finding(
        t,
        "rfid_nfc_attack",
        "RFID/NFC gateway",
        "low",
        "T0809",
        &[8080, 80],
        "RFID middleware HTTP admin candidates.",
    )
    .await
}
cli_wrapper!(run_rfid_nfc_attack, run_rfid_nfc_attack_result);

pub async fn run_industrial_protocol_fuzz_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    // Real, read-only ICS protocol handshakes (not a bare TCP connect): send an
    // actual Modbus FC-03 read, an OPC-UA HEL/ACK discovery, and a BACnet
    // ReadProperty, then report every protocol that genuinely answers with
    // fingerprint evidence. Reuses the vetted probes from `ot_ics_engine`.
    let mut findings: Vec<Value> = Vec::new();
    if let Some(fp) = probe_modbus_function_code(&host).await {
        findings.push(ot_fingerprint_finding(&fp, "industrial_protocol_fuzz", t));
    }
    if let Some(fp) = probe_opcua_discovery(&host).await {
        findings.push(ot_fingerprint_finding(&fp, "industrial_protocol_fuzz", t));
    }
    if let Some(fp) = probe_bacnet_read_property(&host).await {
        findings.push(ot_fingerprint_finding(&fp, "industrial_protocol_fuzz", t));
    }
    if !findings.is_empty() {
        let n = findings.len();
        return EngineResult::ok(
            findings,
            format!(
                "industrial_protocol_fuzz: {n} ICS protocol handshake(s) confirmed via live probes"
            ),
        );
    }
    // No handshake confirmed — fall back to the open-port surface so coverage
    // never regresses.
    port_probe_finding(
        t,
        "industrial_protocol_fuzz",
        "Industrial protocol surface",
        "high",
        "T0843",
        &[502, 102, 20000, 4840, 44818],
        "ICS ports reachable but no Modbus/OPC-UA/BACnet handshake confirmed — fuzz under authorized, controlled conditions.",
    )
    .await
}
cli_wrapper!(
    run_industrial_protocol_fuzz,
    run_industrial_protocol_fuzz_result
);

#[cfg(test)]
mod hl7_tests {
    use super::*;

    #[test]
    fn mllp_frame_wraps_with_sb_eb_cr() {
        let f = build_mllp_frame("MSH|^~\\&|A");
        assert_eq!(f.first(), Some(&0x0B));
        assert_eq!(f[f.len() - 2], 0x1C);
        assert_eq!(f[f.len() - 1], 0x0D);
        // payload preserved between SB and EB
        assert_eq!(&f[1..f.len() - 2], b"MSH|^~\\&|A");
    }

    #[test]
    fn detects_hl7_ack_and_mllp_framing() {
        // MLLP-framed ACK
        let ack = build_mllp_frame("MSH|^~\\&|RECV|FAC|...||ACK^A19|1|P|2.5\rMSA|AA|WSCAN1");
        assert!(looks_like_hl7(&ack));
        // Bare MSA segment without framing
        assert!(looks_like_hl7(b"MSA|AR|WSCAN1|Unknown message type"));
        // Non-HL7 noise
        assert!(!looks_like_hl7(b"HTTP/1.1 400 Bad Request\r\n\r\n"));
        assert!(!looks_like_hl7(b""));
    }
}

#[cfg(test)]
mod mqtt_tests {
    use super::*;

    #[test]
    fn connect_packet_is_well_formed() {
        let pkt = build_mqtt_connect("weissman-scan");
        assert_eq!(pkt[0], 0x10); // CONNECT control packet
        let var = &pkt[2..]; // skip type + single remaining-length byte (payload < 128)
        assert_eq!(&var[0..6], &[0x00, 0x04, b'M', b'Q', b'T', b'T']);
        assert_eq!(var[6], 0x04); // protocol level 3.1.1
        assert_eq!(var[7], 0x02); // clean-session flag
    }

    #[test]
    fn remaining_length_varint_encoding() {
        let mut o = Vec::new();
        mqtt_encode_remaining_length(0, &mut o);
        assert_eq!(o, vec![0x00]);
        let mut o2 = Vec::new();
        mqtt_encode_remaining_length(127, &mut o2);
        assert_eq!(o2, vec![0x7F]);
        let mut o3 = Vec::new();
        mqtt_encode_remaining_length(128, &mut o3);
        assert_eq!(o3, vec![0x80, 0x01]); // MQTT spec multi-byte example
    }

    #[test]
    fn connack_return_code_parsed() {
        assert_eq!(parse_mqtt_connack(&[0x20, 0x02, 0x00, 0x00]), Some(0x00));
        assert_eq!(parse_mqtt_connack(&[0x20, 0x02, 0x00, 0x05]), Some(0x05));
        assert_eq!(parse_mqtt_connack(&[0x30, 0x02, 0x00, 0x00]), None); // not a CONNACK
        assert_eq!(parse_mqtt_connack(&[0x20, 0x02]), None); // too short
    }
}
