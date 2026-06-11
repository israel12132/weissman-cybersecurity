//! Advanced OT/ICS Engines — real TCP/UDP protocol fingerprint probes.
//! Passive surface checks delegate to `ot_ics_engine`; bus-level / physical attacks
//! require an enrolled endpoint agent (no HTTP stand-ins).

use crate::engine_probes::{agent_required_ok, empty_ok, extract_host, finding, tcp_open, tcp_probe_response};
use crate::engine_result::{print_result, EngineResult};
use crate::ot_ics_engine::{probe_bacnet_read_property, probe_modbus_function_code, probe_opcua_discovery, OtFingerprint};
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
        &format!("{} on {}:{} ({})", fp.protocol, fp.host, fp.port, fp.vendor_hint),
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
                &format!("TCP {}:502 accepts connections but no FC03/readProperty confirmation.", host),
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
                &format!("TCP {}:4840 accepts connections but HEL/ACK discovery was not confirmed.", host),
                t,
            )],
            "opcua_attack: port open, discovery unconfirmed".to_string(),
        );
    }
    empty_ok("opcua_attack", t)
}
cli_wrapper!(run_opcua_attack, run_opcua_attack_result);

pub async fn run_modbus_exploit_result(target: &str) -> EngineResult {
    agent_required_bus_attack(
        "modbus_exploit",
        target,
        "Modbus write/coerce exploits require on-segment agent",
        "Function-code abuse and register writes need L2/L3 access to the fieldbus from an OT-segment agent.",
    )
    .await
}
cli_wrapper!(run_modbus_exploit, run_modbus_exploit_result);

pub async fn run_plc_logic_bomb_result(target: &str) -> EngineResult {
    agent_required_bus_attack(
        "plc_logic_bomb",
        target,
        "PLC logic manipulation requires engineering-workstation agent",
        "Logic downloads and runtime tampering are validated from an enrolled agent on the OT engineering network.",
    )
    .await
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

pub async fn run_hospital_hl7_attack_result(target: &str) -> EngineResult {
    agent_required_bus_attack(
        "hospital_hl7_attack",
        target,
        "HL7/clinical interface attacks require on-segment agent",
        "MLLP/HL7 manipulation and medical-device bus testing need an agent on the clinical network segment.",
    )
    .await
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

pub async fn run_mqtt_attack_result(t: &str) -> EngineResult {
    port_probe_finding(t, "mqtt_attack", "MQTT broker port", "medium", "T0809", &[1883, 8883], "MQTT plaintext/TLS broker.").await
}
cli_wrapper!(run_mqtt_attack, run_mqtt_attack_result);

pub async fn run_coap_attack_result(t: &str) -> EngineResult {
    port_probe_finding(t, "coap_attack", "CoAP IoT protocol port", "low", "T0809", &[5683, 5684], "CoAP UDP service.").await
}
cli_wrapper!(run_coap_attack, run_coap_attack_result);

pub async fn run_zigbee_attack_result(t: &str) -> EngineResult {
    port_probe_finding(t, "zigbee_attack", "Zigbee gateway port", "low", "T0809", &[9999, 17754], "Zigbee2MQTT / Hue bridge.").await
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
            0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC0,
            0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02,
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
        EngineResult::ok(findings.clone(), format!("iec61850_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_iec61850_attack, run_iec61850_attack_result);

pub async fn run_plc_logic_attack_result(t: &str) -> EngineResult {
    port_probe_finding(t, "plc_logic_attack", "PLC engineering port", "high", "T0843", &[44818, 102, 502, 9600], "Common PLC engineering/runtime ports.").await
}
cli_wrapper!(run_plc_logic_attack, run_plc_logic_attack_result);

pub async fn run_hmi_attack_result(t: &str) -> EngineResult {
    port_probe_finding(t, "hmi_attack", "HMI / SCADA web UI", "high", "T0822", &[80, 443, 8080, 8443], "Web-based HMI surfaces.").await
}
cli_wrapper!(run_hmi_attack, run_hmi_attack_result);

pub async fn run_satellite_comm_attack_result(t: &str) -> EngineResult {
    port_probe_finding(t, "satellite_comm_attack", "Satellite gateway management", "medium", "T0883", &[443, 8443, 8000], "VSAT gateway HTTP admin candidates.").await
}
cli_wrapper!(run_satellite_comm_attack, run_satellite_comm_attack_result);

pub async fn run_firmware_emulation_attack_result(t: &str) -> EngineResult {
    crate::iot_firmware_engine::run_iot_firmware_result(t).await
}
cli_wrapper!(run_firmware_emulation_attack, run_firmware_emulation_attack_result);

pub async fn run_profinet_attack_result(t: &str) -> EngineResult {
    port_probe_finding(t, "profinet_attack", "PROFINET realtime port", "high", "T0843", &[34962, 34963, 34964], "PROFINET-IO endpoints.").await
}
cli_wrapper!(run_profinet_attack, run_profinet_attack_result);

pub async fn run_rfid_nfc_attack_result(t: &str) -> EngineResult {
    port_probe_finding(t, "rfid_nfc_attack", "RFID/NFC gateway", "low", "T0809", &[8080, 80], "RFID middleware HTTP admin candidates.").await
}
cli_wrapper!(run_rfid_nfc_attack, run_rfid_nfc_attack_result);

pub async fn run_industrial_protocol_fuzz_result(t: &str) -> EngineResult {
    port_probe_finding(t, "industrial_protocol_fuzz", "Industrial protocol surface", "high", "T0843", &[502, 102, 20000, 4840, 44818], "Common ICS ports to fuzz under controlled conditions.").await
}
cli_wrapper!(run_industrial_protocol_fuzz, run_industrial_protocol_fuzz_result);
