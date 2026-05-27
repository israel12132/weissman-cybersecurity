//! Advanced OT/ICS Engines — real TCP/UDP port + protocol fingerprint probes.
//! Industrial protocols are detected by attempting a TCP connect on well-known ports and (where
//! safe) reading a banner or sending a minimal protocol-specific probe frame.

use crate::engine_probes::{empty_ok, extract_host, finding, tcp_open, tcp_probe_response};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

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

// Modbus TCP — port 502; verify with a "Read Holding Registers" probe.
pub async fn run_modbus_attack_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    if tcp_open(&host, 502).await {
        // MBAP header + function 03 read holding registers (1 register at addr 0)
        let probe: [u8; 12] = [0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01];
        let resp = tcp_probe_response(&host, 502, &probe).await;
        let modbus_like = resp.as_deref().map(|b| b.len() >= 8 && b[7] == 0x03 || b.get(7) == Some(&0x83)).unwrap_or(false);
        findings.push(finding(
            "modbus_attack",
            if modbus_like {
                "Modbus/TCP confirmed (function 03 response)"
            } else {
                "Port 502/tcp open (Modbus likely)"
            },
            "high",
            "T0843",
            &format!("TCP {}:{} reachable. {}", host, 502, if modbus_like { "Function 03 echoed." } else { "No protocol confirmation." }),
            target,
        ));
    }
    if findings.is_empty() {
        empty_ok("modbus_attack", target)
    } else {
        EngineResult::ok(findings.clone(), format!("modbus_attack: {}", findings.len()))
    }
}
cli_wrapper!(run_modbus_attack, run_modbus_attack_result);

pub async fn run_dnp3_attack_result(t: &str) -> EngineResult {
    port_probe_finding(t, "dnp3_attack", "DNP3 industrial protocol", "high", "T0843", &[20000], "DNP3 standard TCP port.").await
}
cli_wrapper!(run_dnp3_attack, run_dnp3_attack_result);

pub async fn run_bacnet_attack_result(t: &str) -> EngineResult {
    // BACnet/IP uses UDP 47808; we test if the host has the port open via TCP just to confirm reachability.
    port_probe_finding(t, "bacnet_attack", "BACnet building-automation port", "medium", "T0843", &[47808], "BACnet/IP listens on UDP 47808.").await
}
cli_wrapper!(run_bacnet_attack, run_bacnet_attack_result);

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
    port_probe_finding(t, "iec61850_attack", "IEC 61850 MMS port", "high", "T0843", &[102], "IEC 61850 / MMS over ISO-TSAP.").await
}
cli_wrapper!(run_iec61850_attack, run_iec61850_attack_result);

pub async fn run_opcua_attack_result(t: &str) -> EngineResult {
    port_probe_finding(t, "opcua_attack", "OPC-UA industrial port", "high", "T0843", &[4840], "OPC-UA discovery endpoint.").await
}
cli_wrapper!(run_opcua_attack, run_opcua_attack_result);

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
