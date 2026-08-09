//! Wireless, BLE & RF IoT Posture — agentless perimeter assessment with optional agent BLE validation.
//!
//! Wiz/CNAPP-style model for the wireless/IoT attack surface: live, read-only probing only — no
//! simulated findings. Maps internet-exposed wireless management planes, IoT cloud hubs, protocol
//! brokers (MQTT/CoAP/LoRaWAN), and controller admin surfaces; synthesises a 0–100 posture grade,
//! toxic-combination attack paths, and a prioritised remediation roadmap.
//!
//! **Remote (agentless) layers**
//!   * IoT cloud hub APIs — AWS IoT Core, Azure IoT Hub, GCP IoT Core, ThingsBoard, Home Assistant,
//!     OpenHAB, Tuya, SmartThings, Particle, Blynk, Node-RED, etc.
//!   * BLE / GATT management APIs — REST gateways that expose pairing, GATT read/write, beacon config.
//!   * Zigbee / Z-Wave / Matter / Thread management consoles and bridge APIs.
//!   * Wireless LAN controllers — UniFi, Meraki, Aruba, Ruckus, MikroTik, Cisco WLC.
//!   * MQTT broker fingerprint — real CONNECT/CONNACK (anonymous vs auth-enforced).
//!   * CoAP — UDP `.well-known/core` resource discovery.
//!   * LoRaWAN gateway backhaul — Semtech UDP 1700, MQTT backhaul ports.
//!   * mDNS / Bonjour — wireless device advertisement on UDP/5353.
//!   * RF/IoT TCP ports — Hue bridge, Zigbee2MQTT, ESPHome, Tasmota, RTSP, TR-069, etc.
//!
//! **Agent hybrid**
//!   When `request_agent_ble_scan` is true, emits an honest `agent_required` info finding for
//!   proximity BLE pairing-mode, Just Works / NoInputNoOutput, and GATT enumeration — radio work
//!   that cannot be performed from a remote scanner.

#![allow(
    clippy::too_many_lines,
    clippy::module_name_repetitions,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::advanced_ot_engines::{build_mqtt_connect, parse_mqtt_connack};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    empty_ok, extract_host, finding_with_probe_depth, http_client, http_get, join_url,
    normalize_url, probe_matched_token, probe_paths_concurrent, status_indicates_presence,
    tcp_banner, tcp_open, tcp_probe_response, tcp_scan, udp_probe_response, HttpProbe,
    DEFAULT_PROBE_CONCURRENCY,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const ENGINE_ID: &str = "ble_rf";

// ─── Parameters (from job_params / GUI) ──────────────────────────────────────────

struct PostureConfig {
    check_iot_hubs: bool,
    check_ble_api: bool,
    check_wireless_controllers: bool,
    check_zigbee: bool,
    check_zwave: bool,
    check_matter: bool,
    check_mqtt: bool,
    check_coap: bool,
    check_lorawan: bool,
    check_mdns: bool,
    check_rf_ports: bool,
    check_attack_paths: bool,
    check_posture_score: bool,
    request_agent_ble_scan: bool,
    strict_mode: bool,
    mqtt_ports: Vec<u16>,
    coap_ports: Vec<u16>,
    extra_paths: Vec<String>,
    #[allow(dead_code)] // parsed from params; not read after refactor
    timeout_ms: u64,
}

impl PostureConfig {
    fn from_params(p: &Value) -> Self {
        let mqtt_ports = parse_ports(p, "mqtt_ports", &[1883, 8883, 8083, 8884]);
        let coap_ports = parse_ports(p, "coap_ports", &[5683, 5684]);
        let extra_paths: Vec<String> = split_list(&pstr(p, "extra_paths"))
            .into_iter()
            .filter(|s| s.starts_with('/'))
            .take(32)
            .collect();

        Self {
            check_iot_hubs: pbool(p, "check_iot_hubs", true),
            check_ble_api: pbool(p, "check_ble_api", true),
            check_wireless_controllers: pbool(p, "check_wireless_controllers", true),
            check_zigbee: pbool(p, "check_zigbee", true),
            check_zwave: pbool(p, "check_zwave", true),
            check_matter: pbool(p, "check_matter", true),
            check_mqtt: pbool(p, "check_mqtt", true),
            check_coap: pbool(p, "check_coap", true),
            check_lorawan: pbool(p, "check_lorawan", true),
            check_mdns: pbool(p, "check_mdns", true),
            check_rf_ports: pbool(p, "check_rf_ports", true),
            check_attack_paths: pbool(p, "check_attack_paths", true),
            check_posture_score: pbool(p, "check_posture_score", true),
            request_agent_ble_scan: pbool(p, "request_agent_ble_scan", true),
            strict_mode: pbool(p, "strict_mode", false),
            mqtt_ports,
            coap_ports,
            extra_paths,
            timeout_ms: pu64(p, "timeout_ms", 8000).clamp(2000, 30000),
        }
    }
}

fn pstr(p: &Value, key: &str) -> String {
    match p.get(key) {
        Some(Value::String(s)) => s.trim().to_string(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn pbool(p: &Value, key: &str, default: bool) -> bool {
    match p.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => {
            let s = s.trim().to_ascii_lowercase();
            if s.is_empty() {
                default
            } else {
                matches!(s.as_str(), "true" | "1" | "yes" | "on" | "enabled")
            }
        }
        Some(Value::Number(n)) => n.as_i64().map(|v| v != 0).unwrap_or(default),
        _ => default,
    }
}

fn pu64(p: &Value, key: &str, default: u64) -> u64 {
    match p.get(key) {
        Some(Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_f64().map(|f| f as u64))
            .unwrap_or(default),
        Some(Value::String(s)) => s.trim().parse::<u64>().unwrap_or(default),
        _ => default,
    }
}

fn split_list(s: &str) -> Vec<String> {
    s.split([',', ' ', ';', '\n', '\t'])
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

fn parse_ports(p: &Value, key: &str, defaults: &[u16]) -> Vec<u16> {
    let raw = pstr(p, key);
    let mut v: Vec<u16> = split_list(&raw)
        .iter()
        .filter_map(|s| s.parse::<u16>().ok())
        .collect();
    if v.is_empty() {
        v = defaults.to_vec();
    }
    v.truncate(8);
    v
}

// ─── Policy metadata (Wiz-style rule IDs) ────────────────────────────────────────

struct PolicyMeta {
    id: &'static str,
    category: &'static str,
    remediation: &'static str,
    controls: &'static [&'static str],
}

const IOT_HUB_EXPOSED: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-001",
    category: "iot_hub",
    remediation: "Require mutual TLS or OAuth for IoT hub APIs; disable public endpoints; use VPC/private link and IP allow-lists.",
    controls: &["NIST-AC-3", "CIS-IoT-1.1", "IEC-62443-SR-7.1"],
};
const BLE_API_EXPOSED: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-002",
    category: "ble_management",
    remediation: "Never expose BLE/GATT management over the internet; require VPN/mTLS; disable Just Works pairing on production devices.",
    controls: &["NIST-AC-17", "CWE-306", "MITRE-T1011"],
};
const WIRELESS_CONTROLLER: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-003",
    category: "wireless_controller",
    remediation: "Restrict wireless controller admin to management VLAN; enforce MFA; disable default credentials; patch controller firmware.",
    controls: &["CIS-WiFi-1.1", "NIST-AC-2", "PCI-DSS-2.2.4"],
};
const ZIGBEE_SURFACE: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-004",
    category: "zigbee",
    remediation: "Isolate Zigbee coordinators on dedicated VLAN; rotate network keys; disable permit-join except during provisioning windows.",
    controls: &["IEC-62443-SR-5.2", "MITRE-T0855"],
};
const ZWAVE_SURFACE: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-005",
    category: "zwave",
    remediation: "Disable internet-facing Z-Wave JS / OpenZWave admin; use S2 security; segment home-automation networks.",
    controls: &["IEC-62443-SR-5.2", "MITRE-T0855"],
};
const MATTER_SURFACE: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-006",
    category: "matter",
    remediation: "Keep Matter commissioners off the public internet; enforce CASE commissioning with attestation; segment Thread border routers.",
    controls: &["Matter-Spec-1.2", "NIST-AC-3"],
};
const MQTT_ANON: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-007",
    category: "mqtt_broker",
    remediation: "Require TLS + username/password or client certificates on MQTT; enforce topic ACLs; disable anonymous CONNECT.",
    controls: &["CIS-IoT-2.1", "MITRE-T0842", "NIST-SC-8"],
};
const MQTT_CONFIRMED: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-008",
    category: "mqtt_broker",
    remediation: "Ensure MQTT brokers are not internet-exposed; if required, enforce mTLS and per-device credentials.",
    controls: &["CIS-IoT-2.1", "MITRE-T0842"],
};
const COAP_EXPOSED: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-009",
    category: "coap",
    remediation:
        "Block CoAP from the internet; use DTLS-PSK or OSCORE; segment constrained-device networks.",
    controls: &["RFC-7252", "MITRE-T0809"],
};
const LORAWAN_GATEWAY: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-010",
    category: "lorawan",
    remediation: "Never expose LoRaWAN packet-forwarder ports; use VPN for gateway backhaul; rotate AppKeys and join nonces.",
    controls: &["LoRaWAN-Spec-1.1", "MITRE-T0855"],
};
const MDNS_WIRELESS: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-011",
    category: "mdns",
    remediation:
        "Disable mDNS on internet-facing interfaces; use DNS-SD only on trusted LAN segments.",
    controls: &["RFC-6762", "NIST-SC-7"],
};
const RF_PORT_EXPOSED: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-012",
    category: "rf_port",
    remediation:
        "Block IoT/RF bridge ports at the perimeter; patch firmware; change factory credentials.",
    controls: &["CIS-IoT-1.2", "MITRE-T1133"],
};
const ATTACK_PATH: PolicyMeta = PolicyMeta {
    id: "WZ-BLE-AP",
    category: "attack_path",
    remediation: "Break the toxic combination: remove internet exposure OR enforce strong auth on each layer.",
    controls: &["NIST-RA-5", "MITRE-T1190"],
};

fn wfinding(
    policy: &PolicyMeta,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    evidence: Value,
) -> Value {
    let mut f = finding_with_probe_depth(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        policy.category,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("policy_id".to_string(), json!(policy.id));
        obj.insert("category".to_string(), json!(policy.category));
        obj.insert("remediation".to_string(), json!(policy.remediation));
        obj.insert("compliance".to_string(), json!(policy.controls));
        if !evidence.is_null() {
            obj.insert("evidence".to_string(), evidence);
        }
    }
    f
}

fn haystack(p: &HttpProbe) -> String {
    format!("{}\n{}", p.body, p.final_url).to_ascii_lowercase()
}

// ─── IoT hub / smart-home cloud signatures ─────────────────────────────────────

struct HubSig {
    name: &'static str,
    paths: &'static [&'static str],
    tokens: &'static [&'static str],
    severity: &'static str,
    mitre: &'static str,
}

const IOT_HUB_SIGS: &[HubSig] = &[
    HubSig {
        name: "AWS IoT Core",
        paths: &["/things", "/api/things", "/iot/things"],
        tokens: &["aws iot", "iot.amazonaws", "x-amzn-requestid", "thingname"],
        severity: "critical",
        mitre: "T1190",
    },
    HubSig {
        name: "Azure IoT Hub",
        paths: &["/devices", "/api/devices", "/iothub/explorer"],
        tokens: &[
            "azure-iothub",
            "microsoft.azure",
            "iothub",
            "sharedaccesskey",
        ],
        severity: "critical",
        mitre: "T1190",
    },
    HubSig {
        name: "Google Cloud IoT Core",
        paths: &["/v1/projects", "/cloudiot/devices"],
        tokens: &["cloudiot", "googleapis.com/iot", "device registry"],
        severity: "critical",
        mitre: "T1190",
    },
    HubSig {
        name: "ThingsBoard",
        paths: &["/api/auth/login", "/api/tenant/devices", "/swagger-ui.html"],
        tokens: &["thingsboard", "tb-ui", "tenantid"],
        severity: "high",
        mitre: "T1190",
    },
    HubSig {
        name: "Home Assistant",
        paths: &["/api/", "/auth/providers", "/api/config", "/lovelace"],
        tokens: &["home assistant", "homeassistant", "supervisor", "hass.io"],
        severity: "high",
        mitre: "T1190",
    },
    HubSig {
        name: "OpenHAB",
        paths: &["/rest/", "/doc/index.html", "/start/index"],
        tokens: &["openhab", "eclipse smart home", "org.openhab"],
        severity: "high",
        mitre: "T1190",
    },
    HubSig {
        name: "Node-RED",
        paths: &["/flows", "/red/", "/admin/"],
        tokens: &["node-red", "nodered", "node red editor"],
        severity: "high",
        mitre: "T1190",
    },
    HubSig {
        name: "Tuya IoT Platform",
        paths: &["/v1.0/iot", "/api/tuya", "/cloud/thing"],
        tokens: &["tuya", "tuyasmart", "tuyacn"],
        severity: "high",
        mitre: "T1190",
    },
    HubSig {
        name: "SmartThings",
        paths: &["/api/smartthings", "/oauth/authorize"],
        tokens: &["smartthings", "samsung smartthings"],
        severity: "high",
        mitre: "T1190",
    },
    HubSig {
        name: "Particle Cloud",
        paths: &["/v1/devices", "/api/particle"],
        tokens: &["particle.io", "particle device"],
        severity: "medium",
        mitre: "T1190",
    },
    HubSig {
        name: "Blynk IoT",
        paths: &["/api/blynk", "/hardware/login"],
        tokens: &["blynk", "blynk.cloud"],
        severity: "medium",
        mitre: "T1190",
    },
    HubSig {
        name: "ESPHome Dashboard",
        paths: &["/", "/edit", "/download.bin"],
        tokens: &["esphome", "espressif", "ota password"],
        severity: "high",
        mitre: "T1190",
    },
    HubSig {
        name: "Tasmota Web UI",
        paths: &["/", "/cm", "/api"],
        tokens: &["tasmota", "sonoff", "mqtt host"],
        severity: "high",
        mitre: "T1190",
    },
];

const BLE_API_PATHS: &[&str] = &[
    "/api/ble",
    "/api/ble/devices",
    "/api/bluetooth",
    "/api/gatt",
    "/api/gatt/read",
    "/api/gatt/write",
    "/api/beacon",
    "/api/ibeacon",
    "/ble/v1/devices",
    "/v1/ble/scan",
    "/bluetooth/devices",
    "/api/v1/bluetooth",
    "/api/pairing",
    "/api/nrf/connect",
    "/api/btle",
];

const BLE_TOKENS: &[&str] = &[
    "bluetooth",
    "ble",
    "gatt",
    "characteristic",
    "pairing",
    "beacon",
    "eddystone",
    "ibeacon",
    "rssi",
    "peripheral",
    "central",
    "nordic",
    "bluez",
];

const WIRELESS_CONTROLLER_PATHS: &[&str] = &[
    "/manage",
    "/unifi/",
    "/Meraki/",
    "/webfig/",
    "/cgi-bin/luci/",
    "/api/wlan",
    "/wireless",
    "/controller/",
    "/api/site/",
    "/api/s/default/self",
    "/j_security_check",
    "/webui/",
    "/wlc/",
    "/api/configuration/wlan",
];

const WIRELESS_TOKENS: &[&str] = &[
    "unifi",
    "meraki",
    "mikrotik",
    "cisco",
    "aruba",
    "ruckus",
    "wireless",
    "wifi",
    "wlan",
    "access point",
    "ssid",
    "controller",
    "capwap",
];

const ZIGBEE_PATHS: &[&str] = &[
    "/api/zigbee",
    "/zigbee2mqtt",
    "/api/zigbee2mqtt",
    "/api/zigbee/networkmap",
    "/api/services/zigbee2mqtt",
    "/api/conbee",
    "/deconz",
    "/api/ph/hue",
    "/clip/v2/resource",
];

const ZIGBEE_TOKENS: &[&str] = &[
    "zigbee",
    "z2m",
    "zigbee2mqtt",
    "deconz",
    "conbee",
    "philips hue",
    "coordinator",
    "permit_join",
    "network map",
];

const ZWAVE_PATHS: &[&str] = &[
    "/api/zwave",
    "/zwave-js-ui",
    "/api/zwavejs",
    "/api/zwave/nodes",
    "/api/services/zwave",
    "/zwave/settings",
];

const ZWAVE_TOKENS: &[&str] = &[
    "zwave",
    "z-wave",
    "zwavejs",
    "openzwave",
    "inclusion",
    "s0",
    "s2",
    "security",
];

const MATTER_PATHS: &[&str] = &[
    "/api/matter",
    "/matter/commission",
    "/api/thread",
    "/api/otbr",
    "/api/homekit",
    "/api/apple/home",
];

const MATTER_TOKENS: &[&str] = &[
    "matter",
    "thread",
    "commission",
    "fabric",
    "operational certificate",
    "homekit",
    "border router",
    "otbr",
];

const RF_IOT_PORTS: &[(u16, &str, &str, &str)] = &[
    (1883, "MQTT (plaintext)", "high", "T0842"),
    (8883, "MQTT-over-TLS", "medium", "T0842"),
    (8083, "MQTT WebSocket", "medium", "T0842"),
    (5683, "CoAP", "medium", "T0809"),
    (5684, "CoAPS (DTLS)", "medium", "T0809"),
    (1700, "LoRaWAN Semtech UDP forwarder", "critical", "T0855"),
    (1783, "LoRaWAN gateway alt", "high", "T0855"),
    (9999, "Zigbee2MQTT / Hue bridge", "high", "T0855"),
    (8080, "ESPHome / Tasmota HTTP", "high", "T1190"),
    (6053, "ESPHome native API", "high", "T1190"),
    (8123, "Home Assistant default", "high", "T1190"),
    (1880, "Node-RED editor", "high", "T1190"),
    (554, "RTSP (IP camera)", "medium", "T1133"),
    (37777, "Dahua DVR", "high", "T1133"),
    (5353, "mDNS (UDP)", "medium", "T1040"),
];

// ─── Probe helpers ───────────────────────────────────────────────────────────────

async fn probe_http_signatures(
    base: &str,
    target: &str,
    paths: &[&str],
    tokens: &[&str],
    policy: &PolicyMeta,
    label: &str,
    default_sev: &str,
    mitre: &str,
    matched: &mut BTreeMap<String, bool>,
) -> Vec<Value> {
    let client = http_client().await;
    let probes = probe_paths_concurrent(&client, base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    let mut out = Vec::new();
    for p in probes {
        if !status_indicates_presence(p.status) {
            continue;
        }
        let hs = haystack(&p);
        let token_hit = probe_matched_token(&p, tokens).or_else(|| {
            tokens
                .iter()
                .find(|t| hs.contains(&t.to_ascii_lowercase()))
                .map(|s| (*s).to_string())
        });
        if token_hit.is_none() && p.status != 200 {
            continue;
        }
        let key = format!("{}:{}", label, p.final_url);
        if matched.contains_key(&key) {
            continue;
        }
        matched.insert(key.clone(), true);
        let sev = if token_hit.is_some() && p.status == 200 {
            default_sev
        } else if p.status == 401 || p.status == 403 {
            "medium"
        } else {
            "low"
        };
        out.push(wfinding(
            policy,
            &format!("{label} surface: {}", p.final_url),
            sev,
            mitre,
            &format!(
                "{} returned HTTP {} {} — {} management plane reachable from the perimeter{}.",
                p.final_url,
                p.status,
                if let Some(t) = &token_hit {
                    format!("(matched '{}')", t)
                } else {
                    String::new()
                },
                label,
                if p.status == 200 {
                    " with content confirming the platform"
                } else {
                    " (auth gate present — still an attack surface)"
                }
            ),
            target,
            json!({
                "url": p.final_url,
                "status": p.status,
                "token": token_hit,
                "body_snippet": p.body.chars().take(200).collect::<String>(),
            }),
        ));
    }
    out
}

async fn probe_mqtt_ports(host: &str, target: &str, ports: &[u16]) -> Vec<Value> {
    let mut out = Vec::new();
    let pkt = build_mqtt_connect("weissman-ble-rf");
    for &port in ports {
        if !tcp_open(host, port).await {
            continue;
        }
        let resp = tcp_probe_response(host, port, &pkt).await;
        if let Some(code) = resp.as_deref().and_then(parse_mqtt_connack) {
            if code == 0x00 {
                out.push(wfinding(
                    &MQTT_ANON,
                    &format!("Anonymous MQTT broker on {host}:{port}"),
                    "critical",
                    "T0842",
                    &format!(
                        "MQTT broker at {host}:{port} accepted an unauthenticated CONNECT (CONNACK 0x00) — any internet client can publish/subscribe (Mirai-class botnet risk, sensor spoofing, actuator control)."
                    ),
                    target,
                    json!({ "host": host, "port": port, "connack": format!("0x{code:02x}") }),
                ));
            } else {
                out.push(wfinding(
                    &MQTT_CONFIRMED,
                    &format!("MQTT broker confirmed on {host}:{port} (auth enforced)"),
                    "medium",
                    "T0842",
                    &format!(
                        "MQTT broker at {host}:{port} responded CONNACK 0x{code:02x} — broker is reachable; authentication is enforced but perimeter exposure remains a risk."
                    ),
                    target,
                    json!({ "host": host, "port": port, "connack": format!("0x{code:02x}") }),
                ));
            }
        } else if port == 8883 || port == 8884 {
            out.push(wfinding(
                &MQTT_CONFIRMED,
                &format!("MQTT-over-TLS port open: {host}:{port}"),
                "medium",
                "T0842",
                &format!("TCP {host}:{port} accepts connections (MQTT-over-TLS candidate) — validate certificate pinning and client auth."),
                target,
                json!({ "host": host, "port": port, "tls": true }),
            ));
        } else {
            out.push(wfinding(
                &MQTT_CONFIRMED,
                &format!("MQTT port candidate: {host}:{port}"),
                "low",
                "T0842",
                &format!("TCP {host}:{port} is open but no CONNACK observed — may be a non-MQTT service or TLS-wrapped."),
                target,
                json!({ "host": host, "port": port }),
            ));
        }
    }
    out
}

/// Minimal CoAP GET `/.well-known/core` (RFC 7252).
fn build_coap_well_known_core(msg_id: u16) -> Vec<u8> {
    // Ver=1, T=NON, TKL=0, Code=GET(1), MsgID
    let mut pkt = vec![0x40, 0x01, (msg_id >> 8) as u8, (msg_id & 0xFF) as u8];
    // Option: Uri-Path ".well-known" (delta=11, len=11)
    pkt.extend_from_slice(&[0xBB]);
    pkt.extend_from_slice(b".well-known");
    // Option: Uri-Path "core" (delta=0, len=4)
    pkt.extend_from_slice(&[0x04]);
    pkt.extend_from_slice(b"core");
    pkt
}

async fn probe_coap_ports(host: &str, target: &str, ports: &[u16]) -> Vec<Value> {
    let mut out = Vec::new();
    let pkt = build_coap_well_known_core(0xBEEF);
    for &port in ports {
        if let Some(resp) = udp_probe_response(host, port, &pkt).await {
            if !resp.is_empty() && (resp[0] & 0xF0) == 0x60 {
                // CoAP ACK (type=2) or response
                let body_hint = String::from_utf8_lossy(&resp);
                out.push(wfinding(
                    &COAP_EXPOSED,
                    &format!("CoAP service responds on {host}:{port}/.well-known/core"),
                    if body_hint.contains("rt=") || body_hint.contains('>') {
                        "high"
                    } else {
                        "medium"
                    },
                    "T0809",
                    &format!(
                        "UDP {host}:{port} answered a CoAP GET for /.well-known/core — constrained IoT resource discovery is internet-reachable{}.",
                        if body_hint.len() > 8 {
                            format!(" Response excerpt: '{}'", body_hint.chars().take(80).collect::<String>())
                        } else {
                            String::new()
                        }
                    ),
                    target,
                    json!({ "host": host, "port": port, "response_hex": hex_prefix(&resp, 48) }),
                ));
            }
        }
    }
    out
}

fn hex_prefix(buf: &[u8], max: usize) -> String {
    buf.iter()
        .take(max)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

async fn probe_lorawan(host: &str, target: &str) -> Vec<Value> {
    let mut out = Vec::new();
    if tcp_open(host, 1700).await {
        out.push(wfinding(
            &LORAWAN_GATEWAY,
            &format!("LoRaWAN packet-forwarder port open: {host}:1700"),
            "critical",
            "T0855",
            &format!(
                "TCP {host}:1700 is reachable — Semtech UDP packet-forwarder ports are commonly used by LoRaWAN gateways; internet exposure enables sensor traffic injection and key-extraction attacks against misconfigured gateways."
            ),
            target,
            json!({ "host": host, "port": 1700, "protocol": "semtech_udp_forwarder" }),
        ));
    }
    // Semtech UDP push probe
    if udp_probe_response(host, 1700, b"\x01\x04\x00\x01")
        .await
        .is_some()
    {
        out.push(wfinding(
            &LORAWAN_GATEWAY,
            &format!("LoRaWAN gateway UDP/1700 responded on {host}"),
            "critical",
            "T0855",
            &format!("UDP {host}:1700 responded to a Semtech PUSH_DATA probe — LoRaWAN gateway backhaul is internet-exposed."),
            target,
            json!({ "host": host, "port": 1700, "udp": true }),
        ));
    }
    out
}

async fn probe_mdns(host: &str, target: &str) -> Vec<Value> {
    // mDNS query for _services._dns-sd._udp.local
    let query: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, b'_', b's',
        b'e', b'r', b'v', b'i', b'c', b'e', b's', 0x07, b'_', b'd', b'n', b's', b'-', b's', b'd',
        0x04, b'_', b'u', b'd', b'p', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00, 0x00, 0x0C, 0x00,
        0x01,
    ];
    let mut out = Vec::new();
    if let Some(resp) = udp_probe_response(host, 5353, query).await {
        if resp.len() > 12 {
            out.push(wfinding(
                &MDNS_WIRELESS,
                &format!("mDNS responder on {host}:5353"),
                "medium",
                "T1040",
                &format!(
                    "Host {host} answered an mDNS query on UDP/5353 — wireless/IoT devices often advertise via Bonjour; internet-exposed mDNS leaks device types and service names."
                ),
                target,
                json!({ "host": host, "port": 5353, "response_len": resp.len() }),
            ));
        }
    }
    out
}

async fn probe_rf_ports(host: &str, target: &str) -> Vec<Value> {
    let ports: Vec<u16> = RF_IOT_PORTS.iter().map(|&(p, ..)| p).collect();
    let open = tcp_scan(host, &ports, 20).await;
    let mut out = Vec::new();
    for port in open {
        if let Some(&(_, name, sev, mitre)) = RF_IOT_PORTS.iter().find(|&&(p, ..)| p == port) {
            let mut desc = format!(
                "{}/tcp ({}) reachable on {host} — RF/IoT bridge exposure; block at perimeter unless explicitly required.",
                port, name
            );
            if matches!(port, 23 | 2323) {
                if let Some(banner) = tcp_banner(host, port).await {
                    let snip: String = banner.chars().take(80).collect();
                    if !snip.trim().is_empty() {
                        desc.push_str(&format!(" Banner: '{}'.", snip.replace('\n', " ")));
                    }
                }
            }
            out.push(wfinding(
                &RF_PORT_EXPOSED,
                &format!("RF/IoT port exposed: {name} ({port}/tcp)"),
                sev,
                mitre,
                &desc,
                target,
                json!({ "host": host, "port": port, "service": name }),
            ));
        }
    }
    out
}

// ─── Posture scoring & toxic combinations ────────────────────────────────────────

struct PostureFacts {
    iot_hub: bool,
    ble_api: bool,
    wireless_ctrl: bool,
    zigbee: bool,
    zwave: bool,
    matter: bool,
    mqtt_anon: bool,
    mqtt_exposed: bool,
    coap: bool,
    lorawan: bool,
    mdns: bool,
    rf_ports: u32,
    critical_count: u32,
    high_count: u32,
}

fn collect_facts(findings: &[Value]) -> PostureFacts {
    let mut f = PostureFacts {
        iot_hub: false,
        ble_api: false,
        wireless_ctrl: false,
        zigbee: false,
        zwave: false,
        matter: false,
        mqtt_anon: false,
        mqtt_exposed: false,
        coap: false,
        lorawan: false,
        mdns: false,
        rf_ports: 0,
        critical_count: 0,
        high_count: 0,
    };
    for finding in findings {
        let cat = finding
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let sev = finding
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        match sev.as_str() {
            "critical" => f.critical_count += 1,
            "high" => f.high_count += 1,
            _ => {}
        }
        match cat {
            "iot_hub" => f.iot_hub = true,
            "ble_management" => f.ble_api = true,
            "wireless_controller" => f.wireless_ctrl = true,
            "zigbee" => f.zigbee = true,
            "zwave" => f.zwave = true,
            "matter" => f.matter = true,
            "mqtt_broker" => {
                f.mqtt_exposed = true;
                if finding.get("policy_id").and_then(|v| v.as_str()) == Some("WZ-BLE-007") {
                    f.mqtt_anon = true;
                }
            }
            "coap" => f.coap = true,
            "lorawan" => f.lorawan = true,
            "mdns" => f.mdns = true,
            "rf_port" => f.rf_ports += 1,
            _ => {}
        }
    }
    f
}

fn grade_letter(score: u32) -> &'static str {
    match score {
        95..=100 => "A+",
        90..=94 => "A",
        85..=89 => "A-",
        80..=84 => "B+",
        75..=79 => "B",
        70..=74 => "B-",
        65..=69 => "C+",
        60..=64 => "C",
        55..=59 => "C-",
        50..=54 => "D",
        _ => "F",
    }
}

fn wireless_verdict(facts: &PostureFacts) -> (&'static str, &'static str) {
    if facts.mqtt_anon && (facts.iot_hub || facts.zigbee || facts.lorawan) {
        return (
            "compromised",
            "Anonymous MQTT + IoT hub/gateway exposure — full device network takeover path",
        );
    }
    if facts.ble_api && facts.wireless_ctrl {
        return (
            "high_risk",
            "BLE management API + wireless controller admin — remote + proximity attack chain",
        );
    }
    if facts.lorawan && facts.mqtt_exposed {
        return (
            "high_risk",
            "LoRaWAN gateway + MQTT backhaul both exposed — sensor spoofing and command injection",
        );
    }
    if facts.critical_count > 0 || facts.mqtt_anon {
        return ("high_risk", "Critical wireless/IoT exposure observed");
    }
    if facts.high_count > 2 || facts.iot_hub || facts.ble_api {
        return (
            "elevated",
            "Multiple high-severity wireless surfaces detected",
        );
    }
    if facts.high_count > 0 || facts.mqtt_exposed || facts.rf_ports > 2 {
        return (
            "moderate",
            "Some wireless/IoT exposure — review perimeter controls",
        );
    }
    (
        "hardened",
        "No critical wireless/IoT perimeter gaps observed",
    )
}

fn compute_score(facts: &PostureFacts, strict: bool) -> u32 {
    let mut score: i32 = 100;
    if facts.mqtt_anon {
        score -= 35;
    }
    if facts.iot_hub {
        score -= 25;
    }
    if facts.ble_api {
        score -= 20;
    }
    if facts.lorawan {
        score -= 22;
    }
    if facts.wireless_ctrl {
        score -= 15;
    }
    if facts.zigbee || facts.zwave || facts.matter {
        score -= 12;
    }
    if facts.mqtt_exposed && !facts.mqtt_anon {
        score -= 10;
    }
    if facts.coap {
        score -= 8;
    }
    if facts.mdns {
        score -= 5;
    }
    score -= (facts.rf_ports as i32).min(15) * 2;
    score -= (facts.critical_count as i32) * 8;
    score -= (facts.high_count as i32) * 4;
    if strict {
        score -= 5;
    }
    score.clamp(0, 100) as u32
}

fn synthesize_attack_paths(facts: &PostureFacts, target: &str) -> Vec<Value> {
    let mut paths = Vec::new();
    if facts.mqtt_anon && facts.iot_hub {
        paths.push(wfinding(
            &ATTACK_PATH,
            "Toxic combination: anonymous MQTT + IoT cloud hub",
            "critical",
            "T1190",
            "Internet client publishes rogue device telemetry to anonymous MQTT while IoT hub API manages device lifecycle — attacker achieves full smart-fleet impersonation and command injection without credentials.",
            target,
            json!({ "chain": ["anonymous_mqtt", "iot_hub_api"], "impact": "device_takeover" }),
        ));
    }
    if facts.ble_api && facts.zigbee {
        paths.push(wfinding(
            &ATTACK_PATH,
            "Toxic combination: BLE GATT API + Zigbee coordinator",
            "critical",
            "T1011",
            "Remote BLE pairing/GATT API combined with exposed Zigbee coordinator enables attacker to bridge proximity BLE attacks into the Zigbee mesh (lighting, locks, HVAC).",
            target,
            json!({ "chain": ["ble_gatt_api", "zigbee_coordinator"], "impact": "mesh_pivot" }),
        ));
    }
    if facts.lorawan && facts.mqtt_anon {
        paths.push(wfinding(
            &ATTACK_PATH,
            "Toxic combination: LoRaWAN gateway + anonymous MQTT",
            "critical",
            "T0855",
            "LoRaWAN packet forwarder with open MQTT backhaul — attacker injects forged sensor uplinks and receives downlink commands intended for field devices.",
            target,
            json!({ "chain": ["lorawan_gateway", "anonymous_mqtt"], "impact": "sensor_spoofing" }),
        ));
    }
    if facts.wireless_ctrl && facts.rf_ports > 0 {
        paths.push(wfinding(
            &ATTACK_PATH,
            "Attack path: wireless controller → IoT bridge ports",
            "high",
            "T1557",
            "Exposed WLAN controller admin combined with open IoT bridge ports — credential compromise on controller yields lateral movement to MQTT/CoAP device networks.",
            target,
            json!({ "chain": ["wlan_controller", "iot_bridge_ports"], "impact": "lateral_movement" }),
        ));
    }
    paths
}

fn build_roadmap(facts: &PostureFacts, host: &str) -> Vec<Value> {
    let mut steps: Vec<(u8, String)> = Vec::new();
    if facts.mqtt_anon {
        steps.push((
            1,
            format!("Disable anonymous MQTT on {host} — require TLS client certificates and topic ACLs."),
        ));
    }
    if facts.iot_hub {
        steps.push((
            2,
            "Remove internet exposure from IoT cloud hub APIs — use private endpoints, mTLS, or IP allow-lists.".into(),
        ));
    }
    if facts.ble_api {
        steps.push((
            3,
            "Take BLE/GATT management APIs off the public internet; disable Just Works / NoInputNoOutput pairing.".into(),
        ));
    }
    if facts.lorawan {
        steps.push((
            4,
            format!("Block LoRaWAN forwarder ports (1700/UDP) on {host} at the firewall."),
        ));
    }
    if facts.wireless_ctrl {
        steps.push((
            5,
            "Restrict wireless controller admin to management VLAN with MFA.".into(),
        ));
    }
    if facts.zigbee || facts.zwave || facts.matter {
        steps.push((
            6,
            "Segment home-automation protocols (Zigbee/Z-Wave/Matter/Thread) from corporate and guest networks.".into(),
        ));
    }
    steps.sort_by_key(|(p, _)| *p);
    steps
        .into_iter()
        .map(|(priority, action)| json!({ "priority": priority, "action": action }))
        .collect()
}

fn posture_summary(
    target: &str,
    host: &str,
    facts: &PostureFacts,
    strict: bool,
    findings_count: usize,
) -> Value {
    let score = compute_score(facts, strict);
    let letter = grade_letter(score);
    let (verdict, headline) = wireless_verdict(facts);
    let subscores = json!({
        "iot_cloud": (100_i32 - if facts.iot_hub { 40 } else { 0 }).max(0),
        "ble_rf": (100_i32 - if facts.ble_api { 35 } else { 0 }).max(0),
        "protocol_brokers": (100_i32
            - if facts.mqtt_anon { 45 } else if facts.mqtt_exposed { 15 } else { 0 }
            - if facts.coap { 10 } else { 0 }
            - if facts.lorawan { 25 } else { 0 })
        .max(0),
        "mesh_protocols": (100_i32
            - if facts.zigbee { 15 } else { 0 }
            - if facts.zwave { 15 } else { 0 }
            - if facts.matter { 15 } else { 0 })
        .max(0),
        "perimeter_rf": (100_i32 - (facts.rf_ports as i32 * 5).min(40)).max(0),
    });
    json!({
        "type": ENGINE_ID,
        "category": "posture_summary",
        "summary": true,
        "title": format!("Wireless & RF IoT posture: {letter} ({score}/100)"),
        "severity": if score >= 85 { "info" } else if score >= 60 { "medium" } else { "high" },
        "mitre_attack": "T1011",
        "description": format!(
            "Target `{host}` wireless/IoT perimeter scored {score}/100 (grade {letter}). Verdict: {verdict} — {headline}. {findings_count} evidence-backed finding(s)."
        ),
        "target": target,
        "grade": letter,
        "score": score,
        "wireless_verdict": verdict,
        "headline": headline,
        "subscores": subscores,
        "details": {
            "iot_hub": facts.iot_hub,
            "ble_api": facts.ble_api,
            "wireless_controller": facts.wireless_ctrl,
            "zigbee": facts.zigbee,
            "zwave": facts.zwave,
            "matter": facts.matter,
            "mqtt_anonymous": facts.mqtt_anon,
            "mqtt_exposed": facts.mqtt_exposed,
            "coap": facts.coap,
            "lorawan": facts.lorawan,
            "mdns": facts.mdns,
            "rf_ports": facts.rf_ports,
        },
        "roadmap": build_roadmap(facts, host),
        "standards": ["IEC-62443", "NIST-CSF-PR.IP", "CIS-IoT", "LoRaWAN-Spec", "Matter-1.2", "MITRE-ICS"],
    })
}

fn agent_ble_info(target: &str) -> Value {
    finding_with_probe_depth(
        ENGINE_ID,
        "Proximity BLE scan requires endpoint agent",
        "info",
        "T1011",
        "Remote scanning cannot perform Bluetooth LE pairing-mode detection, GATT characteristic enumeration, or RF spectrum analysis. Enroll a Weissman endpoint agent on a host with Bluetooth hardware to validate pairing security (Just Works / NoInputNoOutput / Passkey), exposed GATT services, and beacon leakage.",
        target,
        "agent_ble_hybrid",
    )
}

// ─── Main runner ─────────────────────────────────────────────────────────────────

pub async fn run_ble_rf_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = PostureConfig::from_params(&ctx.job_params);
    let base = normalize_url(target);
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();
    let mut matched: BTreeMap<String, bool> = BTreeMap::new();

    // IoT cloud hubs
    if cfg.check_iot_hubs {
        for sig in IOT_HUB_SIGS {
            let mut paths: Vec<&str> = sig.paths.to_vec();
            for ep in &cfg.extra_paths {
                paths.push(ep.as_str());
            }
            findings.extend(
                probe_http_signatures(
                    &base,
                    target,
                    &paths,
                    sig.tokens,
                    &IOT_HUB_EXPOSED,
                    sig.name,
                    sig.severity,
                    sig.mitre,
                    &mut matched,
                )
                .await,
            );
        }
    }

    // BLE management APIs
    if cfg.check_ble_api {
        let mut paths: Vec<&str> = BLE_API_PATHS.to_vec();
        for ep in &cfg.extra_paths {
            paths.push(ep.as_str());
        }
        findings.extend(
            probe_http_signatures(
                &base,
                target,
                &paths,
                BLE_TOKENS,
                &BLE_API_EXPOSED,
                "BLE/GATT management",
                "high",
                "T1011",
                &mut matched,
            )
            .await,
        );
    }

    // Wireless LAN controllers
    if cfg.check_wireless_controllers {
        findings.extend(
            probe_http_signatures(
                &base,
                target,
                WIRELESS_CONTROLLER_PATHS,
                WIRELESS_TOKENS,
                &WIRELESS_CONTROLLER,
                "Wireless controller",
                "high",
                "T1557",
                &mut matched,
            )
            .await,
        );
    }

    if cfg.check_zigbee {
        findings.extend(
            probe_http_signatures(
                &base,
                target,
                ZIGBEE_PATHS,
                ZIGBEE_TOKENS,
                &ZIGBEE_SURFACE,
                "Zigbee coordinator",
                "high",
                "T0855",
                &mut matched,
            )
            .await,
        );
    }

    if cfg.check_zwave {
        findings.extend(
            probe_http_signatures(
                &base,
                target,
                ZWAVE_PATHS,
                ZWAVE_TOKENS,
                &ZWAVE_SURFACE,
                "Z-Wave gateway",
                "high",
                "T0855",
                &mut matched,
            )
            .await,
        );
    }

    if cfg.check_matter {
        findings.extend(
            probe_http_signatures(
                &base,
                target,
                MATTER_PATHS,
                MATTER_TOKENS,
                &MATTER_SURFACE,
                "Matter/Thread",
                "high",
                "T0855",
                &mut matched,
            )
            .await,
        );
    }

    if cfg.check_mqtt {
        findings.extend(probe_mqtt_ports(&host, target, &cfg.mqtt_ports).await);
    }

    if cfg.check_coap {
        findings.extend(probe_coap_ports(&host, target, &cfg.coap_ports).await);
    }

    if cfg.check_lorawan {
        findings.extend(probe_lorawan(&host, target).await);
    }

    if cfg.check_mdns {
        findings.extend(probe_mdns(&host, target).await);
    }

    if cfg.check_rf_ports {
        findings.extend(probe_rf_ports(&host, target).await);
    }

    // Extra path-only probes (user-supplied)
    if !cfg.extra_paths.is_empty() {
        let client = http_client().await;
        let path_refs: Vec<&str> = cfg.extra_paths.iter().map(String::as_str).collect();
        let probes =
            probe_paths_concurrent(&client, &base, &path_refs, DEFAULT_PROBE_CONCURRENCY).await;
        for p in probes {
            if status_indicates_presence(p.status) {
                findings.push(wfinding(
                    &RF_PORT_EXPOSED,
                    &format!("Custom wireless path exposed: {}", p.final_url),
                    "medium",
                    "T1190",
                    &format!(
                        "{} returned HTTP {} — operator-supplied wireless/IoT path is reachable.",
                        p.final_url, p.status
                    ),
                    target,
                    json!({ "url": p.final_url, "status": p.status }),
                ));
            }
        }
    }

    let facts = collect_facts(&findings);

    if cfg.check_attack_paths {
        findings.extend(synthesize_attack_paths(&facts, target));
    }

    if cfg.request_agent_ble_scan {
        findings.push(agent_ble_info(target));
    }

    if cfg.check_posture_score {
        findings.insert(
            0,
            posture_summary(target, &host, &facts, cfg.strict_mode, findings.len()),
        );
    }

    if findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("{ENGINE_ID}: {host} — {n} wireless/RF finding(s)"),
    )
}

pub async fn run_ble_rf_result(target: &str) -> EngineResult {
    run_ble_rf_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_ble_rf(target: &str) {
    print_result(run_ble_rf_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coap_packet_has_well_known_core() {
        let pkt = build_coap_well_known_core(1);
        assert!(pkt.starts_with(&[0x40, 0x01]));
        let body = String::from_utf8_lossy(&pkt);
        assert!(body.contains(".well-known"));
        assert!(body.contains("core"));
    }

    #[test]
    fn grade_boundaries() {
        assert_eq!(grade_letter(100), "A+");
        assert_eq!(grade_letter(50), "D");
        assert_eq!(grade_letter(30), "F");
    }

    #[test]
    fn toxic_mqtt_iot_hub_verdict() {
        let facts = PostureFacts {
            mqtt_anon: true,
            iot_hub: true,
            ..PostureFacts {
                iot_hub: false,
                ble_api: false,
                wireless_ctrl: false,
                zigbee: false,
                zwave: false,
                matter: false,
                mqtt_anon: false,
                mqtt_exposed: false,
                coap: false,
                lorawan: false,
                mdns: false,
                rf_ports: 0,
                critical_count: 0,
                high_count: 0,
            }
        };
        let (v, _) = wireless_verdict(&facts);
        assert_eq!(v, "compromised");
    }

    #[test]
    fn config_parses_bools_from_strings() {
        let p = json!({ "check_mqtt": "false", "strict_mode": "true", "timeout_ms": "12000" });
        let c = PostureConfig::from_params(&p);
        assert!(!c.check_mqtt);
        assert!(c.strict_mode);
        assert_eq!(c.timeout_ms, 12000);
    }

    #[tokio::test]
    async fn empty_target_errors() {
        assert!(!run_ble_rf_result("").await.success);
    }
}
