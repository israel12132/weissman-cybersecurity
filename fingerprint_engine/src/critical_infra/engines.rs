//! Critical-infrastructure attack engines — verticals no mainstream scanner covers end-to-end:
//! aviation (ADS-B/ACARS), maritime (AIS/NMEA/gpsd), EV charging (OCPP), smart grid
//! (IEC 60870-5-104 / DLMS-COSEM), railway signalling, building automation (KNX/Niagara Fox),
//! robotics (ROS / Universal Robots), and OT Safety-Instrumented-Systems (Triconex/TRITON-class).
//!
//! Every probe is **live** and read-only: real protocol handshakes (IEC-104 STARTDT, KNXnet/IP
//! SEARCH_REQUEST, ROS XML-RPC `getSystemState`, OCPP WebSocket upgrade with the `ocpp` subprotocol)
//! and real TCP/UDP service identification. RF-layer injection (1090 MHz ADS-B, VHF AIS, GSM-R,
//! balise) genuinely needs an SDR/on-site collector and is surfaced through the agent — never faked.

use super::critical_finding;
use crate::arsenal_config::{ArsenalConfig, Evidence};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    agent_required_ok, empty_ok, extract_host, http_client, http_get, tcp_banner, tcp_open,
    tcp_probe_response, tcp_scan, udp_probe_response,
};
use crate::engine_result::EngineResult;

// ── Protocol builders (read-only, standards-accurate) ──────────────────────────

/// IEC 60870-5-104 APCI U-frame: STARTDT activation. A live RTU/controller replies with STARTDT
/// confirmation (control octet 0x0B). 100% read-only — no ASDU / control command is sent.
fn iec104_startdt_act() -> [u8; 6] {
    [0x68, 0x04, 0x07, 0x00, 0x00, 0x00]
}

/// KNXnet/IP SEARCH_REQUEST (service 0x0201) with a zeroed discovery HPAI. A KNX/IP router replies
/// with SEARCH_RESPONSE (service 0x0202) disclosing device name + KNX individual address.
fn knxnet_search_request() -> [u8; 14] {
    [
        0x06, 0x10, // header length, protocol version 1.0
        0x02, 0x01, // service type: SEARCH_REQUEST
        0x00, 0x0e, // total length 14
        0x08, 0x01, // HPAI structure length 8, host protocol code 0x01 (IPv4 UDP)
        0x00, 0x00, 0x00, 0x00, // IP 0.0.0.0 (reply to source)
        0x00, 0x00, // port 0
    ]
}

// ── Engine: aviation / ADS-B / ACARS ───────────────────────────────────────────

const ADSB_PORTS: &[u16] = &[30001, 30002, 30003, 30004, 30005, 8080, 8754, 5550];

/// Real probe: network-exposed ADS-B/Mode-S feeders (dump1090/readsb/FlightAware), SBS BaseStation
/// feeds and raw Beast input ports (which accept *injected* aircraft).
pub async fn run_avionics_adsb_attack_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let open = tcp_scan(&host, &cfg.ports_or("ports", ADSB_PORTS), cfg.concurrency()).await;
    let mut findings = Vec::new();

    for &port in &open {
        let (kind, sev, score, injectable, desc) = match port {
            30001 | 30004 | 30104 => (
                "Beast/raw INPUT feed",
                "critical",
                0.9,
                true,
                "Raw/Beast INPUT port accepts Mode-S frames — an attacker can inject phantom aircraft into the feed (ghost-plane / TCAS-confusion data integrity attack).",
            ),
            30003 => (
                "SBS BaseStation feed",
                "high",
                0.7,
                false,
                "BaseStation (SBS-1) CSV output feed exposed — leaks live surveillance data and signals an exposed ADS-B aggregator.",
            ),
            8080 | 8754 => (
                "ADS-B web map",
                "medium",
                0.55,
                false,
                "dump1090/tar1090/SkyAware web interface exposed.",
            ),
            5550 => (
                "ACARS/VDLM2 feed",
                "high",
                0.65,
                false,
                "ACARS/VDLM2 decoder feed exposed — aircraft datalink messaging is observable and potentially injectable.",
            ),
            _ => (
                "ADS-B feeder port",
                "medium",
                0.5,
                false,
                "ADS-B feeder service port open.",
            ),
        };
        let mut ev = Evidence::new()
            .with("host", host.clone())
            .with("port", port)
            .with("feed_kind", kind)
            .check("tcp_connect", true, "open")
            .check(
                "injectable_input",
                injectable,
                if injectable {
                    "raw input accepts frames"
                } else {
                    "output/observation only"
                },
            );
        if port == 30003 {
            if let Some(b) = tcp_banner(&host, port).await {
                if b.contains("MSG,") || b.contains(',') {
                    ev = ev.raw_excerpt(b.as_bytes()).check(
                        "sbs_csv",
                        true,
                        "BaseStation CSV observed",
                    );
                }
            }
        } else if matches!(port, 8080 | 8754) {
            let client = http_client().await;
            if let Some(r) = http_get(&client, &format!("http://{}:{}/", host, port)).await {
                let bl = r.body.to_ascii_lowercase();
                if bl.contains("dump1090")
                    || bl.contains("tar1090")
                    || bl.contains("skyaware")
                    || bl.contains("aircraft")
                {
                    ev = ev.check("web_map_confirm", true, "ADS-B web map fingerprint");
                }
            }
        }
        findings.push(critical_finding(
            "avionics_adsb_attack",
            &format!("{} on {}:{}", kind, host, port),
            sev,
            "T0855",
            desc,
            target,
            score,
            ev,
        ));
    }

    if cfg.emit_agent_guidance() {
        let mut r = EngineResult::ok(findings, String::new());
        let mut g = agent_required_ok(
            "avionics_adsb_attack",
            target,
            "1090 MHz RF ADS-B spoofing/jamming and ACARS uplink injection require an SDR collector",
            "Over-the-air avionics signal injection is an RF action performed by an authorized SDR-equipped agent on-site.",
        );
        r.findings.append(&mut g.findings);
        r.message = format!(
            "avionics_adsb_attack: {} aviation finding(s) on {}",
            r.findings.len(),
            host
        );
        return r;
    }
    if findings.is_empty() {
        return empty_ok("avionics_adsb_attack", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("avionics_adsb_attack: {} finding(s) on {}", n, host),
    )
}

// ── Engine: maritime / AIS / NMEA / gpsd ────────────────────────────────────────

const MARITIME_PORTS: &[u16] = &[10110, 2947, 5631, 4001, 4002, 2000, 8040, 39150];

/// Real probe: AIS/NMEA over TCP (ECDIS/OpenCPN feeds) and gpsd JSON control socket.
pub async fn run_maritime_ais_attack_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let open = tcp_scan(
        &host,
        &cfg.ports_or("ports", MARITIME_PORTS),
        cfg.concurrency(),
    )
    .await;
    let mut findings = Vec::new();

    for &port in &open {
        let mut ev = Evidence::new()
            .with("host", host.clone())
            .with("port", port)
            .check("tcp_connect", true, "open");
        let (title, sev, score, mut desc): (&str, &str, f64, &str) = if port == 2947 {
            ("gpsd control socket exposed", "high", 0.7, "gpsd is reachable; ?WATCH/?POLL expose live GNSS position and the daemon is a manipulation surface for navigation data.")
        } else {
            ("AIS/NMEA feed exposed", "high", 0.7, "NMEA-0183/AIS feed reachable; AIS sentences can be observed and, on a writable feed, spoofed (ghost-vessel / collision-avoidance data integrity attack).")
        };
        let mut confirmed = false;
        if port == 2947 {
            if let Some(resp) =
                tcp_probe_response(&host, port, b"?WATCH={\"enable\":true,\"json\":true};\r\n")
                    .await
            {
                let s = String::from_utf8_lossy(&resp);
                if s.contains("\"class\"") || s.contains("VERSION") || s.contains("gpsd") {
                    confirmed = true;
                    ev = ev.raw_excerpt(&resp).check(
                        "gpsd_version",
                        true,
                        s.chars().take(120).collect::<String>(),
                    );
                }
            }
        } else if let Some(b) = tcp_banner(&host, port).await {
            if b.contains("!AIVDM")
                || b.contains("!AIVDO")
                || b.starts_with('$')
                || b.contains("GPGGA")
                || b.contains("GPRMC")
            {
                confirmed = true;
                desc = "Live AIS/NMEA sentences observed on an exposed feed (ECDIS/AIS aggregator). Writable feeds enable AIS spoofing.";
                ev = ev.raw_excerpt(b.as_bytes()).check(
                    "nmea_sentence",
                    true,
                    b.chars().take(120).collect::<String>(),
                );
            }
        }
        let final_score = if confirmed {
            (score + 0.15).min(0.92)
        } else {
            score - 0.2
        };
        findings.push(critical_finding(
            "maritime_ais_attack",
            &format!("{} on {}:{}", title, host, port),
            if confirmed { sev } else { "medium" },
            "T0855",
            desc,
            target,
            final_score,
            ev,
        ));
    }

    if cfg.emit_agent_guidance() {
        let mut r = EngineResult::ok(findings, String::new());
        let mut g = agent_required_ok(
            "maritime_ais_attack",
            target,
            "VHF AIS (161.975/162.025 MHz) over-the-air spoofing and GNSS spoofing require an SDR collector",
            "Radio-layer AIS/GNSS injection is performed by an authorized SDR-equipped agent in range of the vessel/port.",
        );
        r.findings.append(&mut g.findings);
        r.message = format!(
            "maritime_ais_attack: {} maritime finding(s) on {}",
            r.findings.len(),
            host
        );
        return r;
    }
    if findings.is_empty() {
        return empty_ok("maritime_ais_attack", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("maritime_ais_attack: {} finding(s) on {}", n, host),
    )
}

// ── Engine: EV charging / OCPP ─────────────────────────────────────────────────

const OCPP_PORTS: &[u16] = &[80, 8080, 8081, 8180, 9000, 9220, 8887];

fn ocpp_ws_handshake(host: &str, port: u16, path: &str, subprotocols: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {subprotocols}\r\nOrigin: https://weissman.probe\r\n\r\n"
    )
    .into_bytes()
}

/// Real probe: OCPP central-system WebSocket endpoints + SteVe management surface.
pub async fn run_ev_charging_ocpp_attack_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let open = tcp_scan(&host, &cfg.ports_or("ports", OCPP_PORTS), cfg.concurrency()).await;
    let subprotocols = cfg.string_or("ocpp_subprotocols", "ocpp2.0.1, ocpp1.6, ocpp1.5");
    let paths = cfg.string_list_or(
        "ocpp_paths",
        &[
            "/ocpp/CP_WEISSMAN",
            "/ocpp",
            "/steve/websocket/CentralSystemService/CP_WEISSMAN",
            "/CentralSystemService/CP_WEISSMAN",
            "/webServices/ocpp/CP_WEISSMAN",
            "/",
        ],
    );
    let mut findings = Vec::new();

    for &port in &open {
        let mut matched = false;
        for path in &paths {
            let req = ocpp_ws_handshake(&host, port, path, &subprotocols);
            if let Some(resp) = tcp_probe_response(&host, port, &req).await {
                let s = String::from_utf8_lossy(&resp).to_ascii_lowercase();
                let upgraded =
                    s.contains("101 switching protocols") && s.contains("upgrade: websocket");
                let ocpp_echo = s.contains("sec-websocket-protocol") && s.contains("ocpp");
                if upgraded {
                    let (sev, score, desc) = if ocpp_echo {
                        (
                            "critical",
                            0.92,
                            "OCPP Central System accepted an unauthenticated WebSocket upgrade and negotiated the `ocpp` subprotocol. An attacker can register/spoof a charge point, replay BootNotification/Authorize/MeterValues, commit energy theft and pivot to the charging backend.",
                        )
                    } else {
                        (
                            "high",
                            0.7,
                            "Unauthenticated WebSocket upgrade accepted on an EV-charging service port. Confirm whether OCPP is exposed without per-charge-point credentials.",
                        )
                    };
                    let ev = Evidence::new()
                        .with("host", host.clone())
                        .with("port", port)
                        .with("path", path.clone())
                        .with("negotiated_ocpp", ocpp_echo)
                        .raw_excerpt(&resp)
                        .check(
                            "ws_upgrade_101",
                            true,
                            "server returned 101 Switching Protocols",
                        )
                        .check(
                            "ocpp_subprotocol",
                            ocpp_echo,
                            "server echoed an ocpp subprotocol",
                        );
                    findings.push(critical_finding(
                        "ev_charging_ocpp_attack",
                        &format!(
                            "OCPP/WebSocket central system reachable on {}:{}{}",
                            host, port, path
                        ),
                        sev,
                        "T0886",
                        desc,
                        target,
                        score,
                        ev,
                    ));
                    matched = true;
                    break;
                }
            }
        }
        // SteVe management UI fingerprint.
        if !matched && matches!(port, 80 | 8080 | 8180) {
            let client = http_client().await;
            if let Some(r) = http_get(
                &client,
                &format!("http://{}:{}/steve/manager/home", host, port),
            )
            .await
            {
                let bl = r.body.to_ascii_lowercase();
                if bl.contains("steve") || bl.contains("ocpp") {
                    findings.push(critical_finding(
                        "ev_charging_ocpp_attack",
                        &format!("SteVe OCPP management UI on {}:{}", host, port),
                        "high",
                        "T0886",
                        "SteVe open-source OCPP server management UI exposed. Verify authentication; the manager controls charge points and transactions.",
                        target,
                        0.65,
                        Evidence::new().with("host", host.clone()).with("port", port).check("steve_ui", true, "SteVe fingerprint"),
                    ));
                }
            }
        }
    }

    if findings.is_empty() {
        return empty_ok("ev_charging_ocpp_attack", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("ev_charging_ocpp_attack: {} finding(s) on {}", n, host),
    )
}

// ── Engine: smart grid / IEC 60870-5-104 / DLMS-COSEM ──────────────────────────

/// Real probe: IEC-104 STARTDT handshake + DLMS/COSEM reachability.
pub async fn run_smart_grid_dlms_attack_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let mut findings = Vec::new();

    let iec104_port = cfg.u64_or("iec104_port", 2404) as u16;
    if cfg.bool_or("check_iec104", true) {
        if let Some(resp) = tcp_probe_response(&host, iec104_port, &iec104_startdt_act()).await {
            let confirmed = resp.first() == Some(&0x68);
            let startdt_con = resp.len() >= 3 && resp[0] == 0x68 && (resp[2] & 0x0b) == 0x0b;
            let ev = Evidence::new()
                .with("host", host.clone())
                .with("port", iec104_port)
                .raw_excerpt(&resp)
                .check("iec104_apci", confirmed, "0x68 APCI start byte observed")
                .check(
                    "startdt_confirmation",
                    startdt_con,
                    "STARTDT_CON control field",
                );
            if confirmed {
                findings.push(critical_finding(
                    "smart_grid_dlms_attack",
                    &format!("IEC 60870-5-104 RTU/controller reachable on {}:{}", host, iec104_port),
                    "critical",
                    "T0855",
                    "IEC-104 telecontrol endpoint answered a STARTDT activation. The protocol is unauthenticated — once data transfer is started an attacker can read measurements and issue control commands (breaker open/close) to grid equipment. Isolate behind an OT firewall + VPN.",
                    target,
                    0.9,
                    ev,
                ));
            }
        } else if tcp_open(&host, iec104_port).await {
            findings.push(critical_finding(
                "smart_grid_dlms_attack",
                &format!("IEC-104 port {}:{} open (handshake unconfirmed)", host, iec104_port),
                "high",
                "T0855",
                "Port 2404 open but STARTDT was not confirmed. Treat as a probable telecontrol endpoint and isolate.",
                target,
                0.55,
                Evidence::new().with("host", host.clone()).with("port", iec104_port).check("tcp_connect", true, "open"),
            ));
        }
    }

    let dlms_port = cfg.u64_or("dlms_port", 4059) as u16;
    if cfg.bool_or("check_dlms", true) && tcp_open(&host, dlms_port).await {
        findings.push(critical_finding(
            "smart_grid_dlms_attack",
            &format!("DLMS/COSEM smart-meter port reachable on {}:{}", host, dlms_port),
            "high",
            "T0855",
            "DLMS/COSEM (IEC 62056) endpoint reachable. Low-level security (LLS) meters use static passwords; exposure enables meter reads, demand manipulation and remote disconnect. Require HLS-GMAC and network isolation.",
            target,
            0.65,
            Evidence::new().with("host", host.clone()).with("port", dlms_port).check("tcp_connect", true, "open"),
        ));
    }

    if findings.is_empty() {
        return empty_ok("smart_grid_dlms_attack", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("smart_grid_dlms_attack: {} finding(s) on {}", n, host),
    )
}

// ── Engine: railway signalling ─────────────────────────────────────────────────

const RAIL_PORTS: &[u16] = &[2404, 502, 102, 20000, 4840, 789, 80, 443];

/// Real probe: OT/telecontrol protocols on rail signalling networks (IEC-104, Modbus, IEC-61850
/// MMS, DNP3, OPC-UA, CrimsonV3) + signalling HMI web fingerprints.
pub async fn run_rail_signaling_attack_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let open = tcp_scan(&host, &cfg.ports_or("ports", RAIL_PORTS), cfg.concurrency()).await;
    let mut findings = Vec::new();

    for &port in &open {
        let (proto, score, desc) = match port {
            2404 => ("IEC 60870-5-104 telecontrol", 0.85, "Telecontrol protocol used in rail SCADA/interlocking back-ends; unauthenticated control surface."),
            502 => ("Modbus/TCP", 0.7, "Modbus used in trackside SCADA / level-crossing controllers; unauthenticated read/write."),
            102 => ("IEC-61850 MMS / S7", 0.7, "MMS/S7comm controller surface in signalling power & interlocking systems."),
            20000 => ("DNP3", 0.7, "DNP3 telecontrol surface in rail electrification/SCADA."),
            4840 => ("OPC-UA", 0.6, "OPC-UA server in modern signalling integration layer."),
            789 => ("Crimson V3 (Red Lion)", 0.6, "Red Lion HMI/RTU protocol common in transport SCADA."),
            _ => ("Signalling HMI web", 0.45, "Web management surface for a signalling/SCADA component."),
        };
        let mut ev = Evidence::new()
            .with("host", host.clone())
            .with("port", port)
            .with("protocol", proto)
            .check("tcp_connect", true, "open");
        if port == 2404 {
            if let Some(resp) = tcp_probe_response(&host, port, &iec104_startdt_act()).await {
                if resp.first() == Some(&0x68) {
                    ev = ev
                        .raw_excerpt(&resp)
                        .check("iec104_startdt", true, "STARTDT response");
                }
            }
        }
        findings.push(critical_finding(
            "rail_signaling_attack",
            &format!("{} reachable on rail network {}:{}", proto, host, port),
            crate::arsenal_config::severity_for_score(score),
            "T0855",
            desc,
            target,
            score,
            ev,
        ));
    }

    if cfg.emit_agent_guidance() {
        let mut r = EngineResult::ok(findings, String::new());
        let mut g = agent_required_ok(
            "rail_signaling_attack",
            target,
            "ETCS/ERTMS EURORADIO (GSM-R), CBTC trackside radio and balise (Eurobalise) tests require an on-site RF/segment collector",
            "Rail radio-block and balise signalling are RF/on-track actions performed by an authorized on-site collector.",
        );
        r.findings.append(&mut g.findings);
        r.message = format!(
            "rail_signaling_attack: {} finding(s) on {}",
            r.findings.len(),
            host
        );
        return r;
    }
    if findings.is_empty() {
        return empty_ok("rail_signaling_attack", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("rail_signaling_attack: {} finding(s) on {}", n, host),
    )
}

// ── Engine: building automation (KNX / Niagara Fox / LonWorks) ─────────────────

/// Real probe: KNXnet/IP SEARCH_REQUEST, Tridium Niagara Fox banner, LonWorks/IP.
pub async fn run_building_automation_attack_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let mut findings = Vec::new();

    // KNXnet/IP (UDP 3671).
    let knx_port = cfg.u64_or("knx_port", 3671) as u16;
    if cfg.bool_or("check_knx", true) {
        if let Some(resp) = udp_probe_response(&host, knx_port, &knxnet_search_request()).await {
            let is_knx = resp.len() >= 4 && resp[0] == 0x06 && resp[1] == 0x10;
            let is_search_resp = resp.len() >= 4 && resp[2] == 0x02 && resp[3] == 0x02;
            if is_knx {
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("udp_port", knx_port)
                    .raw_excerpt(&resp)
                    .check("knxnet_header", true, "0x0610 KNXnet/IP header")
                    .check("search_response", is_search_resp, "SEARCH_RESPONSE service");
                findings.push(critical_finding(
                    "building_automation_attack",
                    &format!("KNXnet/IP building controller reachable on {}:{}", host, knx_port),
                    "high",
                    "T0855",
                    "KNXnet/IP router answered a SEARCH_REQUEST. KNX has no authentication — an attacker on the network can drive HVAC, lighting, blinds, access control and energy systems. Place behind a KNX Secure router / VLAN isolation.",
                    target,
                    0.8,
                    ev,
                ));
            }
        }
    }

    // Tridium Niagara Fox (TCP 1911/4911) + LonWorks (TCP 1628/1629).
    let fox_ports = cfg.ports_or("fox_ports", &[1911, 4911]);
    let open = tcp_scan(
        &host,
        &[fox_ports.clone(), vec![1628, 1629, 47808]].concat(),
        cfg.concurrency(),
    )
    .await;
    for &port in &open {
        if fox_ports.contains(&port) {
            if let Some(b) = tcp_banner(&host, port).await {
                if b.to_ascii_lowercase().contains("fox") {
                    findings.push(critical_finding(
                        "building_automation_attack",
                        &format!("Tridium Niagara Fox on {}:{}", host, port),
                        "high",
                        "T0855",
                        "Niagara Fox protocol exposed. Fox leaks station/version and is associated with default-credential and BlueFrost/Niagara CVE exploitation of building-management JACE controllers.",
                        target,
                        0.75,
                        Evidence::new().with("host", host.clone()).with("port", port).raw_excerpt(b.as_bytes()).check("fox_banner", true, b.chars().take(80).collect::<String>()),
                    ));
                }
            }
        } else if matches!(port, 1628 | 1629) {
            findings.push(critical_finding(
                "building_automation_attack",
                &format!("LonWorks/IP (LonTalk) reachable on {}:{}", host, port),
                "medium",
                "T0855",
                "LonWorks/IP building bus reachable; legacy LonTalk has no authentication.",
                target,
                0.5,
                Evidence::new()
                    .with("host", host.clone())
                    .with("port", port)
                    .check("tcp_connect", true, "open"),
            ));
        }
    }

    if findings.is_empty() {
        return empty_ok("building_automation_attack", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("building_automation_attack: {} finding(s) on {}", n, host),
    )
}

// ── Engine: robotics / ROS / Universal Robots ──────────────────────────────────

/// Real probe: ROS1 master XML-RPC `getSystemState` (unauth full takeover surface) + Universal
/// Robots dashboard/interface ports + ROS2 DDS discovery range.
pub async fn run_robotics_ros2_attack_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let mut findings = Vec::new();

    // ROS1 master (XML-RPC 11311).
    let ros_port = cfg.u64_or("ros_master_port", 11311) as u16;
    if cfg.bool_or("check_ros1", true) && tcp_open(&host, ros_port).await {
        let client = http_client().await;
        let xml = "<?xml version=\"1.0\"?><methodCall><methodName>getSystemState</methodName><params><param><value>/weissman_probe</value></param></params></methodCall>";
        let url = format!("http://{}:{}/", host, ros_port);
        if let Ok(resp) = client
            .post(&url)
            .header("Content-Type", "text/xml")
            .body(xml)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let body = match resp.text().await {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(
                        target: "robotics_ros2_attack",
                        host = %host,
                        port = ros_port,
                        error = %e,
                        "ROS XML-RPC body read failed"
                    );
                    String::new()
                }
            };
            if body.contains("methodResponse") {
                let ev = Evidence::new()
                    .with("host", host.clone())
                    .with("port", ros_port)
                    .with("status", status)
                    .raw_excerpt(body.as_bytes())
                    .check(
                        "ros_xmlrpc_getsystemstate",
                        true,
                        "ROS master returned methodResponse",
                    );
                findings.push(critical_finding(
                    "robotics_ros2_attack",
                    &format!("Unauthenticated ROS master on {}:{}", host, ros_port),
                    "critical",
                    "T0855",
                    "ROS1 master answered getSystemState without authentication. An attacker can enumerate every node/topic/service, publish to actuator topics and hijack the robot (ROS has no built-in auth). Firewall 11311 and migrate to ROS2 + SROS2 security.",
                    target,
                    0.9,
                    ev,
                ));
            }
        }
    }

    // Universal Robots dashboard (29999) + interfaces (30001-30003).
    let ur_ports = cfg.ports_or("ur_ports", &[29999, 30001, 30002, 30003]);
    let open = tcp_scan(&host, &ur_ports, cfg.concurrency()).await;
    for &port in &open {
        if port == 29999 {
            if let Some(b) = tcp_banner(&host, port).await {
                if b.to_ascii_lowercase().contains("universal robots")
                    || b.to_ascii_lowercase().contains("dashboard")
                {
                    findings.push(critical_finding(
                        "robotics_ros2_attack",
                        &format!("Universal Robots dashboard on {}:{}", host, port),
                        "critical",
                        "T0855",
                        "UR Dashboard Server reachable unauthenticated — supports power on/off, brake release, load & play program. Direct physical-safety control of the robot arm. Isolate the controller network.",
                        target,
                        0.88,
                        Evidence::new().with("host", host.clone()).with("port", port).raw_excerpt(b.as_bytes()).check("ur_dashboard", true, b.chars().take(80).collect::<String>()),
                    ));
                }
            }
        } else {
            findings.push(critical_finding(
                "robotics_ros2_attack",
                &format!("Universal Robots interface port {}:{} open", host, port),
                "high",
                "T0855",
                "UR primary/secondary/realtime interface reachable; accepts URScript commands that move the arm. Restrict to the controller VLAN.",
                target,
                0.65,
                Evidence::new().with("host", host.clone()).with("port", port).check("tcp_connect", true, "open"),
            ));
        }
    }

    // ROS2 DDS / RTPS discovery (UDP 7400-7410) — best-effort liveness.
    if cfg.bool_or("check_ros2_dds", true) {
        let dds_port = cfg.u64_or("dds_discovery_port", 7400) as u16;
        // RTPS minimal header: "RTPS" + protocol version 2.3 + vendor + guid prefix.
        let mut rtps = b"RTPS".to_vec();
        rtps.extend_from_slice(&[0x02, 0x03, 0x01, 0x0f]);
        rtps.extend_from_slice(&[0u8; 12]);
        if let Some(resp) = udp_probe_response(&host, dds_port, &rtps).await {
            if resp.starts_with(b"RTPS") {
                findings.push(critical_finding(
                    "robotics_ros2_attack",
                    &format!("ROS2 DDS/RTPS participant on {}:{}", host, dds_port),
                    "high",
                    "T0855",
                    "DDS/RTPS discovery responded. Without SROS2/DDS-Security an attacker can join the data space and publish to robot topics.",
                    target,
                    0.7,
                    Evidence::new().with("host", host.clone()).with("udp_port", dds_port).raw_excerpt(&resp).check("rtps_reply", true, "RTPS magic in response"),
                ));
            }
        }
    }

    if findings.is_empty() {
        return empty_ok("robotics_ros2_attack", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("robotics_ros2_attack: {} finding(s) on {}", n, host),
    )
}

// ── Engine: OT Safety-Instrumented-Systems (Triconex / TRITON-class) ───────────

/// Real probe: Triconex TriStation (UDP/TCP 1502) and SIS controller reachability. TriStation is
/// the protocol TRITON/TRISIS abused; reachability of a safety controller is a life-safety finding.
pub async fn run_ot_sis_triton_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let mut findings = Vec::new();

    let tristation_port = cfg.u64_or("tristation_port", 1502) as u16;
    // TriStation runs over UDP 1502; a benign probe + reachability check.
    let mut observed = false;
    let mut ev = Evidence::new()
        .with("host", host.clone())
        .with("port", tristation_port)
        .with("protocol", "TriStation/TSAA");
    if let Some(resp) = udp_probe_response(
        &host,
        tristation_port,
        &[0x00, 0x00, 0x00, 0x00, 0x05, 0x00],
    )
    .await
    {
        observed = true;
        ev = ev
            .raw_excerpt(&resp)
            .check("tristation_udp_reply", true, "UDP 1502 responded");
    } else if tcp_open(&host, tristation_port).await {
        observed = true;
        ev = ev.check("tristation_tcp_open", true, "TCP 1502 open");
    }
    if observed {
        findings.push(critical_finding(
            "ot_sis_triton_attack",
            &format!("Triconex/TriStation Safety-Instrumented-System reachable on {}:{}", host, tristation_port),
            "critical",
            "T0853",
            "A Triconex TriStation (TSAA) safety controller is network-reachable — the exact exposure TRITON/TRISIS abused to reprogram safety logic. Reaching a SIS from the control or IT network is a life-safety risk. Enforce an isolated SIS network, keypad in RUN/PROGRAM control, and IEC 61511 separation.",
            target,
            0.92,
            ev,
        ));
    }

    // Other SIS web/management surfaces (HIMA, Yokogawa ProSafe, Schneider).
    let other = tcp_scan(
        &host,
        &cfg.ports_or("sis_ports", &[502, 80, 443, 1500, 6000]),
        cfg.concurrency(),
    )
    .await;
    for &port in &other {
        if port == 502 {
            findings.push(critical_finding(
                "ot_sis_triton_attack",
                &format!("Modbus reachable alongside SIS on {}:{}", host, port),
                "high",
                "T0853",
                "Modbus reachable on a segment that also exposes a safety controller — verify the SIS is not addressable from this path.",
                target,
                0.6,
                Evidence::new().with("host", host.clone()).with("port", port).check("tcp_connect", true, "open"),
            ));
        }
    }

    if cfg.emit_agent_guidance() && !findings.is_empty() {
        let mut r = EngineResult::ok(findings, String::new());
        let mut g = agent_required_ok(
            "ot_sis_triton_attack",
            target,
            "Authorized SIS logic-integrity validation must run from an on-segment OT collector under change control",
            "Reading/validating safety-controller program state is an intrusive OT action performed by an authorized on-segment agent under IEC 61511 change control.",
        );
        r.findings.append(&mut g.findings);
        r.message = format!(
            "ot_sis_triton_attack: {} SIS finding(s) on {}",
            r.findings.len(),
            host
        );
        return r;
    }
    if findings.is_empty() {
        return empty_ok("ot_sis_triton_attack", target);
    }
    let n = findings.len();
    EngineResult::ok(
        findings,
        format!("ot_sis_triton_attack: {} finding(s) on {}", n, host),
    )
}
