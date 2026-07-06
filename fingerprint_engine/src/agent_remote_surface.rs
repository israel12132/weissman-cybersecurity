//! Remote attack-surface probes for engines that also require an endpoint agent for
//! host-resident validation. Every helper performs **live** network/DNS/HTTP/TCP
//! operations against the user-supplied target — never simulated findings.
//!
//! These run *before* agent dispatch so operators get evidence-backed perimeter
//! signals even when no agent is enrolled.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    dns_a, dns_txt, empty_ok, extract_host, finding_with_probe_depth, fingerprint_stack,
    has_header, header_value, http_client, http_get, http_get_with_headers, join_url,
    normalize_url, probe_matched_token, probe_paths_concurrent, status_indicates_presence,
    tcp_banner, tcp_open, tcp_scan, udp_probe_response, DEFAULT_PROBE_CONCURRENCY,
};
use crate::engine_result::EngineResult;
use serde_json::{json, Value};

const REMOTE_DEPTH: &str = "agent_hybrid_remote_surface";

fn remote_finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
) -> Value {
    let mut f = finding_with_probe_depth(
        engine_id,
        title,
        severity,
        mitre,
        description,
        target,
        REMOTE_DEPTH,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("remote_surface".to_string(), json!(true));
        obj.insert("agent_validation_recommended".to_string(), json!(true));
    }
    f
}

fn collect(engine_id: &str, target: &str, findings: Vec<Value>) -> EngineResult {
    if findings.is_empty() {
        empty_ok(engine_id, target)
    } else {
        let count = findings.len();
        EngineResult::ok(
            findings,
            format!(
                "{}: {} remote surface finding(s) — enroll endpoint agent for host-resident validation",
                engine_id,
                count
            ),
        )
    }
}

/// Run the remote-surface probe for an agent-required engine id.
pub async fn run_remote_surface_probe(
    engine_id: &str,
    target: &str,
    _ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    match engine_id {
        "process_hollowing" => probe_process_injection_surface(engine_id, target).await,
        "dll_hijacking_engine" => probe_dll_hijack_surface(engine_id, target).await,
        "process_inventory" => probe_process_inventory_surface(engine_id, target).await,
        "av_bypass_engine" => probe_edr_av_surface(engine_id, target).await,
        "log_tampering_engine" => probe_log_tampering_surface(engine_id, target).await,
        "timestomping" => probe_timestomping_surface(engine_id, target).await,
        "anti_debug_evasion" => probe_anti_debug_surface(engine_id, target).await,
        "rootkit_surface_probe" | "rootkit_simulation" => probe_rootkit_surface(engine_id, target).await,
        "memory_forensics_evasion" => probe_memory_forensics_surface(engine_id, target).await,
        "usb_enumeration" => probe_usb_policy_surface(engine_id, target).await,
        "dns_tunneling_c2" => probe_dns_tunneling_surface(engine_id, target).await,
        "icmp_covert" => probe_icmp_covert_surface(engine_id, target).await,
        "bootkit_uefi" => probe_bootkit_surface(engine_id, target).await,
        "persistence_mechanism" => probe_persistence_surface(engine_id, target).await,
        "polymorphic_engine" => probe_polymorphic_surface(engine_id, target).await,
        "ransomware_emulation" => probe_ransomware_surface(engine_id, target).await,
        "acoustic_exfil" => probe_acoustic_exfil_surface(engine_id, target).await,
        "em_exfil_engine" => probe_em_exfil_surface(engine_id, target).await,
        "optical_exfil" => probe_optical_exfil_surface(engine_id, target).await,
        "keyboard_acoustic" => probe_keyboard_acoustic_surface(engine_id, target).await,
        "screen_capture_exfil" => probe_screen_capture_surface(engine_id, target).await,
        "clipboard_hijack" => probe_clipboard_surface(engine_id, target).await,
        "insider_exfil" => probe_insider_exfil_surface(engine_id, target).await,
        "storage_covert_channel" => probe_storage_covert_surface(engine_id, target).await,
        "arp_spoofing_engine" => probe_arp_spoofing_surface(engine_id, target).await,
        "vlan_hopping_attack" => probe_vlan_hopping_surface(engine_id, target).await,
        "dhcp_attack_engine" => probe_dhcp_surface(engine_id, target).await,
        "wifi_attack_engine" => probe_wifi_surface(engine_id, target).await,
        "bluetooth_attack_engine" => probe_bluetooth_surface(engine_id, target).await,
        "lte_5g_attack" => probe_lte_5g_surface(engine_id, target).await,
        "wpa3_attack_engine" => probe_wpa3_surface(engine_id, target).await,
        "packet_injection_engine" => probe_packet_injection_surface(engine_id, target).await,
        "network_tap_advanced" => probe_network_tap_surface(engine_id, target).await,
        "multicast_attack" => probe_multicast_surface(engine_id, target).await,
        "nat_traversal_attack" => probe_nat_traversal_surface(engine_id, target).await,
        "sim_swap_engine" => probe_sim_swap_surface(engine_id, target).await,
        "bluetooth_mobile_attack" => probe_bluetooth_mobile_surface(engine_id, target).await,
        "nfc_relay_attack" => probe_nfc_surface(engine_id, target).await,
        "deepfake_voice_engine" => probe_deepfake_voice_surface(engine_id, target).await,
        "pretexting_engine" => probe_pretexting_surface(engine_id, target).await,
        "insider_threat_engine" => probe_insider_threat_surface(engine_id, target).await,
        "physical_social_eng" => probe_physical_social_surface(engine_id, target).await,
        "lorawan_attack" | "lora_attack" => probe_lorawan_surface(engine_id, target).await,
        "voltage_glitch_attack" => probe_voltage_glitch_surface(engine_id, target).await,
        "tpm_firmware_attack" => probe_tpm_surface(engine_id, target).await,
        "cold_boot_attack" => probe_cold_boot_surface(engine_id, target).await,
        "infostealer_emulation" => probe_infostealer_surface(engine_id, target).await,
        other => empty_ok(other, target),
    }
}

// ── Stealth / EDR ─────────────────────────────────────────────────────────────

async fn probe_process_injection_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/api/debug/pid",
        "/api/process",
        "/debug/pprof",
        "/actuator/env",
        "/.env",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if !status_indicates_presence(p.status) {
            continue;
        }
        let body = p.body.to_ascii_lowercase();
        if body.contains("process") || body.contains("pid") || body.contains("runtime") {
            findings.push(remote_finding(
                engine_id,
                "Process/runtime introspection endpoint exposed",
                "high",
                "T1055",
                &format!(
                    "{} returned {} — process injection tradecraft often targets exposed runtime/debug interfaces.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    let open = tcp_scan(&host, &[445, 5985, 5986, 135], 8).await;
    if open.contains(&445) {
        findings.push(remote_finding(
            engine_id,
            "SMB (445) reachable — lateral/process injection pivot surface",
            "medium",
            "T1055",
            &format!("Host {} accepts TCP/445 — review lateral movement and process injection blast radius.", host),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

async fn probe_dll_hijack_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/downloads/",
        "/update/",
        "/plugins/",
        "/libs/",
        "/static/js/",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if p.status == 200 && (p.body.contains(".dll") || p.body.contains(".so")) {
            findings.push(remote_finding(
                engine_id,
                "Native library artifacts exposed over HTTP",
                "medium",
                "T1574.001",
                &format!(
                    "{} lists loadable library paths — DLL search-order hijacking depends on writable/load paths on endpoints.",
                    p.final_url
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_process_inventory_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/metrics",
        "/api/v1/targets",
        "/prometheus/metrics",
        "/debug/vars",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if p.status == 200 && p.body.contains("process_") {
            findings.push(remote_finding(
                engine_id,
                "Process metrics exposed (Prometheus/debug)",
                "medium",
                "T1057",
                &format!(
                    "{} exposes process_* metrics — baseline process inventory is available remotely; agent confirms host truth.",
                    p.final_url
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_edr_av_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let fp = fingerprint_stack(&p);
        let blob = format!(
            "{:?} {} {}",
            fp.server,
            fp.powered_by.as_deref().unwrap_or(""),
            headers_blob(&p)
        )
        .to_ascii_lowercase();
        for sig in [
            "crowdstrike",
            "sentinelone",
            "carbonblack",
            "cylance",
            "defender",
            "x-protected-by",
        ] {
            if blob.contains(sig) {
                findings.push(remote_finding(
                    engine_id,
                    &format!("Perimeter EDR/WAF signal: {}", sig),
                    "info",
                    "T1562.001",
                    &format!(
                        "Response from {} includes '{}' — AV/EDR bypass tradecraft targets this stack; agent validates host-resident controls.",
                        p.final_url, sig
                    ),
                    target,
                ));
                break;
            }
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_log_tampering_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/logs",
        "/kibana",
        "/elastic/",
        "/_search",
        "/api/logs",
        "/graylog/",
        "/splunk/",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            let tok = probe_matched_token(
                &p,
                &[
                    "kibana",
                    "elasticsearch",
                    "graylog",
                    "splunk",
                    "logstash",
                    "opensearch",
                ],
            );
            if tok.is_some() || p.status == 200 {
                findings.push(remote_finding(
                    engine_id,
                    "Centralized log platform reachable",
                    "high",
                    "T1070",
                    &format!(
                        "{} ({}) — log tampering detection requires agent-side integrity monitoring on endpoints feeding this platform.",
                        p.final_url, p.status
                    ),
                    target,
                ));
                break;
            }
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_timestomping_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/.git/HEAD",
        "/backup.zip",
        "/backup.tar.gz",
        "/db.sql.bak",
        "/archive.zip",
        "/old/",
        "/.bak",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if !status_indicates_presence(p.status) {
            continue;
        }
        let lm = p
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("last-modified"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        findings.push(remote_finding(
            engine_id,
            "Backup or VCS artifact exposed (timestamp surface)",
            if p.final_url.contains(".git") {
                "high"
            } else {
                "medium"
            },
            "T1070.006",
            &format!(
                "{} ({}){} — timestomping tradecraft alters MAC times on disk; exposed archives and .git leak filesystem timeline anchors for agent validation.",
                p.final_url,
                p.status,
                if lm.is_empty() {
                    String::new()
                } else {
                    format!(" Last-Modified: {lm}")
                }
            ),
            target,
        ));
        if findings.len() >= 3 {
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_anti_debug_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &["/api/debug", "/debug", "/__debug__", "/api/dev"];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Debug/dev API exposed in production",
                "medium",
                "T1622",
                &format!(
                    "{} is reachable — anti-debug and dev-mode endpoints often coexist; agent validates debugger detection on host.",
                    p.final_url
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_rootkit_surface(engine_id: &str, target: &str) -> EngineResult {
    probe_edr_av_surface(engine_id, target).await
}

async fn probe_memory_forensics_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    if tcp_open(&host, 22).await {
        if let Some(banner) = tcp_banner(&host, 22).await {
            let b = banner.to_ascii_lowercase();
            if b.contains("linux") {
                findings.push(remote_finding(
                    engine_id,
                    "SSH exposed on Linux host (memory forensics relevance)",
                    "low",
                    "T1003",
                    &format!(
                        "SSH banner on {}:{} — memory forensics evasion is host-resident; agent collects live kernel module/process integrity.",
                        host, 22
                    ),
                    target,
                ));
            }
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_usb_policy_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/policy/usb",
        "/mdm/policy",
        "/intune/",
        "/api/device/compliance",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Device/USB policy portal exposed",
                "medium",
                "T1091",
                &format!(
                    "{} ({}) — USB enumeration requires host agent; exposed MDM/policy UI indicates device-control surface.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_dns_tunneling_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let txts = dns_txt(&host).await;
    let mut findings = Vec::new();
    for r in &txts {
        if r.len() > 180 {
            findings.push(remote_finding(
                engine_id,
                "Unusually long TXT record (possible DNS tunnel exfil)",
                "medium",
                "T1071.004",
                &format!(
                    "TXT on {} is {} chars — high-entropy long TXT records can carry C2 payloads; agent validates local resolver behavior.",
                    host,
                    r.len()
                ),
                target,
            ));
        }
        let lower = r.to_ascii_lowercase();
        for sig in ["base64", "tunnel", "c2", "beacon"] {
            if lower.contains(sig) {
                findings.push(remote_finding(
                    engine_id,
                    &format!("Suspicious TXT token: {}", sig),
                    "medium",
                    "T1071.004",
                    &format!(
                        "TXT record on {} contains '{}' — review for DNS tunneling indicators.",
                        host, sig
                    ),
                    target,
                ));
                break;
            }
        }
    }
    // Subdomain entropy probe (common tunnel pattern)
    for label in ["data", "tunnel", "exfil", "c2", "dnscat"] {
        let sub = format!("{label}.{host}");
        if !dns_a(&sub).await.is_empty() {
            findings.push(remote_finding(
                engine_id,
                &format!("Suspicious subdomain resolves: {}", sub),
                "high",
                "T1071.004",
                &format!(
                    "{} has A records — label '{}' is commonly used for DNS tunnel endpoints.",
                    sub, label
                ),
                target,
            ));
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_icmp_covert_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    // ICMP reachability via ping is OS-dependent; TCP fallback signals flat perimeter
    if tcp_open(&host, 443).await || tcp_open(&host, 80).await {
        findings.push(remote_finding(
            engine_id,
            "Host reachable — ICMP covert channels require L3 path validation",
            "info",
            "T1095",
            &format!(
                "Host {} accepts TCP — ICMP covert exfil cannot be confirmed remotely; agent performs local ICMP capability test.",
                host
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

async fn probe_bootkit_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/api/attestation",
        "/.well-known/openid-configuration",
        "/secureboot",
        "/tpm",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Firmware/attestation endpoint exposed",
                "medium",
                "T1542.001",
                &format!(
                    "{} ({}) — UEFI/bootkit detection requires TPM/SecureBoot attestation from the host agent.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_persistence_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/cron",
        "/api/cron",
        "/api/scheduled",
        "/actuator/scheduledtasks",
        "/api/v1/namespaces/kube-system/pods",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Scheduler/persistence management surface exposed",
                "high",
                "T1547",
                &format!(
                    "{} ({}) — persistence mechanisms (cron, scheduled tasks, K8s) are manageable remotely; agent audits autoruns/registry.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_polymorphic_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if let Some(ct) = header_value(&p.headers, "content-type") {
            if ct.contains("application/octet-stream") || ct.contains("application/x-msdownload") {
                findings.push(remote_finding(
                    engine_id,
                    "Binary download served without integrity attestation",
                    "medium",
                    "T1027",
                    &format!(
                        "{} serves {} — polymorphic payloads often ship as mutable binaries; verify code signing and agent-side entropy monitoring.",
                        p.final_url, ct
                    ),
                    target,
                ));
            }
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_ransomware_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/backup",
        "/veeam/",
        "/api/backup",
        "/commvault/",
        "/rubrik/",
        "/v1/snapshot",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Backup/snapshot interface exposed",
                "high",
                "T1486",
                &format!(
                    "{} ({}) — ransomware tradecraft targets backup interfaces; agent validates VSS/shadow-copy protection locally.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    let open = tcp_scan(&host, &[445, 2049, 873], 6).await;
    if !open.is_empty() {
        findings.push(remote_finding(
            engine_id,
            &format!("File-share ports open: {:?}", open),
            "medium",
            "T1486",
            &format!(
                "Host {} exposes {:?} — ransomware staging often abuses open file services.",
                host, open
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

// ── Data exfiltration (physical channels — remote surface only) ─────────────────

async fn probe_acoustic_exfil_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &["/api/tts", "/v1/audio/speech", "/speech", "/voice"];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Speech/audio generation API exposed",
                "low",
                "T1048",
                &format!(
                    "{} ({}) — acoustic exfil requires host microphone access; exposed TTS/audio APIs indicate audio subsystem in scope.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_em_exfil_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/emc-compliance",
        "/docs/emc",
        "/shielding",
        "/rf-lab",
        "/api/spectrum",
        "/api/emc",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if !status_indicates_presence(p.status) {
            continue;
        }
        let body = p.body.to_ascii_lowercase();
        if body.contains("emc")
            || body.contains("tempest")
            || body.contains("shield")
            || body.contains("spectrum")
            || body.contains("faraday")
        {
            findings.push(remote_finding(
                engine_id,
                "EMC/TEMPEST documentation or RF lab surface exposed",
                "low",
                "T1048",
                &format!(
                    "{} ({}) — EM side-channel exfil requires physical proximity; exposed EMC/RF policy pages indicate RF-sensitive facilities in scope for agent validation.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_optical_exfil_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &["/api/camera", "/stream", "/webcam", "/video"];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Camera/video stream endpoint exposed",
                "medium",
                "T1052",
                &format!(
                    "{} ({}) — optical exfil uses cameras/displays; agent validates local capture devices.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_keyboard_acoustic_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/api/dictation",
        "/api/speech",
        "/webrtc",
        "/api/voice",
        "/api/transcribe",
        "/ws/audio",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Voice/dictation/WebRTC endpoint exposed",
                "medium",
                "T1056.001",
                &format!(
                    "{} ({}) — acoustic keyboard side-channels correlate with exposed audio capture APIs; agent validates local microphone hooks.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_screen_capture_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    let vnc_ports = tcp_scan(&host, &[5900, 5901, 5902, 5800, 3389], 8).await;
    for port in vnc_ports {
        let svc = if port == 3389 { "RDP" } else { "VNC" };
        findings.push(remote_finding(
            engine_id,
            &format!("{} port {} open — remote desktop surface", svc, port),
            "high",
            "T1113",
            &format!(
                "Host {} accepts TCP/{} — screen capture exfil often abuses RDP/VNC; agent validates local session hooks.",
                host, port
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

async fn probe_clipboard_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/api/clipboard",
        "/api/paste",
        "/clipboard",
        "/api/share",
        "/api/copy",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Clipboard/share API endpoint exposed",
                "high",
                "T1115",
                &format!(
                    "{} ({}) — clipboard hijacking requires host hook; exposed clipboard/share APIs widen blast radius.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_insider_exfil_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/api/export",
        "/api/download",
        "/api/bulk",
        "/graphql",
        "/api/v1/users/export",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Bulk export/download endpoint exposed",
                "high",
                "T1048",
                &format!(
                    "{} ({}) — insider exfil often abuses bulk export APIs; agent monitors endpoint data staging.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_storage_covert_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    let cloud_hints = dns_txt(&host).await;
    for r in cloud_hints {
        let lower = r.to_ascii_lowercase();
        if lower.contains("google-site-verification") {
            continue;
        }
        if lower.contains("amazonses") || lower.contains("_amazonses") {
            findings.push(remote_finding(
                engine_id,
                "AWS SES DNS hint — cloud storage exfil path",
                "low",
                "T1567",
                &format!("TXT on {} references AWS mail/storage — review cross-account exfil via cloud APIs.", host),
                target,
            ));
        }
    }
    let open = tcp_scan(&host, &[9000, 9001, 445, 2049], 6).await;
    if open.contains(&9000) || open.contains(&9001) {
        findings.push(remote_finding(
            engine_id,
            "MinIO/S3-compatible port exposed",
            "high",
            "T1567",
            &format!(
                "Host {} exposes {:?} — object storage covert channels often target S3/MinIO.",
                host, open
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

// ── Network / wireless ────────────────────────────────────────────────────────

async fn probe_arp_spoofing_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    let mgmt = tcp_scan(&host, &[161, 4786, 830, 23], 6).await;
    if mgmt.contains(&161) {
        findings.push(remote_finding(
            engine_id,
            "SNMP (161) exposed — L2/L3 management plane",
            "medium",
            "T1557",
            &format!(
                "Host {} accepts SNMP — ARP spoofing is link-local; exposed switch/router mgmt increases VLAN flatness risk.",
                host
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

async fn probe_vlan_hopping_surface(engine_id: &str, target: &str) -> EngineResult {
    probe_arp_spoofing_surface(engine_id, target).await
}

async fn probe_dhcp_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    if udp_probe_response(&host, 67, &[0x01]).await.is_some() {
        findings.push(remote_finding(
            engine_id,
            "UDP/67 responded — DHCP service reachable",
            "medium",
            "T1557",
            &format!(
                "Host {} answered on UDP/67 — rogue DHCP requires L2 visibility; agent or DHCP snooping validates server authenticity.",
                host
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

async fn probe_wifi_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/manage",
        "/unifi/",
        "/Meraki/",
        "/webfig/",
        "/cgi-bin/luci/",
        "/api/wlan",
        "/wireless",
    ];
    let tokens = &[
        "unifi",
        "meraki",
        "mikrotik",
        "cisco",
        "wireless",
        "wifi",
        "wlan",
        "access point",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            if probe_matched_token(&p, tokens).is_some() {
                findings.push(remote_finding(
                    engine_id,
                    "Wireless controller admin surface exposed",
                    "high",
                    "T1557",
                    &format!(
                        "{} confirms Wi-Fi management UI — WPA cracking/ evil-twin requires RF proximity; lock down controller access.",
                        p.final_url
                    ),
                    target,
                ));
                break;
            }
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_bluetooth_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &["/api/ble", "/bluetooth", "/api/gatt"];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Bluetooth/BLE management API exposed",
                "medium",
                "T1557",
                &format!(
                    "{} ({}) — BLE attacks require radio proximity; exposed BLE APIs indicate paired-device surface.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_lte_5g_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/api/5g",
        "/api/slice",
        "/nrf/",
        "/namf/",
        "/nudm/",
        "/openapi/",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            if probe_matched_token(&p, &["5g", "amf", "smf", "nrf", "slice", "telco"]).is_some() {
                findings.push(remote_finding(
                    engine_id,
                    "5G core/network function API exposed",
                    "high",
                    "T1557",
                    &format!(
                        "{} — 5G slice isolation bypass requires carrier core access; perimeter exposure of telco APIs is critical.",
                        p.final_url
                    ),
                    target,
                ));
                break;
            }
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_wpa3_surface(engine_id: &str, target: &str) -> EngineResult {
    let mut findings = probe_wifi_surface(engine_id, target).await.findings;
    let client = http_client().await;
    let base = normalize_url(target);
    if let Some(p) = http_get(&client, &join_url(&base, "/portal")).await {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Captive portal detected (WPA enterprise surface)",
                "medium",
                "T1557",
                &format!(
                    "{} — captive portals are common WPA2/3 enterprise entry points; validate EAP configuration on-site.",
                    p.final_url
                ),
                target,
            ));
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_packet_injection_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    if tcp_open(&host, 53).await {
        findings.push(remote_finding(
            engine_id,
            "DNS (53/TCP) open — packet injection pivot",
            "low",
            "T1557",
            &format!(
                "Host {} accepts TCP/53 — raw packet injection requires L2/L3 adjacency; agent validates NIC promiscuous mode.",
                host
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

async fn probe_network_tap_surface(engine_id: &str, target: &str) -> EngineResult {
    probe_arp_spoofing_surface(engine_id, target).await
}

async fn probe_multicast_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    if udp_probe_response(&host, 5353, b"\x00\x00\x00\x00\x00\x01")
        .await
        .is_some()
    {
        findings.push(remote_finding(
            engine_id,
            "mDNS (5353) responded",
            "medium",
            "T1557",
            &format!(
                "Host {} answered mDNS — multicast reconnaissance surface; agent validates IGMP/mDNS listeners.",
                host
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

async fn probe_nat_traversal_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    let stun_ports = tcp_scan(&host, &[3478, 5349, 19302], 6).await;
    if !stun_ports.is_empty() {
        findings.push(remote_finding(
            engine_id,
            &format!("STUN/TURN ports open: {:?}", stun_ports),
            "medium",
            "T1090",
            &format!(
                "Host {} exposes {:?} — NAT traversal abuse targets STUN/TURN for hole punching.",
                host, stun_ports
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

// ── Mobile / social ───────────────────────────────────────────────────────────

async fn probe_sim_swap_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &["/api/sim", "/api/msisdn", "/api/otp/sms", "/mfa/sms"];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "SIM/SMS OTP API exposed",
                "high",
                "T1628",
                &format!(
                    "{} ({}) — SIM swap attacks target carrier APIs; lock down telco integration endpoints.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_bluetooth_mobile_surface(engine_id: &str, target: &str) -> EngineResult {
    probe_bluetooth_surface(engine_id, target).await
}

async fn probe_nfc_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/api/nfc",
        "/api/payment/nfc",
        "/api/wallet",
        "/api/tap",
        "/nfc",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "NFC/payment API endpoint exposed",
                "medium",
                "T1557",
                &format!(
                    "{} ({}) — NFC relay requires physical tap; exposed NFC/payment APIs indicate access integration in scope.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    let host = extract_host(target);
    if findings.is_empty() && (tcp_open(&host, 8080).await || tcp_open(&host, 443).await) {
        findings.push(remote_finding(
            engine_id,
            "Mobile payment web surface reachable",
            "info",
            "T1557",
            &format!(
                "Host {host} accepts HTTPS/8080 — NFC relay attacks pair with mobile wallet webviews; agent validates local NFC stack."
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

async fn probe_deepfake_voice_surface(engine_id: &str, target: &str) -> EngineResult {
    probe_acoustic_exfil_surface(engine_id, target).await
}

async fn probe_pretexting_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    let mx = dns_a(&host).await;
    if mx.is_empty() {
        return collect(engine_id, target, findings);
    }
    let client = http_client().await;
    let url = normalize_url(target);
    if let Some(p) = http_get(&client, &url).await {
        let body = p.body.to_ascii_lowercase();
        for sig in ["support@", "help@", "security@", "it@", "admin@"] {
            if body.contains(sig) {
                findings.push(remote_finding(
                    engine_id,
                    &format!("Public contact vector: {}", sig),
                    "low",
                    "T1566",
                    &format!(
                        "Page at {} exposes {} — pretexting/vishing targets these roles; agent validates user awareness controls.",
                        p.final_url, sig
                    ),
                    target,
                ));
                break;
            }
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_insider_threat_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/hr/",
        "/internal/",
        "/staff/",
        "/employee/",
        "/wiki/",
        "/intranet/",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) && p.status != 404 {
            findings.push(remote_finding(
                engine_id,
                "Internal/staff portal exposed to perimeter",
                "high",
                "T1078",
                &format!(
                    "{} ({}) — insider threat tradecraft targets internal portals; restrict to corporate network/VPN.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_physical_social_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/visitor",
        "/badges",
        "/reception",
        "/docs/physical-security",
        "/security-policy",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Physical security / visitor management surface exposed",
                "medium",
                "T1204",
                &format!(
                    "{} ({}) — physical social engineering targets visitor/badging workflows; agent validates USB/HID policy on endpoints.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

// ── OT / hardware ─────────────────────────────────────────────────────────────

async fn probe_lorawan_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let mut findings = Vec::new();
    let open = tcp_scan(&host, &[1700, 1783, 8883, 1883], 6).await;
    if open.contains(&1700) {
        findings.push(remote_finding(
            engine_id,
            "LoRaWAN gateway port 1700 open (Semtech UDP)",
            "high",
            "T0855",
            &format!(
                "Host {} accepts TCP/1700 — LoRaWAN gateways often expose 1700/UDP; agent validates local RF stack.",
                host
            ),
            target,
        ));
    }
    if open.contains(&1883) || open.contains(&8883) {
        findings.push(remote_finding(
            engine_id,
            "MQTT broker port exposed (IoT/LoRa backhaul)",
            "medium",
            "T0855",
            &format!(
                "Host {} exposes MQTT ({:?}) — LoRaWAN backhaul often uses MQTT; validate auth and topic ACLs.",
                host, open
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

async fn probe_voltage_glitch_surface(engine_id: &str, target: &str) -> EngineResult {
    let host = extract_host(target);
    let client = http_client().await;
    let base = normalize_url(target);
    let mut findings = Vec::new();
    let jtag_ports = tcp_scan(&host, &[4444, 3333, 23, 8728, 47808], 8).await;
    for port in jtag_ports {
        let label = match port {
            4444 | 3333 => "OpenOCD/JTAG debug",
            23 => "Telnet (embedded debug)",
            8728 => "ESP8266/32 serial bridge",
            47808 => "BACnet/IP (ICS debug plane)",
            _ => "Debug/service port",
        };
        findings.push(remote_finding(
            engine_id,
            &format!("{label} port {port}/tcp open"),
            "high",
            "T0809",
            &format!(
                "Host {} accepts TCP/{port} — fault-injection and voltage-glitch attacks target exposed JTAG/UART/debug services; agent validates local secure-boot policy.",
                host
            ),
            target,
        ));
    }
    let paths = &["/jtag", "/debug/swd", "/api/firmware", "/docs/hardware"];
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if status_indicates_presence(p.status) {
            findings.push(remote_finding(
                engine_id,
                "Hardware debug documentation or API exposed",
                "medium",
                "T0809",
                &format!(
                    "{} ({}) — voltage/fault injection targets SoC debug interfaces documented here.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    collect(engine_id, target, findings)
}

async fn probe_tpm_surface(engine_id: &str, target: &str) -> EngineResult {
    probe_bootkit_surface(engine_id, target).await
}

async fn probe_cold_boot_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/bitlocker",
        "/docs/encryption",
        "/security/encryption",
        "/api/device/encryption",
        "/tpm",
        "/secure-boot",
    ];
    let mut findings = Vec::new();
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if !status_indicates_presence(p.status) {
            continue;
        }
        let body = p.body.to_ascii_lowercase();
        if body.contains("bitlocker")
            || body.contains("full disk")
            || body.contains("fde")
            || body.contains("tpm")
            || body.contains("secure boot")
            || body.contains("hibernation")
        {
            findings.push(remote_finding(
                engine_id,
                "Full-disk encryption / TPM policy surface exposed",
                "info",
                "T1552",
                &format!(
                    "{} ({}) — cold-boot attacks target RAM remanence when FDE/hibernate policies are weak; agent validates local key material handling.",
                    p.final_url, p.status
                ),
                target,
            ));
            break;
        }
    }
    let host = extract_host(target);
    if tcp_open(&host, 3389).await && findings.is_empty() {
        findings.push(remote_finding(
            engine_id,
            "RDP exposed without observed FDE policy page",
            "medium",
            "T1552",
            &format!(
                "Host {host} accepts RDP/3389 — review BitLocker/hibernate lock policy via endpoint agent; cold-boot window applies to unattended workstations.",
            ),
            target,
        ));
    }
    collect(engine_id, target, findings)
}

async fn probe_infostealer_surface(engine_id: &str, target: &str) -> EngineResult {
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let body = p.body.to_ascii_lowercase();
        for sig in [
            "redline",
            "raccoon",
            "vidar",
            "stealer",
            "infostealer",
            "cookies.sqlite",
            "login data",
        ] {
            if body.contains(sig) {
                findings.push(remote_finding(
                    engine_id,
                    &format!("Infostealer artifact hint: {}", sig),
                    "high",
                    "T1555",
                    &format!(
                        "Response from {} contains '{}' — commodity infostealer blast-radius assessment requires agent-side credential vault inspection.",
                        p.final_url, sig
                    ),
                    target,
                ));
                break;
            }
        }
    }
    let host = extract_host(target);
    for sub in ["logs", "stealer", "credentials", "cookies"] {
        let fqdn = format!("{sub}.{host}");
        if !dns_a(&fqdn).await.is_empty() {
            findings.push(remote_finding(
                engine_id,
                &format!("Suspicious subdomain: {}", fqdn),
                "high",
                "T1555",
                &format!(
                    "{} resolves — stealer log markets often use dedicated subdomains; agent validates browser credential stores.",
                    fqdn
                ),
                target,
            ));
        }
    }
    collect(engine_id, target, findings)
}

fn headers_blob(probe: &crate::engine_probes::HttpProbe) -> String {
    probe
        .headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
}
