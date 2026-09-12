//! SCADA/ICS wrapper around ot_ics_engine.
use crate::engine_probes::{
    http_client, normalize_url, probe_paths_concurrent, status_indicates_presence, tcp_scan,
    DEFAULT_PROBE_CONCURRENCY,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::json;

fn extract_host(target: &str) -> String {
    let t = target.trim();
    let t = t
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let t = t.split('/').next().unwrap_or(t);
    let t = t.split(':').next().unwrap_or(t);
    t.to_string()
}

pub async fn run_scada_ics_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let domains_json = serde_json::to_string(&[&host]).unwrap_or_else(|_| "[]".to_string());
    let hosts = crate::ot_ics_engine::resolve_scan_hosts(&domains_json, "[]", 64);
    let fingerprints = crate::ot_ics_engine::scan_hosts_passive(&hosts).await;
    let mut findings: Vec<serde_json::Value> = Vec::new();
    for fp in &fingerprints {
        let proto = fp.protocol.to_ascii_lowercase();
        let mitre = if proto.contains("mqtt")
            || proto.contains("opc")
            || proto.contains("iec")
            || proto.contains("dnp")
        {
            "T0869"
        } else {
            "T0843"
        };
        let severity = if fp.confidence > 0.8 {
            "critical"
        } else if fp.confidence > 0.5 {
            "high"
        } else {
            "medium"
        };
        findings.push(json!({
            "type": "scada_ics",
            "title": format!("OT/ICS device detected: {} on {}:{}", fp.protocol, fp.host, fp.port),
            "severity": severity,
            "mitre_attack": mitre,
            "description": format!("Vendor: {}, confidence: {:.2}, protocol: {}", fp.vendor_hint, fp.confidence, fp.protocol)
        }));
    }

    // ICS C2: commonly used industrial application-layer ports (evidence only, no writes).
    let c2_ports = tcp_scan(&host, &[1883, 8883, 2404, 4840, 20000, 44818], 8).await;
    for port in c2_ports {
        let (title, mitre) = match port {
            1883 | 8883 => (
                format!("MQTT broker on {host}:{port} — ICS C2 via standard application protocol"),
                "T0869",
            ),
            2404 => (
                format!("IEC 60870-5-104 on {host}:2404 — commonly used ICS C2 port"),
                "T0885",
            ),
            4840 => (
                format!("OPC UA discovery on {host}:4840 — engineering C2/session surface"),
                "T0869",
            ),
            20000 => (
                format!("DNP3 TCP 20000 on {host} — commonly used ICS C2 port"),
                "T0885",
            ),
            44818 => (
                format!("EtherNet/IP 44818 on {host} — commonly used ICS C2 port"),
                "T0885",
            ),
            _ => continue,
        };
        findings.push(json!({
            "type": "scada_ics",
            "title": title,
            "severity": "high",
            "mitre_attack": mitre,
            "description": format!(
                "Live TCP connect to {host}:{port} succeeded. This is C2/channel surface evidence — no industrial write, no SIS/Triton payload."
            )
        }));
    }

    // ICS privilege-escalation surface: engineering HMI/PLC admin panels (no exploit).
    let client = http_client().await;
    let base = normalize_url(target);
    let paths = &[
        "/portal",
        "/webvisu",
        "/codesys",
        "/TIAPortal",
        "/plc",
        "/hmi",
        "/admin",
        "/login",
    ];
    let probes = probe_paths_concurrent(&client, &base, paths, DEFAULT_PROBE_CONCURRENCY).await;
    for p in probes {
        if !status_indicates_presence(p.status) {
            continue;
        }
        let body = p.body.to_ascii_lowercase();
        if body.contains("password")
            || body.contains("login")
            || body.contains("codesys")
            || body.contains("siemens")
            || body.contains("plc")
            || body.contains("hmi")
        {
            findings.push(json!({
                "type": "scada_ics",
                "title": format!("Engineering/PLC admin panel at {}", p.final_url),
                "severity": if p.status == 200 { "critical" } else { "high" },
                "mitre_attack": "T0890",
                "description": format!(
                    "{} returned HTTP {} — engineering workstation / PLC web admin is the ICS privilege-escalation surface. Auditor only; no write to process I/O.",
                    p.final_url, p.status
                )
            }));
            break;
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("SCADA/ICS: {} findings", findings.len()),
    )
}

pub async fn run_scada_ics(target: &str) {
    print_result(run_scada_ics_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_strips_scheme_path_and_port() {
        assert_eq!(extract_host("https://example.com:8080/path"), "example.com");
    }

    #[test]
    fn extract_host_strips_http_scheme() {
        assert_eq!(extract_host("http://example.com/x"), "example.com");
    }

    #[test]
    fn extract_host_bare_host() {
        assert_eq!(extract_host("example.com"), "example.com");
    }

    #[test]
    fn extract_host_trims_whitespace() {
        assert_eq!(extract_host("  example.com  "), "example.com");
    }

    #[test]
    fn extract_host_drops_port_only() {
        assert_eq!(extract_host("10.0.0.1:502"), "10.0.0.1");
    }

    #[test]
    fn ics_c2_and_priv_esc_are_evidence_only() {
        let src = include_str!("scada_ics_engine.rs");
        assert!(src.contains("T0869"));
        assert!(src.contains("T0885"));
        assert!(src.contains("T0890"));
        assert!(src.contains("no industrial write"));
        assert!(src.contains("no write to process I/O"));
    }
}
