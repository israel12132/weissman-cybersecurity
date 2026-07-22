//! Advanced Data-exfiltration engines — real DNS/HTTP indicator detection.

use crate::engine_probes::{
    dns_txt, empty_ok, extract_host, finding, header_value, http_client, http_get, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

pub async fn run_dns_exfil_engine_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let txts = dns_txt(&host).await;
    let mut findings: Vec<Value> = Vec::new();
    for r in txts.iter() {
        // High-entropy TXT records (lots of base64) signal exfil candidates.
        let unique_chars = r.chars().collect::<std::collections::HashSet<_>>().len();
        if r.len() > 80 && unique_chars > 30 {
            findings.push(finding(
                "dns_exfil_engine",
                "High-entropy TXT record",
                "low",
                "T1048.003",
                &format!(
                    "TXT on {} is {} chars / {} unique — DNS exfil candidate.",
                    host,
                    r.len(),
                    unique_chars
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("dns_exfil_engine", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("dns_exfil_engine: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_dns_exfil_engine, run_dns_exfil_engine_result);

pub async fn run_http_covert_exfil_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        // Excessive custom X- headers can carry covert channels.
        let x_headers: Vec<_> = p
            .headers
            .iter()
            .filter(|(k, _)| k.to_ascii_lowercase().starts_with("x-"))
            .collect();
        if x_headers.len() > 10 {
            findings.push(finding(
                "http_covert_exfil",
                &format!("{} custom X- headers observed", x_headers.len()),
                "low",
                "T1071.001",
                &format!(
                    "Server at {} returns many X- headers — review for covert encoding.",
                    p.final_url
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("http_covert_exfil", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("http_covert_exfil: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_http_covert_exfil, run_http_covert_exfil_result);

pub async fn run_cloud_exfil_engine_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if p.body.contains("amazonaws.com")
            || p.body.contains("storage.googleapis.com")
            || p.body.contains(".blob.core.windows.net")
        {
            findings.push(finding(
                "cloud_exfil_engine",
                "Cloud-storage URLs in response",
                "info",
                "T1567.002",
                &format!(
                    "{} references cloud-storage URLs — verify outbound DLP.",
                    p.final_url
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("cloud_exfil_engine", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("cloud_exfil_engine: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_cloud_exfil_engine, run_cloud_exfil_engine_result);

pub async fn run_encrypted_exfil_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    const LARGE_BODY_BYTES: usize = 1_048_576;
    const CLOUD_REF_MIN_BYTES: usize = 10_240;
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if p.body.len() >= LARGE_BODY_BYTES {
            findings.push(finding(
                "encrypted_exfil",
                &format!("Large outbound response ({} B)", p.body.len()),
                "medium",
                "T1048.002",
                &format!(
                    "Response from {} is {} bytes — large payloads may carry encrypted or compressed exfil staging; verify DLP/egress inspection.",
                    p.final_url, p.body.len()
                ),
                t,
            ));
        }
        if let Some(cl) = header_value(&p.headers, "content-length") {
            if let Ok(len) = cl.parse::<usize>() {
                if len >= LARGE_BODY_BYTES && p.body.len() < LARGE_BODY_BYTES {
                    findings.push(finding(
                        "encrypted_exfil",
                        &format!("Content-Length indicates large payload ({} B)", len),
                        "medium",
                        "T1048.002",
                        &format!(
                            "Content-Length header on {} declares {} bytes — inspect egress for bulk encrypted transfers.",
                            p.final_url, len
                        ),
                        t,
                    ));
                }
            }
        }
        let cloud_hosts = [
            ("amazonaws.com", "AWS S3/object storage"),
            ("storage.googleapis.com", "Google Cloud Storage"),
            (".blob.core.windows.net", "Azure Blob Storage"),
            ("dropbox.com", "Dropbox"),
            ("backblazeb2.com", "Backblaze B2"),
            ("wasabisys.com", "Wasabi"),
        ];
        for (host, label) in cloud_hosts {
            if p.body.contains(host) && p.body.len() >= CLOUD_REF_MIN_BYTES {
                findings.push(finding(
                    "encrypted_exfil",
                    &format!("Cloud storage URL in large response ({})", label),
                    "info",
                    "T1567.002",
                    &format!(
                        "Response from {} ({} B) references {} — verify outbound uploads to third-party storage are authorized.",
                        p.final_url, p.body.len(), label
                    ),
                    t,
                ));
                break;
            }
        }
    }
    if findings.is_empty() {
        empty_ok("encrypted_exfil", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!(
                "encrypted_exfil: {} exfil surface signal(s)",
                findings.len()
            ),
        )
    }
}
cli_wrapper!(run_encrypted_exfil, run_encrypted_exfil_result);

pub async fn run_acoustic_exfil_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "acoustic_exfil",
        t,
        "Acoustic exfiltration detection requires endpoint audio sampling",
        "Air-gap acoustic channels are inaudible from the network. The agent samples microphone events and ultrasonic emissions.",
    )
}
cli_wrapper!(run_acoustic_exfil, run_acoustic_exfil_result);

pub async fn run_em_exfil_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "em_exfil_engine",
        t,
        "Electromagnetic exfiltration detection requires on-host sensing",
        "TEMPEST / RF-side-channel evidence cannot be collected over the network.",
    )
}
cli_wrapper!(run_em_exfil_engine, run_em_exfil_engine_result);

pub async fn run_optical_exfil_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "optical_exfil",
        t,
        "Optical exfiltration detection requires endpoint camera/LED monitoring",
        "LED-modulation / screen-blink channels cannot be detected from a network probe.",
    )
}
cli_wrapper!(run_optical_exfil, run_optical_exfil_result);

pub async fn run_cache_timing_exfil_result(t: &str) -> EngineResult {
    crate::timing_sidechannel_engine::run_timing_sidechannel_result(t).await
}
cli_wrapper!(run_cache_timing_exfil, run_cache_timing_exfil_result);

pub async fn run_keyboard_acoustic_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "keyboard_acoustic",
        t,
        "Keyboard acoustic side-channel detection requires endpoint audio agent",
        "Keystroke acoustic recovery is microphone-side; remote probing cannot observe it.",
    )
}
cli_wrapper!(run_keyboard_acoustic, run_keyboard_acoustic_result);

pub async fn run_screen_capture_exfil_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "screen_capture_exfil",
        t,
        "Screen-capture exfiltration detection needs endpoint event hooks",
        "The agent monitors GDI/X11/AVCaptureSession events that aren't exposed over the network.",
    )
}
cli_wrapper!(run_screen_capture_exfil, run_screen_capture_exfil_result);

pub async fn run_clipboard_hijack_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "clipboard_hijack",
        t,
        "Clipboard hijack detection requires endpoint clipboard API access",
        "OS clipboard transitions are not network-observable; the agent diffs allowed sources per copy event.",
    )
}
cli_wrapper!(run_clipboard_hijack, run_clipboard_hijack_result);

pub async fn run_database_exfil_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    for &port in [3306u16, 5432, 1433, 27017, 6379, 9200].iter() {
        if crate::engine_probes::tcp_open(&host, port).await {
            findings.push(finding(
                "database_exfil",
                &format!("DB port open: {}", port),
                "high",
                "T1213",
                &format!(
                    "TCP {}:{} is reachable — exposed database surface.",
                    host, port
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("database_exfil", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("database_exfil: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_database_exfil, run_database_exfil_result);

pub async fn run_email_exfil_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(t);
    let mut findings: Vec<Value> = Vec::new();
    for &port in [25u16, 465, 587, 110, 143, 993, 995].iter() {
        if crate::engine_probes::tcp_open(&host, port).await {
            findings.push(finding(
                "email_exfil",
                &format!("Mail port open: {}", port),
                "info",
                "T1048.003",
                &format!(
                    "TCP {}:{} reachable — review mail-server hardening.",
                    host, port
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("email_exfil", t)
    } else {
        EngineResult::ok(findings.clone(), format!("email_exfil: {}", findings.len()))
    }
}
cli_wrapper!(run_email_exfil, run_email_exfil_result);

pub async fn run_insider_exfil_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "insider_exfil",
        t,
        "Insider exfiltration detection requires user-behaviour telemetry",
        "Insider activity (mass downloads, USB writes, email forwards) is observed by the agent + DLP feed, not over the network.",
    )
}
cli_wrapper!(run_insider_exfil, run_insider_exfil_result);

pub async fn run_storage_covert_channel_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "storage_covert_channel",
        t,
        "Storage covert channel detection requires filesystem inotify hooks",
        "Steganographic writes into ADS/slack space / EXIF chunks are FS-level events; the agent watches inode + xattr changes.",
    )
}
cli_wrapper!(
    run_storage_covert_channel,
    run_storage_covert_channel_result
);

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn network_engines_reject_empty_target() {
        for r in [
            run_dns_exfil_engine_result("").await,
            run_dns_exfil_engine_result("   ").await,
            run_http_covert_exfil_result("").await,
            run_cloud_exfil_engine_result("").await,
            run_encrypted_exfil_result("").await,
            run_database_exfil_result("").await,
            run_email_exfil_result("").await,
        ] {
            assert_eq!(r.status, "error");
            assert!(r.message.contains("target required"));
            assert!(r.findings.is_empty());
        }
    }

    #[tokio::test]
    async fn agent_required_engines_emit_agent_required_finding() {
        let cases = [
            ("acoustic_exfil", run_acoustic_exfil_result("host").await),
            ("em_exfil_engine", run_em_exfil_engine_result("host").await),
            ("optical_exfil", run_optical_exfil_result("host").await),
            (
                "keyboard_acoustic",
                run_keyboard_acoustic_result("host").await,
            ),
            (
                "screen_capture_exfil",
                run_screen_capture_exfil_result("host").await,
            ),
            (
                "clipboard_hijack",
                run_clipboard_hijack_result("host").await,
            ),
            ("insider_exfil", run_insider_exfil_result("host").await),
            (
                "storage_covert_channel",
                run_storage_covert_channel_result("host").await,
            ),
        ];
        for (engine_id, r) in cases {
            assert_eq!(r.status, "ok");
            assert_eq!(r.findings.len(), 1);
            let f = &r.findings[0];
            assert_eq!(f["type"], engine_id);
            assert_eq!(f["category"], "agent_required");
            assert_eq!(f["severity"], "info");
            assert_eq!(f["agent_required"], true);
            assert!(r.message.contains("agent-based collector required"));
        }
    }
}
