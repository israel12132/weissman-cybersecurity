//! Scheduled-tasks / persistence enumeration.

use super::finding;
use serde_json::{json, Value};

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Enumerate user crontabs + system cron + systemd units that look user-installed.
        for path in &[
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ] {
            if let Ok(meta) = tokio::fs::metadata(path).await {
                let extras = json_extras(json!({
                    "path": path,
                    "size_bytes": meta.len(),
                    "type": if meta.is_dir() { "directory" } else { "file" },
                }));
                findings.push(finding(
                    engine,
                    &format!("Cron persistence path present: {}", path),
                    "info",
                    "T1053.003",
                    &format!("{} is part of standard cron infrastructure — review for unauthorized entries.", path),
                    extras,
                ));
            }
        }
        if let Ok(mut rd) = tokio::fs::read_dir("/etc/systemd/system").await {
            let mut units: Vec<String> = Vec::new();
            while let Ok(Some(entry)) = rd.next_entry().await {
                if entry.file_name().to_string_lossy().ends_with(".service") {
                    units.push(entry.file_name().to_string_lossy().to_string());
                }
            }
            if !units.is_empty() {
                let mut extras = serde_json::Map::new();
                extras.insert("unit_count".into(), json!(units.len()));
                extras.insert("units".into(), json!(units));
                findings.push(finding(
                    engine,
                    &format!("{} user systemd units present", units.len()),
                    "info",
                    "T1543.002",
                    "Agent enumerated /etc/systemd/system/. Compare against a known-good baseline to spot rogue services.",
                    extras,
                ));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = tokio::process::Command::new("launchctl")
            .arg("list")
            .output()
            .await;
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = stdout.lines().collect();
            let extras = json_extras(json!({
                "launchd_entries": lines.len().saturating_sub(1),
                "sample": lines.iter().skip(1).take(15).copied().collect::<Vec<_>>(),
            }));
            findings.push(finding(
                engine,
                "launchctl inventory captured",
                "info",
                "T1543.001",
                "Agent enumerated launchd jobs. Review unsigned third-party labels.",
                extras,
            ));
        }
    }

    #[cfg(target_os = "windows")]
    {
        let output = tokio::process::Command::new("schtasks")
            .args(["/Query", "/FO", "CSV", "/NH"])
            .output()
            .await;
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let count = stdout.lines().count();
            let extras = json_extras(json!({"scheduled_task_count": count}));
            findings.push(finding(
                engine,
                "Scheduled-tasks inventory captured",
                "info",
                "T1053.005",
                "Agent enumerated Windows Task Scheduler. Cross-check against the application allow-list.",
                extras,
            ));
        }
    }

    if findings.is_empty() {
        findings.push(finding(
            engine,
            "No persistence inventory available on this host",
            "info",
            "T1547",
            "Agent could not collect any persistence indicator (insufficient privileges or unsupported OS).",
            serde_json::Map::new(),
        ));
    }
    Ok(findings)
}

pub async fn run_uefi(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let efi_root = std::path::PathBuf::from("/boot/efi/EFI");
    let mut count = 0usize;
    let mut sample: Vec<String> = Vec::new();
    if efi_root.is_dir() {
        if let Ok(mut rd) = tokio::fs::read_dir(&efi_root).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                count += 1;
                if sample.len() < 15 {
                    sample.push(entry.path().display().to_string());
                }
            }
        }
    }
    findings.push(finding(
        engine,
        if count == 0 {
            "EFI partition not visible to agent"
        } else {
            "EFI partition inventory captured"
        },
        "info",
        "T1542.003",
        &format!(
            "Agent counted {} entries below /boot/efi/EFI. SecureBoot validation requires SBAT / measured-boot attestation outside the agent.",
            count
        ),
        json_extras(json!({"entries": count, "sample": sample})),
    ));
    Ok(findings)
}

fn json_extras(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}
