//! Mobile-adjacent collectors — SIM profiles, NFC readers, BLE GATT surface.

use super::finding;
use super::util::{dir_entry_names, run_cmd, run_cmd_lossy};
use serde_json::{json, Map, Value};

pub async fn run_sim_swap(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mut profiles: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Some(out) = run_cmd_lossy("mmcli", &["-m", "0"]).await {
            for line in out.lines() {
                if line.contains("operator") || line.contains("imei") || line.contains("sim") {
                    profiles.push(line.trim().to_string());
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_cmd_lossy("powershell", &["-NoProfile", "-Command", "Get-CimInstance -ClassName Win32_SerialPort | Select-Object Name, DeviceID"]).await {
            profiles.extend(out.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string));
        }
    }

    let mut extras = Map::new();
    extras.insert("cellular_profile_lines".into(), json!(profiles.len()));
    extras.insert("sample".into(), json!(profiles.iter().take(8).collect::<Vec<_>>()));
    findings.push(finding(
        engine,
        "Cellular/SIM profile inventory for swap-risk assessment",
        if profiles.is_empty() { "info" } else { "medium" },
        "T1556.006",
        "SIM-swap attacks bypass SMS MFA. Agent captured modem/SIM metadata — enforce FIDO2 and carrier PIN/port-freeze policies.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_nfc(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut readers: Vec<String> = Vec::new();

    if let Some(out) = run_cmd_lossy("pcsc_scan", &[]).await {
        readers.extend(out.lines().map(str::trim).filter(|l| !l.is_empty()).take(15).map(str::to_string));
    }
    if let Some(out) = run_cmd("nfc-list", &[]).await {
        readers.extend(out.lines().map(str::trim).filter(|l| !l.is_empty()).take(15).map(str::to_string));
    }
    #[cfg(target_os = "linux")]
    {
        for name in dir_entry_names("/dev").await {
            if name.starts_with("nfc") {
                readers.push(format!("/dev/{name}"));
            }
        }
    }

    let mut extras = Map::new();
    extras.insert("nfc_readers".into(), json!(readers));
    Ok(vec![finding(
        engine,
        &format!("NFC relay surface: {} reader/device entry(ies)", readers.len()),
        if readers.is_empty() { "info" } else { "medium" },
        "T1557.002",
        "NFC relay attacks extend contactless payment/badge taps over the network. Active PC/SC or nfc-list devices increase relay feasibility from this host.",
        extras,
    )])
}
