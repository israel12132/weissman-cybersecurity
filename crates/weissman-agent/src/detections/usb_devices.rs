//! USB-device enumeration.

use super::finding;
use serde_json::{json, Value};

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let inventory = collect_usb().await;
    let mut extras = serde_json::Map::new();
    extras.insert("device_count".into(), json!(inventory.len()));
    extras.insert(
        "devices".into(),
        Value::Array(
            inventory
                .iter()
                .take(60)
                .map(|d| Value::String(d.clone()))
                .collect(),
        ),
    );
    findings.push(finding(
        engine,
        &format!("USB-device inventory: {} entries", inventory.len()),
        "info",
        "T1091",
        "Agent enumerated currently attached USB devices. Compare against the asset register to detect rogue / unauthorised storage.",
        extras,
    ));
    Ok(findings)
}

async fn collect_usb() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        let mut out = Vec::new();
        if let Ok(mut rd) = tokio::fs::read_dir("/sys/bus/usb/devices").await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                let id_vendor = tokio::fs::read_to_string(path.join("idVendor"))
                    .await
                    .unwrap_or_default();
                let id_product = tokio::fs::read_to_string(path.join("idProduct"))
                    .await
                    .unwrap_or_default();
                let product = tokio::fs::read_to_string(path.join("product"))
                    .await
                    .unwrap_or_default();
                if !id_vendor.trim().is_empty() {
                    out.push(format!(
                        "{}:{}  {}",
                        id_vendor.trim(),
                        id_product.trim(),
                        product.trim()
                    ));
                }
            }
        }
        out
    }
    #[cfg(target_os = "macos")]
    {
        let out = tokio::process::Command::new("system_profiler")
            .args(["SPUSBDataType", "-json"])
            .output()
            .await;
        if let Ok(o) = out {
            if o.status.success() {
                return String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter(|l| l.contains("\"_name\"") || l.contains("\"product_id\""))
                    .map(|l| l.trim().to_string())
                    .collect();
            }
        }
        return Vec::new();
    }
    #[cfg(target_os = "windows")]
    {
        let out = tokio::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-PnpDevice -Class USB | Select-Object -ExpandProperty FriendlyName",
            ])
            .output()
            .await;
        if let Ok(o) = out {
            if o.status.success() {
                return String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
        return Vec::new();
    }
}
