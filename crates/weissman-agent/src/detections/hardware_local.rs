//! OT / hardware-security collectors — LoRaWAN, TPM, cold-boot, glitch/debug interfaces.

use super::finding;
use super::util::{dir_entry_names, path_exists, run_cmd_lossy};
use serde_json::{json, Map, Value};

pub async fn run_lorawan(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut radios: Vec<String> = Vec::new();
    for name in dir_entry_names("/dev").await {
        if name.starts_with("ttyUSB") || name.starts_with("ttyACM") || name.contains("lora") {
            radios.push(format!("/dev/{name}"));
        }
    }
    if let Some(out) = run_cmd_lossy("lsusb", &[]).await {
        for line in out.lines() {
            let l = line.to_ascii_lowercase();
            if l.contains("silicon labs")
                || l.contains("ftdi")
                || l.contains("ch340")
                || l.contains("lora")
            {
                radios.push(line.trim().to_string());
            }
        }
    }

    let mut extras = Map::new();
    extras.insert("serial_lora_devices".into(), json!(radios));
    Ok(vec![finding(
        engine,
        &format!("LoRa/LoRaWAN radio surface: {} device(s)", radios.len()),
        if radios.is_empty() { "info" } else { "medium" },
        "T1599",
        "USB serial adapters often host LoRa concentrators/gateways. Agent enumerated UART devices matching common LoRa dongles.",
        extras,
    )])
}

pub async fn run_voltage_glitch(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut debug_ifaces: Vec<String> = Vec::new();
    for name in dir_entry_names("/dev").await {
        if name.starts_with("ttyUSB") || name.starts_with("ttyACM") {
            debug_ifaces.push(format!("/dev/{name}"));
        }
    }
    let glitch_tools = super::util::any_process_matches(&[
        "openocd",
        "st-link",
        "jlink",
        "chipwhisperer",
        "pyocd",
        "dfu-util",
    ]);

    let mut extras = Map::new();
    extras.insert("debug_adapters".into(), json!(debug_ifaces));
    extras.insert("glitch_tools".into(), json!(glitch_tools));
    Ok(vec![finding(
        engine,
        &format!(
            "Fault-injection / debug surface: {} adapter(s), {} tool(s)",
            debug_ifaces.len(),
            glitch_tools.len()
        ),
        if !glitch_tools.is_empty() { "high" } else if !debug_ifaces.is_empty() { "medium" } else { "info" },
        "T1199",
        "Voltage-glitch and JTAG/SWD attacks require physical debug adapters. Agent inventoried connected programmers and glitch frameworks.",
        extras,
    )])
}

pub async fn run_tpm(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut present = false;
    let mut version_hint = String::new();

    #[cfg(target_os = "linux")]
    {
        present = path_exists("/dev/tpm0").await || path_exists("/dev/tpmrm0").await;
        if let Some(out) = run_cmd_lossy("tpm2_getcap", &["properties-fixed"]).await {
            version_hint = out.lines().take(5).collect::<Vec<_>>().join("; ");
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_cmd_lossy(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-Tpm | Select-Object TpmPresent, TpmReady, ManufacturerVersion",
            ],
        )
        .await
        {
            present = out.to_ascii_lowercase().contains("true");
            version_hint = out.chars().take(200).collect();
        }
    }

    let mut extras = Map::new();
    extras.insert("tpm_present".into(), json!(present));
    extras.insert("version_hint".into(), Value::String(version_hint));
    Ok(vec![finding(
        engine,
        if present {
            "TPM present — firmware integrity baseline captured"
        } else {
            "No TPM device node observed"
        },
        if present { "info" } else { "medium" },
        "T1542.003",
        "TPM firmware attacks target boot-chain trust. Agent verified TPM visibility and (where available) manufacturer version.",
        extras,
    )])
}

pub async fn run_cold_boot(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mut encryption_on = false;

    #[cfg(target_os = "linux")]
    {
        encryption_on = path_exists("/etc/crypttab").await;
        if let Ok(text) = tokio::fs::read_to_string("/sys/power/mem_sleep").await {
            if text.trim() == "s2idle" {
                findings.push(finding(
                    engine,
                    "Suspend mode s2idle — RAM retention attack surface",
                    "medium",
                    "T1556",
                    "Modern standby keeps DRAM powered; cold-boot attacks extract keys from RAM after hard reset.",
                    Map::new(),
                ));
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_cmd_lossy("manage-bde", &["-status"]).await {
            encryption_on = out.to_ascii_lowercase().contains("protection on");
        }
    }

    if !encryption_on {
        findings.push(finding(
            engine,
            "Full-disk encryption not confirmed active",
            "high",
            "T1556",
            "Cold-boot attacks recover BitLocker/FileVault keys from RAM when FDE is absent or suspended.",
            Map::new(),
        ));
    } else {
        findings.push(finding(
            engine,
            "FDE active — cold-boot residual risk remains on sleep/resume",
            "info",
            "T1556",
            "Disk encryption is enabled; still disable S3 sleep on high-value laptops and require hibernate/shutdown.",
            Map::new(),
        ));
    }
    Ok(findings)
}
