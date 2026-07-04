//! Covert exfiltration channel collectors — acoustic, EM, optical, keyboard, storage ADS.

use super::finding;
use super::util::{any_process_matches, dir_entry_names, run_cmd_lossy};
use serde_json::{json, Map, Value};

pub async fn run_acoustic(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let audio_procs = any_process_matches(&[
        "pulseaudio",
        "pipewire",
        "arecord",
        "ffmpeg",
        "sox",
        "audacity",
        "parec",
    ]);
    let mut devices: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        devices = dir_entry_names("/dev/snd").await;
        if let Some(out) = run_cmd_lossy("pactl", &["list", "sources", "short"]).await {
            for line in out.lines().take(10) {
                devices.push(line.trim().to_string());
            }
        }
    }

    let mut extras = Map::new();
    extras.insert("audio_devices".into(), json!(devices.len()));
    extras.insert("audio_processes".into(), json!(audio_procs));
    findings.push(finding(
        engine,
        &format!("Acoustic exfil surface: {} audio device(s)", devices.len()),
        if audio_procs.iter().any(|p| p.contains("arecord") || p.contains("ffmpeg")) {
            "medium"
        } else {
            "info"
        },
        "T1123",
        "Agent inventoried microphones and audio subsystems. Covert acoustic channels modulate data into near-ultrasonic carriers — monitor for sustained capture without user-facing apps.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_em_exfil(engine: &str) -> anyhow::Result<Vec<Value>> {
    let sdr_tools = any_process_matches(&[
        "rtl_sdr", "gqrx", "gnuradio", "hackrf", "bladeRF", "limeSDR", "urh",
    ]);
    let mut findings = Vec::new();
    let mut extras = Map::new();
    extras.insert("sdr_tools".into(), json!(sdr_tools));
    findings.push(finding(
        engine,
        if sdr_tools.is_empty() {
            "No SDR/EM exfil tooling observed"
        } else {
            "SDR / electromagnetic tooling active"
        },
        if sdr_tools.is_empty() { "info" } else { "high" },
        "T1052",
        "Electromagnetic exfiltration requires SDR hardware and signal-generation software. Agent flagged running SDR-related processes.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_optical(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let capture = any_process_matches(&[
        "ffmpeg",
        "obs",
        "screencapture",
        "snippingtool",
        "greenshot",
        "flameshot",
        "scrot",
    ]);
    let mut cameras: Vec<String> = Vec::new();

    #[cfg(target_os = "linux")]
    {
        cameras = dir_entry_names("/dev")
            .await
            .into_iter()
            .filter(|n| n.starts_with("video"))
            .collect();
    }

    let mut extras = Map::new();
    extras.insert("camera_devices".into(), json!(cameras));
    extras.insert("capture_tools".into(), json!(capture));
    findings.push(finding(
        engine,
        &format!("Optical exfil surface: {} camera(s), {} capture tool(s)", cameras.len(), capture.len()),
        if !capture.is_empty() { "medium" } else { "info" },
        "T1125",
        "Optical exfil uses cameras/screen recorders to leak data via QR or modulated light. Agent inventoried video devices and active capture utilities.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_keyboard_acoustic(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = run_acoustic(engine).await?;
    let keyloggers = any_process_matches(&[
        "keylogger",
        "logkeys",
        "lkl",
        "kidlogger",
        "refog",
        "ardamax",
    ]);
    if !keyloggers.is_empty() {
        let mut extras = Map::new();
        extras.insert("suspect_processes".into(), json!(keyloggers));
        findings.push(finding(
            engine,
            "Keyboard-capture tooling detected",
            "critical",
            "T1056.001",
            "Process names match known keylogging tools — acoustic side-channel is secondary; direct key capture is primary.",
            extras,
        ));
    }
    Ok(findings)
}

pub async fn run_screen_capture(engine: &str) -> anyhow::Result<Vec<Value>> {
    run_optical(engine).await
}

pub async fn run_storage_covert(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let stego = any_process_matches(&["steghide", "stegosuite", "openstego", "outguess"]);

    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_cmd_lossy(
            "powershell",
            &["-NoProfile", "-Command", "Get-ChildItem -Path $env:TEMP -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match ':$' } | Select-Object -First 5 FullName"],
        )
        .await
        {
            if !out.trim().is_empty() {
                let mut extras = Map::new();
                extras.insert("ads_sample".into(), Value::String(out.chars().take(500).collect()));
                findings.push(finding(
                    engine,
                    "Possible NTFS alternate data stream artifacts in TEMP",
                    "high",
                    "T1564.004",
                    "Alternate Data Streams can hide payloads from Explorer — verify with `dir /r` and MFT forensics.",
                    extras,
                ));
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = std::env::var("HOME").ok() {
            if let Some(out) = run_cmd_lossy("getfattr", &["-d", "-m", "-", &home]).await {
                if out.lines().count() > 3 {
                    let mut extras = Map::new();
                    extras.insert("xattr_lines".into(), json!(out.lines().count()));
                    findings.push(finding(
                        engine,
                        "Extended attributes present on home directory",
                        "low",
                        "T1564",
                        "Linux xattr can store covert metadata payloads — compare against baseline.",
                        extras,
                    ));
                }
            }
        }
    }

    if !stego.is_empty() {
        let mut extras = Map::new();
        extras.insert("stego_tools".into(), json!(stego));
        findings.push(finding(
            engine,
            "Steganography tooling running",
            "high",
            "T1027.003",
            "Steganography utilities can embed exfiltrated data inside benign-looking media files on local storage.",
            extras,
        ));
    }

    if findings.is_empty() {
        findings.push(finding(
            engine,
            "Storage covert-channel baseline — no ADS/stego indicators",
            "info",
            "T1564.004",
            "Agent scanned for NTFS ADS patterns and steganography tooling — none observed.",
            Map::new(),
        ));
    }
    Ok(findings)
}
