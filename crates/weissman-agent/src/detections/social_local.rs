//! Social-engineering / insider-threat host collectors.

use super::finding;
use super::util::{any_process_matches, dir_entry_names, run_cmd_lossy};
use serde_json::{json, Map, Value};

pub async fn run_deepfake_voice(engine: &str) -> anyhow::Result<Vec<Value>> {
    let tts = any_process_matches(&[
        "elevenlabs", "coqui", "bark", "tortoise", "realtime-voice", "so-vits", "piper",
        "ffmpeg", "obs", "voicemod", "clownfish",
    ]);
    let mut model_paths: Vec<String> = Vec::new();
    if let Some(home) = std::env::var("HOME").ok().or_else(|| std::env::var("USERPROFILE").ok()) {
        for sub in [".cache/torch", ".local/share/tts", "Documents/voice"] {
            let p = format!("{home}/{sub}");
            if tokio::fs::metadata(&p).await.is_ok() {
                model_paths.push(p);
            }
        }
    }

    let mut extras = Map::new();
    extras.insert("voice_tools".into(), json!(tts));
    extras.insert("model_cache_paths".into(), json!(model_paths));
    Ok(vec![finding(
        engine,
        if tts.is_empty() {
            "No voice-cloning/TTS tooling observed"
        } else {
            "Voice synthesis / cloning tooling active"
        },
        if tts.is_empty() { "info" } else { "high" },
        "T1566.002",
        "Deepfake vishing requires TTS/voice-conversion stacks. Agent inventoried voice-related processes and local model caches.",
        extras,
    )])
}

pub async fn run_pretexting(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mail_clients = any_process_matches(&[
        "outlook", "thunderbird", "mail", "evolution", "mutt", "geary",
    ]);
    let rules_hint = false;

    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_cmd_lossy(
            "powershell",
            &["-NoProfile", "-Command", "Get-InboxRule -ErrorAction SilentlyContinue | Select-Object -First 5 Name, Enabled"],
        )
        .await
        {
            rules_hint = out.lines().count() > 2;
        }
    }

    let mut extras = Map::new();
    extras.insert("mail_clients".into(), json!(mail_clients));
    extras.insert("inbox_rules_enumerated".into(), json!(rules_hint));
    findings.push(finding(
        engine,
        "Email client / pretexting surface inventory",
        if rules_hint { "medium" } else { "info" },
        "T1566.002",
        "Pretexting often combines inbox rules and auto-forwarding. Agent verified mail-client presence and (where permitted) inbox-rule visibility.",
        extras,
    ));
    Ok(findings)
}

pub async fn run_insider_threat(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let sync_tools = any_process_matches(&[
        "dropbox", "onedrive", "googledrivesync", "rclone", "syncthing", "mega", "box",
    ]);
    let archive_tools = any_process_matches(&["7z", "7zfm", "winrar", "rar", "tar", "zip"]);
    let usb_tools = any_process_matches(&["usb", "mass storage"]);

    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = tokio::fs::read_to_string("/proc/mounts").await {
            if text.contains("/media/") || text.contains("/mnt/") {
                let mut extras = Map::new();
                extras.insert("removable_mount".into(), json!(true));
                findings.push(finding(
                    engine,
                    "Removable media mounted — insider exfil pivot",
                    "medium",
                    "T1052.001",
                    "/proc/mounts shows removable-media mount points while cloud-sync tooling may be active — correlate DLP alerts.",
                    extras,
                ));
            }
        }
    }

    if !sync_tools.is_empty() && !archive_tools.is_empty() {
        let mut extras = Map::new();
        extras.insert("sync_tools".into(), json!(sync_tools));
        extras.insert("archive_tools".into(), json!(archive_tools));
        findings.push(finding(
            engine,
            "Cloud sync + archival tooling concurrently active",
            "high",
            "T1567.002",
            "Insider exfiltration often stages archives then uploads via personal sync clients.",
            extras,
        ));
    }

    if findings.is_empty() {
        let mut extras = Map::new();
        extras.insert("sync_tools".into(), json!(sync_tools));
        extras.insert("usb_related".into(), json!(usb_tools));
        findings.push(finding(
            engine,
            "Insider-threat process baseline captured",
            "info",
            "T1567",
            "Agent inventoried sync/archival/USB-related processes — no high-confidence insider pattern on this snapshot.",
            extras,
        ));
    }
    Ok(findings)
}

pub async fn run_physical_social(engine: &str) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let mut screen_locked = true;

    #[cfg(target_os = "linux")]
    {
        if run_cmd_lossy("loginctl", &["show-session", "self", "-p", "LockedHint"]).await
            .is_some_and(|s| s.contains("no"))
        {
            screen_locked = false;
        }
    }
    #[cfg(target_os = "macos")]
    {
        if run_cmd_lossy(
            "python3",
            &["-c", "import Quartz; print(Quartz.CGSessionCopyCurrentSessionDictionary())"],
        )
        .await
        .is_none()
        {
            screen_locked = false; // best-effort
        }
    }
    #[cfg(target_os = "windows")]
    {
        if run_cmd_lossy(
            "powershell",
            &["-NoProfile", "-Command", "(Get-Process logonui -ErrorAction SilentlyContinue) -eq $null"],
        )
        .await
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("true"))
        {
            screen_locked = false;
        }
    }

    let smartcard = dir_entry_names("/dev").await
        .into_iter()
        .any(|n| n.starts_with("usb") || n.contains("sc"));
    let hid_badusb = any_process_matches(&["rubber", "ducky", "badusb", "arduino"]);

    if !screen_locked {
        findings.push(finding(
            engine,
            "Interactive session appears unlocked — physical access risk",
            "medium",
            "T1200",
            "Unattended unlocked workstations enable evil-maid / BadUSB / shoulder-surfing tradecraft.",
            Map::new(),
        ));
    }
    if !hid_badusb.is_empty() {
        let mut extras = Map::new();
        extras.insert("processes".into(), json!(hid_badusb));
        findings.push(finding(
            engine,
            "HID/BadUSB-adjacent tooling observed",
            "high",
            "T1200",
            "Processes match HID injection / BadUSB development tools.",
            extras,
        ));
    }

    let mut extras = Map::new();
    extras.insert("smartcard_devices".into(), json!(smartcard));
    findings.push(finding(
        engine,
        "Physical attack surface inventory",
        "info",
        "T1200",
        "Agent assessed screen-lock state, smart-card readers, and HID tooling relevant to physical/social intrusion.",
        extras,
    ));
    Ok(findings)
}
