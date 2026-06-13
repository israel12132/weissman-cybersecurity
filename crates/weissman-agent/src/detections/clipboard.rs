//! Clipboard / screen-capture / insider-exfil sensing.
//!
//! Cross-platform clipboard reads require platform crates and may need a desktop session
//! (Wayland forbids background reads without portal consent). We capture *whatever the OS will
//! let us see without elevated permissions*: the size and entropy of the current clipboard text
//! contents (Linux X11 with `xsel`/`xclip` if installed, macOS `pbpaste`, Windows `Get-Clipboard`).
//!
//! Outputs an info finding always so SOC can see the agent collected.

use super::finding;
use serde_json::{json, Value};

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    let content = clipboard_text().await;
    let size = content.as_ref().map(|c| c.len()).unwrap_or(0);
    let entropy = content.as_deref().map(entropy_bits).unwrap_or(0.0);

    let mut extras = serde_json::Map::new();
    extras.insert("clipboard_size".into(), json!(size));
    extras.insert("entropy_bits_per_byte".into(), json!(entropy));
    extras.insert("source".into(), Value::String(clipboard_source()));

    let mut findings = vec![finding(
        engine,
        if size == 0 {
            "Clipboard empty or unreadable"
        } else {
            "Clipboard contents sampled"
        },
        "info",
        "T1115",
        &format!(
            "Agent observed the current clipboard buffer ({} byte(s), {:.2} bits-of-entropy/byte). Persistent very-high-entropy buffers are a soft indicator of credential capture.",
            size, entropy
        ),
        extras,
    )];

    if size > 1_000_000 {
        let extras2 = json_extras(json!({"size_bytes": size}));
        findings.push(finding(
            engine,
            "Clipboard contains unusually large payload",
            "medium",
            "T1115",
            "Clipboard buffer exceeds 1 MB — consistent with bulk-extraction of credentials/secrets.",
            extras2,
        ));
    }
    if size > 64 && entropy > 7.4 {
        let extras2 = json_extras(json!({"size_bytes": size, "entropy_bits_per_byte": entropy}));
        findings.push(finding(
            engine,
            "High-entropy clipboard content",
            "medium",
            "T1115",
            "Clipboard appears to hold encrypted / encoded data (entropy > 7.4). Investigate whether a paste-and-decrypt workflow is in use.",
            extras2,
        ));
    }
    Ok(findings)
}

fn clipboard_source() -> String {
    #[cfg(target_os = "linux")]
    {
        return "xsel/xclip (X11)".to_string();
    }
    #[cfg(target_os = "macos")]
    {
        return "pbpaste".to_string();
    }
    #[cfg(target_os = "windows")]
    {
        return "Get-Clipboard".to_string();
    }
    #[allow(unreachable_code)]
    "unknown".to_string()
}

async fn clipboard_text() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        for cmd in ["xsel", "xclip"] {
            let out = tokio::process::Command::new(cmd)
                .args(if cmd == "xsel" {
                    vec!["--clipboard", "--output"]
                } else {
                    vec!["-selection", "clipboard", "-out"]
                })
                .output()
                .await;
            if let Ok(o) = out {
                if o.status.success() {
                    return Some(String::from_utf8_lossy(&o.stdout).to_string());
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = tokio::process::Command::new("pbpaste").output().await {
            if o.status.success() {
                return Some(String::from_utf8_lossy(&o.stdout).to_string());
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(o) = tokio::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-Clipboard -Raw"])
            .output()
            .await
        {
            if o.status.success() {
                return Some(String::from_utf8_lossy(&o.stdout).to_string());
            }
        }
    }
    None
}

fn entropy_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let bytes = s.as_bytes();
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut h = 0.0;
    for c in counts.iter() {
        if *c == 0 {
            continue;
        }
        let p = (*c as f64) / total;
        h -= p * p.log2();
    }
    h
}

fn json_extras(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}
