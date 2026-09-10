//! IOC / hash / substring hunt on the local filesystem (YARA-like, no fake hits).

use super::finding;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

pub async fn run(engine: &str, params: &Value) -> anyhow::Result<Vec<Value>> {
    let mut findings = Vec::new();
    let hashes: Vec<String> = params
        .get("sha256")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                .collect()
        })
        .unwrap_or_default();
    let needles: Vec<String> = params
        .get("strings")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .filter(|s| s.len() >= 4)
                .collect()
        })
        .unwrap_or_default();
    let roots = ["/tmp", "/var/tmp", "/home"];
    if hashes.is_empty() && needles.is_empty() {
        findings.push(finding(
            engine,
            "IOC hunt idle — no sha256 or strings in task params",
            "info",
            "T1083",
            "Dispatch this engine with params.sha256[] and/or params.strings[] from the threat-intel feed.",
            json_map(json!({})),
        ));
        return Ok(findings);
    }

    let mut scanned = 0u32;
    for root in roots {
        let Ok(mut rd) = tokio::fs::read_dir(root).await else {
            continue;
        };
        while let Ok(Some(ent)) = rd.next_entry().await {
            if scanned > 400 {
                break;
            }
            let path = ent.path();
            if !path.is_file() {
                continue;
            }
            scanned += 1;
            if let Ok(bytes) = tokio::fs::read(&path).await {
                if bytes.len() > 8_000_000 {
                    continue;
                }
                if !hashes.is_empty() {
                    let digest = hex::encode(Sha256::digest(&bytes));
                    if hashes.iter().any(|h| *h == digest) {
                        findings.push(finding(
                            engine,
                            "SHA-256 IOC matched on disk",
                            "critical",
                            "T1083",
                            &format!("{} hashed to {digest}", path.display()),
                            json_map(json!({ "path": path.display().to_string(), "sha256": digest })),
                        ));
                    }
                }
                if !needles.is_empty() {
                    if let Ok(txt) = std::str::from_utf8(&bytes) {
                        for n in &needles {
                            if txt.contains(n) {
                                findings.push(finding(
                                    engine,
                                    "String IOC matched on disk",
                                    "high",
                                    "T1083",
                                    &format!("{} contains needle (len {})", path.display(), n.len()),
                                    json_map(json!({ "path": path.display().to_string() })),
                                ));
                            }
                        }
                    }
                }
            }
            let _ = Path::new(&path);
        }
    }
    if findings.is_empty() {
        findings.push(finding(
            engine,
            "IOC hunt completed with no matches",
            "info",
            "T1083",
            &format!("Scanned {scanned} files under /tmp /var/tmp /home."),
            json_map(json!({ "scanned": scanned })),
        ));
    }
    Ok(findings)
}

fn json_map(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}
