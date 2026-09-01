//! Shared helpers for platform command execution and process enumeration.

use crate::hostobs;

pub async fn run_cmd(program: &str, args: &[&str]) -> Option<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

pub async fn run_cmd_lossy(program: &str, args: &[&str]) -> Option<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        None
    } else {
        Some(stdout.to_string())
    }
}

pub fn process_names_lower() -> Vec<String> {
    hostobs::list_processes_light()
        .into_iter()
        .map(|p| p.basename_lower())
        .collect()
}

pub fn any_process_matches(needles: &[&str]) -> Vec<String> {
    let names = process_names_lower();
    let mut hits = Vec::new();
    for needle in needles {
        let n = needle.to_ascii_lowercase();
        if names.iter().any(|p| p.contains(&n)) {
            hits.push((*needle).to_string());
        }
    }
    hits
}

pub async fn path_exists(path: &str) -> bool {
    tokio::fs::metadata(path).await.is_ok()
}

pub async fn dir_entry_names(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(mut rd) = tokio::fs::read_dir(path).await else {
        return out;
    };
    while let Ok(Some(entry)) = rd.next_entry().await {
        out.push(entry.file_name().to_string_lossy().to_string());
    }
    out
}

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}
