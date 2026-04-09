//! Dynamic signature engine: load payload → expected_signature rules from config.
//! Global cache with 60s timer: check file mtime at most once per 60s to avoid I/O throttle.

use regex::Regex;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

const MTIME_CHECK_INTERVAL_SECS: u64 = 60;

#[derive(Clone, Debug, Deserialize)]
pub struct PayloadSignatureRule {
    pub payload: String,
    pub expected_signature: String,
}

#[derive(Clone)]
struct CachedRules {
    path: PathBuf,
    mtime: Option<SystemTime>,
    rules: Vec<PayloadSignatureRule>,
    last_check: SystemTime,
}

static CACHE: Mutex<Option<CachedRules>> = Mutex::new(None);

fn file_modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

fn now() -> SystemTime {
    SystemTime::now()
}

fn elapsed_since(t: SystemTime) -> Option<Duration> {
    now().duration_since(t).ok()
}

/// Load rules from JSON. Only checks file mtime once every 60s; otherwise returns in-memory cache (no disk I/O).
pub fn load_signature_rules() -> Vec<PayloadSignatureRule> {
    {
        let guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref cached) = *guard {
            if elapsed_since(cached.last_check)
                .map(|d| d.as_secs() < MTIME_CHECK_INTERVAL_SECS)
                .unwrap_or(false)
            {
                return cached.rules.clone();
            }
        }
    }
    let paths = signature_config_paths();
    for path in &paths {
        if !path.exists() {
            continue;
        }
        let mtime = file_modified(path);
        {
            let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref mut cached) = *guard {
                if cached.path == *path && cached.mtime == mtime {
                    cached.last_check = now();
                    return cached.rules.clone();
                }
            }
        }
        if let Some(rules) = load_from_path(path) {
            let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(CachedRules {
                path: path.clone(),
                mtime,
                rules: rules.clone(),
                last_check: now(),
            });
            return rules;
        }
    }
    default_rules()
}

fn signature_config_paths() -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = std::env::var("WEISSMAN_PAYLOAD_SIGNATURES") {
        out.push(std::path::PathBuf::from(p));
    }
    if let Ok(cwd) = std::env::current_dir() {
        out.push(cwd.join("config").join("payload_signatures.json"));
        out.push(cwd.join("payload_signatures.json"));
        out.push(
            cwd.join("..")
                .join("config")
                .join("payload_signatures.json"),
        );
        out.push(cwd.join("..").join("payload_signatures.json"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            out.push(parent.join("config").join("payload_signatures.json"));
            out.push(parent.join("payload_signatures.json"));
            if let Some(grandparent) = parent.parent() {
                out.push(grandparent.join("config").join("payload_signatures.json"));
                out.push(
                    grandparent
                        .join("fingerprint_engine")
                        .join("config")
                        .join("payload_signatures.json"),
                );
            }
        }
    }
    out
}

fn load_from_path(path: &Path) -> Option<Vec<PayloadSignatureRule>> {
    let data = std::fs::read_to_string(path).ok()?;
    let rules: Vec<PayloadSignatureRule> = serde_json::from_str(&data).ok()?;
    if rules.is_empty() {
        return None;
    }
    Some(rules)
}

/// Embedded default rules if no config file found (LFI + one SQLi example).
fn default_rules() -> Vec<PayloadSignatureRule> {
    vec![
        PayloadSignatureRule {
            payload: "../".to_string(),
            expected_signature: "root:x:|root:\\*:0:0|root::0:0:".to_string(),
        },
        PayloadSignatureRule {
            payload: "etc/passwd".to_string(),
            expected_signature: "root:x:|root:\\*:0:0|root::0:0:".to_string(),
        },
    ]
}

/// Find the first rule whose payload is contained in the fuzzer payload (or exact match).
pub fn find_matching_rule<'a>(
    fuzzer_payload: &str,
    rules: &'a [PayloadSignatureRule],
) -> Option<&'a PayloadSignatureRule> {
    let lower = fuzzer_payload.to_lowercase();
    for rule in rules {
        let rp = rule.payload.to_lowercase();
        if rp.is_empty() {
            continue;
        }
        if lower.contains(&rp) || rp.contains(&lower) {
            return Some(rule);
        }
    }
    None
}

/// Check if response body matches the expected_signature (regex or literal).
pub fn response_matches_signature(body: &str, expected_signature: &str) -> bool {
    if expected_signature.is_empty() {
        return false;
    }
    if let Ok(re) = Regex::new(expected_signature) {
        if re.is_match(body) {
            return true;
        }
    }
    body.contains(expected_signature)
}
