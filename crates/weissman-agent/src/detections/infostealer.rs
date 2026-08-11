//! Commodity infostealer blast-radius emulation — read-only host-resident collector.
//!
//! Models what RedLine / Lumma / StealC / Rhadamanthys-class stealers harvest: Chromium-family
//! credential stores, Firefox logins, messaging tokens, crypto wallets, SSH keys, VPN profiles,
//! and email client caches. **Never decrypts or exfiltrates secrets** — only reports which stores
//! exist, are readable, and their size so SOC can quantify blast radius before an incident.

use super::finding;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
struct Config {
    check_browsers: bool,
    check_chromium: bool,
    check_firefox: bool,
    check_crypto_wallets: bool,
    check_messaging: bool,
    check_ssh_keys: bool,
    check_vpn_profiles: bool,
    check_email_clients: bool,
    check_cloud_tokens: bool,
    max_sample_bytes: u64,
    intensity: String,
    custom_paths: Vec<String>,
    browser_profiles: Vec<String>,
    stealer_families: Vec<String>,
}

impl Config {
    fn from_params(params: &Value) -> Self {
        fn bool_or(v: &Value, key: &str, default: bool) -> bool {
            v.get(key)
                .or_else(|| v.get("options").and_then(|o| o.get(key)))
                .and_then(|x| match x {
                    Value::Bool(b) => Some(*b),
                    Value::String(s) => Some(matches!(
                        s.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )),
                    _ => None,
                })
                .unwrap_or(default)
        }
        fn str_or(v: &Value, key: &str, default: &str) -> String {
            v.get(key)
                .or_else(|| v.get("options").and_then(|o| o.get(key)))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| default.to_string())
        }
        fn str_list(v: &Value, key: &str) -> Vec<String> {
            let raw = v
                .get(key)
                .or_else(|| v.get("options").and_then(|o| o.get(key)));
            match raw {
                Some(Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|x| x.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                Some(Value::String(s)) => s
                    .split(['\n', ','])
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(str::to_string)
                    .collect(),
                _ => vec![],
            }
        }
        Self {
            check_browsers: bool_or(params, "check_browsers", true),
            check_chromium: bool_or(params, "check_chromium", true),
            check_firefox: bool_or(params, "check_firefox", true),
            check_crypto_wallets: bool_or(params, "check_crypto_wallets", true),
            check_messaging: bool_or(params, "check_messaging", true),
            check_ssh_keys: bool_or(params, "check_ssh_keys", true),
            check_vpn_profiles: bool_or(params, "check_vpn_profiles", true),
            check_email_clients: bool_or(params, "check_email_clients", true),
            check_cloud_tokens: bool_or(params, "check_cloud_tokens", true),
            max_sample_bytes: params
                .get("max_sample_bytes")
                .or_else(|| {
                    params
                        .get("options")
                        .and_then(|o| o.get("max_sample_bytes"))
                })
                .and_then(Value::as_u64)
                .unwrap_or(4096),
            intensity: str_or(params, "intensity", "normal"),
            custom_paths: str_list(params, "custom_paths"),
            browser_profiles: {
                let p = str_list(params, "browser_profiles");
                if p.is_empty() {
                    vec!["Default".into(), "Profile 1".into(), "Profile 2".into()]
                } else {
                    p
                }
            },
            stealer_families: {
                let f = str_list(params, "stealer_families");
                if f.is_empty() {
                    vec![
                        "RedLine".into(),
                        "Lumma".into(),
                        "StealC".into(),
                        "Rhadamanthys".into(),
                        "Raccoon".into(),
                        "Vidar".into(),
                    ]
                } else {
                    f
                }
            },
        }
    }
}

#[derive(Clone, Debug, Default)]
struct StoreHit {
    category: &'static str,
    label: String,
    path: PathBuf,
    size_bytes: u64,
    readable: bool,
    severity: &'static str,
    mitre: &'static str,
    detail: String,
}

fn home_dir() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("HOME") {
        return Some(PathBuf::from(h));
    }
    if let Ok(h) = std::env::var("USERPROFILE") {
        return Some(PathBuf::from(h));
    }
    None
}

fn local_app_data() -> Option<PathBuf> {
    std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)
}

fn app_data() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(PathBuf::from)
}

/// Probe a candidate credential store: how big is it, and can this agent read it?
///
/// The read is bounded. This used to call `tokio::fs::read(path)` — slurping the ENTIRE file into
/// memory purely to compare its length against `max_bytes`, a number it already had from
/// `metadata()`. Since `custom_paths` comes straight through the dispatch API, an operator (or
/// anyone who compromises the server) could point every agent in the fleet at a multi-gigabyte
/// file and OOM-kill the whole fleet, repeatedly. Opening and reading one byte answers the actual
/// question — "can we open this?" — at fixed cost.
async fn probe_path(path: &Path, max_bytes: u64) -> (u64, bool) {
    use tokio::io::AsyncReadExt;

    let meta = match tokio::fs::metadata(path).await {
        Ok(m) => m,
        Err(_) => return (0, false),
    };
    let size = meta.len();
    if meta.is_dir() {
        return (size, true);
    }
    if !meta.is_file() {
        return (size, false);
    }
    // Same semantics as before — a file bigger than the sample budget counts as not readable —
    // but decided from the size we already have instead of by reading the file.
    if size > max_bytes.max(1) {
        return (size, false);
    }
    let readable = match tokio::fs::File::open(path).await {
        // A zero-length file is still readable; read_exact would report UnexpectedEof.
        Ok(_) if size == 0 => true,
        Ok(mut f) => {
            let mut probe = [0u8; 1];
            f.read_exact(&mut probe).await.is_ok()
        }
        Err(_) => false,
    };
    (size, readable)
}

fn push_chromium_family(
    hits: &mut Vec<StoreHit>,
    browser: &str,
    base: PathBuf,
    profiles: &[String],
    artifacts: &[(&str, &str, &'static str)],
) {
    for profile in profiles {
        let profile_dir = base.join(profile);
        for (file, label_suffix, sev) in artifacts {
            let p = profile_dir.join(file);
            // Carry the per-artifact severity and description through instead of discarding them —
            // otherwise every Chromium artifact (including `History`) shipped as `critical` via the
            // post-probe fallback, drowning the genuinely critical Login Data / Local State signals.
            hits.push(StoreHit {
                category: "browser",
                label: format!("{browser} {label_suffix}"),
                path: p,
                severity: sev,
                mitre: "T1555.003",
                detail: (*label_suffix).to_string(),
                ..Default::default()
            });
        }
    }
}

fn collect_candidate_paths(cfg: &Config) -> Vec<StoreHit> {
    let mut hits: Vec<StoreHit> = Vec::new();
    let home = home_dir();
    let local = local_app_data();
    let roaming = app_data();

    let chromium_artifacts: &[(&str, &str, &'static str)] = &[
        ("Login Data", "saved passwords (Login Data)", "critical"),
        ("Cookies", "session cookies", "critical"),
        ("Web Data", "autofill / payment cards", "high"),
        ("History", "browsing history", "medium"),
        ("Local State", "DPAPI/AES key envelope", "critical"),
    ];

    if cfg.check_browsers && cfg.check_chromium {
        if let Some(ref l) = local {
            for (browser, sub) in [
                ("Chrome", "Google/Chrome/User Data"),
                ("Edge", "Microsoft/Edge/User Data"),
                ("Brave", "BraveSoftware/Brave-Browser/User Data"),
                ("Opera", "Opera Software/Opera Stable"),
                ("Vivaldi", "Vivaldi/User Data"),
            ] {
                push_chromium_family(
                    &mut hits,
                    browser,
                    l.join(sub),
                    &cfg.browser_profiles,
                    chromium_artifacts,
                );
            }
        }
        if let Some(ref h) = home {
            #[cfg(target_os = "macos")]
            {
                for (browser, sub) in [
                    ("Chrome", "Library/Application Support/Google/Chrome"),
                    ("Edge", "Library/Application Support/Microsoft Edge"),
                    (
                        "Brave",
                        "Library/Application Support/BraveSoftware/Brave-Browser",
                    ),
                ] {
                    push_chromium_family(
                        &mut hits,
                        browser,
                        h.join(sub),
                        &cfg.browser_profiles,
                        chromium_artifacts,
                    );
                }
            }
            #[cfg(target_os = "linux")]
            {
                for (browser, sub) in [
                    ("Chrome", ".config/google-chrome"),
                    ("Chromium", ".config/chromium"),
                    ("Brave", ".config/BraveSoftware/Brave-Browser"),
                ] {
                    push_chromium_family(
                        &mut hits,
                        browser,
                        h.join(sub),
                        &cfg.browser_profiles,
                        chromium_artifacts,
                    );
                }
            }
        }
    }

    if cfg.check_browsers && cfg.check_firefox {
        let firefox_roots: Vec<PathBuf> = {
            let mut roots = Vec::new();
            if let Some(ref r) = roaming {
                roots.push(r.join("Mozilla/Firefox/Profiles"));
            }
            if let Some(ref h) = home {
                roots.push(h.join(".mozilla/firefox"));
                #[cfg(target_os = "macos")]
                roots.push(h.join("Library/Application Support/Firefox/Profiles"));
            }
            roots
        };
        for root in firefox_roots {
            hits.push(StoreHit {
                category: "browser",
                label: "Firefox logins.json".into(),
                path: root.join("logins.json"),
                severity: "critical",
                mitre: "T1555.003",
                detail: "Firefox password store".into(),
                ..Default::default()
            });
            hits.push(StoreHit {
                category: "browser",
                label: "Firefox cookies.sqlite".into(),
                path: root.join("cookies.sqlite"),
                severity: "critical",
                mitre: "T1539",
                detail: "Firefox session cookies".into(),
                ..Default::default()
            });
            hits.push(StoreHit {
                category: "browser",
                label: "Firefox key4.db".into(),
                path: root.join("key4.db"),
                severity: "high",
                mitre: "T1555.003",
                detail: "Firefox master-key database".into(),
                ..Default::default()
            });
        }
    }

    if cfg.check_messaging {
        if let Some(ref r) = roaming {
            for (app, sub, sev) in [
                ("Discord", "discord/Local Storage/leveldb", "critical"),
                ("Slack", "Slack/storage", "high"),
                ("Signal", "Signal/config.json", "high"),
                ("Telegram", "Telegram Desktop/tdata", "critical"),
            ] {
                hits.push(StoreHit {
                    category: "messaging",
                    label: format!("{app} token store"),
                    path: r.join(sub),
                    severity: sev,
                    mitre: "T1528",
                    detail: format!("{app} session / token cache"),
                    ..Default::default()
                });
            }
        }
        if let Some(ref h) = home {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                hits.push(StoreHit {
                    category: "messaging",
                    label: "Telegram tdata".into(),
                    path: h.join(".local/share/TelegramDesktop/tdata"),
                    severity: "critical",
                    mitre: "T1528",
                    detail: "Telegram desktop session".into(),
                    ..Default::default()
                });
            }
        }
    }

    if cfg.check_crypto_wallets {
        let wallet_paths: Vec<(&str, PathBuf, &'static str)> = {
            let mut w = Vec::new();
            if let Some(ref h) = home {
                w.push(("Exodus", h.join(".config/Exodus/exodus.wallet"), "critical"));
                w.push(("Electrum", h.join(".electrum/wallets"), "critical"));
                w.push(("MetaMask (ext)", h.join(".config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"), "critical"));
                #[cfg(target_os = "windows")]
                if let Some(ref r) = roaming {
                    w.push(("Exodus", r.join("Exodus/exodus.wallet"), "critical"));
                    w.push(("Atomic", r.join("atomic/Local Storage/leveldb"), "high"));
                }
            }
            w
        };
        for (name, path, sev) in wallet_paths {
            hits.push(StoreHit {
                category: "crypto",
                label: format!("{name} wallet"),
                path,
                severity: sev,
                mitre: "T1555",
                detail: format!("{name} cryptocurrency wallet / extension store"),
                ..Default::default()
            });
        }
    }

    if cfg.check_ssh_keys {
        if let Some(ref h) = home {
            for name in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"] {
                hits.push(StoreHit {
                    category: "ssh",
                    label: format!("SSH private key ({name})"),
                    path: h.join(".ssh").join(name),
                    severity: "critical",
                    mitre: "T1552.004",
                    detail: "SSH private key file".into(),
                    ..Default::default()
                });
            }
        }
    }

    if cfg.check_vpn_profiles {
        if let Some(ref h) = home {
            hits.push(StoreHit {
                category: "vpn",
                label: "OpenVPN profiles".into(),
                path: h.join(".openvpn"),
                severity: "high",
                mitre: "T1552",
                detail: "OpenVPN configuration / credentials".into(),
                ..Default::default()
            });
            hits.push(StoreHit {
                category: "vpn",
                label: "WireGuard config".into(),
                path: h.join(".config/wireguard"),
                severity: "high",
                mitre: "T1552",
                detail: "WireGuard tunnel keys".into(),
                ..Default::default()
            });
        }
    }

    if cfg.check_email_clients {
        if let Some(ref r) = roaming {
            hits.push(StoreHit {
                category: "email",
                label: "Outlook OST cache".into(),
                path: r.join("Microsoft/Outlook"),
                severity: "high",
                mitre: "T1114",
                detail: "Outlook offline cache".into(),
                ..Default::default()
            });
        }
        if let Some(ref h) = home {
            hits.push(StoreHit {
                category: "email",
                label: "Thunderbird profile".into(),
                path: h.join(".thunderbird"),
                severity: "high",
                mitre: "T1114",
                detail: "Thunderbird mail store".into(),
                ..Default::default()
            });
        }
    }

    if cfg.check_cloud_tokens {
        if let Some(ref h) = home {
            for (label, sub) in [
                ("AWS CLI credentials", ".aws/credentials"),
                ("Azure CLI token cache", ".azure/msal_token_cache.json"),
                ("gcloud credentials", ".config/gcloud/credentials.db"),
                ("kubectl config", ".kube/config"),
                ("GitHub CLI token", ".config/gh/hosts.yml"),
                ("npm token", ".npmrc"),
                ("Docker config", ".docker/config.json"),
            ] {
                hits.push(StoreHit {
                    category: "cloud",
                    label: label.into(),
                    path: h.join(sub),
                    severity: "critical",
                    mitre: "T1528",
                    detail: format!("{label} on disk"),
                    ..Default::default()
                });
            }
        }
    }

    // `custom_paths` arrives unvalidated from POST /api/agents/dispatch, so this list is
    // attacker-influenced the moment the server is. Each entry has the agent stat a path and
    // report its size and existence, which makes an unbounded list a fleet-wide
    // file-existence-and-size oracle for anything the agent can see — reachable with no host
    // access at all. Capping the count does not make it an allow-list, but it bounds both the
    // oracle and the per-task work; combined with the bounded read in `probe_path`, a hostile
    // params blob can no longer turn the fleet into a scanner or OOM it.
    const MAX_CUSTOM_PATHS: usize = 32;
    if cfg.custom_paths.len() > MAX_CUSTOM_PATHS {
        tracing::warn!(
            target: "agent",
            supplied = cfg.custom_paths.len(),
            cap = MAX_CUSTOM_PATHS,
            "infostealer custom_paths truncated"
        );
    }
    for custom in cfg.custom_paths.iter().take(MAX_CUSTOM_PATHS) {
        hits.push(StoreHit {
            category: "custom",
            label: format!("Custom path: {}", custom),
            path: PathBuf::from(custom),
            severity: "high",
            mitre: "T1555",
            detail: "Operator-supplied secret store".into(),
            ..Default::default()
        });
    }

    hits
}

fn blast_radius_score(accessible: &[&StoreHit], intensity: &str) -> u32 {
    let mut score: u32 = 0;
    for h in accessible {
        score += match h.category {
            "browser" => 12,
            "crypto" => 15,
            "messaging" => 10,
            "ssh" => 14,
            "cloud" => 13,
            "vpn" => 8,
            "email" => 7,
            _ => 5,
        };
        if h.severity == "critical" {
            score += 3;
        }
    }
    let cap = match intensity {
        "deep" => 100,
        "quick" => 60,
        _ => 85,
    };
    score.min(cap)
}

fn grade_from_score(score: u32) -> &'static str {
    match score {
        0..=15 => "A",
        16..=35 => "B",
        36..=55 => "C",
        56..=75 => "D",
        _ => "F",
    }
}

pub async fn run(
    engine: &str,
    _target: Option<&str>,
    params: &Value,
) -> anyhow::Result<Vec<Value>> {
    let cfg = Config::from_params(params);
    let candidates = collect_candidate_paths(&cfg);
    let mut probed: Vec<StoreHit> = Vec::new();

    for mut hit in candidates {
        let (size, readable) = probe_path(&hit.path, cfg.max_sample_bytes).await;
        if !hit.path.exists() && size == 0 && !readable {
            continue;
        }
        hit.size_bytes = size;
        hit.readable = readable;
        if hit.severity.is_empty() {
            hit.severity = if readable { "critical" } else { "medium" };
        }
        if hit.mitre.is_empty() {
            hit.mitre = "T1555";
        }
        probed.push(hit);
    }

    // Firefox profile glob — expand directories that exist
    if cfg.check_firefox {
        let mut expanded = Vec::new();
        for hit in probed.drain(..) {
            if hit.label.starts_with("Firefox") && hit.path.parent().is_some() {
                let parent = hit.path.parent().unwrap().to_path_buf();
                if parent.is_dir() {
                    if let Ok(mut rd) = tokio::fs::read_dir(&parent).await {
                        while let Ok(Some(entry)) = rd.next_entry().await {
                            let p = entry.path();
                            if !p.is_dir() {
                                continue;
                            }
                            let candidate = p.join(hit.path.file_name().unwrap_or_default());
                            if candidate.exists() {
                                let (size, readable) =
                                    probe_path(&candidate, cfg.max_sample_bytes).await;
                                expanded.push(StoreHit {
                                    category: hit.category,
                                    label: format!(
                                        "{} ({})",
                                        hit.label,
                                        p.file_name().unwrap_or_default().to_string_lossy()
                                    ),
                                    path: candidate,
                                    size_bytes: size,
                                    readable,
                                    severity: hit.severity,
                                    mitre: hit.mitre,
                                    detail: hit.detail.clone(),
                                });
                            }
                        }
                    }
                }
            }
            expanded.push(hit);
        }
        probed = expanded;
    }

    let accessible: Vec<&StoreHit> = probed.iter().filter(|h| h.readable).collect();
    let mut findings: Vec<Value> = Vec::new();

    for hit in &probed {
        if !hit.readable {
            continue;
        }
        let mut extras = Map::new();
        extras.insert("category".into(), json!(hit.category));
        extras.insert("path".into(), json!(hit.path.display().to_string()));
        extras.insert("size_bytes".into(), json!(hit.size_bytes));
        extras.insert("readable".into(), json!(true));
        extras.insert(
            "stealer_relevance".into(),
            json!(format!(
                "Commodity stealers ({}) harvest this store in initial access phase",
                cfg.stealer_families.join(", ")
            )),
        );
        findings.push(finding(
            engine,
            &format!("Accessible secret store: {}", hit.label),
            hit.severity,
            hit.mitre,
            &format!(
                "{} at {} ({} bytes, read verified). {}",
                hit.label,
                hit.path.display(),
                hit.size_bytes,
                hit.detail
            ),
            extras,
        ));
    }

    let score = blast_radius_score(&accessible, &cfg.intensity);
    let grade = grade_from_score(score);
    let mut summary_extras = Map::new();
    summary_extras.insert("blast_radius_score".into(), json!(score));
    summary_extras.insert("grade".into(), json!(grade));
    summary_extras.insert("accessible_stores".into(), json!(accessible.len()));
    summary_extras.insert("total_candidates".into(), json!(probed.len()));
    summary_extras.insert(
        "categories".into(),
        json!(accessible
            .iter()
            .map(|h| h.category)
            .collect::<std::collections::BTreeSet<_>>()),
    );
    summary_extras.insert("stealer_families".into(), json!(cfg.stealer_families));
    summary_extras.insert("intensity".into(), json!(cfg.intensity));
    summary_extras.insert("hostname".into(), json!(hostname::get()?.to_string_lossy()));
    summary_extras.insert("username".into(), json!(whoami::username()));

    findings.insert(
        0,
        finding(
            engine,
            &format!("Infostealer blast-radius grade {grade} ({score}/100)"),
            if score >= 56 {
                "critical"
            } else if score >= 36 {
                "high"
            } else if score >= 16 {
                "medium"
            } else {
                "info"
            },
            "T1555",
            &format!(
                "Agent verified {} accessible secret store(s) across {} categories. \
                 Score models commodity infostealer harvest ({} family reference). \
                 Grade {grade} — higher = more attacker-accessible credential surface.",
                accessible.len(),
                summary_extras
                    .get("categories")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0),
                cfg.stealer_families.join(", ")
            ),
            summary_extras,
        ),
    );

    if findings.len() <= 1 && accessible.is_empty() {
        let mut extras = Map::new();
        extras.insert("accessible_stores".into(), json!(0));
        extras.insert("stealer_families".into(), json!(cfg.stealer_families));
        findings.push(finding(
            engine,
            "No accessible secret stores detected",
            "info",
            "T1555",
            "Agent completed read-only infostealer blast-radius scan — no high-value credential stores were readable with current permissions.",
            extras,
        ));
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_monotonic() {
        assert_eq!(grade_from_score(0), "A");
        assert_eq!(grade_from_score(80), "F");
    }

    #[test]
    fn config_defaults() {
        let cfg = Config::from_params(&json!({}));
        assert!(cfg.check_browsers);
        assert!(!cfg.stealer_families.is_empty());
    }

    /// `probe_path` must not read the file to decide readability.
    ///
    /// The old implementation called `tokio::fs::read` on an operator-supplied path, so a large
    /// file OOM-killed the agent. This asserts the two properties that matter: an oversized file
    /// is reported not-readable (unchanged semantics) and the call stays cheap regardless of size.
    #[tokio::test]
    async fn probe_path_does_not_slurp_large_files() {
        let dir = std::env::temp_dir().join(format!("weissman-infostealer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        // 8 MiB — small enough for CI, far above the 4096-byte default sample budget.
        let big = dir.join("big.bin");
        std::fs::write(&big, vec![0u8; 8 * 1024 * 1024]).expect("write big");
        let started = std::time::Instant::now();
        let (size, readable) = probe_path(&big, 4096).await;
        let elapsed = started.elapsed();
        assert_eq!(size, 8 * 1024 * 1024, "size still comes from metadata");
        assert!(!readable, "a file larger than the sample budget is not 'readable'");
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "probe took {elapsed:?} — it is still reading the whole file"
        );

        // A small file within budget is readable, and an empty one is too.
        let small = dir.join("small.bin");
        std::fs::write(&small, b"cookies").expect("write small");
        let (ssize, sreadable) = probe_path(&small, 4096).await;
        assert_eq!(ssize, 7);
        assert!(sreadable, "a file within budget must read as readable");

        let empty = dir.join("empty.bin");
        std::fs::write(&empty, b"").expect("write empty");
        let (esize, ereadable) = probe_path(&empty, 4096).await;
        assert_eq!(esize, 0);
        assert!(ereadable, "an empty file is readable, not a read_exact EOF failure");

        // A path that does not exist reports nothing.
        let (msize, mreadable) = probe_path(&dir.join("nope"), 4096).await;
        assert_eq!((msize, mreadable), (0, false));

        let _ = std::fs::remove_dir_all(&dir);
    }

}