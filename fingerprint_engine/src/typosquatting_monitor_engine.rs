//! Software Supply-Chain Typosquatting & Dependency-Confusion Monitor — world-class, real-probe.
//!
//! Inspired by the dependency-security platforms that define the category (Socket.dev, Snyk,
//! Phylum, GitHub/Dependabot). It hunts the two dominant package-ecosystem supply-chain attacks
//! against a target's brand, using **live public-registry queries only** — every finding is backed
//! by a real HTTP response from npm/PyPI/crates.io/RubyGems; nothing is simulated:
//!
//!   * **Typosquatting (flagship)** — generates the full typo-permutation space of the target's
//!     package name(s) (omission, repetition, transposition, keyboard-adjacent, homoglyph,
//!     separator and affix squats) and confirms which permutations are *actually registered* on the
//!     public registries. Registered squats are escalated when **recently published** or when they
//!     ship **install hooks** (`preinstall`/`install`/`postinstall`) — the hallmark of a live
//!     malicious package.
//!   * **Dependency confusion (Alex-Birsan class)** — for operator-supplied internal/private
//!     package names, checks whether the public registry namespace is unclaimed (an attacker can
//!     publish a higher-version public package your build will silently pull) or already taken by a
//!     third party.
//!
//! ### Wiz-style differentiators
//!   * **Attack-path synthesis** — confirmed squats/confusion become ordered supply-chain kill chains.
//!   * **Posture score** — a quantified 0–100 supply-chain-hygiene grade from observed registrations.
//!
//! Every knob (package names, ecosystems, permutation strategies, recency window, install-hook check,
//! dependency-confusion list, intensity, caps, timeout, concurrency) is GUI-driven via
//! [`ArsenalConfig`] (`POST /api/command-center/scan` → `EngineRunContext::job_params`).
//!
//! MITRE ATT&CK: T1195.002 (Compromise Software Supply Chain), T1195.001 (Compromise Software
//! Dependencies and Development Tools).

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, http_get};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Duration;

const ENGINE_ID: &str = "typosquatting_monitor";

const T_SUPPLY_CHAIN: &str = "T1195.002"; // Compromise Software Supply Chain
const T_DEPENDENCIES: &str = "T1195.001"; // Compromise Software Dependencies and Development Tools

const DEFAULT_ECOSYSTEMS: &[&str] = &["npm", "pypi"];
const DEFAULT_AFFIXES: &[&str] = &[
    "js", "-js", ".js", "cli", "-cli", "core", "-core", "lib", "-lib", "node", "node-", "py", "py-",
    "python-", "sdk", "-sdk", "api", "-api", "2", "official", "-official", "app", "-app",
];

// ── Per-package registry observation ────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
struct PkgInfo {
    ecosystem: String,
    name: String,
    exists: bool,
    created: Option<String>,
    recent: bool,
    install_scripts: bool,
    versions: u64,
    url: String,
}

#[derive(Default, Clone)]
struct SupplyPosture {
    registered_squats: Vec<String>,
    malicious_indicators: usize, // squats with install hooks
    recent_squats: usize,
    confusion_unclaimed: Vec<String>,
    confusion_taken: Vec<String>,
    checks: u32,
}

impl SupplyPosture {
    fn score(&self) -> u32 {
        let mut s: i32 = 100;
        s -= (self.registered_squats.len() as i32).min(8) * 6;
        s -= (self.malicious_indicators as i32).min(5) * 14;
        s -= (self.recent_squats as i32).min(6) * 5;
        s -= (self.confusion_unclaimed.len() as i32).min(6) * 10;
        s -= (self.confusion_taken.len() as i32).min(6) * 8;
        s.clamp(0, 100) as u32
    }

    fn grade(&self) -> &'static str {
        match self.score() {
            90..=100 => "A",
            75..=89 => "B",
            55..=74 => "C",
            35..=54 => "D",
            _ => "F",
        }
    }

    fn has_any(&self) -> bool {
        !self.registered_squats.is_empty()
            || !self.confusion_unclaimed.is_empty()
            || !self.confusion_taken.is_empty()
    }
}

// ── Permutation engine ──────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct TypoStrategies {
    omission: bool,
    repetition: bool,
    transposition: bool,
    replacement: bool,
    insertion: bool,
    separator: bool,
    affix: bool,
    homoglyph: bool,
}

impl TypoStrategies {
    fn for_intensity(i: Intensity) -> Self {
        match i {
            Intensity::Light => TypoStrategies {
                omission: true,
                repetition: false,
                transposition: true,
                replacement: false,
                insertion: false,
                separator: true,
                affix: true,
                homoglyph: true,
            },
            _ => TypoStrategies {
                omission: true,
                repetition: true,
                transposition: true,
                replacement: true,
                insertion: i == Intensity::Aggressive,
                separator: true,
                affix: true,
                homoglyph: true,
            },
        }
    }
}

fn qwerty_adjacent(c: char) -> &'static str {
    match c {
        'q' => "wa", 'w' => "qeas", 'e' => "wrsd", 'r' => "etdf", 't' => "ryfg", 'y' => "tugh",
        'u' => "yihj", 'i' => "uojk", 'o' => "ipkl", 'p' => "ol",
        'a' => "qwsz", 's' => "wedxza", 'd' => "erfcxs", 'f' => "rtgvcd", 'g' => "tyhbvf",
        'h' => "yujnbg", 'j' => "uikmnh", 'k' => "iolmj", 'l' => "opk",
        'z' => "asx", 'x' => "sdcz", 'c' => "dfvx", 'v' => "fgbc", 'b' => "ghnv", 'n' => "hjmb",
        'm' => "jkn",
        _ => "",
    }
}

fn homoglyphs(c: char) -> &'static str {
    match c {
        'o' => "0", '0' => "o", 'l' => "1i", 'i' => "1l", '1' => "li", 'e' => "3", '3' => "e",
        'a' => "4", '4' => "a", 's' => "5", '5' => "s", 'b' => "8", '8' => "b", 'g' => "9",
        't' => "7", 'z' => "2", '2' => "z",
        _ => "",
    }
}

fn valid_pkg_name(s: &str) -> bool {
    let s = s.trim();
    s.len() >= 2
        && s.len() <= 100
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.')
}

fn generate_typos(base: &str, st: &TypoStrategies, affixes: &[String], cap: usize) -> Vec<String> {
    let b = base.trim().to_ascii_lowercase();
    let chars: Vec<char> = b.chars().collect();
    let mut out: BTreeSet<String> = BTreeSet::new();

    if st.omission {
        for i in 0..chars.len() {
            let mut s = chars.clone();
            s.remove(i);
            out.insert(s.into_iter().collect());
        }
    }
    if st.repetition {
        for i in 0..chars.len() {
            let mut s = chars.clone();
            s.insert(i, chars[i]);
            out.insert(s.into_iter().collect());
        }
    }
    if st.transposition {
        for i in 0..chars.len().saturating_sub(1) {
            let mut s = chars.clone();
            s.swap(i, i + 1);
            out.insert(s.into_iter().collect());
        }
    }
    if st.replacement {
        for (i, &c) in chars.iter().enumerate() {
            for r in qwerty_adjacent(c).chars() {
                let mut s = chars.clone();
                s[i] = r;
                out.insert(s.into_iter().collect());
            }
        }
    }
    if st.insertion {
        for i in 0..chars.len() {
            for r in qwerty_adjacent(chars[i]).chars() {
                let mut s = chars.clone();
                s.insert(i, r);
                out.insert(s.into_iter().collect());
            }
        }
    }
    if st.homoglyph {
        for (i, &c) in chars.iter().enumerate() {
            for r in homoglyphs(c).chars() {
                let mut s = chars.clone();
                s[i] = r;
                out.insert(s.into_iter().collect());
            }
        }
    }
    if st.separator {
        out.insert(b.replace('-', "_"));
        out.insert(b.replace('_', "-"));
        out.insert(b.replace(['-', '_'], ""));
        // hyphenate at a single internal boundary
        if chars.len() > 3 {
            let mid = chars.len() / 2;
            let mut s = chars.clone();
            s.insert(mid, '-');
            out.insert(s.into_iter().collect());
        }
    }
    if st.affix {
        for a in affixes {
            out.insert(format!("{}{}", b, a));
            out.insert(format!("{}-{}", b, a));
            out.insert(format!("{}{}", a, b));
        }
    }

    out.remove(&b);
    out.into_iter().filter(|s| valid_pkg_name(s)).take(cap).collect()
}

fn base_package_names(host: &str) -> Vec<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = h.split('.').filter(|s| !s.is_empty()).collect();
    let mut out = Vec::new();
    if let Some(first) = labels.first() {
        if first.len() >= 2 && *first != "www" {
            out.push((*first).to_string());
        }
    }
    if labels.len() >= 2 {
        out.push(labels[..labels.len() - 1].join("-"));
        out.push(labels[..labels.len() - 1].join(""));
    }
    out.retain(|s| s.len() >= 2);
    out.sort();
    out.dedup();
    out
}

// ── Live registry queries ───────────────────────────────────────────────────────

fn build_client(timeout_ms: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms.clamp(800, 30_000)))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-SupplyChain/2.0 (+typosquat-monitor)")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn is_recent(iso: &str, days: i64) -> bool {
    chrono::DateTime::parse_from_rfc3339(iso.trim())
        .map(|dt| {
            let age = chrono::Utc::now() - dt.with_timezone(&chrono::Utc);
            age.num_days() >= 0 && age.num_days() <= days
        })
        .unwrap_or(false)
}

async fn check_npm(client: &reqwest::Client, name: &str, recent_days: i64) -> Option<PkgInfo> {
    let enc = name.replace('/', "%2f");
    let url = format!("https://registry.npmjs.org/{}", enc);
    let p = http_get(client, &url).await?;
    let mut info = PkgInfo {
        ecosystem: "npm".into(),
        name: name.to_string(),
        url: url.clone(),
        ..Default::default()
    };
    if p.status == 404 {
        return Some(info);
    }
    if p.status != 200 {
        return None;
    }
    let v: Value = serde_json::from_str(&p.body).ok()?;
    if v.get("error").is_some() {
        return Some(info);
    }
    info.exists = true;
    info.created = v
        .get("time")
        .and_then(|t| t.get("created"))
        .and_then(Value::as_str)
        .map(str::to_string);
    info.recent = info.created.as_deref().map(|c| is_recent(c, recent_days)).unwrap_or(false);
    let latest = v.get("dist-tags").and_then(|d| d.get("latest")).and_then(Value::as_str);
    info.install_scripts = latest
        .and_then(|lv| v.get("versions").and_then(|vs| vs.get(lv)).and_then(|ver| ver.get("scripts")))
        .map(|s| ["preinstall", "install", "postinstall"].iter().any(|k| s.get(*k).is_some()))
        .unwrap_or(false);
    info.versions = v
        .get("versions")
        .and_then(Value::as_object)
        .map(|o| o.len() as u64)
        .unwrap_or(0);
    Some(info)
}

async fn check_pypi(client: &reqwest::Client, name: &str, recent_days: i64) -> Option<PkgInfo> {
    let url = format!("https://pypi.org/pypi/{}/json", name);
    let p = http_get(client, &url).await?;
    let mut info = PkgInfo {
        ecosystem: "pypi".into(),
        name: name.to_string(),
        url: url.clone(),
        ..Default::default()
    };
    if p.status == 404 {
        return Some(info);
    }
    if p.status != 200 {
        return None;
    }
    let v: Value = serde_json::from_str(&p.body).ok()?;
    info.exists = true;
    let mut newest: Option<String> = None;
    if let Some(rels) = v.get("releases").and_then(Value::as_object) {
        info.versions = rels.len() as u64;
        for files in rels.values() {
            if let Some(arr) = files.as_array() {
                for f in arr {
                    if let Some(t) = f.get("upload_time_iso_8601").and_then(Value::as_str) {
                        if newest.as_deref().map(|n| t > n).unwrap_or(true) {
                            newest = Some(t.to_string());
                        }
                    }
                }
            }
        }
    }
    info.recent = newest.as_deref().map(|c| is_recent(c, recent_days)).unwrap_or(false);
    info.created = newest;
    Some(info)
}

async fn check_crates(client: &reqwest::Client, name: &str, recent_days: i64) -> Option<PkgInfo> {
    let url = format!("https://crates.io/api/v1/crates/{}", name);
    let p = http_get(client, &url).await?;
    let mut info = PkgInfo {
        ecosystem: "crates".into(),
        name: name.to_string(),
        url: url.clone(),
        ..Default::default()
    };
    if p.status == 404 {
        return Some(info);
    }
    if p.status != 200 {
        return None;
    }
    let v: Value = serde_json::from_str(&p.body).ok()?;
    if v.get("crate").is_none() {
        return Some(info);
    }
    info.exists = true;
    info.created = v
        .get("crate")
        .and_then(|c| c.get("created_at"))
        .and_then(Value::as_str)
        .map(str::to_string);
    info.recent = info.created.as_deref().map(|c| is_recent(c, recent_days)).unwrap_or(false);
    Some(info)
}

async fn check_rubygems(client: &reqwest::Client, name: &str, _recent_days: i64) -> Option<PkgInfo> {
    let url = format!("https://rubygems.org/api/v1/gems/{}.json", name);
    let p = http_get(client, &url).await?;
    let mut info = PkgInfo {
        ecosystem: "rubygems".into(),
        name: name.to_string(),
        url: url.clone(),
        ..Default::default()
    };
    if p.status == 404 {
        return Some(info);
    }
    if p.status != 200 {
        return None;
    }
    info.exists = p.body.contains("\"name\"");
    Some(info)
}

async fn check_pkg(
    client: &reqwest::Client,
    ecosystem: &str,
    name: &str,
    recent_days: i64,
) -> Option<PkgInfo> {
    match ecosystem {
        "npm" => check_npm(client, name, recent_days).await,
        "pypi" => check_pypi(client, name, recent_days).await,
        "crates" | "crates.io" | "cargo" => check_crates(client, name, recent_days).await,
        "rubygems" | "gem" | "ruby" => check_rubygems(client, name, recent_days).await,
        _ => None,
    }
}

fn with_fields(mut f: Value, extra: &[(&str, Value)]) -> Value {
    if let Some(obj) = f.as_object_mut() {
        for (k, v) in extra {
            obj.insert((*k).to_string(), v.clone());
        }
    }
    f
}

// ── Attack-path synthesis ───────────────────────────────────────────────────────

fn synthesize_attack_paths(target: &str, p: &SupplyPosture) -> Vec<Value> {
    let mut out = Vec::new();
    let mut emit = |title: &str, steps: Vec<&str>, sev: &str, mitre: &str, impact: &str| {
        let ev = Evidence::new()
            .with("kind", "attack_path")
            .with("steps", json!(steps))
            .with("step_count", steps.len());
        out.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Attack path: {}", title),
                sev,
                mitre,
                &format!("{} Chain: {}", impact, steps.join("  →  ")),
                target,
                0.9,
                ev,
            ),
            &[("category", json!("attack_path")), ("kill_chain", json!(steps))],
        ));
    };

    if p.malicious_indicators > 0 {
        emit(
            "typosquat with install hook → developer/CI compromise",
            vec![
                "attacker publishes a typosquat of your package with a postinstall hook",
                "a developer or CI mistypes the dependency name",
                "npm/pip runs the install hook → code execution on the build host",
                "secrets/tokens stolen, malicious artifact built",
            ],
            "critical",
            T_SUPPLY_CHAIN,
            "A registered typosquat that ships install scripts is a live supply-chain weapon.",
        );
    } else if !p.registered_squats.is_empty() {
        emit(
            "registered typosquat → confused install",
            vec![
                "attacker holds a look-alike package name",
                "a typo during install pulls the squat instead of the real package",
                "malicious or abandoned code enters the dependency tree",
            ],
            "high",
            T_SUPPLY_CHAIN,
            "Registered look-alike packages are pre-positioned for a typo-driven install.",
        );
    }
    if !p.confusion_unclaimed.is_empty() {
        emit(
            "dependency confusion → forced malicious upgrade (Alex-Birsan)",
            vec![
                "an internal package name is unclaimed on the public registry",
                "attacker publishes a public package with that name and a higher version",
                "the resolver prefers the higher public version over the private one",
                "malicious code executes in your build/CI",
            ],
            "critical",
            T_DEPENDENCIES,
            "An unclaimed internal name on the public registry is a direct dependency-confusion path.",
        );
    }
    out
}

// ── Entry points ────────────────────────────────────────────────────────────────

/// Full, GUI-parameterised supply-chain typosquatting + dependency-confusion assessment.
pub async fn run_typosquatting_monitor_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    let intensity = cfg.intensity();
    let timeout_ms = cfg.timeout_ms(9000);
    let concurrency = cfg.concurrency().clamp(1, 32);
    let recent_days = cfg.u64_or("recent_days", 90) as i64;
    let check_install = cfg.bool_or("check_install_scripts", true);
    let do_confusion = cfg.bool_or("check_dependency_confusion", true);
    let do_paths = cfg.bool_or("attack_path_synthesis", true);
    let do_score = cfg.bool_or("posture_scoring", true);

    let ecosystems = cfg.string_list_or("ecosystems", DEFAULT_ECOSYSTEMS);

    // Base package names: operator-supplied + domain-derived.
    let mut bases = cfg.string_list("package_names");
    if cfg.bool_or("derive_from_domain", true) {
        bases.extend(base_package_names(&host));
    }
    bases.sort();
    bases.dedup();
    bases.truncate(cfg.usize_or("max_base_names", 4).max(1));
    if bases.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    // Strategy toggles (intensity defaults, individually overridable).
    let def = TypoStrategies::for_intensity(intensity);
    let st = TypoStrategies {
        omission: cfg.bool_or("strat_omission", def.omission),
        repetition: cfg.bool_or("strat_repetition", def.repetition),
        transposition: cfg.bool_or("strat_transposition", def.transposition),
        replacement: cfg.bool_or("strat_replacement", def.replacement),
        insertion: cfg.bool_or("strat_insertion", def.insertion),
        separator: cfg.bool_or("strat_separator", def.separator),
        affix: cfg.bool_or("strat_affix", def.affix),
        homoglyph: cfg.bool_or("strat_homoglyph", def.homoglyph),
    };
    let affixes = cfg.string_list_or("affixes", DEFAULT_AFFIXES);
    let max_candidates = cfg.usize_or(
        "max_candidates",
        match intensity {
            Intensity::Light => 40,
            Intensity::Normal => 100,
            Intensity::Aggressive => 250,
        },
    );

    // Generate the candidate squat set across all base names.
    let per_base = (max_candidates / bases.len()).max(8);
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for b in &bases {
        for t in generate_typos(b, &st, &affixes, per_base) {
            candidates.insert(t);
        }
    }
    for b in &bases {
        candidates.remove(b);
    }
    let mut candidates: Vec<String> = candidates.into_iter().collect();
    candidates.truncate(max_candidates);

    let client = build_client(timeout_ms);
    let mut posture = SupplyPosture::default();
    posture.checks += 1;

    // ── Typosquat sweep across ecosystems (concurrent) ──────────────────────────
    let tasks: Vec<(String, String)> = ecosystems
        .iter()
        .flat_map(|e| candidates.iter().map(move |c| (e.clone(), c.clone())))
        .collect();
    let hits: Vec<PkgInfo> = stream::iter(tasks)
        .map(|(eco, name)| {
            let c = client.clone();
            async move { check_pkg(&c, &eco, &name, recent_days).await }
        })
        .buffer_unordered(concurrency)
        .filter_map(|x| async move { x.filter(|i| i.exists) })
        .collect()
        .await;

    let mut findings: Vec<Value> = Vec::new();
    for info in hits {
        posture.registered_squats.push(format!("{}:{}", info.ecosystem, info.name));
        let suspicious_install = check_install && info.install_scripts;
        if suspicious_install {
            posture.malicious_indicators += 1;
        }
        if info.recent {
            posture.recent_squats += 1;
        }
        let (sev, conf) = if suspicious_install {
            ("critical", 0.9)
        } else if info.recent {
            ("high", 0.78)
        } else {
            ("medium", 0.6)
        };
        let mut ev = Evidence::new()
            .with("ecosystem", info.ecosystem.clone())
            .with("package", info.name.clone())
            .with("registry_url", info.url.clone())
            .with("published", info.created.clone().unwrap_or_default())
            .with("recently_published", info.recent)
            .with("version_count", info.versions)
            .check("registered_on_public_registry", true, "package name resolves on the public registry");
        if suspicious_install {
            ev = ev.check("install_hook", true, "ships preinstall/install/postinstall script");
        }
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Typosquat registered on {}: {}", info.ecosystem, info.name),
                sev,
                T_SUPPLY_CHAIN,
                &format!(
                    "A look-alike of your package name is registered on {} as '{}'{}{}. {} Pin exact dependency names + integrity hashes (lockfiles), defensively register critical look-alikes, and enable a dependency-firewall/allow-list.",
                    info.ecosystem,
                    info.name,
                    if info.recent { " (recently published)" } else { "" },
                    if suspicious_install { " and it ships an install hook" } else { "" },
                    if suspicious_install {
                        "An install hook on a squat strongly indicates an active malicious package — report it to the registry and block it immediately."
                    } else {
                        "Even if currently benign, the name is pre-positioned for a typo-driven install."
                    }
                ),
                target,
                conf,
                ev,
            ),
            &[
                ("category", json!("typosquat")),
                ("ecosystem", json!(info.ecosystem)),
                ("package", json!(info.name)),
            ],
        ));
    }

    // ── Dependency confusion (Alex-Birsan) ──────────────────────────────────────
    let internal_pkgs = cfg.string_list("internal_packages");
    if do_confusion && !internal_pkgs.is_empty() {
        posture.checks += 1;
        let conf_tasks: Vec<(String, String)> = ecosystems
            .iter()
            .flat_map(|e| internal_pkgs.iter().map(move |c| (e.clone(), c.clone())))
            .collect();
        let conf_hits: Vec<PkgInfo> = stream::iter(conf_tasks)
            .map(|(eco, name)| {
                let c = client.clone();
                async move { check_pkg(&c, &eco, &name, recent_days).await }
            })
            .buffer_unordered(concurrency)
            .filter_map(|x| async move { x })
            .collect()
            .await;
        for info in conf_hits {
            if info.exists {
                posture.confusion_taken.push(format!("{}:{}", info.ecosystem, info.name));
                let sev = if info.recent || info.install_scripts { "critical" } else { "high" };
                let ev = Evidence::new()
                    .with("ecosystem", info.ecosystem.clone())
                    .with("internal_package", info.name.clone())
                    .with("registry_url", info.url.clone())
                    .with("published", info.created.clone().unwrap_or_default())
                    .check("public_name_taken", true, "a public package already holds this internal name");
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &format!("Dependency-confusion: internal name '{}' is taken on {}", info.name, info.ecosystem),
                        sev,
                        T_DEPENDENCIES,
                        &format!(
                            "Your internal/private package name '{}' already exists publicly on {}. If you do not own that public package, a build that resolves from the public registry can pull the third-party (possibly malicious) version instead of yours. Scope the package (e.g. @org/name), pin a private registry, and verify ownership of the public name.",
                            info.name, info.ecosystem
                        ),
                        target,
                        0.8,
                        ev,
                    ),
                    &[("category", json!("dependency_confusion")), ("ecosystem", json!(info.ecosystem)), ("package", json!(info.name))],
                ));
            } else {
                posture.confusion_unclaimed.push(format!("{}:{}", info.ecosystem, info.name));
                let ev = Evidence::new()
                    .with("ecosystem", info.ecosystem.clone())
                    .with("internal_package", info.name.clone())
                    .with("registry_url", info.url.clone())
                    .check("public_name_unclaimed", true, "internal name is free to register on the public registry");
                findings.push(with_fields(
                    finding_rich(
                        ENGINE_ID,
                        &format!("Dependency-confusion risk: '{}' unclaimed on {}", info.name, info.ecosystem),
                        "high",
                        T_DEPENDENCIES,
                        &format!(
                            "Your internal/private package name '{}' is unclaimed on the public {} registry. An attacker can publish a public package with this exact name and a higher version; a misconfigured resolver will prefer it (the Alex-Birsan dependency-confusion attack that breached Apple/Microsoft/etc.). Defensively register the name, scope it to your org, and force private-registry resolution.",
                            info.name, info.ecosystem
                        ),
                        target,
                        0.78,
                        ev,
                    ),
                    &[("category", json!("dependency_confusion")), ("ecosystem", json!(info.ecosystem)), ("package", json!(info.name))],
                ));
            }
        }
    }

    if do_paths {
        findings.extend(synthesize_attack_paths(target, &posture));
    }

    if do_score && posture.has_any() {
        let score = posture.score();
        let grade = posture.grade();
        let ev = Evidence::new()
            .with("score", score)
            .with("grade", grade)
            .with("base_names", json!(bases))
            .with("candidates_tested", candidates.len())
            .with("ecosystems", json!(ecosystems))
            .with("registered_squats", json!(posture.registered_squats))
            .with("malicious_indicators", posture.malicious_indicators)
            .with("recent_squats", posture.recent_squats)
            .with("dependency_confusion_unclaimed", json!(posture.confusion_unclaimed))
            .with("dependency_confusion_taken", json!(posture.confusion_taken));
        findings.push(with_fields(
            finding_rich(
                ENGINE_ID,
                &format!("Supply-Chain Typosquat Posture: {}/100 (Grade {})", score, grade),
                "info",
                T_SUPPLY_CHAIN,
                &format!(
                    "Quantified supply-chain typosquat/dependency-confusion posture for '{}' across {} ecosystem(s) from {} live registry checks.",
                    bases.join(", "),
                    ecosystems.len(),
                    candidates.len()
                ),
                target,
                1.0,
                ev,
            ),
            &[("category", json!("posture_score")), ("score", json!(score)), ("grade", json!(grade))],
        ));
    }

    if findings.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }
    let summary = format!(
        "typosquatting_monitor: {} finding(s) · {} registered squat(s) ({} with install hooks) · {} dep-confusion · posture {}/100 (Grade {})",
        findings.len(),
        posture.registered_squats.len(),
        posture.malicious_indicators,
        posture.confusion_unclaimed.len() + posture.confusion_taken.len(),
        posture.score(),
        posture.grade()
    );
    EngineResult::ok(findings, summary)
}

/// Backward-compatible entry (default parameters) — used by other engines + the CLI wrapper.
pub async fn run_typosquatting_monitor_result(target: &str) -> EngineResult {
    run_typosquatting_monitor_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_typosquatting_monitor(target: &str) {
    print_result(run_typosquatting_monitor_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_names_from_domain() {
        let b = base_package_names("react.dev");
        assert!(b.contains(&"react".to_string()));
        let b2 = base_package_names("www.acme-corp.com");
        // www is skipped; registrable forms are derived.
        assert!(b2.iter().any(|s| s.contains("acme")));
    }

    #[test]
    fn typo_generation_is_valid_and_excludes_original() {
        let st = TypoStrategies::for_intensity(Intensity::Aggressive);
        let affixes: Vec<String> = DEFAULT_AFFIXES.iter().map(|s| s.to_string()).collect();
        let typos = generate_typos("react", &st, &affixes, 200);
        assert!(!typos.is_empty());
        assert!(!typos.contains(&"react".to_string()));
        assert!(typos.iter().all(|t| valid_pkg_name(t)));
        // omission of a char yields "reat"/"rect"/etc.; transposition yields "raect".
        assert!(typos.iter().any(|t| t == "raect" || t == "reactjs" || t == "react-js"));
    }

    #[test]
    fn valid_pkg_name_rules() {
        assert!(valid_pkg_name("react-dom"));
        assert!(valid_pkg_name("lodash.merge"));
        assert!(!valid_pkg_name("a"));
        assert!(!valid_pkg_name("-bad"));
        assert!(!valid_pkg_name("UPPER")); // we only generate lowercase
        assert!(!valid_pkg_name("has space"));
    }

    #[test]
    fn homoglyph_and_keyboard_maps_are_reasonable() {
        assert!(homoglyphs('o').contains('0'));
        assert!(homoglyphs('l').contains('1'));
        assert!(qwerty_adjacent('a').contains('s'));
        assert_eq!(qwerty_adjacent('@'), "");
    }

    #[test]
    fn is_recent_handles_iso_and_garbage() {
        assert!(!is_recent("not-a-date", 90));
        let old = "2000-01-01T00:00:00Z";
        assert!(!is_recent(old, 90));
    }

    #[test]
    fn posture_score_reacts_to_malicious_squats() {
        let mut p = SupplyPosture::default();
        assert_eq!(p.score(), 100);
        assert_eq!(p.grade(), "A");
        p.registered_squats.push("npm:reactt".into());
        p.malicious_indicators = 2;
        p.confusion_unclaimed.push("npm:acme-internal".into());
        assert!(p.score() < 70);
    }

    #[test]
    fn attack_paths_only_for_real_exposure() {
        assert!(synthesize_attack_paths("react.dev", &SupplyPosture::default()).is_empty());
        let mut p = SupplyPosture::default();
        p.confusion_unclaimed.push("npm:acme-internal".into());
        let paths = synthesize_attack_paths("react.dev", &p);
        assert!(paths.iter().any(|f| f["severity"] == "critical"));
        assert!(paths.iter().all(|f| f["category"] == json!("attack_path")));
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_typosquatting_monitor_result_ctx("", &EngineRunContext::default()).await;
        assert!(!r.success);
    }
}
