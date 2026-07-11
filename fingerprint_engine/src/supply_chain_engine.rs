//! Supply chain audit — evidence-first SCA from the attacker's vantage point.
//!
//! FALSE-POSITIVE FIX (design contract): a *vulnerability* is reported ONLY when
//!   (1) the dependency is proven present on the scanned target — parsed from a
//!       manifest / lockfile / SBOM the target actually serves, or extracted
//!       from a JavaScript bundle / sourcemap the target ships — AND
//!   (2) OSV confirms the *observed version* falls inside the affected range
//!       (the version is sent in the OSV query, so OSV performs the range match).
//!
//! The target hostname is NEVER used to search a public registry. There is no
//! domain-keyword guessing, no "find any package whose name contains a word from
//! the URL". Severity is the real CVSS v3.1 base score computed from the advisory
//! vector (falling back to the advisory's declared severity, never to a guess).
//!
//! Module 2: routes through StealthClientFactory + jitter + identity morphing when config provided.

use crate::engine_probes::{empty_ok, finding_with_probe_depth, normalize_url};
use crate::engine_result::{print_result, EngineResult};
use crate::stealth_engine;
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

const SUPPLY_PROBE_DEPTH: &str = "supply_chain_target_evidence";
const TIMEOUT_SECS: u64 = 8;
/// Parallel OSV queries (OSV rate-limits; keep bounded).
const OSV_CONCURRENCY: usize = 16;
/// Parallel JS asset fetches when reconstructing the front-end dependency graph.
const ASSET_CONCURRENCY: usize = 8;
const MAX_FRONTEND_ASSETS: usize = 24;
const MAX_ASSET_BYTES: usize = 3 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
/// Hard cap on OSV lookups per scan (defence against a maliciously huge SBOM).
const MAX_COMPONENTS_FOR_OSV: usize = 400;

/// Dependency manifests / lockfiles / SBOMs probed directly on the target.
const MANIFEST_PATHS: &[&str] = &[
    "/sbom.json",
    "/bom.json",
    "/cyclonedx.json",
    "/cyclonedx.bom.json",
    "/spdx.json",
    "/.well-known/sbom",
    "/api/sbom",
    "/package.json",
    "/package-lock.json",
    "/npm-shrinkwrap.json",
    "/pnpm-lock.yaml",
    "/yarn.lock",
    "/requirements.txt",
    "/Pipfile.lock",
    "/poetry.lock",
    "/composer.lock",
    "/Gemfile.lock",
    "/go.sum",
    "/go.mod",
    "/Cargo.lock",
];

// ─────────────────────────────────────────────────────────────────────────────
// Ecosystem model
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Ecosystem {
    Npm,
    PyPI,
    CratesIo,
    Go,
    Maven,
    RubyGems,
    Packagist,
}

impl Ecosystem {
    /// Exact ecosystem string expected by the OSV `/v1/query` API.
    fn osv(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::Maven => "Maven",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Packagist => "Packagist",
        }
    }

    /// Human/UI label kept stable for the existing finding contract.
    fn label(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "pypi",
            Ecosystem::CratesIo => "cargo",
            Ecosystem::Go => "go",
            Ecosystem::Maven => "maven",
            Ecosystem::RubyGems => "rubygems",
            Ecosystem::Packagist => "composer",
        }
    }

    fn from_purl_type(t: &str) -> Option<Ecosystem> {
        match t.to_ascii_lowercase().as_str() {
            "npm" => Some(Ecosystem::Npm),
            "pypi" => Some(Ecosystem::PyPI),
            "cargo" => Some(Ecosystem::CratesIo),
            "golang" | "go" => Some(Ecosystem::Go),
            "maven" => Some(Ecosystem::Maven),
            "gem" => Some(Ecosystem::RubyGems),
            "composer" => Some(Ecosystem::Packagist),
            _ => None,
        }
    }
}

/// A dependency that was *actually observed on the target*, with the evidence that proves it.
#[derive(Clone)]
struct ObservedComponent {
    ecosystem: Ecosystem,
    name: String,
    /// Exact version when we could resolve one; `None` means inventory-only (never OSV-matched).
    version: Option<String>,
    /// The URL on the target where the evidence was retrieved.
    evidence_url: String,
    /// What kind of evidence (e.g. `npm_lockfile`, `cyclonedx_sbom`, `js_sourcemap`).
    evidence_kind: &'static str,
    /// The exact text snippet that proves the component is present.
    evidence_excerpt: String,
}

fn comp(
    ecosystem: Ecosystem,
    name: &str,
    version: Option<String>,
    url: &str,
    kind: &'static str,
    excerpt: &str,
) -> ObservedComponent {
    ObservedComponent {
        ecosystem,
        name: name.to_string(),
        version,
        evidence_url: url.to_string(),
        evidence_kind: kind,
        evidence_excerpt: excerpt.chars().take(240).collect(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding builders
// ─────────────────────────────────────────────────────────────────────────────

fn supply_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    extra: serde_json::Value,
) -> serde_json::Value {
    let mut f = finding_with_probe_depth(
        "supply_chain",
        title,
        severity,
        "T1195.001",
        description,
        target,
        SUPPLY_PROBE_DEPTH,
    );
    if let Some(obj) = f.as_object_mut() {
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    f
}

fn classify_manifest(path: &str, body: &str) -> (&'static str, &'static str) {
    let p = path.to_ascii_lowercase();
    let body_low = body.to_ascii_lowercase();
    if p.contains("cyclonedx") || (body_low.contains("bomformat") && body_low.contains("cyclonedx"))
    {
        return ("CycloneDX SBOM", "high");
    }
    if p.contains("spdx") || body_low.contains("spdxversion") {
        return ("SPDX SBOM", "high");
    }
    if p.ends_with("package-lock.json")
        || p.ends_with("npm-shrinkwrap.json")
        || p.ends_with("pnpm-lock.yaml")
        || p.ends_with("yarn.lock")
    {
        return ("NPM lockfile", "medium");
    }
    if p.ends_with("requirements.txt") || p.ends_with("pipfile.lock") || p.ends_with("poetry.lock")
    {
        return ("Python dependency manifest", "medium");
    }
    if p.ends_with("cargo.lock") {
        return ("Rust Cargo.lock", "medium");
    }
    if p.ends_with("go.sum") || p.ends_with("go.mod") {
        return ("Go module manifest", "medium");
    }
    if p.ends_with("composer.lock") {
        return ("PHP composer.lock", "medium");
    }
    if p.ends_with("gemfile.lock") {
        return ("Ruby Gemfile.lock", "medium");
    }
    if p.ends_with("package.json") {
        return ("NPM package.json", "low");
    }
    ("Dependency manifest", "low")
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP plumbing
// ─────────────────────────────────────────────────────────────────────────────

async fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn apply_stealth_headers(
    req: reqwest::RequestBuilder,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> reqwest::RequestBuilder {
    match stealth {
        Some(s) => req.headers(stealth_engine::random_morph_headers(s)),
        None => req,
    }
}

/// Read a response body with an upper byte bound (lossy UTF-8), so a hostile huge
/// asset cannot exhaust memory.
async fn read_capped(resp: reqwest::Response, max: usize) -> Option<String> {
    let bytes = resp.bytes().await.ok()?;
    let slice = if bytes.len() > max {
        &bytes[..max]
    } else {
        &bytes[..]
    };
    Some(String::from_utf8_lossy(slice).into_owned())
}

/// Prefix derived from client target — retained for backward compatibility with
/// callers that still build registry PoC strings. NOT used for detection anymore.
pub fn target_prefix_for_poc(target: &str) -> String {
    weissman_core::models::poc::client_target_search_prefix(target)
}

// ─────────────────────────────────────────────────────────────────────────────
// Version normalisation
// ─────────────────────────────────────────────────────────────────────────────

/// Accept a string only if it is an *exact* version (no range operators / wildcards
/// / tags). Returns the cleaned version, or `None` for ranges like `^1.2.0`, `*`,
/// `latest`, `>=1.0 <2.0`, etc. This is what keeps OSV matching version-anchored.
fn normalize_exact_version(raw: &str) -> Option<String> {
    let t = raw.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    if t.is_empty() {
        return None;
    }
    let t = t.strip_prefix("==").unwrap_or(t).trim();
    // Strip a single leading `v` (go.sum / composer style: v1.2.3).
    let t = if (t.starts_with('v') || t.starts_with('V'))
        && t.len() > 1
        && t.as_bytes()[1].is_ascii_digit()
    {
        &t[1..]
    } else {
        t
    };
    let first = t.chars().next()?;
    if !first.is_ascii_digit() {
        return None;
    }
    // Reject anything that signals a range / wildcard / list rather than a pin.
    if t.chars().any(|c| {
        matches!(
            c,
            '*' | 'x' | 'X' | '^' | '~' | '>' | '<' | '|' | ' ' | ',' | '='
        )
    }) {
        return None;
    }
    Some(t.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest / lockfile / SBOM parsers (each returns the components it can prove)
// ─────────────────────────────────────────────────────────────────────────────

fn parse_components(path: &str, body: &str, url: &str) -> Vec<ObservedComponent> {
    let p = path.to_ascii_lowercase();
    let trimmed = body.trim_start();
    let looks_json = trimmed.starts_with('{') || trimmed.starts_with('[');

    if p.ends_with("package-lock.json") || p.ends_with("npm-shrinkwrap.json") {
        return parse_package_lock(body, url);
    }
    if p.ends_with("pnpm-lock.yaml") {
        return parse_pnpm_lock(body, url);
    }
    if p.ends_with("yarn.lock") {
        return parse_yarn_lock(body, url);
    }
    if p.ends_with("package.json") {
        return parse_package_json(body, url);
    }
    if p.ends_with("requirements.txt") {
        return parse_requirements_txt(body, url);
    }
    if p.ends_with("pipfile.lock") {
        return parse_pipfile_lock(body, url);
    }
    if p.ends_with("poetry.lock") {
        return parse_toml_package_blocks(body, url, Ecosystem::PyPI, "poetry_lock");
    }
    if p.ends_with("cargo.lock") {
        return parse_toml_package_blocks(body, url, Ecosystem::CratesIo, "cargo_lock");
    }
    if p.ends_with("go.sum") {
        return parse_go_sum(body, url);
    }
    if p.ends_with("go.mod") {
        return parse_go_mod(body, url);
    }
    if p.ends_with("composer.lock") {
        return parse_composer_lock(body, url);
    }
    if p.ends_with("gemfile.lock") {
        return parse_gemfile_lock(body, url);
    }

    // SBOM detection by content for generic /sbom.json, /bom.json, /api/sbom, ...
    let body_low = body.to_ascii_lowercase();
    if p.contains("cyclonedx") || (looks_json && body_low.contains("\"bomformat\"")) {
        return parse_cyclonedx(body, url);
    }
    if p.contains("spdx") || (looks_json && body_low.contains("spdxversion")) {
        return parse_spdx(body, url);
    }
    if p.contains("sbom") || p.contains("bom.json") || p.contains("bom") {
        let mut c = parse_cyclonedx(body, url);
        if c.is_empty() {
            c = parse_spdx(body, url);
        }
        return c;
    }
    Vec::new()
}

fn parse_package_lock(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return out;
    };
    // npm lockfile v2/v3: { "packages": { "node_modules/<pkg>": { "version": "x" } } }
    if let Some(pkgs) = v.get("packages").and_then(Value::as_object) {
        for (path, meta) in pkgs {
            let Some((_, name)) = path.rsplit_once("node_modules/") else {
                continue;
            };
            let name = name.trim_end_matches('/');
            if name.is_empty() {
                continue;
            }
            if let Some(ver) = meta
                .get("version")
                .and_then(Value::as_str)
                .and_then(normalize_exact_version)
            {
                out.push(comp(
                    Ecosystem::Npm,
                    name,
                    Some(ver.clone()),
                    url,
                    "npm_lockfile",
                    &format!("{name}@{ver}"),
                ));
            }
        }
    }
    // npm lockfile v1: { "dependencies": { name: { version, dependencies: {...} } } }
    if let Some(deps) = v.get("dependencies").and_then(Value::as_object) {
        collect_npm_v1(deps, url, &mut out);
    }
    out
}

fn collect_npm_v1(
    deps: &serde_json::Map<String, Value>,
    url: &str,
    out: &mut Vec<ObservedComponent>,
) {
    for (name, meta) in deps {
        if let Some(ver) = meta
            .get("version")
            .and_then(Value::as_str)
            .and_then(normalize_exact_version)
        {
            out.push(comp(
                Ecosystem::Npm,
                name,
                Some(ver.clone()),
                url,
                "npm_lockfile",
                &format!("{name}@{ver}"),
            ));
        }
        if let Some(sub) = meta.get("dependencies").and_then(Value::as_object) {
            collect_npm_v1(sub, url, out);
        }
    }
}

fn parse_package_json(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return out;
    };
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(deps) = v.get(key).and_then(Value::as_object) {
            for (name, range) in deps {
                let r = range.as_str().unwrap_or("");
                // Only ranges that are exact pins become OSV-eligible; everything
                // else is recorded as inventory (version = None).
                let version = normalize_exact_version(r);
                out.push(comp(
                    Ecosystem::Npm,
                    name,
                    version,
                    url,
                    "package_json",
                    &format!("{name}: {r}"),
                ));
            }
        }
    }
    out
}

fn yarn_name_from_spec(spec: &str) -> Option<String> {
    let s = spec.trim().trim_matches('"');
    if let Some(rest) = s.strip_prefix('@') {
        // scoped: "@scope/name@range" — the name ends at the second '@'
        if let Some(at) = rest.find('@') {
            return Some(format!("@{}", &rest[..at]));
        }
        return Some(format!("@{rest}"));
    }
    if let Some(at) = s.find('@') {
        return Some(s[..at].to_string());
    }
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn parse_yarn_lock(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let mut cur_name: Option<String> = None;
    for line in body.lines() {
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let trimmed = line.trim();
        if !indented && trimmed.ends_with(':') {
            let header = trimmed.trim_end_matches(':');
            let first = header.split(',').next().unwrap_or(header);
            // yarn berry uses "name@npm:range" — strip the protocol so the name resolves.
            let first = first.replace("@npm:", "@");
            cur_name = yarn_name_from_spec(&first);
        } else if indented && (trimmed.starts_with("version ") || trimmed.starts_with("version:")) {
            let vraw = trimmed
                .trim_start_matches("version")
                .trim_start_matches(':')
                .trim()
                .trim_matches('"');
            if let (Some(name), Some(ver)) = (cur_name.clone(), normalize_exact_version(vraw)) {
                out.push(comp(
                    Ecosystem::Npm,
                    &name,
                    Some(ver.clone()),
                    url,
                    "yarn_lockfile",
                    &format!("{name}@{ver}"),
                ));
            }
        }
    }
    out
}

fn parse_pnpm_lock(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(body) else {
        return out;
    };
    if let Some(pkgs) = v.get("packages").and_then(serde_yaml::Value::as_mapping) {
        for (k, _) in pkgs {
            if let Some(key) = k.as_str() {
                if let Some((name, ver)) = pnpm_split(key) {
                    out.push(comp(
                        Ecosystem::Npm,
                        &name,
                        Some(ver.clone()),
                        url,
                        "pnpm_lockfile",
                        &format!("{name}@{ver}"),
                    ));
                }
            }
        }
    }
    out
}

/// pnpm keys: `/lodash@4.17.21`, `/@scope/pkg@1.2.3(peer)`, or legacy `/lodash/4.17.21`.
fn pnpm_split(key: &str) -> Option<(String, String)> {
    let k = key.trim_start_matches('/');
    let k = k.split('(').next().unwrap_or(k);
    if let Some(scoped) = k.strip_prefix('@') {
        if let Some(at) = scoped.rfind('@') {
            let name = format!("@{}", &scoped[..at]);
            return normalize_exact_version(&scoped[at + 1..]).map(|vv| (name, vv));
        }
    } else if let Some(at) = k.rfind('@') {
        let name = k[..at].to_string();
        return normalize_exact_version(&k[at + 1..]).map(|vv| (name, vv));
    }
    if let Some(slash) = k.rfind('/') {
        let name = k[..slash].to_string();
        return normalize_exact_version(&k[slash + 1..]).map(|vv| (name, vv));
    }
    None
}

fn parse_requirements_txt(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    for raw in body.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        if let Some((name, ver)) = line.split_once("==") {
            let name = name.split('[').next().unwrap_or(name).trim();
            let ver = ver
                .split(|c: char| c == ';' || c == ' ' || c == '\\')
                .next()
                .unwrap_or(ver)
                .trim();
            if name.is_empty() {
                continue;
            }
            if let Some(ver) = normalize_exact_version(ver) {
                out.push(comp(
                    Ecosystem::PyPI,
                    name,
                    Some(ver.clone()),
                    url,
                    "pip_requirements",
                    &format!("{name}=={ver}"),
                ));
            }
        }
    }
    out
}

fn parse_pipfile_lock(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return out;
    };
    for sect in ["default", "develop"] {
        if let Some(m) = v.get(sect).and_then(Value::as_object) {
            for (name, meta) in m {
                if let Some(ver) = meta
                    .get("version")
                    .and_then(Value::as_str)
                    .and_then(normalize_exact_version)
                {
                    out.push(comp(
                        Ecosystem::PyPI,
                        name,
                        Some(ver.clone()),
                        url,
                        "pipfile_lock",
                        &format!("{name}=={ver}"),
                    ));
                }
            }
        }
    }
    out
}

/// Shared parser for TOML lockfiles whose entries are `[[package]]` blocks with
/// `name = "x"` / `version = "y"` (Cargo.lock and poetry.lock share this shape).
fn parse_toml_package_blocks(
    body: &str,
    url: &str,
    ecosystem: Ecosystem,
    kind: &'static str,
) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in body.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            name = None;
        } else if let Some(rest) = t.strip_prefix("name = ") {
            name = Some(rest.trim().trim_matches('"').to_string());
        } else if let Some(rest) = t.strip_prefix("version = ") {
            if let Some(n) = name.clone() {
                if let Some(ver) = normalize_exact_version(rest.trim().trim_matches('"')) {
                    out.push(comp(
                        ecosystem,
                        &n,
                        Some(ver.clone()),
                        url,
                        kind,
                        &format!("{n} {ver}"),
                    ));
                }
            }
        }
    }
    out
}

fn parse_go_sum(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for line in body.lines() {
        let mut it = line.split_whitespace();
        let (Some(module), Some(ver)) = (it.next(), it.next()) else {
            continue;
        };
        if module.is_empty() {
            continue;
        }
        let ver = ver.trim_end_matches("/go.mod");
        if let Some(ver) = normalize_exact_version(ver) {
            let key = format!("{module}@{ver}");
            if seen.insert(key.clone()) {
                out.push(comp(Ecosystem::Go, module, Some(ver), url, "go_sum", &key));
            }
        }
    }
    out
}

fn parse_go_mod(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw in body.lines() {
        let t = raw.trim();
        if t.starts_with("require (") {
            in_block = true;
            continue;
        }
        if in_block && t == ")" {
            in_block = false;
            continue;
        }
        let line = if let Some(r) = t.strip_prefix("require ") {
            r
        } else if in_block {
            t
        } else {
            continue;
        };
        let mut it = line.split_whitespace();
        let (Some(module), Some(ver)) = (it.next(), it.next()) else {
            continue;
        };
        if module == "(" || module.is_empty() {
            continue;
        }
        if let Some(ver) = normalize_exact_version(ver) {
            out.push(comp(
                Ecosystem::Go,
                module,
                Some(ver.clone()),
                url,
                "go_mod",
                &format!("{module} {ver}"),
            ));
        }
    }
    out
}

fn parse_composer_lock(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return out;
    };
    for sect in ["packages", "packages-dev"] {
        if let Some(arr) = v.get(sect).and_then(Value::as_array) {
            for p in arr {
                let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                if name.is_empty() {
                    continue;
                }
                if let Some(ver) = p
                    .get("version")
                    .and_then(Value::as_str)
                    .and_then(normalize_exact_version)
                {
                    out.push(comp(
                        Ecosystem::Packagist,
                        name,
                        Some(ver.clone()),
                        url,
                        "composer_lock",
                        &format!("{name} {ver}"),
                    ));
                }
            }
        }
    }
    out
}

fn parse_gemfile_lock(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let mut in_specs = false;
    for raw in body.lines() {
        let trimmed = raw.trim();
        if trimmed == "specs:" {
            in_specs = true;
            continue;
        }
        if !raw.starts_with(' ') && !trimmed.is_empty() {
            in_specs = false;
        }
        if !in_specs {
            continue;
        }
        // Direct gems sit at 4-space indent: "    name (1.2.3)"; their deps at 6.
        let indent = raw.len() - raw.trim_start().len();
        if indent != 4 {
            continue;
        }
        if let Some(open) = trimmed.find('(') {
            let name = trimmed[..open].trim();
            let ver = trimmed[open + 1..].trim_end_matches(')').trim();
            if name.is_empty() {
                continue;
            }
            if let Some(ver) = normalize_exact_version(ver) {
                out.push(comp(
                    Ecosystem::RubyGems,
                    name,
                    Some(ver.clone()),
                    url,
                    "gemfile_lock",
                    &format!("{name} ({ver})"),
                ));
            }
        }
    }
    out
}

/// Parse a package-url into (ecosystem, name, version). Handles npm scope encoding
/// and Maven group/artifact joining so the name matches what OSV expects.
fn parse_purl(purl: &str) -> (Option<Ecosystem>, String, Option<String>) {
    let Some(p) = purl.strip_prefix("pkg:") else {
        return (None, String::new(), None);
    };
    let Some((typ, rest)) = p.split_once('/') else {
        return (None, String::new(), None);
    };
    let eco = Ecosystem::from_purl_type(typ);
    let rest = rest.split('?').next().unwrap_or(rest);
    let rest = rest.split('#').next().unwrap_or(rest);
    let (name_part, ver) = match rest.rsplit_once('@') {
        Some((n, v)) => (n.to_string(), normalize_exact_version(v)),
        None => (rest.to_string(), None),
    };
    let mut name = name_part.replace("%40", "@");
    if matches!(eco, Some(Ecosystem::Maven)) {
        name = name.replacen('/', ":", 1);
    }
    (eco, name, ver)
}

fn parse_cyclonedx(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return out;
    };
    if let Some(comps) = v.get("components").and_then(Value::as_array) {
        for c in comps {
            collect_cyclonedx_comp(c, url, &mut out);
            if let Some(sub) = c.get("components").and_then(Value::as_array) {
                for s in sub {
                    collect_cyclonedx_comp(s, url, &mut out);
                }
            }
        }
    }
    out
}

fn collect_cyclonedx_comp(c: &Value, url: &str, out: &mut Vec<ObservedComponent>) {
    let purl = c.get("purl").and_then(Value::as_str).unwrap_or("");
    let (eco, pname, pver) = parse_purl(purl);
    let name = if pname.is_empty() {
        c.get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    } else {
        pname
    };
    let ver = pver.or_else(|| {
        c.get("version")
            .and_then(Value::as_str)
            .and_then(normalize_exact_version)
    });
    let Some(eco) = eco else {
        return; // unknown ecosystem -> cannot OSV-match soundly
    };
    if name.is_empty() {
        return;
    }
    let excerpt = match &ver {
        Some(x) => format!("{name}@{x}"),
        None => name.clone(),
    };
    out.push(comp(eco, &name, ver, url, "cyclonedx_sbom", &excerpt));
}

fn parse_spdx(body: &str, url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return out;
    };
    if let Some(pkgs) = v.get("packages").and_then(Value::as_array) {
        for p in pkgs {
            let mut eco = None;
            let mut name = String::new();
            let mut ver = None;
            if let Some(refs) = p.get("externalRefs").and_then(Value::as_array) {
                for r in refs {
                    let rt = r.get("referenceType").and_then(Value::as_str).unwrap_or("");
                    if rt == "purl" || rt == "package-url" {
                        let locator = r
                            .get("referenceLocator")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let (e, n, vv) = parse_purl(locator);
                        if e.is_some() {
                            eco = e;
                            name = n;
                            ver = vv;
                        }
                    }
                }
            }
            if name.is_empty() {
                name = p
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
            }
            if ver.is_none() {
                ver = p
                    .get("versionInfo")
                    .and_then(Value::as_str)
                    .and_then(normalize_exact_version);
            }
            let (Some(eco), false) = (eco, name.is_empty()) else {
                continue;
            };
            let excerpt = match &ver {
                Some(x) => format!("{name}@{x}"),
                None => name.clone(),
            };
            out.push(comp(eco, &name, ver, url, "spdx_sbom", &excerpt));
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Dependency graph + reachability analysis
//
// Reconstructs the *relationship* graph (who pulls in whom) from the same
// artifacts the target serves, so every vulnerable component can be classified by
// reachability and traced back to a direct dependency. This is what turns a flat
// "package X is vulnerable" list into "X is a transitive dep pulled in by your
// direct dep Y, and it is shipped to the browser".
// ─────────────────────────────────────────────────────────────────────────────

/// Name-level dependency graph (ecosystem-scoped). Best-effort: populated from the
/// formats that expose relationships, and degrades gracefully when they do not.
#[derive(Default)]
struct DepGraph {
    nodes: HashSet<String>,
    direct: HashSet<String>,
    edges: HashMap<String, BTreeSet<String>>,
    indeg: HashSet<String>,
}

/// Internal node key: ecosystem label + a unit-separator + exact package name.
fn gkey(eco: Ecosystem, name: &str) -> String {
    format!("{}\u{1}{}", eco.label(), name)
}

fn gkey_name(key: &str) -> String {
    key.splitn(2, '\u{1}').nth(1).unwrap_or(key).to_string()
}

impl DepGraph {
    fn add_node(&mut self, eco: Ecosystem, name: &str) {
        self.nodes.insert(gkey(eco, name));
    }

    fn add_direct(&mut self, eco: Ecosystem, name: &str) {
        let k = gkey(eco, name);
        self.nodes.insert(k.clone());
        self.direct.insert(k);
    }

    fn add_edge(&mut self, eco: Ecosystem, parent: &str, child: &str) {
        if parent.is_empty() || child.is_empty() {
            return;
        }
        let pk = gkey(eco, parent);
        let ck = gkey(eco, child);
        self.nodes.insert(pk.clone());
        self.nodes.insert(ck.clone());
        self.edges.entry(pk).or_default().insert(ck.clone());
        self.indeg.insert(ck);
    }

    fn is_direct(&self, eco: Ecosystem, name: &str) -> bool {
        self.direct.contains(&gkey(eco, name))
    }

    fn edge_count(&self) -> usize {
        self.edges.values().map(BTreeSet::len).sum()
    }
}

/// Reachability tier for a component, strongest signal first.
fn reachability_tier(
    g: &DepGraph,
    eco: Ecosystem,
    name: &str,
    evidence_kind: &str,
) -> &'static str {
    if evidence_kind.starts_with("js_") {
        // Observed in a bundle/sourcemap the target actually ships to clients.
        return "client_runtime";
    }
    let k = gkey(eco, name);
    if g.direct.contains(&k) {
        "direct"
    } else if g.indeg.contains(&k) {
        "transitive"
    } else {
        "declared"
    }
}

/// Shortest dependency path from a direct/root dependency to `name` (names only).
/// Returns `[name]` when the component is itself direct, or `[]` when no path is known.
fn dependency_path(g: &DepGraph, eco: Ecosystem, name: &str) -> Vec<String> {
    let target = gkey(eco, name);
    if g.direct.contains(&target) {
        return vec![name.to_string()];
    }
    let sources: Vec<String> = if g.direct.is_empty() {
        // No declared roots (e.g. yarn.lock/Cargo.lock alone): use graph roots.
        g.edges
            .keys()
            .filter(|k| !g.indeg.contains(*k))
            .cloned()
            .collect()
    } else {
        g.direct.iter().cloned().collect()
    };

    let mut queue: VecDeque<String> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut prev: HashMap<String, String> = HashMap::new();
    for s in &sources {
        if visited.insert(s.clone()) {
            queue.push_back(s.clone());
        }
    }
    while let Some(cur) = queue.pop_front() {
        if cur == target {
            let mut chain = vec![cur.clone()];
            let mut node = cur;
            while let Some(p) = prev.get(&node) {
                chain.push(p.clone());
                node = p.clone();
            }
            chain.reverse();
            return chain.iter().map(|k| gkey_name(k)).collect();
        }
        if let Some(children) = g.edges.get(&cur) {
            for ch in children {
                if visited.insert(ch.clone()) {
                    prev.insert(ch.clone(), cur.clone());
                    queue.push_back(ch.clone());
                }
            }
        }
    }
    if g.nodes.contains(&target) {
        vec![name.to_string()]
    } else {
        Vec::new()
    }
}

/// Populate the dependency graph from a single manifest/lockfile/SBOM body.
fn extract_graph(path: &str, body: &str, g: &mut DepGraph) {
    let p = path.to_ascii_lowercase();
    if p.ends_with("package-lock.json") || p.ends_with("npm-shrinkwrap.json") {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            graph_npm_lock(&v, g);
        }
        return;
    }
    if p.ends_with("pnpm-lock.yaml") {
        if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(body) {
            graph_pnpm(&v, g);
        }
        return;
    }
    if p.ends_with("yarn.lock") {
        graph_yarn(body, g);
        return;
    }
    if p.ends_with("package.json") {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            graph_package_json(&v, g);
        }
        return;
    }
    if p.ends_with("requirements.txt") {
        for c in parse_requirements_txt(body, "") {
            g.add_direct(c.ecosystem, &c.name);
        }
        return;
    }
    if p.ends_with("pipfile.lock") {
        for c in parse_pipfile_lock(body, "") {
            g.add_direct(c.ecosystem, &c.name);
        }
        return;
    }
    if p.ends_with("go.mod") {
        for c in parse_go_mod(body, "") {
            g.add_direct(c.ecosystem, &c.name);
        }
        return;
    }
    if p.ends_with("cargo.lock") {
        graph_cargo(body, g);
        return;
    }
    if p.ends_with("composer.lock") {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            graph_composer(&v, g);
        }
        return;
    }
    let body_low = body.to_ascii_lowercase();
    if p.contains("cyclonedx") || body_low.contains("\"bomformat\"") {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            graph_cyclonedx(&v, g);
        }
        return;
    }
    if p.contains("spdx") || body_low.contains("spdxversion") {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            graph_spdx(&v, g);
        }
        return;
    }
    if p.contains("sbom") || p.contains("bom") {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            graph_cyclonedx(&v, g);
            graph_spdx(&v, g);
        }
    }
}

fn graph_package_json(v: &Value, g: &mut DepGraph) {
    for key in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(d) = v.get(key).and_then(Value::as_object) {
            for (n, _) in d {
                g.add_direct(Ecosystem::Npm, n);
            }
        }
    }
}

fn graph_npm_lock(v: &Value, g: &mut DepGraph) {
    if let Some(pkgs) = v.get("packages").and_then(Value::as_object) {
        if let Some(root) = pkgs.get("") {
            for key in [
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ] {
                if let Some(d) = root.get(key).and_then(Value::as_object) {
                    for (n, _) in d {
                        g.add_direct(Ecosystem::Npm, n);
                    }
                }
            }
        }
        for (path, meta) in pkgs {
            if path.is_empty() {
                continue;
            }
            let Some((_, parent)) = path.rsplit_once("node_modules/") else {
                continue;
            };
            let parent = parent.trim_end_matches('/');
            if let Some(d) = meta.get("dependencies").and_then(Value::as_object) {
                for (child, _) in d {
                    g.add_edge(Ecosystem::Npm, parent, child);
                }
            }
            if let Some(d) = meta.get("optionalDependencies").and_then(Value::as_object) {
                for (child, _) in d {
                    g.add_edge(Ecosystem::Npm, parent, child);
                }
            }
        }
    }
    if let Some(deps) = v.get("dependencies").and_then(Value::as_object) {
        graph_npm_v1(deps, g);
    }
}

fn graph_npm_v1(deps: &serde_json::Map<String, Value>, g: &mut DepGraph) {
    for (name, meta) in deps {
        g.add_node(Ecosystem::Npm, name);
        if let Some(req) = meta.get("requires").and_then(Value::as_object) {
            for (child, _) in req {
                g.add_edge(Ecosystem::Npm, name, child);
            }
        }
        if let Some(sub) = meta.get("dependencies").and_then(Value::as_object) {
            graph_npm_v1(sub, g);
        }
    }
}

fn graph_pnpm(v: &serde_yaml::Value, g: &mut DepGraph) {
    if let Some(imps) = v.get("importers").and_then(serde_yaml::Value::as_mapping) {
        for (_, imp) in imps {
            for key in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(d) = imp.get(key).and_then(serde_yaml::Value::as_mapping) {
                    for (n, _) in d {
                        if let Some(n) = n.as_str() {
                            g.add_direct(Ecosystem::Npm, n);
                        }
                    }
                }
            }
        }
    }
    for key in ["dependencies", "devDependencies"] {
        if let Some(d) = v.get(key).and_then(serde_yaml::Value::as_mapping) {
            for (n, _) in d {
                if let Some(n) = n.as_str() {
                    g.add_direct(Ecosystem::Npm, n);
                }
            }
        }
    }
    if let Some(pkgs) = v.get("packages").and_then(serde_yaml::Value::as_mapping) {
        for (k, meta) in pkgs {
            let Some(key) = k.as_str() else { continue };
            let Some((parent, _)) = pnpm_split(key) else {
                continue;
            };
            if let Some(d) = meta
                .get("dependencies")
                .and_then(serde_yaml::Value::as_mapping)
            {
                for (c, _) in d {
                    if let Some(c) = c.as_str() {
                        g.add_edge(Ecosystem::Npm, &parent, c);
                    }
                }
            }
        }
    }
}

fn graph_yarn(body: &str, g: &mut DepGraph) {
    let mut cur_name: Option<String> = None;
    let mut in_deps = false;
    for line in body.lines() {
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let trimmed = line.trim();
        if !indented {
            let header = trimmed.trim_end_matches(':');
            let first = header
                .split(',')
                .next()
                .unwrap_or(header)
                .replace("@npm:", "@");
            cur_name = yarn_name_from_spec(&first);
            in_deps = false;
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if trimmed.starts_with("dependencies:") || trimmed.starts_with("optionalDependencies:") {
            in_deps = true;
            continue;
        }
        if indent <= 2 {
            in_deps = false;
        }
        if in_deps && indent >= 4 {
            let child = trimmed
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches('"');
            if let Some(parent) = &cur_name {
                if !child.is_empty() && !child.ends_with(':') {
                    g.add_edge(Ecosystem::Npm, parent, child);
                }
            }
        }
    }
}

fn graph_cargo(body: &str, g: &mut DepGraph) {
    let mut name: Option<String> = None;
    let mut in_deps = false;
    for line in body.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            name = None;
            in_deps = false;
        } else if let Some(r) = t.strip_prefix("name = ") {
            name = Some(r.trim().trim_matches('"').to_string());
        } else if t.starts_with("dependencies = [") {
            in_deps = !t.ends_with(']');
        } else if in_deps {
            if t.starts_with(']') {
                in_deps = false;
            } else {
                let dep = t.trim_matches(|c| c == '"' || c == ',').trim();
                let child = dep.split_whitespace().next().unwrap_or("");
                if let Some(parent) = &name {
                    g.add_edge(Ecosystem::CratesIo, parent, child);
                }
            }
        }
    }
}

fn graph_composer(v: &Value, g: &mut DepGraph) {
    for sect in ["packages", "packages-dev"] {
        if let Some(arr) = v.get(sect).and_then(Value::as_array) {
            for p in arr {
                let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                if name.is_empty() {
                    continue;
                }
                if let Some(req) = p.get("require").and_then(Value::as_object) {
                    for (child, _) in req {
                        // Skip platform requirements (php, ext-*, lib-*) — only real packages.
                        if child.contains('/') {
                            g.add_edge(Ecosystem::Packagist, name, child);
                        }
                    }
                }
            }
        }
    }
}

fn cdx_register(c: &Value, refmap: &mut HashMap<String, (Ecosystem, String)>) {
    let purl = c.get("purl").and_then(Value::as_str).unwrap_or("");
    let (eco, pname, _) = parse_purl(purl);
    let name = if pname.is_empty() {
        c.get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    } else {
        pname
    };
    let Some(eco) = eco else { return };
    if name.is_empty() {
        return;
    }
    if let Some(bomref) = c.get("bom-ref").and_then(Value::as_str) {
        refmap.insert(bomref.to_string(), (eco, name.clone()));
    }
    if !purl.is_empty() {
        refmap.insert(purl.to_string(), (eco, name));
    }
}

fn graph_cyclonedx(v: &Value, g: &mut DepGraph) {
    let mut refmap: HashMap<String, (Ecosystem, String)> = HashMap::new();
    if let Some(comps) = v.get("components").and_then(Value::as_array) {
        for c in comps {
            cdx_register(c, &mut refmap);
            if let Some(sub) = c.get("components").and_then(Value::as_array) {
                for s in sub {
                    cdx_register(s, &mut refmap);
                }
            }
        }
    }
    let root_ref = v
        .get("metadata")
        .and_then(|m| m.get("component"))
        .and_then(|c| c.get("bom-ref"))
        .and_then(Value::as_str);
    if let Some(deps) = v.get("dependencies").and_then(Value::as_array) {
        for d in deps {
            let r = d.get("ref").and_then(Value::as_str).unwrap_or("");
            let on = d.get("dependsOn").and_then(Value::as_array);
            if Some(r) == root_ref {
                if let Some(on) = on {
                    for ch in on {
                        if let Some((eco, n)) = ch.as_str().and_then(|cr| refmap.get(cr)) {
                            g.add_direct(*eco, n);
                        }
                    }
                }
                continue;
            }
            let Some((peco, pname)) = refmap.get(r) else {
                continue;
            };
            if let Some(on) = on {
                for ch in on {
                    if let Some((ceco, cname)) = ch.as_str().and_then(|cr| refmap.get(cr)) {
                        if peco == ceco {
                            g.add_edge(*peco, pname, cname);
                        }
                    }
                }
            }
        }
    }
}

fn graph_spdx(v: &Value, g: &mut DepGraph) {
    let mut idmap: HashMap<String, (Ecosystem, String)> = HashMap::new();
    if let Some(pkgs) = v.get("packages").and_then(Value::as_array) {
        for p in pkgs {
            let id = p.get("SPDXID").and_then(Value::as_str).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            let mut eco = None;
            let mut name = String::new();
            if let Some(refs) = p.get("externalRefs").and_then(Value::as_array) {
                for r in refs {
                    let rt = r.get("referenceType").and_then(Value::as_str).unwrap_or("");
                    if rt == "purl" || rt == "package-url" {
                        let locator = r
                            .get("referenceLocator")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let (e, n, _) = parse_purl(locator);
                        if e.is_some() {
                            eco = e;
                            name = n;
                        }
                    }
                }
            }
            if name.is_empty() {
                name = p
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
            }
            if let (Some(eco), false) = (eco, name.is_empty()) {
                idmap.insert(id.to_string(), (eco, name));
            }
        }
    }
    if let Some(rels) = v.get("relationships").and_then(Value::as_array) {
        for r in rels {
            let rt = r
                .get("relationshipType")
                .and_then(Value::as_str)
                .unwrap_or("");
            let from = r.get("spdxElementId").and_then(Value::as_str).unwrap_or("");
            let to = r
                .get("relatedSpdxElement")
                .and_then(Value::as_str)
                .unwrap_or("");
            if rt != "DEPENDS_ON" {
                continue;
            }
            if let (Some((peco, pname)), Some((ceco, cname))) = (idmap.get(from), idmap.get(to)) {
                if peco == ceco {
                    g.add_edge(*peco, pname, cname);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Target evidence collection
// ─────────────────────────────────────────────────────────────────────────────

/// Probe the target for exposed manifests/lockfiles/SBOMs, emit an info-leak
/// finding for each, and parse out the concrete components they declare.
async fn harvest_manifests(
    c: Arc<reqwest::Client>,
    target: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> (Vec<Value>, Vec<ObservedComponent>, DepGraph) {
    let base = normalize_url(target);
    let base = base.trim_end_matches('/').to_string();
    let mut findings = Vec::new();
    let mut comps = Vec::new();
    let mut graph = DepGraph::default();

    for &path in MANIFEST_PATHS {
        let url = format!("{base}{path}");
        if let Some(s) = stealth {
            stealth_engine::apply_jitter(s).await;
        }
        let req = apply_stealth_headers(c.get(&url), stealth);
        let Ok(resp) = req.send().await else { continue };
        if resp.status().as_u16() != 200 {
            continue;
        }
        let Some(body) = read_capped(resp, MAX_MANIFEST_BYTES).await else {
            continue;
        };
        if body.len() < 12 {
            continue;
        }
        let parsed = parse_components(path, &body, &url);
        extract_graph(path, &body, &mut graph);
        let (doc_type, severity) = classify_manifest(path, &body);
        let looks_like_manifest = !parsed.is_empty()
            || body.contains("dependencies")
            || body.contains("packages")
            || body.contains("components")
            || body.contains("[[package]]")
            || body.contains("bomFormat")
            || body.contains("SPDXVersion");
        if looks_like_manifest {
            findings.push(supply_finding(
                &format!("Exposed {doc_type} at {path}"),
                severity,
                &format!(
                    "Live {} fetched from {} ({} bytes); {} dependency record(s) parsed. \
                     Exposed manifests leak the exact dependency inventory and enable targeted CVE selection — remove public access.",
                    doc_type,
                    url,
                    body.len(),
                    parsed.len()
                ),
                target,
                json!({
                    "url": url,
                    "document_type": doc_type,
                    "body_length": body.len(),
                    "components_parsed": parsed.len(),
                    "discovery": "manifest_probe"
                }),
            ));
        }
        comps.extend(parsed);
    }
    (findings, comps, graph)
}

/// Compiled front-end library banner signatures (retire.js-style). Each maps a
/// distinctive banner to the canonical npm package name; the version captured is
/// still gated through OSV's version-range matching before any finding is raised.
fn frontend_signatures() -> Vec<(&'static str, regex::Regex)> {
    const RAW: &[(&str, &str)] = &[
        (
            "jquery",
            r"(?i)jQuery\s+(?:JavaScript Library\s+)?v?(\d+\.\d+\.\d+)",
        ),
        ("jquery-ui", r"(?i)jQuery UI\s+(?:-\s+)?v?(\d+\.\d+\.\d+)"),
        ("bootstrap", r"(?i)Bootstrap\s+v?(\d+\.\d+\.\d+)"),
        ("lodash", r"(?i)lodash(?:\.js)?\s+v?(\d+\.\d+\.\d+)"),
        ("underscore", r"(?i)Underscore(?:\.js)?\s+v?(\d+\.\d+\.\d+)"),
        ("moment", r"(?i)moment(?:\.js)?\s+v?(\d+\.\d+\.\d+)"),
        ("angular", r"(?i)AngularJS\s+v?(\d+\.\d+\.\d+)"),
        ("vue", r"(?i)Vue(?:\.js)?\s+v(\d+\.\d+\.\d+)"),
        ("react", r"(?i)@license React v(\d+\.\d+\.\d+)"),
        ("d3", r"(?i)\bd3\s+v(\d+\.\d+\.\d+)"),
        ("handlebars", r"(?i)Handlebars(?:\.js)?\s+v?(\d+\.\d+\.\d+)"),
        ("backbone", r"(?i)Backbone(?:\.js)?\s+v?(\d+\.\d+\.\d+)"),
        ("axios", r"(?i)axios/(\d+\.\d+\.\d+)"),
        ("dompurify", r"(?i)DOMPurify\s+(\d+\.\d+\.\d+)"),
    ];
    RAW.iter()
        .filter_map(|(n, r)| regex::Regex::new(r).ok().map(|re| (*n, re)))
        .collect()
}

fn extract_banner_components(
    body: &str,
    url: &str,
    sigs: &[(&'static str, regex::Regex)],
) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    // Banners live at the top of a bundle; scan only the head to avoid matching
    // arbitrary version-looking strings deep inside minified code.
    let head: String = body.chars().take(8192).collect();
    for (npm, re) in sigs {
        if let Some(cap) = re.captures(&head) {
            if let Some(ver) = cap.get(1) {
                let version = ver.as_str().to_string();
                let key = format!("{npm}@{version}");
                if seen.insert(key) {
                    out.push(comp(
                        Ecosystem::Npm,
                        npm,
                        Some(version.clone()),
                        url,
                        "js_bundle_banner",
                        &format!("{npm} {version}"),
                    ));
                }
            }
        }
    }
    out
}

fn find_sourcemap_ref(body: &str) -> Option<String> {
    for marker in ["//# sourceMappingURL=", "//@ sourceMappingURL="] {
        if let Some(idx) = body.rfind(marker) {
            let after = &body[idx + marker.len()..];
            let val = after.lines().next().unwrap_or("").trim();
            if !val.is_empty() && !val.starts_with("data:") {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn npm_name_from_node_modules_path(path: &str) -> Option<String> {
    let idx = path.rfind("node_modules/")?;
    let rest = path[idx + "node_modules/".len()..].trim_start_matches('/');
    let mut parts = rest.split('/');
    let first = parts.next()?;
    if first.starts_with('@') {
        let second = parts.next()?;
        if second.is_empty() {
            return None;
        }
        Some(format!("{first}/{second}"))
    } else if first.is_empty() {
        None
    } else {
        Some(first.to_string())
    }
}

fn extract_sourcemap_components(map_body: &str, map_url: &str) -> Vec<ObservedComponent> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(map_body) else {
        return out;
    };
    let Some(sources) = v.get("sources").and_then(Value::as_array) else {
        return out;
    };
    let mut seen = HashSet::new();
    for s in sources {
        let Some(path) = s.as_str() else { continue };
        if let Some(name) = npm_name_from_node_modules_path(path) {
            if seen.insert(name.clone()) {
                out.push(comp(
                    Ecosystem::Npm,
                    &name,
                    None, // sourcemaps reveal the name, not the version
                    map_url,
                    "js_sourcemap",
                    &format!("source: {}", path.chars().take(160).collect::<String>()),
                ));
            }
        }
    }
    out
}

async fn process_js_asset(
    c: Arc<reqwest::Client>,
    url: String,
    stealth: Option<stealth_engine::StealthConfig>,
    sigs: Arc<Vec<(&'static str, regex::Regex)>>,
) -> (Vec<ObservedComponent>, Vec<Value>) {
    let mut comps = Vec::new();
    let mut findings = Vec::new();
    if let Some(s) = &stealth {
        stealth_engine::apply_jitter(s).await;
    }
    let req = apply_stealth_headers(c.get(&url), stealth.as_ref());
    let Ok(resp) = req.send().await else {
        return (comps, findings);
    };
    if resp.status().as_u16() != 200 {
        return (comps, findings);
    }
    let Some(body) = read_capped(resp, MAX_ASSET_BYTES).await else {
        return (comps, findings);
    };

    comps.extend(extract_banner_components(&body, &url, sigs.as_ref()));

    if let Some(map_ref) = find_sourcemap_ref(&body) {
        if let Ok(asset_u) = url::Url::parse(&url) {
            if let Ok(map_u) = asset_u.join(&map_ref) {
                if map_u.scheme().starts_with("http") && map_u.host_str() == asset_u.host_str() {
                    if let Some(s) = &stealth {
                        stealth_engine::apply_jitter(s).await;
                    }
                    let req = apply_stealth_headers(c.get(map_u.as_str()), stealth.as_ref());
                    if let Ok(mresp) = req.send().await {
                        if mresp.status().as_u16() == 200 {
                            if let Some(mbody) = read_capped(mresp, MAX_ASSET_BYTES).await {
                                let smc = extract_sourcemap_components(&mbody, map_u.as_str());
                                if !smc.is_empty() {
                                    findings.push(supply_finding(
                                        &format!("Exposed JavaScript source map ({} sources)", smc.len()),
                                        "medium",
                                        &format!(
                                            "Source map {} is publicly served and reveals {} bundled dependency path(s). \
                                             Source maps disclose original source and the exact dependency tree — disable them in production.",
                                            map_u.as_str(),
                                            smc.len()
                                        ),
                                        map_u.as_str(),
                                        json!({
                                            "url": map_u.as_str(),
                                            "asset_url": url,
                                            "sources_with_packages": smc.len(),
                                            "discovery": "js_sourcemap"
                                        }),
                                    ));
                                }
                                comps.extend(smc);
                            }
                        }
                    }
                }
            }
        }
    }
    (comps, findings)
}

/// Fetch the target's HTML, discover the same-origin JS it actually serves, and
/// reconstruct front-end dependencies from bundle banners + source maps.
async fn harvest_frontend(
    c: Arc<reqwest::Client>,
    target: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> (Vec<Value>, Vec<ObservedComponent>) {
    let base_str = normalize_url(target);
    let Ok(base_url) = url::Url::parse(&base_str) else {
        return (Vec::new(), Vec::new());
    };
    let host = base_url.host_str().unwrap_or("").to_string();
    if host.is_empty() {
        return (Vec::new(), Vec::new());
    }

    if let Some(s) = stealth {
        stealth_engine::apply_jitter(s).await;
    }
    let req = apply_stealth_headers(c.get(base_url.as_str()), stealth);
    let Ok(resp) = req.send().await else {
        return (Vec::new(), Vec::new());
    };
    if resp.status().as_u16() != 200 {
        return (Vec::new(), Vec::new());
    }
    let Some(html) = read_capped(resp, MAX_ASSET_BYTES).await else {
        return (Vec::new(), Vec::new());
    };

    let mut candidates: Vec<String> = Vec::new();
    if let Ok(re) = regex::Regex::new(r#"(?i)<script[^>]+src\s*=\s*["']([^"']+)["']"#) {
        for cap in re.captures_iter(&html) {
            if let Some(m) = cap.get(1) {
                candidates.push(m.as_str().to_string());
            }
        }
    }
    if let Ok(re) = regex::Regex::new(r#"(?i)<link[^>]+href\s*=\s*["']([^"']+\.m?js)["']"#) {
        for cap in re.captures_iter(&html) {
            if let Some(m) = cap.get(1) {
                candidates.push(m.as_str().to_string());
            }
        }
    }

    let mut resolved: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for a in candidates {
        let Ok(abs) = base_url.join(&a) else { continue };
        if abs.host_str().unwrap_or("") != host {
            continue; // only assets the target itself serves count as evidence
        }
        let p = abs.path().to_ascii_lowercase();
        if !(p.ends_with(".js") || p.ends_with(".mjs")) {
            continue;
        }
        let s = abs.to_string();
        if seen.insert(s.clone()) {
            resolved.push(s);
        }
        if resolved.len() >= MAX_FRONTEND_ASSETS {
            break;
        }
    }

    if resolved.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let sigs = Arc::new(frontend_signatures());
    let owned_stealth = stealth.cloned();
    let results: Vec<(Vec<ObservedComponent>, Vec<Value>)> =
        stream::iter(resolved.into_iter().map(|asset| {
            let c = Arc::clone(&c);
            let st = owned_stealth.clone();
            let sigs = Arc::clone(&sigs);
            async move { process_js_asset(c, asset, st, sigs).await }
        }))
        .buffer_unordered(ASSET_CONCURRENCY)
        .collect()
        .await;

    let mut comps = Vec::new();
    let mut findings = Vec::new();
    for (c_part, f_part) in results {
        comps.extend(c_part);
        findings.extend(f_part);
    }
    (findings, comps)
}

// ─────────────────────────────────────────────────────────────────────────────
// OSV (version-anchored) + CVSS v3.1 scoring
// ─────────────────────────────────────────────────────────────────────────────

struct OsvVuln {
    id: String,
    cve: Option<String>,
    summary: String,
    cvss_score: Option<f64>,
    cvss_vector: Option<String>,
    severity_label: String,
}

async fn query_osv(
    c: &reqwest::Client,
    eco: Ecosystem,
    name: &str,
    version: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> Vec<OsvVuln> {
    let mut out = Vec::new();
    if let Some(s) = stealth {
        stealth_engine::apply_jitter(s).await;
    }
    // Sending `version` makes OSV perform authoritative affected-range matching:
    // a result means *this exact version* is vulnerable — not merely that the
    // package name has ever had a CVE.
    let body = json!({ "version": version, "package": { "name": name, "ecosystem": eco.osv() } });
    let req = apply_stealth_headers(c.post("https://api.osv.dev/v1/query").json(&body), stealth);
    let Ok(r) = req.send().await else { return out };
    if !r.status().is_success() {
        return out;
    }
    let Ok(data) = r.json::<Value>().await else {
        return out;
    };
    let Some(vulns) = data.get("vulns").and_then(Value::as_array) else {
        return out;
    };
    for v in vulns.iter().take(50) {
        let id = v
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let mut cve = None;
        if let Some(al) = v.get("aliases").and_then(Value::as_array) {
            for a in al {
                if let Some(s) = a.as_str() {
                    let u = s.trim().to_ascii_uppercase();
                    if u.starts_with("CVE-") {
                        cve = Some(u);
                        break;
                    }
                }
            }
        }
        let summary = v
            .get("summary")
            .and_then(Value::as_str)
            .or_else(|| v.get("details").and_then(Value::as_str))
            .unwrap_or("")
            .chars()
            .take(280)
            .collect::<String>();
        let (score, vector) = osv_cvss(v);
        let label = if let Some(s) = score {
            severity_bucket(s).to_string()
        } else if let Some(t) = osv_text_severity(v) {
            t
        } else {
            "medium".to_string()
        };
        out.push(OsvVuln {
            id,
            cve,
            summary,
            cvss_score: score,
            cvss_vector: vector,
            severity_label: label,
        });
    }
    out
}

fn osv_cvss(v: &Value) -> (Option<f64>, Option<String>) {
    let Some(arr) = v.get("severity").and_then(Value::as_array) else {
        return (None, None);
    };
    let mut best: Option<f64> = None;
    let mut vector: Option<String> = None;
    for s in arr {
        let typ = s.get("type").and_then(Value::as_str).unwrap_or("");
        let score = s.get("score").and_then(Value::as_str).unwrap_or("");
        if score.is_empty() {
            continue;
        }
        vector = Some(score.to_string());
        if typ.eq_ignore_ascii_case("CVSS_V3") || score.starts_with("CVSS:3") {
            if let Some(b) = cvss3_base_score(score) {
                best = Some(best.map_or(b, |x: f64| x.max(b)));
            }
        }
    }
    (best, vector)
}

fn osv_text_severity(v: &Value) -> Option<String> {
    let t = v
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(Value::as_str)?;
    Some(
        match t.to_ascii_uppercase().as_str() {
            "CRITICAL" => "critical",
            "HIGH" => "high",
            "MODERATE" | "MEDIUM" => "medium",
            "LOW" => "low",
            _ => return None,
        }
        .to_string(),
    )
}

/// Compute the CVSS v3.0/3.1 base score from a vector string per the official spec.
fn cvss3_base_score(vector: &str) -> Option<f64> {
    let mut m: HashMap<&str, &str> = HashMap::new();
    for part in vector.split('/') {
        if let Some((k, val)) = part.split_once(':') {
            m.insert(k, val);
        }
    }
    let av: f64 = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac: f64 = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let ui: f64 = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let scope_changed = matches!(*m.get("S")?, "C");
    let pr: f64 = match (*m.get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let imp = |x: &str| -> f64 {
        match x {
            "H" => 0.56,
            "L" => 0.22,
            "N" => 0.0,
            _ => -1.0,
        }
    };
    let ci = imp(*m.get("C")?);
    let ii = imp(*m.get("I")?);
    let ai = imp(*m.get("A")?);
    if ci < 0.0 || ii < 0.0 || ai < 0.0 {
        return None;
    }
    let iss = 1.0 - ((1.0 - ci) * (1.0 - ii) * (1.0 - ai));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };
    let exploit = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let raw = if scope_changed {
        (1.08 * (impact + exploit)).min(10.0)
    } else {
        (impact + exploit).min(10.0)
    };
    Some(roundup_1(raw))
}

/// CVSS "Roundup": round up to one decimal place (spec-exact integer method).
fn roundup_1(x: f64) -> f64 {
    let int_input = (x * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input as f64 / 10_000.0).floor() + 1.0) / 10.0
    }
}

fn severity_bucket(score: f64) -> &'static str {
    if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else if score > 0.0 {
        "low"
    } else {
        "info"
    }
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn max_severity(vulns: &[OsvVuln]) -> &'static str {
    let best = vulns
        .iter()
        .map(|v| sev_rank(&v.severity_label))
        .max()
        .unwrap_or(0);
    match best {
        4 => "critical",
        3 => "high",
        2 => "medium",
        1 => "low",
        _ => "medium",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Findings from observed components
// ─────────────────────────────────────────────────────────────────────────────

fn vuln_finding(
    cmp: &ObservedComponent,
    vulns: &[OsvVuln],
    target: &str,
    reachability: &str,
    dep_path: &[String],
    is_direct: bool,
) -> Value {
    let version = cmp.version.clone().unwrap_or_default();
    let osv_ids: Vec<String> = vulns.iter().map(|v| v.id.clone()).collect();
    let cves: Vec<String> = vulns.iter().filter_map(|v| v.cve.clone()).collect();
    let summaries: Vec<String> = vulns
        .iter()
        .map(|v| v.summary.clone())
        .filter(|s| !s.is_empty())
        .collect();
    let vectors: Vec<String> = vulns.iter().filter_map(|v| v.cvss_vector.clone()).collect();
    let max_cvss = vulns
        .iter()
        .filter_map(|v| v.cvss_score)
        .fold(None, |acc: Option<f64>, x| {
            Some(acc.map_or(x, |a| a.max(x)))
        });
    let sev = max_severity(vulns);
    let cve_first = cves.first().cloned().unwrap_or_default();
    let reachable = matches!(reachability, "client_runtime" | "direct" | "transitive");
    let path_str = if dep_path.is_empty() {
        String::new()
    } else {
        dep_path.join(" → ")
    };
    let reach_note = match reachability {
        "client_runtime" => " It is shipped in a JavaScript bundle the target serves to clients (runtime-reachable).".to_string(),
        "direct" => " It is a DIRECT (top-level) dependency.".to_string(),
        "transitive" if !path_str.is_empty() => format!(" It is a transitive dependency pulled in via: {path_str}."),
        "transitive" => " It is a transitive dependency.".to_string(),
        _ => String::new(),
    };

    let osv_body = json!({
        "version": version,
        "package": { "name": cmp.name, "ecosystem": cmp.ecosystem.osv() }
    });
    let poc = format!(
        "# 1) Evidence the component is actually present on the target:\n\
         curl -sS '{}'\n\
         # 2) Confirm the advisory applies to the OBSERVED version (OSV does the range match):\n\
         curl -sS -X POST 'https://api.osv.dev/v1/query' -H 'Content-Type: application/json' -d '{}'",
        cmp.evidence_url,
        serde_json::to_string(&osv_body).unwrap_or_default()
    );

    supply_finding(
        &format!(
            "Vulnerable {} dependency '{}@{}'",
            cmp.ecosystem.label(),
            cmp.name,
            version
        ),
        sev,
        &format!(
            "{}@{} is present on the target (evidence: {} fetched from {}). OSV confirms {} advisory/ies affecting this exact version{}.{}",
            cmp.name,
            version,
            cmp.evidence_kind,
            cmp.evidence_url,
            vulns.len(),
            if cves.is_empty() {
                String::new()
            } else {
                format!(": {}", cves.join(", "))
            },
            reach_note
        ),
        target,
        json!({
            "package": cmp.name,
            "ecosystem": cmp.ecosystem.label(),
            "version": version,
            "vuln_count": vulns.len(),
            "osv_ids": osv_ids,
            "cves": cves,
            "cve": cve_first,
            "osv_summaries": summaries,
            "cvss_score": max_cvss,
            "cvss_vectors": vectors,
            "evidence_url": cmp.evidence_url,
            "evidence_kind": cmp.evidence_kind,
            "evidence_excerpt": cmp.evidence_excerpt,
            "reachability": reachability,
            "reachable": reachable,
            "is_direct_dependency": is_direct,
            "dependency_path": dep_path,
            "poc_exploit": poc,
            "discovery": cmp.evidence_kind,
        }),
    )
}

fn typosquat_finding(
    cmp: &ObservedComponent,
    similar: &str,
    target: &str,
    reachability: &str,
    is_direct: bool,
) -> Value {
    supply_finding(
        &format!("Possible typosquat dependency '{}'", cmp.name),
        "high",
        &format!(
            "'{}' is present on the target (evidence: {} at {}, reachability: {}) and is within edit-distance of the popular package '{}'. \
             Verify this is the intended package and not a malicious typosquat / dependency-confusion artifact.",
            cmp.name, cmp.evidence_kind, cmp.evidence_url, reachability, similar
        ),
        target,
        json!({
            "package": cmp.name,
            "ecosystem": cmp.ecosystem.label(),
            "version": cmp.version.clone().unwrap_or_default(),
            "typosquat_risk": true,
            "typosquat_similar_to": similar,
            "evidence_url": cmp.evidence_url,
            "evidence_kind": cmp.evidence_kind,
            "evidence_excerpt": cmp.evidence_excerpt,
            "reachability": reachability,
            "is_direct_dependency": is_direct,
            "discovery": cmp.evidence_kind,
        }),
    )
}

fn inventory_finding(comps: &[ObservedComponent], graph: &DepGraph, target: &str) -> Value {
    let total = comps.len();
    let mut by_eco: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_reach: BTreeMap<&str, usize> = BTreeMap::new();
    let sample: Vec<Value> = comps
        .iter()
        .take(80)
        .map(|c| {
            let reach = reachability_tier(graph, c.ecosystem, &c.name, c.evidence_kind);
            json!({
                "package": c.name,
                "ecosystem": c.ecosystem.label(),
                "version": c.version.clone().unwrap_or_default(),
                "evidence_kind": c.evidence_kind,
                "evidence_url": c.evidence_url,
                "reachability": reach
            })
        })
        .collect();
    for c in comps {
        *by_eco.entry(c.ecosystem.label()).or_default() += 1;
        *by_reach
            .entry(reachability_tier(
                graph,
                c.ecosystem,
                &c.name,
                c.evidence_kind,
            ))
            .or_default() += 1;
    }
    // Bounded edge + direct lists so the UI can draw the actual dependency graph.
    const MAX_GRAPH_EXPORT: usize = 200;
    let edges: Vec<[String; 2]> = graph
        .edges
        .iter()
        .flat_map(|(parent, kids)| {
            let p = gkey_name(parent);
            kids.iter()
                .map(move |c| [p.clone(), gkey_name(c)])
                .collect::<Vec<_>>()
        })
        .take(MAX_GRAPH_EXPORT)
        .collect();
    let direct_deps: Vec<String> = graph
        .direct
        .iter()
        .map(|k| gkey_name(k))
        .take(MAX_GRAPH_EXPORT)
        .collect();
    supply_finding(
        &format!("Reconstructed dependency inventory ({total} components)"),
        "info",
        &format!(
            "Reconstructed {} dependency component(s) directly observed on the target across {} ecosystem(s), \
             with a {}-edge dependency graph and {} direct dependency/ies resolved. \
             This is the ground-truth inventory used for vulnerability matching — derived only from artifacts the target serves, with no registry name-guessing.",
            total,
            by_eco.len(),
            graph.edge_count(),
            graph.direct.len()
        ),
        target,
        json!({
            "components_observed": total,
            "by_ecosystem": by_eco,
            "by_reachability": by_reach,
            "dependency_graph": {
                "nodes": graph.nodes.len(),
                "edges": graph.edge_count(),
                "direct": graph.direct.len()
            },
            "dependency_edges": edges,
            "direct_dependencies": direct_deps,
            "components": sample,
            "discovery": "evidence_inventory"
        }),
    )
}

fn dedupe_components(comps: Vec<ObservedComponent>) -> Vec<ObservedComponent> {
    let mut map: BTreeMap<(String, String, String), ObservedComponent> = BTreeMap::new();
    for c in comps {
        let key = (
            c.ecosystem.label().to_string(),
            c.name.clone(),
            c.version.clone().unwrap_or_default(),
        );
        map.entry(key).or_insert(c);
    }
    // Collapse version-less duplicates when a versioned record for the same
    // (ecosystem, name) already exists.
    let mut versioned: HashSet<(String, String)> = HashSet::new();
    for ((eco, name, ver), _) in &map {
        if !ver.is_empty() {
            versioned.insert((eco.clone(), name.clone()));
        }
    }
    map.into_iter()
        .filter(|((eco, name, ver), _)| {
            !(ver.is_empty() && versioned.contains(&(eco.clone(), name.clone())))
        })
        .map(|(_, v)| v)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Typosquat heuristic (now applied ONLY to components proven present on target)
// ─────────────────────────────────────────────────────────────────────────────

/// Detect a likely typosquat: a *present* package whose name is suspiciously close
/// to a well-known package. Returns the likely impersonated package name.
fn detect_typosquat(name: &str) -> Option<String> {
    const POPULAR_PACKAGES: &[&str] = &[
        "lodash",
        "express",
        "react",
        "vue",
        "angular",
        "axios",
        "moment",
        "chalk",
        "debug",
        "request",
        "underscore",
        "bluebird",
        "commander",
        "webpack",
        "babel",
        "eslint",
        "typescript",
        "jest",
        "mocha",
        "passport",
        "mongoose",
        "sequelize",
        "knex",
        "pg",
        "mysql",
        "redis",
        "socket.io",
        "ws",
        "node-fetch",
        "cross-fetch",
        "dotenv",
        "uuid",
        "fs-extra",
        "glob",
        "rimraf",
        "semver",
        "minimist",
        "yargs",
        "inquirer",
        "ora",
        "jsonwebtoken",
        "bcrypt",
        "crypto-js",
        "helmet",
        "cors",
        "body-parser",
        "multer",
        "nodemailer",
        "aws-sdk",
    ];
    let name_lower = name.trim_start_matches('@').to_lowercase();
    for &popular in POPULAR_PACKAGES {
        if name_lower == popular {
            return None;
        }
        let max_dist = if popular.len() <= 8 { 2 } else { 3 };
        if levenshtein_distance(&name_lower, popular) <= max_dist {
            return Some(popular.to_string());
        }
        if (name_lower.starts_with(popular) || name_lower.ends_with(popular))
            && name_lower != popular
            && name_lower.len() <= popular.len() + 5
        {
            return Some(popular.to_string());
        }
    }
    None
}

fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len();
    let n = b.len();
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    if m.abs_diff(n) > 4 {
        return usize::MAX;
    }
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1])
            };
        }
    }
    dp[m][n]
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry points
// ─────────────────────────────────────────────────────────────────────────────

pub async fn run_supply_chain_result(
    target: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> EngineResult {
    let target = target.trim();
    if target.is_empty() {
        return EngineResult::error("target required");
    }

    let c = match stealth {
        Some(s) => {
            stealth_engine::apply_jitter(s).await;
            stealth_engine::build_client(s, TIMEOUT_SECS)
        }
        None => default_client().await,
    };
    let c = Arc::new(c);
    let st: Option<stealth_engine::StealthConfig> = stealth.cloned();

    // 1) Collect evidence from the target: exposed manifests/SBOMs + front-end bundles.
    let (manifest_res, frontend_res) = tokio::join!(
        harvest_manifests(Arc::clone(&c), target, st.as_ref()),
        harvest_frontend(Arc::clone(&c), target, st.as_ref()),
    );
    let (mut findings, mut comps, graph) = manifest_res;
    let (fe_findings, fe_comps) = frontend_res;
    findings.extend(fe_findings);
    comps.extend(fe_comps);

    let comps = dedupe_components(comps);

    if comps.is_empty() {
        // No dependency was proven present on the target — we do NOT invent any.
        if findings.is_empty() {
            return empty_ok("supply_chain", target);
        }
        let msg = format!(
            "Supply chain: {} evidence finding(s); no resolvable components",
            findings.len()
        );
        return EngineResult::ok(findings, msg);
    }

    // 2) Typosquat / dependency-confusion on packages proven present.
    for cmp in &comps {
        if cmp.ecosystem == Ecosystem::Npm {
            if let Some(sim) = detect_typosquat(&cmp.name) {
                let reach = reachability_tier(&graph, cmp.ecosystem, &cmp.name, cmp.evidence_kind);
                let is_direct = graph.is_direct(cmp.ecosystem, &cmp.name);
                findings.push(typosquat_finding(cmp, &sim, target, reach, is_direct));
            }
        }
    }

    // 3) Version-anchored OSV lookups — only components with a resolved version.
    //    Reachability + dependency path are computed up-front (sync, off the graph)
    //    so the async OSV tasks carry owned, ready-to-serialize context.
    struct OsvCandidate {
        cmp: ObservedComponent,
        reachability: &'static str,
        dep_path: Vec<String>,
        is_direct: bool,
    }
    let to_query: Vec<OsvCandidate> = comps
        .iter()
        .filter(|c| c.version.is_some())
        .take(MAX_COMPONENTS_FOR_OSV)
        .map(|c| OsvCandidate {
            cmp: c.clone(),
            reachability: reachability_tier(&graph, c.ecosystem, &c.name, c.evidence_kind),
            dep_path: dependency_path(&graph, c.ecosystem, &c.name),
            is_direct: graph.is_direct(c.ecosystem, &c.name),
        })
        .collect();

    let vuln_findings: Vec<Value> = stream::iter(to_query.into_iter().map(|q| {
        let c = Arc::clone(&c);
        let st = st.clone();
        async move {
            let ver = q.cmp.version.clone().unwrap_or_default();
            let vulns =
                query_osv(c.as_ref(), q.cmp.ecosystem, &q.cmp.name, &ver, st.as_ref()).await;
            if vulns.is_empty() {
                None
            } else {
                Some(vuln_finding(
                    &q.cmp,
                    &vulns,
                    target,
                    q.reachability,
                    &q.dep_path,
                    q.is_direct,
                ))
            }
        }
    }))
    .buffer_unordered(OSV_CONCURRENCY)
    .filter_map(|x| async move { x })
    .collect()
    .await;

    findings.extend(vuln_findings);

    // 4) Always surface the reconstructed inventory + dependency graph (evidence base).
    findings.push(inventory_finding(&comps, &graph, target));

    let msg = format!(
        "Supply chain: {} finding(s) from {} observed component(s)",
        findings.len(),
        comps.len()
    );
    EngineResult::ok(findings, msg)
}

pub async fn run_supply_chain(target: &str) {
    print_result(run_supply_chain_result(target, None).await);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — all pure (no network): parsers, purl, CVSS, graph, reachability.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(v: &'a [ObservedComponent], name: &str) -> Option<&'a ObservedComponent> {
        v.iter().find(|c| c.name == name)
    }
    fn ver(v: &[ObservedComponent], name: &str) -> Option<String> {
        find(v, name).and_then(|c| c.version.clone())
    }

    #[test]
    fn version_normalisation_accepts_pins_rejects_ranges() {
        assert_eq!(normalize_exact_version("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(
            normalize_exact_version("==2.31.0").as_deref(),
            Some("2.31.0")
        );
        assert_eq!(normalize_exact_version("v1.9.1").as_deref(), Some("1.9.1"));
        assert_eq!(
            normalize_exact_version("1.0.0-beta.1").as_deref(),
            Some("1.0.0-beta.1")
        );
        // Ranges / wildcards / tags must NOT resolve to a version.
        assert!(normalize_exact_version("^4.17.0").is_none());
        assert!(normalize_exact_version("~1.2.0").is_none());
        assert!(normalize_exact_version(">=1.0.0 <2.0.0").is_none());
        assert!(normalize_exact_version("1.2.x").is_none());
        assert!(normalize_exact_version("*").is_none());
        assert!(normalize_exact_version("latest").is_none());
    }

    #[test]
    fn npm_package_lock_v3_components_and_graph() {
        let body = r#"{
            "name": "app", "lockfileVersion": 3,
            "packages": {
                "": { "name": "app", "version": "1.0.0", "dependencies": { "lodash": "^4.17.0" } },
                "node_modules/lodash": { "version": "4.17.21", "dependencies": { "leftpad": "^1.0.0" } },
                "node_modules/leftpad": { "version": "1.0.0" },
                "node_modules/@babel/core": { "version": "7.24.0" }
            }
        }"#;
        let comps = parse_components("/package-lock.json", body, "u");
        assert_eq!(ver(&comps, "lodash").as_deref(), Some("4.17.21"));
        assert_eq!(ver(&comps, "leftpad").as_deref(), Some("1.0.0"));
        assert_eq!(ver(&comps, "@babel/core").as_deref(), Some("7.24.0"));
        assert_eq!(find(&comps, "lodash").unwrap().ecosystem, Ecosystem::Npm);

        let mut g = DepGraph::default();
        extract_graph("/package-lock.json", body, &mut g);
        assert!(g.is_direct(Ecosystem::Npm, "lodash"));
        assert_eq!(
            reachability_tier(&g, Ecosystem::Npm, "lodash", "npm_lockfile"),
            "direct"
        );
        assert_eq!(
            reachability_tier(&g, Ecosystem::Npm, "leftpad", "npm_lockfile"),
            "transitive"
        );
        assert_eq!(
            dependency_path(&g, Ecosystem::Npm, "leftpad"),
            vec!["lodash".to_string(), "leftpad".to_string()]
        );
    }

    #[test]
    fn npm_package_lock_v1_nested() {
        let body = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": { "version": "4.17.21", "requires": { "leftpad": "1.0.0" } },
                "leftpad": { "version": "1.0.0" }
            }
        }"#;
        let comps = parse_components("/package-lock.json", body, "u");
        assert_eq!(ver(&comps, "lodash").as_deref(), Some("4.17.21"));
        let mut g = DepGraph::default();
        extract_graph("/package-lock.json", body, &mut g);
        // v1 lockfile has no root declaration; leftpad is reachable via lodash edge.
        assert_eq!(
            dependency_path(&g, Ecosystem::Npm, "leftpad"),
            vec!["lodash".to_string(), "leftpad".to_string()]
        );
    }

    #[test]
    fn package_json_pins_only() {
        let body = r#"{ "dependencies": { "pinned": "1.2.3", "ranged": "^4.0.0" } }"#;
        let comps = parse_components("/package.json", body, "u");
        assert_eq!(ver(&comps, "pinned").as_deref(), Some("1.2.3"));
        // A range is recorded as inventory (no version) so it is never OSV-matched.
        assert!(ver(&comps, "ranged").is_none());
        assert!(find(&comps, "ranged").is_some());
    }

    #[test]
    fn yarn_lock_classic_and_graph_edges() {
        let body = "# yarn lockfile v1\n\
lodash@^4.17.0:\n  version \"4.17.21\"\n  resolved \"x\"\n  dependencies:\n    leftpad \"^1.0.0\"\n\n\
\"@babel/core@^7.0.0\":\n  version \"7.24.0\"\n";
        let comps = parse_components("/yarn.lock", body, "u");
        assert_eq!(ver(&comps, "lodash").as_deref(), Some("4.17.21"));
        assert_eq!(ver(&comps, "@babel/core").as_deref(), Some("7.24.0"));
        let mut g = DepGraph::default();
        extract_graph("/yarn.lock", body, &mut g);
        assert_eq!(
            reachability_tier(&g, Ecosystem::Npm, "leftpad", "yarn_lockfile"),
            "transitive"
        );
    }

    #[test]
    fn pnpm_key_splitting() {
        assert_eq!(
            pnpm_split("/lodash@4.17.21"),
            Some(("lodash".to_string(), "4.17.21".to_string()))
        );
        assert_eq!(
            pnpm_split("/@babel/core@7.24.0(peer)"),
            Some(("@babel/core".to_string(), "7.24.0".to_string()))
        );
        assert_eq!(
            pnpm_split("/lodash/4.17.21"),
            Some(("lodash".to_string(), "4.17.21".to_string()))
        );
    }

    #[test]
    fn python_requirements_and_pipfile() {
        let req =
            "flask==2.3.0\nrequests>=2.0\n# comment\nDjango[argon2]==4.2.0 ; python_version>'3'\n";
        let comps = parse_components("/requirements.txt", req, "u");
        assert_eq!(ver(&comps, "flask").as_deref(), Some("2.3.0"));
        assert_eq!(ver(&comps, "Django").as_deref(), Some("4.2.0"));
        assert!(find(&comps, "requests").is_none()); // non-pinned range skipped
        assert_eq!(find(&comps, "flask").unwrap().ecosystem, Ecosystem::PyPI);

        let pip = r#"{ "default": { "urllib3": { "version": "==2.0.7" } } }"#;
        let pc = parse_components("/Pipfile.lock", pip, "u");
        assert_eq!(ver(&pc, "urllib3").as_deref(), Some("2.0.7"));
    }

    #[test]
    fn cargo_and_poetry_toml_blocks() {
        let cargo = "[[package]]\nname = \"serde\"\nversion = \"1.0.197\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.36.0\"\n";
        let comps = parse_components("/Cargo.lock", cargo, "u");
        assert_eq!(ver(&comps, "serde").as_deref(), Some("1.0.197"));
        assert_eq!(
            find(&comps, "tokio").unwrap().ecosystem,
            Ecosystem::CratesIo
        );

        let poetry = "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n";
        let pc = parse_components("/poetry.lock", poetry, "u");
        assert_eq!(find(&pc, "requests").unwrap().ecosystem, Ecosystem::PyPI);
    }

    #[test]
    fn go_sum_and_mod() {
        let gosum = "github.com/foo/bar v1.2.3 h1:abc=\ngithub.com/foo/bar v1.2.3/go.mod h1:def=\n";
        let comps = parse_components("/go.sum", gosum, "u");
        assert_eq!(comps.len(), 1);
        assert_eq!(ver(&comps, "github.com/foo/bar").as_deref(), Some("1.2.3"));

        let gomod = "module example.com/app\ngo 1.21\nrequire (\n    github.com/gin-gonic/gin v1.9.1\n    github.com/x/y v0.1.0 // indirect\n)\n";
        let mut g = DepGraph::default();
        extract_graph("/go.mod", gomod, &mut g);
        assert!(g.is_direct(Ecosystem::Go, "github.com/gin-gonic/gin"));
    }

    #[test]
    fn composer_and_gemfile() {
        let composer = r#"{ "packages": [
            { "name": "monolog/monolog", "version": "2.9.1", "require": { "php": ">=7.2", "psr/log": "^1.0" } },
            { "name": "psr/log", "version": "1.1.4" }
        ] }"#;
        let comps = parse_components("/composer.lock", composer, "u");
        assert_eq!(ver(&comps, "monolog/monolog").as_deref(), Some("2.9.1"));
        let mut g = DepGraph::default();
        extract_graph("/composer.lock", composer, &mut g);
        assert_eq!(
            reachability_tier(&g, Ecosystem::Packagist, "psr/log", "composer_lock"),
            "transitive"
        );

        let gem = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n    rack (2.2.3)\n\nPLATFORMS\n  ruby\n";
        let gc = parse_components("/Gemfile.lock", gem, "u");
        assert_eq!(ver(&gc, "rake").as_deref(), Some("13.0.6"));
        assert_eq!(find(&gc, "rack").unwrap().ecosystem, Ecosystem::RubyGems);
    }

    #[test]
    fn cyclonedx_components_graph_and_purl() {
        let body = r#"{
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": { "component": { "bom-ref": "root-ref", "name": "app" } },
            "components": [
                { "bom-ref": "pkg:npm/express@4.18.2", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2" },
                { "bom-ref": "pkg:npm/qs@6.11.0", "name": "qs", "version": "6.11.0", "purl": "pkg:npm/qs@6.11.0" }
            ],
            "dependencies": [
                { "ref": "root-ref", "dependsOn": ["pkg:npm/express@4.18.2"] },
                { "ref": "pkg:npm/express@4.18.2", "dependsOn": ["pkg:npm/qs@6.11.0"] }
            ]
        }"#;
        let comps = parse_components("/sbom.json", body, "u");
        assert_eq!(ver(&comps, "express").as_deref(), Some("4.18.2"));
        assert_eq!(ver(&comps, "qs").as_deref(), Some("6.11.0"));

        let mut g = DepGraph::default();
        extract_graph("/sbom.json", body, &mut g);
        assert!(g.is_direct(Ecosystem::Npm, "express"));
        assert_eq!(
            dependency_path(&g, Ecosystem::Npm, "qs"),
            vec!["express".to_string(), "qs".to_string()]
        );
    }

    #[test]
    fn spdx_components_and_relationships() {
        let body = r#"{
            "spdxVersion": "SPDX-2.3",
            "packages": [
                { "SPDXID": "SPDXRef-express", "name": "express", "versionInfo": "4.18.2",
                  "externalRefs": [{ "referenceType": "purl", "referenceLocator": "pkg:npm/express@4.18.2" }] },
                { "SPDXID": "SPDXRef-qs", "name": "qs", "versionInfo": "6.11.0",
                  "externalRefs": [{ "referenceType": "purl", "referenceLocator": "pkg:npm/qs@6.11.0" }] }
            ],
            "relationships": [
                { "spdxElementId": "SPDXRef-express", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-qs" }
            ]
        }"#;
        let comps = parse_components("/spdx.json", body, "u");
        assert_eq!(ver(&comps, "express").as_deref(), Some("4.18.2"));
        let mut g = DepGraph::default();
        extract_graph("/spdx.json", body, &mut g);
        assert_eq!(
            dependency_path(&g, Ecosystem::Npm, "qs"),
            vec!["express".to_string(), "qs".to_string()]
        );
    }

    #[test]
    fn purl_parsing_handles_scopes_and_maven() {
        let (e, n, v) = parse_purl("pkg:npm/%40babel/core@7.24.0");
        assert_eq!(e, Some(Ecosystem::Npm));
        assert_eq!(n, "@babel/core");
        assert_eq!(v.as_deref(), Some("7.24.0"));

        let (e, n, _) = parse_purl("pkg:maven/org.apache.commons/commons-lang3@3.12.0");
        assert_eq!(e, Some(Ecosystem::Maven));
        assert_eq!(n, "org.apache.commons:commons-lang3");

        let (e, n, v) = parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.1");
        assert_eq!(e, Some(Ecosystem::Go));
        assert_eq!(n, "github.com/gin-gonic/gin");
        assert_eq!(v.as_deref(), Some("1.9.1"));
    }

    #[test]
    fn cvss31_base_scores_match_spec() {
        // CVE-2023-50728 vector (NVD) → 7.5 HIGH.
        let s = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H").unwrap();
        assert!((s - 7.5).abs() < 1e-9, "got {s}");
        assert_eq!(severity_bucket(s), "high");

        // Full-impact network → 9.8 CRITICAL.
        let s = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert!((s - 9.8).abs() < 1e-9, "got {s}");
        assert_eq!(severity_bucket(s), "critical");

        // Scope-changed worst case → 10.0.
        let s = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").unwrap();
        assert!((s - 10.0).abs() < 1e-9, "got {s}");

        // Low-impact local → low bucket.
        let s = cvss3_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N").unwrap();
        assert_eq!(severity_bucket(s), "low");

        assert!(cvss3_base_score("not-a-vector").is_none());
    }

    #[test]
    fn severity_buckets_boundaries() {
        assert_eq!(severity_bucket(9.0), "critical");
        assert_eq!(severity_bucket(7.0), "high");
        assert_eq!(severity_bucket(4.0), "medium");
        assert_eq!(severity_bucket(0.1), "low");
        assert_eq!(severity_bucket(0.0), "info");
    }

    #[test]
    fn typosquat_detection() {
        assert_eq!(detect_typosquat("lodahs").as_deref(), Some("lodash"));
        assert_eq!(detect_typosquat("expresss").as_deref(), Some("express"));
        assert!(detect_typosquat("lodash").is_none());
        assert!(detect_typosquat("totally-unrelated-xyz").is_none());
    }

    #[test]
    fn sourcemap_and_node_modules_extraction() {
        assert_eq!(
            npm_name_from_node_modules_path("webpack:///./node_modules/lodash/index.js").as_deref(),
            Some("lodash")
        );
        assert_eq!(
            npm_name_from_node_modules_path("../node_modules/@babel/runtime/helpers/x.js")
                .as_deref(),
            Some("@babel/runtime")
        );

        assert_eq!(
            find_sourcemap_ref("code();\n//# sourceMappingURL=app.js.map").as_deref(),
            Some("app.js.map")
        );
        assert!(
            find_sourcemap_ref("//# sourceMappingURL=data:application/json;base64,xxx").is_none()
        );

        let map = r#"{ "version": 3, "sources": ["webpack:///./node_modules/lodash/lodash.js", "./src/app.js"] }"#;
        let comps = extract_sourcemap_components(map, "m");
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].name, "lodash");
        assert!(comps[0].version.is_none());
        assert_eq!(comps[0].evidence_kind, "js_sourcemap");
    }

    #[test]
    fn banner_signature_extraction() {
        let sigs = frontend_signatures();
        let js = "/*! jQuery v3.4.1 | (c) JS Foundation */\n!function(){}();";
        let comps = extract_banner_components(js, "a.js", &sigs);
        let jq = comps.iter().find(|c| c.name == "jquery").expect("jquery");
        assert_eq!(jq.version.as_deref(), Some("3.4.1"));
        assert_eq!(jq.evidence_kind, "js_bundle_banner");
    }

    #[test]
    fn dedupe_prefers_versioned() {
        let comps = vec![
            comp(
                Ecosystem::Npm,
                "lodash",
                Some("4.17.21".into()),
                "u",
                "npm_lockfile",
                "x",
            ),
            comp(
                Ecosystem::Npm,
                "lodash",
                Some("4.17.21".into()),
                "u2",
                "yarn_lockfile",
                "y",
            ),
            comp(Ecosystem::Npm, "lodash", None, "m", "js_sourcemap", "z"),
            comp(Ecosystem::Npm, "express", None, "m", "js_sourcemap", "z"),
        ];
        let out = dedupe_components(comps);
        // lodash collapses to a single versioned record; express (no version) stays.
        assert_eq!(out.iter().filter(|c| c.name == "lodash").count(), 1);
        assert_eq!(
            ver(&out, "lodash").as_deref(),
            Some("4.17.21"),
            "versioned record must win"
        );
        assert!(find(&out, "express").is_some());
    }

    #[test]
    fn reachability_client_runtime_wins() {
        let g = DepGraph::default();
        assert_eq!(
            reachability_tier(&g, Ecosystem::Npm, "anything", "js_sourcemap"),
            "client_runtime"
        );
        assert_eq!(
            reachability_tier(&g, Ecosystem::Npm, "unknown", "npm_lockfile"),
            "declared"
        );
    }
}
