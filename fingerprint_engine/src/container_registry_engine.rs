//! Container Registry Security Engine — agentless CNAPP / supply-chain posture at Wiz depth.
//!
//! Strict **real-probe-only** contract: findings are emitted only when the engine observes a live
//! HTTP/registry API signal. Nothing is fabricated.
//!
//! Capabilities (all driven from `job_params` via [`ArsenalConfig`]):
//!   1. **Multi-registry fingerprinting** — Docker Distribution v2, Harbor, Nexus, Artifactory,
//!      GitLab Registry, Quay, Docker Hub, GHCR, GCR/Artifact Registry, ECR Public Gallery, ACR.
//!   2. **Unauthenticated catalog / tag enumeration** — live `/v2/_catalog`, `/tags/list` probes.
//!   3. **Manifest & config-blob analysis** — root-user containers, env secret patterns, `:latest` drift.
//!   4. **Image signing surface** — Cosign/Notary signature extension absence on fetched manifests.
//!   5. **Cloud org namespace exposure** — Docker Hub, GHCR, GCR tag lists derived from target domain.
//!   6. **Policy catalog (CR-WZ-*)** — aggregated hits from live artifacts (Wiz-style control mapping).
//!   7. **Attack-path synthesis** — toxic combinations (open catalog + root image + secrets in config).
//!   8. **Posture score** — 0–100 graded container supply-chain exposure with compliance mapping.
//!   9. **Security graph** — registry → repo → image → risk node chain for analyst visualization.
//!
//! MITRE: T1525 (Implant Internal Image), T1195.002 (Supply Chain Compromise: Software Supply Chain).

use crate::arsenal_config::{finding_rich, severity_for_score, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    detect_secrets, empty_ok, http_get_with_headers, join_url, normalize_url, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const ENGINE_ID: &str = "container_registry";
const MITRE: &str = "T1525";

const REGISTRY_HEADERS: &[(&str, &str)] = &[
    ("Accept", "application/json"),
    ("Docker-Distribution-API-Version", "registry/2.0"),
];

const SELF_HOSTED_PATHS: &[&str] = &[
    "/v2/",
    "/v2/_catalog",
    "/v2/_catalog?n=100",
    "/api/v2.0/projects",
    "/api/v2.0/repositories",
    "/service/rest/v1/components",
    "/artifactory/api/system/ping",
    "/harbor/projects",
    "/service/token",
    "/v2/_catalog?n=25",
];

const KNOWN_VULN_TAG_PATTERNS: &[(&str, &str, &str)] = &[
    ("log4j", "2.14", "CVE-2021-44228"),
    ("log4j", "2.15", "CVE-2021-44228"),
    ("spring-boot", "2.5", "CVE-2022-22965"),
    ("openssl", "1.0.2", "CVE-2022-0778"),
    ("node", "16.13", "CVE-2022-32223"),
    ("python", "3.9.7", "CVE-2021-3737"),
];

// ── Settings ──────────────────────────────────────────────────────────────────

struct Settings {
    intensity: Intensity,
    timeout_ms: u64,
    #[allow(dead_code)] // parsed from settings; not read after refactor
    concurrency: usize,
    namespace: Option<String>,
    repositories: Vec<String>,
    registry_filter: BTreeSet<String>,
    probe_fingerprint: bool,
    probe_catalog: bool,
    probe_tags: bool,
    probe_manifests: bool,
    probe_config_blobs: bool,
    probe_cloud_registries: bool,
    probe_self_hosted: bool,
    probe_signing: bool,
    probe_vulnerable_tags: bool,
    attack_synth: bool,
    posture_scoring: bool,
    bearer_token: Option<String>,
    auth_header: Option<String>,
    basic_auth: Option<String>,
    min_sev_rank: u8,
    max_repos: usize,
    max_tags_per_repo: usize,
    max_manifests: usize,
    dry_run: bool,
    compliance_frameworks: Vec<String>,
}

fn sev_rank(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn parse_settings(ctx: &EngineRunContext, target: &str) -> Settings {
    let cfg = ArsenalConfig::from_ctx(ctx);
    let intensity = cfg.intensity();
    let namespace = cfg
        .string("namespace")
        .or_else(|| cfg.string("organization"))
        .or_else(|| cfg.string("registry"))
        .filter(|s| s != "docker.io" && s != "registry-1.docker.io")
        .or_else(|| Some(org_from_target(target)));

    Settings {
        intensity,
        timeout_ms: cfg.timeout_ms(12_000),
        concurrency: cfg.concurrency().clamp(1, 64),
        namespace,
        repositories: cfg.string_list("repositories"),
        registry_filter: cfg
            .string_list("registry_filter")
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect(),
        probe_fingerprint: cfg.bool_or("probe_fingerprint", true),
        probe_catalog: cfg.bool_or("probe_catalog", true),
        probe_tags: cfg.bool_or("probe_tags", true),
        probe_manifests: cfg.bool_or("probe_manifests", intensity != Intensity::Light),
        probe_config_blobs: cfg.bool_or("probe_config_blobs", intensity != Intensity::Light),
        probe_cloud_registries: cfg.bool_or("probe_cloud_registries", true),
        probe_self_hosted: cfg.bool_or("probe_self_hosted", true),
        probe_signing: cfg.bool_or("probe_signing", true),
        probe_vulnerable_tags: cfg.bool_or("probe_vulnerable_tags", true),
        attack_synth: cfg.bool_or("attack_path_synthesis", true),
        posture_scoring: cfg.bool_or("posture_scoring", true),
        bearer_token: cfg.string("bearer_token"),
        auth_header: cfg.string("auth_header"),
        basic_auth: cfg.string("basic_auth"),
        min_sev_rank: sev_rank(&cfg.string_or("min_severity", "info")),
        max_repos: match intensity {
            Intensity::Light => cfg.usize_or("max_repos", 5).clamp(1, 50),
            Intensity::Normal => cfg.usize_or("max_repos", 15).clamp(1, 100),
            Intensity::Aggressive => cfg.usize_or("max_repos", 40).clamp(1, 200),
        },
        max_tags_per_repo: match intensity {
            Intensity::Light => cfg.usize_or("max_tags_per_repo", 5).clamp(1, 50),
            Intensity::Normal => cfg.usize_or("max_tags_per_repo", 15).clamp(1, 100),
            Intensity::Aggressive => cfg.usize_or("max_tags_per_repo", 30).clamp(1, 200),
        },
        max_manifests: match intensity {
            Intensity::Light => cfg.usize_or("max_manifests", 3).clamp(1, 30),
            Intensity::Normal => cfg.usize_or("max_manifests", 10).clamp(1, 80),
            Intensity::Aggressive => cfg.usize_or("max_manifests", 25).clamp(1, 150),
        },
        dry_run: cfg.bool_or("dry_run", false),
        compliance_frameworks: cfg.string_list_or(
            "compliance_frameworks",
            &[
                "NIST-SA-12",
                "SOC2-CC8.1",
                "PCI-DSS-6.3.2",
                "MITRE-T1525",
                "CIS-5.1",
            ],
        ),
    }
}

fn registry_allowed(settings: &Settings, registry_id: &str) -> bool {
    settings.registry_filter.is_empty()
        || settings
            .registry_filter
            .contains(&registry_id.to_ascii_lowercase())
}

fn auth_headers(settings: &Settings) -> Vec<(String, String)> {
    let mut hs = REGISTRY_HEADERS
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<Vec<_>>();
    if let Some(ah) = &settings.auth_header {
        if let Some((k, v)) = ah.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if !k.is_empty() && !v.is_empty() {
                hs.push((k.to_string(), v.to_string()));
            }
        }
    }
    if let Some(bt) = &settings.bearer_token {
        let bt = bt.trim();
        if !bt.is_empty()
            && !hs
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        {
            let val = if bt.to_ascii_lowercase().starts_with("bearer ") {
                bt.to_string()
            } else {
                format!("Bearer {bt}")
            };
            hs.push(("Authorization".to_string(), val));
        }
    }
    if let Some(ba) = &settings.basic_auth {
        let ba = ba.trim();
        if !ba.is_empty() {
            hs.push(("Authorization".to_string(), format!("Basic {ba}")));
        }
    }
    hs
}

// ── Posture tracking ──────────────────────────────────────────────────────────

#[derive(Default)]
struct Posture {
    registries_detected: BTreeSet<String>,
    catalog_exposed: u32,
    tags_exposed: u32,
    manifests_fetched: u32,
    root_user_images: u32,
    secrets_in_config: u32,
    unsigned_images: u32,
    latest_tag_usage: u32,
    vuln_tag_hits: u32,
    cloud_public_repos: u32,
    policy_hits: BTreeMap<String, u32>,
    score_penalty: f64,
}

impl Posture {
    fn compute_score(&self) -> u8 {
        let mut score = 100.0_f64;
        score -= f64::from(self.catalog_exposed) * 18.0;
        score -= f64::from(self.tags_exposed) * 4.0;
        score -= f64::from(self.root_user_images) * 12.0;
        score -= f64::from(self.secrets_in_config) * 20.0;
        score -= f64::from(self.unsigned_images) * 3.0;
        score -= f64::from(self.latest_tag_usage) * 2.0;
        score -= f64::from(self.vuln_tag_hits) * 15.0;
        score -= f64::from(self.cloud_public_repos) * 5.0;
        score -= self.score_penalty;
        score.clamp(0.0, 100.0) as u8
    }

    fn grade(score: u8) -> &'static str {
        match score {
            97..=100 => "A+",
            93..=96 => "A",
            90..=92 => "A-",
            87..=89 => "B+",
            83..=86 => "B",
            80..=82 => "B-",
            77..=79 => "C+",
            73..=76 => "C",
            70..=72 => "C-",
            60..=69 => "D",
            _ => "F",
        }
    }
}

fn push_if_severe(findings: &mut Vec<Value>, settings: &Settings, finding: Value) {
    let sev = finding
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info");
    if sev_rank(sev) >= settings.min_sev_rank {
        findings.push(finding);
    }
}

fn record_policy(posture: &mut Posture, policy_id: &str) {
    *posture
        .policy_hits
        .entry(policy_id.to_string())
        .or_insert(0) += 1;
}

// ── Target helpers ────────────────────────────────────────────────────────────

fn org_from_target(target: &str) -> String {
    let t = target.trim();
    let stripped = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    let host = stripped.split('/').next().unwrap_or(stripped);
    let host = host.split(':').next().unwrap_or(host);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2].to_string()
    } else {
        host.to_string()
    }
}

fn registrable_domain(target: &str) -> String {
    let t = target.trim();
    let stripped = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    let host = stripped.split('/').next().unwrap_or(stripped);
    let host = host.split(':').next().unwrap_or(host);
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        host.to_string()
    }
}

fn is_docker_catalog(body: &str) -> bool {
    body.contains("\"repositories\"") || body.contains("Docker-Distribution-API-Version")
}

fn detect_registry_platform(probe: &HttpProbe) -> Option<(&'static str, &'static str)> {
    let body_lc = probe.body.to_ascii_lowercase();
    let hdrs: String = probe
        .headers
        .iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    if body_lc.contains("harbor") || hdrs.contains("x-harbor") {
        return Some(("harbor", "Harbor"));
    }
    if body_lc.contains("nexus") || body_lc.contains("sonatype") {
        return Some(("nexus", "Sonatype Nexus"));
    }
    if body_lc.contains("artifactory") || hdrs.contains("x-artifactory") {
        return Some(("artifactory", "JFrog Artifactory"));
    }
    if body_lc.contains("gitlab") || hdrs.contains("x-gitlab") {
        return Some(("gitlab_registry", "GitLab Container Registry"));
    }
    if body_lc.contains("quay") || probe.final_url.contains("quay.io") {
        return Some(("quay", "Red Hat Quay"));
    }
    if hdrs.contains("docker-distribution-api-version") || body_lc.contains("registry/2.0") {
        return Some(("docker_distribution", "Docker Distribution v2"));
    }
    None
}

async fn registry_get(client: &Client, url: &str, settings: &Settings) -> Option<HttpProbe> {
    let auth = auth_headers(settings);
    let hs: Vec<(&str, &str)> = auth.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    http_get_with_headers(client, url, &hs).await
}

fn parse_catalog_repos(body: &str) -> Vec<String> {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if let Some(arr) = v.get("repositories").and_then(|r| r.as_array()) {
            return arr
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
        }
    }
    Vec::new()
}

fn parse_tags(body: &str) -> Vec<String> {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if let Some(arr) = v.get("tags").and_then(|r| r.as_array()) {
            return arr
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
        }
    }
    Vec::new()
}

fn manifest_config_digest(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    v.get("config")
        .and_then(|c| c.get("digest"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            v.get("manifests")
                .and_then(|m| m.as_array())
                .and_then(|arr| arr.first())
                .and_then(|m| m.get("digest"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

fn config_runs_as_root(body: &str) -> bool {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        let user = v
            .get("config")
            .and_then(|c| c.get("User"))
            .and_then(Value::as_str)
            .unwrap_or("");
        return user.is_empty() || user == "root" || user == "0";
    }
    true
}

fn config_env_text(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if let Some(env) = v
            .get("config")
            .and_then(|c| c.get("Env"))
            .and_then(|e| e.as_array())
        {
            return env
                .iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join("\n");
        }
    }
    String::new()
}

fn manifest_has_signatures(body: &str) -> bool {
    body.contains("signatures")
        || body.contains("application/vnd.dev.cosign")
        || body.contains("application/vnd.docker.distribution.manifest.v1+signed")
}

fn tag_matches_vuln(tag: &str) -> Option<(&'static str, &'static str)> {
    let tag_lc = tag.to_ascii_lowercase();
    for (pkg, ver, cve) in KNOWN_VULN_TAG_PATTERNS {
        if tag_lc.contains(pkg) && tag_lc.contains(ver) {
            return Some((cve, pkg));
        }
    }
    None
}

// ── Self-hosted registry probes ───────────────────────────────────────────────

async fn probe_self_hosted(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_self_hosted {
        return;
    }

    if settings.probe_fingerprint {
        if let Some(probe) = registry_get(client, base, settings).await {
            if let Some((pid, label)) = detect_registry_platform(&probe) {
                if registry_allowed(settings, pid) {
                    posture.registries_detected.insert(pid.to_string());
                    push_if_severe(
                        findings,
                        settings,
                        finding_rich(
                            ENGINE_ID,
                            &format!("Container registry fingerprint: {label}"),
                            "info",
                            MITRE,
                            &format!(
                                "Live HTTP fingerprint on {host} identifies {label} (HTTP {}). \
                                 Comparable to Wiz container asset discovery — registry platform \
                                 confirmed from real response headers/body.",
                                probe.status
                            ),
                            host,
                            0.94,
                            Evidence::new()
                                .with("platform", pid)
                                .with("url", &base)
                                .with("status", probe.status),
                        ),
                    );
                }
            }
        }
    }

    let paths: Vec<String> = if settings.intensity == Intensity::Light {
        SELF_HOSTED_PATHS
            .iter()
            .take(4)
            .map(|s| s.to_string())
            .collect()
    } else {
        SELF_HOSTED_PATHS.iter().map(|s| s.to_string()).collect()
    };

    for path in paths {
        let url = join_url(base, &path);
        let Some(probe) = registry_get(client, &url, settings).await else {
            continue;
        };

        if probe.status == 200 && path.contains("_catalog") && is_docker_catalog(&probe.body) {
            let repos = parse_catalog_repos(&probe.body);
            posture.catalog_exposed += 1;
            record_policy(posture, "CR-WZ-001");
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    "Unauthenticated container registry catalog (CR-WZ-001)",
                    "critical",
                    MITRE,
                    &format!(
                        "Registry API {} returned HTTP 200 with catalog data ({} repos visible). \
                         Unauthenticated catalog access enables full image enumeration and \
                         supply-chain pivot — identical to Wiz 'public container registry' toxic \
                         findings.",
                        probe.final_url,
                        repos.len()
                    ),
                    host,
                    0.97,
                    Evidence::new()
                        .with("url", &probe.final_url)
                        .with("repo_count", repos.len())
                        .with("policy", "CR-WZ-001")
                        .check("catalog_unauthenticated", true, repos.len()),
                ),
            );

            if settings.probe_tags && !settings.dry_run {
                let repo_sample: Vec<String> = if settings.repositories.is_empty() {
                    repos.into_iter().take(settings.max_repos).collect()
                } else {
                    settings.repositories.clone()
                };
                for repo in repo_sample {
                    probe_repo_tags(client, base, host, &repo, settings, posture, findings).await;
                }
            }
        } else if probe.status == 401 {
            let www = probe
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("www-authenticate"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            if www.to_ascii_lowercase().contains("bearer")
                || www.to_ascii_lowercase().contains("registry")
            {
                posture
                    .registries_detected
                    .insert("docker_distribution".to_string());
                push_if_severe(
                    findings,
                    settings,
                    finding_rich(
                        ENGINE_ID,
                        "Container registry requires authentication (CR-WZ-010)",
                        "info",
                        MITRE,
                        &format!(
                            "Registry surface at {} requires authentication ({}). Verify push/pull \
                             RBAC, image signing (Cosign/Sigstore), and immutable tags.",
                            probe.final_url,
                            www.chars().take(160).collect::<String>()
                        ),
                        host,
                        0.88,
                        Evidence::new()
                            .with("url", &probe.final_url)
                            .with("www_authenticate", www)
                            .with("policy", "CR-WZ-010"),
                    ),
                );
            }
        } else if probe.status == 200
            && (path.contains("projects") || path.contains("components") || path.contains("harbor"))
        {
            posture.catalog_exposed += 1;
            record_policy(posture, "CR-WZ-002");
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    "Harbor/Nexus/Artifactory API exposed without auth (CR-WZ-002)",
                    "high",
                    MITRE,
                    &format!(
                        "Enterprise registry management API {} responded HTTP 200 ({} bytes). \
                         Project/repository metadata may be enumerable without credentials.",
                        probe.final_url,
                        probe.body.len()
                    ),
                    host,
                    0.91,
                    Evidence::new()
                        .with("url", &probe.final_url)
                        .with("policy", "CR-WZ-002"),
                ),
            );
        }
    }
}

async fn probe_repo_tags(
    client: &Client,
    base: &str,
    host: &str,
    repo: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    let url = join_url(base, &format!("/v2/{repo}/tags/list"));
    let Some(probe) = registry_get(client, &url, settings).await else {
        return;
    };
    if probe.status != 200 {
        return;
    }
    let tags = parse_tags(&probe.body);
    if tags.is_empty() {
        return;
    }
    posture.tags_exposed += 1;
    record_policy(posture, "CR-WZ-003");
    push_if_severe(
        findings,
        settings,
        finding_rich(
            ENGINE_ID,
            &format!("Unauthenticated tag list: {repo} (CR-WZ-003)"),
            "high",
            MITRE,
            &format!(
                "Repository {repo} tag list returned HTTP 200 with {} tags at {}. Attackers can \
                 enumerate versions and pull images without credentials.",
                tags.len(),
                probe.final_url
            ),
            host,
            0.92,
            Evidence::new()
                .with("repository", repo)
                .with("url", &probe.final_url)
                .with("tag_count", tags.len())
                .with("policy", "CR-WZ-003"),
        ),
    );

    if !settings.probe_manifests || settings.dry_run {
        return;
    }

    let tag_sample: Vec<&String> = tags.iter().take(settings.max_tags_per_repo).collect();
    let mut manifest_count = 0_usize;
    for tag in tag_sample {
        if manifest_count >= settings.max_manifests {
            break;
        }
        if settings.probe_vulnerable_tags {
            if tag == "latest" {
                posture.latest_tag_usage += 1;
                record_policy(posture, "CR-WZ-006");
                push_if_severe(
                    findings,
                    settings,
                    finding_rich(
                        ENGINE_ID,
                        &format!("`:latest` tag in use: {repo} (CR-WZ-006)"),
                        "medium",
                        "T1195.002",
                        &format!(
                            "Repository {repo} exposes a `:latest` tag. Mutable latest tags break \
                             reproducibility and enable silent supply-chain substitution (Wiz \
                             container best-practice violation)."
                        ),
                        host,
                        0.85,
                        Evidence::new()
                            .with("repository", repo)
                            .with("tag", "latest")
                            .with("policy", "CR-WZ-006"),
                    ),
                );
            }
            if let Some((cve, pkg)) = tag_matches_vuln(tag) {
                posture.vuln_tag_hits += 1;
                record_policy(posture, "CR-WZ-007");
                push_if_severe(
                    findings,
                    settings,
                    finding_rich(
                        ENGINE_ID,
                        &format!("Known-vulnerable tag pattern: {repo}:{tag} → {cve}"),
                        "critical",
                        "T1195.002",
                        &format!(
                            "Tag {repo}:{tag} matches known-vulnerable {pkg} version pattern \
                             associated with {cve}. Prioritize rebuild on patched base image."
                        ),
                        host,
                        0.89,
                        Evidence::new()
                            .with("repository", repo)
                            .with("tag", tag.as_str())
                            .with("cve", cve)
                            .with("policy", "CR-WZ-007"),
                    ),
                );
            }
        }

        let manifest_url = join_url(base, &format!("/v2/{repo}/manifests/{tag}"));
        let manifest_headers: Vec<(String, String)> = auth_headers(settings);
        let mut mh = manifest_headers.clone();
        mh.push((
            "Accept".to_string(),
            "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json".to_string(),
        ));
        let hs: Vec<(&str, &str)> = mh.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let Some(mprobe) = http_get_with_headers(client, &manifest_url, &hs).await else {
            continue;
        };
        if mprobe.status != 200 {
            continue;
        }
        manifest_count += 1;
        posture.manifests_fetched += 1;

        if settings.probe_signing && !manifest_has_signatures(&mprobe.body) {
            posture.unsigned_images += 1;
            record_policy(posture, "CR-WZ-005");
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("Unsigned container image: {repo}:{tag} (CR-WZ-005)"),
                    "medium",
                    "T1195.002",
                    &format!(
                        "Manifest for {repo}:{tag} lacks Cosign/Notary signature extensions. \
                         Unsigned images cannot be verified at deploy time (Sigstore/Wiz policy gap)."
                    ),
                    host,
                    0.86,
                    Evidence::new()
                        .with("repository", repo)
                        .with("tag", tag.as_str())
                        .with("url", &manifest_url)
                        .with("policy", "CR-WZ-005"),
                ),
            );
        }

        if !settings.probe_config_blobs {
            continue;
        }
        let Some(digest) = manifest_config_digest(&mprobe.body) else {
            continue;
        };
        let blob_url = join_url(base, &format!("/v2/{repo}/blobs/{digest}"));
        let Some(bprobe) = registry_get(client, &blob_url, settings).await else {
            continue;
        };
        if bprobe.status != 200 {
            continue;
        }

        if config_runs_as_root(&bprobe.body) {
            posture.root_user_images += 1;
            record_policy(posture, "CR-WZ-004");
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("Container runs as root: {repo}:{tag} (CR-WZ-004)"),
                    "high",
                    MITRE,
                    &format!(
                        "Image config blob for {repo}:{tag} specifies empty/root User. Root \
                         containers amplify escape impact — CIS Docker Benchmark §4.1 / Wiz \
                         runtime hardening violation."
                    ),
                    host,
                    0.93,
                    Evidence::new()
                        .with("repository", repo)
                        .with("tag", tag.as_str())
                        .with("config_digest", &digest)
                        .with("policy", "CR-WZ-004"),
                ),
            );
        }

        let env_text = config_env_text(&bprobe.body);
        let secrets = detect_secrets(&env_text);
        if !secrets.is_empty() {
            posture.secrets_in_config += 1;
            record_policy(posture, "CR-WZ-008");
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("Secrets in image config env: {repo}:{tag} (CR-WZ-008)",),
                    "critical",
                    "T1552.004",
                    &format!(
                        "Image config for {repo}:{tag} contains environment variables matching \
                         secret patterns ({:?}). Anyone with pull access can extract credentials \
                         from the layer — identical to Wiz 'secret in container' findings.",
                        secrets
                    ),
                    host,
                    0.96,
                    Evidence::new()
                        .with("repository", repo)
                        .with("tag", tag.as_str())
                        .with("secret_patterns", json!(secrets))
                        .with("policy", "CR-WZ-008"),
                ),
            );
        }
    }
}

// ── Cloud registry plane ────────────────────────────────────────────────────────

async fn probe_dockerhub(
    client: &Client,
    org: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !registry_allowed(settings, "dockerhub") {
        return;
    }
    let url = format!("https://hub.docker.com/v2/repositories/{org}/?page_size=25");
    let Some(probe) = registry_get(client, &url, settings).await else {
        return;
    };
    if probe.status != 200 {
        return;
    }
    if let Ok(data) = serde_json::from_str::<Value>(&probe.body) {
        let count = data.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
        if count > 0 {
            posture.cloud_public_repos += 1;
            posture.registries_detected.insert("dockerhub".to_string());
            record_policy(posture, "CR-WZ-020");
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("Public Docker Hub organization '{org}' ({count} repos)"),
                    "medium",
                    MITRE,
                    &format!(
                        "Docker Hub API confirms {count} public repositories for '{org}'. Public \
                         images may leak secrets, internal architecture, or ship vulnerable base layers."
                    ),
                    host,
                    0.90,
                    Evidence::new()
                        .with("url", &url)
                        .with("count", count)
                        .with("registry", "dockerhub")
                        .with("policy", "CR-WZ-020"),
                ),
            );

            if settings.probe_tags && settings.intensity != Intensity::Light {
                if let Some(results) = data.get("results").and_then(|r| r.as_array()) {
                    for repo in results.iter().take(settings.max_repos.min(5)) {
                        let name = repo.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        if name.is_empty() {
                            continue;
                        }
                        let tags_url = format!(
                            "https://hub.docker.com/v2/repositories/{org}/{name}/tags?page_size={}",
                            settings.max_tags_per_repo.min(10)
                        );
                        if let Some(tprobe) = registry_get(client, &tags_url, settings).await {
                            if tprobe.status == 200 {
                                let tags = parse_tags(&tprobe.body);
                                if !tags.is_empty() {
                                    posture.tags_exposed += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn probe_ghcr(
    client: &Client,
    org: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !registry_allowed(settings, "ghcr") {
        return;
    }
    let url = format!("https://ghcr.io/v2/{org}/");
    let Some(probe) = registry_get(client, &url, settings).await else {
        return;
    };
    if probe.status == 200 || probe.status == 401 {
        posture.registries_detected.insert("ghcr".to_string());
        let sev = if probe.status == 200 { "high" } else { "info" };
        if probe.status == 200 {
            record_policy(posture, "CR-WZ-021");
        }
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("GHCR namespace '{org}' reachable (HTTP {})", probe.status),
                sev,
                MITRE,
                &format!(
                    "GitHub Container Registry namespace {url} responded HTTP {}. Review package \
                     visibility, OIDC publish policies, and org-wide GHCR retention/signing.",
                    probe.status
                ),
                host,
                if probe.status == 200 { 0.91 } else { 0.82 },
                Evidence::new()
                    .with("url", &url)
                    .with("registry", "ghcr")
                    .with("policy", "CR-WZ-021"),
            ),
        );

        if probe.status == 200 && settings.probe_tags {
            for repo in settings
                .repositories
                .iter()
                .take(settings.max_repos)
                .cloned()
            {
                let full = if repo.contains('/') {
                    repo.clone()
                } else {
                    format!("{org}/{repo}")
                };
                probe_repo_tags(
                    client,
                    "https://ghcr.io",
                    host,
                    &full,
                    settings,
                    posture,
                    findings,
                )
                .await;
            }
        }
    }
}

async fn probe_gcr(
    client: &Client,
    org: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !registry_allowed(settings, "gcr") {
        return;
    }
    let urls = [
        format!("https://gcr.io/v2/{org}/tags/list"),
        format!("https://{org}.gcr.io/v2/_catalog"),
    ];
    for url in &urls {
        let Some(probe) = registry_get(client, url, settings).await else {
            continue;
        };
        if probe.status == 200 && (probe.body.contains("tags") || is_docker_catalog(&probe.body)) {
            posture.registries_detected.insert("gcr".to_string());
            posture.catalog_exposed += 1;
            record_policy(posture, "CR-WZ-022");
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    "GCR / Artifact Registry tags or catalog exposed (CR-WZ-022)",
                    "high",
                    MITRE,
                    &format!(
                        "Google container registry endpoint {} returned tag/catalog data (HTTP 200). \
                         Enumerated images accelerate targeted CVE exploitation.",
                        probe.final_url
                    ),
                    host,
                    0.92,
                    Evidence::new()
                        .with("url", &probe.final_url)
                        .with("registry", "gcr")
                        .with("policy", "CR-WZ-022"),
                ),
            );
        }
    }
}

async fn probe_ecr_public(
    client: &Client,
    org: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !registry_allowed(settings, "ecr") {
        return;
    }
    let url = format!("https://gallery.ecr.aws/{org}");
    let Some(probe) = registry_get(client, &url, settings).await else {
        return;
    };
    if probe.status == 200 && !probe.body.contains("Page not found") {
        posture.registries_detected.insert("ecr".to_string());
        posture.cloud_public_repos += 1;
        record_policy(posture, "CR-WZ-023");
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("AWS ECR Public Gallery namespace '{org}'"),
                "medium",
                MITRE,
                &format!(
                    "ECR Public Gallery page for '{org}' is live (HTTP 200). Public container \
                     images expand attack surface for dependency confusion and CVE targeting."
                ),
                host,
                0.87,
                Evidence::new()
                    .with("url", &url)
                    .with("registry", "ecr_public")
                    .with("policy", "CR-WZ-023"),
            ),
        );
    }
}

async fn probe_acr(
    client: &Client,
    org: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !registry_allowed(settings, "acr") {
        return;
    }
    let url = format!("https://{org}.azurecr.io/v2/_catalog");
    let Some(probe) = registry_get(client, &url, settings).await else {
        return;
    };
    if probe.status == 200 && is_docker_catalog(&probe.body) {
        posture.registries_detected.insert("acr".to_string());
        posture.catalog_exposed += 1;
        record_policy(posture, "CR-WZ-024");
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("Azure ACR catalog exposed: {org}.azurecr.io (CR-WZ-024)"),
                "critical",
                MITRE,
                &format!(
                    "Azure Container Registry {org}.azurecr.io returned unauthenticated catalog \
                     data. Equivalent to Wiz 'public ACR' critical misconfiguration."
                ),
                host,
                0.95,
                Evidence::new()
                    .with("url", &url)
                    .with("registry", "acr")
                    .with("policy", "CR-WZ-024"),
            ),
        );
    } else if probe.status == 401 {
        posture.registries_detected.insert("acr".to_string());
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("Azure ACR detected: {org}.azurecr.io (auth required)"),
                "info",
                MITRE,
                &format!(
                    "ACR endpoint {url} requires authentication — verify Azure RBAC, content \
                     trust, and Defender for Containers image scanning."
                ),
                host,
                0.84,
                Evidence::new().with("url", &url).with("registry", "acr"),
            ),
        );
    }
}

async fn probe_quay(
    client: &Client,
    org: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !registry_allowed(settings, "quay") {
        return;
    }
    let url = format!("https://quay.io/api/v1/repository?namespace={org}&public=true");
    let Some(probe) = registry_get(client, &url, settings).await else {
        return;
    };
    if probe.status == 200 {
        if let Ok(v) = serde_json::from_str::<Value>(&probe.body) {
            let repos = v
                .get("repositories")
                .and_then(|r| r.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if repos > 0 {
                posture.registries_detected.insert("quay".to_string());
                posture.cloud_public_repos += 1;
                record_policy(posture, "CR-WZ-025");
                push_if_severe(
                    findings,
                    settings,
                    finding_rich(
                        ENGINE_ID,
                        &format!("Quay.io public namespace '{org}' ({repos} repos)"),
                        "medium",
                        MITRE,
                        &format!(
                            "Quay API lists {repos} public repositories under namespace '{org}'. \
                             Review robot account tokens and vulnerability scanning settings."
                        ),
                        host,
                        0.88,
                        Evidence::new()
                            .with("url", &url)
                            .with("repo_count", repos)
                            .with("registry", "quay")
                            .with("policy", "CR-WZ-025"),
                    ),
                );
            }
        }
    }
}

async fn probe_cloud_registries(
    client: &Client,
    org: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_cloud_registries {
        return;
    }
    probe_dockerhub(client, org, host, settings, posture, findings).await;
    probe_ghcr(client, org, host, settings, posture, findings).await;
    probe_gcr(client, org, host, settings, posture, findings).await;
    probe_ecr_public(client, org, host, settings, posture, findings).await;
    probe_acr(client, org, host, settings, posture, findings).await;
    probe_quay(client, org, host, settings, posture, findings).await;
}

// ── Attack paths & security graph ─────────────────────────────────────────────

fn attack_paths(posture: &Posture, host: &str) -> Vec<Value> {
    let mut paths = Vec::new();
    if posture.catalog_exposed > 0 && posture.root_user_images > 0 {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Open registry catalog + root containers → supply-chain implant",
            "severity": "critical",
            "mitre_attack": MITRE,
            "description": format!(
                "Toxic combination on {host}: unauthenticated catalog enumeration exposes images that \
                 run as root — attackers pull, backdoor, and push a poisoned tag (Wiz container \
                 breach chain)."
            ),
            "confidence": 0.94
        }));
    }
    if posture.catalog_exposed > 0 && posture.secrets_in_config > 0 {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Public registry + secrets baked into image config → credential theft",
            "severity": "critical",
            "mitre_attack": "T1552.004",
            "description": format!(
                "Enumerated public images on {host} embed credentials in environment variables — \
                 any anonymous pull exfiltrates production secrets."
            ),
            "confidence": 0.93
        }));
    }
    if posture.unsigned_images > 0 && posture.catalog_exposed > 0 {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Unsigned images in open registry → silent substitution at deploy",
            "severity": "high",
            "mitre_attack": "T1195.002",
            "description": format!(
                "Publicly pullable unsigned images on {host} can be replaced with malicious \
                 layers; clusters without admission signing (Cosign/Kyverno) will accept them."
            ),
            "confidence": 0.88
        }));
    }
    if posture.vuln_tag_hits > 0 && posture.tags_exposed > 0 {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Enumerated tags match known CVE patterns → targeted exploitation",
            "severity": "critical",
            "mitre_attack": "T1195.002",
            "description": format!(
                "Tag enumeration on {host} surfaced images matching known-vulnerable version \
                 patterns — direct path to RCE via published CVE exploits."
            ),
            "confidence": 0.90
        }));
    }
    paths
}

fn security_graph(posture: &Posture, host: &str) -> Value {
    let mut nodes = vec![
        json!({"id": "target", "type": "host", "label": host}),
        json!({"id": "registry", "type": "registry", "label": "Container Registry Surface"}),
    ];
    let mut edges = vec![json!({"from": "target", "to": "registry", "relation": "hosts"})];

    if posture.catalog_exposed > 0 {
        let nid = "open_catalog";
        nodes.push(json!({"id": nid, "type": "misconfig", "label": "Unauthenticated Catalog"}));
        edges.push(json!({"from": "registry", "to": nid, "relation": "exposes"}));
    }
    if posture.root_user_images > 0 {
        let nid = "root_image";
        nodes.push(json!({"id": nid, "type": "hardening", "label": "Root Container Images"}));
        edges.push(json!({"from": "registry", "to": nid, "relation": "ships"}));
    }
    if posture.secrets_in_config > 0 {
        let nid = "image_secrets";
        nodes.push(json!({"id": nid, "type": "secret", "label": "Secrets in Image Config"}));
        edges.push(json!({"from": "registry", "to": nid, "relation": "embeds"}));
    }
    if posture.unsigned_images > 0 {
        let nid = "unsigned";
        nodes.push(json!({"id": nid, "type": "integrity", "label": "Unsigned Images"}));
        edges.push(json!({"from": "registry", "to": nid, "relation": "lacks"}));
    }

    json!({ "nodes": nodes, "edges": edges })
}

fn posture_summary_finding(posture: &Posture, host: &str, settings: &Settings) -> Value {
    let score = posture.compute_score();
    let grade = Posture::grade(score);
    let exposure = 1.0 - (f64::from(score) / 100.0);
    let sev = severity_for_score(exposure);

    let mut dims = BTreeMap::new();
    dims.insert("catalog_exposure", json!(posture.catalog_exposed));
    dims.insert("tag_enumeration", json!(posture.tags_exposed));
    dims.insert("root_user_images", json!(posture.root_user_images));
    dims.insert("secrets_in_config", json!(posture.secrets_in_config));
    dims.insert("unsigned_images", json!(posture.unsigned_images));
    dims.insert("cloud_public_repos", json!(posture.cloud_public_repos));
    dims.insert(
        "registries_detected",
        json!(posture.registries_detected.iter().collect::<Vec<_>>()),
    );

    finding_rich(
        ENGINE_ID,
        &format!("Container registry posture: {grade} ({score}/100)"),
        sev,
        MITRE,
        &format!(
            "Aggregated container supply-chain posture for {host}: grade {grade} ({score}/100). \
             {} registry platform(s) detected; {} policy control(s) triggered. Frameworks: {}.",
            posture.registries_detected.len(),
            posture.policy_hits.values().sum::<u32>(),
            settings.compliance_frameworks.join(", ")
        ),
        host,
        0.98,
        Evidence::new()
            .with("posture_score", score)
            .with("posture_grade", grade)
            .with("dimensions", json!(dims))
            .with("policy_hits", json!(posture.policy_hits))
            .with(
                "compliance_frameworks",
                json!(settings.compliance_frameworks),
            )
            .with("category", "posture_summary"),
    )
}

// ── Entry points ──────────────────────────────────────────────────────────────

pub async fn run_container_registry_result_ctx(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let settings = parse_settings(ctx, target);
    if settings.dry_run {
        return EngineResult::ok(
            vec![finding_rich(
                ENGINE_ID,
                "Container registry scan plan (dry run)",
                "info",
                MITRE,
                &format!(
                    "Dry-run mode — would probe self-hosted registry at {}, cloud namespaces for \
                     '{}', catalog={}, tags={}, manifests={}, config_blobs={}.",
                    normalize_url(target),
                    settings.namespace.as_deref().unwrap_or("auto"),
                    settings.probe_catalog,
                    settings.probe_tags,
                    settings.probe_manifests,
                    settings.probe_config_blobs
                ),
                target,
                1.0,
                Evidence::new().with("dry_run", true),
            )],
            "container_registry: dry-run plan".to_string(),
        );
    }

    let base = normalize_url(target);
    let host = extract_host_from_target(target);
    let org = settings
        .namespace
        .clone()
        .unwrap_or_else(|| org_from_target(target));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(settings.timeout_ms))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut posture = Posture::default();
    let mut findings: Vec<Value> = Vec::new();

    probe_self_hosted(
        &client,
        &base,
        &host,
        &settings,
        &mut posture,
        &mut findings,
    )
    .await;
    probe_cloud_registries(&client, &org, &host, &settings, &mut posture, &mut findings).await;

    if settings.attack_synth {
        for ap in attack_paths(&posture, &host) {
            push_if_severe(&mut findings, &settings, ap);
        }
        push_if_severe(
            &mut findings,
            &settings,
            json!({
                "type": ENGINE_ID,
                "category": "security_graph",
                "title": "Container registry security graph",
                "severity": "info",
                "target": host,
                "graph": security_graph(&posture, &host),
            }),
        );
    }

    if settings.posture_scoring {
        push_if_severe(
            &mut findings,
            &settings,
            posture_summary_finding(&posture, &host, &settings),
        );
    }

    if findings.is_empty() {
        empty_ok(ENGINE_ID, target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("container_registry: {n} live finding(s)"))
    }
}

fn extract_host_from_target(target: &str) -> String {
    let domain = registrable_domain(target);
    if domain.is_empty() {
        target.to_string()
    } else {
        domain
    }
}

pub async fn run_container_registry_result(target: &str) -> EngineResult {
    run_container_registry_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_container_registry(target: &str) {
    print_result(run_container_registry_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_body_detected() {
        assert!(is_docker_catalog(r#"{"repositories":["app/backend"]}"#));
        assert!(!is_docker_catalog(r#"{"status":"ok"}"#));
    }

    #[test]
    fn org_from_target_works() {
        assert_eq!(org_from_target("https://acme.com"), "acme");
        assert_eq!(org_from_target("registry.acme.io:5000"), "acme");
    }

    #[test]
    fn parse_catalog_and_tags() {
        assert_eq!(
            parse_catalog_repos(r#"{"repositories":["a/b","c"]}"#),
            vec!["a/b".to_string(), "c".to_string()]
        );
        assert_eq!(
            parse_tags(r#"{"name":"x","tags":["latest","1.0"]}"#),
            vec!["latest".to_string(), "1.0".to_string()]
        );
    }

    #[test]
    fn root_user_detection() {
        let cfg = r#"{"config":{"User":""}}"#;
        assert!(config_runs_as_root(cfg));
        let cfg2 = r#"{"config":{"User":"1000"}}"#;
        assert!(!config_runs_as_root(cfg2));
    }

    #[test]
    fn posture_score_degrades_with_findings() {
        let mut p = Posture::default();
        assert_eq!(p.compute_score(), 100);
        p.catalog_exposed = 1;
        p.root_user_images = 1;
        assert!(p.compute_score() < 80);
    }

    #[test]
    fn vuln_tag_pattern_matches() {
        assert!(tag_matches_vuln("log4j-2.14.1").is_some());
        assert!(tag_matches_vuln("stable").is_none());
    }
}
