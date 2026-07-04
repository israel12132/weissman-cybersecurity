//! CI/CD Pipeline Security Engine — agentless DevSecOps assessment at Wiz / Prisma Cloud / GitHub
//! Advanced Security depth.
//!
//! Strict **real-probe-only** contract: findings are emitted only when the engine observes a live
//! HTTP/API signal (unauthenticated CI endpoint, exposed pipeline config, workflow policy violation
//! in fetched content, secret pattern in a real response). Nothing is fabricated.
//!
//! Capabilities (all driven from `job_params` via [`ArsenalConfig`]):
//!   1. **Multi-platform CI/CD fingerprinting** — Jenkins, GitLab, ArgoCD, Tekton, Azure DevOps,
//!      GitHub Actions (self-hosted), Drone, CircleCI, Spinnaker, TeamCity, Buildkite, Harness.
//!   2. **Unauthenticated API exposure** — live endpoint probes with platform-specific body markers.
//!   3. **Pipeline config exposure** — Jenkinsfile, .gitlab-ci.yml, azure-pipelines.yml, workflows.
//!   4. **GitHub Actions static analysis** — pwn-request, script injection, unpinned actions, write-all.
//!   5. **Repository plane** — fetch CI files from public GitHub repos (optional token for private).
//!   6. **Secret leakage** — high-precision patterns in API responses and config artifacts.
//!   7. **Runner / token surface** — registration-token and build-log exposure indicators.
//!   8. **Attack-path synthesis** — toxic combinations (open Jenkins + secrets, pwn-request + self-hosted).
//!   9. **Posture score** — 0–100 graded DevSecOps exposure with compliance mapping.
//!  10. **Multi-dimensional risk** — API / pipeline integrity / secrets / runner isolation / supply-chain.
//!  11. **Policy catalog (WZ-*)** — aggregated hits from static analysis on live artifacts.
//!  12. **Build log & artifact exposure** — Jenkins Blue Ocean, GitLab jobs, artifact registries.
//!  13. **Multi-vendor repository plane** — GitHub, GitLab (self-hosted), Bitbucket Cloud, Azure DevOps
//!      recursive CI/GitOps file fetch + static analysis.
//!  14. **GitOps static analysis** — ArgoCD Application/AppProject, Tekton PipelineRun/Task.
//!  15. **Live ArgoCD API parsing** — unauthenticated Application objects expose repo URLs & sync policy.
//!  16. **Repository governance APIs** — GitHub/GitLab/Azure DevOps branch protection, token defaults,
//!      fork-PR workflow access, secret scanning enablement (live API only).
//!  17. **Embedded secret scan (WZ-SEC-001)** — high-precision patterns in fetched pipeline artifacts.
//!  18. **Compliance posture + remediation playbook** — framework-mapped scores and prioritized actions.
//!
//! MITRE: T1195.002 (Supply Chain Compromise: Software Supply Chain) / T1552.004 (Private Keys).

use crate::arsenal_config::{finding_rich, severity_for_score, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    detect_secrets, http_get_with_headers, join_url, normalize_url, status_indicates_presence,
    HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const ENGINE_ID: &str = "cicd_pipeline";
const MITRE: &str = "T1195.002";

// ── Platform endpoint corpora ───────────────────────────────────────────────────

struct PlatformDef {
    id: &'static str,
    label: &'static str,
    paths: &'static [&'static str],
    body_markers: &'static [&'static str],
    header_markers: &'static [&'static str],
}

#[rustfmt::skip]
fn platforms() -> &'static [PlatformDef] {
    &[
        PlatformDef {
            id: "jenkins", label: "Jenkins",
            paths: &["/api/json", "/computer/api/json", "/credentials/store/system/domain/_/api/json", "/script", "/manage", "/asynchPeople/"],
            body_markers: &["hudson", "jenkins", "Jenkins-Crumb"],
            header_markers: &["x-jenkins", "x-hudson"],
        },
        PlatformDef {
            id: "gitlab", label: "GitLab CI",
            paths: &["/api/v4/version", "/api/v4/runners", "/api/v4/projects", "/api/v4/pipelines", "/-/metrics", "/admin/runners"],
            body_markers: &["gitlab", "GitLab", "X-Gitlab-"],
            header_markers: &["x-gitlab-meta", "x-request-id"],
        },
        PlatformDef {
            id: "argocd", label: "ArgoCD",
            paths: &["/api/v1/applications", "/api/v1/repositories", "/api/v1/clusters", "/api/v1/projects", "/api/version", "/api/v1/settings"],
            body_markers: &["argoproj", "Argo CD", "applications"],
            header_markers: &["grpc-metadata-content-type"],
        },
        PlatformDef {
            id: "tekton", label: "Tekton",
            paths: &["/apis/tekton.dev/v1beta1/pipelineruns", "/apis/tekton.dev/v1beta1/taskruns", "/apis/tekton.dev/v1/namespaces/default/pipelines"],
            body_markers: &["tekton.dev", "PipelineRun", "TaskRun"],
            header_markers: &[],
        },
        PlatformDef {
            id: "azure_devops", label: "Azure DevOps",
            paths: &["/_apis/distributedtask/pools", "/_apis/build/builds", "/_apis/projects", "/_apis/pipelines", "/_apis/release/releases"],
            body_markers: &["visualstudio.com", "Azure DevOps", "distributedtask"],
            header_markers: &["x-tfs-processid", "x-vss-e2eid"],
        },
        PlatformDef {
            id: "github_actions", label: "GitHub Actions (self-hosted)",
            paths: &["/_apis/distributedtask/pools", "/api/v3/meta", "/api/v3/actions/runners", "/settings/actions"],
            body_markers: &["actions-runner", "GitHub Actions"],
            header_markers: &["x-github-request-id"],
        },
        PlatformDef {
            id: "drone", label: "Drone CI",
            paths: &["/api/user", "/api/repos", "/api/builds", "/api/secrets", "/api/users"],
            body_markers: &["drone", "Drone"],
            header_markers: &[],
        },
        PlatformDef {
            id: "circleci", label: "CircleCI",
            paths: &["/api/v1.1/me", "/api/v2/project", "/api/v2/pipeline"],
            body_markers: &["circleci", "CircleCI"],
            header_markers: &[],
        },
        PlatformDef {
            id: "spinnaker", label: "Spinnaker",
            paths: &["/api/v1/applications", "/gate/applications", "/api/v1/projects", "/health"],
            body_markers: &["spinnaker", "Spinnaker"],
            header_markers: &[],
        },
        PlatformDef {
            id: "teamcity", label: "TeamCity",
            paths: &["/app/rest/server", "/app/rest/builds", "/app/rest/projects", "/app/rest/agents"],
            body_markers: &["TeamCity", "BuildType", "teamcity"],
            header_markers: &[],
        },
        PlatformDef {
            id: "buildkite", label: "Buildkite",
            paths: &["/v2/organizations", "/v2/pipelines", "/v2/builds"],
            body_markers: &["buildkite", "Buildkite"],
            header_markers: &[],
        },
        PlatformDef {
            id: "harness", label: "Harness",
            paths: &["/api/users/current-user", "/api/pipelines", "/api/projects", "/gateway/api/health"],
            body_markers: &["harness", "Harness"],
            header_markers: &[],
        },
        PlatformDef {
            id: "woodpecker", label: "Woodpecker CI",
            paths: &["/api/user", "/api/repos", "/api/pipelines", "/api/builds"],
            body_markers: &["woodpecker", "Woodpecker"],
            header_markers: &[],
        },
        PlatformDef {
            id: "bitbucket", label: "Bitbucket Pipelines",
            paths: &["/rest/api/1.0/projects", "/rest/api/latest/projects", "/plugins/servlet/oauth/users"],
            body_markers: &["bitbucket", "Bitbucket"],
            header_markers: &[],
        },
        PlatformDef {
            id: "gitea", label: "Gitea Actions",
            paths: &["/api/v1/version", "/api/v1/repos/search", "/api/v1/actions/runners", "/api/v1/admin/actions/runners"],
            body_markers: &["gitea", "Gitea", "forgejo"],
            header_markers: &["x-gitea"],
        },
        PlatformDef {
            id: "concourse", label: "Concourse CI",
            paths: &["/api/v1/info", "/api/v1/teams/main/pipelines", "/api/v1/containers", "/sky/issuer"],
            body_markers: &["concourse", "Concourse", "fly.io"],
            header_markers: &["x-concourse"],
        },
        PlatformDef {
            id: "codefresh", label: "Codefresh",
            paths: &["/api/accounts", "/api/pipelines", "/api/builds", "/api/clusters"],
            body_markers: &["codefresh", "Codefresh"],
            header_markers: &[],
        },
        PlatformDef {
            id: "cloud_build", label: "Google Cloud Build",
            paths: &["/v1/projects", "/cloudbuild/v1/projects", "/api/cloudbuild"],
            body_markers: &["cloudbuild", "Cloud Build", "google.devtools.cloudbuild"],
            header_markers: &["x-cloud-trace-context"],
        },
        PlatformDef {
            id: "sonarqube", label: "SonarQube (CI gate)",
            paths: &["/api/system/status", "/api/authentication/validate", "/api/qualitygates/list", "/api/projects/search"],
            body_markers: &["sonarqube", "SonarQube"],
            header_markers: &[],
        },
    ]
}

const CONFIG_PATHS: &[&str] = &[
    "/Jenkinsfile",
    "/.gitlab-ci.yml",
    "/azure-pipelines.yml",
    "/bitbucket-pipelines.yml",
    "/.circleci/config.yml",
    "/.github/workflows/ci.yml",
    "/.github/workflows/main.yml",
    "/.github/workflows/build.yml",
    "/.github/workflows/deploy.yml",
    "/.github/workflows/release.yml",
    "/.woodpecker.yml",
    "/.drone.yml",
    "/.buildkite/pipeline.yml",
    "/spinnaker.yml",
    "/.travis.yml",
    "/.teamcity/settings.kts",
    "/.harness/pipeline.yaml",
    "/.tekton/pipeline.yaml",
    "/.tekton/pipelinerun.yaml",
    "/.argo/workflows.yaml",
    "/.argo/workflow-template.yaml",
    "/.github/dependabot.yml",
    "/.github/CODEOWNERS",
    "/.gitlab/ci/deploy.yml",
    "/.gitlab/ci/build.yml",
    "/renovate.json",
    "/.github/renovate.json",
    "/.pre-commit-config.yaml",
    "/.snyk",
    "/.github/actions/deploy/action.yml",
    "/.github/workflows/security.yml",
    "/.github/workflows/slsa.yml",
    "/catalog-info.yaml",
    "/.prow.yaml",
    "/cloudbuild.yaml",
    "/.github/workflows/dependency-review.yml",
    "/.github/workflows/codeql.yml",
    "/.github/workflows/container-scan.yml",
    "/.github/workflows/sign.yml",
    "/.github/workflows/oidc-aws.yml",
    "/.github/workflows/terraform.yml",
    "/.github/actions/setup/action.yml",
    "/.gitlab/ci/security.yml",
    "/.gitlab/ci/sast.yml",
    "/.gitlab/ci/secret-detection.yml",
    "/.gitea/workflows/ci.yml",
    "/.circleci/security.yml",
    "/.github/pull_request_template.md",
    "/.github/settings.yml",
    "/.github/renovate.json5",
    "/.sops.yaml",
    "/.infrastructure/terraform/main.tf",
    "/.github/workflows/release-please.yml",
];

const BUILD_LOG_PATHS: &[&str] = &[
    "/job/",
    "/view/all/",
    "/blue/rest/organizations/jenkins/pipelines/",
    "/computer/",
    "/asynchPeople/",
    "/api/json?tree=allBuilds[number,url,building,result]",
    "/-/jobs",
    "/-/pipelines",
    "/api/v4/projects?visibility=public",
    "/app/rest/builds",
    "/api/builds",
];

const ARTIFACT_PATHS: &[&str] = &[
    "/artifacts/",
    "/repository/maven-public/",
    "/artifactory/api/storage/",
    "/service/rest/v1/repositories",
    "/v2/_catalog",
    "/api/v4/projects/1/packages",
    "/api/v4/projects/1/registry/repositories",
    "/api/v4/groups/1/-/packages",
    "/nexus/service/rest/v1/repositories",
    "/ui/repos/tree/General",
];

const RUNNER_TOKEN_MARKERS: &[&str] = &[
    "registration-token",
    "runner-registration-token",
    "RUNNER_TOKEN",
    "runner_token",
    "glrt-",
    "ghp_",
    "gho_",
    "glpat-",
    "xoxb-",
    "AKIA",
];

const SECRET_KEYWORDS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "access_key",
    "aws_secret",
    "github_token",
    "gh_token",
    "slack_token",
    "npm_token",
    "docker_password",
];

// ── Settings ──────────────────────────────────────────────────────────────────

struct Settings {
    intensity: Intensity,
    timeout_ms: u64,
    concurrency: usize,
    api_paths: Vec<String>,
    config_paths: Vec<String>,
    platform_filter: BTreeSet<String>,
    probe_fingerprint: bool,
    probe_api: bool,
    probe_config: bool,
    probe_repo: bool,
    probe_workflow_analysis: bool,
    probe_runner_tokens: bool,
    probe_jenkins_console: bool,
    probe_build_logs: bool,
    probe_artifact_exposure: bool,
    probe_repo_governance: bool,
    probe_secret_scan: bool,
    attack_synth: bool,
    posture_scoring: bool,
    repo_url: Option<String>,
    repo_ref: Option<String>,
    github_token: Option<String>,
    gitlab_token: Option<String>,
    azure_devops_pat: Option<String>,
    bearer_token: Option<String>,
    auth_header: Option<String>,
    min_sev_rank: u8,
    max_requests: usize,
    max_repo_files: u32,
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

fn parse_settings(ctx: &EngineRunContext) -> Settings {
    let cfg = ArsenalConfig::from_ctx(ctx);
    let intensity = cfg.intensity();

    let mut api_paths: Vec<String> = cfg.string_list("api_paths");
    if api_paths.is_empty() {
        for p in platforms() {
            api_paths.extend(p.paths.iter().map(|s| s.to_string()));
        }
    }
    let depth = match intensity {
        Intensity::Light => 24,
        Intensity::Normal => 48,
        Intensity::Aggressive => 96,
    };
    api_paths.truncate(depth);

    let mut config_paths = cfg.string_list_or("config_paths", CONFIG_PATHS);
    if intensity == Intensity::Light {
        config_paths.truncate(10);
    }

    let platform_filter: BTreeSet<String> = cfg
        .string_list("platform_filter")
        .into_iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();

    let github_token = cfg
        .string("github_token")
        .or_else(|| ctx.github_token.clone())
        .filter(|t| !t.trim().is_empty());

    Settings {
        intensity,
        timeout_ms: cfg.timeout_ms(10_000),
        concurrency: cfg.concurrency().clamp(1, 64),
        api_paths,
        config_paths,
        platform_filter,
        probe_fingerprint: cfg.bool_or("probe_fingerprint", true),
        probe_api: cfg.bool_or("probe_api", true),
        probe_config: cfg.bool_or("probe_config", true),
        probe_repo: cfg.bool_or("probe_repo", true),
        probe_workflow_analysis: cfg.bool_or("probe_workflow_analysis", true),
        probe_runner_tokens: cfg.bool_or("probe_runner_tokens", true),
        probe_jenkins_console: cfg.bool_or("probe_jenkins_console", intensity != Intensity::Light),
        probe_build_logs: cfg.bool_or("probe_build_logs", intensity != Intensity::Light),
        probe_artifact_exposure: cfg.bool_or("probe_artifact_exposure", true),
        probe_repo_governance: cfg.bool_or("probe_repo_governance", true),
        probe_secret_scan: cfg.bool_or("probe_secret_scan", true),
        attack_synth: cfg.bool_or("attack_path_synthesis", true),
        posture_scoring: cfg.bool_or("posture_scoring", true),
        repo_url: cfg.string("repo_url"),
        repo_ref: cfg.string("repo_ref"),
        github_token,
        gitlab_token: cfg.string("gitlab_token"),
        azure_devops_pat: cfg.string("azure_devops_pat"),
        bearer_token: cfg.string("bearer_token"),
        auth_header: cfg.string("auth_header"),
        min_sev_rank: sev_rank(&cfg.string_or("min_severity", "info")),
        max_requests: cfg.usize_or("max_requests", 600).clamp(10, 3000),
        max_repo_files: match intensity {
            Intensity::Light => cfg.usize_or("max_repo_files", 12).clamp(1, 100) as u32,
            Intensity::Normal => cfg.usize_or("max_repo_files", 32).clamp(1, 100) as u32,
            Intensity::Aggressive => cfg.usize_or("max_repo_files", 64).clamp(1, 150) as u32,
        },
        dry_run: cfg.bool_or("dry_run", false),
        compliance_frameworks: cfg.string_list_or(
            "compliance_frameworks",
            &[
                "NIST-SA-12",
                "SOC2-CC8.1",
                "PCI-DSS-6.3.2",
                "MITRE-T1195.002",
            ],
        ),
    }
}

fn platform_allowed(settings: &Settings, platform_id: &str) -> bool {
    settings.platform_filter.is_empty()
        || settings
            .platform_filter
            .contains(&platform_id.to_ascii_lowercase())
}

fn auth_headers(settings: &Settings) -> Vec<(String, String)> {
    let mut hs = Vec::new();
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
    if let Some(gt) = &settings.gitlab_token {
        if !gt.trim().is_empty() {
            hs.push(("PRIVATE-TOKEN".to_string(), gt.trim().to_string()));
        }
    }
    hs
}

async fn build_client(timeout_ms: u64) -> Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-CICD-Security/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn headers_blob(probe: &HttpProbe) -> String {
    probe
        .headers
        .iter()
        .map(|(k, v)| format!("{}:{}", k.to_ascii_lowercase(), v.to_ascii_lowercase()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn detect_platform(probe: &HttpProbe) -> Option<(&'static str, &'static str)> {
    let hb = headers_blob(probe);
    let body_l = probe.body.to_ascii_lowercase();
    for p in platforms() {
        let header_hit = p
            .header_markers
            .iter()
            .any(|t| hb.contains(&t.to_ascii_lowercase()));
        let body_hit = p
            .body_markers
            .iter()
            .any(|t| body_l.contains(&t.to_ascii_lowercase()));
        if header_hit || body_hit {
            return Some((p.id, p.label));
        }
    }
    None
}

fn identify_tool_from_path(path: &str) -> (&'static str, &'static str) {
    let pl = path.to_ascii_lowercase();
    for p in platforms() {
        if p.paths
            .iter()
            .any(|ep| pl.contains(&ep.to_ascii_lowercase().trim_start_matches('/')))
        {
            return (p.id, p.label);
        }
    }
    if pl.contains("jenkins") || pl.contains("script") {
        return ("jenkins", "Jenkins");
    }
    if pl.contains("gitlab") || pl.contains("v4/runners") {
        return ("gitlab", "GitLab CI");
    }
    if pl.contains("tekton") {
        return ("tekton", "Tekton");
    }
    if pl.contains("_apis") {
        return ("azure_devops", "Azure DevOps");
    }
    ("cicd", "CI/CD")
}

// ── Posture ───────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Posture {
    platforms: BTreeSet<String>,
    api_exposed: u32,
    config_exposed: u32,
    workflow_violations: u32,
    secrets_in_response: bool,
    jenkins_console: bool,
    runner_tokens: bool,
    unauthenticated_critical: bool,
    build_logs_exposed: u32,
    artifact_exposed: u32,
    slsa_gaps: u32,
    secrets_in_configs: u32,
    docker_privilege: bool,
    oidc_fork_risk: bool,
    federation_exposed: bool,
    policy_hits: BTreeMap<String, u32>,
}

impl Posture {
    fn exposure_score(&self) -> f64 {
        let mut score = 0.0_f64;
        if self.unauthenticated_critical {
            score += 0.35;
        }
        if self.secrets_in_response {
            score += 0.30;
        }
        if self.secrets_in_configs > 0 {
            score += 0.12 * (self.secrets_in_configs.min(3) as f64);
        }
        if self.jenkins_console {
            score += 0.25;
        }
        if self.workflow_violations > 0 {
            score += 0.15 * (self.workflow_violations.min(4) as f64);
        }
        if self.config_exposed > 0 {
            score += 0.10 * (self.config_exposed.min(3) as f64);
        }
        if self.api_exposed > 0 {
            score += 0.05 * (self.api_exposed.min(5) as f64);
        }
        if self.runner_tokens {
            score += 0.20;
        }
        if self.build_logs_exposed > 0 {
            score += 0.08 * (self.build_logs_exposed.min(3) as f64);
        }
        if self.artifact_exposed > 0 {
            score += 0.10 * (self.artifact_exposed.min(2) as f64);
        }
        if self.docker_privilege {
            score += 0.22;
        }
        if self.oidc_fork_risk {
            score += 0.18;
        }
        if self.federation_exposed {
            score += 0.12;
        }
        score.clamp(0.0, 1.0)
    }
}

fn record_policy_hits(posture: &mut Posture, findings: &[Value]) {
    for f in findings {
        let policy = f
            .get("evidence")
            .and_then(|e| e.get("policy"))
            .and_then(Value::as_str)
            .or_else(|| {
                f.get("evidence")
                    .and_then(|e| e.as_object())
                    .and_then(|o| o.get("policy"))
                    .and_then(Value::as_str)
            });
        if let Some(p) = policy {
            *posture.policy_hits.entry(p.to_string()).or_insert(0) += 1;
        }
    }
}

fn scan_artifact_secrets(
    posture: &mut Posture,
    findings: &mut Vec<Value>,
    settings: &Settings,
    host: &str,
    source: &str,
    path: &str,
    content: &str,
) {
    if !settings.probe_secret_scan {
        return;
    }
    let secrets = detect_secrets(content);
    if secrets.is_empty() {
        return;
    }
    posture.secrets_in_response = true;
    posture.secrets_in_configs += 1;
    push_if_severe(
        findings,
        settings,
        finding_rich(
            ENGINE_ID,
            &format!("Embedded secrets in CI artifact: {path}"),
            "critical",
            "T1552.004",
            &format!(
                "Live content from {source} ({path}) contains high-confidence secret patterns: {}. \
                 Rotate immediately and purge from Git history.",
                secrets.join(", ")
            ),
            host,
            0.97,
            Evidence::new()
                .with("source", source)
                .with("path", path)
                .with("secret_types", json!(secrets))
                .with("policy", "WZ-SEC-001")
                .with(
                    "remediation",
                    "Revoke credentials, rotate keys, enable secret scanning, rewrite history with BFG/git-filter-repo",
                ),
        ),
    );
}

fn compliance_posture(policy_hits: &BTreeMap<String, u32>, frameworks: &[String]) -> Value {
    let mut map = serde_json::Map::new();
    for fw in frameworks {
        let score = if policy_hits.is_empty() {
            100
        } else {
            let hits: u32 = policy_hits.values().sum();
            (100_i32.saturating_sub((hits * 8) as i32)).clamp(0, 100) as u32
        };
        map.insert(
            fw.clone(),
            json!({ "score": score, "policy_violations": policy_hits.len() }),
        );
    }
    Value::Object(map)
}

fn remediation_playbook(posture: &Posture, policy_hits: &BTreeMap<String, u32>) -> Value {
    let mut actions: Vec<Value> = Vec::new();
    if posture.jenkins_console {
        actions.push(json!({"priority": "P0", "action": "Disable or restrict Jenkins script console; require auth + CSRF"}));
    }
    if posture.api_exposed > 0 {
        actions.push(json!({"priority": "P0", "action": "Require authentication on all CI/CD API endpoints; restrict to VPN/zero-trust"}));
    }
    if posture.secrets_in_configs > 0 {
        actions.push(json!({"priority": "P0", "action": "Rotate exposed secrets; enable GitHub/GitLab secret scanning push protection"}));
    }
    if posture.runner_tokens {
        actions.push(json!({"priority": "P0", "action": "Revoke runner registration tokens; re-enroll runners with one-time tokens"}));
    }
    if posture.workflow_violations > 0 {
        actions.push(json!({"priority": "P1", "action": "Fix pwn-request/injection workflows; pin actions to SHA; scope GITHUB_TOKEN to read"}));
    }
    if posture.slsa_gaps > 0 {
        actions.push(json!({"priority": "P1", "action": "Add cosign/SLSA provenance attestation to release pipelines (Build L2+)"}));
    }
    if posture.artifact_exposed > 0 {
        actions.push(json!({"priority": "P1", "action": "Lock artifact registries; require signed publishes and immutability"}));
    }
    if policy_hits.contains_key("WZ-GOV-003") || policy_hits.contains_key("WZ-GL-GOV-001") {
        actions.push(json!({"priority": "P1", "action": "Enable branch protection with required reviews and signed commits"}));
    }
    json!({ "actions": actions, "total": actions.len() })
}

fn append_workflow_findings(
    posture: &mut Posture,
    findings: &mut Vec<Value>,
    settings: &Settings,
    wf: Vec<Value>,
) {
    posture.workflow_violations += wf.len() as u32;
    for f in &wf {
        if f.get("title").and_then(Value::as_str).is_some_and(|t| {
            t.to_ascii_lowercase().contains("slsa")
                || t.contains("cosign")
                || t.contains("provenance")
        }) {
            posture.slsa_gaps += 1;
        }
    }
    record_policy_hits(posture, &wf);
    for f in wf {
        push_if_severe(findings, settings, f);
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

// ── GitHub Actions static analysis (Wiz-class policy checks) ──────────────────

fn analyze_github_workflow(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();

    let has_prt = lc.contains("pull_request_target");
    let checks_pr_head = content.contains("github.event.pull_request.head.ref")
        || content.contains("github.head_ref")
        || content.contains("pull_request.head.sha");
    if has_prt && checks_pr_head {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("GitHub Actions pwn-request risk: {filename}"),
            "critical",
            MITRE,
            "Workflow uses pull_request_target and checks out or executes untrusted PR head code while \
             repository secrets are available — the canonical 'pwn request' enabling secret exfiltration \
             and arbitrary code execution on the runner.",
            host,
            0.94,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-GHA-001")
                .check("pull_request_target", true, "head_ref checkout"),
        ));
    }

    const INJECT_PATTERNS: &[&str] = &[
        "${{ github.event.issue.title",
        "${{ github.event.pull_request.title",
        "${{ github.event.pull_request.body",
        "${{ github.event.comment.body",
        "${{ github.event.review.body",
    ];
    for pat in INJECT_PATTERNS {
        if content.contains(pat) && content.contains("run:") {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("GitHub Actions script injection surface: {filename}"),
                "high",
                "T1059",
                &format!(
                    "Workflow {filename} interpolates attacker-controllable GitHub context ({pat}) \
                     into a run step — enabling command injection on the runner.",
                ),
                host,
                0.88,
                Evidence::new().with("file", filename).with("pattern", pat),
            ));
            break;
        }
    }

    if lc.contains("permissions:") && (lc.contains("write-all") || lc.contains("write_all")) {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("GitHub Actions write-all permissions: {filename}"),
            "medium",
            "T1098",
            &format!(
                "Workflow {filename} grants permissions: write-all — excessive GITHUB_TOKEN scope."
            ),
            host,
            0.85,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-GHA-005"),
        ));
    }

    if content.contains("uses:") {
        for line in content.lines() {
            let l = line.trim();
            if !l.starts_with("- uses:") && !l.starts_with("uses:") {
                continue;
            }
            if l.contains('@') {
                let after = l.split('@').nth(1).unwrap_or("").trim();
                if after == "main" || after == "master" || after.starts_with("v") && after.len() < 8
                {
                    let sev = if after == "main" || after == "master" {
                        "high"
                    } else {
                        "medium"
                    };
                    out.push(finding_rich(
                        ENGINE_ID,
                        &format!("Unpinned third-party GitHub Action: {filename}"),
                        sev,
                        "T1195.001",
                        &format!(
                            "Action reference '{l}' is pinned to a mutable ref ({after}) — \
                                 supply-chain takeover via tag/branch movement."
                        ),
                        host,
                        0.82,
                        Evidence::new().with("file", filename).with("uses_line", l),
                    ));
                }
            }
        }
    }

    if lc.contains("runs-on:")
        && lc.contains("self-hosted")
        && (has_prt || lc.contains("pull_request:"))
    {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Self-hosted runner exposed to fork PRs: {filename}"),
            "high",
            MITRE,
            &format!(
                "Workflow {filename} runs pull_request/pull_request_target jobs on self-hosted \
                     runners — untrusted fork code executes on your infrastructure."
            ),
            host,
            0.86,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-GHA-007"),
        ));
    }

    if (lc.contains("curl ") || lc.contains("wget "))
        && (lc.contains("| sh") || lc.contains("| bash"))
    {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Remote script piped to shell in workflow: {filename}"),
            "high",
            MITRE,
            &format!(
                "Workflow {filename} pipes remote curl/wget output into a shell — executing \
                     unverified code in CI."
            ),
            host,
            0.84,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-GHA-008"),
        ));
    }

    if lc.contains("id-token: write") || lc.contains("id-token:write") {
        if lc.contains("pull_request") || has_prt {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("GitHub OIDC write token on PR workflow: {filename}"),
                "high",
                "T1550.001",
                &format!(
                    "Workflow {filename} requests id-token: write on pull_request paths — verify OIDC \
                     trust policies cannot be abused by fork PRs (Wiz-class cloud identity pivot)."
                ),
                host,
                0.85,
                Evidence::new().with("file", filename).with("policy", "WZ-GHA-009"),
            ));
        }
    }

    if lc.contains("secrets: inherit") || lc.contains("secrets:inherit") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("GitHub reusable workflow inherits all secrets: {filename}"),
            "medium",
            "T1552.001",
            &format!(
                "Workflow {filename} uses secrets: inherit — downstream reusable workflows receive the \
                 full secret namespace without explicit scoping."
            ),
            host,
            0.80,
            Evidence::new().with("file", filename).with("policy", "WZ-GHA-010"),
        ));
    }

    if lc.contains("workflow_call") {
        for line in content.lines() {
            let l = line.trim();
            if l.starts_with("uses:") && l.contains('@') {
                let after = l.split('@').nth(1).unwrap_or("").trim();
                if after == "main" || after == "master" {
                    out.push(finding_rich(
                        ENGINE_ID,
                        &format!("Unpinned reusable workflow reference: {filename}"),
                        "high",
                        "T1195.001",
                        &format!("Reusable workflow call '{l}' pinned to mutable ref — supply-chain takeover."),
                        host,
                        0.83,
                        Evidence::new().with("file", filename).with("uses_line", l),
                    ));
                }
            }
        }
    }

    // workflow_dispatch — attacker-controlled inputs interpolated into run steps
    if lc.contains("workflow_dispatch:") && lc.contains("inputs:") {
        for pat in ["github.event.inputs.", "inputs."] {
            if content.contains(pat) && content.contains("run:") {
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("GitHub workflow_dispatch input injection: {filename}"),
                    "high",
                    "T1059",
                    &format!(
                        "Workflow {filename} accepts workflow_dispatch inputs and interpolates them into \
                         run steps — manual trigger abuse / operator social-engineering → runner RCE."
                    ),
                    host,
                    0.86,
                    Evidence::new().with("file", filename).with("policy", "WZ-GHA-011"),
                ));
                break;
            }
        }
    }

    // Dependency confusion / untrusted package registries in CI
    const DEP_CONFUSION: &[(&str, &str)] = &[
        ("npm install --registry", "WZ-GHA-012"),
        ("npm ci --registry", "WZ-GHA-012"),
        ("pip install -i ", "WZ-GHA-013"),
        ("pip install --index-url", "WZ-GHA-013"),
        ("yarn add --registry", "WZ-GHA-012"),
        ("pnpm install --registry", "WZ-GHA-012"),
        ("gem sources -a", "WZ-GHA-014"),
        ("go install ", "WZ-GHA-015"),
    ];
    for (pat, policy) in DEP_CONFUSION {
        if lc.contains(&pat.to_ascii_lowercase()) {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("CI dependency source override: {filename}"),
                "high",
                "T1195.001",
                &format!(
                    "Workflow {filename} installs dependencies from a non-default registry/source ({pat}) — \
                     dependency confusion / typosquatting pivot into production artifacts."
                ),
                host,
                0.87,
                Evidence::new().with("file", filename).with("pattern", pat).with("policy", policy),
            ));
        }
    }

    // persist-credentials on PR paths leaks GITHUB_TOKEN to subsequent steps / cache
    if lc.contains("persist-credentials: true") && (lc.contains("pull_request") || has_prt) {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("GitHub checkout persist-credentials on PR path: {filename}"),
            "medium",
            "T1552.001",
            &format!(
                "Workflow {filename} enables persist-credentials during pull_request — token material may \
                 leak via cache artifacts or later steps on fork-triggered runs."
            ),
            host,
            0.79,
            Evidence::new().with("file", filename).with("policy", "WZ-GHA-016"),
        ));
    }

    // SLSA / provenance gap — release/deploy workflows without signing attestation
    let is_release = lc.contains("release") || lc.contains("deploy") || lc.contains("publish");
    let has_provenance = lc.contains("slsa")
        || lc.contains("cosign")
        || lc.contains("provenance")
        || lc.contains("attestation")
        || lc.contains("sigstore")
        || lc.contains("in-toto");
    if is_release && !has_provenance && lc.contains("runs-on:") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("SLSA provenance gap in release workflow: {filename}"),
            "medium",
            "T1195.002",
            &format!(
                "Release/deploy workflow {filename} has no cosign/SLSA/provenance/attestation step — \
                 artifacts are not cryptographically attributable (SLSA Build L2+ gap)."
            ),
            host,
            0.76,
            Evidence::new().with("file", filename).with("policy", "WZ-SLSA-001"),
        ));
    }

    // Cache poisoning surface — shared cache keys on untrusted PR paths
    if lc.contains("actions/cache") && (lc.contains("pull_request") || has_prt) {
        if !lc.contains("restore-keys") || lc.contains("github.sha") {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("GitHub Actions cache poisoning surface: {filename}"),
                "medium",
                MITRE,
                &format!(
                    "Workflow {filename} uses actions/cache on pull_request without strict restore-key \
                     isolation — fork PRs may poison shared build caches consumed by default-branch jobs."
                ),
                host,
                0.78,
                Evidence::new().with("file", filename).with("policy", "WZ-GHA-017"),
            ));
        }
    }

    // Long-lived AWS access keys in CI instead of OIDC role assumption
    if (lc.contains("aws-access-key-id")
        || lc.contains("aws_secret_access_key")
        || lc.contains("access_key_id"))
        && !lc.contains("role-to-assume")
        && !lc.contains("id-token: write")
        && !lc.contains("id-token:write")
    {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Long-lived AWS keys in workflow (no OIDC): {filename}"),
            "critical",
            "T1552.001",
            &format!(
                "Workflow {filename} configures static AWS access keys without role-to-assume/OIDC — \
                 prefer aws-actions/configure-aws-credentials with id-token + IAM role (WZ cloud identity best practice)."
            ),
            host,
            0.92,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-GHA-018")
                .with("remediation", "Replace static keys with GitHub OIDC → IAM role trust"),
        ));
    }

    out
}

fn analyze_gitlab_ci(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();
    if lc.contains("when: manual") && lc.contains("allow_failure: false") {
        // informational only — skip
    }
    if content.contains("CI_JOB_TOKEN") && lc.contains("curl ") && lc.contains("api/v4") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("GitLab CI job token over-exposure risk: {filename}"),
            "medium",
            "T1552.001",
            &format!("Pipeline {filename} uses CI_JOB_TOKEN in outbound API calls — verify scope is minimal."),
            host,
            0.72,
            Evidence::new().with("file", filename),
        ));
    }
    if lc.contains("script:") && (lc.contains("eval ") || lc.contains("$(")) {
        for line in content.lines() {
            if line.contains("${") && line.contains("CI_") {
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("GitLab CI dynamic script interpolation: {filename}"),
                    "medium",
                    "T1059",
                    "Pipeline script interpolates CI variables dynamically — review for injection via \
                     protected variable override.",
                    host,
                    0.70,
                    Evidence::new().with("file", filename).with("line", line.trim()),
                ));
                break;
            }
        }
    }

    if lc.contains("include:") && (lc.contains("http://") || lc.contains("https://")) {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("GitLab CI remote include from URL: {filename}"),
            "high",
            "T1195.001",
            &format!(
                "Pipeline {filename} includes CI configuration from a remote HTTP URL — supply-chain \
                 takeover if the remote template is compromised or MITM'd."
            ),
            host,
            0.88,
            Evidence::new().with("file", filename).with("policy", "WZ-GL-003"),
        ));
    }

    if lc.contains("rules:") && lc.contains("merge_request_event") {
        if !lc.contains("protected")
            && !lc.contains("if: $CI_MERGE_REQUEST_SOURCE_BRANCH_PROTECTED")
        {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("GitLab CI runs on unprotected fork MRs: {filename}"),
                "high",
                MITRE,
                &format!(
                    "Pipeline {filename} triggers on merge_request_event without branch-protection guard — \
                     fork MRs execute with CI_JOB_TOKEN scope."
                ),
                host,
                0.84,
                Evidence::new().with("file", filename).with("policy", "WZ-GL-004"),
            ));
        }
    }

    if lc.contains("trigger:") && lc.contains("include:") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("GitLab downstream pipeline trigger: {filename}"),
            "medium",
            MITRE,
            &format!(
                "Pipeline {filename} uses trigger/include to launch downstream pipelines — verify child \
                 pipelines cannot be abused via fork MR token scope."
            ),
            host,
            0.74,
            Evidence::new().with("file", filename).with("policy", "WZ-GL-005"),
        ));
    }

    out
}

fn analyze_azure_pipelines(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();

    if lc.contains("pr:") && lc.contains("trigger:") && !lc.contains("pr: none") {
        if lc.contains("script:") && (lc.contains("${{") || lc.contains("$(")) {
            for pat in [
                "github.event.pull_request.title",
                "Build.SourceBranch",
                "variables['",
            ] {
                if content.contains(pat) {
                    out.push(finding_rich(
                        ENGINE_ID,
                        &format!("Azure Pipelines PR injection surface: {filename}"),
                        "high",
                        "T1059",
                        &format!(
                            "Pipeline {filename} runs scripts on pull_request triggers with attacker-controllable \
                             context ({pat}) — command injection on hosted or self-hosted agents."
                        ),
                        host,
                        0.86,
                        Evidence::new().with("file", filename).with("pattern", pat).with("policy", "WZ-ADO-001"),
                    ));
                    break;
                }
            }
        }
    }

    if lc.contains("pool:") && lc.contains("name:") && lc.contains("demands:") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Azure Pipelines self-hosted pool binding: {filename}"),
            "medium",
            MITRE,
            &format!(
                "Pipeline {filename} targets a named self-hosted agent pool — verify fork PR isolation \
                 and secret scoping (OIDC / variable groups)."
            ),
            host,
            0.78,
            Evidence::new().with("file", filename).with("policy", "WZ-ADO-003"),
        ));
    }

    if content.contains("secureFile") || content.contains("AzureKeyVault@") {
        if lc.contains("pr:") && !lc.contains("pr: none") {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("Azure Pipelines secrets on PR path: {filename}"),
                "high",
                "T1552.001",
                &format!(
                    "Pipeline {filename} references Key Vault / secure files while PR triggers are enabled — \
                     fork PRs may reach privileged material."
                ),
                host,
                0.84,
                Evidence::new().with("file", filename).with("policy", "WZ-ADO-004"),
            ));
        }
    }

    if (lc.contains("curl ") || lc.contains("wget "))
        && (lc.contains("| sh") || lc.contains("| bash"))
    {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Remote script piped to shell in Azure Pipeline: {filename}"),
            "high",
            MITRE,
            &format!("Pipeline {filename} pipes remote curl/wget into a shell during build."),
            host,
            0.83,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-ADO-008"),
        ));
    }

    out
}

fn analyze_jenkinsfile(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();

    if lc.contains("disablesecurity()")
        || lc.contains("hudson.model.hudson") && lc.contains("script")
    {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Jenkins security bypass in pipeline: {filename}"),
            "critical",
            MITRE,
            &format!(
                "Jenkinsfile {filename} references disableSecurity() or script console APIs — \
                 build controller RCE / sandbox escape risk."
            ),
            host,
            0.95,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-JNK-001"),
        ));
    }

    if (lc.contains("curl ") || lc.contains("wget "))
        && (lc.contains("| sh") || lc.contains("| bash"))
    {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Remote script piped to shell in Jenkinsfile: {filename}"),
            "high",
            MITRE,
            &format!("Jenkinsfile {filename} executes unverified remote install scripts."),
            host,
            0.84,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-JNK-008"),
        ));
    }

    if lc.contains("withcredentials") && (lc.contains("echo") || lc.contains("print")) {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Jenkins credential echo risk: {filename}"),
            "high",
            "T1552.001",
            &format!(
                "Jenkinsfile {filename} uses withCredentials near echo/print — secrets may leak into build logs."
            ),
            host,
            0.80,
            Evidence::new().with("file", filename).with("policy", "WZ-JNK-004"),
        ));
    }

    if lc.contains("agent any") || lc.contains("agent { label") {
        if lc.contains("pullrequest") || lc.contains("change-request") || lc.contains("fork") {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("Jenkins fork/PR jobs on shared agents: {filename}"),
                "high",
                MITRE,
                &format!(
                    "Jenkinsfile {filename} runs untrusted PR/fork code on shared agents — \
                     lateral movement to production credentials."
                ),
                host,
                0.82,
                Evidence::new()
                    .with("file", filename)
                    .with("policy", "WZ-JNK-007"),
            ));
        }
    }

    out
}

fn analyze_circleci(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();

    if content.contains("orb:") {
        for line in content.lines() {
            let l = line.trim();
            if l.starts_with("- ") && l.contains('/') && !l.contains('@') {
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("Unpinned CircleCI orb: {filename}"),
                    "high",
                    "T1195.001",
                    &format!("CircleCI config {filename} references unpinned orb '{l}' — orb supply-chain takeover."),
                    host,
                    0.83,
                    Evidence::new().with("file", filename).with("orb_line", l).with("policy", "WZ-CCI-001"),
                ));
            }
        }
    }

    if lc.contains("setup_remote_docker") && lc.contains("docker_layer_caching: true") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("CircleCI shared Docker layer cache: {filename}"),
            "medium",
            MITRE,
            &format!(
                "Config {filename} enables Docker layer caching on shared infrastructure — cache poisoning \
                 across projects on the same executor class."
            ),
            host,
            0.75,
            Evidence::new().with("file", filename).with("policy", "WZ-CCI-002"),
        ));
    }

    out
}

fn analyze_workflow_content(content: &str, url_or_path: &str, host: &str) -> Vec<Value> {
    let fname = url_or_path.rsplit('/').next().unwrap_or("config");
    let body_l = content.to_ascii_lowercase();
    let mut out = Vec::new();

    if url_or_path.contains(".github/workflows") || body_l.contains("runs-on:") {
        out.extend(analyze_github_workflow(content, fname, host));
    } else if url_or_path.contains("gitlab-ci")
        || body_l.contains("stages:") && body_l.contains("script:")
    {
        out.extend(analyze_gitlab_ci(content, fname, host));
    } else if url_or_path.contains("azure-pipelines")
        || body_l.contains("trigger:") && body_l.contains("pool:")
    {
        out.extend(analyze_azure_pipelines(content, fname, host));
    } else if url_or_path.contains("Jenkinsfile") || body_l.contains("pipeline {") {
        out.extend(analyze_jenkinsfile(content, fname, host));
    } else if url_or_path.contains(".circleci")
        || body_l.contains("orbs:")
        || body_l.contains("version: 2")
    {
        out.extend(analyze_circleci(content, fname, host));
    } else if url_or_path.contains(".argo/")
        || body_l.contains("argoproj.io")
        || body_l.contains("kind: application")
    {
        out.extend(analyze_argocd_manifest(content, fname, host));
    } else if url_or_path.contains(".tekton/")
        || body_l.contains("tekton.dev")
        || body_l.contains("kind: pipelinerun")
    {
        out.extend(analyze_tekton_manifest(content, fname, host));
    } else if url_or_path.contains("bitbucket-pipelines")
        || body_l.contains("pipelines:") && body_l.contains("step:")
    {
        out.extend(analyze_bitbucket_pipelines(content, fname, host));
    } else if url_or_path.contains(".github/actions/")
        && (fname.ends_with("action.yml") || fname.ends_with("action.yaml"))
    {
        out.extend(analyze_github_composite_action(content, fname, host));
    } else if url_or_path.contains("dependabot") || fname == "dependabot.yml" {
        out.extend(analyze_dependabot_config(content, fname, host));
    } else if url_or_path.contains("renovate") || fname.contains("renovate") {
        out.extend(analyze_renovate_config(content, fname, host));
    } else if (body_l.contains("pipeline:") && body_l.contains("harness.io"))
        || url_or_path.contains(".harness/")
    {
        out.extend(analyze_harness_pipeline(content, fname, host));
    } else if body_l.contains("spinnaker") || url_or_path.contains("spinnaker") {
        out.extend(analyze_spinnaker_config(content, fname, host));
    } else if fname == "Makefile" || fname == "makefile" || body_l.contains(".phony:") {
        out.extend(analyze_makefile_ci(content, fname, host));
    }

    out
}

fn analyze_github_composite_action(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();
    if content.contains("${{") && content.contains("inputs.") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Composite action input injection surface: {filename}"),
            "high",
            "T1059",
            &format!("Composite action {filename} interpolates inputs into run steps — callers can inject shell metacharacters."),
            host,
            0.84,
            Evidence::new().with("file", filename).with("policy", "WZ-GHA-COMP-001"),
        ));
    }
    if lc.contains("runs:") && lc.contains("using: composite") && !lc.contains("shell: bash") {
        // informational - composite defaults to bash
    }
    out
}

fn analyze_dependabot_config(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();
    if !lc.contains("groups:") && lc.contains("package-ecosystem:") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Dependabot without grouped updates: {filename}"),
            "low",
            MITRE,
            &format!("Dependabot config {filename} lacks update groups — noisy PR volume reduces review quality (supply-chain fatigue)."),
            host,
            0.65,
            Evidence::new().with("file", filename).with("policy", "WZ-DEP-001"),
        ));
    }
    if lc.contains("insecure-external-connections: true") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Dependabot allows insecure external connections: {filename}"),
            "medium",
            MITRE,
            &format!("Dependabot {filename} sets insecure-external-connections — MITM on dependency metadata fetches."),
            host,
            0.78,
            Evidence::new().with("file", filename).with("policy", "WZ-DEP-002"),
        ));
    }
    out
}

fn analyze_renovate_config(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    if content.contains("\"automerge\": true") || content.contains("automerge: true") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Renovate automerge enabled: {filename}"),
            "medium",
            MITRE,
            &format!("Renovate config {filename} enables automerge — compromised dependency updates may land without human review."),
            host,
            0.77,
            Evidence::new().with("file", filename).with("policy", "WZ-REN-001"),
        ));
    }
    out
}

fn analyze_harness_pipeline(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();
    if lc.contains("connectorref") && lc.contains("account.") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Harness pipeline uses account-level connector: {filename}"),
            "medium",
            "T1552.001",
            &format!("Harness pipeline {filename} binds account-level connectors — scope credentials per pipeline/environment."),
            host,
            0.76,
            Evidence::new().with("file", filename).with("policy", "WZ-HAR-001"),
        ));
    }
    if lc.contains("privileged: true") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Harness pipeline privileged step: {filename}"),
            "critical",
            "T1610",
            &format!("Harness pipeline {filename} runs privileged containers."),
            host,
            0.93,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-HAR-002"),
        ));
    }
    out
}

fn analyze_spinnaker_config(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();
    if lc.contains("usernamepassword") || lc.contains("basicauth") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Spinnaker basic auth credentials in config: {filename}"),
            "high",
            "T1552.001",
            &format!("Spinnaker config {filename} references basic auth credential blocks — verify secrets are not inline."),
            host,
            0.82,
            Evidence::new().with("file", filename).with("policy", "WZ-SPN-001"),
        ));
    }
    if lc.contains("dockerregistry") && lc.contains("password") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Spinnaker docker registry password reference: {filename}"),
            "high",
            MITRE,
            &format!("Spinnaker {filename} embeds docker registry password material."),
            host,
            0.85,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-SPN-002"),
        ));
    }
    out
}

fn analyze_makefile_ci(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();
    if lc.contains("curl ") && lc.contains("| sh") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Makefile pipes remote script to shell: {filename}"),
            "high",
            MITRE,
            &format!("Makefile {filename} used as CI entrypoint pipes curl to shell."),
            host,
            0.83,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-MKF-001"),
        ));
    }
    out
}

fn analyze_argocd_manifest(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();

    if lc.contains("kind: application") || lc.contains("kind: appproject") {
        if lc.contains("repoURL:") || lc.contains("repourl:") {
            for line in content.lines() {
                let l = line.trim();
                if !l.to_ascii_lowercase().starts_with("repourl:") && !l.contains("repoURL:") {
                    continue;
                }
                let url_part = l
                    .split(':')
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join(":")
                    .trim()
                    .to_string();
                if url_part.starts_with("http://") {
                    out.push(finding_rich(
                        ENGINE_ID,
                        &format!("ArgoCD Application uses insecure HTTP repo URL: {filename}"),
                        "high",
                        MITRE,
                        &format!(
                            "GitOps manifest {filename} references repoURL over plain HTTP ({url_part}) — \
                             MITM can swap deployment manifests in transit."
                        ),
                        host,
                        0.89,
                        Evidence::new().with("file", filename).with("repoURL", url_part.clone()).with("policy", "WZ-ARGO-001"),
                    ));
                }
                if url_part.contains("github.com")
                    && !url_part.contains("@")
                    && lc.contains("syncpolicy:")
                {
                    out.push(finding_rich(
                        ENGINE_ID,
                        &format!("ArgoCD auto-sync from public Git without commit pin: {filename}"),
                        "medium",
                        MITRE,
                        &format!(
                            "Manifest {filename} auto-syncs from {url_part} — verify targetRevision pins \
                             immutable SHAs/tags, not floating branches."
                        ),
                        host,
                        0.80,
                        Evidence::new().with("file", filename).with("policy", "WZ-ARGO-002"),
                    ));
                }
            }
        }

        if lc.contains("automated:") && lc.contains("prune: true") {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("ArgoCD automated prune enabled: {filename}"),
                "medium",
                MITRE,
                &format!(
                    "GitOps manifest {filename} enables automated sync with prune — a malicious manifest \
                     change can delete production resources automatically."
                ),
                host,
                0.78,
                Evidence::new().with("file", filename).with("policy", "WZ-ARGO-003"),
            ));
        }

        if lc.contains("namespace: kube-system") || lc.contains("namespace: kube-public") {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("ArgoCD deploys into privileged namespace: {filename}"),
                "high",
                "T1610",
                &format!(
                    "Application {filename} targets a cluster infrastructure namespace — compromised \
                     GitOps repo yields cluster-admin adjacent blast radius."
                ),
                host,
                0.86,
                Evidence::new().with("file", filename).with("policy", "WZ-ARGO-004"),
            ));
        }
    }

    if lc.contains("kind: appproject") {
        if lc.contains("clusterresourcewhitelist") && lc.contains("*") {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("ArgoCD AppProject allows all cluster resources: {filename}"),
                "high",
                "T1098",
                &format!(
                    "AppProject {filename} whitelists all cluster-scoped resources — any Application \
                     in this project can escalate to cluster-wide objects."
                ),
                host,
                0.87,
                Evidence::new().with("file", filename).with("policy", "WZ-ARGO-005"),
            ));
        }
        if content.contains("sourceRepos:") && content.contains("- '*") {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("ArgoCD AppProject wildcard sourceRepos: {filename}"),
                "high",
                MITRE,
                &format!(
                    "AppProject {filename} permits Applications from any source repository — \
                     supply-chain manifest injection from arbitrary Git hosts."
                ),
                host,
                0.88,
                Evidence::new()
                    .with("file", filename)
                    .with("policy", "WZ-ARGO-006"),
            ));
        }
    }

    out
}

fn analyze_tekton_manifest(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();

    if lc.contains("privileged: true") || lc.contains("privileged:true") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Tekton task runs privileged container: {filename}"),
            "critical",
            "T1610",
            &format!(
                "Tekton manifest {filename} sets privileged: true — pipeline step has full node \
                 capabilities; untrusted PR/fork code equals host compromise."
            ),
            host,
            0.94,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-TKN-001"),
        ));
    }

    if lc.contains("hostpath:") || lc.contains("hostpath ") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Tekton pipeline mounts hostPath volume: {filename}"),
            "high",
            MITRE,
            &format!(
                "Tekton manifest {filename} mounts hostPath — pipeline tasks can read/write node \
                 filesystem (docker.sock / kubelet credential paths)."
            ),
            host,
            0.88,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-TKN-002"),
        ));
    }

    if lc.contains("serviceaccountname:") && lc.contains("default") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Tekton pipeline uses default ServiceAccount: {filename}"),
            "medium",
            "T1098",
            &format!(
                "Tekton manifest {filename} runs as default ServiceAccount — likely excessive RBAC \
                 for CI workloads in the namespace."
            ),
            host,
            0.74,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-TKN-003"),
        ));
    }

    if lc.contains("runasuser: 0") || lc.contains("runasnonroot: false") {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Tekton task runs as root: {filename}"),
            "medium",
            "T1610",
            &format!("Tekton manifest {filename} executes containers as root — container breakout yields node UID 0."),
            host,
            0.76,
            Evidence::new().with("file", filename).with("policy", "WZ-TKN-004"),
        ));
    }

    out
}

fn analyze_bitbucket_pipelines(content: &str, filename: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();

    if lc.contains("pull-requests:") || lc.contains("pull-requests") {
        if content.contains("BITBUCKET_PR") || content.contains("${BITBUCKET") {
            out.push(finding_rich(
                ENGINE_ID,
                &format!("Bitbucket Pipelines PR variable interpolation: {filename}"),
                "high",
                "T1059",
                &format!(
                    "Bitbucket pipeline {filename} runs pull-request pipelines with dynamic variable \
                     interpolation — fork PRs may inject shell commands."
                ),
                host,
                0.85,
                Evidence::new().with("file", filename).with("policy", "WZ-BB-001"),
            ));
        }
    }

    if (lc.contains("curl ") || lc.contains("wget "))
        && (lc.contains("| sh") || lc.contains("| bash"))
    {
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Remote script piped to shell in Bitbucket Pipeline: {filename}"),
            "high",
            MITRE,
            &format!(
                "Bitbucket pipeline {filename} pipes remote install scripts into shell during CI."
            ),
            host,
            0.83,
            Evidence::new()
                .with("file", filename)
                .with("policy", "WZ-BB-008"),
        ));
    }

    out
}

fn analyze_live_argocd_applications(body: &str, url: &str, host: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return out;
    };
    let apps: Vec<&Value> = v
        .get("items")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .or_else(|| v.get("metadata").map(|_| vec![&v]))
        .unwrap_or_default();

    for app in apps.iter().take(32) {
        let name = app
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("application");
        let repo = app
            .pointer("/spec/source/repoURL")
            .or_else(|| app.pointer("/spec/source/repoUrl"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if repo.is_empty() {
            continue;
        }
        let auto = app.pointer("/spec/syncPolicy/automated").is_some();
        let sev = if repo.starts_with("http://") {
            "critical"
        } else if auto {
            "high"
        } else {
            "medium"
        };
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Live ArgoCD Application exposed: {name}"),
            sev,
            MITRE,
            &format!(
                "Unauthenticated ArgoCD API at {url} returned Application '{name}' with repoURL={repo}{}. \
                 GitOps blast radius visible to any network observer.",
                if auto { " and automated sync enabled" } else { "" }
            ),
            host,
            0.92,
            Evidence::new()
                .with("application", name)
                .with("repoURL", repo)
                .with("url", url)
                .with("automated_sync", auto)
                .with("policy", "WZ-ARGO-LIVE-001"),
        ));
    }
    out
}

fn risk_dimensions(posture: &Posture) -> Value {
    let clamp100 = |v: f64| (v * 100.0).round() as u32;
    json!({
        "api_exposure": clamp100((posture.api_exposed as f64 * 0.18).min(1.0)),
        "pipeline_integrity": clamp100((posture.workflow_violations as f64 * 0.12 + posture.config_exposed as f64 * 0.08).min(1.0)),
        "secrets_leakage": clamp100(if posture.secrets_in_response {
            0.95
        } else if posture.secrets_in_configs > 0 {
            0.75 + (posture.secrets_in_configs.min(3) as f64 * 0.05)
        } else if posture.runner_tokens {
            0.7
        } else {
            0.0
        }),
        "runner_isolation": clamp100(if posture.jenkins_console { 1.0 } else if posture.runner_tokens { 0.85 } else { posture.workflow_violations as f64 * 0.1 }),
        "supply_chain": clamp100((posture.artifact_exposed as f64 * 0.25 + posture.slsa_gaps as f64 * 0.15 + posture.build_logs_exposed as f64 * 0.1).min(1.0)),
    })
}

async fn probe_paths_with_auth(
    client: &Client,
    base: &str,
    paths: &[&str],
    concurrency: usize,
    auth_hs: &[(String, String)],
) -> Vec<HttpProbe> {
    let urls: Vec<String> = paths.iter().map(|p| join_url(base, p)).collect();
    stream::iter(urls)
        .map(|u| {
            let c = client.clone();
            let auth_hs = auth_hs.to_vec();
            async move {
                let refs: Vec<(&str, &str)> = auth_hs
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                http_get_with_headers(&c, &u, &refs).await
            }
        })
        .buffer_unordered(concurrency.max(1))
        .filter_map(|x| async move { x })
        .collect()
        .await
}

fn build_supply_chain_graph(posture: &Posture, host: &str) -> Value {
    let mut nodes = vec![json!({"id": "target", "type": "target", "label": host})];
    let mut edges: Vec<Value> = Vec::new();

    for pid in &posture.platforms {
        let label = platforms()
            .iter()
            .find(|p| p.id == pid.as_str())
            .map(|p| p.label)
            .unwrap_or(pid.as_str());
        nodes.push(json!({"id": pid, "type": "platform", "label": label}));
        edges.push(json!({"from": "target", "to": pid, "relation": "hosts"}));
    }
    if posture.api_exposed > 0 {
        let nid = "open_api";
        nodes.push(json!({"id": nid, "type": "exposure", "label": "Unauthenticated API"}));
        edges.push(json!({"from": "target", "to": nid, "relation": "exposes"}));
    }
    if posture.config_exposed > 0 {
        let nid = "config_leak";
        nodes.push(json!({"id": nid, "type": "exposure", "label": "Pipeline Config"}));
        edges.push(json!({"from": "target", "to": nid, "relation": "leaks"}));
    }
    if posture.secrets_in_response {
        let nid = "secrets";
        nodes.push(json!({"id": nid, "type": "credential", "label": "Secrets in Response"}));
        edges.push(json!({"from": "open_api", "to": nid, "relation": "leaks"}));
    }
    if posture.jenkins_console {
        let nid = "jenkins_rce";
        nodes.push(json!({"id": nid, "type": "rce", "label": "Jenkins Script Console"}));
        edges.push(json!({"from": "jenkins", "to": nid, "relation": "enables"}));
    }
    if posture.runner_tokens {
        let nid = "rogue_runner";
        nodes.push(json!({"id": nid, "type": "persistence", "label": "Rogue Runner Registration"}));
        edges.push(json!({"from": "open_api", "to": nid, "relation": "enables"}));
    }
    if posture.workflow_violations > 0 {
        let nid = "workflow_abuse";
        nodes.push(json!({"id": nid, "type": "policy", "label": "Workflow Policy Violations"}));
        edges.push(json!({"from": "config_leak", "to": nid, "relation": "contains"}));
    }
    if posture.build_logs_exposed > 0 {
        let nid = "build_logs";
        nodes.push(json!({"id": nid, "type": "exposure", "label": "Build Logs"}));
        edges.push(json!({"from": "target", "to": nid, "relation": "leaks"}));
    }
    if posture.artifact_exposed > 0 {
        let nid = "artifacts";
        nodes.push(json!({"id": nid, "type": "artifact", "label": "Artifact Registry"}));
        edges.push(json!({"from": "target", "to": nid, "relation": "hosts"}));
        edges.push(json!({"from": nid, "to": "workflow_abuse", "relation": "poisons"}));
    }
    if posture.slsa_gaps > 0 {
        let nid = "slsa_gap";
        nodes.push(json!({"id": nid, "type": "policy", "label": "SLSA Provenance Gap"}));
        edges.push(json!({"from": "config_leak", "to": nid, "relation": "missing"}));
    }

    json!({ "nodes": nodes, "edges": edges })
}

async fn probe_platform_fingerprint(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_fingerprint {
        return;
    }
    let auth_hs = auth_headers(settings);
    let auth_refs: Vec<(&str, &str)> = auth_hs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let Some(probe) = http_get_with_headers(client, &base, &auth_refs).await else {
        return;
    };
    if let Some((pid, label)) = detect_platform(&probe) {
        if platform_allowed(settings, pid) {
            posture.platforms.insert(pid.to_string());
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("CI/CD platform fingerprint: {label}"),
                    "info",
                    MITRE,
                    &format!(
                        "Live HTTP fingerprint on {} identifies {label} (HTTP {}). Comparable to Wiz \
                         DevSecOps asset discovery — platform confirmed from real response headers/body.",
                        host, probe.status
                    ),
                    host,
                    0.95,
                    Evidence::new()
                        .with("platform", pid)
                        .with("url", &base)
                        .with("status", probe.status),
                ),
            );
        }
    }
}

// ── Attack paths ──────────────────────────────────────────────────────────────

fn attack_paths(posture: &Posture, host: &str) -> Vec<Value> {
    let mut paths = Vec::new();
    if posture.jenkins_console && posture.api_exposed > 0 {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Unauthenticated Jenkins + script console → supply-chain RCE",
            "severity": "critical",
            "mitre_attack": MITRE,
            "path_steps": ["Open Jenkins API", "Reach /script console", "Groovy RCE on controller", "Poison all build artifacts"],
            "description": format!(
                "Toxic combination on {}: Jenkins API responds without authentication and the Groovy \
                 script console surface is reachable — attackers achieve arbitrary code execution on the \
                 build controller and poison every downstream artifact (Wiz DevSecOps breach chain).",
                host
            ),
            "confidence": 0.93
        }));
    }
    if posture.secrets_in_response && posture.api_exposed > 0 {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Open CI/CD API + credential leakage → pipeline takeover",
            "severity": "critical",
            "mitre_attack": "T1552.004",
            "path_steps": ["Unauthenticated CI API", "Secrets in response body", "Register rogue runner / trigger pipeline", "Persist in build infra"],
            "description": format!(
                "Unauthenticated CI/CD endpoints on {} return responses containing secret keywords or \
                 token patterns — an attacker registers a malicious runner or triggers privileged pipelines.",
                host
            ),
            "confidence": 0.90
        }));
    }
    if posture.workflow_violations > 0 && posture.config_exposed > 0 {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Exposed workflow + pwn-request/injection → org secret exfiltration",
            "severity": "critical",
            "mitre_attack": MITRE,
            "path_steps": ["Leaked pipeline YAML", "pwn-request / script injection", "Fork PR triggers workflow", "Exfil org secrets"],
            "description": format!(
                "Pipeline configuration is web-accessible on {} and static analysis found GitHub Actions \
                 pwn-request or script-injection patterns — fork PRs can steal organization secrets.",
                host
            ),
            "confidence": 0.91
        }));
    }
    if posture.runner_tokens {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Runner registration token exposure → persistent build infrastructure compromise",
            "severity": "critical",
            "mitre_attack": MITRE,
            "path_steps": ["Token in API/log response", "Register malicious runner", "Receive prod build jobs", "Inject backdoored artifacts"],
            "description": format!(
                "Runner registration token material observed on {} — attackers register rogue runners \
                 that receive production build jobs and inject malicious artifacts.",
                host
            ),
            "confidence": 0.88
        }));
    }
    if posture.artifact_exposed > 0 && posture.workflow_violations > 0 {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Open artifact registry + weak pipeline → supply-chain artifact substitution",
            "severity": "critical",
            "mitre_attack": MITRE,
            "path_steps": ["Exposed artifact/registry API", "Policy-violating publish workflow", "Replace release artifact", "Downstream deploy consumes poison"],
            "description": format!(
                "Artifact registry surface on {} is reachable without strong auth and pipeline static analysis \
                 found publish/release gaps — attackers substitute malicious packages/images consumed by production.",
                host
            ),
            "confidence": 0.87
        }));
    }
    if posture.build_logs_exposed > 0 && posture.secrets_in_response {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Exposed build logs + secret material → credential replay",
            "severity": "high",
            "mitre_attack": "T1552.001",
            "path_steps": ["Public build log URL", "Secret/token in log output", "Replay credential", "Pivot to deploy keys"],
            "description": format!(
                "Build logs on {} are web-accessible and prior probes detected secret patterns — historical \
                 CI output often contains replayable tokens and cloud credentials.",
                host
            ),
            "confidence": 0.85
        }));
    }
    if posture.platforms.contains("argocd") && posture.api_exposed > 0 {
        paths.push(json!({
            "type": ENGINE_ID,
            "category": "attack_path",
            "title": "Open ArgoCD API → GitOps manifest hijack → cluster takeover",
            "severity": "critical",
            "mitre_attack": MITRE,
            "path_steps": ["Unauthenticated /api/v1/applications", "Read repoURL + sync policy", "Poison Git source or sync malicious App", "Cluster-wide deploy"],
            "description": format!(
                "ArgoCD API on {} responds without authentication — attackers enumerate Applications, \
                 identify connected Git repos, and chain to manifest substitution (CNCF GitOps breach class).",
                host
            ),
            "confidence": 0.90
        }));
    }
    paths
}

// ── Probe phases ──────────────────────────────────────────────────────────────

async fn probe_api_exposure(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_api {
        return;
    }
    let auth_hs = auth_headers(settings);
    let paths: Vec<&str> = settings.api_paths.iter().map(String::as_str).collect();
    let probes = probe_paths_with_auth(client, base, &paths, settings.concurrency, &auth_hs).await;

    for probe in probes {
        if !status_indicates_presence(probe.status) {
            continue;
        }
        let (pid, label) =
            detect_platform(&probe).unwrap_or_else(|| identify_tool_from_path(&probe.final_url));
        if !platform_allowed(settings, pid) {
            continue;
        }
        posture.platforms.insert(pid.to_string());
        if probe.status == 200 || probe.status == 201 {
            posture.api_exposed += 1;
            let is_jenkins_script = probe.final_url.contains("/script");
            if is_jenkins_script {
                posture.jenkins_console = true;
            }
            let sev = if is_jenkins_script {
                "critical"
            } else if probe.status == 200 {
                "critical"
            } else {
                "high"
            };
            if sev == "critical" {
                posture.unauthenticated_critical = true;
            }

            let secrets = detect_secrets(&probe.body);
            let keyword_hit = SECRET_KEYWORDS
                .iter()
                .any(|k| probe.body.to_ascii_lowercase().contains(k));
            if !secrets.is_empty() || keyword_hit {
                posture.secrets_in_response = true;
            }

            if settings.probe_runner_tokens {
                let token_hit = RUNNER_TOKEN_MARKERS.iter().any(|m| probe.body.contains(m));
                if token_hit {
                    posture.runner_tokens = true;
                }
            }

            let mut ev = Evidence::new()
                .with("platform", pid)
                .with("url", &probe.final_url)
                .with("status", probe.status)
                .with("body_len", probe.body.len())
                .check("unauthenticated", probe.status == 200, probe.status);
            if !secrets.is_empty() {
                ev = ev.with("secret_types", json!(secrets));
            }

            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("{} API exposed without authentication: {}", label, probe.final_url),
                    sev,
                    MITRE,
                    &format!(
                        "{} endpoint {} returned HTTP {} ({} bytes). Unauthenticated CI/CD access enables \
                         pipeline injection, secret theft, and supply-chain compromise.",
                        label, probe.final_url, probe.status, probe.body.len()
                    ),
                    host,
                    if is_jenkins_script { 0.97 } else { 0.92 },
                    ev,
                ),
            );

            if pid == "argocd" && settings.probe_workflow_analysis {
                let live = analyze_live_argocd_applications(&probe.body, &probe.final_url, host);
                append_workflow_findings(posture, findings, settings, live);
            }
        }
    }
}

async fn probe_jenkins_script_console(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_jenkins_console {
        return;
    }
    let url = join_url(base, "/script");
    let auth_hs = auth_headers(settings);
    let auth_refs: Vec<(&str, &str)> = auth_hs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let Some(probe) = http_get_with_headers(client, &url, &auth_refs).await else {
        return;
    };
    if probe.status != 200 {
        return;
    }
    let body_l = probe.body.to_ascii_lowercase();
    if !body_l.contains("groovy") && !body_l.contains("jenkins") && !body_l.contains("script") {
        return;
    }
    posture.jenkins_console = true;
    posture.unauthenticated_critical = true;
    push_if_severe(
        findings,
        settings,
        finding_rich(
            ENGINE_ID,
            &format!("Jenkins Groovy script console reachable: {}", url),
            "critical",
            MITRE,
            &format!(
                "Jenkins script console at {} responds HTTP 200 — if unauthenticated, this is \
                 arbitrary code execution on the build controller (CISA KEV-class DevSecOps risk).",
                url
            ),
            host,
            0.98,
            Evidence::new().with("url", &url).with("status", 200).check(
                "groovy_console",
                true,
                "reachable",
            ),
        ),
    );
}

async fn probe_config_exposure(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_config {
        return;
    }
    let paths: Vec<&str> = settings.config_paths.iter().map(String::as_str).collect();
    let auth_hs = auth_headers(settings);
    let probes = probe_paths_with_auth(client, base, &paths, settings.concurrency, &auth_hs).await;

    for probe in probes {
        if probe.status != 200 || probe.body.len() < 12 {
            continue;
        }
        let body_l = probe.body.to_ascii_lowercase();
        let looks_ci = body_l.contains("pipeline")
            || body_l.contains("jobs:")
            || body_l.contains("stages:")
            || body_l.contains("on:")
            || body_l.contains("workflow")
            || body_l.contains("jenkins")
            || body_l.contains("script:")
            || body_l.contains("runs-on:")
            || probe.final_url.contains("Jenkinsfile")
            || probe.final_url.contains("workflow");
        if !looks_ci {
            continue;
        }
        posture.config_exposed += 1;
        let secrets = detect_secrets(&probe.body);
        let sev = if secrets.is_empty() {
            "high"
        } else {
            "critical"
        };

        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("CI/CD pipeline config exposed: {}", probe.final_url),
                sev,
                MITRE,
                &format!(
                    "Pipeline configuration {} is web-accessible (HTTP 200, {} bytes){}. \
                     Exposed CI/CD configs reveal deployment targets, secrets references, and runner topology.",
                    probe.final_url,
                    probe.body.len(),
                    if secrets.is_empty() {
                        String::new()
                    } else {
                        format!(" with embedded secrets: {}", secrets.join(", "))
                    }
                ),
                host,
                if secrets.is_empty() { 0.90 } else { 0.97 },
                Evidence::new()
                    .with("url", &probe.final_url)
                    .with("body_len", probe.body.len()),
            ),
        );

        if settings.probe_workflow_analysis {
            let wf = analyze_workflow_content(&probe.body, &probe.final_url, host);
            append_workflow_findings(posture, findings, settings, wf);
        }
    }
}

const BUILD_LOG_MARKERS: &[&str] = &[
    "console output",
    "consoletext",
    "started by",
    "building remotely",
    "finished: success",
    "finished: failure",
    "pipeline #",
    "build #",
    "hudson.model",
    "gitlab-ci",
    "job log",
    "log.txt",
    "allbuilds",
    "lastbuild",
];

const ARTIFACT_MARKERS: &[&str] = &[
    "repositories",
    "packages",
    "_catalog",
    "maven-metadata",
    "artifactid",
    "downloadurl",
    "application/vnd.docker",
    "registry/repositories",
    "tree/General",
    "blobstore",
];

async fn probe_build_log_exposure(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_build_logs {
        return;
    }
    let auth_hs = auth_headers(settings);
    let limit = settings.max_requests.min(80).min(BUILD_LOG_PATHS.len());
    let paths: Vec<&str> = BUILD_LOG_PATHS.iter().take(limit).copied().collect();
    let probes =
        probe_paths_with_auth(client, base, &paths, settings.concurrency.min(8), &auth_hs).await;

    for probe in probes {
        if probe.status != 200 || probe.body.len() < 20 {
            continue;
        }
        let body_l = probe.body.to_ascii_lowercase();
        let is_log = BUILD_LOG_MARKERS.iter().any(|m| body_l.contains(m));
        if !is_log {
            continue;
        }
        posture.build_logs_exposed += 1;
        let secrets = detect_secrets(&probe.body);
        if !secrets.is_empty() {
            posture.secrets_in_response = true;
        }
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("CI build log/history exposed: {}", probe.final_url),
                if secrets.is_empty() { "high" } else { "critical" },
                "T1552.001",
                &format!(
                    "Build log or job history at {} returned HTTP 200 ({} bytes) with CI log markers{} — \
                     historical CI output frequently contains replayable tokens.",
                    probe.final_url,
                    probe.body.len(),
                    if secrets.is_empty() {
                        String::new()
                    } else {
                        format!(" and secrets: {}", secrets.join(", "))
                    }
                ),
                host,
                if secrets.is_empty() { 0.88 } else { 0.96 },
                Evidence::new()
                    .with("url", &probe.final_url)
                    .with("body_len", probe.body.len())
                    .with("policy", "WZ-LOG-001"),
            ),
        );
    }
}

async fn probe_artifact_registry_exposure(
    client: &Client,
    base: &str,
    host: &str,
    settings: &Settings,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_artifact_exposure {
        return;
    }
    let auth_hs = auth_headers(settings);
    let limit = settings.max_requests.min(60).min(ARTIFACT_PATHS.len());
    let paths: Vec<&str> = ARTIFACT_PATHS.iter().take(limit).copied().collect();
    let probes =
        probe_paths_with_auth(client, base, &paths, settings.concurrency.min(8), &auth_hs).await;

    for probe in probes {
        if !status_indicates_presence(probe.status) || probe.body.len() < 8 {
            continue;
        }
        let body_l = probe.body.to_ascii_lowercase();
        let is_registry = ARTIFACT_MARKERS.iter().any(|m| body_l.contains(m))
            || probe.final_url.contains("_catalog")
            || probe.final_url.contains("artifactory")
            || probe.final_url.contains("repository");
        if !is_registry && probe.status != 200 {
            continue;
        }
        if probe.status == 200 && !is_registry {
            continue;
        }
        posture.artifact_exposed += 1;
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                &format!("Artifact registry / package API exposed: {}", probe.final_url),
                if probe.status == 200 { "critical" } else { "high" },
                MITRE,
                &format!(
                    "Artifact or package registry endpoint {} returned HTTP {} — unauthenticated access \
                     enables supply-chain artifact substitution (Wiz-class poisoned-package pivot).",
                    probe.final_url, probe.status
                ),
                host,
                0.91,
                Evidence::new()
                    .with("url", &probe.final_url)
                    .with("status", probe.status)
                    .with("policy", "WZ-ART-001"),
            ),
        );
    }
}

async fn probe_github_repo_governance(
    client: &Client,
    settings: &Settings,
    host: &str,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_repo_governance {
        return;
    }
    let Some(repo_url) = settings.repo_url.as_ref().filter(|u| !u.trim().is_empty()) else {
        return;
    };
    let Some((owner, repo)) = parse_github_repo(repo_url) else {
        return;
    };

    let auth = |req: reqwest::RequestBuilder| -> reqwest::RequestBuilder {
        let req = req
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "Weissman-CICD-Security/1.0");
        if let Some(t) = &settings.github_token {
            req.header("Authorization", format!("Bearer {t}"))
        } else {
            req
        }
    };

    // Actions permissions — real GitHub API (public repos return limited data; token unlocks full)
    let perm_url = format!("https://api.github.com/repos/{owner}/{repo}/actions/permissions");
    if let Ok(resp) = auth(client.get(&perm_url)).send().await {
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<Value>().await {
                let fork_prs = v.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                let allowed = v
                    .get("allowed_actions")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if allowed == "all" || allowed.is_empty() {
                    push_if_severe(
                        findings,
                        settings,
                        finding_rich(
                            ENGINE_ID,
                            &format!("GitHub Actions allows all actions: {owner}/{repo}"),
                            "medium",
                            MITRE,
                            &format!(
                                "Live GitHub API: repos/{owner}/{repo} actions/permissions allows broad \
                                 action execution — typosquatted or compromised third-party actions are in scope."
                            ),
                            host,
                            0.82,
                            Evidence::new()
                                .with("repo", format!("{owner}/{repo}"))
                                .with("allowed_actions", allowed)
                                .with("policy", "WZ-GOV-001"),
                        ),
                    );
                    posture.workflow_violations += 1;
                }
                if v.get("enabled").and_then(Value::as_bool) == Some(true) && fork_prs {
                    // check fork PR workflow policy via workflow permissions endpoint
                    let wf_perm = format!(
                        "https://api.github.com/repos/{owner}/{repo}/actions/permissions/workflow"
                    );
                    if let Ok(r2) = auth(client.get(&wf_perm)).send().await {
                        if r2.status().is_success() {
                            if let Ok(wv) = r2.json::<Value>().await {
                                let default_rw = wv
                                    .get("default_workflow_permissions")
                                    .and_then(Value::as_str)
                                    .unwrap_or("");
                                if default_rw == "write" || default_rw == "read-and-write" {
                                    push_if_severe(
                                        findings,
                                        settings,
                                        finding_rich(
                                            ENGINE_ID,
                                            &format!("GitHub default GITHUB_TOKEN write scope: {owner}/{repo}"),
                                            "high",
                                            "T1098",
                                            &format!(
                                                "Live API: {owner}/{repo} default_workflow_permissions={default_rw} — \
                                                 workflows receive write-capable GITHUB_TOKEN by default."
                                            ),
                                            host,
                                            0.86,
                                            Evidence::new()
                                                .with("repo", format!("{owner}/{repo}"))
                                                .with("default_workflow_permissions", default_rw)
                                                .with("policy", "WZ-GOV-002"),
                                        ),
                                    );
                                    posture.workflow_violations += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Branch protection — 404 means unprotected (real signal for public repos with token)
    let branch = settings
        .repo_ref
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("main");
    let prot_url =
        format!("https://api.github.com/repos/{owner}/{repo}/branches/{branch}/protection");
    if let Ok(resp) = auth(client.get(&prot_url)).send().await {
        if resp.status().as_u16() == 404 {
            push_if_severe(
                findings,
                settings,
                finding_rich(
                    ENGINE_ID,
                    &format!("GitHub branch without protection rules: {owner}/{repo}@{branch}"),
                    "high",
                    "T1195.002",
                    &format!(
                        "Live GitHub API returned 404 for branch protection on {owner}/{repo}@{branch} — \
                         direct pushes and unreviewed pipeline changes may reach default branch."
                    ),
                    host,
                    0.88,
                    Evidence::new()
                        .with("repo", format!("{owner}/{repo}"))
                        .with("branch", branch)
                        .with("policy", "WZ-GOV-003"),
                ),
            );
            posture.workflow_violations += 1;
        } else if resp.status().is_success() {
            if let Ok(v) = resp.json::<Value>().await {
                let reviews = v.get("required_pull_request_reviews");
                if reviews.is_none() {
                    push_if_severe(
                        findings,
                        settings,
                        finding_rich(
                            ENGINE_ID,
                            &format!("GitHub branch protection without required PR reviews: {owner}/{repo}"),
                            "medium",
                            MITRE,
                            &format!(
                                "Branch protection exists on {owner}/{repo}@{branch} but required_pull_request_reviews \
                                 is absent — pipeline tampering may merge without human review."
                            ),
                            host,
                            0.80,
                            Evidence::new()
                                .with("repo", format!("{owner}/{repo}"))
                                .with("policy", "WZ-GOV-004"),
                        ),
                    );
                }
                if v.get("required_signatures")
                    .and_then(|s| s.get("enabled"))
                    .and_then(Value::as_bool)
                    != Some(true)
                {
                    push_if_severe(
                        findings,
                        settings,
                        finding_rich(
                            ENGINE_ID,
                            &format!("GitHub branch lacks required signed commits: {owner}/{repo}@{branch}"),
                            "medium",
                            "T1195.002",
                            &format!(
                                "Live GitHub API: branch protection on {owner}/{repo}@{branch} does not require \
                                 signed commits — unsigned pipeline commits can land on default branch."
                            ),
                            host,
                            0.81,
                            Evidence::new()
                                .with("repo", format!("{owner}/{repo}"))
                                .with("branch", branch)
                                .with("policy", "WZ-GOV-005"),
                        ),
                    );
                    posture.workflow_violations += 1;
                }
            }
        }
    }

    // Fork PR workflow access — real GitHub Actions permissions API
    let access_url =
        format!("https://api.github.com/repos/{owner}/{repo}/actions/permissions/access");
    if let Ok(resp) = auth(client.get(&access_url)).send().await {
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<Value>().await {
                let level = v.get("access_level").and_then(Value::as_str).unwrap_or("");
                if !level.is_empty() && level != "none" {
                    push_if_severe(
                        findings,
                        settings,
                        finding_rich(
                            ENGINE_ID,
                            &format!("GitHub Actions fork/outside workflow access: {owner}/{repo}"),
                            "high",
                            MITRE,
                            &format!(
                                "Live GitHub API: actions/permissions/access access_level={level} — \
                                 workflows from fork pull requests or outside collaborators may execute with repo secrets."
                            ),
                            host,
                            0.89,
                            Evidence::new()
                                .with("repo", format!("{owner}/{repo}"))
                                .with("access_level", level)
                                .with("policy", "WZ-GOV-006"),
                        ),
                    );
                    posture.workflow_violations += 1;
                }
            }
        }
    }

    // Secret scanning / push protection — requires token; skipped silently when unauthenticated
    if settings.github_token.is_some() {
        let meta_url = format!("https://api.github.com/repos/{owner}/{repo}");
        if let Ok(resp) = auth(client.get(&meta_url)).send().await {
            if resp.status().is_success() {
                if let Ok(v) = resp.json::<Value>().await {
                    let sec = v.get("security_and_analysis").cloned().unwrap_or(json!({}));
                    let secret_scan = sec
                        .get("secret_scanning")
                        .and_then(|s| s.get("status"))
                        .and_then(Value::as_str)
                        .unwrap_or("disabled");
                    let push_prot = sec
                        .get("secret_scanning_push_protection")
                        .and_then(|s| s.get("status"))
                        .and_then(Value::as_str)
                        .unwrap_or("disabled");
                    if secret_scan != "enabled" {
                        push_if_severe(
                            findings,
                            settings,
                            finding_rich(
                                ENGINE_ID,
                                &format!("GitHub secret scanning not enabled: {owner}/{repo}"),
                                "medium",
                                "T1552.004",
                                &format!(
                                    "Live GitHub API: security_and_analysis.secret_scanning.status={secret_scan} — \
                                     pipeline secrets in commits may go undetected."
                                ),
                                host,
                                0.78,
                                Evidence::new()
                                    .with("repo", format!("{owner}/{repo}"))
                                    .with("secret_scanning", secret_scan)
                                    .with("policy", "WZ-GOV-007"),
                            ),
                        );
                    }
                    if push_prot != "enabled" {
                        push_if_severe(
                            findings,
                            settings,
                            finding_rich(
                                ENGINE_ID,
                                &format!("GitHub secret scanning push protection disabled: {owner}/{repo}"),
                                "high",
                                "T1552.004",
                                &format!(
                                    "Live GitHub API: secret_scanning_push_protection.status={push_prot} — \
                                     developers can push secrets into CI/CD configs without block."
                                ),
                                host,
                                0.84,
                                Evidence::new()
                                    .with("repo", format!("{owner}/{repo}"))
                                    .with("push_protection", push_prot)
                                    .with("policy", "WZ-GOV-008"),
                            ),
                        );
                        posture.workflow_violations += 1;
                    }
                }
            }
        }
    }
}

fn parse_github_repo(url: &str) -> Option<(String, String)> {
    let t = url.trim().trim_end_matches('/');
    let parts: Vec<&str> = t.split("github.com/").collect();
    if parts.len() < 2 {
        return None;
    }
    let segs: Vec<&str> = parts[1].split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() < 2 {
        return None;
    }
    Some((
        segs[0].to_string(),
        segs[1].trim_end_matches(".git").to_string(),
    ))
}

/// Parsed repository target for the multi-vendor repository plane.
enum RepoTarget {
    GitHub {
        owner: String,
        repo: String,
    },
    GitLab {
        api_base: String,
        project_path: String,
    },
    Bitbucket {
        workspace: String,
        repo: String,
    },
    AzureDevOps {
        org: String,
        project: String,
        repo: String,
    },
}

fn parse_azure_devops_repo(url: &str) -> Option<(String, String, String)> {
    let t = url.trim().trim_end_matches('/').trim_end_matches(".git");
    if let Some(rest) = t.split("dev.azure.com/").nth(1) {
        let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
        if segs.len() >= 4 && segs[2] == "_git" {
            return Some((
                segs[0].to_string(),
                segs[1].to_string(),
                segs[3].to_string(),
            ));
        }
    }
    if let Some(rest) = t.split("visualstudio.com/").nth(1) {
        let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
        if segs.len() >= 3 && segs[1] == "_git" {
            let org = t
                .split("://")
                .nth(1)
                .and_then(|h| h.split('.').next())
                .unwrap_or("org")
                .to_string();
            return Some((org, segs[0].to_string(), segs[2].to_string()));
        }
    }
    None
}

fn ado_basic_auth(pat: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!(":{pat}"))
}

fn parse_repo_target(url: &str) -> Option<RepoTarget> {
    let t = url.trim().trim_end_matches('/').trim_end_matches(".git");
    if let Some((owner, repo)) = parse_github_repo(t) {
        return Some(RepoTarget::GitHub { owner, repo });
    }
    if t.contains("gitlab") {
        if let Some(idx) = t.find("://") {
            let rest = &t[idx + 3..];
            if let Some(slash) = rest.find('/') {
                let host = &rest[..slash];
                let path = rest[slash + 1..].trim_matches('/');
                if !path.is_empty() && path.contains('/') {
                    let api_base = if host.contains("gitlab.com") {
                        "https://gitlab.com/api/v4".to_string()
                    } else {
                        format!("https://{host}/api/v4")
                    };
                    return Some(RepoTarget::GitLab {
                        api_base,
                        project_path: path.to_string(),
                    });
                }
            }
        }
    }
    if t.contains("bitbucket.org/") {
        let segs: Vec<&str> = t
            .split("bitbucket.org/")
            .nth(1)?
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if segs.len() >= 2 {
            return Some(RepoTarget::Bitbucket {
                workspace: segs[0].to_string(),
                repo: segs[1].to_string(),
            });
        }
    }
    if let Some((org, project, repo)) = parse_azure_devops_repo(t) {
        return Some(RepoTarget::AzureDevOps { org, project, repo });
    }
    None
}

const CI_REPO_PATTERNS: &[&str] = &[
    ".github/workflows/",
    "Jenkinsfile",
    ".gitlab-ci.yml",
    ".gitlab/ci/",
    "azure-pipelines.yml",
    ".circleci/config.yml",
    ".woodpecker.yml",
    ".drone.yml",
    ".argo/",
    ".tekton/",
    "bitbucket-pipelines.yml",
    "application.yaml",
    "applications.yaml",
    "appproject",
];

fn path_matches_ci_artifact(path: &str) -> bool {
    let pl = path.to_ascii_lowercase();
    CI_REPO_PATTERNS
        .iter()
        .any(|p| pl.contains(&p.to_ascii_lowercase()))
}

fn ingest_repo_ci_file(
    posture: &mut Posture,
    findings: &mut Vec<Value>,
    settings: &Settings,
    host: &str,
    repo_label: &str,
    reff: &str,
    path: &str,
    body: &str,
) {
    posture.config_exposed += 1;
    push_if_severe(
        findings,
        settings,
        finding_rich(
            ENGINE_ID,
            &format!("CI config fetched from repository: {path}"),
            "info",
            MITRE,
            &format!(
                "Live fetch from {repo_label}@{reff}: {path} ({} bytes). Static workflow \
                 analysis applied — Wiz Code / GitHub Advanced Security / GitLab SAST pipeline depth.",
                body.len()
            ),
            host,
            1.0,
            Evidence::new()
                .with("repo", repo_label)
                .with("ref", reff)
                .with("path", path),
        ),
    );
    if settings.probe_workflow_analysis {
        let wf = analyze_workflow_content(body, path, host);
        append_workflow_findings(posture, findings, settings, wf);
    }
    scan_artifact_secrets(posture, findings, settings, host, repo_label, path, body);
}

async fn probe_repository_plane(
    client: &Client,
    settings: &Settings,
    host: &str,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
) {
    if !settings.probe_repo {
        return;
    }
    let Some(repo_url) = settings.repo_url.as_ref().filter(|u| !u.trim().is_empty()) else {
        return;
    };
    let Some(target) = parse_repo_target(repo_url) else {
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                "Repository URL not parseable",
                "info",
                "",
                "Provide github.com, gitlab.com (or self-hosted GitLab), bitbucket.org, or dev.azure.com org/project/_git/repo URL.",
                host,
                1.0,
                Evidence::new().with("repo_url", repo_url.as_str()),
            ),
        );
        return;
    };

    match target {
        RepoTarget::GitHub { owner, repo } => {
            probe_github_repo_inner(client, settings, host, posture, findings, &owner, &repo).await;
        }
        RepoTarget::GitLab {
            api_base,
            project_path,
        } => {
            probe_gitlab_repo_inner(
                client,
                settings,
                host,
                posture,
                findings,
                &api_base,
                &project_path,
            )
            .await;
        }
        RepoTarget::Bitbucket { workspace, repo } => {
            probe_bitbucket_repo_inner(
                client, settings, host, posture, findings, &workspace, &repo,
            )
            .await;
        }
        RepoTarget::AzureDevOps { org, project, repo } => {
            probe_azure_devops_repo_inner(
                client, settings, host, posture, findings, &org, &project, &repo,
            )
            .await;
        }
    }
}

async fn probe_github_repo_inner(
    client: &Client,
    settings: &Settings,
    host: &str,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
    owner: &str,
    repo: &str,
) {
    let auth = |req: reqwest::RequestBuilder| -> reqwest::RequestBuilder {
        let req = req
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "Weissman-CICD-Security/1.0");
        if let Some(t) = &settings.github_token {
            req.header("Authorization", format!("Bearer {t}"))
        } else {
            req
        }
    };

    let reff = match &settings.repo_ref {
        Some(r) if !r.trim().is_empty() => r.trim().to_string(),
        _ => {
            let meta_url = format!("https://api.github.com/repos/{owner}/{repo}");
            match auth(client.get(&meta_url)).send().await {
                Ok(resp) if resp.status().is_success() => resp
                    .json::<Value>()
                    .await
                    .ok()
                    .and_then(|v| {
                        v.get("default_branch")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| "main".to_string()),
                _ => "main".to_string(),
            }
        }
    };

    let tree_url =
        format!("https://api.github.com/repos/{owner}/{repo}/git/trees/{reff}?recursive=1");
    let Ok(resp) = auth(client.get(&tree_url)).send().await else {
        return;
    };
    if !resp.status().is_success() {
        return;
    }
    let Ok(tree) = resp.json::<Value>().await else {
        return;
    };
    let entries = tree
        .get("tree")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let repo_label = format!("{owner}/{repo}");
    let mut fetched = 0u32;

    for e in entries {
        if fetched >= settings.max_repo_files {
            break;
        }
        if e.get("type").and_then(Value::as_str) != Some("blob") {
            continue;
        }
        let Some(path) = e.get("path").and_then(Value::as_str) else {
            continue;
        };
        if !path_matches_ci_artifact(path) {
            continue;
        }
        let size = e.get("size").and_then(Value::as_u64).unwrap_or(0);
        if size > 262_144 {
            continue;
        }
        let raw_url = format!("https://raw.githubusercontent.com/{owner}/{repo}/{reff}/{path}");
        let mut rb = client
            .get(&raw_url)
            .header("User-Agent", "Weissman-CICD-Security/1.0");
        if let Some(t) = &settings.github_token {
            rb = rb.header("Authorization", format!("Bearer {t}"));
        }
        let Ok(r) = rb.send().await else { continue };
        if !r.status().is_success() {
            continue;
        }
        let Ok(body) = r.text().await else { continue };
        fetched += 1;
        ingest_repo_ci_file(
            posture,
            findings,
            settings,
            host,
            &repo_label,
            &reff,
            path,
            &body,
        );
    }

    if settings.probe_repo_governance {
        probe_github_repo_governance(client, settings, host, posture, findings).await;
    }
}

async fn probe_gitlab_repo_inner(
    client: &Client,
    settings: &Settings,
    host: &str,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
    api_base: &str,
    project_path: &str,
) {
    let encoded_project = urlencoding::encode(project_path);
    let gl_auth = |req: reqwest::RequestBuilder| -> reqwest::RequestBuilder {
        let req = req.header("User-Agent", "Weissman-CICD-Security/1.0");
        if let Some(t) = &settings.gitlab_token {
            req.header("PRIVATE-TOKEN", t.trim())
        } else {
            req
        }
    };

    let meta_url = format!("{api_base}/projects/{encoded_project}");
    let reff = match &settings.repo_ref {
        Some(r) if !r.trim().is_empty() => r.trim().to_string(),
        _ => match gl_auth(client.get(&meta_url)).send().await {
            Ok(resp) if resp.status().is_success() => resp
                .json::<Value>()
                .await
                .ok()
                .and_then(|v| {
                    v.get("default_branch")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "main".to_string()),
            _ => "main".to_string(),
        },
    };

    let mut entries: Vec<Value> = Vec::new();
    let mut page = 1u32;
    loop {
        let page_url = format!(
            "{api_base}/projects/{encoded_project}/repository/tree?recursive=true&ref={}&per_page=100&page={page}",
            urlencoding::encode(&reff)
        );
        let Ok(resp) = gl_auth(client.get(&page_url)).send().await else {
            break;
        };
        if !resp.status().is_success() {
            break;
        }
        let Ok(batch) = resp.json::<Value>().await else {
            break;
        };
        let batch_arr = batch.as_array().cloned().unwrap_or_default();
        let n = batch_arr.len();
        entries.extend(batch_arr);
        if n < 100 || page >= 10 {
            break;
        }
        page += 1;
    }
    let repo_label = project_path.to_string();
    let mut fetched = 0u32;

    for e in entries {
        if fetched >= settings.max_repo_files {
            break;
        }
        if e.get("type").and_then(Value::as_str) != Some("blob") {
            continue;
        }
        let Some(path) = e.get("path").and_then(Value::as_str) else {
            continue;
        };
        if !path_matches_ci_artifact(path) {
            continue;
        }
        let encoded_path = urlencoding::encode(path);
        let file_url = format!(
            "{api_base}/projects/{encoded_project}/repository/files/{encoded_path}/raw?ref={}",
            urlencoding::encode(&reff)
        );
        let Ok(r) = gl_auth(client.get(&file_url)).send().await else {
            continue;
        };
        if !r.status().is_success() {
            continue;
        }
        let Ok(body) = r.text().await else { continue };
        if body.len() > 262_144 {
            continue;
        }
        fetched += 1;
        ingest_repo_ci_file(
            posture,
            findings,
            settings,
            host,
            &repo_label,
            &reff,
            path,
            &body,
        );
    }

    if settings.probe_repo_governance {
        probe_gitlab_repo_governance(
            client,
            settings,
            host,
            posture,
            findings,
            api_base,
            project_path,
        )
        .await;
    }
}

async fn probe_gitlab_repo_governance(
    client: &Client,
    settings: &Settings,
    host: &str,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
    api_base: &str,
    project_path: &str,
) {
    let Some(token) = settings
        .gitlab_token
        .as_ref()
        .filter(|t| !t.trim().is_empty())
    else {
        return;
    };
    let encoded_project = urlencoding::encode(project_path);
    let auth = |req: reqwest::RequestBuilder| -> reqwest::RequestBuilder {
        req.header("PRIVATE-TOKEN", token.trim())
            .header("User-Agent", "Weissman-CICD-Security/1.0")
    };

    let prot_url = format!("{api_base}/projects/{encoded_project}/protected_branches");
    if let Ok(resp) = auth(client.get(&prot_url)).send().await {
        if resp.status().is_success() {
            if let Ok(arr) = resp.json::<Value>().await {
                if arr.as_array().is_some_and(|a| a.is_empty()) {
                    push_if_severe(
                        findings,
                        settings,
                        finding_rich(
                            ENGINE_ID,
                            &format!("GitLab project has no protected branches: {project_path}"),
                            "high",
                            "T1195.002",
                            &format!(
                                "Live GitLab API: project {project_path} has zero protected branches — \
                                 direct pushes can alter CI/CD without review."
                            ),
                            host,
                            0.87,
                            Evidence::new()
                                .with("project", project_path)
                                .with("policy", "WZ-GL-GOV-001"),
                        ),
                    );
                    posture.workflow_violations += 1;
                }
            }
        }
    }

    let meta_url = format!("{api_base}/projects/{encoded_project}");
    if let Ok(resp) = auth(client.get(&meta_url)).send().await {
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<Value>().await {
                let vis = v.get("visibility").and_then(Value::as_str).unwrap_or("");
                let pub_buil = v
                    .get("public_builds")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if vis == "public" && pub_buil {
                    push_if_severe(
                        findings,
                        settings,
                        finding_rich(
                            ENGINE_ID,
                            &format!("GitLab public project with public CI logs: {project_path}"),
                            "medium",
                            "T1552.001",
                            &format!(
                                "Live GitLab API: {project_path} is public with public_builds=true — \
                                 CI logs may leak credentials."
                            ),
                            host,
                            0.80,
                            Evidence::new()
                                .with("project", project_path)
                                .with("policy", "WZ-GL-GOV-002"),
                        ),
                    );
                }
                if v.get("only_allow_merge_if_pipeline_succeeds")
                    .and_then(Value::as_bool)
                    != Some(true)
                {
                    push_if_severe(
                        findings,
                        settings,
                        finding_rich(
                            ENGINE_ID,
                            &format!("GitLab merge without required pipeline success: {project_path}"),
                            "medium",
                            MITRE,
                            &format!(
                                "Live GitLab API: {project_path} does not enforce pipeline-success before merge."
                            ),
                            host,
                            0.76,
                            Evidence::new()
                                .with("project", project_path)
                                .with("policy", "WZ-GL-GOV-003"),
                        ),
                    );
                }
            }
        }
    }
}

async fn probe_azure_devops_repo_inner(
    client: &Client,
    settings: &Settings,
    host: &str,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
    org: &str,
    project: &str,
    repo: &str,
) {
    let Some(pat) = settings
        .azure_devops_pat
        .as_ref()
        .filter(|t| !t.trim().is_empty())
    else {
        push_if_severe(
            findings,
            settings,
            finding_rich(
                ENGINE_ID,
                "Azure DevOps repository plane requires PAT",
                "info",
                "",
                &format!(
                    "Provide azure_devops_pat to fetch CI files from dev.azure.com/{org}/{project}/_git/{repo}. \
                     Azure DevOps REST API requires authentication even for public projects."
                ),
                host,
                1.0,
                Evidence::new()
                    .with("org", org)
                    .with("project", project)
                    .with("repo", repo),
            ),
        );
        return;
    };

    let auth_header = format!("Basic {}", ado_basic_auth(pat.trim()));
    let ado_auth = |req: reqwest::RequestBuilder| -> reqwest::RequestBuilder {
        req.header("Authorization", auth_header.as_str())
            .header("User-Agent", "Weissman-CICD-Security/1.0")
    };

    let repo_api = format!(
        "https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo}?api-version=7.1"
    );
    let reff = match &settings.repo_ref {
        Some(r) if !r.trim().is_empty() => r.trim().to_string(),
        _ => match ado_auth(client.get(&repo_api)).send().await {
            Ok(resp) if resp.status().is_success() => resp
                .json::<Value>()
                .await
                .ok()
                .and_then(|v| {
                    v.get("defaultBranch")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .map(|b| b.trim_start_matches("refs/heads/").to_string())
                .unwrap_or_else(|| "main".to_string()),
            _ => "main".to_string(),
        },
    };

    let items_url = format!(
        "https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo}/items\
         ?scopePath=/&recursionLevel=Full&versionDescriptor.version={}&versionDescriptor.versionType=branch&api-version=7.1",
        urlencoding::encode(&reff)
    );
    let Ok(resp) = ado_auth(client.get(&items_url)).send().await else {
        return;
    };
    if !resp.status().is_success() {
        return;
    }
    let Ok(items_doc) = resp.json::<Value>().await else {
        return;
    };
    let entries = items_doc
        .get("value")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let repo_label = format!("{org}/{project}/_git/{repo}");
    let mut fetched = 0u32;

    for e in entries {
        if fetched >= settings.max_repo_files {
            break;
        }
        if e.get("isFolder").and_then(Value::as_bool).unwrap_or(false) {
            continue;
        }
        let Some(path) = e.get("path").and_then(Value::as_str) else {
            continue;
        };
        let path = path.trim_start_matches('/');
        if path.is_empty() || !path_matches_ci_artifact(path) {
            continue;
        }
        let size = e.get("size").and_then(Value::as_u64).unwrap_or(0);
        if size > 262_144 {
            continue;
        }
        let file_url = format!(
            "https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo}/items\
             ?path={}&versionDescriptor.version={}&versionDescriptor.versionType=branch&includeContent=true&api-version=7.1",
            urlencoding::encode(&format!("/{path}")),
            urlencoding::encode(&reff)
        );
        let Ok(r) = ado_auth(client.get(&file_url)).send().await else {
            continue;
        };
        if !r.status().is_success() {
            continue;
        }
        let Ok(body) = r.text().await else { continue };
        if body.len() < 8 {
            continue;
        }
        fetched += 1;
        ingest_repo_ci_file(
            posture,
            findings,
            settings,
            host,
            &repo_label,
            &reff,
            path,
            &body,
        );
    }

    if settings.probe_repo_governance {
        probe_azure_devops_repo_governance(
            client, settings, host, posture, findings, org, project, repo, pat,
        )
        .await;
    }
}

async fn probe_azure_devops_repo_governance(
    client: &Client,
    settings: &Settings,
    host: &str,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
    org: &str,
    project: &str,
    repo: &str,
    pat: &str,
) {
    let auth_header = format!("Basic {}", ado_basic_auth(pat.trim()));
    let ado_auth = |req: reqwest::RequestBuilder| -> reqwest::RequestBuilder {
        req.header("Authorization", auth_header.as_str())
            .header("User-Agent", "Weissman-CICD-Security/1.0")
    };

    let policy_url = format!(
        "https://dev.azure.com/{org}/{project}/_apis/policy/configurations?api-version=7.1"
    );
    if let Ok(resp) = ado_auth(client.get(&policy_url)).send().await {
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<Value>().await {
                let policies = v
                    .get("value")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let repo_policies: Vec<_> = policies
                    .iter()
                    .filter(|p| {
                        p.get("isEnabled").and_then(Value::as_bool).unwrap_or(false)
                            && p.get("settings")
                                .and_then(|s| s.get("scope"))
                                .and_then(Value::as_array)
                                .is_some_and(|scopes| {
                                    scopes.iter().any(|sc| {
                                        sc.get("repositoryId").and_then(Value::as_str).is_some_and(
                                            |id| id.contains(repo) || id.eq_ignore_ascii_case(repo),
                                        ) || sc.get("repositoryId").is_none()
                                    })
                                })
                    })
                    .collect();
                let has_build = repo_policies.iter().any(|p| {
                    p.get("type")
                        .and_then(|t| t.get("displayName"))
                        .and_then(Value::as_str)
                        .is_some_and(|n| n.to_ascii_lowercase().contains("build"))
                });
                let has_review = repo_policies.iter().any(|p| {
                    p.get("type")
                        .and_then(|t| t.get("displayName"))
                        .and_then(Value::as_str)
                        .is_some_and(|n| {
                            let nl = n.to_ascii_lowercase();
                            nl.contains("review")
                                || nl.contains("approver")
                                || nl.contains("minimum")
                        })
                });
                if repo_policies.is_empty() || (!has_build && !has_review) {
                    push_if_severe(
                        findings,
                        settings,
                        finding_rich(
                            ENGINE_ID,
                            &format!("Azure DevOps branch policies weak or absent: {org}/{project}/{repo}"),
                            "high",
                            "T1195.002",
                            &format!(
                                "Live Azure DevOps policy API: {} enabled policies scoped to repo — \
                                 missing required build validation or minimum reviewer gates for pipeline integrity.",
                                repo_policies.len()
                            ),
                            host,
                            0.86,
                            Evidence::new()
                                .with("org", org)
                                .with("project", project)
                                .with("repo", repo)
                                .with("policy_count", repo_policies.len())
                                .with("policy", "WZ-ADO-GOV-001"),
                        ),
                    );
                    posture.workflow_violations += 1;
                }
            }
        }
    }
}

async fn probe_bitbucket_repo_inner(
    client: &Client,
    settings: &Settings,
    host: &str,
    posture: &mut Posture,
    findings: &mut Vec<Value>,
    workspace: &str,
    repo: &str,
) {
    let reff = settings
        .repo_ref
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("main");
    let repo_label = format!("{workspace}/{repo}");
    let mut fetched = 0u32;

    for path in [
        "bitbucket-pipelines.yml",
        ".circleci/config.yml",
        "Jenkinsfile",
    ] {
        if fetched >= settings.max_repo_files {
            break;
        }
        let raw_url = format!(
            "https://api.bitbucket.org/2.0/repositories/{workspace}/{repo}/src/{reff}/{path}"
        );
        let Ok(r) = client
            .get(&raw_url)
            .header("User-Agent", "Weissman-CICD-Security/1.0")
            .send()
            .await
        else {
            continue;
        };
        if !r.status().is_success() {
            continue;
        }
        let Ok(body) = r.text().await else { continue };
        if body.len() < 12 || body.len() > 262_144 {
            continue;
        }
        fetched += 1;
        ingest_repo_ci_file(
            posture,
            findings,
            settings,
            host,
            &repo_label,
            reff,
            path,
            &body,
        );
    }
}

fn emit_posture_summary(
    posture: &Posture,
    host: &str,
    settings: &Settings,
    findings: &mut Vec<Value>,
) {
    if !settings.posture_scoring {
        return;
    }
    let score = posture.exposure_score();
    let graph = build_supply_chain_graph(posture, host);
    let dims = risk_dimensions(posture);
    let grade = if score >= 0.85 {
        "F"
    } else if score >= 0.65 {
        "D"
    } else if score >= 0.45 {
        "C"
    } else if score >= 0.25 {
        "B"
    } else {
        "A"
    };
    let sev = severity_for_score(score);
    findings.push(json!({
        "type": ENGINE_ID,
        "category": "cicd_metrics",
        "title": format!("CI/CD DevSecOps posture: {:.0}/100 (grade {})", score * 100.0, grade),
        "severity": sev,
        "mitre_attack": MITRE,
        "description": format!(
            "Agentless CI/CD posture for {}: platforms={:?}, api_exposed={}, config_leaks={}, \
             workflow_violations={}, secrets={}, secrets_in_configs={}, jenkins_console={}, runner_tokens={}, build_logs={}, \
             artifacts={}, slsa_gaps={}. Grade {} — mapped to {}.",
            host,
            posture.platforms,
            posture.api_exposed,
            posture.config_exposed,
            posture.workflow_violations,
            posture.secrets_in_response,
            posture.secrets_in_configs,
            posture.jenkins_console,
            posture.runner_tokens,
            posture.build_logs_exposed,
            posture.artifact_exposed,
            posture.slsa_gaps,
            grade,
            settings.compliance_frameworks.join(", ")
        ),
        "cicd_metrics": {
            "score": (score * 100.0).round() as u32,
            "grade": grade,
            "platforms": posture.platforms.iter().collect::<Vec<_>>(),
            "api_exposed": posture.api_exposed,
            "config_exposed": posture.config_exposed,
            "workflow_violations": posture.workflow_violations,
            "secrets_in_response": posture.secrets_in_response,
            "secrets_in_configs": posture.secrets_in_configs,
            "jenkins_console": posture.jenkins_console,
            "runner_tokens": posture.runner_tokens,
            "build_logs_exposed": posture.build_logs_exposed,
            "artifact_exposed": posture.artifact_exposed,
            "slsa_gaps": posture.slsa_gaps,
            "policy_hits": posture.policy_hits,
            "risk_dimensions": dims,
            "frameworks": settings.compliance_frameworks,
            "compliance_posture": compliance_posture(&posture.policy_hits, &settings.compliance_frameworks),
            "remediation_playbook": remediation_playbook(posture, &posture.policy_hits),
            "supply_chain_graph": graph,
        },
        "confidence": 0.90
    }));
}

// ── Public entry points ───────────────────────────────────────────────────────

pub async fn run_cicd_pipeline_result(target: &str) -> EngineResult {
    run_cicd_pipeline_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_cicd_pipeline_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let settings = parse_settings(ctx);
    if settings.dry_run {
        let phases = json!([
            {"phase": "platform_fingerprint", "enabled": settings.probe_fingerprint, "platforms": if settings.platform_filter.is_empty() { platforms().len() } else { settings.platform_filter.len() }},
            {"phase": "api_exposure", "enabled": settings.probe_api, "paths": settings.api_paths.len(), "max_requests_budget": settings.max_requests},
            {"phase": "jenkins_script_console", "enabled": settings.probe_jenkins_console},
            {"phase": "config_exposure", "enabled": settings.probe_config, "paths": settings.config_paths.len()},
            {"phase": "build_log_exposure", "enabled": settings.probe_build_logs},
            {"phase": "artifact_registry_exposure", "enabled": settings.probe_artifact_exposure},
            {"phase": "repository_plane", "enabled": settings.probe_repo, "repo_url": settings.repo_url, "max_repo_files": settings.max_repo_files, "vendors": ["github","gitlab","bitbucket","azure_devops"]},
            {"phase": "repo_governance", "enabled": settings.probe_repo_governance},
            {"phase": "workflow_static_analysis", "enabled": settings.probe_workflow_analysis},
            {"phase": "secret_scan_wz_sec_001", "enabled": settings.probe_secret_scan},
            {"phase": "runner_token_surface", "enabled": settings.probe_runner_tokens},
            {"phase": "attack_path_synthesis", "enabled": settings.attack_synth},
            {"phase": "posture_scoring", "enabled": settings.posture_scoring, "frameworks": settings.compliance_frameworks},
        ]);
        return EngineResult::ok(
            vec![json!({
                "type": ENGINE_ID,
                "category": "dry_run",
                "title": "CI/CD security scan plan (dry run)",
                "severity": "info",
                "description": format!(
                    "Dry run — {} probe phases planned for {} with max {} HTTP requests, intensity {}.",
                    phases.as_array().map(|a| a.len()).unwrap_or(0),
                    target.trim(),
                    settings.max_requests,
                    settings.intensity.as_str(),
                ),
                "evidence": {
                    "target": target.trim(),
                    "intensity": settings.intensity.as_str(),
                    "timeout_ms": settings.timeout_ms,
                    "concurrency": settings.concurrency,
                    "max_requests": settings.max_requests,
                    "max_repo_files": settings.max_repo_files,
                    "min_severity": settings.min_sev_rank,
                    "api_paths": settings.api_paths.len(),
                    "config_paths": settings.config_paths.len(),
                    "platform_filter": settings.platform_filter.iter().collect::<Vec<_>>(),
                    "probe_fingerprint": settings.probe_fingerprint,
                    "probe_api": settings.probe_api,
                    "probe_config": settings.probe_config,
                    "probe_repo": settings.probe_repo,
                    "probe_workflow_analysis": settings.probe_workflow_analysis,
                    "probe_runner_tokens": settings.probe_runner_tokens,
                    "probe_jenkins_console": settings.probe_jenkins_console,
                    "probe_build_logs": settings.probe_build_logs,
                    "probe_artifact_exposure": settings.probe_artifact_exposure,
                    "probe_repo_governance": settings.probe_repo_governance,
                    "probe_secret_scan": settings.probe_secret_scan,
                    "attack_path_synthesis": settings.attack_synth,
                    "posture_scoring": settings.posture_scoring,
                    "repo_url": settings.repo_url,
                    "repo_ref": settings.repo_ref,
                    "has_github_token": settings.github_token.is_some(),
                    "has_gitlab_token": settings.gitlab_token.is_some(),
                    "has_azure_devops_pat": settings.azure_devops_pat.is_some(),
                    "compliance_frameworks": settings.compliance_frameworks,
                    "phases": phases,
                }
            })],
            format!("cicd_pipeline: dry-run plan for {}", target.trim()),
        );
    }

    let base = normalize_url(target);
    let host = crate::engine_probes::extract_host(&base);
    let client = build_client(settings.timeout_ms).await;

    let mut posture = Posture::default();
    let mut findings: Vec<Value> = Vec::new();

    probe_platform_fingerprint(
        &client,
        &base,
        &host,
        &settings,
        &mut posture,
        &mut findings,
    )
    .await;
    probe_api_exposure(
        &client,
        &base,
        &host,
        &settings,
        &mut posture,
        &mut findings,
    )
    .await;
    probe_jenkins_script_console(
        &client,
        &base,
        &host,
        &settings,
        &mut posture,
        &mut findings,
    )
    .await;
    probe_config_exposure(
        &client,
        &base,
        &host,
        &settings,
        &mut posture,
        &mut findings,
    )
    .await;
    probe_build_log_exposure(
        &client,
        &base,
        &host,
        &settings,
        &mut posture,
        &mut findings,
    )
    .await;
    probe_artifact_registry_exposure(
        &client,
        &base,
        &host,
        &settings,
        &mut posture,
        &mut findings,
    )
    .await;
    probe_repository_plane(&client, &settings, &host, &mut posture, &mut findings).await;

    if settings.attack_synth {
        for ap in attack_paths(&posture, &host) {
            push_if_severe(&mut findings, &settings, ap);
        }
    }

    emit_posture_summary(&posture, &host, &settings, &mut findings);

    let n = findings
        .iter()
        .filter(|f| {
            f.get("category")
                .and_then(Value::as_str)
                .is_some_and(|c| c != "cicd_metrics" && c != "dry_run")
        })
        .count();

    EngineResult::ok(
        findings,
        format!(
            "cicd_pipeline: {} finding(s) on {} (posture {:.0}/100)",
            n,
            host,
            posture.exposure_score() * 100.0
        ),
    )
}

pub async fn run_cicd_pipeline(target: &str) {
    print_result(run_cicd_pipeline_result_ctx(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_dispatch::EngineRunContext;
    use serde_json::json;

    fn ctx(params: Value) -> EngineRunContext {
        EngineRunContext {
            job_params: params,
            ..Default::default()
        }
    }

    #[test]
    fn settings_defaults() {
        let s = parse_settings(&ctx(json!({})));
        assert!(s.probe_api);
        assert!(s.probe_config);
        assert!(!s.api_paths.is_empty());
    }

    #[test]
    fn pwn_request_detected() {
        let wf = r#"on: pull_request_target
jobs:
  x:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}"#;
        let f = analyze_github_workflow(wf, "ci.yml", "example.com");
        assert!(f.iter().any(|x| x
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("pwn-request")));
    }

    #[test]
    fn posture_jenkins_console_weights_high() {
        let mut p = Posture::default();
        p.jenkins_console = true;
        assert!(p.exposure_score() >= 0.2);
    }

    #[test]
    fn parse_github_repo_url() {
        let (o, r) = parse_github_repo("https://github.com/acme/widget").unwrap();
        assert_eq!(o, "acme");
        assert_eq!(r, "widget");
    }

    #[test]
    fn azure_pr_injection_detected() {
        let wf = r#"trigger:
  - main
pr:
  - main
pool:
  vmImage: ubuntu-latest
steps:
  - script: echo "${{ github.event.pull_request.title }}"
"#;
        let f = analyze_azure_pipelines(wf, "azure-pipelines.yml", "example.com");
        assert!(f.iter().any(|x| {
            x.get("title")
                .and_then(Value::as_str)
                .unwrap_or("")
                .contains("injection")
        }));
    }

    #[test]
    fn slsa_gap_on_release_without_provenance() {
        let wf = r#"on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish"#;
        let f = analyze_github_workflow(wf, "release.yml", "example.com");
        assert!(f.iter().any(|x| x
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("SLSA")));
    }

    #[test]
    fn dependency_confusion_npm_registry() {
        let wf = r#"jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: npm install --registry https://evil.example.com pkg"#;
        let f = analyze_github_workflow(wf, "ci.yml", "example.com");
        assert!(f.iter().any(|x| x
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("dependency")));
    }

    #[test]
    fn parse_gitlab_repo_target() {
        let t = parse_repo_target("https://gitlab.com/acme/widgets").unwrap();
        match t {
            RepoTarget::GitLab { project_path, .. } => assert_eq!(project_path, "acme/widgets"),
            _ => panic!("expected gitlab"),
        }
    }

    #[test]
    fn argocd_http_repo_detected() {
        let y = r#"apiVersion: argoproj.io/v1alpha1
kind: Application
spec:
  source:
    repoURL: http://git.internal/app
  syncPolicy:
    automated: {}"#;
        let f = analyze_argocd_manifest(y, "app.yaml", "example.com");
        assert!(f.iter().any(|x| x
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("HTTP")));
    }

    #[test]
    fn tekton_privileged_detected() {
        let y = r#"apiVersion: tekton.dev/v1
kind: Task
spec:
  steps:
    - securityContext:
        privileged: true"#;
        let f = analyze_tekton_manifest(y, "task.yaml", "example.com");
        assert!(f.iter().any(|x| x
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("privileged")));
    }

    #[test]
    fn parse_azure_devops_repo_target() {
        let t = parse_repo_target("https://dev.azure.com/contoso/widgets/_git/pipeline").unwrap();
        match t {
            RepoTarget::AzureDevOps { org, project, repo } => {
                assert_eq!(org, "contoso");
                assert_eq!(project, "widgets");
                assert_eq!(repo, "pipeline");
            }
            _ => panic!("expected azure devops"),
        }
    }

    #[test]
    fn compliance_posture_scores_frameworks() {
        let mut hits = BTreeMap::new();
        hits.insert("WZ-GHA-001".to_string(), 2);
        let cp = compliance_posture(&hits, &["SOC2-CC8.1".to_string()]);
        assert!(cp.get("SOC2-CC8.1").is_some());
    }

    #[test]
    fn remediation_playbook_jenkins_console() {
        let mut p = Posture::default();
        p.jenkins_console = true;
        let rb = remediation_playbook(&p, &BTreeMap::new());
        assert!(rb
            .get("actions")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty()));
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_cicd_pipeline_result_ctx("", &EngineRunContext::default()).await;
        assert!(!r.success);
    }

    #[tokio::test]
    async fn dry_run_ok() {
        let r = run_cicd_pipeline_result_ctx("https://example.com", &ctx(json!({"dry_run": true})))
            .await;
        assert!(r.success);
    }
}
