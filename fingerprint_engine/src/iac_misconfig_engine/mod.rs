//! IaC Security engine — a world-class, fully deterministic Infrastructure-as-Code static analyzer
//! (Wiz / Checkov / tfsec / KICS class) plus a remote leak prober.
//!
//! It enforces a large multi-framework policy library — Terraform (HCL), Kubernetes, Dockerfile,
//! CloudFormation/SAM, docker-compose, GitHub Actions, Azure ARM — and a cross-framework secret
//! scanner, mapping every finding to MITRE ATT&CK, CWE and compliance packs (CIS, PCI-DSS, HIPAA,
//! NIST 800-53, SOC2, ISO 27001, FedRAMP) and a master auditor compliance packet. Nothing is fabricated: a finding is only emitted when an analyzer
//! observes a real violating value in the supplied IaC, or a real file is reachable over HTTP.
//!
//! Three scan modes, all driven from `EngineRunContext::job_params` (POST /api/command-center/scan):
//!   * `static`   — analyze inline IaC content pasted/typed by the operator (no network; fully real).
//!   * `repo`     — fetch a git (GitHub) repository tree and analyze every IaC artifact in it.
//!   * `exposure` — probe the target host for publicly reachable IaC files (state, .env, …) and
//!                  deep-analyze whatever it can fetch.

pub mod ansible;
pub mod argo_rollouts;
pub mod argocd;
pub mod arm;
pub mod attack_chains;
pub mod audit_packet;
pub mod backstage;
pub mod bicep;
pub mod cdk;
pub mod cert_manager;
pub mod ci_platform;
pub mod cloudformation;
pub mod compliance_playbooks;
pub mod compose;
pub mod cross_correlation;
pub mod crossplane;
pub mod cue;
pub mod detect;
pub mod dockerfile;
pub mod drift_hints;
pub mod envoy_gateway;
pub mod external_secrets;
pub mod falco;
pub mod fedramp_report;
pub mod fix_bundles;
pub mod flux;
pub mod gate_evidence;
pub mod gate_profiles;
pub mod gateway_api;
pub mod github_actions;
pub mod helm;
pub mod helmfile;
pub mod hipaa_report;
pub mod iso27001_report;
pub mod istio;
pub mod keda;
pub mod kubernetes;
pub mod kustomize;
pub mod kyverno;
pub mod linkerd;
pub mod live_blast;
pub mod mitre;
pub mod model;
pub mod nginx;
pub mod nist_report;
pub mod opa;
pub mod openapi;
pub mod packer;
pub mod pci_report;
pub mod plan_reconcile;
pub mod policies;
pub mod posture;
pub mod prometheus_operator;
pub mod pulumi;
pub mod resource_graph;
pub mod sealed_secrets;
pub mod secrets;
pub mod serverless;
pub mod skaffold;
pub mod soc_report;
pub mod sops;
pub mod supply_chain;
pub mod tekton;
pub mod terraform;
pub mod terragrunt;
pub mod tfplan;
pub mod vault_hcl;
pub mod velero;
pub mod waivers;

use crate::engine_dispatch::EngineRunContext;
use crate::engine_result::{print_result, EngineResult};
use model::{Finding, Framework, IacFile, Severity};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

// ──────────────────────────────────────────────────────────────────────────────
// job_params accessors (top-level or nested under `options: { … }`)
// ──────────────────────────────────────────────────────────────────────────────

fn jp<'a>(p: &'a Value, key: &str) -> Option<&'a Value> {
    p.get(key)
        .or_else(|| p.get("options").and_then(|o| o.get(key)))
}
fn jp_str(p: &Value, key: &str) -> Option<String> {
    jp(p, key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
fn jp_bool(p: &Value, key: &str, default: bool) -> bool {
    match jp(p, key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Some(Value::Number(n)) => n.as_i64().map(|x| x != 0).unwrap_or(default),
        _ => default,
    }
}
fn jp_u64(p: &Value, key: &str, default: u64) -> u64 {
    match jp(p, key) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(default),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(default),
        _ => default,
    }
}
fn jp_list(p: &Value, key: &str) -> Vec<String> {
    match jp(p, key) {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        Some(Value::String(s)) => s
            .split(['\n', ','])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Config
// ──────────────────────────────────────────────────────────────────────────────

struct Cfg {
    modes: Vec<String>,
    inline_content: Option<String>,
    inline_filename: String,
    forced: Option<Framework>,
    repo_url: Option<String>,
    repo_ref: Option<String>,
    repo_subdir: String,
    max_files: usize,
    frameworks_filter: Option<HashSet<String>>,
    providers_filter: Option<HashSet<String>>,
    compliance_packs: HashSet<String>,
    min_severity: Severity,
    fail_severity: Severity,
    secret_scan: bool,
    skip_policies: HashSet<String>,
    only_policies: Option<HashSet<String>>,
    extra_exposure_paths: Vec<String>,
    timeout_ms: u64,
    verify_tls: bool,
    dedupe: bool,
    attack_path_synthesis: bool,
    cross_file_correlation: bool,
    include_policy_catalog: bool,
    gate_profile: Option<String>,
    asset_tier: String,
    resource_graph: bool,
    drift_analysis: bool,
    live_blast: bool,
}

impl Cfg {
    fn from_params(p: &Value, target: &str) -> Self {
        let inline_content = jp_str(p, "iac_content");
        let repo_url = jp_str(p, "repo_url");
        let mut modes = jp_list(p, "scan_modes");
        if modes.is_empty() {
            if inline_content.is_some() {
                modes.push("static".to_string());
            } else if repo_url.is_some() {
                modes.push("repo".to_string());
            } else if !target.trim().is_empty() {
                modes.push("exposure".to_string());
            }
        }
        let frameworks_filter = {
            let l = jp_list(p, "frameworks");
            if l.is_empty() {
                None
            } else {
                Some(
                    l.iter()
                        .filter_map(|s| Framework::parse(s).map(|f| f.as_str().to_string()))
                        .collect(),
                )
            }
        };
        let providers_filter = {
            let l = jp_list(p, "providers");
            if l.is_empty() {
                None
            } else {
                Some(l.iter().map(|s| s.to_ascii_lowercase()).collect())
            }
        };
        let compliance_packs = {
            let l = jp_list(p, "compliance_packs");
            if l.is_empty() {
                policies::KNOWN_PACKS
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                l.iter().map(|s| s.to_ascii_uppercase()).collect()
            }
        };
        let only = jp_list(p, "only_policies");
        Cfg {
            modes,
            inline_content,
            inline_filename: jp_str(p, "iac_filename").unwrap_or_else(|| "input.tf".to_string()),
            forced: jp_str(p, "iac_type").and_then(|s| Framework::parse(&s)),
            repo_url,
            repo_ref: jp_str(p, "repo_ref"),
            repo_subdir: jp_str(p, "repo_subdir").unwrap_or_default(),
            max_files: usize::try_from(jp_u64(p, "max_files", 300).clamp(1, 2000)).unwrap_or(300),
            frameworks_filter,
            providers_filter,
            compliance_packs,
            min_severity: jp_str(p, "min_severity")
                .and_then(|s| Severity::parse(&s))
                .unwrap_or(Severity::Info),
            fail_severity: jp_str(p, "fail_severity")
                .and_then(|s| Severity::parse(&s))
                .unwrap_or(Severity::High),
            secret_scan: jp_bool(p, "secret_scan", true),
            skip_policies: jp_list(p, "skip_policies").into_iter().collect(),
            only_policies: if only.is_empty() {
                None
            } else {
                Some(only.into_iter().collect())
            },
            extra_exposure_paths: jp_list(p, "exposure_paths"),
            timeout_ms: jp_u64(p, "timeout_ms", 8000).clamp(500, 30_000),
            verify_tls: jp_bool(p, "verify_tls", true),
            dedupe: jp_bool(p, "dedupe", true),
            attack_path_synthesis: jp_bool(p, "attack_path_synthesis", true),
            cross_file_correlation: jp_bool(p, "cross_file_correlation", true),
            include_policy_catalog: jp_bool(p, "include_policy_catalog", true),
            gate_profile: jp_str(p, "gate_profile"),
            asset_tier: jp_str(p, "asset_tier").unwrap_or_else(|| "tier3".to_string()),
            resource_graph: jp_bool(p, "resource_graph", true),
            drift_analysis: jp_bool(p, "drift_analysis", true),
            live_blast: jp_bool(
                p,
                "live_blast",
                jp_bool(p, "live_cloud_reconcile", false)
                    || jp_str(p, "aws_cross_account_role_arn").is_some()
                    || (jp_str(p, "k8s_api_server").is_some() && jp_str(p, "k8s_token").is_some()),
            ),
        }
    }

    fn live_blast_config(p: &Value, github_token: Option<String>) -> live_blast::LiveBlastConfig {
        let repo = jp_str(p, "git_repo_url")
            .or_else(|| jp_str(p, "repo_url"))
            .unwrap_or_default();
        live_blast::LiveBlastConfig {
            enabled: live_blast::live_aws_runtime_enabled()
                && jp_bool(
                    p,
                    "live_blast",
                    jp_bool(p, "live_cloud_reconcile", false)
                        || jp_str(p, "aws_cross_account_role_arn").is_some()
                        || (jp_str(p, "k8s_api_server").is_some()
                            && jp_str(p, "k8s_token").is_some()),
                ),
            aws_role_arn: jp_str(p, "aws_cross_account_role_arn").unwrap_or_default(),
            aws_external_id: jp_str(p, "aws_external_id").unwrap_or_default(),
            aws_regions: jp_list(p, "aws_regions"),
            k8s_api_server: jp_str(p, "k8s_api_server").unwrap_or_default(),
            k8s_token: jp_str(p, "k8s_token")
                .or_else(|| jp_str(p, "k8s_bearer_token"))
                .unwrap_or_default(),
            k8s_namespace: jp_str(p, "k8s_namespace").unwrap_or_else(|| "default".to_string()),
            verify_tls: jp_bool(p, "verify_tls", true),
            timeout_ms: jp_u64(p, "timeout_ms", 8000).clamp(500, 30_000),
            iam_simulate: jp_bool(p, "iam_simulate", jp_bool(p, "live_blast", false)),
            k8s_rbac_prove: jp_bool(p, "k8s_rbac_prove", jp_bool(p, "live_blast", false)),
            autopilot: jp_bool(p, "autopilot", false),
            autopilot_create_pr: jp_bool(p, "autopilot_create_pr", false),
            git_repo_url: repo,
            git_base_branch: jp_str(p, "git_base_branch").unwrap_or_else(|| "main".to_string()),
            github_token: jp_str(p, "github_token")
                .or(github_token)
                .unwrap_or_default(),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// Full engine entry point with operator parameters from the scan request body. This is the
/// signature `engine_dispatch` calls (`run_iac_misconfig_result(target, ctx)`).
pub async fn run_iac_misconfig_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let mut job_params = ctx.job_params.clone();
    if let Some(gp) = jp_str(&job_params, "gate_profile") {
        gate_profiles::apply_profile(&mut job_params, &gp);
    }
    let cfg = Cfg::from_params(&job_params, target);
    if cfg.modes.is_empty() {
        return EngineResult::error("IaC Security: provide inline iac_content, a repo_url, or a target host for exposure scanning");
    }

    let mut files: Vec<IacFile> = Vec::new();
    let mut sources: Vec<String> = Vec::new();
    let mut exposure_findings: Vec<Finding> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // ── static (inline) ──
    if cfg.modes.iter().any(|m| m == "static") {
        files.extend(collect_inline_files(&cfg, &job_params));
        if let Some(content) = &cfg.inline_content {
            if !files.iter().any(|f| f.name == cfg.inline_filename) {
                files.push(IacFile {
                    name: cfg.inline_filename.clone(),
                    content: content.clone(),
                    forced: cfg.forced,
                    origin: "inline".to_string(),
                });
                sources.push(format!("inline:{}", cfg.inline_filename));
            }
        } else if !files.is_empty() {
            for f in &files {
                sources.push(format!("inline:{}", f.name));
            }
        }
    }

    // ── repo ──
    if cfg.modes.iter().any(|m| m == "repo") {
        if let Some(url) = &cfg.repo_url {
            match fetch_repo_files(url, &cfg, ctx).await {
                Ok(mut fs) => {
                    sources.push(format!("repo:{} ({} files)", url, fs.len()));
                    files.append(&mut fs);
                }
                Err(e) => notes.push(format!("repo fetch failed: {}", e)),
            }
        }
    }

    // ── exposure ──
    if cfg.modes.iter().any(|m| m == "exposure") && !target.trim().is_empty() {
        let (exp, mut fetched, note) = exposure_scan(target, &cfg).await;
        exposure_findings = exp;
        if let Some(n) = note {
            notes.push(n);
        }
        sources.push(format!("exposure:{}", target));
        files.append(&mut fetched);
    }

    // ── analyze every gathered file ──
    let mut frameworks_seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut findings: Vec<Finding> = exposure_findings;
    for f in &files {
        let (fw, mut fs) = analyze_file(f, cfg.secret_scan);
        *frameworks_seen.entry(fw.as_str().to_string()).or_insert(0) += 1;
        findings.append(&mut fs);
    }

    if cfg.cross_file_correlation && files.len() >= 2 {
        findings.extend(cross_correlation::correlate(&files, &findings));
        findings.extend(supply_chain::analyze(&files, &findings));
    }
    if cfg.resource_graph && files.len() >= 2 {
        findings.extend(resource_graph::analyze(&files));
    }
    if cfg.drift_analysis && files.len() >= 2 {
        findings.extend(drift_hints::analyze(&files));
    }
    if let Some(plan) =
        jp_str(&job_params, "terraform_plan_json").or_else(|| jp_str(&job_params, "tf_plan_json"))
    {
        let plan_findings = tfplan::evaluate_plan(&plan);
        findings.extend(plan_findings.iter().cloned());
        sources.push("tfplan:operator-supplied".to_string());
        let static_tf: Vec<Finding> = findings
            .iter()
            .filter(|f| f.policy.framework == "terraform")
            .cloned()
            .collect();
        findings.extend(plan_reconcile::reconcile(&static_tf, &plan_findings));
    }

    let waivers = waivers::parse(&job_params);

    let base_risk_pre_live: u64 = findings
        .iter()
        .map(|f| u64::from(f.policy.severity.weight()))
        .sum::<u64>()
        .min(100);

    let live_blast_result = if cfg.live_blast && !files.is_empty() {
        let lb_cfg = Cfg::live_blast_config(&job_params, ctx.github_token.clone());
        let result = live_blast::analyze(&files, &lb_cfg, base_risk_pre_live).await;
        notes.extend(result.notes.clone());
        Some(result)
    } else {
        None
    };

    if let Some(ref lb) = live_blast_result {
        findings.extend(lb.findings.clone());
    }

    let (mut findings, waived) = waivers::apply(findings, &waivers);

    // ── filter ──
    findings.retain(|f| keep(f, &cfg));
    if cfg.dedupe {
        let mut seen = HashSet::new();
        findings.retain(|f| {
            seen.insert(format!(
                "{}|{}|{}|{}",
                f.policy.id, f.file, f.line, f.resource
            ))
        });
    }
    findings.sort_by(|a, b| b.policy.severity.cmp(&a.policy.severity));

    let base_risk: u64 = findings
        .iter()
        .filter(|f| !f.policy.id.starts_with("WZ-LIVE"))
        .map(|f| u64::from(f.policy.severity.weight()))
        .sum::<u64>()
        .min(100);

    let chains = if cfg.attack_path_synthesis {
        attack_chains::synthesize(&findings)
    } else {
        Vec::new()
    };
    let blast = attack_chains::blast_radius_multiplier(&chains);

    // ── assemble JSON ──
    let mut out: Vec<Value> = Vec::with_capacity(findings.len() + chains.len() + 1);
    let summary = build_summary(
        target,
        &cfg,
        &files,
        &frameworks_seen,
        &findings,
        &chains,
        blast,
        &sources,
        &notes,
        &waived,
        live_blast_result.as_ref(),
    );
    out.push(summary.clone());
    for f in &findings {
        out.push(f.to_json(target));
    }
    for c in &chains {
        out.push(attack_chains::chain_to_finding(c, target));
    }

    let s = &summary["iac_summary"];
    let chain_n = chains.len();
    let msg = format!(
        "IaC Security: {} findings across {} files [{} critical, {} high, {} medium]{} — risk {}/100 (grade {}), gate {}",
        findings.len(),
        files.len(),
        s["by_severity"]["critical"].as_u64().unwrap_or(0),
        s["by_severity"]["high"].as_u64().unwrap_or(0),
        s["by_severity"]["medium"].as_u64().unwrap_or(0),
        if chain_n > 0 { format!(", {chain_n} attack paths") } else { String::new() },
        s["risk_score"].as_u64().unwrap_or(0),
        s["grade"].as_str().unwrap_or("?"),
        if s["gate"]["passed"].as_bool().unwrap_or(true) { "PASS" } else { "FAIL" },
    );
    EngineResult::ok(out, msg)
}

/// Back-compat entry point (target-only) for callers that do not thread a context (supply-chain
/// alias, CLI). Runs the remote-exposure probe + deep analysis with default options.
pub async fn run_iac_misconfig_result_default(target: &str) -> EngineResult {
    run_iac_misconfig_result(target, &EngineRunContext::default()).await
}

/// CLI helper.
pub async fn run_iac_misconfig(target: &str) {
    print_result(run_iac_misconfig_result_default(target).await);
}

// ──────────────────────────────────────────────────────────────────────────────
// Analysis driver + filtering
// ──────────────────────────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────────────────────────
// Inline / multi-file static collection
// ──────────────────────────────────────────────────────────────────────────────

fn collect_inline_files(cfg: &Cfg, params: &Value) -> Vec<IacFile> {
    let mut out = Vec::new();
    let raw = jp(params, "iac_files");
    let Some(Value::Array(arr)) = raw else {
        return out;
    };
    for item in arr {
        let (name, content, forced) = match item {
            Value::Object(obj) => {
                let name = obj
                    .get("name")
                    .or_else(|| obj.get("filename"))
                    .and_then(Value::as_str)
                    .unwrap_or("input.tf")
                    .trim()
                    .to_string();
                let content = obj
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if content.is_empty() {
                    continue;
                }
                let forced = obj
                    .get("type")
                    .or_else(|| obj.get("iac_type"))
                    .and_then(Value::as_str)
                    .and_then(Framework::parse);
                (name, content, forced)
            }
            Value::String(s) if !s.trim().is_empty() => continue,
            _ => continue,
        };
        out.push(IacFile {
            name,
            content,
            forced,
            origin: "inline".to_string(),
        });
    }
    let _ = cfg; // reserved for future per-file limits
    out
}

fn analyze_file(file: &IacFile, secret_scan: bool) -> (Framework, Vec<Finding>) {
    let fw = detect::detect(&file.name, &file.content, file.forced);
    let mut findings = match fw {
        Framework::Terraform => terraform::evaluate(&file.name, &file.content),
        Framework::Kubernetes => kubernetes::evaluate(&file.name, &file.content),
        Framework::Dockerfile => dockerfile::evaluate(&file.name, &file.content),
        Framework::CloudFormation => cloudformation::evaluate(&file.name, &file.content),
        Framework::DockerCompose => compose::evaluate(&file.name, &file.content),
        Framework::GithubActions => github_actions::evaluate(&file.name, &file.content),
        Framework::Arm => arm::evaluate(&file.name, &file.content),
        Framework::Helm => helm::evaluate(&file.name, &file.content),
        Framework::OpenApi => openapi::evaluate(&file.name, &file.content),
        Framework::Serverless => serverless::evaluate(&file.name, &file.content),
        Framework::Kustomize => kustomize::evaluate(&file.name, &file.content),
        Framework::Bicep => bicep::evaluate(&file.name, &file.content),
        Framework::Pulumi => pulumi::evaluate(&file.name, &file.content),
        Framework::Cdk => cdk::evaluate(&file.name, &file.content),
        Framework::Ansible => ansible::evaluate(&file.name, &file.content),
        Framework::Nginx => nginx::evaluate(&file.name, &file.content),
        Framework::Crossplane => crossplane::evaluate(&file.name, &file.content),
        Framework::Terragrunt => terragrunt::evaluate(&file.name, &file.content),
        Framework::ArgoCd => argocd::evaluate(&file.name, &file.content),
        Framework::Flux => flux::evaluate(&file.name, &file.content),
        Framework::Opa => opa::evaluate(&file.name, &file.content),
        Framework::Vault => vault_hcl::evaluate(&file.name, &file.content),
        Framework::Istio => istio::evaluate(&file.name, &file.content),
        Framework::Kyverno => kyverno::evaluate(&file.name, &file.content),
        Framework::Sops => sops::evaluate(&file.name, &file.content),
        Framework::Cue => cue::evaluate(&file.name, &file.content),
        Framework::CiPlatform => ci_platform::evaluate(&file.name, &file.content),
        Framework::Linkerd => linkerd::evaluate(&file.name, &file.content),
        Framework::Packer => packer::evaluate(&file.name, &file.content),
        Framework::Helmfile => helmfile::evaluate(&file.name, &file.content),
        Framework::CertManager => cert_manager::evaluate(&file.name, &file.content),
        Framework::ExternalSecrets => external_secrets::evaluate(&file.name, &file.content),
        Framework::GatewayApi => gateway_api::evaluate(&file.name, &file.content),
        Framework::Skaffold => skaffold::evaluate(&file.name, &file.content),
        Framework::Velero => velero::evaluate(&file.name, &file.content),
        Framework::Keda => keda::evaluate(&file.name, &file.content),
        Framework::Tekton => tekton::evaluate(&file.name, &file.content),
        Framework::Falco => falco::evaluate(&file.name, &file.content),
        Framework::Backstage => backstage::evaluate(&file.name, &file.content),
        Framework::EnvoyGateway => envoy_gateway::evaluate(&file.name, &file.content),
        Framework::SealedSecrets => sealed_secrets::evaluate(&file.name, &file.content),
        Framework::PrometheusOperator => prometheus_operator::evaluate(&file.name, &file.content),
        Framework::ArgoRollouts => argo_rollouts::evaluate(&file.name, &file.content),
        Framework::Unknown => {
            // Secondary sniff: Pulumi/CDK TypeScript/Python in repo scans.
            let mut extra = pulumi::evaluate(&file.name, &file.content);
            if extra.is_empty() {
                extra = cdk::evaluate(&file.name, &file.content);
            }
            extra
        }
    };
    if secret_scan {
        findings.extend(secrets::evaluate(&file.name, &file.content));
    }
    (fw, findings)
}

fn keep(f: &Finding, cfg: &Cfg) -> bool {
    if f.policy.severity < cfg.min_severity {
        return false;
    }
    if let Some(only) = &cfg.only_policies {
        if !only.contains(f.policy.id) {
            return false;
        }
    }
    if cfg.skip_policies.contains(f.policy.id) {
        return false;
    }
    // framework filter never drops secret/exposure findings (they are cross-cutting)
    if let Some(fw) = &cfg.frameworks_filter {
        let cross = f.policy.framework == "secrets"
            || f.policy.framework == "exposure"
            || f.policy.framework == "correlation"
            || f.policy.framework == "graph"
            || f.policy.framework == "drift"
            || f.policy.framework == "tfplan"
            || f.policy.framework == "reconcile"
            || f.policy.framework == "supply_chain"
            || f.policy.framework == "live_blast";
        if !cross && !fw.contains(f.policy.framework) {
            return false;
        }
    }
    if let Some(pr) = &cfg.providers_filter {
        if f.policy.provider != "generic" && !pr.contains(f.policy.provider) {
            return false;
        }
    }
    true
}

// ──────────────────────────────────────────────────────────────────────────────
// Summary, scoring and compliance posture
// ──────────────────────────────────────────────────────────────────────────────

fn grade(score: u64) -> &'static str {
    match score {
        0..=9 => "A",
        10..=24 => "B",
        25..=49 => "C",
        50..=74 => "D",
        _ => "F",
    }
}

#[allow(clippy::too_many_arguments)]
fn build_summary(
    target: &str,
    cfg: &Cfg,
    files: &[IacFile],
    frameworks_seen: &BTreeMap<String, usize>,
    findings: &[Finding],
    chains: &[attack_chains::SynthesizedChain],
    blast: f64,
    sources: &[String],
    notes: &[String],
    waived: &[Value],
    live_blast: Option<&live_blast::LiveBlastResult>,
) -> Value {
    let (mut crit, mut high, mut med, mut low, mut info) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut by_framework: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_provider: BTreeMap<String, u64> = BTreeMap::new();
    let mut triggered: HashSet<&str> = HashSet::new();
    // pack -> set of failed controls
    let mut pack_controls: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    let mut pack_findings: BTreeMap<String, u64> = BTreeMap::new();

    for f in findings {
        match f.policy.severity {
            Severity::Critical => crit += 1,
            Severity::High => high += 1,
            Severity::Medium => med += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
        *by_framework
            .entry(f.policy.framework.to_string())
            .or_insert(0) += 1;
        *by_provider
            .entry(f.policy.provider.to_string())
            .or_insert(0) += 1;
        triggered.insert(f.policy.id);
        for tag in f.policy.compliance {
            let pack = policies::pack_of(tag);
            if cfg.compliance_packs.contains(pack) {
                pack_controls
                    .entry(pack.to_string())
                    .or_default()
                    .insert((*tag).to_string());
                *pack_findings.entry(pack.to_string()).or_insert(0) += 1;
            }
        }
    }

    let tier_mult = gate_profiles::asset_tier_multiplier(&cfg.asset_tier);
    let base_risk = (crit * 25 + high * 10 + med * 4 + low).min(100);
    let static_risk = ((base_risk as f64) * blast * tier_mult).round().min(100.0) as u64;
    let (risk_score, real_live_risk_score, live_blast_json) = if let Some(lb) = live_blast {
        let live_score = ((lb.real_live_risk_score as f64) * blast * tier_mult)
            .round()
            .min(100.0) as u64;
        let final_score = static_risk.max(live_score);
        (
            final_score,
            Some(live_score),
            Some(lb.summary_json(base_risk)),
        )
    } else {
        (static_risk, None, None)
    };
    let gate_blocking = findings
        .iter()
        .filter(|f| f.policy.severity >= cfg.fail_severity)
        .count() as u64
        + chains
            .iter()
            .filter(|c| c.severity() >= cfg.fail_severity)
            .count() as u64;

    // compliance coverage of the whole catalog (how many controls per pack the engine can assess)
    let catalog = policies::all_policies();
    let mut catalog_pack_controls: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for p in &catalog {
        for tag in p.compliance {
            catalog_pack_controls
                .entry(policies::pack_of(tag).to_string())
                .or_default()
                .insert((*tag).to_string());
        }
    }

    let compliance: Vec<Value> = policies::KNOWN_PACKS
        .iter()
        .filter(|p| cfg.compliance_packs.contains(**p))
        .map(|pack| {
            let failed: HashSet<String> = pack_controls.get(*pack).cloned().unwrap_or_default();
            let mut failed_sorted: Vec<String> = failed.iter().cloned().collect();
            failed_sorted.sort();
            let covered = catalog_pack_controls
                .get(*pack)
                .map(HashSet::len)
                .unwrap_or(0);
            json!({
                "pack": pack,
                "controls_covered": covered,
                "controls_failed": failed_sorted.len(),
                "failed_findings": pack_findings.get(*pack).copied().unwrap_or(0),
                "failed_controls": failed_sorted,
                "status": if failed_sorted.is_empty() { "pass" } else { "fail" },
            })
        })
        .collect();

    let frameworks: Value = frameworks_seen
        .iter()
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect::<serde_json::Map<_, _>>()
        .into();
    let exploit = posture::exploitability_index(findings, chains);
    let remediation = posture::remediation_queue(findings, chains);
    let coverage = posture::framework_coverage(&triggered);
    let catalog_json = if cfg.include_policy_catalog {
        json!(posture::policy_catalog(&triggered))
    } else {
        Value::Null
    };
    let mitre = mitre::mitre_rollup(findings, chains);
    let executive = mitre::executive_summary(
        findings,
        chains,
        exploit,
        grade(risk_score),
        gate_blocking == 0,
    );
    let gate_evidence = gate_evidence::build(
        target,
        findings,
        chains,
        cfg.fail_severity,
        gate_blocking == 0,
        cfg.gate_profile.as_deref().unwrap_or("default"),
        waived,
        live_blast_json.as_ref(),
    );
    let fix_bundle = fix_bundles::export_bundle(findings, target, Some(&gate_evidence));
    let attack_mermaid = attack_chains::mermaid_graph(chains);
    let cis_scorecard = posture::cis_scorecard(&compliance);
    let drift_count = findings
        .iter()
        .filter(|f| f.policy.framework == "drift")
        .count() as u64;
    let reconcile_count = findings
        .iter()
        .filter(|f| f.policy.framework == "reconcile")
        .count() as u64;
    let supply_chain_count = findings
        .iter()
        .filter(|f| f.policy.framework == "supply_chain")
        .count() as u64;
    let fix_count = fix_bundle
        .get("fix_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let readiness = posture::readiness_report(
        findings,
        chains,
        exploit,
        fix_count,
        drift_count,
        waived.len() as u64,
    );
    let risk_heatmap = posture::risk_heatmap(findings);
    let playbooks = compliance_playbooks::build(findings, &compliance);
    let soc2_report = soc_report::build(findings, &compliance);
    let pci_report = pci_report::build(findings, &compliance);
    let hipaa_report = hipaa_report::build(findings, &compliance);
    let nist_report = nist_report::build(findings, &compliance);
    let iso27001_report = iso27001_report::build(findings, &compliance);
    let fedramp_report = fedramp_report::build(findings, &compliance, &nist_report);
    let audit_packet = audit_packet::build(
        target,
        findings,
        chains,
        gate_blocking == 0,
        cfg.gate_profile.as_deref().unwrap_or("default"),
        &readiness,
        &cis_scorecard,
        &compliance,
        &soc2_report,
        &pci_report,
        &hipaa_report,
        &nist_report,
        &iso27001_report,
        &fedramp_report,
        &gate_evidence,
        &remediation,
        &playbooks,
        live_blast_json.as_ref(),
        real_live_risk_score,
    );

    let iac_summary = json!({
        "files_scanned": files.len(),
        "frameworks_detected": frameworks,
        "findings_total": findings.len(),
        "by_severity": { "critical": crit, "high": high, "medium": med, "low": low, "info": info },
        "by_framework": by_framework,
        "by_provider": by_provider,
        "policies_available": catalog.len(),
        "policies_triggered": triggered.len(),
        "risk_score": risk_score,
        "static_risk_score": static_risk,
        "real_live_risk_score": real_live_risk_score,
        "base_risk_score": base_risk,
        "live_blast": live_blast_json,
        "blast_radius_multiplier": blast,
        "asset_tier": cfg.asset_tier,
        "asset_tier_multiplier": tier_mult,
        "gate_profile": cfg.gate_profile,
        "grade": grade(risk_score),
        "gate": {
            "fail_severity": cfg.fail_severity.as_str(),
            "blocking_findings": gate_blocking,
            "passed": gate_blocking == 0,
        },
        "attack_path_synthesis": cfg.attack_path_synthesis,
        "cross_file_correlation": cfg.cross_file_correlation,
        "drift_analysis": cfg.drift_analysis,
        "attack_chains": chains.iter().map(attack_chains::SynthesizedChain::summary_json).collect::<Vec<_>>(),
        "attack_path_mermaid": attack_mermaid,
        "policy_waivers_applied": waived,
        "waived_findings": waived.len(),
        "drift_findings": drift_count,
        "plan_reconcile_findings": reconcile_count,
        "supply_chain_findings": supply_chain_count,
        "exploitability_index": exploit,
        "readiness": readiness,
        "cis_scorecard": cis_scorecard,
        "risk_heatmap": risk_heatmap,
        "compliance_playbooks": playbooks,
        "soc2_report": soc2_report,
        "pci_report": pci_report,
        "hipaa_report": hipaa_report,
        "nist_report": nist_report,
        "iso27001_report": iso27001_report,
        "fedramp_report": fedramp_report,
        "audit_packet": audit_packet,
        "gate_evidence": gate_evidence,
        "remediation_queue": remediation,
        "framework_coverage": coverage,
        "policy_catalog": catalog_json,
        "mitre_rollup": mitre,
        "executive_summary": executive,
        "fix_bundle": fix_bundle,
        "compliance": compliance,
        "scan_modes": cfg.modes,
        "sources": sources,
        "secret_scan": cfg.secret_scan,
        "notes": notes,
        "engine": "weissman-iac-security",
    });

    json!({
        "type": "iac_misconfig",
        "engine_id": "iac_misconfig",
        "category": "iac_summary",
        "title": "IaC Security Posture",
        "severity": "info",
        "target": target,
        "iac_summary": iac_summary,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// HTTP client
// ──────────────────────────────────────────────────────────────────────────────

fn client(cfg: &Cfg) -> reqwest::Client {
    let accept_invalid =
        !cfg.verify_tls || weissman_core::tls_policy::danger_accept_invalid_certs();
    reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms))
        .danger_accept_invalid_certs(accept_invalid)
        .user_agent("Weissman-IaC-Security/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

// ──────────────────────────────────────────────────────────────────────────────
// Exposure (remote leak) scanning
// ──────────────────────────────────────────────────────────────────────────────

fn normalize_base(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

struct ExpPath {
    path: &'static str,
    policy: model::PolicyMeta,
    indicators: &'static [&'static str],
}

fn exposure_paths() -> Vec<ExpPath> {
    use policies::*;
    vec![
        ExpPath {
            path: "/terraform.tfstate",
            policy: EXPOSED_TFSTATE,
            indicators: &["terraform_version", "\"resources\"", "\"outputs\""],
        },
        ExpPath {
            path: "/.terraform/terraform.tfstate",
            policy: EXPOSED_TFSTATE,
            indicators: &["terraform_version", "\"resources\""],
        },
        ExpPath {
            path: "/terraform.tfstate.backup",
            policy: EXPOSED_TFSTATE,
            indicators: &["terraform_version", "\"resources\""],
        },
        ExpPath {
            path: "/.env",
            policy: EXPOSED_ENV,
            indicators: &["=", "SECRET", "KEY", "PASSWORD", "TOKEN"],
        },
        ExpPath {
            path: "/.env.local",
            policy: EXPOSED_ENV,
            indicators: &["=", "SECRET", "KEY", "PASSWORD"],
        },
        ExpPath {
            path: "/.env.production",
            policy: EXPOSED_ENV,
            indicators: &["=", "SECRET", "KEY", "PASSWORD"],
        },
        ExpPath {
            path: "/.git/config",
            policy: EXPOSED_GIT,
            indicators: &["[core]", "[remote", "url ="],
        },
        ExpPath {
            path: "/docker-compose.yml",
            policy: EXPOSED_COMPOSE,
            indicators: &["services:", "image:"],
        },
        ExpPath {
            path: "/docker-compose.yaml",
            policy: EXPOSED_COMPOSE,
            indicators: &["services:", "image:"],
        },
        ExpPath {
            path: "/k8s.yaml",
            policy: EXPOSED_K8S,
            indicators: &["apiVersion:", "kind:"],
        },
        ExpPath {
            path: "/kubernetes.yaml",
            policy: EXPOSED_K8S,
            indicators: &["apiVersion:", "kind:"],
        },
        ExpPath {
            path: "/deployment.yaml",
            policy: EXPOSED_K8S,
            indicators: &["apiVersion:", "kind:"],
        },
        ExpPath {
            path: "/Dockerfile",
            policy: EXPOSED_GENERIC,
            indicators: &["FROM "],
        },
        ExpPath {
            path: "/main.tf",
            policy: EXPOSED_GENERIC,
            indicators: &["resource \"", "provider \""],
        },
        ExpPath {
            path: "/variables.tf",
            policy: EXPOSED_GENERIC,
            indicators: &["variable \""],
        },
        ExpPath {
            path: "/.terraform.lock.hcl",
            policy: EXPOSED_GENERIC,
            indicators: &["provider", "hashes"],
        },
        ExpPath {
            path: "/serverless.yml",
            policy: EXPOSED_GENERIC,
            indicators: &["service:", "provider:"],
        },
        ExpPath {
            path: "/cloudformation.yaml",
            policy: EXPOSED_GENERIC,
            indicators: &["AWSTemplateFormatVersion", "Resources:"],
        },
        ExpPath {
            path: "/ansible/hosts",
            policy: EXPOSED_GENERIC,
            indicators: &["[all]", "ansible_"],
        },
        ExpPath {
            path: "/inventory",
            policy: EXPOSED_GENERIC,
            indicators: &["[all]", "ansible_host"],
        },
        ExpPath {
            path: "/Pulumi.yaml",
            policy: EXPOSED_GENERIC,
            indicators: &["name:", "runtime:"],
        },
        ExpPath {
            path: "/pulumi/Pulumi.yaml",
            policy: EXPOSED_GENERIC,
            indicators: &["name:", "runtime:"],
        },
        ExpPath {
            path: "/crossplane/providerconfig.yaml",
            policy: EXPOSED_K8S,
            indicators: &["apiVersion:", "ProviderConfig"],
        },
        ExpPath {
            path: "/terragrunt.hcl",
            policy: EXPOSED_GENERIC,
            indicators: &["remote_state", "terraform"],
        },
        ExpPath {
            path: "/atlantis.yaml",
            policy: EXPOSED_GENERIC,
            indicators: &["repos:", "workflows:"],
        },
        ExpPath {
            path: "/.kube/config",
            policy: EXPOSED_ENV,
            indicators: &["apiVersion:", "clusters:", "users:"],
        },
        ExpPath {
            path: "/kubeconfig",
            policy: EXPOSED_ENV,
            indicators: &["apiVersion:", "clusters:"],
        },
        ExpPath {
            path: "/.sops.yaml",
            policy: EXPOSED_GENERIC,
            indicators: &["creation_rules:", "sops"],
        },
        ExpPath {
            path: "/secrets.yaml",
            policy: EXPOSED_K8S,
            indicators: &["apiVersion:", "kind:", "Secret"],
        },
        ExpPath {
            path: "/spacelift.yaml",
            policy: EXPOSED_GENERIC,
            indicators: &["stack:", "terraform"],
        },
        ExpPath {
            path: "/helmfile.yaml",
            policy: EXPOSED_K8S,
            indicators: &["releases:", "chart:"],
        },
        ExpPath {
            path: "/packer.pkr.hcl",
            policy: EXPOSED_GENERIC,
            indicators: &["source", "builder"],
        },
        ExpPath {
            path: "/skaffold.yaml",
            policy: EXPOSED_K8S,
            indicators: &["apiVersion:", "skaffold"],
        },
        ExpPath {
            path: "/falco/custom-rules.yaml",
            policy: EXPOSED_GENERIC,
            indicators: &["- rule:", "condition:"],
        },
        ExpPath {
            path: "/app-config.yaml",
            policy: EXPOSED_GENERIC,
            indicators: &["backstage", "auth:", "integrations:"],
        },
        ExpPath {
            path: "/envoy-gateway/gateway.yaml",
            policy: EXPOSED_K8S,
            indicators: &["gateway.envoyproxy.io", "EnvoyProxy"],
        },
        ExpPath {
            path: "/sealed-secrets/db.yaml",
            policy: EXPOSED_K8S,
            indicators: &["SealedSecret", "encryptedData"],
        },
        ExpPath {
            path: "/monitoring/servicemonitor.yaml",
            policy: EXPOSED_K8S,
            indicators: &["ServiceMonitor", "monitoring.coreos.com"],
        },
        ExpPath {
            path: "/rollouts/api.yaml",
            policy: EXPOSED_K8S,
            indicators: &["Rollout", "argoproj.io"],
        },
        ExpPath {
            path: "/renovate.json",
            policy: EXPOSED_GENERIC,
            indicators: &["extends:", "packageRules", "renovate"],
        },
        ExpPath {
            path: "/.terraformrc",
            policy: EXPOSED_GENERIC,
            indicators: &["credentials", "provider_install"],
        },
    ]
}

async fn exposure_scan(target: &str, cfg: &Cfg) -> (Vec<Finding>, Vec<IacFile>, Option<String>) {
    let base = normalize_base(target);
    let cli = client(cfg);
    let mut findings = Vec::new();
    let mut fetched = Vec::new();
    let mut probed = 0u32;

    // (path, policy, indicators) — builtin table plus operator-supplied extras.
    let builtin = exposure_paths();
    let mut targets: Vec<(String, model::PolicyMeta, &[&str])> = builtin
        .iter()
        .map(|e| (e.path.to_string(), e.policy, e.indicators))
        .collect();
    for extra in &cfg.extra_exposure_paths {
        let p = if extra.starts_with('/') {
            extra.clone()
        } else {
            format!("/{}", extra)
        };
        targets.push((p, policies::EXPOSED_GENERIC, &[]));
    }

    for (path, policy, indicators) in &targets {
        let url = format!("{}{}", base, path);
        probed += 1;
        let Ok(resp) = cli.get(&url).send().await else {
            continue;
        };
        if resp.status().as_u16() != 200 {
            continue;
        }
        let body = resp.text().await.unwrap_or_default();
        if body.trim_start().starts_with('<') {
            continue; // HTML error/landing page, not the raw file
        }
        let confirmed = indicators.is_empty() || indicators.iter().any(|ind| body.contains(ind));
        if !confirmed {
            continue;
        }
        findings.push(
            Finding::new(*policy, url.clone(), url.clone())
                .observed(format!("HTTP 200, {} bytes", body.len())),
        );
        // deep-analyze the leaked artifact too
        if detect::detect(path, &body, None) != Framework::Unknown {
            fetched.push(IacFile {
                name: path.trim_start_matches('/').to_string(),
                content: body,
                forced: None,
                origin: format!("exposure:{}", url),
            });
        }
    }
    (
        findings,
        fetched,
        Some(format!("probed {} exposure paths on {}", probed, base)),
    )
}

// ──────────────────────────────────────────────────────────────────────────────
// Repository fetching (GitHub)
// ──────────────────────────────────────────────────────────────────────────────

fn parse_github(url: &str) -> Option<(String, String)> {
    let u = url.trim().trim_end_matches('/').trim_end_matches(".git");
    let rest = u
        .strip_prefix("https://github.com/")
        .or_else(|| u.strip_prefix("http://github.com/"))
        .or_else(|| u.strip_prefix("git@github.com:"))
        .or_else(|| u.strip_prefix("github.com/"))?;
    let mut it = rest.split('/');
    let owner = it.next()?.to_string();
    let repo = it.next()?.to_string();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner, repo))
}

fn is_playbook_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("playbook")
        || p.contains("/roles/")
        || p.ends_with("/main.yml")
        || p.ends_with("/main.yaml")
}

fn is_iac_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    let base = p.rsplit('/').next().unwrap_or(&p);
    if base == "package-lock.json" || base.ends_with(".lock") || base == "yarn.lock" {
        return false;
    }
    base == "chart.yaml"
        || base == "chart.yml"
        || base == "values.yaml"
        || base == "values.yml"
        || base.ends_with("openapi.json")
        || base.ends_with("swagger.json")
        || base.ends_with("serverless.yml")
        || base.ends_with("serverless.yaml")
        || base.ends_with("kustomization.yaml")
        || base.ends_with("kustomization.yml")
        || p.contains("/templates/")
        || base == "dockerfile"
        || base.starts_with("dockerfile.")
        || base.ends_with(".dockerfile")
        || base.ends_with(".tf")
        || base.ends_with(".tf.json")
        || base.ends_with(".tfvars")
        || base == "terragrunt.hcl"
        || (base.ends_with(".hcl")
            && (p.contains("/terragrunt/") || base.starts_with("terragrunt")))
        || p.contains("/crossplane/")
        || p.contains("/xrds/")
        || p.contains("/compositions/")
        || p.contains("/argocd/")
        || p.contains("flux-system/")
        || base.ends_with(".rego")
        || (p.contains("vault") && base.ends_with(".hcl"))
        || p.contains("istio")
        || p.contains("kyverno")
        || p.contains("linkerd")
        || base.ends_with(".pkr.hcl")
        || base.ends_with(".pkr.json")
        || base == "helmfile.yaml"
        || base == "helmfile.yml"
        || base == "skaffold.yaml"
        || base == "skaffold.yml"
        || p.contains("velero")
        || p.contains("keda")
        || p.contains("tekton")
        || p.contains("falco")
        || p.contains("backstage")
        || p.contains("envoy-gateway")
        || p.contains("envoygateway")
        || p.contains("app-config")
        || p.contains("sealedsecret")
        || p.contains("servicemonitor")
        || p.contains("rollout")
        || p.contains("externalsecret")
        || p.contains("gateway.networking")
        || base.ends_with(".cue")
        || base == ".sops.yaml"
        || base == "renovate.json"
        || base == "atlantis.yaml"
        || base.ends_with(".bicep")
        || base == "pulumi.yaml"
        || base == "pulumi.yml"
        || base == "cdk.json"
        || base.ends_with("nginx.conf")
        || (p.contains("nginx/") && base.ends_with(".conf"))
        || (base.ends_with(".ts")
            && (p.contains("/infra/")
                || p.contains("/pulumi/")
                || p.contains("/cdk/")
                || p.contains("/lib/")))
        || (base.ends_with(".py")
            && (p.contains("/infra/") || p.contains("/pulumi/") || p.contains("/cdk/")))
        || is_playbook_path(path)
        || base.starts_with("docker-compose")
        || p.contains(".github/workflows/") && (base.ends_with(".yml") || base.ends_with(".yaml"))
        || base.ends_with(".yaml")
        || base.ends_with(".yml")
        || base.ends_with(".json") && base.len() < 64
}

async fn fetch_repo_files(
    url: &str,
    cfg: &Cfg,
    ctx: &EngineRunContext,
) -> Result<Vec<IacFile>, String> {
    let (owner, repo) = parse_github(url)
        .ok_or_else(|| "only github.com repositories are supported".to_string())?;
    let cli = client(cfg);
    let token = ctx.github_token.clone().filter(|t| !t.trim().is_empty());

    let auth = |req: reqwest::RequestBuilder| -> reqwest::RequestBuilder {
        let req = req
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "Weissman-IaC-Security/1.0");
        if let Some(t) = &token {
            req.header("Authorization", format!("Bearer {}", t))
        } else {
            req
        }
    };

    // resolve ref (default branch when not provided)
    let reff = match &cfg.repo_ref {
        Some(r) => r.clone(),
        None => {
            let meta_url = format!("https://api.github.com/repos/{}/{}", owner, repo);
            let resp = auth(cli.get(&meta_url))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !resp.status().is_success() {
                return Err(format!("repo metadata HTTP {}", resp.status().as_u16()));
            }
            let v: Value = resp.json().await.map_err(|e| e.to_string())?;
            v.get("default_branch")
                .and_then(Value::as_str)
                .unwrap_or("main")
                .to_string()
        }
    };

    let tree_url = format!(
        "https://api.github.com/repos/{}/{}/git/trees/{}?recursive=1",
        owner, repo, reff
    );
    let resp = auth(cli.get(&tree_url))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("git tree HTTP {}", resp.status().as_u16()));
    }
    let tree: Value = resp.json().await.map_err(|e| e.to_string())?;
    let entries = tree
        .get("tree")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut files = Vec::new();
    for e in entries {
        if files.len() >= cfg.max_files {
            break;
        }
        if e.get("type").and_then(Value::as_str) != Some("blob") {
            continue;
        }
        let Some(path) = e.get("path").and_then(Value::as_str) else {
            continue;
        };
        if !cfg.repo_subdir.is_empty() && !path.starts_with(cfg.repo_subdir.trim_start_matches('/'))
        {
            continue;
        }
        if !is_iac_path(path) {
            continue;
        }
        let size = e.get("size").and_then(Value::as_u64).unwrap_or(0);
        if size > 524_288 {
            continue; // skip files > 512 KB
        }
        let raw_url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}/{}",
            owner, repo, reff, path
        );
        let mut rb = cli
            .get(&raw_url)
            .header("User-Agent", "Weissman-IaC-Security/1.0");
        if let Some(t) = &token {
            rb = rb.header("Authorization", format!("Bearer {}", t));
        }
        if let Ok(r) = rb.send().await {
            if r.status().is_success() {
                if let Ok(body) = r.text().await {
                    files.push(IacFile {
                        name: path.to_string(),
                        content: body,
                        forced: None,
                        origin: format!("repo:{}/{}@{}", owner, repo, reff),
                    });
                }
            }
        }
    }
    Ok(files)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(params: Value) -> EngineRunContext {
        EngineRunContext {
            job_params: params,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn static_inline_terraform_scan() {
        let tf = "resource \"aws_s3_bucket\" \"b\" { acl = \"public-read\" }\nresource \"aws_security_group\" \"sg\" { ingress { from_port = 22 to_port = 22 cidr_blocks = [\"0.0.0.0/0\"] } }\nresource \"aws_iam_policy\" \"admin\" {\n  policy = <<EOF\n{ \"Version\": \"2012-10-17\", \"Statement\": [ { \"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\" } ] }\nEOF\n}";
        let ctx = ctx_with(
            json!({ "scan_modes": ["static"], "iac_content": tf, "iac_filename": "main.tf" }),
        );
        let r = run_iac_misconfig_result("inline", &ctx).await;
        assert!(r.success);
        // summary + at least the two violations
        let summary = r
            .findings
            .iter()
            .find(|f| f["category"] == "iac_summary")
            .expect("summary present");
        assert!(summary["iac_summary"]["findings_total"].as_u64().unwrap() >= 2);
        assert!(
            summary["iac_summary"]["by_severity"]["critical"]
                .as_u64()
                .unwrap()
                >= 1
        );
        assert!(r
            .findings
            .iter()
            .any(|f| f["policy_id"] == "WZ-TF-AWS-S3-001"));
        assert!(r
            .findings
            .iter()
            .any(|f| f["policy_id"] == "WZ-TF-AWS-SG-002"));
        let chains = summary["iac_summary"]["attack_chains"].as_array().unwrap();
        assert!(
            !chains.is_empty(),
            "toxic combo sample should trigger attack paths"
        );
    }

    #[tokio::test]
    async fn min_severity_filter_drops_low() {
        let tf = "resource \"aws_kms_key\" \"k\" { }"; // medium finding
        let ctx = ctx_with(
            json!({ "scan_modes": ["static"], "iac_content": tf, "iac_filename": "k.tf", "min_severity": "high" }),
        );
        let r = run_iac_misconfig_result("inline", &ctx).await;
        assert!(!r
            .findings
            .iter()
            .any(|f| f["policy_id"] == "WZ-TF-AWS-KMS-001"));
    }

    #[tokio::test]
    async fn compliance_posture_present() {
        let tf = "resource \"aws_s3_bucket\" \"b\" { acl = \"public-read\" }";
        let ctx = ctx_with(
            json!({ "scan_modes": ["static"], "iac_content": tf, "iac_filename": "main.tf", "compliance_packs": ["CIS", "PCI-DSS"] }),
        );
        let r = run_iac_misconfig_result("inline", &ctx).await;
        let summary = r
            .findings
            .iter()
            .find(|f| f["category"] == "iac_summary")
            .unwrap();
        let packs = summary["iac_summary"]["compliance"].as_array().unwrap();
        assert!(packs
            .iter()
            .any(|p| p["pack"] == "CIS" && p["status"] == "fail"));
    }

    #[tokio::test]
    async fn multi_file_drift_and_readiness() {
        let ctx = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_files": [
                { "name": "prod.tf", "content": "resource \"aws_s3_bucket\" \"assets\" { acl = \"public-read\" }" },
                { "name": "staging.tf", "content": "resource \"aws_s3_bucket\" \"assets\" { acl = \"private\" }" }
            ],
            "drift_analysis": true
        }));
        let r = run_iac_misconfig_result("inline", &ctx).await;
        assert!(r.success);
        let summary = r
            .findings
            .iter()
            .find(|f| f["category"] == "iac_summary")
            .unwrap();
        assert!(summary["iac_summary"]["drift_findings"].as_u64().unwrap() >= 1);
        assert!(summary["iac_summary"]["readiness"]
            .get("readiness_score")
            .is_some());
        assert!(summary["iac_summary"]["cis_scorecard"]
            .get("overall_pass_pct")
            .is_some());
    }

    #[tokio::test]
    async fn plan_reconcile_detects_gap() {
        let tf = "resource \"aws_s3_bucket\" \"b\" { bucket = \"ok\" }";
        let plan = r#"{"resource_changes":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","change":{"actions":["create"],"after":{"acl":"public-read"}}}]}"#;
        let ctx = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": tf,
            "iac_filename": "main.tf",
            "terraform_plan_json": plan
        }));
        let r = run_iac_misconfig_result("inline", &ctx).await;
        assert!(r.success);
        assert!(r.findings.iter().any(|f| f["policy_id"] == "WZ-RECON-001"));
        let summary = r
            .findings
            .iter()
            .find(|f| f["category"] == "iac_summary")
            .unwrap();
        assert!(
            summary["iac_summary"]["plan_reconcile_findings"]
                .as_u64()
                .unwrap()
                >= 1
        );
    }

    #[tokio::test]
    async fn kyverno_and_atlantis_samples() {
        let kyverno = "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: audit-only\nspec:\n  validationFailureAction: audit\n  background: false";
        let ctx = ctx_with(
            json!({ "scan_modes": ["static"], "iac_content": kyverno, "iac_filename": "kyverno/policy.yaml", "iac_type": "kyverno" }),
        );
        let r = run_iac_misconfig_result("inline", &ctx).await;
        assert!(r.findings.iter().any(|f| f["policy_id"] == "WZ-KYV-001"));

        let atl = "repos:\n  - id: /.*/\n    automerge: true\n    apply_requirements: []";
        let ctx2 = ctx_with(
            json!({ "scan_modes": ["static"], "iac_content": atl, "iac_filename": "atlantis.yaml", "iac_type": "ci_platform" }),
        );
        let r2 = run_iac_misconfig_result("inline", &ctx2).await;
        assert!(r2.findings.iter().any(|f| f["policy_id"] == "WZ-CI-001"));
    }

    #[tokio::test]
    async fn soc2_report_in_summary() {
        let tf = "resource \"aws_s3_bucket\" \"b\" { acl = \"public-read\" }";
        let ctx = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": tf,
            "iac_filename": "main.tf",
            "compliance_packs": ["SOC2", "CIS"]
        }));
        let r = run_iac_misconfig_result("inline", &ctx).await;
        let summary = r
            .findings
            .iter()
            .find(|f| f["category"] == "iac_summary")
            .unwrap();
        assert!(summary["iac_summary"]["soc2_report"]
            .get("cc_families")
            .is_some());
    }

    #[tokio::test]
    async fn pci_report_in_summary() {
        let tf = "resource \"aws_s3_bucket\" \"b\" { acl = \"public-read\" }";
        let ctx = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": tf,
            "iac_filename": "main.tf",
            "compliance_packs": ["PCI-DSS", "SOC2"]
        }));
        let r = run_iac_misconfig_result("inline", &ctx).await;
        let summary = r
            .findings
            .iter()
            .find(|f| f["category"] == "iac_summary")
            .unwrap();
        assert!(summary["iac_summary"]["pci_report"]
            .get("requirements")
            .is_some());
    }

    #[tokio::test]
    async fn compliance_reports_and_gate_evidence() {
        let tf = "resource \"aws_s3_bucket\" \"b\" { acl = \"public-read\" }";
        let ctx = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": tf,
            "iac_filename": "main.tf",
            "compliance_packs": ["HIPAA", "NIST", "PCI-DSS", "SOC2"]
        }));
        let r = run_iac_misconfig_result("inline", &ctx).await;
        let summary = r
            .findings
            .iter()
            .find(|f| f["category"] == "iac_summary")
            .unwrap();
        let s = &summary["iac_summary"];
        assert!(s["hipaa_report"].get("safeguard_families").is_some());
        assert!(s["nist_report"].get("control_families").is_some());
        assert!(s["iso27001_report"].get("annex_a_themes").is_some());
        assert!(s["fedramp_report"].get("families").is_some());
        assert_eq!(
            s["audit_packet"]["packet_type"],
            "weissman-iac-audit-packet-v1"
        );
        assert_eq!(s["gate_evidence"]["evidence_type"], "iac_gate_audit");
        assert!(s["fix_bundle"].get("gate_evidence").is_some());
    }

    #[tokio::test]
    async fn sealed_secrets_prometheus_rollouts_samples() {
        let ss = "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  annotations:\n    sealedsecrets.bitnami.com/cluster-wide: 'true'\nspec:\n  encryptedData:\n    pass: AgBx\n  template:\n    stringData:\n      password: leak";
        let ctx = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": ss,
            "iac_filename": "sealed/db.yaml",
            "iac_type": "sealed_secrets"
        }));
        let r = run_iac_misconfig_result("inline", &ctx).await;
        let viol: Vec<_> = r
            .findings
            .iter()
            .filter(|f| f["category"] == "iac_policy_violation")
            .collect();
        assert!(viol.iter().any(|f| f["policy_id"] == "WZ-SS-001"));

        let prm = "apiVersion: monitoring.coreos.com/v1\nkind: ServiceMonitor\nspec:\n  endpoints:\n    - tlsConfig:\n        insecureSkipVerify: true";
        let ctx2 = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": prm,
            "iac_filename": "monitoring/sm.yaml",
            "iac_type": "prometheus_operator"
        }));
        let r2 = run_iac_misconfig_result("inline", &ctx2).await;
        let viol2: Vec<_> = r2
            .findings
            .iter()
            .filter(|f| f["category"] == "iac_policy_violation")
            .collect();
        assert!(viol2.iter().any(|f| f["policy_id"] == "WZ-PRM-001"));

        let aro = "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nspec:\n  strategy:\n    canary:\n      steps:\n        - setWeight: 50";
        let ctx3 = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": aro,
            "iac_filename": "rollouts/api.yaml",
            "iac_type": "argo_rollouts"
        }));
        let r3 = run_iac_misconfig_result("inline", &ctx3).await;
        let viol3: Vec<_> = r3
            .findings
            .iter()
            .filter(|f| f["category"] == "iac_policy_violation")
            .collect();
        assert!(viol3.iter().any(|f| f["policy_id"] == "WZ-ARO-001"));
    }

    #[tokio::test]
    async fn backstage_and_envoy_gateway_samples() {
        let bs = "auth:\n  dangerouslyAllowGuestAccess: true\ngithub_token: ghp_test";
        let ctx = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": bs,
            "iac_filename": "app-config.yaml",
            "iac_type": "backstage"
        }));
        let r = run_iac_misconfig_result("inline", &ctx).await;
        let findings: Vec<_> = r
            .findings
            .iter()
            .filter(|f| f["category"] == "iac_policy_violation")
            .collect();
        assert!(findings.iter().any(|f| f["policy_id"] == "WZ-BS-001"));

        let egw = "apiVersion: gateway.envoyproxy.io/v1alpha1\nkind: EnvoyProxy\nspec:\n  admin:\n    address: 0.0.0.0:9901";
        let ctx2 = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": egw,
            "iac_filename": "envoy-gateway/proxy.yaml",
            "iac_type": "envoy_gateway"
        }));
        let r2 = run_iac_misconfig_result("inline", &ctx2).await;
        let findings2: Vec<_> = r2
            .findings
            .iter()
            .filter(|f| f["category"] == "iac_policy_violation")
            .collect();
        assert!(findings2.iter().any(|f| f["policy_id"] == "WZ-EGW-004"));
    }

    #[tokio::test]
    async fn live_blast_graph_proven_paths() {
        let tf = r#"
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 443
    to_port     = 443
  }
}
resource "aws_s3_bucket" "assets" {
  bucket = "corp-assets"
  acl    = "public-read"
}
"#;
        let ctx = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": tf,
            "iac_filename": "main.tf",
            "live_blast": true
        }));
        let r = run_iac_misconfig_result("inline", &ctx).await;
        let summary = r
            .findings
            .iter()
            .find(|f| f["category"] == "iac_summary")
            .unwrap();
        let lb = &summary["iac_summary"]["live_blast"];
        assert!(
            lb.get("proven_path_count")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                >= 1
                || lb
                    .get("graph")
                    .and_then(|g| g.get("edge_count"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    >= 2
        );
    }

    #[tokio::test]
    async fn live_blast_cross_plane_irsa_graph() {
        let tf = r#"
resource "aws_iam_role_for_service_account" "app" {
  role_arn        = "arn:aws:iam::123456789012:role/app-irsa"
  service_account = "app-sa"
}
resource "aws_s3_bucket" "data" {
  bucket = "corp-data"
  acl    = "public-read"
}
"#;
        let k8s = r#"
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/app-irsa
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api
spec:
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 80
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  type: ClusterIP
  ports:
  - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  template:
    spec:
      serviceAccountName: app-sa
      containers:
      - name: app
        image: app:latest
"#;
        let ctx = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_files": [
                {"name": "irsa.tf", "content": tf},
                {"name": "k8s.yaml", "content": k8s}
            ],
            "live_blast": true,
            "iam_simulate": false
        }));
        let r = run_iac_misconfig_result("inline", &ctx).await;
        let summary = r
            .findings
            .iter()
            .find(|f| f["category"] == "iac_summary")
            .unwrap();
        let lb = &summary["iac_summary"]["live_blast"];
        assert!(
            lb.get("cross_plane_bridges")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                >= 1
        );
        assert_eq!(
            lb.get("engine_tier").and_then(Value::as_str),
            Some("sovereign-autopilot")
        );
    }

    #[tokio::test]
    async fn live_blast_autopilot_generates_patches() {
        let tf = r#"
resource "aws_s3_bucket" "assets" {
  bucket = "corp-assets"
  acl    = "public-read"
}
"#;
        let ctx = ctx_with(json!({
            "scan_modes": ["static"],
            "iac_content": tf,
            "iac_filename": "main.tf",
            "live_blast": true,
            "autopilot": true,
            "iam_simulate": false
        }));
        let r = run_iac_misconfig_result("inline", &ctx).await;
        let summary = r
            .findings
            .iter()
            .find(|f| f["category"] == "iac_summary")
            .unwrap();
        let ap = &summary["iac_summary"]["live_blast"]["autopilot"];
        assert!(ap.get("patch_count").and_then(Value::as_u64).unwrap_or(0) >= 1);
    }

    #[test]
    fn github_url_parsing() {
        assert_eq!(
            parse_github("https://github.com/hashicorp/terraform.git"),
            Some(("hashicorp".to_string(), "terraform".to_string()))
        );
        assert_eq!(
            parse_github("git@github.com:owner/repo"),
            Some(("owner".to_string(), "repo".to_string()))
        );
    }
}
