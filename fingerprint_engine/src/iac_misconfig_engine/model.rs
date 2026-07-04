//! Shared model for the IaC Security engine: severities, the policy catalog metadata, and the
//! per-violation `Finding` shape. Every analyzer (terraform, kubernetes, dockerfile, …) emits
//! `Finding`s by referencing a `PolicyMeta` from the canonical catalog, so titles, severities,
//! remediation, references and compliance mappings stay in one source of truth and the UI can show
//! exact policy coverage. Nothing here fabricates a result — a `Finding` is only created when an
//! analyzer observes a real violating value in the supplied IaC.

use serde::Serialize;
use serde_json::{json, Value};

/// Ordered severity ladder. `Ord` is used for `min_severity` / `fail_severity` gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "moderate" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }

    /// Risk weight used when computing the aggregate posture score.
    #[must_use]
    pub fn weight(self) -> u32 {
        match self {
            Severity::Critical => 40,
            Severity::High => 20,
            Severity::Medium => 8,
            Severity::Low => 3,
            Severity::Info => 0,
        }
    }
}

/// Canonical, immutable metadata for one security policy. This is the single source of truth: the
/// catalog (`crate::iac_misconfig_engine::policies::ALL_POLICIES`) lists every policy the engine can
/// enforce, and analyzers reference an entry by `id` when they observe a violation.
#[derive(Debug, Clone, Copy)]
pub struct PolicyMeta {
    /// Stable policy id, e.g. `WZ-TF-AWS-S3-PUBLIC-ACL`.
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    /// Source framework: terraform | kubernetes | dockerfile | cloudformation | docker_compose |
    /// github_actions | arm | secrets.
    pub framework: &'static str,
    /// aws | azure | gcp | kubernetes | docker | github | generic.
    pub provider: &'static str,
    pub description: &'static str,
    pub remediation: &'static str,
    /// MITRE ATT&CK technique id, e.g. `T1530`.
    pub mitre: &'static str,
    /// CWE id, e.g. `CWE-732`.
    pub cwe: &'static str,
    /// External references (CIS benchmark sections, vendor docs, scanner rule ids).
    pub references: &'static [&'static str],
    /// Compliance control mappings, e.g. `CIS-AWS-2.1.1`, `PCI-DSS-3.4`, `NIST-SC-13`.
    pub compliance: &'static [&'static str],
}

/// A concrete violation discovered by an analyzer, bound to a `PolicyMeta`.
#[derive(Debug, Clone)]
pub struct Finding {
    pub policy: PolicyMeta,
    /// Resource address / locator, e.g. `aws_s3_bucket.assets` or `Deployment/web`.
    pub resource: String,
    /// File the violation was found in.
    pub file: String,
    /// Best-effort 1-based line number (0 = unknown).
    pub line: usize,
    /// The exact observed value / excerpt that triggered the policy (evidence, never fabricated).
    pub observed: String,
    /// Optional concrete code fix tailored to this violation.
    pub code_fix: Option<String>,
}

impl Finding {
    #[must_use]
    pub fn new(policy: PolicyMeta, resource: impl Into<String>, file: impl Into<String>) -> Self {
        Self {
            policy,
            resource: resource.into(),
            file: file.into(),
            line: 0,
            observed: String::new(),
            code_fix: None,
        }
    }

    #[must_use]
    pub fn at(mut self, line: usize) -> Self {
        self.line = line;
        self
    }

    #[must_use]
    pub fn observed(mut self, observed: impl Into<String>) -> Self {
        self.observed = observed.into();
        self
    }

    #[must_use]
    pub fn fix(mut self, code: impl Into<String>) -> Self {
        self.code_fix = Some(code.into());
        self
    }

    /// Serialize into the platform's standard engine-finding JSON, enriched with the full IaC
    /// evidence trail (policy id, remediation, code fix, references, compliance, line).
    #[must_use]
    pub fn to_json(&self, target: &str) -> Value {
        let p = &self.policy;
        let location = if self.line > 0 {
            format!("{}:{}", self.file, self.line)
        } else {
            self.file.clone()
        };
        let mut description = format!(
            "{} — {} ({}). {}",
            p.description, self.resource, location, p.remediation
        );
        if !self.observed.is_empty() {
            description.push_str(&format!(" Observed: {}", truncate(&self.observed, 240)));
        }
        json!({
            "type": "iac_misconfig",
            "engine_id": "iac_misconfig",
            "category": "iac_policy_violation",
            "policy_id": p.id,
            "title": format!("{} [{}]", p.title, p.id),
            "severity": p.severity.as_str(),
            "framework": p.framework,
            "provider": p.provider,
            "mitre_attack": p.mitre,
            "cwe": p.cwe,
            "resource": self.resource,
            "file": self.file,
            "line": self.line,
            "location": location,
            "target": target,
            "description": description,
            "remediation": p.remediation,
            "code_fix": self.code_fix,
            "observed": truncate(&self.observed, 512),
            "references": p.references,
            "compliance": p.compliance,
            "confidence": 0.95,
            "verification_method": "static_iac_analysis",
        })
    }
}

#[must_use]
pub fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

/// Detected / requested IaC framework kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    Terraform,
    Kubernetes,
    Dockerfile,
    CloudFormation,
    DockerCompose,
    GithubActions,
    Arm,
    Helm,
    OpenApi,
    Serverless,
    Kustomize,
    Bicep,
    Pulumi,
    Cdk,
    Ansible,
    Nginx,
    Crossplane,
    Terragrunt,
    ArgoCd,
    Flux,
    Opa,
    Vault,
    Istio,
    Kyverno,
    Sops,
    Cue,
    CiPlatform,
    Linkerd,
    Packer,
    Helmfile,
    CertManager,
    ExternalSecrets,
    GatewayApi,
    Skaffold,
    Velero,
    Keda,
    Tekton,
    Falco,
    Backstage,
    EnvoyGateway,
    SealedSecrets,
    PrometheusOperator,
    ArgoRollouts,
    Unknown,
}

impl Framework {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Framework::Terraform => "terraform",
            Framework::Kubernetes => "kubernetes",
            Framework::Dockerfile => "dockerfile",
            Framework::CloudFormation => "cloudformation",
            Framework::DockerCompose => "docker_compose",
            Framework::GithubActions => "github_actions",
            Framework::Arm => "arm",
            Framework::Helm => "helm",
            Framework::OpenApi => "openapi",
            Framework::Serverless => "serverless",
            Framework::Kustomize => "kustomize",
            Framework::Bicep => "bicep",
            Framework::Pulumi => "pulumi",
            Framework::Cdk => "cdk",
            Framework::Ansible => "ansible",
            Framework::Nginx => "nginx",
            Framework::Crossplane => "crossplane",
            Framework::Terragrunt => "terragrunt",
            Framework::ArgoCd => "argocd",
            Framework::Flux => "flux",
            Framework::Opa => "opa",
            Framework::Vault => "vault",
            Framework::Istio => "istio",
            Framework::Kyverno => "kyverno",
            Framework::Sops => "sops",
            Framework::Cue => "cue",
            Framework::CiPlatform => "ci_platform",
            Framework::Linkerd => "linkerd",
            Framework::Packer => "packer",
            Framework::Helmfile => "helmfile",
            Framework::CertManager => "cert_manager",
            Framework::ExternalSecrets => "external_secrets",
            Framework::GatewayApi => "gateway_api",
            Framework::Skaffold => "skaffold",
            Framework::Velero => "velero",
            Framework::Keda => "keda",
            Framework::Tekton => "tekton",
            Framework::Falco => "falco",
            Framework::Backstage => "backstage",
            Framework::EnvoyGateway => "envoy_gateway",
            Framework::SealedSecrets => "sealed_secrets",
            Framework::PrometheusOperator => "prometheus_operator",
            Framework::ArgoRollouts => "argo_rollouts",
            Framework::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "terraform" | "tf" | "hcl" => Some(Framework::Terraform),
            "kubernetes" | "k8s" | "kube" => Some(Framework::Kubernetes),
            "dockerfile" | "docker" => Some(Framework::Dockerfile),
            "cloudformation" | "cfn" | "sam" => Some(Framework::CloudFormation),
            "docker_compose" | "compose" => Some(Framework::DockerCompose),
            "github_actions" | "gha" | "actions" | "workflow" => Some(Framework::GithubActions),
            "arm" | "azure_arm" => Some(Framework::Arm),
            "helm" | "chart" => Some(Framework::Helm),
            "openapi" | "swagger" | "oas" => Some(Framework::OpenApi),
            "serverless" | "sls" => Some(Framework::Serverless),
            "kustomize" | "kustomization" => Some(Framework::Kustomize),
            "bicep" => Some(Framework::Bicep),
            "pulumi" | "plm" => Some(Framework::Pulumi),
            "cdk" | "aws_cdk" => Some(Framework::Cdk),
            "ansible" | "playbook" => Some(Framework::Ansible),
            "nginx" => Some(Framework::Nginx),
            "crossplane" | "xp" => Some(Framework::Crossplane),
            "terragrunt" | "tg" => Some(Framework::Terragrunt),
            "argocd" | "argo" => Some(Framework::ArgoCd),
            "flux" | "fluxcd" => Some(Framework::Flux),
            "opa" | "rego" | "gatekeeper" => Some(Framework::Opa),
            "vault" | "vault_hcl" => Some(Framework::Vault),
            "istio" | "service_mesh" => Some(Framework::Istio),
            "kyverno" | "kyv" => Some(Framework::Kyverno),
            "sops" => Some(Framework::Sops),
            "cue" => Some(Framework::Cue),
            "ci_platform" | "atlantis" | "spacelift" | "renovate" => Some(Framework::CiPlatform),
            "linkerd" | "ldr" => Some(Framework::Linkerd),
            "packer" | "pkr" => Some(Framework::Packer),
            "helmfile" | "hlf" => Some(Framework::Helmfile),
            "cert_manager" | "cert-manager" | "certmanager" => Some(Framework::CertManager),
            "external_secrets" | "external-secrets" | "eso" => Some(Framework::ExternalSecrets),
            "gateway_api" | "gateway-api" | "gateway" => Some(Framework::GatewayApi),
            "skaffold" | "skf" => Some(Framework::Skaffold),
            "velero" | "vel" => Some(Framework::Velero),
            "keda" => Some(Framework::Keda),
            "tekton" | "tkn" => Some(Framework::Tekton),
            "falco" | "flc" => Some(Framework::Falco),
            "backstage" | "bs" => Some(Framework::Backstage),
            "envoy_gateway" | "envoy-gateway" | "egw" => Some(Framework::EnvoyGateway),
            "sealed_secrets" | "sealed-secrets" | "ss" => Some(Framework::SealedSecrets),
            "prometheus_operator" | "prometheus-operator" | "prm" => {
                Some(Framework::PrometheusOperator)
            }
            "argo_rollouts" | "argo-rollouts" | "aro" => Some(Framework::ArgoRollouts),
            _ => None,
        }
    }
}

/// One IaC artifact to analyze (a single file's content + an identifying name).
#[derive(Debug, Clone)]
pub struct IacFile {
    pub name: String,
    pub content: String,
    /// `None` => auto-detect from name + content.
    pub forced: Option<Framework>,
    /// Where the artifact came from: `inline`, `repo`, or `exposure:<url>`.
    pub origin: String,
}

/// Find a best-effort 1-based line number for the first occurrence of `needle` in `raw`.
#[must_use]
pub fn line_of(raw: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    if let Some(idx) = raw.find(needle) {
        return raw[..idx].bytes().filter(|&b| b == b'\n').count() + 1;
    }
    0
}
