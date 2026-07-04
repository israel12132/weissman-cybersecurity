//! Deterministic IaC framework detection from a file name plus a content sniff. Mirrors how Wiz /
//! Checkov / KICS classify artifacts before parsing. Name signals win; content signals break ties.

use super::model::Framework;

/// Classify an artifact. `forced` short-circuits everything (operator override from the GUI).
#[must_use]
pub fn detect(name: &str, content: &str, forced: Option<Framework>) -> Framework {
    if let Some(f) = forced {
        if f != Framework::Unknown {
            return f;
        }
    }
    let lname = name.trim().to_ascii_lowercase();
    let base = lname.rsplit('/').next().unwrap_or(&lname).to_string();

    // ── Strong filename signals ──────────────────────────────────────────────
    if base.ends_with("nginx.conf") || (lname.contains("nginx/") && base.ends_with(".conf")) {
        return Framework::Nginx;
    }
    if lname.contains("sites-available/")
        || lname.contains("sites-enabled/")
        || lname.contains("conf.d/")
    {
        return Framework::Nginx;
    }
    if (base.ends_with(".yml") || base.ends_with(".yaml"))
        && (lname.contains("playbook") || lname.contains("/roles/") || base == "main.yml")
    {
        return Framework::Ansible;
    }
    if base == "serverless.yml" || base == "serverless.yaml" {
        return Framework::Serverless;
    }
    if base.ends_with("kustomization.yaml") || base.ends_with("kustomization.yml") {
        return Framework::Kustomize;
    }
    if base.ends_with("openapi.yaml")
        || base.ends_with("openapi.yml")
        || base.ends_with("openapi.json")
        || base.ends_with("swagger.yaml")
        || base.ends_with("swagger.json")
    {
        return Framework::OpenApi;
    }
    if base == "chart.yaml" || base == "chart.yml" {
        return Framework::Helm;
    }
    if base == "values.yaml" || base == "values.yml" {
        return Framework::Helm;
    }
    if lname.contains("/templates/")
        && (base.ends_with(".yaml") || base.ends_with(".yml") || base.ends_with(".tpl"))
    {
        return Framework::Helm;
    }
    if base == "dockerfile" || base.starts_with("dockerfile.") || base.ends_with(".dockerfile") {
        return Framework::Dockerfile;
    }
    if base.ends_with(".bicep") {
        return Framework::Bicep;
    }
    if base == "pulumi.yaml" || base == "pulumi.yml" || base == "pulumiproject.yaml" {
        return Framework::Pulumi;
    }
    if base == "cdk.json" || base.ends_with("cdk.context.json") {
        return Framework::Cdk;
    }
    if base.ends_with(".rego") {
        return Framework::Opa;
    }
    if lname.contains("argocd") || base.contains("application.yaml") && lname.contains("argo") {
        return Framework::ArgoCd;
    }
    if lname.contains("flux")
        || base.contains("kustomization.yaml") && lname.contains("flux-system")
    {
        return Framework::Flux;
    }
    if lname.contains("istio")
        || base.contains("peerauthentication")
        || base.contains("authorizationpolicy")
    {
        return Framework::Istio;
    }
    if lname.contains("kyverno") || base.ends_with("-policy.yaml") || base.ends_with("-policy.yml")
    {
        return Framework::Kyverno;
    }
    if base == ".sops.yaml"
        || base == ".sops.yml"
        || base.ends_with(".sops.yaml")
        || base.ends_with(".sops.yml")
    {
        return Framework::Sops;
    }
    if base.ends_with(".cue") {
        return Framework::Cue;
    }
    if base == "atlantis.yaml"
        || base == "atlantis.yml"
        || base == "renovate.json"
        || lname.contains("spacelift")
    {
        return Framework::CiPlatform;
    }
    if lname.contains("linkerd") || base.contains("serverauthorization") {
        return Framework::Linkerd;
    }
    if base.ends_with(".pkr.hcl") || base.ends_with(".pkr.json") {
        return Framework::Packer;
    }
    if base == "helmfile.yaml" || base == "helmfile.yml" || base.ends_with(".helmfile.yaml") {
        return Framework::Helmfile;
    }
    if base == "skaffold.yaml" || base == "skaffold.yml" {
        return Framework::Skaffold;
    }
    if lname.contains("velero") || base.contains("backupstoragelocation") {
        return Framework::Velero;
    }
    if lname.contains("keda") || base.contains("scaledobject") {
        return Framework::Keda;
    }
    if lname.contains("tekton") || lname.contains("/pipeline") && base.ends_with(".yaml") {
        return Framework::Tekton;
    }
    if lname.contains("falco") || base.contains("falco_rules") {
        return Framework::Falco;
    }
    if lname.contains("backstage")
        || base == "app-config.yaml"
        || base == "app-config.yml"
        || base.ends_with("catalog-info.yaml")
    {
        return Framework::Backstage;
    }
    if lname.contains("envoy-gateway")
        || lname.contains("envoygateway")
        || base.contains("envoyproxy")
    {
        return Framework::EnvoyGateway;
    }
    if lname.contains("sealedsecret") || base.contains("sealed-secret") {
        return Framework::SealedSecrets;
    }
    if lname.contains("servicemonitor") || lname.contains("prometheus") && base.ends_with(".yaml") {
        return Framework::PrometheusOperator;
    }
    if lname.contains("rollout") || base.contains("analysistemplate") {
        return Framework::ArgoRollouts;
    }
    if lname.contains("externalsecret")
        || lname.contains("secretstore")
        || lname.contains("clustersecretstore")
    {
        return Framework::ExternalSecrets;
    }
    if lname.contains("httproute") || lname.contains("gateway-api") || base == "gateway.yaml" {
        return Framework::GatewayApi;
    }
    if lname.contains("vault") && base.ends_with(".hcl") {
        return Framework::Vault;
    }
    if base.ends_with("terragrunt.hcl") || (base.ends_with(".hcl") && lname.contains("terragrunt"))
    {
        return Framework::Terragrunt;
    }
    if lname.contains("/crossplane/")
        || lname.contains("/xrds/")
        || lname.contains("/compositions/")
    {
        return Framework::Crossplane;
    }
    if base.ends_with(".tf") || base.ends_with(".tf.json") || base.ends_with(".tfvars") {
        return Framework::Terraform;
    }
    if base.starts_with("docker-compose") || base.starts_with("compose.") {
        return Framework::DockerCompose;
    }
    // GitHub Actions live under .github/workflows/*.yml.
    if lname.contains(".github/workflows/") && (base.ends_with(".yml") || base.ends_with(".yaml")) {
        return Framework::GithubActions;
    }

    let head: String = content.chars().take(4000).collect();
    let lc = head.to_ascii_lowercase();

    // ── JSON artifacts (CFN vs ARM vs Terraform-json) ────────────────────────
    let trimmed = head.trim_start();
    if trimmed.starts_with('{') {
        if head.contains("AWSTemplateFormatVersion") || head.contains("\"Resources\"") {
            return Framework::CloudFormation;
        }
        if head.contains("schema.management.azure.com") || head.contains("\"$schema\"") {
            return Framework::Arm;
        }
        if base.ends_with(".json")
            && (head.contains("\"resource\"") || head.contains("\"provider\""))
        {
            return Framework::Terraform;
        }
    }

    // ── YAML content signals ─────────────────────────────────────────────────
    if base.ends_with(".yml") || base.ends_with(".yaml") || trimmed.starts_with("---") {
        if head.contains("AWSTemplateFormatVersion") || lc.contains("transform: aws::serverless") {
            return Framework::CloudFormation;
        }
        if lc.contains("\non: ")
            || lc.starts_with("on:")
            || lc.contains("\njobs:")
            || lc.contains("runs-on:")
        {
            return Framework::GithubActions;
        }
        if lc.contains("openapi:")
            || lc.contains("\"openapi\"")
            || lc.contains("swagger:")
            || lc.contains("\"swagger\"")
        {
            return Framework::OpenApi;
        }
        if lc.contains("apiversion: kustomize.config.k8s.io") {
            return Framework::Kustomize;
        }
        if lc.contains("apiextensions.crossplane.io")
            || lc.contains("pkg.crossplane.io")
            || lc.contains("kind: composition")
        {
            return Framework::Crossplane;
        }
        if lc.contains("argoproj.io") || lc.contains("kind: appproject") {
            return Framework::ArgoCd;
        }
        if lc.contains("toolkit.fluxcd.io") {
            return Framework::Flux;
        }
        if lc.contains("security.istio.io") || lc.contains("networking.istio.io") {
            return Framework::Istio;
        }
        if lc.contains("kyverno.io")
            || (lc.contains("kind: clusterpolicy") && lc.contains("validationfailureaction"))
        {
            return Framework::Kyverno;
        }
        if lc.contains("creation_rules:") && (lc.contains("sops") || lc.contains("encrypted_regex"))
        {
            return Framework::Sops;
        }
        if lc.contains("repos:") && lc.contains("workflows:") && lc.contains("atlantis") {
            return Framework::CiPlatform;
        }
        if (lc.contains("\"extends\"") && lc.contains("renovate")) || lc.contains("pindigests") {
            return Framework::CiPlatform;
        }
        if lc.contains("policy.linkerd.io") || lc.contains("kind: serverauthorization") {
            return Framework::Linkerd;
        }
        if lc.contains("cert-manager.io") || lc.contains("kind: clusterissuer") {
            return Framework::CertManager;
        }
        if lc.contains("external-secrets.io") || lc.contains("kind: externalsecret") {
            return Framework::ExternalSecrets;
        }
        if lc.contains("gateway.networking.k8s.io") || lc.contains("kind: httproute") {
            return Framework::GatewayApi;
        }
        if lc.contains("apiversion: skaffold") {
            return Framework::Skaffold;
        }
        if lc.contains("velero.io") || lc.contains("backupstoragelocation") {
            return Framework::Velero;
        }
        if lc.contains("keda.sh") || lc.contains("kind: scaledobject") {
            return Framework::Keda;
        }
        if lc.contains("tekton.dev") {
            return Framework::Tekton;
        }
        if lc.contains("- rule:") && lc.contains("condition:") {
            return Framework::Falco;
        }
        if lc.contains("backstage.io") || lc.contains("dangerouslyallowguestaccess") {
            return Framework::Backstage;
        }
        if lc.contains("gateway.envoyproxy.io") || lc.contains("kind: envoyproxy") {
            return Framework::EnvoyGateway;
        }
        if lc.contains("kind: sealedsecret") || lc.contains("bitnami.com/sealedsecret") {
            return Framework::SealedSecrets;
        }
        if lc.contains("monitoring.coreos.com") || lc.contains("kind: servicemonitor") {
            return Framework::PrometheusOperator;
        }
        if lc.contains("argoproj.io") && lc.contains("kind: rollout") {
            return Framework::ArgoRollouts;
        }
        if lc.contains("releases:")
            && lc.contains("chart:")
            && (lc.contains("helmfile") || lc.contains("setvalues"))
        {
            return Framework::Helmfile;
        }
        if lc.contains("templates.gatekeeper.sh") || lc.contains("kind: constrainttemplate") {
            return Framework::Opa;
        }
        if lc.contains("- hosts:") && lc.contains("tasks:") {
            return Framework::Ansible;
        }
        if lc.contains("server {") && lc.contains("listen ") {
            return Framework::Nginx;
        }
        if lc.contains("services:") && lc.contains("functions:") && lc.contains("provider:") {
            return Framework::Serverless;
        }
        if lc.contains("resource ") && lc.contains("microsoft.") {
            return Framework::Bicep;
        }
        if lc.contains("@pulumi/") || lc.contains("import pulumi") {
            return Framework::Pulumi;
        }
        if lc.contains("aws-cdk-lib") || lc.contains("aws_cdk") {
            return Framework::Cdk;
        }
        if lc.contains("services:")
            && (lc.contains("image:") || lc.contains("build:"))
            && !lc.contains("apiversion")
        {
            return Framework::DockerCompose;
        }
        if lc.contains("apiversion:") && lc.contains("kind:") {
            return Framework::Kubernetes;
        }
        // Helm templated K8s manifests still carry apiVersion/kind hints.
        if lc.contains("kind:") && (lc.contains("spec:") || lc.contains("metadata:")) {
            return Framework::Kubernetes;
        }
    }

    // ── HCL fallback (resource "x" "y" {) ────────────────────────────────────
    if base.ends_with(".cue")
        || lc.contains("package ") && lc.contains("{") && lc.contains("#config")
    {
        return Framework::Cue;
    }
    if lc.contains("packer {") || lc.contains("\"builders\"") && lc.contains("amazon-ebs") {
        return Framework::Packer;
    }
    if lc.contains("resource \"") || lc.contains("provider \"") || lc.contains("terraform {") {
        return Framework::Terraform;
    }
    if lc.contains("path \"") && lc.contains("capabilities") {
        return Framework::Vault;
    }
    if lc.starts_with("from ") || lc.contains("\nfrom ") {
        return Framework::Dockerfile;
    }

    Framework::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_by_name() {
        assert_eq!(detect("main.tf", "", None), Framework::Terraform);
        assert_eq!(detect("Dockerfile", "", None), Framework::Dockerfile);
        assert_eq!(
            detect("docker-compose.yml", "services:\n  a:\n    image: x", None),
            Framework::DockerCompose
        );
    }

    #[test]
    fn detects_k8s_and_actions_by_content() {
        assert_eq!(
            detect(
                "deploy.yaml",
                "apiVersion: apps/v1\nkind: Deployment\nspec: {}",
                None
            ),
            Framework::Kubernetes
        );
        assert_eq!(
            detect(
                ".github/workflows/ci.yml",
                "on: push\njobs:\n  b:\n    runs-on: ubuntu",
                None
            ),
            Framework::GithubActions
        );
    }

    #[test]
    fn detects_cfn_json() {
        assert_eq!(
            detect(
                "stack.json",
                "{\"AWSTemplateFormatVersion\":\"2010-09-09\",\"Resources\":{}}",
                None
            ),
            Framework::CloudFormation
        );
    }
}
