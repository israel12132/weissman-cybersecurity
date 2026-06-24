//! Canonical aggregation of every policy the IaC engine can enforce, plus exposure (remote leak)
//! policies and the compliance-pack mapping used to compute posture. This is the single registry
//! the catalog endpoint, the coverage summary and the per-violation findings all draw from.

use super::model::{PolicyMeta, Severity};
use super::{
    ansible, argocd, argo_rollouts, arm, backstage, bicep, cdk, cert_manager, ci_platform, cloudformation, compose, cross_correlation, crossplane,
    cue, dockerfile, drift_hints, envoy_gateway, external_secrets, falco, flux, gateway_api, github_actions, helm, helmfile, istio, keda,
    kyverno, kustomize, kubernetes, linkerd, live_blast, nginx, openapi, opa, packer, plan_reconcile, prometheus_operator, pulumi, resource_graph, sealed_secrets, secrets,
    serverless, skaffold, sops, supply_chain, tekton, terraform, terragrunt, tfplan, vault_hcl, velero,
};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "exposure", provider: "generic",
            description: $desc, remediation: $rem, mitre: "T1552", cwe: "CWE-538",
            references: $refs, compliance: $comp,
        }
    };
}

// ── Exposure policies (remote leak detection over HTTP) ──────────────────────
pub const EXPOSED_TFSTATE: PolicyMeta = pol!("WZ-EXP-001", "Terraform state file publicly exposed", Critical, "A Terraform state file is reachable over HTTP. State files contain resource attributes and frequently plaintext secrets (DB passwords, keys).", "Remove the file from the web root; store state in an encrypted, access-controlled backend (S3+DynamoDB, TFC) and rotate any leaked secrets.", &["CIS-AWS-2.1.x"], &["NIST-SC-28", "PCI-DSS-3.4", "SOC2-CC6.1", "MITRE-T1552"]);
pub const EXPOSED_ENV: PolicyMeta = pol!("WZ-EXP-002", "Environment (.env) file publicly exposed", Critical, "A .env file is reachable over HTTP, typically leaking credentials and API keys.", "Block access to dotfiles at the web server; move secrets to a secret manager and rotate them.", &["OWASP-A05"], &["NIST-IA-5", "PCI-DSS-8.2.1", "SOC2-CC6.1", "MITRE-T1552"]);
pub const EXPOSED_GIT: PolicyMeta = pol!("WZ-EXP-003", "Git metadata (.git) publicly exposed", High, "A .git directory/config is reachable over HTTP, allowing source and history (and embedded secrets) to be reconstructed.", "Deny access to .git at the web server and remove it from deployed artifacts.", &["OWASP-A05"], &["NIST-CM-7", "SOC2-CC6.1", "MITRE-T1552"]);
pub const EXPOSED_COMPOSE: PolicyMeta = pol!("WZ-EXP-004", "docker-compose file publicly exposed", High, "A docker-compose file is reachable over HTTP, revealing services, images and sometimes credentials.", "Block access to deployment files at the web server.", &["OWASP-A05"], &["NIST-CM-7", "SOC2-CC6.1"]);
pub const EXPOSED_K8S: PolicyMeta = pol!("WZ-EXP-005", "Kubernetes manifest publicly exposed", High, "A Kubernetes manifest is reachable over HTTP, revealing workload topology and configuration.", "Block access to manifests at the web server.", &["OWASP-A05"], &["NIST-CM-7", "SOC2-CC6.1"]);
pub const EXPOSED_GENERIC: PolicyMeta = pol!("WZ-EXP-006", "Sensitive IaC/config file publicly exposed", Medium, "An infrastructure/config file is reachable over HTTP and should not be publicly accessible.", "Restrict access to infrastructure and configuration files.", &["OWASP-A05"], &["NIST-CM-7", "SOC2-CC6.1"]);

#[must_use]
pub fn exposure_policies() -> Vec<PolicyMeta> {
    vec![EXPOSED_TFSTATE, EXPOSED_ENV, EXPOSED_GIT, EXPOSED_COMPOSE, EXPOSED_K8S, EXPOSED_GENERIC]
}

/// The complete catalog across every analyzer.
#[must_use]
pub fn all_policies() -> Vec<PolicyMeta> {
    let mut v = Vec::new();
    v.extend(terraform::policies());
    v.extend(kubernetes::policies());
    v.extend(dockerfile::policies());
    v.extend(cloudformation::policies());
    v.extend(compose::policies());
    v.extend(github_actions::policies());
    v.extend(arm::policies());
    v.extend(helm::policies());
    v.extend(openapi::policies());
    v.extend(serverless::policies());
    v.extend(kustomize::policies());
    v.extend(bicep::policies());
    v.extend(pulumi::policies());
    v.extend(cdk::policies());
    v.extend(ansible::policies());
    v.extend(nginx::policies());
    v.extend(crossplane::policies());
    v.extend(terragrunt::policies());
    v.extend(argocd::policies());
    v.extend(flux::policies());
    v.extend(opa::policies());
    v.extend(vault_hcl::policies());
    v.extend(istio::policies());
    v.extend(kyverno::policies());
    v.extend(sops::policies());
    v.extend(cue::policies());
    v.extend(ci_platform::policies());
    v.extend(linkerd::policies());
    v.extend(packer::policies());
    v.extend(helmfile::policies());
    v.extend(cert_manager::policies());
    v.extend(external_secrets::policies());
    v.extend(gateway_api::policies());
    v.extend(skaffold::policies());
    v.extend(velero::policies());
    v.extend(keda::policies());
    v.extend(tekton::policies());
    v.extend(falco::policies());
    v.extend(backstage::policies());
    v.extend(envoy_gateway::policies());
    v.extend(sealed_secrets::policies());
    v.extend(prometheus_operator::policies());
    v.extend(argo_rollouts::policies());
    v.extend(supply_chain::policies());
    v.extend(plan_reconcile::policies());
    v.extend(tfplan::policies());
    v.extend(drift_hints::policies());
    v.extend(resource_graph::policies());
    v.extend(cross_correlation::policies());
    v.extend(secrets::policies());
    v.extend(live_blast::policies::policies());
    v.extend(exposure_policies());
    v
}

/// Compliance packs the engine reports posture for.
pub const KNOWN_PACKS: &[&str] = &["CIS", "PCI-DSS", "HIPAA", "NIST", "SOC2", "ISO27001", "MITRE"];

/// Map a single compliance control tag to its parent pack.
#[must_use]
pub fn pack_of(tag: &str) -> &'static str {
    let t = tag.trim();
    if t.starts_with("CIS") {
        "CIS"
    } else if t.starts_with("PCI") {
        "PCI-DSS"
    } else if t.starts_with("HIPAA") {
        "HIPAA"
    } else if t.starts_with("NIST") {
        "NIST"
    } else if t.starts_with("SOC2") {
        "SOC2"
    } else if t.starts_with("ISO27001") || t.starts_with("ISO-27001") {
        "ISO27001"
    } else if t.starts_with("MITRE") || t.starts_with('T') {
        "MITRE"
    } else {
        "OTHER"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_large_and_unique() {
        let all = all_policies();
        assert!(all.len() >= 331, "catalog should be world-class size, got {}", all.len());
        let mut ids: Vec<&str> = all.iter().map(|p| p.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "policy ids must be unique");
    }

    #[test]
    fn pack_mapping() {
        assert_eq!(pack_of("CIS-AWS-2.1.5"), "CIS");
        assert_eq!(pack_of("PCI-DSS-3.4"), "PCI-DSS");
        assert_eq!(pack_of("T1530"), "MITRE");
        assert_eq!(pack_of("NIST-SC-28"), "NIST");
    }
}
