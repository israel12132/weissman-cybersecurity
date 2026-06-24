//! Supply-chain correlation — cross-file analysis detecting toxic combinations of unpinned
//! dependencies and committed secrets across the same repository scan.

use super::model::{Finding, IacFile, PolicyMeta, Severity};
use std::collections::HashSet;

use Severity::{Critical, High};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "supply_chain", provider: "generic",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const TF_MODULE_AND_SECRET: PolicyMeta = pol!(
    "WZ-SC-001",
    "Unpinned Terraform module + committed secret in same repository",
    Critical,
    "Repository contains both WZ-TF-SUPPLY-001 (mutable module ref) and a secret finding — supply-chain implant can use stolen credentials.",
    "Pin all module sources to immutable refs; remove secrets from VCS and rotate.",
    "T1195.001",
    "CWE-798",
    &["CIS-Supply"],
    &["NIST-SA-12", "PCI-DSS-8.2.1", "SOC2-CC8.1"]
);
pub const HELM_AND_SECRET: PolicyMeta = pol!(
    "WZ-SC-002",
    "Unpinned Helm chart + hard-coded secret in same repository",
    High,
    "Chart.yaml unpinned dependency coexists with WZ-HELM-002 or secret scanner hit.",
    "Pin chart versions; encrypt values with SOPS; use external-secrets.",
    "T1195.001",
    "CWE-798",
    &["CIS-Supply"],
    &["NIST-SA-12", "PCI-DSS-8.2.1"]
);
pub const LATEST_IMAGE_STACK: PolicyMeta = pol!(
    "WZ-SC-003",
    "Mutable image tags across Dockerfile + Kubernetes in same repo",
    High,
    "Both Dockerfile :latest and K8s image:latest (WZ-DKR-002 / WZ-K8S-011) in one scan — full stack non-reproducible.",
    "Pin digests end-to-end: Dockerfile, K8s manifests, and CI build pipelines.",
    "T1195.001",
    "CWE-494",
    &["CIS-Supply"],
    &["NIST-SA-12", "SOC2-CC8.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![TF_MODULE_AND_SECRET, HELM_AND_SECRET, LATEST_IMAGE_STACK]
}

/// Correlate supply-chain policy combinations across the scan.
#[must_use]
pub fn analyze(files: &[IacFile], findings: &[Finding]) -> Vec<Finding> {
    let mut out = Vec::new();
    if files.len() < 2 {
        return out;
    }
    let triggered: HashSet<&str> = findings.iter().map(|f| f.policy.id).collect();

    let has_secret = triggered.iter().any(|id| id.starts_with("WZ-SEC-"));
    let has_tf_supply = triggered.contains("WZ-TF-SUPPLY-001");
    let has_helm_unpin = triggered.contains("WZ-HELM-001");
    let has_helm_secret = triggered.contains("WZ-HELM-002");
    let has_dkr_latest = triggered.contains("WZ-DKR-002");
    let has_k8s_latest = triggered.contains("WZ-K8S-011");

    if has_tf_supply && has_secret {
        out.push(
            Finding::new(TF_MODULE_AND_SECRET, "repo-supply-chain", "correlation")
                .observed("WZ-TF-SUPPLY-001 + secret finding in same scan"),
        );
    }
    if has_helm_unpin && (has_helm_secret || has_secret) {
        out.push(
            Finding::new(HELM_AND_SECRET, "repo-supply-chain", "correlation")
                .observed("unpinned helm + secret in same scan"),
        );
    }
    if has_dkr_latest && has_k8s_latest {
        out.push(
            Finding::new(LATEST_IMAGE_STACK, "repo-supply-chain", "correlation")
                .observed("Dockerfile latest + K8s latest tag in same scan"),
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::secrets::AWS_KEY;
    use crate::iac_misconfig_engine::terraform::MODULE_UNPINNED;

    #[test]
    fn detects_tf_module_plus_secret() {
        let files = [
            IacFile { name: "main.tf".into(), content: String::new(), forced: None, origin: "inline".into() },
            IacFile { name: ".env".into(), content: String::new(), forced: None, origin: "inline".into() },
        ];
        let findings = vec![
            Finding::new(MODULE_UNPINNED, "main.tf", "module.x"),
            Finding::new(AWS_KEY, ".env", ".env"),
        ];
        let out = analyze(&files, &findings);
        assert!(out.iter().any(|f| f.policy.id == TF_MODULE_AND_SECRET.id));
    }
}
