//! Flux CD GitOps analyzer — Kustomization / HelmRelease / GitRepository sources with mutable
//! refs, insecure endpoints, and missing verification.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "flux",
            provider: "kubernetes",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const GIT_REF_BRANCH: PolicyMeta = pol!(
    "WZ-FLX-001",
    "Flux GitRepository tracks mutable branch ref",
    High,
    "ref.branch is main/master without commit pin — any push deploys.",
    "Pin to tag or commit; enable Git signature verification.",
    "T1195.002",
    "CWE-494",
    &["CIS-K8S-5.1.1"],
    &["NIST-SA-12", "SOC2-CC8.1"]
);
pub const INSECURE_GIT: PolicyMeta = pol!(
    "WZ-FLX-002",
    "Flux GitRepository uses insecure HTTP URL",
    High,
    "url: http:// for GitRepository or Bucket source.",
    "Use https:// or internal SSH with known_hosts.",
    "T1557",
    "CWE-319",
    &["CIS-K8S-5.4.1"],
    &["NIST-SC-8", "PCI-DSS-4.1"]
);
pub const KUST_PRUNE_OFF: PolicyMeta = pol!(
    "WZ-FLX-003",
    "Flux Kustomization prune disabled",
    Medium,
    "spec.prune: false leaves orphaned cluster objects after manifest removal.",
    "Set prune: true with health checks and dependsOn ordering.",
    "T1098",
    "CWE-693",
    &["CIS-K8S-5.1.1"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const HELM_SKIP_CRDS: PolicyMeta = pol!(
    "WZ-FLX-004",
    "Flux HelmRelease skips CRD upgrade safeguards",
    Medium,
    "skipCrds or disableWait together with mutable chart version.",
    "Pin chart version; enable CRD upgrade policies; use OCI registry with signature.",
    "T1195.001",
    "CWE-1104",
    &["CIS-K8S-5.1.1"],
    &["NIST-SA-12", "SOC2-CC8.1"]
);
pub const SUSPEND_FALSE_PROD: PolicyMeta = pol!(
    "WZ-FLX-005",
    "Flux Kustomization targets production without suspend guard",
    High,
    "production path/name with interval sync and no suspend — rapid blast radius on bad commit.",
    "Use notification alerts, image policy, and production sync windows.",
    "T1195.002",
    "CWE-693",
    &["CIS-K8S-5.1.1"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        GIT_REF_BRANCH,
        INSECURE_GIT,
        KUST_PRUNE_OFF,
        HELM_SKIP_CRDS,
        SUSPEND_FALSE_PROD,
    ]
}

fn is_flux(name: &str, content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("helm.toolkit.fluxcd.io")
        || lc.contains("kustomize.toolkit.fluxcd.io")
        || lc.contains("source.toolkit.fluxcd.io")
        || name.to_ascii_lowercase().contains("flux")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_flux(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("kind: gitrepository")
        && (lc.contains("branch: main") || lc.contains("branch: master"))
        && !lc.contains("tag:")
    {
        out.push(Finding::new(GIT_REF_BRANCH, file, file).observed("mutable branch ref"));
    }
    if lc.contains("url: http://") {
        out.push(Finding::new(INSECURE_GIT, file, file).observed("http:// git source"));
    }
    if lc.contains("kind: kustomization") && lc.contains("prune: false") {
        out.push(Finding::new(KUST_PRUNE_OFF, file, file).observed("prune: false"));
    }
    if lc.contains("kind: helmrelease")
        && (lc.contains("skipcrds: true") || lc.contains("disablewait: true"))
    {
        out.push(Finding::new(HELM_SKIP_CRDS, file, file).observed("HelmRelease unsafe flags"));
    }
    if lc.contains("kind: kustomization")
        && (lc.contains("prod") || lc.contains("production"))
        && !lc.contains("suspend: true")
    {
        out.push(
            Finding::new(SUSPEND_FALSE_PROD, file, file)
                .observed("production kustomization always syncing"),
        );
    }

    out
}
