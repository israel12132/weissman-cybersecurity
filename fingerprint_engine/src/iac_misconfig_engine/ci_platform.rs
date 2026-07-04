//! CI/IaC platform configs — Atlantis, Spacelift, and generic pipeline guards that weaken
//! Terraform apply gates.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "ci_platform",
            provider: "generic",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const ATLANTIS_APPLY_ALL: PolicyMeta = pol!(
    "WZ-CI-001",
    "Atlantis allows apply on all repos without approval",
    Critical,
    "apply_requirements empty or repos allow apply without approved/mergeable.",
    "Require approved, mergeable, undiverged apply_requirements.",
    "T1195.002",
    "CWE-284",
    &["CIS-CI"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const ATLANTIS_AUTO_MERGE: PolicyMeta = pol!(
    "WZ-CI-002",
    "Atlantis automerge enabled without security scan gate",
    High,
    "automerge: true without policy check integration.",
    "Disable automerge; require IaC scan PASS in apply_requirements.",
    "T1195.002",
    "CWE-693",
    &["CIS-CI"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const SPACELIFT_PUBLIC: PolicyMeta = pol!(
    "WZ-CI-003",
    "Spacelift stack uses public worker pool with sensitive context",
    High,
    "worker_pool: public with attached sensitive context labels.",
    "Use private worker pools for production stacks.",
    "T1021",
    "CWE-668",
    &["CIS-CI"],
    &["NIST-SC-7", "SOC2-CC6.6"]
);
pub const SPACELIFT_NO_PROTECT: PolicyMeta = pol!(
    "WZ-CI-004",
    "Spacelift stack protection disabled",
    High,
    "protect_deployment: false or enable_local_preview without protection.",
    "Enable protect_deployment and require tracked runs.",
    "T1098",
    "CWE-693",
    &["CIS-CI"],
    &["NIST-CM-7", "SOC2-CC8.1"]
);
pub const RENOVATE_PIN_OFF: PolicyMeta = pol!(
    "WZ-CI-005",
    "Renovate/IaC bot disables digest or hash pinning",
    Medium,
    "renovate config sets pinDigests: false or rangeStrategy: replace for modules.",
    "Pin provider/module versions to immutable refs.",
    "T1195.001",
    "CWE-494",
    &["CIS-Supply"],
    &["NIST-SA-12", "SOC2-CC8.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        ATLANTIS_APPLY_ALL,
        ATLANTIS_AUTO_MERGE,
        SPACELIFT_PUBLIC,
        SPACELIFT_NO_PROTECT,
        RENOVATE_PIN_OFF,
    ]
}

fn is_ci_platform(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.contains("atlantis")
        || n == "atlantis.yaml"
        || n == "atlantis.yml"
        || n.contains("spacelift")
        || lc.contains("spacelift.io")
        || n.contains("renovate")
        || n == "renovate.json"
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_ci_platform(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("repos:")
        && (lc.contains("apply_requirements: []") || !lc.contains("apply_requirements"))
    {
        out.push(
            Finding::new(ATLANTIS_APPLY_ALL, file, file)
                .observed("Atlantis missing apply_requirements"),
        );
    }
    if lc.contains("automerge: true") {
        out.push(Finding::new(ATLANTIS_AUTO_MERGE, file, file).observed("automerge enabled"));
    }
    if lc.contains("worker_pool") && lc.contains("public") {
        out.push(Finding::new(SPACELIFT_PUBLIC, file, file).observed("public worker pool"));
    }
    if lc.contains("protect_deployment: false") || lc.contains("enable_local_preview: true") {
        out.push(
            Finding::new(SPACELIFT_NO_PROTECT, file, file).observed("deployment protection off"),
        );
    }
    if lc.contains("pindigests: false") || lc.contains("rangestrategy: replace") {
        out.push(Finding::new(RENOVATE_PIN_OFF, file, file).observed("weak renovate pinning"));
    }

    out
}
