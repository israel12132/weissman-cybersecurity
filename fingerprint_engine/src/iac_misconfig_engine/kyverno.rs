//! Kyverno policy analyzer — validate/mutate/generate rules with overly permissive patterns,
//! wildcard exclusions, and background scanning disabled on security policies.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "kyverno",
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

pub const VALIDATE_DISABLED: PolicyMeta = pol!(
    "WZ-KYV-001",
    "Kyverno policy validation disabled (Enforce: false)",
    High,
    "validationFailureAction: audit or spec.validationFailureAction overrides deny.",
    "Set validationFailureAction: Enforce on security policies.",
    "T1562",
    "CWE-693",
    &["CIS-K8S-5.7.1"],
    &["NIST-CM-7", "SOC2-CC8.1"]
);
pub const MUTATE_PRIV: PolicyMeta = pol!(
    "WZ-KYV-002",
    "Kyverno mutate rule injects privileged securityContext",
    Critical,
    "mutate patch sets privileged: true on Pods.",
    "Remove privileged mutations; use validate-only policies.",
    "T1610",
    "CWE-250",
    &["CIS-K8S-5.2.1"],
    &["NIST-AC-6", "SOC2-CC6.1"]
);
pub const EXCLUDE_ALL: PolicyMeta = pol!(
    "WZ-KYV-003",
    "Kyverno policy excludes all namespaces",
    High,
    "spec.rules[].exclude.any with namespace: * disables protection cluster-wide.",
    "Remove blanket exclusions; use narrow break-glass namespaces.",
    "T1098",
    "CWE-732",
    &["CIS-K8S-5.7.1"],
    &["NIST-AC-6", "SOC2-CC6.3"]
);
pub const GENERATE_SECRET: PolicyMeta = pol!(
    "WZ-KYV-004",
    "Kyverno generate rule creates Secret from literal",
    Critical,
    "generate.data contains password/token literals in manifest.",
    "Generate from external secret store; never embed literals.",
    "T1552.001",
    "CWE-798",
    &["CIS-K8S-5.4.1"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const BG_SCAN_OFF: PolicyMeta = pol!(
    "WZ-KYV-005",
    "Kyverno background scanning disabled",
    Medium,
    "spec.background: false on validate policy — existing resources never re-checked.",
    "Enable background: true for drift detection on live cluster.",
    "T1098",
    "CWE-693",
    &["CIS-K8S-5.7.1"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        VALIDATE_DISABLED,
        MUTATE_PRIV,
        EXCLUDE_ALL,
        GENERATE_SECRET,
        BG_SCAN_OFF,
    ]
}

fn is_kyverno(name: &str, content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("kyverno.io")
        || name.to_ascii_lowercase().contains("kyverno")
        || ((lc.contains("kind: clusterpolicy") || lc.contains("kind: policy"))
            && lc.contains("validationfailureaction"))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_kyverno(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("validationfailureaction: audit") || lc.contains("enforce: false") {
        out.push(
            Finding::new(VALIDATE_DISABLED, file, file)
                .observed("validationFailureAction audit / enforce false"),
        );
    }
    if lc.contains("mutate") && lc.contains("privileged: true") {
        out.push(Finding::new(MUTATE_PRIV, file, file).observed("mutate injects privileged"));
    }
    if lc.contains("exclude:") && lc.contains("namespace: '*'") || lc.contains("namespace: \"*\"") {
        out.push(Finding::new(EXCLUDE_ALL, file, file).observed("exclude namespace *"));
    }
    if lc.contains("generate:")
        && (lc.contains("password:") || lc.contains("token:") || lc.contains("apikey:"))
    {
        out.push(
            Finding::new(GENERATE_SECRET, file, file).observed("generate rule with secret literal"),
        );
    }
    if lc.contains("background: false") {
        out.push(Finding::new(BG_SCAN_OFF, file, file).observed("background: false"));
    }

    out
}
