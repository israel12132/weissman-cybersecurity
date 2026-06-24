//! Helmfile orchestrator analyzer — secret literals in setValues, mutable chart versions,
//! and unsafe release hooks for production deployments.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "helmfile", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const SETVALUES_SECRET: PolicyMeta = pol!(
    "WZ-HLF-001",
    "Helmfile setValues embeds secret literal",
    Critical,
    "setValues or values block in helmfile.yaml contains password/token/apiKey literal.",
    "Use helm-secrets, SOPS-encrypted values, or external-secrets references.",
    "T1552.001",
    "CWE-798",
    &["CIS-K8S-5.x"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const CHART_VERSION_WILDCARD: PolicyMeta = pol!(
    "WZ-HLF-002",
    "Helmfile release uses mutable chart version",
    High,
    "version: * or missing version on chart — pulls latest mutable chart on every sync.",
    "Pin chart version to immutable semver; use OCI registry with digest pinning.",
    "T1195.001",
    "CWE-494",
    &["CIS-Supply"],
    &["NIST-SA-12", "SOC2-CC8.1"]
);
pub const WAIT_FALSE_PROD: PolicyMeta = pol!(
    "WZ-HLF-003",
    "Helmfile production release with wait disabled",
    High,
    "wait: false on release in production context — broken deployments may go unnoticed.",
    "Set wait: true and timeout; add helm test hooks for critical releases.",
    "T1195",
    "CWE-693",
    &["CIS-CI"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const MISSING_ATOMIC: PolicyMeta = pol!(
    "WZ-HLF-004",
    "Helmfile release without atomic rollback",
    Medium,
    "atomic: false or missing on production release — failed upgrades leave cluster in partial state.",
    "Enable atomic: true and cleanupOnFail for production helmfile releases.",
    "T1490",
    "CWE-693",
    &["CIS-CI"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const INSECURE_REPO: PolicyMeta = pol!(
    "WZ-HLF-005",
    "Helmfile chart repository uses cleartext HTTP",
    High,
    "repository URL uses http:// for chart source — MITM and chart substitution risk.",
    "Use https:// or OCI registries with signature verification.",
    "T1195.002",
    "CWE-319",
    &["CIS-Supply"],
    &["NIST-SC-8", "PCI-DSS-4.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![SETVALUES_SECRET, CHART_VERSION_WILDCARD, WAIT_FALSE_PROD, MISSING_ATOMIC, INSECURE_REPO]
}

fn is_helmfile(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n == "helmfile.yaml"
        || n == "helmfile.yml"
        || n.ends_with(".helmfile.yaml")
        || n.contains("helmfile")
        || lc.contains("releases:") && lc.contains("chart:")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_helmfile(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    for key in ["password", "apikey", "token", "secret"] {
        if (lc.contains("setvalues") || lc.contains("values:")) && lc.contains(key) {
            out.push(Finding::new(SETVALUES_SECRET, file, file).observed(format!("setValues literal {key}")));
            break;
        }
    }
    if lc.contains("version: '*'") || lc.contains("version: \"*\"") || (lc.contains("chart:") && !lc.contains("version:")) {
        out.push(Finding::new(CHART_VERSION_WILDCARD, file, file).observed("mutable/missing chart version"));
    }
    if lc.contains("wait: false") {
        out.push(Finding::new(WAIT_FALSE_PROD, file, file).observed("wait: false"));
    }
    if lc.contains("atomic: false") || (lc.contains("releases:") && !lc.contains("atomic:")) {
        out.push(Finding::new(MISSING_ATOMIC, file, file).observed("atomic rollback not enabled"));
    }
    if lc.contains("repository: http://") || lc.contains("chart: http://") {
        out.push(Finding::new(INSECURE_REPO, file, file).observed("http chart repository"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_secret_setvalues() {
        let y = "releases:\n  - name: api\n    chart: ./charts/api\n    setValues:\n      - name: db.password\n        value: SuperSecret123!";
        let f = evaluate("helmfile.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == SETVALUES_SECRET.id));
    }
}
