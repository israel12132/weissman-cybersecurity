//! Skaffold dev/deploy pipeline analyzer — mutable image tags, insecure build args with secrets,
//! and port-forward to production profiles.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "skaffold", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const LATEST_TAG: PolicyMeta = pol!(
    "WZ-SKF-001",
    "Skaffold deploys mutable image tag (latest)",
    High,
    "image tag :latest or no digest pin in Skaffold manifest — non-reproducible deploys.",
    "Pin image digest or immutable semver tag in Skaffold artifacts.",
    "T1195.001",
    "CWE-494",
    &["CIS-Supply"],
    &["NIST-SA-12", "SOC2-CC8.1"]
);
pub const BUILD_SECRET: PolicyMeta = pol!(
    "WZ-SKF-002",
    "Skaffold buildArgs embed secret literal",
    Critical,
    "buildArgs or env contains password/token/apiKey literal in skaffold.yaml.",
    "Use build secrets (--secret) or CI-injected env; never commit literals.",
    "T1552.001",
    "CWE-798",
    &["CIS-Secrets"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const PORT_FORWARD_PROD: PolicyMeta = pol!(
    "WZ-SKF-003",
    "Skaffold portForward enabled on production profile",
    High,
    "portForward stanza in prod/production profile — exposes cluster services locally without auth.",
    "Remove portForward from production profiles; use kubectl port-forward with RBAC only.",
    "T1021",
    "CWE-668",
    &["CIS-K8S-5.x"],
    &["NIST-AC-6", "SOC2-CC6.6"]
);
pub const INSECURE_REGISTRY: PolicyMeta = pol!(
    "WZ-SKF-004",
    "Skaffold pushes to insecure HTTP registry",
    High,
    "cluster push or custom build pushes to http:// registry endpoint.",
    "Use HTTPS/OCI registries with image signing and admission policies.",
    "T1195.002",
    "CWE-319",
    &["CIS-Supply"],
    &["NIST-SC-8", "PCI-DSS-4.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![LATEST_TAG, BUILD_SECRET, PORT_FORWARD_PROD, INSECURE_REGISTRY]
}

fn is_skaffold(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n == "skaffold.yaml" || n == "skaffold.yml" || n.ends_with(".skaffold.yaml") || lc.contains("apiversion: skaffold")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_skaffold(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains(":latest") || (lc.contains("image:") && !lc.contains("digest:") && !lc.contains("@sha256")) {
        out.push(Finding::new(LATEST_TAG, file, file).observed("mutable latest tag"));
    }
    for key in ["password", "apikey", "token", "secret"] {
        if (lc.contains("buildargs") || lc.contains("env:")) && lc.contains(key) {
            out.push(Finding::new(BUILD_SECRET, file, file).observed(format!("build secret {key}")));
            break;
        }
    }
    if lc.contains("portforward:") && (lc.contains("prod") || lc.contains("production")) {
        out.push(Finding::new(PORT_FORWARD_PROD, file, file).observed("portForward in prod profile"));
    }
    if lc.contains("http://") && (lc.contains("push") || lc.contains("registry")) {
        out.push(Finding::new(INSECURE_REGISTRY, file, file).observed("http registry push"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_latest_and_secret() {
        let y = "apiVersion: skaffold/v4beta7\nkind: Config\nbuild:\n  artifacts:\n    - image: payments/api:latest\n      docker:\n        buildArgs:\n          API_KEY: SuperSecret123!";
        let f = evaluate("skaffold.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == LATEST_TAG.id));
        assert!(f.iter().any(|x| x.policy.id == BUILD_SECRET.id));
    }
}
