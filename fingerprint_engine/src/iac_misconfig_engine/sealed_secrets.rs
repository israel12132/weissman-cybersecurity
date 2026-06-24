//! Sealed Secrets analyzer — weak encryption, over-broad scope, and plaintext template leakage.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "sealed_secrets", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const WIDE_SCOPE: PolicyMeta = pol!(
    "WZ-SS-001",
    "SealedSecret scoped to all namespaces",
    High,
    "metadata.annotations sealedsecrets.bitnami.com/cluster-wide: 'true' without namespace RBAC guard.",
    "Scope SealedSecrets per namespace; restrict cluster-wide sealing to platform admins only.",
    "T1098",
    "CWE-668",
    &["CIS-K8S-5.1.3"],
    &["NIST-AC-6", "SOC2-CC6.1", "ISO27001-A.9.4"]
);
pub const WEAK_RSA: PolicyMeta = pol!(
    "WZ-SS-002",
    "Sealed Secrets controller uses weak RSA key size",
    Critical,
    "Sealing key or controller config references 1024-bit RSA or deprecated encryption.",
    "Rotate to 4096-bit RSA or use age/X25519; enforce key rotation policy.",
    "T1557",
    "CWE-326",
    &["CIS-Crypto"],
    &["NIST-SC-12", "PCI-DSS-3.6.1", "ISO27001-A.8.24"]
);
pub const PLAINTEXT_TEMPLATE: PolicyMeta = pol!(
    "WZ-SS-003",
    "SealedSecret template exposes plaintext secret data",
    Critical,
    "spec.template.data or stringData contains unencrypted literals alongside encryptedData.",
    "Remove plaintext template fields; only store encryptedData blobs.",
    "T1552.001",
    "CWE-312",
    &["CIS-Secrets"],
    &["NIST-IA-5", "PCI-DSS-3.4", "HIPAA-164.312(a)(1)"]
);
pub const NO_ROTATION: PolicyMeta = pol!(
    "WZ-SS-004",
    "Sealed Secrets lacks key rotation annotation",
    Medium,
    "SealedSecret missing sealedsecrets.bitnami.com/managed: 'true' on long-lived credentials.",
    "Enable controller-managed rotation; re-seal on key rotation events.",
    "T1552",
    "CWE-324",
    &["CIS-Secrets"],
    &["NIST-SC-12", "SOC2-CC6.1"]
);
pub const INSECURE_ANNOTATION: PolicyMeta = pol!(
    "WZ-SS-005",
    "SealedSecret annotation disables strict validation",
    High,
    "annotation sealedsecrets.bitnami.com/strict-validation: 'false' or skip-validation present.",
    "Enable strict validation; reject malformed or cross-namespace sealed payloads.",
    "T1190",
    "CWE-345",
    &["CIS-K8S-5.x"],
    &["NIST-SI-7", "ISO27001-A.8.24"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![WIDE_SCOPE, WEAK_RSA, PLAINTEXT_TEMPLATE, NO_ROTATION, INSECURE_ANNOTATION]
}

fn is_sealed_secret(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.contains("sealedsecret") || lc.contains("kind: sealedsecret") || lc.contains("bitnami.com/sealedsecret")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_sealed_secret(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("cluster-wide: 'true'") || lc.contains("cluster-wide: true") {
        out.push(Finding::new(WIDE_SCOPE, file, file).observed("cluster-wide SealedSecret"));
    }
    if lc.contains("rsa-1024") || lc.contains("keysize: 1024") || lc.contains("encryption: rsa") && lc.contains("1024") {
        out.push(Finding::new(WEAK_RSA, file, file).observed("weak RSA key size"));
    }
    if (lc.contains("stringdata:") || lc.contains("template:") && lc.contains("data:"))
        && !lc.contains("encrypteddata:")
    {
        out.push(Finding::new(PLAINTEXT_TEMPLATE, file, file).observed("plaintext template data"));
    }
    if lc.contains("encrypteddata:") && (lc.contains("stringdata:") || lc.contains("password:")) {
        out.push(Finding::new(PLAINTEXT_TEMPLATE, file, file).observed("plaintext alongside encryptedData"));
    }
    if lc.contains("strict-validation: 'false'") || lc.contains("skip-validation: true") {
        out.push(Finding::new(INSECURE_ANNOTATION, file, file).observed("strict validation disabled"));
    }
    if lc.contains("encrypteddata:") && !lc.contains("managed: 'true'") && !lc.contains("managed: true") {
        out.push(Finding::new(NO_ROTATION, file, file).observed("no managed rotation annotation"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_cluster_wide() {
        let y = "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  annotations:\n    sealedsecrets.bitnami.com/cluster-wide: 'true'";
        let f = evaluate("sealed/db.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == WIDE_SCOPE.id));
    }
}
