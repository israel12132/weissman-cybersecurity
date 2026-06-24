//! External Secrets Operator analyzer — overly broad ClusterSecretStore, weak refresh intervals,
//! and plaintext secret references in ExternalSecret manifests.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "external_secrets", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const CLUSTER_STORE_CREDS: PolicyMeta = pol!(
    "WZ-ESO-001",
    "ClusterSecretStore embeds cloud credentials in manifest",
    Critical,
    "ClusterSecretStore spec contains accessKeyID, secretAccessKey, or serviceAccountKey inline.",
    "Use workload identity / IRSA / Workload Identity; reference Kubernetes Secret for auth only.",
    "T1552.001",
    "CWE-798",
    &["CIS-K8S-5.4.1"],
    &["NIST-IA-5", "PCI-DSS-8.2.1", "SOC2-CC6.1"]
);
pub const REFRESH_TOO_SLOW: PolicyMeta = pol!(
    "WZ-ESO-002",
    "ExternalSecret refreshInterval too slow for production",
    Medium,
    "refreshInterval > 1h on production ExternalSecret — stale secrets after rotation.",
    "Set refreshInterval <= 15m for production; enable rotation hooks.",
    "T1552",
    "CWE-324",
    &["CIS-K8S-5.4.1"],
    &["NIST-IA-5", "SOC2-CC6.7"]
);
pub const LITERAL_TARGET: PolicyMeta = pol!(
    "WZ-ESO-003",
    "ExternalSecret dataFrom embeds secret literal",
    High,
    "data or dataFrom block contains password/token literal instead of remote key reference.",
    "Reference remoteRef.key only; never embed secret values in ExternalSecret YAML.",
    "T1552.001",
    "CWE-798",
    &["CIS-K8S-5.4.1"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const WILDCARD_STORE: PolicyMeta = pol!(
    "WZ-ESO-004",
    "ClusterSecretStore grants wildcard secret path access",
    High,
    "ClusterSecretStore path or role allows * or /** on vault/aws paths — over-broad secret pull.",
    "Scope provider paths to application prefixes; use namespace-scoped SecretStore.",
    "T1098",
    "CWE-732",
    &["CIS-K8S-5.4.1"],
    &["NIST-AC-6", "SOC2-CC6.3"]
);
pub const NO_CREATION_POLICY: PolicyMeta = pol!(
    "WZ-ESO-005",
    "ExternalSecret missing creationPolicy Owner",
    Medium,
    "creationPolicy: Merge or Orphan — orphaned secrets survive workload deletion.",
    "Set creationPolicy: Owner so secrets are garbage-collected with the workload.",
    "T1098",
    "CWE-693",
    &["CIS-K8S-5.4.1"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![CLUSTER_STORE_CREDS, REFRESH_TOO_SLOW, LITERAL_TARGET, WILDCARD_STORE, NO_CREATION_POLICY]
}

fn is_eso(name: &str, content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("external-secrets.io")
        || lc.contains("kind: externalsecret")
        || lc.contains("kind: clustersecretstore")
        || lc.contains("kind: secretstore")
        || name.to_ascii_lowercase().contains("externalsecret")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_eso(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("accesskeyid") || lc.contains("secretaccesskey") || lc.contains("serviceaccountkey") {
        out.push(Finding::new(CLUSTER_STORE_CREDS, file, file).observed("inline cloud credentials in store"));
    }
    if lc.contains("refreshinterval: 24h") || lc.contains("refreshinterval: 12h") || lc.contains("refreshinterval: 6h") {
        out.push(Finding::new(REFRESH_TOO_SLOW, file, file).observed("slow refreshInterval"));
    }
    if (lc.contains("data:") || lc.contains("datafrom:"))
        && (lc.contains("password:") || lc.contains("token:") || lc.contains("apikey:"))
        && !lc.contains("remoteref:")
    {
        out.push(Finding::new(LITERAL_TARGET, file, file).observed("literal in ExternalSecret data"));
    }
    if lc.contains("path: \"*\"") || lc.contains("path: '*'") || lc.contains("role: \"*\"") {
        out.push(Finding::new(WILDCARD_STORE, file, file).observed("wildcard secret path/role"));
    }
    if lc.contains("creationpolicy: merge") || lc.contains("creationpolicy: orphan") {
        out.push(Finding::new(NO_CREATION_POLICY, file, file).observed("non-Owner creationPolicy"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_inline_store_creds() {
        let y = "apiVersion: external-secrets.io/v1beta1\nkind: ClusterSecretStore\nspec:\n  provider:\n    aws:\n      service: SecretsManager\n      accessKeyID: AKIAIOSFODNN7EXAMPLE\n      secretAccessKey: wJalr";
        let f = evaluate("eso/store.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == CLUSTER_STORE_CREDS.id));
    }
}
