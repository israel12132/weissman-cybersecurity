//! cert-manager Certificate analyzer — weak key sizes, excessive validity, CA misuse,
//! and insecure ACME challenge methods for production.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "cert_manager", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const WEAK_KEY_SIZE: PolicyMeta = pol!(
    "WZ-CERT-001",
    "cert-manager Certificate uses weak RSA key size",
    High,
    "privateKey.size < 2048 or algorithm RSA with 1024-bit key.",
    "Use ECDSA P-256 or RSA 4096; enable privateKey.rotationPolicy: Always.",
    "T1557",
    "CWE-326",
    &["CIS-K8S-5.x"],
    &["NIST-SC-12", "PCI-DSS-4.1"]
);
pub const LONG_VALIDITY: PolicyMeta = pol!(
    "WZ-CERT-002",
    "cert-manager Certificate validity exceeds 90 days",
    Medium,
    "duration or renewBefore implies certificate lifetime > 90d — violates short-lived cert best practice.",
    "Set duration: 2160h (90d) or less; automate renewal with cert-manager.",
    "T1557",
    "CWE-295",
    &["CIS-K8S-5.x"],
    &["NIST-SC-12", "SOC2-CC6.7"]
);
pub const IS_CA_TRUE: PolicyMeta = pol!(
    "WZ-CERT-003",
    "cert-manager Certificate marked as CA",
    Critical,
    "isCA: true on namespaced Certificate — unintended intermediate CA in workload namespace.",
    "Use ClusterIssuer for CA certs only with strict RBAC; never isCA in app namespaces.",
    "T1588",
    "CWE-295",
    &["CIS-K8S-5.x"],
    &["NIST-SC-12", "SOC2-CC6.1"]
);
pub const ROTATION_NEVER: PolicyMeta = pol!(
    "WZ-CERT-004",
    "cert-manager private key rotationPolicy Never",
    High,
    "privateKey.rotationPolicy: Never — compromised keys persist for full cert lifetime.",
    "Set rotationPolicy: Always or set renewBefore aggressively with short duration.",
    "T1557",
    "CWE-324",
    &["CIS-K8S-5.x"],
    &["NIST-SC-12", "SOC2-CC6.7"]
);
pub const HTTP01_PROD: PolicyMeta = pol!(
    "WZ-CERT-005",
    "cert-manager ACME HTTP-01 solver on production ingress",
    Medium,
    "solver http01 on production Certificate — MITM and domain takeover risk vs DNS-01.",
    "Use DNS-01 with restricted IAM; scope HTTP-01 to staging only.",
    "T1557",
    "CWE-295",
    &["CIS-K8S-5.x"],
    &["NIST-SC-8", "PCI-DSS-4.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![WEAK_KEY_SIZE, LONG_VALIDITY, IS_CA_TRUE, ROTATION_NEVER, HTTP01_PROD]
}

fn is_cert_manager(name: &str, content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("cert-manager.io")
        || lc.contains("kind: certificate")
            && lc.contains("cert-manager")
        || lc.contains("kind: clusterissuer")
        || lc.contains("kind: issuer")
            && lc.contains("acme")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_cert_manager(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("size: 1024") || lc.contains("size: 512") {
        out.push(Finding::new(WEAK_KEY_SIZE, file, file).observed("RSA key size < 2048"));
    }
    if lc.contains("duration: 8760h") || lc.contains("duration: 17520h") || lc.contains("duration: 2160h0m0s") {
        // only flag clearly long durations
        if lc.contains("8760h") || lc.contains("17520h") {
            out.push(Finding::new(LONG_VALIDITY, file, file).observed("validity > 90 days"));
        }
    }
    if lc.contains("isca: true") {
        out.push(Finding::new(IS_CA_TRUE, file, file).observed("isCA: true"));
    }
    if lc.contains("rotationpolicy: never") {
        out.push(Finding::new(ROTATION_NEVER, file, file).observed("rotationPolicy Never"));
    }
    if lc.contains("http01:") && (lc.contains("prod") || lc.contains("production") || !lc.contains("staging")) {
        out.push(Finding::new(HTTP01_PROD, file, file).observed("HTTP-01 ACME solver"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_isca_and_weak_key() {
        let y = "apiVersion: cert-manager.io/v1\nkind: Certificate\nspec:\n  isCA: true\n  privateKey:\n    size: 1024\n    rotationPolicy: Never";
        let f = evaluate("cert.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == IS_CA_TRUE.id));
        assert!(f.iter().any(|x| x.policy.id == WEAK_KEY_SIZE.id));
    }
}
