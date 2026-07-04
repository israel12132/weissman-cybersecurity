//! Backstage developer-portal analyzer — guest auth, inline secrets in app-config, permissive CORS,
//! and TechDocs storage misconfigurations.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "backstage",
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

pub const GUEST_AUTH: PolicyMeta = pol!(
    "WZ-BS-001",
    "Backstage auth provider disabled or guest access enabled",
    Critical,
    "app-config disables auth or enables dangerouslyAllowGuestAccess — unauthenticated portal access.",
    "Enable OAuth/OIDC auth provider; set dangerouslyAllowGuestAccess: false; enforce RBAC.",
    "T1078",
    "CWE-306",
    &["OWASP-A07"],
    &["NIST-AC-3", "SOC2-CC6.1", "ISO27001-A.9.4"]
);
pub const INLINE_SECRETS: PolicyMeta = pol!(
    "WZ-BS-002",
    "Backstage app-config embeds cloud or SCM credentials",
    Critical,
    "AWS/GITHUB/GITLAB tokens or passwords appear as literals in app-config.yaml.",
    "Use Kubernetes secrets + env substitution; integrate External Secrets Operator.",
    "T1552.001",
    "CWE-798",
    &["CIS-Secrets"],
    &["NIST-IA-5", "PCI-DSS-8.2.1", "ISO27001-A.10.1"]
);
pub const ADMIN_URL_EXPOSED: PolicyMeta = pol!(
    "WZ-BS-003",
    "Backstage catalog-info exposes internal admin or debug URLs",
    High,
    "catalog-info annotations or links point to /admin, /debug, or internal-only endpoints.",
    "Remove admin URLs from catalog; use internal-only TechDocs and restricted annotations.",
    "T1190",
    "CWE-200",
    &["OWASP-A01"],
    &["NIST-AC-3", "SOC2-CC6.6", "ISO27001-A.13.1"]
);
pub const PERMISSIVE_CORS: PolicyMeta = pol!(
    "WZ-BS-004",
    "Backstage CORS allows wildcard origin",
    High,
    "backend.cors.origin: '*' or methods include unsafe cross-origin access.",
    "Enumerate explicit origins; restrict methods; enable credentials only for trusted domains.",
    "T1190",
    "CWE-942",
    &["OWASP-A05"],
    &["NIST-SC-8", "PCI-DSS-6.5.10", "ISO27001-A.13.1"]
);
pub const TECHDOCS_PUBLIC_S3: PolicyMeta = pol!(
    "WZ-BS-005",
    "Backstage TechDocs publisher uses public or unencrypted object storage",
    Medium,
    "techdocs.publisher.awsS3 or GCS bucket lacks encryption and uses public-read ACL.",
    "Use private buckets with SSE-KMS; scope IAM to Backstage SA only.",
    "T1530",
    "CWE-284",
    &["CIS-Storage"],
    &["NIST-SC-28", "SOC2-CC6.1", "ISO27001-A.8.24"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        GUEST_AUTH,
        INLINE_SECRETS,
        ADMIN_URL_EXPOSED,
        PERMISSIVE_CORS,
        TECHDOCS_PUBLIC_S3,
    ]
}

fn is_backstage(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.contains("backstage")
        || n == "app-config.yaml"
        || n == "app-config.yml"
        || n.ends_with("catalog-info.yaml")
        || lc.contains("backstage.io")
        || lc.contains("kind: location") && lc.contains("backstage")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_backstage(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("dangerouslyallowguestaccess: true")
        || lc.contains("auth:\n  environment: development")
        || (lc.contains("auth:") && lc.contains("providers: []"))
        || lc.contains("guest: true")
    {
        out.push(Finding::new(GUEST_AUTH, file, file).observed("guest or disabled auth"));
    }
    if lc.contains("aws_access_key")
        || lc.contains("aws_secret_access_key")
        || lc.contains("github_token:")
        || lc.contains("gitlab_token:")
        || lc.contains("password:") && (lc.contains("integration") || lc.contains("auth"))
    {
        out.push(
            Finding::new(INLINE_SECRETS, file, file).observed("inline credentials in app-config"),
        );
    }
    if lc.contains("/admin") || lc.contains("/debug") || lc.contains("actuator") {
        out.push(
            Finding::new(ADMIN_URL_EXPOSED, file, file).observed("admin/debug URL in catalog"),
        );
    }
    if lc.contains("origin: '*'")
        || lc.contains("origin: \"*\"")
        || lc.contains("allowedorigins: '*'")
    {
        out.push(Finding::new(PERMISSIVE_CORS, file, file).observed("wildcard CORS origin"));
    }
    if (lc.contains("techdocs") || lc.contains("awss3"))
        && (lc.contains("publicread")
            || lc.contains("public-read")
            || lc.contains("blockpublicaccess: false"))
    {
        out.push(Finding::new(TECHDOCS_PUBLIC_S3, file, file).observed("public TechDocs storage"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_guest_auth() {
        let y = "app:\n  title: Portal\nauth:\n  environment: development\n  dangerouslyAllowGuestAccess: true";
        let f = evaluate("app-config.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == GUEST_AUTH.id));
    }
}
