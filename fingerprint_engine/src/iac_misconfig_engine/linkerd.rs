//! Linkerd service mesh analyzer — unauthenticated ServerAuthorization, disabled mesh TLS,
//! and tap/external exposure misconfigurations.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "linkerd", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const SA_ALLOW_ALL: PolicyMeta = pol!(
    "WZ-LDR-001",
    "Linkerd ServerAuthorization allows unauthenticated clients",
    Critical,
    "ServerAuthorization without requireAuthentication or with all-unauthenticated — any pod can call protected services.",
    "Set requireAuthentication: true and scope client identities via meshTLS or serviceAccount.",
    "T1021",
    "CWE-284",
    &["CIS-K8S-5.7.2"],
    &["NIST-AC-3", "SOC2-CC6.6"]
);
pub const MESH_TLS_OFF: PolicyMeta = pol!(
    "WZ-LDR-002",
    "Linkerd MeshTLSAuthentication disabled or permissive",
    High,
    "MeshTLSAuthentication with identity: '*' or disabled mesh TLS — plaintext east-west traffic.",
    "Require meshTLS identity per service; disable legacy proxy injection without TLS.",
    "T1040",
    "CWE-319",
    &["CIS-K8S-5.7.2"],
    &["NIST-SC-8", "PCI-DSS-4.1"]
);
pub const SERVER_NO_AUTH: PolicyMeta = pol!(
    "WZ-LDR-003",
    "Linkerd Server resource without authentication policy",
    High,
    "Server policy defines a port without paired ServerAuthorization — default allow applies.",
    "Attach ServerAuthorization with explicit client identities for every Server.",
    "T1021",
    "CWE-284",
    &["CIS-K8S-5.7.2"],
    &["NIST-AC-3", "SOC2-CC6.6"]
);
pub const INJECT_DISABLED: PolicyMeta = pol!(
    "WZ-LDR-004",
    "Linkerd proxy injection explicitly disabled on workload",
    Medium,
    "annotation linkerd.io/inject: disabled on Deployment/Namespace — bypasses mesh controls.",
    "Enable injection or use Linkerd control-plane namespace policy; document exceptions.",
    "T1562",
    "CWE-693",
    &["CIS-K8S-5.7.2"],
    &["NIST-CM-7", "SOC2-CC8.1"]
);
pub const TAP_EXPOSED: PolicyMeta = pol!(
    "WZ-LDR-005",
    "Linkerd tap or external workload exposure enabled",
    High,
    "Tap policy or external-workload annotation exposes live traffic inspection without RBAC guard.",
    "Restrict tap to break-glass RBAC; disable external-workload in production clusters.",
    "T1040",
    "CWE-200",
    &["CIS-K8S-5.7.2"],
    &["NIST-AU-12", "SOC2-CC7.2"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![SA_ALLOW_ALL, MESH_TLS_OFF, SERVER_NO_AUTH, INJECT_DISABLED, TAP_EXPOSED]
}

fn is_linkerd(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    lc.contains("policy.linkerd.io")
        || lc.contains("linkerd.io/inject")
        || n.contains("linkerd")
        || lc.contains("kind: serverauthorization")
        || lc.contains("kind: server")
            && lc.contains("policy.linkerd.io")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_linkerd(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("kind: serverauthorization")
        && (lc.contains("requireauthentication: false")
            || !lc.contains("requireauthentication")
            || lc.contains("unauthenticated: true"))
    {
        out.push(Finding::new(SA_ALLOW_ALL, file, file).observed("ServerAuthorization unauthenticated"));
    }
    if lc.contains("meshtlsauthentication") && (lc.contains("identity: '*'") || lc.contains("identity: \"*\"")) {
        out.push(Finding::new(MESH_TLS_OFF, file, file).observed("MeshTLS identity wildcard"));
    }
    if lc.contains("kind: server") && lc.contains("policy.linkerd.io") && !lc.contains("serverauthorization") {
        out.push(Finding::new(SERVER_NO_AUTH, file, file).observed("Server without ServerAuthorization"));
    }
    if lc.contains("linkerd.io/inject: disabled") || lc.contains("linkerd.io/inject: \"disabled\"") {
        out.push(Finding::new(INJECT_DISABLED, file, file).observed("proxy injection disabled"));
    }
    if (lc.contains("kind: authorizationpolicy") && lc.contains("tap")) || lc.contains("external-workload") {
        out.push(Finding::new(TAP_EXPOSED, file, file).observed("tap or external-workload exposure"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unauthenticated_serverauthorization() {
        let y = "apiVersion: policy.linkerd.io/v1beta1\nkind: ServerAuthorization\nmetadata:\n  name: all\nspec:\n  server:\n    name: api\n  client:\n    unauthenticated: true";
        let f = evaluate("linkerd/sa.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == SA_ALLOW_ALL.id));
    }
}
