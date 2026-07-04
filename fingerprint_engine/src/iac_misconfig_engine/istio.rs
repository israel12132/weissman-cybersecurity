//! Istio service mesh analyzer — permissive mTLS, ALLOW_ALL authorization, and wide egress.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "istio",
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

pub const MTLS_PERMISSIVE: PolicyMeta = pol!(
    "WZ-IST-001",
    "Istio PeerAuthentication mTLS mode PERMISSIVE",
    High,
    "mTLS PERMISSIVE allows plaintext sidecar traffic — MITM and lateral movement.",
    "Set mtls.mode: STRICT mesh-wide via PeerAuthentication or meshConfig.",
    "T1040",
    "CWE-319",
    &["CIS-K8S-5.7.2"],
    &["NIST-SC-8", "PCI-DSS-4.1"]
);
pub const AUTHZ_ALLOW_ALL: PolicyMeta = pol!(
    "WZ-IST-002",
    "Istio AuthorizationPolicy allows all principals",
    Critical,
    "rules with empty from / sources / namespaces — zero-trust bypass.",
    "Explicitly allow only required service accounts and namespaces.",
    "T1021",
    "CWE-284",
    &["CIS-K8S-5.7.2"],
    &["NIST-AC-3", "SOC2-CC6.6"]
);
pub const EGRESS_WILDCARD: PolicyMeta = pol!(
    "WZ-IST-003",
    "Istio ServiceEntry exposes wildcard external hosts",
    High,
    "hosts: [\"*.\"] or \"*\" in ServiceEntry enables unrestricted egress.",
    "Enumerate required external hosts; use EGRESS gateways with authorization.",
    "T1071",
    "CWE-668",
    &["CIS-K8S-5.7.2"],
    &["NIST-SC-7", "PCI-DSS-1.3.4"]
);
pub const SIDECAR_OUTBOUND_ALL: PolicyMeta = pol!(
    "WZ-IST-004",
    "Istio Sidecar captures all outbound traffic without restriction",
    Medium,
    "outboundTrafficPolicy: ALLOW_ANY on Sidecar without ServiceEntry scoping.",
    "Set REGISTRY_ONLY or explicit egress hosts.",
    "T1071",
    "CWE-668",
    &["CIS-K8S-5.7.2"],
    &["NIST-SC-7", "SOC2-CC6.6"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        MTLS_PERMISSIVE,
        AUTHZ_ALLOW_ALL,
        EGRESS_WILDCARD,
        SIDECAR_OUTBOUND_ALL,
    ]
}

fn is_istio(name: &str, content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("security.istio.io")
        || lc.contains("networking.istio.io")
        || name.to_ascii_lowercase().contains("istio")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_istio(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("mode: permissive") || lc.contains("mtls:\n    mode: permissive") {
        out.push(Finding::new(MTLS_PERMISSIVE, file, file).observed("mTLS PERMISSIVE"));
    }
    if lc.contains("kind: authorizationpolicy")
        && (lc.contains("rules: []") || lc.contains("action: allow") && !lc.contains("from:"))
    {
        out.push(
            Finding::new(AUTHZ_ALLOW_ALL, file, file).observed("AuthorizationPolicy allow-all"),
        );
    }
    if lc.contains("kind: serviceentry")
        && (lc.contains("hosts:\n  - '*'")
            || lc.contains("hosts:\n  - \"*\"")
            || lc.contains("*.com"))
    {
        out.push(Finding::new(EGRESS_WILDCARD, file, file).observed("wildcard ServiceEntry hosts"));
    }
    if lc.contains("outboundtrafficpolicy: allow_any") {
        out.push(Finding::new(SIDECAR_OUTBOUND_ALL, file, file).observed("ALLOW_ANY outbound"));
    }

    out
}
