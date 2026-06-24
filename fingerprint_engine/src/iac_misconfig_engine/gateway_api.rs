//! Kubernetes Gateway API analyzer — cleartext listeners, wildcard hostnames, missing TLS
//! termination, and HTTPRoute rules exposing admin paths without filters.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "gateway_api", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const HTTP_LISTENER: PolicyMeta = pol!(
    "WZ-GW-001",
    "Gateway API listener uses HTTP protocol on production",
    High,
    "Gateway spec.listeners[].protocol is HTTP without TLS termination — cleartext ingress.",
    "Use HTTPS protocol with certificateRefs; enforce TLS 1.2+ at Gateway.",
    "T1040",
    "CWE-319",
    &["CIS-K8S-5.7.2"],
    &["NIST-SC-8", "PCI-DSS-4.1"]
);
pub const WILDCARD_HOST: PolicyMeta = pol!(
    "WZ-GW-002",
    "HTTPRoute allows wildcard hostname",
    High,
    "hostnames includes * or empty hostnames with catch-all rules — unintended route hijack.",
    "Enumerate explicit hostnames per route; use ReferenceGrant to scope cross-namespace.",
    "T1190",
    "CWE-284",
    &["CIS-K8S-5.7.2"],
    &["NIST-AC-3", "SOC2-CC6.6"]
);
pub const NO_TLS_TERMINATION: PolicyMeta = pol!(
    "WZ-GW-003",
    "Gateway HTTPS listener missing TLS certificateRef",
    Critical,
    "HTTPS listener without tls.certificateRefs or mode: Terminate — broken or passthrough TLS.",
    "Attach cert-manager Certificate or Kubernetes TLS secret via certificateRefs.",
    "T1557",
    "CWE-295",
    &["CIS-K8S-5.7.2"],
    &["NIST-SC-12", "PCI-DSS-4.1"]
);
pub const ADMIN_PATH_EXPOSED: PolicyMeta = pol!(
    "WZ-GW-004",
    "HTTPRoute exposes /admin or /debug path without filter",
    Critical,
    "HTTPRoute matches /admin, /debug, /actuator without URLRewrite or RequestHeader filter.",
    "Remove admin paths from public routes; add authentication filter or internal Gateway only.",
    "T1190",
    "CWE-306",
    &["OWASP-API2"],
    &["NIST-AC-3", "PCI-DSS-6.5.10"]
);
pub const CROSS_NS_REF: PolicyMeta = pol!(
    "WZ-GW-005",
    "HTTPRoute references backend in another namespace without policy",
    Medium,
    "backendRefs namespace differs from route namespace — verify ReferenceGrant exists.",
    "Add ReferenceGrant with explicit from/to; default-deny cross-namespace backend refs.",
    "T1021",
    "CWE-668",
    &["CIS-K8S-5.7.2"],
    &["NIST-AC-6", "SOC2-CC6.6"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![HTTP_LISTENER, WILDCARD_HOST, NO_TLS_TERMINATION, ADMIN_PATH_EXPOSED, CROSS_NS_REF]
}

fn is_gateway_api(name: &str, content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("gateway.networking.k8s.io")
        || lc.contains("kind: gateway")
        || lc.contains("kind: httproute")
        || lc.contains("kind: grpcroute")
        || name.to_ascii_lowercase().contains("gateway")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_gateway_api(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("protocol: http") && !lc.contains("protocol: https") {
        out.push(Finding::new(HTTP_LISTENER, file, file).observed("HTTP listener without TLS"));
    }
    if lc.contains("hostnames:") && (lc.contains("- '*'") || lc.contains("- \"*\"")) {
        out.push(Finding::new(WILDCARD_HOST, file, file).observed("wildcard hostname"));
    }
    if lc.contains("protocol: https") && !lc.contains("certificaterefs") && !lc.contains("mode: terminate") {
        out.push(Finding::new(NO_TLS_TERMINATION, file, file).observed("HTTPS without certificateRefs"));
    }
    for path in ["/admin", "/debug", "/actuator", "/metrics"] {
        if lc.contains(path) && lc.contains("kind: httproute") {
            out.push(Finding::new(ADMIN_PATH_EXPOSED, file, file).observed(format!("sensitive path {path}")));
            break;
        }
    }
    if lc.contains("backendrefs:") && lc.contains("namespace:") && !lc.contains("referencegrant") {
        out.push(Finding::new(CROSS_NS_REF, file, file).observed("cross-namespace backendRef"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_http_listener() {
        let y = "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\nspec:\n  listeners:\n    - protocol: HTTP\n      port: 80";
        let f = evaluate("gw.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == HTTP_LISTENER.id));
    }
}
