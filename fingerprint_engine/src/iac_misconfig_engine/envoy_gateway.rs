//! Envoy Gateway (gateway.envoyproxy.io) analyzer — cleartext listeners, wildcard hosts,
//! disabled JWT/ext_authz, exposed admin, and upstream TLS verification bypass.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "envoy_gateway", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const CLEARTEXT_LISTENER: PolicyMeta = pol!(
    "WZ-EGW-001",
    "Envoy Gateway listener allows cleartext HTTP",
    High,
    "GatewayClass/HTTPRoute or EnvoyProxy config exposes HTTP without TLS termination.",
    "Terminate TLS at Gateway; redirect HTTP→HTTPS; enforce minimum TLS 1.2.",
    "T1040",
    "CWE-319",
    &["CIS-K8S-5.7.2"],
    &["NIST-SC-8", "PCI-DSS-4.1", "ISO27001-A.10.1"]
);
pub const JWT_DISABLED: PolicyMeta = pol!(
    "WZ-EGW-002",
    "Envoy Gateway SecurityPolicy disables JWT or ext_authz",
    Critical,
    "jwt.disabled: true or extAuthz backend omitted on public listener.",
    "Enable JWT validation with issuer/audience; wire ext_authz to OPA/AuthZ service.",
    "T1078",
    "CWE-306",
    &["OWASP-API2"],
    &["NIST-IA-2", "SOC2-CC6.1", "ISO27001-A.9.4"]
);
pub const WILDCARD_HOST: PolicyMeta = pol!(
    "WZ-EGW-003",
    "Envoy Gateway HTTPRoute uses wildcard hostname",
    High,
    "hostname: '*' or empty hostnames with catch-all rules — route hijack risk.",
    "Enumerate explicit hostnames; scope routes per tenant.",
    "T1190",
    "CWE-284",
    &["CIS-K8S-5.7.2"],
    &["NIST-AC-3", "SOC2-CC6.6", "ISO27001-A.13.1"]
);
pub const ADMIN_EXPOSED: PolicyMeta = pol!(
    "WZ-EGW-004",
    "Envoy admin interface bound to 0.0.0.0",
    Critical,
    "admin.address or envoy admin port exposed on 0.0.0.0/0 — config dump and cluster takeover.",
    "Bind admin to 127.0.0.1; disable on data plane; protect with NetworkPolicy.",
    "T1190",
    "CWE-306",
    &["Envoy-Hardening"],
    &["NIST-AC-3", "PCI-DSS-2.2.4", "ISO27001-A.8.20"]
);
pub const TLS_VERIFY_SKIP: PolicyMeta = pol!(
    "WZ-EGW-005",
    "Envoy upstream TLS verification disabled",
    Medium,
    "insecureSkipVerify: true or validateServerCertificate: false on Backend/Cluster.",
    "Enable full chain validation; pin CA; use mesh mTLS for east-west.",
    "T1557",
    "CWE-295",
    &["CIS-K8S-5.7.2"],
    &["NIST-SC-12", "PCI-DSS-4.1", "ISO27001-A.10.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![CLEARTEXT_LISTENER, JWT_DISABLED, WILDCARD_HOST, ADMIN_EXPOSED, TLS_VERIFY_SKIP]
}

fn is_envoy_gateway(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.contains("envoy-gateway")
        || n.contains("envoygateway")
        || lc.contains("gateway.envoyproxy.io")
        || lc.contains("gatewayclass")
            && lc.contains("envoy")
        || lc.contains("kind: envoyproxy")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_envoy_gateway(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("protocol: http") && !lc.contains("httpsredirect") && !lc.contains("tls:") {
        out.push(Finding::new(CLEARTEXT_LISTENER, file, file).observed("cleartext HTTP listener"));
    }
    if lc.contains("jwt:") && (lc.contains("disabled: true") || lc.contains("enable: false"))
        || lc.contains("extauthz:") && lc.contains("disabled: true")
    {
        out.push(Finding::new(JWT_DISABLED, file, file).observed("JWT/ext_authz disabled"));
    }
    if lc.contains("hostname: '*'") || lc.contains("hostnames:\n  - '*'") || lc.contains("hostnames: ['*']") {
        out.push(Finding::new(WILDCARD_HOST, file, file).observed("wildcard hostname"));
    }
    if lc.contains("0.0.0.0:9901") || lc.contains("admin:\n  address:") && lc.contains("0.0.0.0") {
        out.push(Finding::new(ADMIN_EXPOSED, file, file).observed("admin on 0.0.0.0"));
    }
    if lc.contains("insecureskipverify: true") || lc.contains("validateservercertificate: false") {
        out.push(Finding::new(TLS_VERIFY_SKIP, file, file).observed("upstream TLS verify disabled"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_admin_exposed() {
        let y = "apiVersion: gateway.envoyproxy.io/v1alpha1\nkind: EnvoyProxy\nspec:\n  admin:\n    address: 0.0.0.0:9901";
        let f = evaluate("envoy-gateway/proxy.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == ADMIN_EXPOSED.id));
    }
}
