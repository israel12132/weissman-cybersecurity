//! Prometheus Operator / Grafana stack analyzer — insecure scrape TLS, admin passwords, and
//! cross-namespace ServiceMonitor exposure.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "prometheus_operator",
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

pub const TLS_SKIP: PolicyMeta = pol!(
    "WZ-PRM-001",
    "ServiceMonitor/PodMonitor skips TLS verification on scrape",
    High,
    "spec.endpoints[].tlsConfig.insecureSkipVerify: true — MITM on metrics path.",
    "Enable TLS verification; use cert-manager for scrape targets; pin CA.",
    "T1557",
    "CWE-295",
    &["CIS-K8S-5.7.2"],
    &["NIST-SC-8", "PCI-DSS-4.1", "ISO27001-A.8.24"]
);
pub const GRAFANA_ADMIN_PASS: PolicyMeta = pol!(
    "WZ-PRM-002",
    "Grafana admin password embedded in manifest",
    Critical,
    "Grafana CR or values set adminPassword/adminUser literals in YAML.",
    "Use Kubernetes Secret + envFrom; integrate SSO/OIDC for Grafana.",
    "T1552.001",
    "CWE-798",
    &["CIS-Secrets"],
    &["NIST-IA-5", "PCI-DSS-8.2.1", "SOC2-CC6.1"]
);
pub const ANY_NAMESPACE: PolicyMeta = pol!(
    "WZ-PRM-003",
    "Prometheus allows ServiceMonitor from any namespace",
    Medium,
    "Prometheus spec.serviceMonitorNamespaceSelector: {} or matchLabels missing — cluster-wide scrape.",
    "Restrict serviceMonitorNamespaceSelector to observability namespaces.",
    "T1040",
    "CWE-200",
    &["CIS-K8S-5.1.3"],
    &["NIST-AC-4", "SOC2-CC6.6"]
);
pub const WEBHOOK_NO_AUTH: PolicyMeta = pol!(
    "WZ-PRM-004",
    "Alertmanager receiver webhook without authentication",
    High,
    "AlertmanagerConfig receiver uses http_config without basic_auth or bearer_token.",
    "Add bearer_token_file or OAuth2; restrict webhook endpoints to internal networks.",
    "T1190",
    "CWE-306",
    &["CIS-Monitoring"],
    &["NIST-AC-3", "PCI-DSS-6.5.10"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![TLS_SKIP, GRAFANA_ADMIN_PASS, ANY_NAMESPACE, WEBHOOK_NO_AUTH]
}

fn is_prometheus_stack(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.contains("prometheus")
        || n.contains("grafana")
        || n.contains("alertmanager")
        || lc.contains("monitoring.coreos.com")
        || lc.contains("kind: servicemonitor")
        || lc.contains("kind: podmonitor")
        || lc.contains("kind: prometheusrule")
        || lc.contains("kind: alertmanagerconfig")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_prometheus_stack(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("insecureskipverify: true") {
        out.push(Finding::new(TLS_SKIP, file, file).observed("insecureSkipVerify on scrape"));
    }
    if lc.contains("adminpassword:")
        || lc.contains("admin_password:")
        || lc.contains("gf_security_admin_password")
    {
        out.push(
            Finding::new(GRAFANA_ADMIN_PASS, file, file).observed("Grafana admin password literal"),
        );
    }
    if lc.contains("servicemonitornamespaceselector: {}")
        || lc.contains("podmonitornamespaceselector: {}")
    {
        out.push(
            Finding::new(ANY_NAMESPACE, file, file).observed("any-namespace monitor selector"),
        );
    }
    if lc.contains("webhook_configs:") && !lc.contains("bearer_token") && !lc.contains("basic_auth")
    {
        out.push(Finding::new(WEBHOOK_NO_AUTH, file, file).observed("webhook without auth"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_tls_skip() {
        let y = "apiVersion: monitoring.coreos.com/v1\nkind: ServiceMonitor\nspec:\n  endpoints:\n    - tlsConfig:\n        insecureSkipVerify: true";
        let f = evaluate("monitoring/servicemonitor.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == TLS_SKIP.id));
    }
}
