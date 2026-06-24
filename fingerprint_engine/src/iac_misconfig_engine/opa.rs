//! OPA / Gatekeeper analyzer — Rego policies and ConstraintTemplates with dangerous default
//! allow, wildcard subjects, or disabled validation.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "opa", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const REGO_DEFAULT_ALLOW: PolicyMeta = pol!("WZ-OPA-001", "OPA Rego policy uses default allow", Critical, "default allow = true or missing deny rules — policy permits everything when evaluation fails.", "Use default deny; explicit allow only for matched conditions.", "T1190", "CWE-693", &["CIS-K8S-5.7.1"], &["NIST-AC-3", "SOC2-CC6.1"]);
pub const GK_DISABLED: PolicyMeta = pol!("WZ-OPA-002", "Gatekeeper Constraint enforcement action disabled", High, "enforcementAction: dryrun or disabled on security Constraint.", "Set enforcementAction: deny for production constraints.", "T1562", "CWE-693", &["CIS-K8S-5.7.1"], &["NIST-CM-7", "SOC2-CC8.1"]);
pub const WILDCARD_EXEMPT: PolicyMeta = pol!("WZ-OPA-003", "Gatekeeper Constraint exempts wildcard namespace", High, "exemptNamespaces includes * or kube-system without narrow scope.", "Remove wildcard exemptions; scope to specific break-glass namespaces.", "T1098", "CWE-732", &["CIS-K8S-5.7.1"], &["NIST-AC-6", "SOC2-CC6.3"]);
pub const UNSAFE_BUILTIN: PolicyMeta = pol!("WZ-OPA-004", "Rego uses http.send or external data without TLS verify", Medium, "http.send or graphql.send in Rego without force_json_decode/tls verification.", "Avoid external calls in admission policies; cache decisions offline.", "T1190", "CWE-295", &["CIS-K8S-5.7.1"], &["NIST-SC-8", "PCI-DSS-4.1"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![REGO_DEFAULT_ALLOW, GK_DISABLED, WILDCARD_EXEMPT, UNSAFE_BUILTIN]
}

fn is_opa(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.ends_with(".rego") || lc.contains("package ") && lc.contains("allow")
        || lc.contains("templates.gatekeeper.sh") || lc.contains("kind: constraint")
        || lc.contains("kind: constrainttemplate")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_opa(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("default allow := true") || lc.contains("default allow = true") {
        out.push(Finding::new(REGO_DEFAULT_ALLOW, file, file).observed("default allow = true"));
    }
    if lc.contains("enforcementaction: dryrun") || lc.contains("enforcementaction: disabled") {
        out.push(Finding::new(GK_DISABLED, file, file).observed("enforcementAction dryrun/disabled"));
    }
    if lc.contains("exemptnamespaces") && lc.contains("*") {
        out.push(Finding::new(WILDCARD_EXEMPT, file, file).observed("wildcard exemptNamespaces"));
    }
    if lc.contains("http.send") || lc.contains("graphql.send") {
        out.push(Finding::new(UNSAFE_BUILTIN, file, file).observed("external call in Rego"));
    }

    out
}
