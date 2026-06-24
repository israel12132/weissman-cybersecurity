//! Falco runtime rule analyzer — disabled rules, overly broad conditions, and missing SIEM output.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "falco", provider: "kubernetes",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const RULE_DISABLED: PolicyMeta = pol!(
    "WZ-FLC-001",
    "Falco rule explicitly disabled",
    High,
    "Rule stanza contains enabled: false — runtime detection suppressed.",
    "Enable rule; tune with exceptions instead of disabling.",
    "T1562",
    "CWE-693",
    &["CIS-Runtime"],
    &["NIST-SI-4", "SOC2-CC7.2"]
);
pub const CATCH_ALL: PolicyMeta = pol!(
    "WZ-FLC-002",
    "Falco custom rule matches all events (always true condition)",
    Medium,
    "condition: true or evt.type=* without filters — alert noise hides real threats.",
    "Scope conditions to specific syscalls/containers; set priority and tags.",
    "T1562",
    "CWE-693",
    &["CIS-Runtime"],
    &["NIST-SI-4", "SOC2-CC7.2"]
);
pub const FILE_ONLY_OUTPUT: PolicyMeta = pol!(
    "WZ-FLC-003",
    "Falco outputs only to local file (no SIEM forwarder)",
    High,
    "falco.yaml program_output file only without grpc/http/syslog output — logs lost on node drain.",
    "Forward to SIEM via falcosidekick; enable grpc output with mTLS.",
    "T1562.008",
    "CWE-778",
    &["CIS-Runtime"],
    &["NIST-AU-12", "SOC2-CC7.2"]
);
pub const SENSITIVE_PATH_EXCL: PolicyMeta = pol!(
    "WZ-FLC-004",
    "Falco rule excludes sensitive container paths from monitoring",
    High,
    "macro/list excludes /etc/shadow, /.ssh, or /var/run/docker.sock from detection.",
    "Remove broad exclusions; use container-scoped exceptions only.",
    "T1562",
    "CWE-693",
    &["CIS-Runtime"],
    &["NIST-SI-4", "SOC2-CC7.2"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![RULE_DISABLED, CATCH_ALL, FILE_ONLY_OUTPUT, SENSITIVE_PATH_EXCL]
}

fn is_falco(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.contains("falco") || lc.contains("- rule:") || lc.contains("condition:") && lc.contains("container")
        || lc.contains("falco.yaml") || lc.contains("falco_rules")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_falco(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("enabled: false") {
        out.push(Finding::new(RULE_DISABLED, file, file).observed("enabled: false"));
    }
    if lc.contains("condition: true") || lc.contains("evt.type=*") {
        out.push(Finding::new(CATCH_ALL, file, file).observed("catch-all condition"));
    }
    if lc.contains("program_output:") && !lc.contains("grpc") && !lc.contains("http_output") && !lc.contains("syslog") {
        out.push(Finding::new(FILE_ONLY_OUTPUT, file, file).observed("file-only output"));
    }
    if lc.contains("not fd.name") && (lc.contains("/etc/shadow") || lc.contains("docker.sock")) {
        out.push(Finding::new(SENSITIVE_PATH_EXCL, file, file).observed("excludes sensitive paths"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_disabled_rule() {
        let r = "- rule: Terminal shell in container\n  enabled: false\n  condition: spawned_process";
        let f = evaluate("falco/custom.yaml", r);
        assert!(f.iter().any(|x| x.policy.id == RULE_DISABLED.id));
    }
}
