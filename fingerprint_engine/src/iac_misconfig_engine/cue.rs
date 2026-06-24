//! CUE configuration analyzer — dangerous defaults, open network CIDR literals, and missing
//! schema validation constraints.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "cue", provider: "generic",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const OPEN_CIDR: PolicyMeta = pol!("WZ-CUE-001", "CUE schema allows 0.0.0.0/0 CIDR", High, "CUE value or default sets cidr/open CIDR to 0.0.0.0/0.", "Constrain with CUE disjunction to private CIDR ranges only.", "T1190", "CWE-284", &["CIS-Network"], &["NIST-SC-7", "PCI-DSS-1.3.1"]);
pub const SECRET_LITERAL: PolicyMeta = pol!("WZ-CUE-002", "CUE file embeds secret literal", High, "password/token/apiKey string literal in CUE module committed to VCS.", "Use CUE tags with external secret injection at render time.", "T1552.001", "CWE-798", &["CIS-Secrets"], &["NIST-IA-5", "PCI-DSS-8.2.1"]);
pub const NO_CONSTRAINT: PolicyMeta = pol!("WZ-CUE-003", "CUE export without validation constraint", Medium, "#Config export lacks CUE constraint (no & or _#schema reference).", "Attach schema: { ... } & #Policy constraints before export.", "T1195", "CWE-693", &["CIS-IaC"], &["NIST-CM-3", "SOC2-CC8.1"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![OPEN_CIDR, SECRET_LITERAL, NO_CONSTRAINT]
}

fn is_cue(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".cue") || content.contains("package ") && content.contains("{")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_cue(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("0.0.0.0/0") {
        out.push(Finding::new(OPEN_CIDR, file, file).observed("0.0.0.0/0 in CUE"));
    }
    for key in ["password:", "apikey:", "token:", "secret:"] {
        if lc.contains(key) && !lc.contains("@tag") {
            out.push(Finding::new(SECRET_LITERAL, file, file).observed(format!("literal {key}")));
            break;
        }
    }
    if lc.contains("#config") && !lc.contains("&") && !lc.contains("#schema") && !lc.contains("_#") {
        out.push(Finding::new(NO_CONSTRAINT, file, file).observed("export without schema constraint"));
    }

    out
}
