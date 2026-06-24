//! HashiCorp Vault HCL policy analyzer — overly broad paths, sudo capabilities, and unbounded TTL.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "vault", provider: "generic",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const PATH_WILDCARD: PolicyMeta = pol!("WZ-VLT-001", "Vault policy grants path wildcard admin", Critical, "path \"*\" or path \"secret/*\" with capabilities = [\"create\", \"update\", \"delete\", \"sudo\"].", "Scope paths to least privilege; split read/write policies.", "T1098", "CWE-732", &["CIS-Vault-1"], &["NIST-AC-6", "PCI-DSS-7.1.2"]);
pub const SUDO_CAP: PolicyMeta = pol!("WZ-VLT-002", "Vault policy includes sudo capability", Critical, "capabilities list contains sudo — bypasses path restrictions.", "Remove sudo; use dedicated break-glass policy with MFA.", "T1098", "CWE-269", &["CIS-Vault-1"], &["NIST-AC-6", "SOC2-CC6.3"]);
pub const UNBOUNDED_TTL: PolicyMeta = pol!("WZ-VLT-003", "Vault auth method allows unbounded token TTL", High, "token_ttl or default_lease_ttl set to 0 or extremely high without max_ttl.", "Set max_ttl <= 24h for human tokens; use short-lived workload identity.", "T1550", "CWE-613", &["CIS-Vault-2"], &["NIST-IA-5", "PCI-DSS-8.2.4"]);
pub const AUDIT_DISABLED: PolicyMeta = pol!("WZ-VLT-004", "Vault audit device disabled or file-only without hash", Medium, "audit device type file without hmac accessor or disabled audit stanza.", "Enable socket/syslog audit with hmac_accessor; ship to SIEM.", "T1562.008", "CWE-778", &["CIS-Vault-3"], &["NIST-AU-12", "SOC2-CC7.2"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![PATH_WILDCARD, SUDO_CAP, UNBOUNDED_TTL, AUDIT_DISABLED]
}

fn is_vault(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.ends_with(".hcl") && (n.contains("vault") || lc.contains("path \""))
        || lc.contains("vault {") || lc.contains("capabilities =")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_vault(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("path \"*\"") || lc.contains("path \"secret/*\"") && lc.contains("delete") {
        out.push(Finding::new(PATH_WILDCARD, file, file).observed("wildcard Vault path"));
    }
    if lc.contains("\"sudo\"") || lc.contains("sudo") && lc.contains("capabilities") {
        out.push(Finding::new(SUDO_CAP, file, file).observed("sudo capability"));
    }
    if (lc.contains("default_lease_ttl") || lc.contains("token_ttl")) && (lc.contains("= 0") || lc.contains("= \"0\"") || lc.contains("8760h")) {
        out.push(Finding::new(UNBOUNDED_TTL, file, file).observed("unbounded or excessive TTL"));
    }
    if lc.contains("audit") && lc.contains("disabled") || lc.contains("type = \"file\"") && !lc.contains("hmac_accessor") {
        out.push(Finding::new(AUDIT_DISABLED, file, file).observed("weak or disabled audit"));
    }

    out
}
