//! Mozilla SOPS config analyzer — weak creation rules, missing shamir threshold, and plaintext
//! regex that is too broad.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "sops", provider: "generic",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const NO_KMS: PolicyMeta = pol!("WZ-SOPS-001", "SOPS creation rules without KMS/PGP encryption", High, ".sops.yaml creation_rules lack kms/pgp/age key — secrets encrypted with weak or local keys only.", "Require KMS or age recipient for all creation_rules.", "T1552.001", "CWE-312", &["CIS-Secrets"], &["NIST-SC-28", "PCI-DSS-3.4"]);
pub const SHAMIR_LOW: PolicyMeta = pol!("WZ-SOPS-002", "SOPS shamir_threshold too low for production", Medium, "shamir_threshold: 1 allows single-key decryption of production secrets.", "Set shamir_threshold >= 2 with distributed key holders.", "T1552.001", "CWE-693", &["CIS-Secrets"], &["NIST-IA-5", "SOC2-CC6.1"]);
pub const BROAD_REGEX: PolicyMeta = pol!("WZ-SOPS-003", "SOPS encrypted_regex matches entire file", High, "encrypted_regex: .* or ^.*$ encrypts everything including non-secret metadata — operational risk.", "Use precise regex for secret keys only (password|token|key).", "T1552", "CWE-200", &["CIS-Secrets"], &["NIST-CM-7", "SOC2-CC8.1"]);
pub const UNENCRYPTED_FILE: PolicyMeta = pol!("WZ-SOPS-004", "SOPS-encrypted file missing sops metadata header", High, "File path suggests secrets but lacks sops metadata (sops_kms, sops_pgp, ENC[).", "Encrypt with sops before commit or remove from VCS.", "T1552.001", "CWE-312", &["CIS-Secrets"], &["NIST-IA-5", "PCI-DSS-8.2.1"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![NO_KMS, SHAMIR_LOW, BROAD_REGEX, UNENCRYPTED_FILE]
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let n = file.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();

    if n.ends_with(".sops.yaml") || n.ends_with(".sops.yml") || n == ".sops.yaml" {
        if !lc.contains("kms:") && !lc.contains("pgp:") && !lc.contains("age:") && !lc.contains("azure_kv:") {
            out.push(Finding::new(NO_KMS, file, file).observed("no KMS/PGP/age in creation_rules"));
        }
        if lc.contains("shamir_threshold: 1") {
            out.push(Finding::new(SHAMIR_LOW, file, file).observed("shamir_threshold: 1"));
        }
        if lc.contains("encrypted_regex:") && (lc.contains(".*") || lc.contains("^.*")) {
            out.push(Finding::new(BROAD_REGEX, file, file).observed("broad encrypted_regex"));
        }
    }
    if (n.ends_with(".enc.yaml") || n.ends_with(".enc.yml") || n.contains("secrets")) && !content.contains("sops_") && !content.contains("ENC[") {
        if lc.contains("password:") || lc.contains("api_key:") || lc.contains("token:") {
            out.push(Finding::new(UNENCRYPTED_FILE, file, file).observed("secrets file without sops metadata"));
        }
    }

    out
}
