//! Terragrunt HCL analyzer — remote state misconfigurations, unpinned dependencies, plaintext
//! credentials in inputs, and overly-broad IAM role assumptions.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "terragrunt", provider: "generic",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const REMOTE_STATE_HTTP: PolicyMeta = pol!(
    "WZ-TG-001",
    "Terragrunt remote_state uses unencrypted HTTP backend",
    Critical,
    "remote_state config points to http:// without encryption — state and secrets traverse cleartext.",
    "Use S3+KMS or GCS with encryption; never HTTP for remote state.",
    "T1552",
    "CWE-319",
    &["CIS-AWS-2.1.x"],
    &["NIST-SC-8", "PCI-DSS-4.1", "SOC2-CC6.1"]
);
pub const REMOTE_STATE_NO_LOCK: PolicyMeta = pol!(
    "WZ-TG-002",
    "Terragrunt S3 remote_state missing DynamoDB lock table",
    High,
    "S3 backend configured without dynamodb_table for state locking — concurrent applies corrupt state.",
    "Add dynamodb_table for state locking and enable versioning on the state bucket.",
    "T1491",
    "CWE-362",
    &["CIS-AWS-2.1.x"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const DEP_UNPINNED: PolicyMeta = pol!(
    "WZ-TG-003",
    "Terragrunt dependency block without version pin",
    High,
    "dependency config_path fetches another module without an immutable ref — supply-chain implant risk.",
    "Pin dependency sources to tagged releases or commit SHAs.",
    "T1195.001",
    "CWE-494",
    &["CIS-AWS-1.x"],
    &["NIST-SA-12", "SOC2-CC8.1"]
);
pub const INPUTS_SECRET: PolicyMeta = pol!(
    "WZ-TG-004",
    "Cleartext secret in Terragrunt inputs",
    Critical,
    "inputs block contains password/token/api_key literals committed to VCS.",
    "Use SOPS, Vault, or CI-injected environment variables for secrets.",
    "T1552.001",
    "CWE-798",
    &["CIS-AWS-1.x"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const IAM_ASSUME_ALL: PolicyMeta = pol!(
    "WZ-TG-005",
    "Terragrunt iam_role assumes overly broad account",
    High,
    "iam_role or iam_assume_role_session_name configured without scoped role ARN.",
    "Scope iam_role to least-privilege role per environment.",
    "T1098",
    "CWE-269",
    &["CIS-AWS-1.16"],
    &["NIST-AC-6", "SOC2-CC6.3"]
);
pub const SKIP_OUTPUTS: PolicyMeta = pol!(
    "WZ-TG-006",
    "Terragrunt skip_outputs on security-critical dependency",
    Medium,
    "skip_outputs = true on a dependency that provides security group or IAM outputs — blind applies.",
    "Enable outputs for security-sensitive dependencies; validate before apply.",
    "T1195",
    "CWE-693",
    &["CIS-AWS-1.x"],
    &["NIST-CM-3", "SOC2-CC8.1"]
);
pub const LOCAL_STATE: PolicyMeta = pol!(
    "WZ-TG-007",
    "Terragrunt disables remote state (local backend)",
    High,
    "remote_state disabled or local backend used — state not shared, not encrypted at rest in team workflows.",
    "Use encrypted remote backend (S3+KMS) with locking for all environments.",
    "T1552",
    "CWE-538",
    &["CIS-AWS-2.1.x"],
    &["NIST-SC-28", "SOC2-CC6.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![REMOTE_STATE_HTTP, REMOTE_STATE_NO_LOCK, DEP_UNPINNED, INPUTS_SECRET, IAM_ASSUME_ALL, SKIP_OUTPUTS, LOCAL_STATE]
}

fn is_terragrunt(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.ends_with("terragrunt.hcl")
        || (n.ends_with(".hcl") && lc.contains("terragrunt"))
        || lc.contains("remote_state {")
        || lc.contains("terraform {")
            && lc.contains("source =")
            && (lc.contains("dependency") || lc.contains("inputs"))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_terragrunt(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("remote_state") && lc.contains("http://") {
        out.push(Finding::new(REMOTE_STATE_HTTP, file, file).observed("remote_state http:// backend"));
    }
    if lc.contains("remote_state") && lc.contains("backend = \"s3\"") && !lc.contains("dynamodb_table") {
        out.push(Finding::new(REMOTE_STATE_NO_LOCK, file, file).observed("S3 backend without dynamodb_table"));
    }
    if lc.contains("dependency \"") && !lc.contains("?ref=") && !lc.contains("version =") {
        out.push(Finding::new(DEP_UNPINNED, file, file).observed("dependency without immutable ref"));
    }
    for key in ["password", "api_key", "secret", "token", "private_key"] {
        if lc.contains(&format!("{key} =")) || lc.contains(&format!("{key}=")) {
            let has_placeholder = lc.contains("get_env") || lc.contains("sops") || lc.contains("vault");
            if !has_placeholder {
                out.push(Finding::new(INPUTS_SECRET, file, file).observed(format!("inputs {key} literal")));
                break;
            }
        }
    }
    if lc.contains("iam_role") && (lc.contains("arn:aws:iam::*:role/admin") || lc.contains("organizationaccessrole")) {
        out.push(Finding::new(IAM_ASSUME_ALL, file, file).observed("broad iam_role ARN"));
    }
    if lc.contains("skip_outputs = true") || lc.contains("skip_outputs=true") {
        out.push(Finding::new(SKIP_OUTPUTS, file, file).observed("skip_outputs = true"));
    }
    if lc.contains("disable_backend_init") || lc.contains("disable_init") && lc.contains("remote_state") {
        out.push(Finding::new(LOCAL_STATE, file, file).observed("remote state init disabled / local workflow"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_http_remote_state() {
        let h = "remote_state {\n  backend = \"s3\"\n  config = { endpoint = \"http://state.local\" }\n}\n";
        assert!(evaluate("terragrunt.hcl", h).iter().any(|f| f.policy.id == REMOTE_STATE_HTTP.id));
    }
}
