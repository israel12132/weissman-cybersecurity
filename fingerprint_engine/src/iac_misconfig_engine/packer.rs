//! HashiCorp Packer image builder analyzer — hardcoded cloud credentials, unencrypted volumes,
//! insecure provisioners, and public AMI settings.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "packer",
            provider: "generic",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const HARDCODED_CREDS: PolicyMeta = pol!(
    "WZ-PKR-001",
    "Packer builder embeds cloud access credentials",
    Critical,
    "access_key, secret_key, or token literal in Packer HCL/JSON builder block.",
    "Use environment variables, vault/SSM data sources, or ephemeral CI OIDC — never commit keys.",
    "T1552.001",
    "CWE-798",
    &["CIS-AMI"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const UNENCRYPTED_VOLUME: PolicyMeta = pol!(
    "WZ-PKR-002",
    "Packer AMI launch block device encryption disabled",
    High,
    "encrypted: false on ebs/block_device_mappings or missing encryption on root volume.",
    "Set encrypted: true and use KMS CMK for all block devices.",
    "T1530",
    "CWE-311",
    &["CIS-AMI"],
    &["NIST-SC-28", "PCI-DSS-3.4"]
);
pub const ROOT_SSH_PASSWORD: PolicyMeta = pol!(
    "WZ-PKR-003",
    "Packer enables SSH root login with password",
    High,
    "ssh_password or communicator password for root without key-only auth.",
    "Use ssh_private_key_file from vault; disable password authentication in provisioners.",
    "T1021",
    "CWE-521",
    &["CIS-AMI"],
    &["NIST-IA-5", "SOC2-CC6.1"]
);
pub const CURL_PROVISIONER: PolicyMeta = pol!(
    "WZ-PKR-004",
    "Packer shell provisioner pipes remote script without checksum",
    Medium,
    "curl | bash or wget pipe pattern in shell provisioner — supply-chain implant risk.",
    "Vendor scripts with checksum verification; use file provisioner with signed artifacts.",
    "T1195.002",
    "CWE-494",
    &["CIS-Supply"],
    &["NIST-SA-12", "SOC2-CC8.1"]
);
pub const PUBLIC_AMI: PolicyMeta = pol!(
    "WZ-PKR-005",
    "Packer amazon-ebs builder sets public AMI or public snapshot",
    High,
    "ami_groups includes all or snapshot sharing set to public.",
    "Keep AMIs private; share only via explicit AWS account IDs.",
    "T1530",
    "CWE-284",
    &["CIS-AMI"],
    &["NIST-AC-3", "SOC2-CC6.1"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        HARDCODED_CREDS,
        UNENCRYPTED_VOLUME,
        ROOT_SSH_PASSWORD,
        CURL_PROVISIONER,
        PUBLIC_AMI,
    ]
}

fn is_packer(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let lc = content.to_ascii_lowercase();
    n.ends_with(".pkr.hcl")
        || n.ends_with(".pkr.json")
        || n.contains("packer")
        || lc.contains("packer {")
        || lc.contains("\"builders\"") && lc.contains("amazon-ebs")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_packer(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("access_key") || lc.contains("secret_key") {
        if lc.contains("akia") || lc.contains("example") || lc.contains("secret") {
            out.push(
                Finding::new(HARDCODED_CREDS, file, file).observed("embedded builder credentials"),
            );
        }
    }
    if lc.contains("encrypted: false")
        || lc.contains("\"encrypted\": false")
        || lc.contains("encrypted = false")
    {
        out.push(
            Finding::new(UNENCRYPTED_VOLUME, file, file)
                .observed("block device encryption disabled"),
        );
    }
    if lc.contains("ssh_password") || lc.contains("communicator_password") {
        out.push(Finding::new(ROOT_SSH_PASSWORD, file, file).observed("SSH password auth"));
    }
    if lc.contains("curl ") && lc.contains("| bash") || lc.contains("wget ") && lc.contains("| sh")
    {
        out.push(Finding::new(CURL_PROVISIONER, file, file).observed("curl|bash provisioner"));
    }
    if lc.contains("ami_groups") && lc.contains("all")
        || lc.contains("snapshot_users") && lc.contains("*")
    {
        out.push(Finding::new(PUBLIC_AMI, file, file).observed("public AMI/snapshot sharing"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_hardcoded_aws_key() {
        let hcl = r#"source "amazon-ebs" "web" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  encrypted = false
}"#;
        let f = evaluate("packer.pkr.hcl", hcl);
        assert!(f.iter().any(|x| x.policy.id == HARDCODED_CREDS.id));
        assert!(f.iter().any(|x| x.policy.id == UNENCRYPTED_VOLUME.id));
    }
}
