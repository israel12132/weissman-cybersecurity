//! Pulumi program analyzer — Pulumi.yaml project metadata plus deterministic pattern matching on
//! TypeScript/Python/Go Pulumi source for cloud anti-patterns (public S3, open SG, unencrypted DB).

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "pulumi", provider: "multi",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const S3_PUBLIC: PolicyMeta = pol!("WZ-PLM-001", "Pulumi S3 bucket configured for public access", Critical, "Pulumi AWS S3 bucket uses public-read ACL or publicAccessBlock disabled.", "Enable blockPublicAcls, blockPublicPolicy, ignorePublicAcls, restrictPublicBuckets.", "T1530", "CWE-732", &["CIS-AWS-2.1.5"], &["CIS-AWS-2.1.5", "NIST-AC-3"]);
pub const SG_OPEN: PolicyMeta = pol!("WZ-PLM-002", "Pulumi security group allows 0.0.0.0/0 ingress", High, "SecurityGroup ingress includes cidrBlocks 0.0.0.0/0.", "Restrict ingress CIDRs to application-tier networks.", "T1190", "CWE-284", &["CIS-AWS-5.2"], &["CIS-AWS-5.2", "NIST-SC-7"]);
pub const RDS_OPEN: PolicyMeta = pol!("WZ-PLM-003", "Pulumi RDS publicly accessible", High, "RDS instance has publiclyAccessible: true.", "Set publiclyAccessible: false; use private subnets.", "T1190", "CWE-668", &["CIS-AWS-2.3"], &["NIST-SC-7", "PCI-DSS-1.3.6"]);
pub const IAM_ADMIN: PolicyMeta = pol!("WZ-PLM-004", "Pulumi IAM policy grants admin wildcard", Critical, "IAM PolicyStatement allows Action * on Resource *.", "Apply least-privilege IAM policies.", "T1098", "CWE-269", &["CIS-AWS-1.16"], &["NIST-AC-6", "MITRE-T1098"]);
pub const UNENCRYPTED: PolicyMeta = pol!("WZ-PLM-005", "Pulumi storage/database encryption disabled", High, "Resource sets encrypted/storageEncrypted to false or omits encryption.", "Enable encryption at rest with CMK.", "T1530", "CWE-311", &["CIS-AWS-2.x"], &["NIST-SC-28", "PCI-DSS-3.4"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![S3_PUBLIC, SG_OPEN, RDS_OPEN, IAM_ADMIN, UNENCRYPTED]
}

fn is_pulumi_artifact(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if n == "pulumi.yaml" || n == "pulumi.yml" || n == "pulumiproject.yaml" {
        return true;
    }
    let lc = content.to_ascii_lowercase();
    (n.ends_with(".ts") || n.ends_with(".py") || n.ends_with(".go"))
        && (lc.contains("@pulumi/") || lc.contains("import pulumi") || lc.contains("from pulumi")
            || lc.contains("aws.s3") || lc.contains("aws.s3.bucket"))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_pulumi_artifact(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if (lc.contains("acl: \"public-read\"") || lc.contains("acl: 'public-read'") || lc.contains("publicreadaccess: true"))
        && (lc.contains("s3.bucket") || lc.contains("aws.s3"))
    {
        out.push(Finding::new(S3_PUBLIC, file, file).observed("S3 public-read / publicReadAccess"));
    }
    if (lc.contains("0.0.0.0/0") || lc.contains("cidrblocks: [\"0.0.0.0/0\"]"))
        && (lc.contains("securitygroup") || lc.contains("ec2.securitygroup"))
    {
        out.push(Finding::new(SG_OPEN, file, file).observed("SecurityGroup 0.0.0.0/0 ingress"));
    }
    if lc.contains("publiclyaccessible: true") && lc.contains("rds") {
        out.push(Finding::new(RDS_OPEN, file, file).observed("publiclyAccessible: true"));
    }
    if (lc.contains("action: \"*\"") || lc.contains("actions: [\"*\"]") || lc.contains("action: '*'"))
        && (lc.contains("resource: \"*\"") || lc.contains("resources: [\"*\"]"))
    {
        out.push(Finding::new(IAM_ADMIN, file, file).observed("IAM Action * Resource *"));
    }
    if lc.contains("encrypted: false") || lc.contains("storageencrypted: false") {
        out.push(Finding::new(UNENCRYPTED, file, file).observed("encryption disabled"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_pulumi_s3_public() {
        let src = r#"import * as aws from "@pulumi/aws";
new aws.s3.Bucket("b", { acl: "public-read" });"#;
        assert!(evaluate("index.ts", src).iter().any(|f| f.policy.id == S3_PUBLIC.id));
    }
}
