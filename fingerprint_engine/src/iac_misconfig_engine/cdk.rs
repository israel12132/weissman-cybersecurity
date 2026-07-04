//! AWS CDK analyzer — pattern matching on TypeScript/Python CDK source and cdk.json for IaC
//! anti-patterns that map 1:1 to CloudFormation risks (public S3, open SG, admin IAM).

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "cdk",
            provider: "aws",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const S3_BLOCK_NONE: PolicyMeta = pol!(
    "WZ-CDK-001",
    "CDK S3 bucket disables Block Public Access",
    Critical,
    "BlockPublicAccess.BLOCK_NONE or publicReadAccess: true on S3 bucket.",
    "Use BlockPublicAccess.BLOCK_ALL and enforce bucket policies.",
    "T1530",
    "CWE-732",
    &["CIS-AWS-2.1.5"],
    &["CIS-AWS-2.1.5", "NIST-AC-3"]
);
pub const SG_ALL: PolicyMeta = pol!(
    "WZ-CDK-002",
    "CDK SecurityGroup allows all inbound (Peer.anyIpv4)",
    High,
    "ec2.Peer.anyIpv4() on ingress opens the instance to the internet.",
    "Use ec2.Peer.ipv4 with scoped CIDRs.",
    "T1190",
    "CWE-284",
    &["CIS-AWS-5.2"],
    &["CIS-AWS-5.2", "NIST-SC-7"]
);
pub const IAM_STAR: PolicyMeta = pol!(
    "WZ-CDK-003",
    "CDK IAM grants * permissions",
    Critical,
    "PolicyStatement with actions ['*'] and resources ['*'].",
    "Scope actions/resources to minimum required.",
    "T1098",
    "CWE-269",
    &["CIS-AWS-1.16"],
    &["NIST-AC-6", "MITRE-T1098"]
);
pub const RDS_PUB: PolicyMeta = pol!(
    "WZ-CDK-004",
    "CDK RDS publicly accessible",
    High,
    "DatabaseInstance or ServerlessCluster with publiclyAccessible: true.",
    "Place RDS in private isolated subnets.",
    "T1190",
    "CWE-668",
    &["CIS-AWS-2.3"],
    &["NIST-SC-7"]
);
pub const LAMBDA_PUB: PolicyMeta = pol!(
    "WZ-CDK-005",
    "CDK Lambda Function URL without auth",
    High,
    "FunctionUrlAuthType.NONE on Lambda function URL.",
    "Use FunctionUrlAuthType.AWS_IAM.",
    "T1190",
    "CWE-306",
    &["CIS-AWS-Lambda"],
    &["NIST-AC-3"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![S3_BLOCK_NONE, SG_ALL, IAM_STAR, RDS_PUB, LAMBDA_PUB]
}

fn is_cdk_artifact(name: &str, content: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if n == "cdk.json" || n.ends_with("cdk.context.json") {
        return true;
    }
    let lc = content.to_ascii_lowercase();
    (n.ends_with(".ts") || n.ends_with(".py") || n.ends_with(".java"))
        && (lc.contains("aws-cdk-lib")
            || lc.contains("aws_cdk")
            || lc.contains("@aws-cdk")
            || lc.contains("blockpublicaccess")
            || lc.contains("peer.anyipv4")
            || lc.contains("functionurlauthtype"))
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_cdk_artifact(file, content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if lc.contains("blockpublicaccess.block_none")
        || (lc.contains("block_none") && lc.contains("blockpublicaccess"))
        || lc.contains("publicreadaccess: true")
        || lc.contains("block_public_acls: false")
    {
        out.push(Finding::new(S3_BLOCK_NONE, file, file).observed("S3 BlockPublicAccess disabled"));
    }
    if lc.contains("peer.anyipv4()") || lc.contains("peer.any_ipv4()") {
        out.push(Finding::new(SG_ALL, file, file).observed("Peer.anyIpv4() ingress"));
    }
    if (lc.contains("actions: ['*']") || lc.contains("actions: [\"*\"]"))
        && (lc.contains("resources: ['*']") || lc.contains("resources: [\"*\"]"))
    {
        out.push(Finding::new(IAM_STAR, file, file).observed("IAM * actions/resources"));
    }
    if lc.contains("publiclyaccessible: true") && lc.contains("rds") {
        out.push(Finding::new(RDS_PUB, file, file).observed("RDS publiclyAccessible"));
    }
    if lc.contains("functionurlauthtype.none")
        || lc.contains("auth_type: lambda.functionurlauthtype.none")
    {
        out.push(Finding::new(LAMBDA_PUB, file, file).observed("Function URL auth NONE"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_cdk_s3_block_none() {
        let src =
            "new s3.Bucket(this, 'B', { blockPublicAccess: s3.BlockPublicAccess.BLOCK_NONE });";
        assert!(evaluate("stack.ts", src)
            .iter()
            .any(|f| f.policy.id == S3_BLOCK_NONE.id));
    }
}
