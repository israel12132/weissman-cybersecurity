//! CloudFormation / SAM analyzer: walks the `Resources` map (YAML — including `!Ref`/`!GetAtt`
//! intrinsic tags — or JSON) and enforces AWS security controls mirroring the Terraform AWS set.

use super::model::{line_of, Finding, PolicyMeta, Severity};
use serde_yaml::Value;

use Severity::{Critical, High, Low, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "cloudformation",
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

pub const S3_PUBLIC: PolicyMeta = pol!("WZ-CFN-S3-001", "S3 bucket AccessControl is public", Critical, "An AWS::S3::Bucket sets AccessControl to PublicRead/PublicReadWrite, exposing objects to anonymous users.", "Set AccessControl to Private and add a PublicAccessBlockConfiguration with all flags true.", "T1530", "CWE-732", &["CIS-AWS-2.1.5"], &["CIS-AWS-2.1.5", "PCI-DSS-1.2.1", "NIST-AC-3", "SOC2-CC6.1", "HIPAA-164.312(a)(1)"]);
pub const S3_PAB: PolicyMeta = pol!("WZ-CFN-S3-002", "S3 PublicAccessBlock weakens protection", High, "PublicAccessBlockConfiguration has one or more flags set to false.", "Set BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls and RestrictPublicBuckets all to true.", "T1530", "CWE-732", &["CIS-AWS-2.1.5"], &["CIS-AWS-2.1.5", "PCI-DSS-1.3", "NIST-AC-3"]);
pub const SG_OPEN: PolicyMeta = pol!(
    "WZ-CFN-SG-001",
    "Security group ingress open to 0.0.0.0/0",
    High,
    "A SecurityGroup ingress allows CidrIp 0.0.0.0/0.",
    "Restrict CidrIp to known ranges; front public services with a load balancer.",
    "T1190",
    "CWE-284",
    &["CIS-AWS-5.2"],
    &["CIS-AWS-5.2", "PCI-DSS-1.2.1", "NIST-SC-7"]
);
pub const SG_ADMIN: PolicyMeta = pol!(
    "WZ-CFN-SG-002",
    "Admin port (SSH/RDP) open to the internet",
    Critical,
    "A SecurityGroup exposes port 22 or 3389 to 0.0.0.0/0.",
    "Never expose SSH/RDP publicly; use SSM/bastion/VPN and scope CidrIp.",
    "T1190",
    "CWE-284",
    &["CIS-AWS-5.2", "CIS-AWS-5.3"],
    &["CIS-AWS-5.2", "CIS-AWS-5.3", "NIST-SC-7", "MITRE-T1190"]
);
pub const RDS_PUBLIC: PolicyMeta = pol!(
    "WZ-CFN-RDS-001",
    "RDS instance is publicly accessible",
    High,
    "AWS::RDS::DBInstance has PubliclyAccessible true.",
    "Set PubliclyAccessible: false and place the DB in private subnets.",
    "T1190",
    "CWE-668",
    &["CIS-AWS-2.3"],
    &["CIS-AWS-2.3", "PCI-DSS-1.3.6", "NIST-SC-7"]
);
pub const RDS_ENC: PolicyMeta = pol!(
    "WZ-CFN-RDS-002",
    "RDS storage not encrypted",
    High,
    "AWS::RDS::DBInstance/DBCluster StorageEncrypted is false or unset.",
    "Set StorageEncrypted: true with a KmsKeyId.",
    "T1530",
    "CWE-311",
    &["CIS-AWS-2.3.1"],
    &[
        "CIS-AWS-2.3.1",
        "PCI-DSS-3.4",
        "NIST-SC-28",
        "HIPAA-164.312(a)(2)(iv)"
    ]
);
pub const EBS_ENC: PolicyMeta = pol!(
    "WZ-CFN-EBS-001",
    "EBS volume not encrypted",
    High,
    "AWS::EC2::Volume Encrypted is false or unset.",
    "Set Encrypted: true and a KmsKeyId.",
    "T1530",
    "CWE-311",
    &["CIS-AWS-2.2.1"],
    &["CIS-AWS-2.2.1", "PCI-DSS-3.4", "NIST-SC-28"]
);
pub const IAM_WILDCARD: PolicyMeta = pol!(
    "WZ-CFN-IAM-001",
    "IAM policy grants wildcard admin",
    Critical,
    "An IAM policy statement allows Action '*' on Resource '*' (full administrator).",
    "Apply least privilege: scope Action and Resource to the minimum required.",
    "T1098",
    "CWE-269",
    &["CIS-AWS-1.16"],
    &["CIS-AWS-1.16", "NIST-AC-6", "SOC2-CC6.3", "MITRE-T1098"]
);
pub const IMDSV1: PolicyMeta = pol!("WZ-CFN-EC2-001", "EC2/LaunchTemplate allows IMDSv1", High, "MetadataOptions does not require IMDSv2 (HttpTokens != required), enabling SSRF credential theft.", "Set MetadataOptions HttpTokens: required.", "T1552.005", "CWE-918", &["CIS-AWS-5.6"], &["CIS-AWS-5.6", "NIST-SC-7", "MITRE-T1552.005"]);
pub const CT_LOGGING: PolicyMeta = pol!(
    "WZ-CFN-CT-001",
    "CloudTrail logging disabled",
    High,
    "AWS::CloudTrail::Trail has IsLogging false.",
    "Set IsLogging: true and EnableLogFileValidation; make it multi-region.",
    "T1562.008",
    "CWE-778",
    &["CIS-AWS-3.1"],
    &[
        "CIS-AWS-3.1",
        "PCI-DSS-10.1",
        "NIST-AU-2",
        "MITRE-T1562.008"
    ]
);
pub const KMS_ROT: PolicyMeta = pol!(
    "WZ-CFN-KMS-001",
    "KMS key rotation disabled",
    Medium,
    "AWS::KMS::Key EnableKeyRotation is false or unset.",
    "Set EnableKeyRotation: true.",
    "T1552",
    "CWE-320",
    &["CIS-AWS-3.8"],
    &["CIS-AWS-3.8", "NIST-SC-12"]
);
pub const OS_ENC: PolicyMeta = pol!(
    "WZ-CFN-OS-001",
    "OpenSearch/Elasticsearch not encrypted at rest",
    High,
    "EncryptionAtRestOptions is disabled on an OpenSearch/Elasticsearch domain.",
    "Enable EncryptionAtRestOptions and NodeToNodeEncryptionOptions.",
    "T1530",
    "CWE-311",
    &["CIS-AWS-x"],
    &["NIST-SC-28", "PCI-DSS-3.4"]
);
pub const REDSHIFT: PolicyMeta = pol!(
    "WZ-CFN-RS-001",
    "Redshift cluster public or unencrypted",
    High,
    "AWS::Redshift::Cluster is PubliclyAccessible or has Encrypted false.",
    "Set PubliclyAccessible: false and Encrypted: true.",
    "T1190",
    "CWE-668",
    &["CIS-AWS-x"],
    &["NIST-SC-7", "PCI-DSS-1.3.6"]
);
pub const DDB_SSE: PolicyMeta = pol!(
    "WZ-CFN-DDB-001",
    "DynamoDB SSE disabled",
    Low,
    "SSESpecification.SSEEnabled is false on a DynamoDB table.",
    "Enable SSESpecification (AWS-managed or KMS CMK).",
    "T1530",
    "CWE-311",
    &["CIS-AWS-x"],
    &["NIST-SC-28"]
);
pub const SQS_ENC: PolicyMeta = pol!(
    "WZ-CFN-SQS-001",
    "SQS/SNS without KMS encryption",
    Low,
    "An SQS queue or SNS topic has no KmsMasterKeyId, so messages are not encrypted with a CMK.",
    "Set KmsMasterKeyId to a KMS key.",
    "T1530",
    "CWE-311",
    &["CIS-AWS-x"],
    &["NIST-SC-28"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        S3_PUBLIC,
        S3_PAB,
        SG_OPEN,
        SG_ADMIN,
        RDS_PUBLIC,
        RDS_ENC,
        EBS_ENC,
        IAM_WILDCARD,
        IMDSV1,
        CT_LOGGING,
        KMS_ROT,
        OS_ENC,
        REDSHIFT,
        DDB_SSE,
        SQS_ENC,
    ]
}

fn vstr<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}
fn vbool_like(v: &Value, k: &str) -> Option<bool> {
    match v.get(k) {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn str_list(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => vec![],
    }
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(doc): Result<Value, _> = serde_yaml::from_str(content) else {
        return out;
    };
    let Some(resources) = doc.get("Resources").and_then(|r| r.as_mapping()) else {
        return out;
    };

    for (k, res) in resources {
        let logical = k.as_str().unwrap_or("resource").to_string();
        let rtype = vstr(res, "Type").unwrap_or("").to_string();
        let props = res.get("Properties").cloned().unwrap_or(Value::Null);
        let line = line_of(content, &logical);

        match rtype.as_str() {
            "AWS::S3::Bucket" => {
                if let Some(acl) = vstr(&props, "AccessControl") {
                    if acl.contains("Public") {
                        out.push(
                            Finding::new(S3_PUBLIC, &logical, file)
                                .at(line)
                                .observed(format!("AccessControl: {}", acl))
                                .fix("AccessControl: Private"),
                        );
                    }
                }
                if let Some(pab) = props.get("PublicAccessBlockConfiguration") {
                    for flag in [
                        "BlockPublicAcls",
                        "BlockPublicPolicy",
                        "IgnorePublicAcls",
                        "RestrictPublicBuckets",
                    ] {
                        if vbool_like(pab, flag) == Some(false) {
                            out.push(
                                Finding::new(S3_PAB, &logical, file)
                                    .at(line)
                                    .observed(format!("{}: false", flag))
                                    .fix(format!("{}: true", flag)),
                            );
                        }
                    }
                }
            }
            "AWS::EC2::SecurityGroup" => {
                if let Some(ingress) = props
                    .get("SecurityGroupIngress")
                    .and_then(Value::as_sequence)
                {
                    for rule in ingress {
                        check_cfn_ingress(file, &logical, line, rule, &mut out);
                    }
                }
            }
            "AWS::EC2::SecurityGroupIngress" => {
                check_cfn_ingress(file, &logical, line, &props, &mut out)
            }
            "AWS::RDS::DBInstance" | "AWS::RDS::DBCluster" => {
                if vbool_like(&props, "PubliclyAccessible") == Some(true) {
                    out.push(
                        Finding::new(RDS_PUBLIC, &logical, file)
                            .at(line)
                            .observed("PubliclyAccessible: true")
                            .fix("PubliclyAccessible: false"),
                    );
                }
                if vbool_like(&props, "StorageEncrypted") != Some(true) {
                    out.push(
                        Finding::new(RDS_ENC, &logical, file)
                            .at(line)
                            .observed("StorageEncrypted not true")
                            .fix("StorageEncrypted: true"),
                    );
                }
            }
            "AWS::EC2::Volume" => {
                if vbool_like(&props, "Encrypted") != Some(true) {
                    out.push(
                        Finding::new(EBS_ENC, &logical, file)
                            .at(line)
                            .observed("Encrypted not true")
                            .fix("Encrypted: true"),
                    );
                }
            }
            "AWS::IAM::Policy"
            | "AWS::IAM::Role"
            | "AWS::IAM::ManagedPolicy"
            | "AWS::IAM::User"
            | "AWS::IAM::Group" => {
                if has_wildcard_statement(res) {
                    out.push(
                        Finding::new(IAM_WILDCARD, &logical, file)
                            .at(line)
                            .observed("Effect Allow with Action '*' and Resource '*'"),
                    );
                }
            }
            "AWS::EC2::Instance" | "AWS::EC2::LaunchTemplate" => {
                let md = props
                    .get("LaunchTemplateData")
                    .and_then(|d| d.get("MetadataOptions"))
                    .or_else(|| props.get("MetadataOptions"));
                let enforced = md
                    .and_then(|m| vstr(m, "HttpTokens"))
                    .map(|t| t == "required")
                    .unwrap_or(false);
                if !enforced {
                    out.push(
                        Finding::new(IMDSV1, &logical, file)
                            .at(line)
                            .observed("MetadataOptions.HttpTokens != required")
                            .fix("MetadataOptions:\n  HttpTokens: required"),
                    );
                }
            }
            "AWS::CloudTrail::Trail" => {
                if vbool_like(&props, "IsLogging") == Some(false) {
                    out.push(
                        Finding::new(CT_LOGGING, &logical, file)
                            .at(line)
                            .observed("IsLogging: false")
                            .fix("IsLogging: true"),
                    );
                }
            }
            "AWS::KMS::Key" => {
                if vbool_like(&props, "EnableKeyRotation") != Some(true) {
                    out.push(
                        Finding::new(KMS_ROT, &logical, file)
                            .at(line)
                            .observed("EnableKeyRotation not true")
                            .fix("EnableKeyRotation: true"),
                    );
                }
            }
            "AWS::Elasticsearch::Domain" | "AWS::OpenSearchService::Domain" => {
                let enc = props
                    .get("EncryptionAtRestOptions")
                    .and_then(|e| vbool_like(e, "Enabled"))
                    .unwrap_or(false);
                if !enc {
                    out.push(
                        Finding::new(OS_ENC, &logical, file)
                            .at(line)
                            .observed("EncryptionAtRestOptions.Enabled != true")
                            .fix("EncryptionAtRestOptions:\n  Enabled: true"),
                    );
                }
            }
            "AWS::Redshift::Cluster" => {
                if vbool_like(&props, "PubliclyAccessible") == Some(true)
                    || vbool_like(&props, "Encrypted") == Some(false)
                {
                    out.push(
                        Finding::new(REDSHIFT, &logical, file)
                            .at(line)
                            .observed("PubliclyAccessible true or Encrypted false")
                            .fix("PubliclyAccessible: false\nEncrypted: true"),
                    );
                }
            }
            "AWS::DynamoDB::Table" => {
                let sse = props
                    .get("SSESpecification")
                    .and_then(|s| vbool_like(s, "SSEEnabled"));
                if sse == Some(false) {
                    out.push(
                        Finding::new(DDB_SSE, &logical, file)
                            .at(line)
                            .observed("SSESpecification.SSEEnabled: false")
                            .fix("SSESpecification:\n  SSEEnabled: true"),
                    );
                }
            }
            "AWS::SQS::Queue" | "AWS::SNS::Topic" => {
                if props.get("KmsMasterKeyId").is_none() {
                    out.push(
                        Finding::new(SQS_ENC, &logical, file)
                            .at(line)
                            .observed("no KmsMasterKeyId")
                            .fix("KmsMasterKeyId: alias/aws/sqs"),
                    );
                }
            }
            _ => {}
        }
    }
    out
}

fn check_cfn_ingress(file: &str, logical: &str, line: usize, rule: &Value, out: &mut Vec<Finding>) {
    let cidr = vstr(rule, "CidrIp").unwrap_or("");
    let cidr6 = vstr(rule, "CidrIpv6").unwrap_or("");
    if cidr == "0.0.0.0/0" || cidr6 == "::/0" {
        let from = rule.get("FromPort").and_then(Value::as_i64);
        let to = rule.get("ToPort").and_then(Value::as_i64);
        let admin = match (from, to) {
            (Some(f), Some(t)) => {
                let (lo, hi) = (f.min(t), f.max(t));
                (lo..=hi).contains(&22) || (lo..=hi).contains(&3389) || (lo == 0 && hi == 0)
            }
            _ => false,
        };
        let pol = if admin { SG_ADMIN } else { SG_OPEN };
        out.push(
            Finding::new(pol, logical, file)
                .at(line)
                .observed(format!("CidrIp 0.0.0.0/0 (FromPort={:?})", from))
                .fix("CidrIp: 10.0.0.0/8"),
        );
    }
}

/// Recursively find any IAM statement allowing Action '*' on Resource '*'.
fn has_wildcard_statement(v: &Value) -> bool {
    if let Some(stmts) = find_statements(v) {
        for s in stmts {
            let effect = s.get("Effect").and_then(Value::as_str).unwrap_or("");
            if effect != "Allow" {
                continue;
            }
            let actions = s.get("Action").map(str_list).unwrap_or_default();
            let resources = s.get("Resource").map(str_list).unwrap_or_default();
            if actions.iter().any(|a| a == "*") && resources.iter().any(|r| r == "*") {
                return true;
            }
        }
    }
    false
}

fn find_statements(v: &Value) -> Option<Vec<Value>> {
    // search any nested "Statement" sequence
    let mut acc = Vec::new();
    collect_statements(v, &mut acc);
    if acc.is_empty() {
        None
    } else {
        Some(acc)
    }
}

fn collect_statements(v: &Value, acc: &mut Vec<Value>) {
    match v {
        Value::Mapping(m) => {
            for (k, val) in m {
                if k.as_str() == Some("Statement") {
                    match val {
                        Value::Sequence(seq) => acc.extend(seq.iter().cloned()),
                        Value::Mapping(_) => acc.push(val.clone()),
                        _ => {}
                    }
                }
                collect_statements(val, acc);
            }
        }
        Value::Sequence(seq) => {
            for x in seq {
                collect_statements(x, acc);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_public_s3_and_open_sg_yaml() {
        let y = r#"
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicRead
  SG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - CidrIp: 0.0.0.0/0
          FromPort: 22
          ToPort: 22
"#;
        let f = evaluate("stack.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == S3_PUBLIC.id));
        assert!(f.iter().any(|x| x.policy.id == SG_ADMIN.id));
    }

    #[test]
    fn flags_iam_wildcard_json() {
        let j = r#"{"Resources":{"P":{"Type":"AWS::IAM::Policy","Properties":{"PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}}}}}"#;
        let f = evaluate("stack.json", j);
        assert!(f.iter().any(|x| x.policy.id == IAM_WILDCARD.id));
    }
}
