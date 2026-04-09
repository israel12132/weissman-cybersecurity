//! Agentless AWS integration: assume a tenant-supplied cross-account IAM role and read
//! S3 / EC2 configuration to detect common misconfigurations. No agents on customer workloads.
//!
//! Caller credentials must be configured via the standard AWS environment / profile chain
//! (the Weissman platform principal that is trusted by the customer role).

use aws_config::BehaviorVersion;
use aws_config::Region;
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::Credentials as AwsCredentials;
use aws_types::SdkConfig;
use serde_json::json;
use std::fmt;
use std::time::SystemTime;

const RULE_S3_PUBLIC: &str = "s3_bucket_public_access";
const RULE_EC2_SG: &str = "ec2_security_group_dangerous_ingress";

/// Customer cross-account role and optional external ID (recommended for third-party assume-role).
#[derive(Clone, Debug, Default)]
pub struct CrossAccountAwsConfig {
    pub role_arn: String,
    pub external_id: String,
    pub session_name: String,
}

#[derive(Clone, Debug)]
pub struct CloudMisconfiguration {
    pub resource_type: String,
    pub resource_id: String,
    pub region: String,
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub detail: serde_json::Value,
}

#[derive(Debug)]
pub enum CloudIntegrationError {
    InvalidInput(String),
    AssumeRole(String),
    Api(String),
}

impl fmt::Display for CloudIntegrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudIntegrationError::InvalidInput(s) => write!(f, "{s}"),
            CloudIntegrationError::AssumeRole(s) => write!(f, "STS AssumeRole: {s}"),
            CloudIntegrationError::Api(s) => write!(f, "AWS API: {s}"),
        }
    }
}

impl std::error::Error for CloudIntegrationError {}

pub fn validate_cross_account_role_arn(arn: &str) -> Result<(), &'static str> {
    let t = arn.trim();
    if t.is_empty() {
        return Ok(());
    }
    if !t.starts_with("arn:aws:iam::") {
        return Err("Cross-account role ARN must start with arn:aws:iam::");
    }
    if !t.contains(":role/") {
        return Err("Cross-account ARN must be an IAM role (contain :role/)");
    }
    Ok(())
}

/// Build an SDK config using STS AssumeRole into the tenant role (shared by cloud scan + deception deploy).
pub async fn assume_role_sdk_config(
    cfg: &CrossAccountAwsConfig,
) -> Result<(SdkConfig, aws_config::Region), CloudIntegrationError> {
    let role = cfg.role_arn.trim();
    if role.is_empty() {
        return Err(CloudIntegrationError::InvalidInput(
            "aws_cross_account_role_arn is empty".into(),
        ));
    }
    validate_cross_account_role_arn(role)
        .map_err(|s: &str| CloudIntegrationError::InvalidInput(s.to_string()))?;
    let base = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let sts = aws_sdk_sts::Client::new(&base);
    let session = if cfg.session_name.trim().is_empty() {
        default_session_name()
    } else {
        cfg.session_name.trim().to_string()
    };
    let mut ar = sts.assume_role().role_arn(role).role_session_name(&session);
    let ext = cfg.external_id.trim();
    if !ext.is_empty() {
        ar = ar.external_id(ext);
    }
    let out = ar
        .send()
        .await
        .map_err(|e| CloudIntegrationError::AssumeRole(e.to_string()))?;
    let c = out
        .credentials()
        .ok_or_else(|| CloudIntegrationError::AssumeRole("no credentials in response".into()))?;
    let exp = SystemTime::try_from(*c.expiration()).ok();
    let tok = c.session_token();
    let session_opt = if tok.is_empty() {
        None
    } else {
        Some(tok.to_string())
    };
    let creds = AwsCredentials::new(
        c.access_key_id(),
        c.secret_access_key(),
        session_opt,
        exp,
        "sts-assume-role",
    );
    let provider = SharedCredentialsProvider::new(creds);
    let home_region = base
        .region()
        .cloned()
        .unwrap_or_else(|| Region::new("us-east-1"));
    let sdk = SdkConfig::builder()
        .credentials_provider(provider)
        .region(home_region.clone())
        .behavior_version(
            base.behavior_version()
                .unwrap_or_else(|| BehaviorVersion::latest()),
        )
        .build();
    Ok((sdk, home_region))
}

fn default_session_name() -> String {
    format!(
        "weissman-cloud-scan-{}",
        uuid::Uuid::new_v4()
            .to_string()
            .split('-')
            .next()
            .unwrap_or("sess")
    )
}

fn map_bucket_location(constraint: Option<&str>) -> String {
    match constraint.unwrap_or("").trim() {
        "" | "US" => "us-east-1".to_string(),
        "EU" => "eu-west-1".to_string(),
        other => other.to_string(),
    }
}

fn is_dangerous_port(from: Option<i32>, to: Option<i32>) -> bool {
    let start = from.unwrap_or(-1);
    let end = to.unwrap_or(start);
    let dangerous = [
        22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5433, 6379, 9200, 27017,
    ];
    for p in dangerous {
        if p >= start && p <= end {
            return true;
        }
    }
    false
}

/// Assume `cfg.role_arn` and scan S3 buckets plus EC2 security groups in the given regions.
pub async fn scan_aws_agentless(
    cfg: &CrossAccountAwsConfig,
    ec2_regions: &[String],
) -> Result<Vec<CloudMisconfiguration>, CloudIntegrationError> {
    let (sdk, home_region) = assume_role_sdk_config(cfg).await?;

    let mut findings: Vec<CloudMisconfiguration> = Vec::new();

    let s3_global = aws_sdk_s3::config::Builder::from(&sdk)
        .region(home_region.clone())
        .build();
    let s3_client = aws_sdk_s3::Client::from_conf(s3_global);
    let buckets = s3_client
        .list_buckets()
        .send()
        .await
        .map_err(|e| CloudIntegrationError::Api(format!("S3 ListBuckets: {e}")))?;
    let bucket_list = buckets.buckets();

    for b in bucket_list {
        let name = b.name().unwrap_or_default().to_string();
        if name.is_empty() {
            continue;
        }
        let loc = s3_client
            .get_bucket_location()
            .bucket(&name)
            .send()
            .await
            .ok()
            .and_then(|r| r.location_constraint().map(|x| x.as_str().to_string()));
        let region = map_bucket_location(loc.as_deref());
        let regional = aws_sdk_s3::config::Builder::from(&sdk)
            .region(Region::new(region.clone()))
            .build();
        let rs3 = aws_sdk_s3::Client::from_conf(regional);

        let mut public_reason: Option<String> = None;
        match rs3.get_public_access_block().bucket(&name).send().await {
            Ok(resp) => {
                if let Some(pab) = resp.public_access_block_configuration() {
                    let weak = [
                        (pab.block_public_acls(), "block_public_acls=false"),
                        (pab.ignore_public_acls(), "ignore_public_acls=false"),
                        (pab.block_public_policy(), "block_public_policy=false"),
                        (
                            pab.restrict_public_buckets(),
                            "restrict_public_buckets=false",
                        ),
                    ];
                    for (flag, label) in weak {
                        if flag == Some(false) {
                            public_reason = Some(label.to_string());
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                let missing = e.as_service_error().and_then(|se| se.meta().code())
                    == Some("NoSuchPublicAccessBlockConfiguration");
                if !missing {
                    tracing::debug!(bucket = %name, err = %e, "get_public_access_block");
                }
            }
        }
        if public_reason.is_none() {
            match rs3.get_bucket_acl().bucket(&name).send().await {
                Ok(acl) => {
                    for g in acl.grants() {
                        let uri = g
                            .grantee()
                            .and_then(|gg| gg.uri())
                            .unwrap_or("")
                            .to_lowercase();
                        if uri.contains("allusers") || uri.contains("authenticatedusers") {
                            public_reason = Some(format!("Bucket ACL grants {uri}"));
                            break;
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(bucket = %name, err = %e, "get_bucket_acl");
                }
            }
        }
        if let Some(reason) = public_reason {
            findings.push(CloudMisconfiguration {
                resource_type: "s3_bucket".into(),
                resource_id: name.clone(),
                region: region.clone(),
                rule_id: RULE_S3_PUBLIC.into(),
                severity: "high".into(),
                title: format!("S3 bucket may allow public access: {name}"),
                detail: json!({ "reason": reason }),
            });
        }
    }

    for reg in ec2_regions {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ec2_conf = aws_sdk_ec2::config::Builder::from(&sdk)
            .region(Region::new(r.to_string()))
            .build();
        let ec2 = aws_sdk_ec2::Client::from_conf(ec2_conf);
        let mut paginator = ec2.describe_security_groups().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let page = page.map_err(|e| {
                CloudIntegrationError::Api(format!("EC2 DescribeSecurityGroups: {e}"))
            })?;
            for sg in page.security_groups() {
                let sg_id = sg.group_id().unwrap_or("").to_string();
                for perm in sg.ip_permissions() {
                    let proto = perm.ip_protocol().unwrap_or("-1");
                    let from = perm.from_port();
                    let to = perm.to_port();
                    let open_world = perm
                        .ip_ranges()
                        .iter()
                        .any(|r| r.cidr_ip() == Some("0.0.0.0/0"));
                    if !open_world {
                        continue;
                    }
                    let dangerous = proto == "-1" || is_dangerous_port(from, to);
                    if !dangerous {
                        continue;
                    }
                    findings.push(CloudMisconfiguration {
                        resource_type: "ec2_security_group".into(),
                        resource_id: sg_id.clone(),
                        region: r.to_string(),
                        rule_id: RULE_EC2_SG.into(),
                        severity: if proto == "-1" {
                            "critical".into()
                        } else {
                            "high".into()
                        },
                        title: format!(
                            "Security group {sg_id} allows wide-open ingress from 0.0.0.0/0"
                        ),
                        detail: json!({
                            "protocol": proto,
                            "from_port": from,
                            "to_port": to,
                        }),
                    });
                }
            }
        }
    }

    Ok(findings)
}

/// Default regions for EC2 security-group pass when `WEISSMAN_AWS_EC2_SCAN_REGIONS` is unset.
pub fn ec2_scan_regions_from_env() -> Vec<String> {
    if let Ok(s) = std::env::var("WEISSMAN_AWS_EC2_SCAN_REGIONS") {
        let v: Vec<String> = s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        if !v.is_empty() {
            return v;
        }
    }
    vec!["us-east-1".into(), "us-west-2".into(), "eu-west-1".into()]
}
