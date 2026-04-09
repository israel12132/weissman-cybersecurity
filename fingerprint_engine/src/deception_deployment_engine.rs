//! Weaponized honeytoken deployment: after STS assume-role into the tenant account, write canary
//! credentials to S3 and/or SSM Parameter Store. Pair with `/api/deception/aws-events` (EventBridge /
//! custom forwarder) to raise CRITICAL alerts when those keys appear in CloudTrail or GuardDuty.

use crate::regex_util::never_matches;
use aws_config::Region;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_ssm::types::ParameterType;
use aws_types::SdkConfig;
use regex::Regex;
use std::sync::OnceLock;

fn akia_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"AKIA[0-9A-Z]{16}").unwrap_or_else(|_| never_matches()))
}

/// Extract fake AWS access key id from honeytoken value (`AKIA...:secret` or plain).
pub fn extract_canary_access_key_id(token_value: &str) -> Option<String> {
    akia_regex()
        .find(token_value)
        .map(|m| m.as_str().to_string())
}

#[derive(Debug, Clone, Default)]
pub struct InjectionTargets {
    pub s3_bucket: Option<String>,
    pub s3_object_key: Option<String>,
    pub ssm_parameter_path: Option<String>,
}

#[derive(Debug)]
pub struct InjectionOutcome {
    pub uri: String,
    pub detail: String,
}

fn normalize_bucket_key(bucket: &str, key: &str) -> Result<(String, String), String> {
    let b = bucket.trim();
    let k = key.trim().trim_start_matches('/');
    if b.is_empty() || k.is_empty() {
        return Err("s3_bucket and s3_object_key required for S3 injection".into());
    }
    Ok((b.to_string(), k.to_string()))
}

/// Deploy honeytoken content into customer account (already-assumed `sdk` + `region`).
pub async fn deploy_honeytoken_injection(
    sdk: &SdkConfig,
    region: &Region,
    asset_type: &str,
    token_value: &str,
    targets: &InjectionTargets,
) -> Result<InjectionOutcome, String> {
    let s3_conf = aws_sdk_s3::config::Builder::from(sdk)
        .region(region.clone())
        .build();
    let s3 = aws_sdk_s3::Client::from_conf(s3_conf);
    let ssm_conf = aws_sdk_ssm::config::Builder::from(sdk)
        .region(region.clone())
        .build();
    let ssm = aws_sdk_ssm::Client::from_conf(ssm_conf);

    match asset_type {
        crate::deception_engine::TYPE_AWS_KEY => {
            let body = format!(
                "# Weissman deception canary — DO NOT USE\nexport AWS_ACCESS_KEY_ID=\"{}\"\n",
                token_value.replace('"', "")
            );
            let (bucket, key) = match (&targets.s3_bucket, &targets.s3_object_key) {
                (Some(b), Some(k)) => normalize_bucket_key(b, k)?,
                _ => {
                    return Err(
                        "For aws_key specify s3_bucket + s3_object_key (e.g. config/canary.env)"
                            .into(),
                    );
                }
            };
            s3.put_object()
                .bucket(&bucket)
                .key(&key)
                .content_type("text/plain")
                .body(ByteStream::from(body.into_bytes()))
                .send()
                .await
                .map_err(|e| format!("S3 PutObject: {}", e))?;
            let uri = format!("s3://{}/{}", bucket, key);
            Ok(InjectionOutcome {
                uri: uri.clone(),
                detail: format!("Canary AWS-style material written to {}", uri),
            })
        }
        crate::deception_engine::TYPE_DB_CRED | crate::deception_engine::TYPE_API_KEY => {
            let name = targets
                .ssm_parameter_path
                .as_deref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    "ssm_parameter_path required (e.g. /weissman/honey/db)".to_string()
                })?;
            let secure = asset_type == crate::deception_engine::TYPE_DB_CRED;
            let ptype = if secure {
                ParameterType::SecureString
            } else {
                ParameterType::String
            };
            ssm.put_parameter()
                .name(&name)
                .value(token_value)
                .overwrite(true)
                .r#type(ptype)
                .description("Weissman deception canary — monitor usage via CloudTrail")
                .send()
                .await
                .map_err(|e| format!("SSM PutParameter: {}", e))?;
            let uri = format!("ssm://{}{}", region.as_ref(), name);
            Ok(InjectionOutcome {
                uri: uri.clone(),
                detail: format!(
                    "Parameter stored at {} (type={})",
                    name,
                    if secure { "SecureString" } else { "String" }
                ),
            })
        }
        _ => Err(format!(
            "Active cloud injection not implemented for asset_type={}",
            asset_type
        )),
    }
}
