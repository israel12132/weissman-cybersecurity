//! Active deployment of honeytokens into cloud (AWS). Uses discovered or provided credentials to inject fake keys.

use aws_credential_types::Credentials;
use aws_sdk_iam::config::Region;
use aws_sdk_iam::Client as IamClient;

/// Result of deploying a honeytoken to AWS (create IAM user + access key).
#[derive(Debug)]
pub struct DeployResult {
    pub deployed: bool,
    pub user_name: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub error: Option<String>,
}

/// Deploy a honeytoken to AWS: create IAM user and access key. Caller stores the secret in deception_assets.
pub async fn deploy_honeytoken_aws(
    access_key_id: &str,
    secret_access_key: &str,
    region: &str,
    honeytoken_user_name: &str,
) -> DeployResult {
    let creds = Credentials::from_keys(access_key_id, secret_access_key, None);
    let config = aws_sdk_iam::Config::builder()
        .region(Region::new(region.to_string()))
        .credentials_provider(creds)
        .build();
    let client = IamClient::from_conf(config);
    if client
        .create_user()
        .user_name(honeytoken_user_name)
        .send()
        .await
        .is_err()
    {
        return DeployResult {
            deployed: false,
            user_name: Some(honeytoken_user_name.to_string()),
            access_key_id: None,
            secret_access_key: None,
            error: Some("CreateUser failed (user may exist)".to_string()),
        };
    }
    let create_key = match client
        .create_access_key()
        .user_name(honeytoken_user_name)
        .send()
        .await
    {
        Ok(k) => k,
        Err(e) => {
            return DeployResult {
                deployed: false,
                user_name: Some(honeytoken_user_name.to_string()),
                access_key_id: None,
                secret_access_key: None,
                error: Some(format!("CreateAccessKey: {}", e)),
            };
        }
    };
    let key_id = create_key
        .access_key
        .as_ref()
        .map(|a| a.access_key_id.clone());
    let secret = create_key
        .access_key
        .as_ref()
        .map(|a| a.secret_access_key.clone());
    DeployResult {
        deployed: key_id.is_some() && secret.is_some(),
        user_name: Some(honeytoken_user_name.to_string()),
        access_key_id: key_id,
        secret_access_key: secret,
        error: None,
    }
}
