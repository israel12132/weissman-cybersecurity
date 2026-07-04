//! CrowdStrike Falcon host containment adapter.

use async_trait::async_trait;
use serde_json::json;

use super::common::{bearer_headers, http_client};
use super::{AdapterContext, AdapterError, IsolateHostAdapter};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct CrowdStrikeFalconAdapter;

#[async_trait]
impl IsolateHostAdapter for CrowdStrikeFalconAdapter {
    fn provider_id(&self) -> &'static str {
        "crowdstrike_falcon"
    }

    async fn isolate(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would contain Falcon host".into(),
                payload: json!({ "target": ctx.cmd.target_id }),
                revert_steps: vec![],
                verify_probe: None,
            });
        }

        let client_id = config_str(&ctx.integration.config, &["client_id", "api_client_id"])
            .ok_or_else(|| AdapterError::Config("crowdstrike client_id required".into()))?;
        let client_secret =
            config_str(&ctx.integration.config, &["client_secret", "api_secret"])
                .ok_or_else(|| AdapterError::Config("crowdstrike client_secret required".into()))?;
        let base = config_str(&ctx.integration.config, &["api_url", "base_url"])
            .unwrap_or_else(|| "https://api.crowdstrike.com".to_string());
        let device_id = resolve_device_id(ctx)?;

        let token = falcon_token(&base, &client_id, &client_secret).await?;
        let url = format!("{base}/devices/entities/devices-actions/v2?action_name=contain");
        let body = json!({ "ids": [device_id] });

        let client = http_client(25).map_err(AdapterError::Provider)?;
        let resp = client
            .post(&url)
            .headers(bearer_headers(&token))
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Provider(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(AdapterError::Provider(format!(
                "Falcon contain HTTP {status}: {}",
                detail.chars().take(400).collect::<String>()
            )));
        }

        let payload = json!({
            "device_id": device_id,
            "base_url": base,
            "client_id": client_id,
            "client_secret": client_secret,
            "action": "contain",
        });

        Ok(AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(device_id.clone()),
            detail: format!("CrowdStrike Falcon contain issued for device {device_id}"),
            payload: payload.clone(),
            revert_steps: self.revert_steps(&AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: Some(device_id),
                detail: String::new(),
                payload,
                revert_steps: vec![],
                verify_probe: None,
            }),
            verify_probe: None,
        })
    }

    async fn verify_isolated(
        &self,
        target: &str,
        ports: &[u16],
        payload: &serde_json::Value,
    ) -> Result<bool, AdapterError> {
        let base = payload
            .get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or("https://api.crowdstrike.com");
        let client_id = payload
            .get("client_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let client_secret = payload
            .get("client_secret")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if client_id.is_empty() || target.is_empty() {
            return super::aws_ec2::tcp_probe_unreachable_batch(target, ports).await;
        }
        let token = falcon_token(base, client_id, &client_secret).await?;
        let url = format!("{base}/devices/entities/devices/v2?ids={target}");
        let client = http_client(15).map_err(AdapterError::Provider)?;
        let resp = client
            .get(&url)
            .headers(bearer_headers(&token))
            .send()
            .await
            .map_err(|e| AdapterError::Provider(e.to_string()))?;
        if !resp.status().is_success() {
            return Ok(false);
        }
        let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
        let contained = body
            .get("resources")
            .and_then(|r| r.as_array())
            .and_then(|a| a.first())
            .and_then(|d| d.get("status"))
            .and_then(|s| s.as_str())
            .map(|s| s.eq_ignore_ascii_case("contained"))
            .unwrap_or(false);
        if contained {
            return Ok(true);
        }
        super::aws_ec2::tcp_probe_unreachable_batch(target, ports).await
    }

    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep> {
        vec![RevertStep {
            provider: self.provider_id().into(),
            operation: "lift_containment".into(),
            payload: outcome.payload.clone(),
            description: "Lift CrowdStrike Falcon containment applied by SOAR".into(),
        }]
    }
}

fn resolve_device_id(ctx: &AdapterContext<'_>) -> Result<String, AdapterError> {
    if let Some(id) = ctx.cmd.params.get("device_id").and_then(|v| v.as_str()) {
        if !id.trim().is_empty() {
            return Ok(id.trim().to_string());
        }
    }
    let target = ctx.cmd.target_id.trim();
    if target.len() >= 32 {
        return Ok(target.to_string());
    }
    Err(AdapterError::Config(
        "crowdstrike device_id (Falcon AID) required in target or params".into(),
    ))
}

async fn falcon_token(
    base: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, AdapterError> {
    let url = format!("{base}/oauth2/token");
    let client = http_client(15).map_err(AdapterError::Provider)?;
    let resp = client
        .post(&url)
        .form(&[("client_id", client_id), ("client_secret", client_secret)])
        .send()
        .await
        .map_err(|e| AdapterError::Provider(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(AdapterError::Provider(format!(
            "Falcon OAuth HTTP {}",
            resp.status()
        )));
    }
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| AdapterError::Provider("Falcon OAuth missing access_token".into()))
}
