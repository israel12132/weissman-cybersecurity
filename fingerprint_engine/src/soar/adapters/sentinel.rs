//! Microsoft Sentinel adapter — Log Analytics Data Collector / ingestion DCR.

use async_trait::async_trait;
use serde_json::json;

use super::common::http_client;
use super::slack::SlackNotifyAdapter;
use super::{AdapterContext, AdapterError};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct SentinelAdapter;

#[async_trait]
impl SlackNotifyAdapter for SentinelAdapter {
    fn provider_id(&self) -> &'static str {
        "sentinel"
    }

    async fn notify(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would ingest to Sentinel".into(),
                payload: json!({}),
                revert_steps: vec![],
                verify_probe: None,
            });
        }
        let url = config_str(
            &ctx.integration.config,
            &["ingest_url", "dce_url", "url"],
        )
        .ok_or_else(|| AdapterError::Config("sentinel ingest_url required".into()))?;
        let token = config_str(
            &ctx.integration.config,
            &["access_token", "token", "bearer"],
        )
        .ok_or_else(|| AdapterError::Config("sentinel access_token required".into()))?;
        let client = http_client(15).map_err(AdapterError::Provider)?;
        let body = json!([{
            "TimeGenerated": chrono::Utc::now().to_rfc3339(),
            "Computer": ctx.cmd.target_id,
            "Title": ctx.cmd.evidence.title,
            "Severity": ctx.cmd.evidence.severity,
            "Source": "Weissman",
        }]);
        let resp = client
            .post(&url)
            .bearer_auth(token)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Provider(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AdapterError::Provider(format!(
                "Sentinel HTTP {}",
                resp.status()
            )));
        }
        Ok(AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(format!("sentinel-{}", ctx.cmd.target_id)),
            detail: "sentinel ingest accepted".into(),
            payload: body,
            revert_steps: vec![],
            verify_probe: None,
        })
    }

    fn revert_steps(&self, _outcome: &AdapterOutcome) -> Vec<RevertStep> {
        vec![]
    }
}
