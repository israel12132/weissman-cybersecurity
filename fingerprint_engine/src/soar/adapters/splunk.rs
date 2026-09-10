//! Splunk HEC adapter — posts finding JSON to a real collector.

use async_trait::async_trait;
use serde_json::json;

use super::common::http_client;
use super::slack::SlackNotifyAdapter;
use super::{AdapterContext, AdapterError};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct SplunkHecAdapter;

#[async_trait]
impl SlackNotifyAdapter for SplunkHecAdapter {
    fn provider_id(&self) -> &'static str {
        "splunk"
    }

    async fn notify(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would POST Splunk HEC".into(),
                payload: json!({}),
                revert_steps: vec![],
                verify_probe: None,
            });
        }
        let url = config_str(
            &ctx.integration.config,
            &["hec_url", "url", "collector_url"],
        )
        .ok_or_else(|| AdapterError::Config("splunk hec_url required".into()))?;
        let token = config_str(&ctx.integration.config, &["hec_token", "token", "api_key"])
            .ok_or_else(|| AdapterError::Config("splunk hec_token required".into()))?;
        let client = http_client(15).map_err(AdapterError::Provider)?;
        let body = json!({
            "event": {
                "source": "weissman",
                "title": ctx.cmd.evidence.title,
                "severity": ctx.cmd.evidence.severity,
                "target": ctx.cmd.target_id,
            },
            "sourcetype": "weissman:finding",
        });
        let resp = client
            .post(&url)
            .header("Authorization", format!("Splunk {token}"))
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Provider(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AdapterError::Provider(format!(
                "Splunk HEC HTTP {}",
                resp.status()
            )));
        }
        Ok(AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(format!("splunk-hec-{}", ctx.cmd.target_id)),
            detail: "splunk HEC accepted event".into(),
            payload: body,
            revert_steps: vec![],
            verify_probe: None,
        })
    }

    fn revert_steps(&self, _outcome: &AdapterOutcome) -> Vec<RevertStep> {
        vec![]
    }
}
