//! Microsoft Teams incoming webhook adapter (Office 365 connector / Workflows).

use async_trait::async_trait;
use serde_json::json;

use super::common::http_client;
use super::slack::SlackNotifyAdapter;
use super::{AdapterContext, AdapterError};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct TeamsAdapter;

#[async_trait]
impl SlackNotifyAdapter for TeamsAdapter {
    fn provider_id(&self) -> &'static str {
        "teams"
    }

    async fn notify(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would post Teams webhook".into(),
                payload: json!({}),
                revert_steps: vec![],
                verify_probe: None,
            });
        }
        let url = config_str(
            &ctx.integration.config,
            &["webhook_url", "url", "incoming_webhook"],
        )
        .ok_or_else(|| AdapterError::Config("teams webhook_url required".into()))?;
        let client = http_client(10).map_err(AdapterError::Provider)?;
        let text = format!(
            "**{}** — {} on {}",
            ctx.cmd.evidence.severity, ctx.cmd.evidence.title, ctx.cmd.target_id
        );
        let body = json!({ "text": text });
        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Provider(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AdapterError::Provider(format!(
                "Teams webhook HTTP {}",
                resp.status()
            )));
        }
        Ok(AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(format!("teams-{}", ctx.cmd.target_id)),
            detail: "teams webhook delivered".into(),
            payload: body,
            revert_steps: vec![],
            verify_probe: None,
        })
    }

    fn revert_steps(&self, _outcome: &AdapterOutcome) -> Vec<RevertStep> {
        vec![]
    }
}
