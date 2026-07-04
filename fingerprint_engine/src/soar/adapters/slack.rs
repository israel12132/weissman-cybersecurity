//! Slack notification adapter (incoming webhook or Web API).

use async_trait::async_trait;
use serde_json::json;

use super::common::http_client;
use super::{AdapterContext, AdapterError};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct SlackAdapter;

#[async_trait]
pub trait SlackNotifyAdapter: Send + Sync {
    fn provider_id(&self) -> &'static str;
    async fn notify(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError>;
    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep>;
}

#[async_trait]
impl SlackNotifyAdapter for SlackAdapter {
    fn provider_id(&self) -> &'static str {
        "slack"
    }

    async fn notify(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would post Slack notification".into(),
                payload: json!({}),
                revert_steps: vec![],
                verify_probe: None,
            });
        }

        let template = ctx
            .cmd
            .params
            .get("template")
            .and_then(|v| v.as_str())
            .unwrap_or("*{{severity}}*: {{title}} on {{target}}");
        let text = render_slack_template(template, ctx);

        let webhook = config_str(
            &ctx.integration.config,
            &["webhook_url", "url", "incoming_webhook"],
        )
        .or_else(|| std::env::var("SLACK_WEBHOOK_URL").ok())
        .filter(|s| !s.trim().is_empty());

        let client = http_client(10).map_err(AdapterError::Provider)?;

        if let Some(url) = webhook {
            let body = json!({ "text": text });
            let resp = client
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| AdapterError::Provider(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(AdapterError::Provider(format!(
                    "Slack webhook HTTP {}",
                    resp.status()
                )));
            }
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: Some(format!("slack-webhook-{}", ctx.cmd.target_id)),
                detail: "slack webhook delivered".into(),
                payload: json!({ "channel": ctx.cmd.params.get("channel"), "text": text }),
                revert_steps: vec![],
                verify_probe: None,
            });
        }

        let bot_token = config_str(&ctx.integration.config, &["bot_token", "token", "api_key"])
            .ok_or_else(|| {
                AdapterError::Config("slack webhook_url or bot_token required".into())
            })?;
        let channel = ctx
            .cmd
            .params
            .get("channel")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| config_str(&ctx.integration.config, &["channel", "default_channel"]))
            .unwrap_or_else(|| "#sec-ops".to_string());

        let body = json!({ "channel": channel, "text": text });
        let resp = client
            .post("https://slack.com/api/chat.postMessage")
            .bearer_auth(bot_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Provider(e.to_string()))?;
        let status = resp.status();
        let payload: serde_json::Value = resp.json().await.unwrap_or(json!({}));
        if !status.is_success() || payload.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(AdapterError::Provider(format!(
                "Slack API error: {}",
                payload
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
            )));
        }
        let ts = payload
            .get("ts")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Ok(AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(ts.clone()),
            detail: format!("slack message posted to {channel} ts={ts}"),
            payload: json!({ "channel": channel, "ts": ts }),
            revert_steps: self.revert_steps(&AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: Some(ts),
                detail: String::new(),
                payload: json!({ "channel": channel }),
                revert_steps: vec![],
                verify_probe: None,
            }),
            verify_probe: None,
        })
    }

    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep> {
        vec![RevertStep {
            provider: self.provider_id().into(),
            operation: "delete_message".into(),
            payload: outcome.payload.clone(),
            description: "Delete Slack SOAR notification (manual if token lacks chat:write)".into(),
        }]
    }
}

fn render_slack_template(template: &str, ctx: &AdapterContext<'_>) -> String {
    let mut s = template.to_string();
    for (k, v) in [
        ("title", ctx.cmd.evidence.title.as_str()),
        ("target", ctx.cmd.evidence.target.as_str()),
        ("severity", ctx.cmd.evidence.severity.as_str()),
        ("source", ctx.cmd.evidence.source.as_str()),
    ] {
        s = s.replace(&format!("{{{{{k}}}}}"), v);
    }
    s
}
