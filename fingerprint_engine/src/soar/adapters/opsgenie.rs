//! OpsGenie on-call paging adapter (Atlassian).

use async_trait::async_trait;
use rand::RngExt;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::json;

use super::common::http_client;
use super::{AdapterContext, AdapterError, PageOncallAdapter};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct OpsGenieAdapter;

const MAX_ATTEMPTS: u32 = 5;

#[async_trait]
impl PageOncallAdapter for OpsGenieAdapter {
    fn provider_id(&self) -> &'static str {
        "opsgenie"
    }

    async fn page(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would create OpsGenie alert".into(),
                payload: json!({}),
                revert_steps: vec![],
                verify_probe: None,
            });
        }

        let api_key = config_str(
            &ctx.integration.config,
            &["api_key", "genie_key", "token", "routing_key"],
        )
        .or_else(|| std::env::var("OPSGENIE_API_KEY").ok())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| AdapterError::Config("opsgenie api_key required".into()))?;

        let team = ctx
            .cmd
            .params
            .get("team")
            .and_then(|v| v.as_str())
            .unwrap_or("sec-oncall");
        let priority = opsgenie_priority(&ctx.cmd.evidence.severity);
        let message = format!(
            "{}: {} on {}",
            ctx.cmd.evidence.severity, ctx.cmd.evidence.title, ctx.cmd.evidence.target
        );

        let body = json!({
            "message": message,
            "alias": format!("weissman-{}-{}", ctx.cmd.target_id, ctx.cmd.evidence.vulnerability_signature()),
            "description": ctx.cmd.evidence,
            "priority": priority,
            "responders": [{ "type": "team", "name": team }],
            "source": "weissman-soar",
            "tags": ["weissman", "soar", &ctx.cmd.evidence.severity],
        });

        let mut headers = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&format!("GenieKey {api_key}")) {
            headers.insert(AUTHORIZATION, v);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let client = http_client(15).map_err(AdapterError::Provider)?;
        let url = config_str(&ctx.integration.config, &["api_url"])
            .unwrap_or_else(|| "https://api.opsgenie.com/v2/alerts".to_string());

        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                let base = 500u64 * 2u64.saturating_pow(attempt - 1);
                let jitter = rand::rng().random_range(0..base / 4);
                tokio::time::sleep(std::time::Duration::from_millis(base + jitter)).await;
            }
            match client
                .post(&url)
                .headers(headers.clone())
                .json(&body)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    let alias = body
                        .get("alias")
                        .and_then(|v| v.as_str())
                        .unwrap_or("opsgenie-alert")
                        .to_string();
                    let request_id = resp
                        .json::<serde_json::Value>()
                        .await
                        .ok()
                        .and_then(|v| {
                            v.get("requestId")
                                .and_then(|r| r.as_str())
                                .map(str::to_string)
                        })
                        .unwrap_or_else(|| alias.clone());
                    return Ok(AdapterOutcome {
                        provider: self.provider_id().into(),
                        external_ref: Some(request_id.clone()),
                        detail: format!(
                            "opsgenie alert created alias={alias} requestId={request_id}"
                        ),
                        payload: json!({ "alias": alias, "api_key_hint": "***" }),
                        revert_steps: self.revert_steps(&AdapterOutcome {
                            provider: self.provider_id().into(),
                            external_ref: Some(alias.clone()),
                            detail: String::new(),
                            payload: json!({ "alias": alias, "api_key": api_key }),
                            revert_steps: vec![],
                            verify_probe: None,
                        }),
                        verify_probe: None,
                    });
                }
                Ok(resp) if resp.status().as_u16() == 429 => {
                    last_err = format!("rate limited HTTP 429 attempt {}", attempt + 1);
                    continue;
                }
                Ok(resp) => {
                    last_err = format!("HTTP {}", resp.status());
                    if resp.status().is_server_error() {
                        continue;
                    }
                    return Err(AdapterError::Provider(last_err));
                }
                Err(e) => {
                    last_err = e.to_string();
                    continue;
                }
            }
        }
        Err(AdapterError::Provider(last_err))
    }

    async fn verify_delivery(
        &self,
        _external_ref: &str,
        _payload: &serde_json::Value,
    ) -> Result<bool, AdapterError> {
        Ok(true)
    }

    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep> {
        let alias = outcome
            .external_ref
            .clone()
            .or_else(|| {
                outcome
                    .payload
                    .get("alias")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        vec![RevertStep {
            provider: self.provider_id().into(),
            operation: "close_alert".into(),
            payload: json!({
                "alias": alias,
                "api_key": outcome.payload.get("api_key").cloned().unwrap_or(json!("")),
            }),
            description: "Close OpsGenie alert opened by SOAR".into(),
        }]
    }
}

fn opsgenie_priority(sev: &str) -> &str {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => "P1",
        "high" => "P2",
        "medium" => "P3",
        "low" => "P4",
        _ => "P3",
    }
}
