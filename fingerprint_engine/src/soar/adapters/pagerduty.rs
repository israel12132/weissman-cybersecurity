//! PagerDuty / generic on-call paging adapter with exponential backoff.

use async_trait::async_trait;
use rand::RngExt;
use serde_json::json;

use super::{AdapterContext, AdapterError, PageOncallAdapter};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct PagerDutyAdapter;

const MAX_ATTEMPTS: u32 = 5;

#[async_trait]
impl PageOncallAdapter for PagerDutyAdapter {
    fn provider_id(&self) -> &'static str {
        "pagerduty"
    }

    async fn page(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would page on-call".into(),
                payload: json!({}),
                revert_steps: vec![],
                verify_probe: None,
            });
        }

        let team = ctx
            .cmd
            .params
            .get("team")
            .and_then(|v| v.as_str())
            .unwrap_or("sec-oncall");
        let severity = ctx
            .cmd
            .params
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or(&ctx.cmd.evidence.severity);

        let routing_key = config_str(&ctx.integration.config, &["routing_key", "key"])
            .or_else(|| std::env::var("PAGERDUTY_ROUTING_KEY").ok())
            .or_else(|| std::env::var("WEISSMAN_PAGER_WEBHOOK_URL").ok())
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                AdapterError::Config(
                    "pagerduty routing_key or WEISSMAN_PAGER_WEBHOOK_URL required".into(),
                )
            })?;

        let summary = format!(
            "{}: {} on {}",
            severity, ctx.cmd.evidence.title, ctx.cmd.evidence.target
        );
        let body = if routing_key.starts_with("http://") || routing_key.starts_with("https://") {
            json!({
                "team": team,
                "severity": severity,
                "summary": summary,
                "details": ctx.cmd.evidence,
            })
        } else {
            json!({
                "routing_key": routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": summary,
                    "severity": pagerduty_severity(severity),
                    "source": "weissman-soar",
                    "custom_details": ctx.cmd.evidence,
                }
            })
        };

        let url = if routing_key.starts_with("http") {
            routing_key.clone()
        } else {
            "https://events.pagerduty.com/v2/enqueue".to_string()
        };

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| AdapterError::Provider(e.to_string()))?;

        let mut last_err = String::new();
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                let base = 500u64 * 2u64.saturating_pow(attempt - 1);
                let jitter = rand::rng().random_range(0..base / 4);
                tokio::time::sleep(std::time::Duration::from_millis(base + jitter)).await;
            }
            match client.post(&url).json(&body).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let dedup_key = resp
                        .json::<serde_json::Value>()
                        .await
                        .ok()
                        .and_then(|v| {
                            v.get("dedup_key")
                                .and_then(|k| k.as_str())
                                .map(str::to_string)
                        })
                        .unwrap_or_else(|| format!("page-{}-{}", team, ctx.cmd.target_id));
                    let payload = json!({ "team": team, "dedup_key": dedup_key, "url": url });
                    return Ok(AdapterOutcome {
                        provider: self.provider_id().into(),
                        external_ref: Some(dedup_key.clone()),
                        detail: format!("paged team={team} dedup={dedup_key}"),
                        payload,
                        revert_steps: self.revert_steps(&AdapterOutcome {
                            provider: self.provider_id().into(),
                            external_ref: Some(dedup_key),
                            detail: String::new(),
                            payload: json!({ "routing_key": routing_key }),
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
        let dedup = outcome.external_ref.clone().unwrap_or_default();
        let routing_key = outcome
            .payload
            .get("routing_key")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        vec![RevertStep {
            provider: self.provider_id().into(),
            operation: "resolve_incident".into(),
            payload: json!({
                "routing_key": routing_key,
                "dedup_key": dedup,
                "event_action": "resolve",
            }),
            description: "Resolve PagerDuty incident opened by SOAR".into(),
        }]
    }
}

fn pagerduty_severity(sev: &str) -> &str {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "error",
        "medium" => "warning",
        "low" => "info",
        _ => "error",
    }
}
