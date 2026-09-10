//! Jira Cloud REST issue adapter.

use async_trait::async_trait;
use serde_json::json;

use super::common::http_client;
use super::servicenow::CreateIncidentAdapter;
use super::{AdapterContext, AdapterError};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct JiraAdapter;

#[async_trait]
impl CreateIncidentAdapter for JiraAdapter {
    fn provider_id(&self) -> &'static str {
        "jira"
    }

    async fn create_incident(
        &self,
        ctx: &AdapterContext<'_>,
    ) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would create Jira issue".into(),
                payload: json!({}),
                revert_steps: vec![],
                verify_probe: None,
            });
        }
        let base = config_str(&ctx.integration.config, &["base_url", "url", "site"])
            .ok_or_else(|| AdapterError::Config("jira base_url required".into()))?;
        let email = config_str(&ctx.integration.config, &["email", "username", "user"])
            .ok_or_else(|| AdapterError::Config("jira email required".into()))?;
        let token = config_str(&ctx.integration.config, &["api_token", "token", "password"])
            .ok_or_else(|| AdapterError::Config("jira api_token required".into()))?;
        let project = config_str(&ctx.integration.config, &["project", "project_key"])
            .unwrap_or_else(|| "SEC".into());
        let client = http_client(20).map_err(AdapterError::Provider)?;
        let url = format!(
            "{}/rest/api/3/issue",
            base.trim_end_matches('/')
        );
        let body = json!({
            "fields": {
                "project": { "key": project },
                "summary": ctx.cmd.evidence.title,
                "issuetype": { "name": "Bug" },
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [{
                        "type": "paragraph",
                        "content": [{
                            "type": "text",
                            "text": format!(
                                "{} — target {} — Weissman SOAR",
                                ctx.cmd.evidence.severity, ctx.cmd.target_id
                            )
                        }]
                    }]
                }
            }
        });
        let resp = client
            .post(&url)
            .basic_auth(email, Some(token))
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Provider(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AdapterError::Provider(format!(
                "Jira HTTP {}",
                resp.status()
            )));
        }
        let parsed: serde_json::Value = resp.json().await.unwrap_or(json!({}));
        let key = parsed
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        Ok(AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(key.clone()),
            detail: format!("jira issue {key} created"),
            payload: parsed,
            revert_steps: vec![],
            verify_probe: None,
        })
    }

    async fn verify_incident(
        &self,
        _sys_id: &str,
        _payload: &serde_json::Value,
    ) -> Result<bool, AdapterError> {
        Ok(true)
    }

    fn revert_steps(&self, _outcome: &AdapterOutcome) -> Vec<RevertStep> {
        vec![]
    }
}
