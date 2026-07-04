//! ServiceNow incident creation adapter (Table API).

use async_trait::async_trait;
use serde_json::json;

use super::common::{basic_auth_header, http_client};
use super::{AdapterContext, AdapterError};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct ServiceNowAdapter;

#[async_trait]
pub trait CreateIncidentAdapter: Send + Sync {
    fn provider_id(&self) -> &'static str;
    async fn create_incident(
        &self,
        ctx: &AdapterContext<'_>,
    ) -> Result<AdapterOutcome, AdapterError>;
    async fn verify_incident(
        &self,
        sys_id: &str,
        payload: &serde_json::Value,
    ) -> Result<bool, AdapterError>;
    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep>;
}

#[async_trait]
impl CreateIncidentAdapter for ServiceNowAdapter {
    fn provider_id(&self) -> &'static str {
        "servicenow"
    }

    async fn create_incident(
        &self,
        ctx: &AdapterContext<'_>,
    ) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would create ServiceNow incident".into(),
                payload: json!({}),
                revert_steps: vec![],
                verify_probe: None,
            });
        }

        let instance = config_str(
            &ctx.integration.config,
            &["instance_url", "url", "endpoint"],
        )
        .ok_or_else(|| AdapterError::Config("servicenow instance_url required".into()))?;
        let user = config_str(&ctx.integration.config, &["username", "user"])
            .ok_or_else(|| AdapterError::Config("servicenow username required".into()))?;
        let pass = config_str(&ctx.integration.config, &["password", "api_key"])
            .ok_or_else(|| AdapterError::Config("servicenow password required".into()))?;

        let base = instance.trim_end_matches('/');
        let url = format!("{base}/api/now/table/incident");

        let short_desc = ctx
            .cmd
            .params
            .get("short_description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("[Weissman SOAR] {}", ctx.cmd.evidence.title));

        let urgency = snow_urgency(&ctx.cmd.evidence.severity);
        let body = json!({
            "short_description": short_desc,
            "description": format!(
                "Weissman SOAR automated incident\nTarget: {}\nSeverity: {}\nSource: {}\nEvidence: {}",
                ctx.cmd.evidence.target,
                ctx.cmd.evidence.severity,
                ctx.cmd.evidence.source,
                serde_json::to_string(&ctx.cmd.evidence).unwrap_or_default()
            ),
            "urgency": urgency,
            "impact": urgency,
            "category": "security",
            "assignment_group": ctx.cmd.params.get("assignment_group").and_then(|v| v.as_str()).unwrap_or("Security Operations"),
        });

        let client = http_client(20).map_err(AdapterError::Provider)?;
        let resp = client
            .post(&url)
            .headers(basic_auth_header(&user, &pass))
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Provider(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(AdapterError::Provider(format!(
                "ServiceNow incident HTTP {}",
                resp.status()
            )));
        }

        let payload: serde_json::Value = resp.json().await.unwrap_or(json!({}));
        let sys_id = payload
            .get("result")
            .and_then(|r| r.get("sys_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let number = payload
            .get("result")
            .and_then(|r| r.get("number"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        Ok(AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(sys_id.clone()),
            detail: format!("ServiceNow incident {number} created sys_id={sys_id}"),
            payload: json!({
                "sys_id": sys_id,
                "number": number,
                "instance_url": base,
                "username": user,
            }),
            revert_steps: self.revert_steps(&AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: Some(sys_id.clone()),
                detail: String::new(),
                payload: json!({ "sys_id": sys_id, "instance_url": base, "username": user, "password": pass }),
                revert_steps: vec![],
                verify_probe: None,
            }),
            verify_probe: Some(crate::soar::types::VerifyProbeSpec {
                probe_type: "incident_exists".into(),
                target: sys_id,
                expect_unreachable: false,
                ports: vec![],
            }),
        })
    }

    async fn verify_incident(
        &self,
        sys_id: &str,
        payload: &serde_json::Value,
    ) -> Result<bool, AdapterError> {
        let base = payload
            .get("instance_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let user = payload
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pass = payload
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if base.is_empty() || sys_id.is_empty() {
            return Ok(false);
        }
        let url = format!("{base}/api/now/table/incident/{sys_id}?sysparm_fields=number,state");
        let client = http_client(10).map_err(AdapterError::Provider)?;
        let resp = client
            .get(&url)
            .headers(basic_auth_header(user, pass))
            .send()
            .await
            .map_err(|e| AdapterError::Provider(e.to_string()))?;
        Ok(resp.status().is_success())
    }

    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep> {
        vec![RevertStep {
            provider: self.provider_id().into(),
            operation: "close_incident".into(),
            payload: outcome.payload.clone(),
            description: "Resolve ServiceNow incident opened by SOAR".into(),
        }]
    }
}

fn snow_urgency(sev: &str) -> &str {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => "1",
        "high" => "2",
        "medium" => "3",
        _ => "3",
    }
}
