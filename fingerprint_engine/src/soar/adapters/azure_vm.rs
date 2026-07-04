//! Azure VM network isolation via NSG deny-all rule (Microsoft.Network REST API).

use async_trait::async_trait;
use serde_json::json;

use super::common::{bearer_headers, http_client};
use super::{AdapterContext, AdapterError, IsolateHostAdapter};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct AzureVmIsolateAdapter;

#[async_trait]
impl IsolateHostAdapter for AzureVmIsolateAdapter {
    fn provider_id(&self) -> &'static str {
        "azure_vm"
    }

    async fn isolate(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would attach Azure deny-all NSG rule".into(),
                payload: json!({ "target": ctx.cmd.target_id }),
                revert_steps: vec![],
                verify_probe: None,
            });
        }

        let subscription = config_str(&ctx.integration.config, &["subscription_id"])
            .ok_or_else(|| AdapterError::Config("azure subscription_id required".into()))?;
        let resource_group = config_str(&ctx.integration.config, &["resource_group"])
            .ok_or_else(|| AdapterError::Config("azure resource_group required".into()))?;
        let vm_name = resolve_vm_name(ctx)?;
        let nsg_name = config_str(&ctx.integration.config, &["nsg_name"])
            .unwrap_or_else(|| format!("weissman-quarantine-{vm_name}"));
        let tenant = config_str(&ctx.integration.config, &["tenant_id", "azure_tenant_id"])
            .ok_or_else(|| AdapterError::Config("azure tenant_id required".into()))?;
        let client_id = config_str(&ctx.integration.config, &["client_id", "azure_client_id"])
            .ok_or_else(|| AdapterError::Config("azure client_id required".into()))?;
        let client_secret = config_str(&ctx.integration.config, &["client_secret"])
            .ok_or_else(|| AdapterError::Config("azure client_secret required".into()))?;

        let token = azure_access_token(&tenant, &client_id, &client_secret).await?;
        let rule_name = "weissman-soar-deny-all-inbound";
        let api = "2023-05-01";
        let url = format!(
            "https://management.azure.com/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}/securityRules/{rule_name}?api-version={api}"
        );

        let body = json!({
            "properties": {
                "protocol": "*",
                "sourcePortRange": "*",
                "destinationPortRange": "*",
                "sourceAddressPrefix": "*",
                "destinationAddressPrefix": "*",
                "access": "Deny",
                "priority": 100,
                "direction": "Inbound",
                "description": format!("Weissman SOAR quarantine for VM {vm_name}")
            }
        });

        let client = http_client(30).map_err(AdapterError::Provider)?;
        let resp = client
            .put(&url)
            .headers(bearer_headers(&token))
            .json(&body)
            .send()
            .await
            .map_err(|e| AdapterError::Provider(e.to_string()))?;

        if !resp.status().is_success() && resp.status().as_u16() != 201 {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(AdapterError::Provider(format!(
                "Azure NSG rule HTTP {status}: {}",
                detail.chars().take(400).collect::<String>()
            )));
        }

        let payload = json!({
            "subscription_id": subscription,
            "resource_group": resource_group,
            "vm_name": vm_name,
            "nsg_name": nsg_name,
            "rule_name": rule_name,
            "tenant_id": tenant,
            "client_id": client_id,
        });

        Ok(AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(vm_name.clone()),
            detail: format!("Azure NSG deny-all rule applied to {nsg_name} for VM {vm_name}"),
            payload: payload.clone(),
            revert_steps: self.revert_steps(&AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: Some(vm_name),
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
        _payload: &serde_json::Value,
    ) -> Result<bool, AdapterError> {
        super::aws_ec2::tcp_probe_unreachable_batch(target, ports).await
    }

    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep> {
        vec![RevertStep {
            provider: self.provider_id().into(),
            operation: "remove_nsg_rule".into(),
            payload: outcome.payload.clone(),
            description: "Remove Weissman SOAR deny-all NSG rule from Azure VM".into(),
        }]
    }
}

fn resolve_vm_name(ctx: &AdapterContext<'_>) -> Result<String, AdapterError> {
    let target = ctx.cmd.target_id.trim();
    if !target.is_empty() {
        return Ok(target.to_string());
    }
    Err(AdapterError::Config(
        "azure vm_name / target_id required".into(),
    ))
}

async fn azure_access_token(
    tenant: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, AdapterError> {
    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let client = http_client(15).map_err(AdapterError::Provider)?;
    let resp = client
        .post(&url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", "https://management.azure.com/.default"),
        ])
        .send()
        .await
        .map_err(|e| AdapterError::Provider(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(AdapterError::Provider(format!(
            "Azure OAuth HTTP {}",
            resp.status()
        )));
    }
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| AdapterError::Provider("Azure OAuth missing access_token".into()))
}
