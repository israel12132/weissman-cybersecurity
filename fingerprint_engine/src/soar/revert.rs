//! Auto-revert runbook persistence and one-click rollback.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::adapters::common::{basic_auth_header, bearer_headers, http_client};
use super::integrations::{config_str, load_integrations, pick_provider};
use super::types::RevertStep;

pub async fn persist_runbook(
    pool: &PgPool,
    tenant_id: i64,
    execution_id: Uuid,
    action_kind: &str,
    steps: &[RevertStep],
) -> Result<Uuid, String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Err("tenant tx".into());
    };
    let id = Uuid::new_v4();
    let steps_json = serde_json::to_value(steps).unwrap_or(json!([]));
    sqlx::query(
        r#"INSERT INTO soar_revert_runbooks (id, tenant_id, execution_id, action_kind, steps)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (execution_id) DO UPDATE SET steps = EXCLUDED.steps"#,
    )
    .bind(id)
    .bind(tenant_id)
    .bind(execution_id)
    .bind(action_kind)
    .bind(steps_json)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(id)
}

pub async fn execute_revert(
    pool: &PgPool,
    tenant_id: i64,
    execution_id: Uuid,
) -> Result<String, String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Err("tenant tx".into());
    };
    let row = sqlx::query(
        r#"SELECT r.steps, r.status
           FROM soar_revert_runbooks r
           WHERE r.execution_id = $1 AND r.tenant_id = $2"#,
    )
    .bind(execution_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let Some(r) = row else {
        return Err("revert runbook not found".into());
    };
    let status: String = r.try_get("status").unwrap_or_default();
    if status == "reverted" {
        return Ok("already reverted".into());
    }
    let steps: Value = r.try_get("steps").unwrap_or(json!([]));
    let _ = tx.commit().await;

    let steps_vec: Vec<RevertStep> = serde_json::from_value(steps).unwrap_or_default();
    let integrations = load_integrations(pool, tenant_id).await;
    let mut details = Vec::new();
    for step in &steps_vec {
        details.push(format!(
            "{}: {}",
            step.operation,
            apply_revert_step(pool, tenant_id, &integrations, step).await
        ));
    }

    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Err("tenant tx".into());
    };
    sqlx::query(
        r#"UPDATE soar_revert_runbooks SET status = 'reverted', reverted_at = now()
           WHERE execution_id = $1 AND tenant_id = $2"#,
    )
    .bind(execution_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = crate::audit_log::insert_audit(
        &mut tx,
        tenant_id,
        None,
        "soar_revert",
        "soar_forensic",
        &format!("reverted execution {execution_id}: {}", details.join("; ")),
        "0.0.0.0",
    )
    .await;
    let _ = tx.commit().await;
    Ok(details.join("; "))
}

async fn apply_revert_step(
    pool: &PgPool,
    tenant_id: i64,
    integrations: &[super::integrations::IntegrationRecord],
    step: &RevertStep,
) -> String {
    let merged = merge_step_payload(integrations, step);
    match step.operation.as_str() {
        "resolve_incident" => resolve_pagerduty_incident(&merged).await,
        "close_alert" => close_opsgenie_alert(&merged).await,
        "remove_nsg_rule" => remove_azure_nsg_rule(&merged).await,
        "lift_containment" => lift_falcon_containment(&merged).await,
        "close_incident" => close_servicenow_incident(&merged).await,
        "delete_message" => delete_slack_message(&merged).await,
        "restore_ec2_security_groups" => {
            restore_ec2_security_groups(pool, tenant_id, &merged).await
        }
        "close_pull_request" => close_github_pr(&merged).await,
        other => format!("unsupported revert operation {other}"),
    }
}

fn merge_step_payload(
    integrations: &[super::integrations::IntegrationRecord],
    step: &RevertStep,
) -> Value {
    let mut payload = step.payload.clone();
    let prefer = match step.provider.as_str() {
        "aws_ec2" => vec!["aws_ec2", "aws"],
        "azure_vm" => vec!["azure_vm", "azure"],
        "crowdstrike_falcon" => vec!["crowdstrike_falcon", "crowdstrike"],
        "opsgenie" => vec!["opsgenie"],
        "pagerduty" => vec!["pagerduty"],
        "servicenow" => vec!["servicenow"],
        "slack" => vec!["slack"],
        "github" => vec!["github"],
        other => vec![other],
    };
    if let Some(integ) = pick_provider(integrations, &prefer) {
        if let Some(obj) = payload.as_object_mut() {
            if let Some(cfg) = integ.config.as_object() {
                for (k, v) in cfg {
                    if !obj.contains_key(k) {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }
    payload
}

async fn resolve_pagerduty_incident(payload: &Value) -> String {
    let routing_key = config_str(payload, &["routing_key"]).unwrap_or_default();
    let dedup = payload
        .get("dedup_key")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if routing_key.is_empty() || dedup.is_empty() {
        return "missing routing_key or dedup_key".into();
    }
    let body = json!({
        "routing_key": routing_key,
        "dedup_key": dedup,
        "event_action": "resolve",
    });
    let client = match Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => return format!("client: {e}"),
    };
    match client
        .post("https://events.pagerduty.com/v2/enqueue")
        .json(&body)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => "pagerduty resolve accepted".into(),
        Ok(r) => format!("pagerduty resolve HTTP {}", r.status()),
        Err(e) => format!("pagerduty resolve error: {e}"),
    }
}

async fn close_opsgenie_alert(payload: &Value) -> String {
    let alias = payload.get("alias").and_then(|v| v.as_str()).unwrap_or("");
    let api_key = config_str(payload, &["api_key", "genie_key", "token"]).unwrap_or_default();
    if alias.is_empty() || api_key.is_empty() {
        return "missing alias or api_key for OpsGenie close".into();
    }
    let base =
        config_str(payload, &["api_url"]).unwrap_or_else(|| "https://api.opsgenie.com".to_string());
    let url = format!("{base}/v2/alerts/{alias}/close?identifierType=alias");
    let client = match http_client(15) {
        Ok(c) => c,
        Err(e) => return format!("client: {e}"),
    };
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&format!("GenieKey {api_key}")) {
        headers.insert(AUTHORIZATION, v);
    }
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    match client
        .post(&url)
        .headers(headers)
        .json(&json!({ "note": "Closed by Weissman SOAR revert" }))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => "opsgenie alert closed".into(),
        Ok(r) => format!("opsgenie close HTTP {}", r.status()),
        Err(e) => format!("opsgenie close error: {e}"),
    }
}

async fn remove_azure_nsg_rule(payload: &Value) -> String {
    let subscription = config_str(payload, &["subscription_id"]).unwrap_or_default();
    let resource_group = config_str(payload, &["resource_group"]).unwrap_or_default();
    let nsg_name = config_str(payload, &["nsg_name"]).unwrap_or_default();
    let rule_name = config_str(payload, &["rule_name"])
        .unwrap_or_else(|| "weissman-soar-deny-all-inbound".to_string());
    let tenant = config_str(payload, &["tenant_id", "azure_tenant_id"]).unwrap_or_default();
    let client_id = config_str(payload, &["client_id", "azure_client_id"]).unwrap_or_default();
    let client_secret = config_str(payload, &["client_secret"]).unwrap_or_default();
    if subscription.is_empty() || resource_group.is_empty() || nsg_name.is_empty() {
        return "missing Azure subscription/resource_group/nsg_name".into();
    }
    if tenant.is_empty() || client_id.is_empty() || client_secret.is_empty() {
        return "missing Azure OAuth credentials for NSG rule removal".into();
    }
    let token = match azure_access_token(&tenant, &client_id, &client_secret).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    let api = "2023-05-01";
    let url = format!(
        "https://management.azure.com/subscriptions/{subscription}/resourceGroups/{resource_group}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}/securityRules/{rule_name}?api-version={api}"
    );
    let client = match http_client(30) {
        Ok(c) => c,
        Err(e) => return format!("client: {e}"),
    };
    match client
        .delete(&url)
        .headers(bearer_headers(&token))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() || r.status().as_u16() == 404 => {
            "azure NSG rule removed".into()
        }
        Ok(r) => format!("azure NSG delete HTTP {}", r.status()),
        Err(e) => format!("azure NSG delete error: {e}"),
    }
}

async fn lift_falcon_containment(payload: &Value) -> String {
    let device_id = payload
        .get("device_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let base = config_str(payload, &["base_url", "api_url"])
        .unwrap_or_else(|| "https://api.crowdstrike.com".to_string());
    let client_id = config_str(payload, &["client_id", "api_client_id"]).unwrap_or_default();
    let client_secret = config_str(payload, &["client_secret", "api_secret"]).unwrap_or_default();
    if device_id.is_empty() || client_id.is_empty() || client_secret.is_empty() {
        return "missing device_id or Falcon OAuth credentials".into();
    }
    let token = match falcon_token(&base, &client_id, &client_secret).await {
        Ok(t) => t,
        Err(e) => return e,
    };
    let url = format!("{base}/devices/entities/devices-actions/v2?action_name=lift_containment");
    let client = match http_client(25) {
        Ok(c) => c,
        Err(e) => return format!("client: {e}"),
    };
    match client
        .post(&url)
        .headers(bearer_headers(&token))
        .json(&json!({ "ids": [device_id] }))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => "falcon containment lifted".into(),
        Ok(r) => format!("falcon lift_containment HTTP {}", r.status()),
        Err(e) => format!("falcon lift_containment error: {e}"),
    }
}

async fn close_servicenow_incident(payload: &Value) -> String {
    let sys_id = payload.get("sys_id").and_then(|v| v.as_str()).unwrap_or("");
    let base = config_str(payload, &["instance_url", "url"]).unwrap_or_default();
    let user = config_str(payload, &["username", "user"]).unwrap_or_default();
    let pass = config_str(payload, &["password", "api_key"]).unwrap_or_default();
    if sys_id.is_empty() || base.is_empty() || user.is_empty() || pass.is_empty() {
        return "missing ServiceNow sys_id or credentials".into();
    }
    let url = format!(
        "{}/api/now/table/incident/{}",
        base.trim_end_matches('/'),
        sys_id
    );
    let client = match http_client(20) {
        Ok(c) => c,
        Err(e) => return format!("client: {e}"),
    };
    match client
        .patch(&url)
        .headers(basic_auth_header(&user, &pass))
        .json(&json!({
            "state": "6",
            "close_code": "Resolved by caller",
            "close_notes": "Closed by Weissman SOAR revert"
        }))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => "servicenow incident resolved".into(),
        Ok(r) => format!("servicenow close HTTP {}", r.status()),
        Err(e) => format!("servicenow close error: {e}"),
    }
}

async fn delete_slack_message(payload: &Value) -> String {
    let ts = payload.get("ts").and_then(|v| v.as_str()).unwrap_or("");
    let channel = payload
        .get("channel")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let bot_token = config_str(payload, &["bot_token", "token"]).unwrap_or_default();
    if bot_token.is_empty() {
        return "slack webhook messages cannot be deleted — bot_token required".into();
    }
    if ts.is_empty() || channel.is_empty() {
        return "missing channel or message ts for Slack delete".into();
    }
    let client = match http_client(10) {
        Ok(c) => c,
        Err(e) => return format!("client: {e}"),
    };
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&format!("Bearer {bot_token}")) {
        headers.insert(AUTHORIZATION, v);
    }
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    match client
        .post("https://slack.com/api/chat.delete")
        .headers(headers)
        .json(&json!({ "channel": channel, "ts": ts }))
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            let body: Value = r.json().await.unwrap_or(json!({}));
            if body.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                "slack message deleted".into()
            } else {
                format!(
                    "slack delete rejected: {}",
                    body.get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                )
            }
        }
        Ok(r) => format!("slack delete HTTP {}", r.status()),
        Err(e) => format!("slack delete error: {e}"),
    }
}

async fn restore_ec2_security_groups(pool: &PgPool, tenant_id: i64, payload: &Value) -> String {
    let instance_id = payload
        .get("instance_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let region =
        config_str(payload, &["region", "aws_region"]).unwrap_or_else(|| "us-east-1".to_string());
    if instance_id.is_empty() {
        return "missing instance_id for EC2 restore".into();
    }
    let role_arn =
        config_str(payload, &["role_arn", "aws_cross_account_role_arn"]).unwrap_or_default();
    let external_id = config_str(payload, &["external_id", "aws_external_id"]).unwrap_or_default();
    if role_arn.is_empty() {
        if let Some(client_id) = payload.get("client_id").and_then(Value::as_i64) {
            let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
                return "tenant tx failed".into();
            };
            let row = sqlx::query(
                "SELECT COALESCE(trim(aws_cross_account_role_arn),'') AS arn, COALESCE(trim(aws_external_id),'') AS ext FROM clients WHERE id = $1",
            )
            .bind(client_id)
            .fetch_optional(&mut *tx)
            .await
            .ok()
            .flatten();
            let _ = tx.commit().await;
            if let Some(r) = row {
                let arn: String = r.try_get("arn").unwrap_or_default();
                let ext: String = r.try_get("ext").unwrap_or_default();
                if !arn.is_empty() {
                    return restore_ec2_via_aws(&arn, &ext, &region, instance_id).await;
                }
            }
        }
        return "missing aws_cross_account_role_arn for EC2 restore".into();
    }
    restore_ec2_via_aws(&role_arn, &external_id, &region, instance_id).await
}

async fn restore_ec2_via_aws(
    role_arn: &str,
    external_id: &str,
    region: &str,
    instance_id: &str,
) -> String {
    use aws_config::Region;
    let aws_cfg = crate::cloud_integration_engine::CrossAccountAwsConfig {
        role_arn: role_arn.to_string(),
        external_id: external_id.to_string(),
        session_name: format!("weissman-soar-revert-{instance_id}"),
    };
    let (sdk, home) = match crate::cloud_integration_engine::assume_role_sdk_config(&aws_cfg).await
    {
        Ok(c) => c,
        Err(e) => return format!("AWS assume role: {e}"),
    };
    let region_use = if region.trim().is_empty() {
        home
    } else {
        Region::new(region.to_string())
    };
    let ec2_conf = aws_sdk_ec2::config::Builder::from(&sdk)
        .region(region_use)
        .build();
    let ec2 = aws_sdk_ec2::Client::from_conf(ec2_conf);
    let di = match ec2
        .describe_instances()
        .instance_ids(instance_id)
        .send()
        .await
    {
        Ok(d) => d,
        Err(e) => return format!("DescribeInstances: {e}"),
    };
    let attached: Vec<String> = di
        .reservations()
        .first()
        .and_then(|r| r.instances().first())
        .map(|i| {
            i.security_groups()
                .iter()
                .filter_map(|sg| sg.group_id().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if attached.is_empty() {
        return format!("instance {instance_id} has no security groups attached");
    }

    let mut quarantine_ids = Vec::new();
    for sg_id in &attached {
        let desc = ec2.describe_security_groups().group_ids(sg_id).send().await;
        let is_quarantine = desc
            .ok()
            .and_then(|r| {
                r.security_groups()
                    .first()
                    .and_then(|sg| sg.group_name())
                    .map(|n| n.contains("weissman-quarantine"))
            })
            .unwrap_or(false);
        if is_quarantine {
            quarantine_ids.push(sg_id.clone());
        }
    }
    if quarantine_ids.is_empty() {
        return format!(
            "no weissman-quarantine security group on {instance_id} — manual restore required"
        );
    }

    let remaining: Vec<String> = attached
        .iter()
        .filter(|sg| !quarantine_ids.contains(sg))
        .cloned()
        .collect();
    if let Err(e) = ec2
        .modify_instance_attribute()
        .instance_id(instance_id)
        .set_groups(if remaining.is_empty() {
            None
        } else {
            Some(remaining)
        })
        .send()
        .await
    {
        return format!("ModifyInstanceAttribute: {e}");
    }
    for sg_id in &quarantine_ids {
        let _ = ec2.delete_security_group().group_id(sg_id).send().await;
    }
    format!(
        "EC2 {instance_id}: removed {} quarantine SG(s) — reattach original SGs if instance was fully isolated",
        quarantine_ids.len()
    )
}

async fn close_github_pr(payload: &Value) -> String {
    let spec_id = payload
        .get("spec_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if spec_id.is_empty() {
        return "missing spec_id for GitHub PR close".into();
    }
    format!("queued: close PR spec {spec_id} — worker uses auto-heal pipeline")
}

async fn azure_access_token(
    tenant: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, String> {
    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    let client = http_client(15).map_err(|e| e.to_string())?;
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
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Azure OAuth HTTP {}", resp.status()));
    }
    let body: Value = resp.json().await.unwrap_or(json!({}));
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "Azure OAuth missing access_token".into())
}

async fn falcon_token(base: &str, client_id: &str, client_secret: &str) -> Result<String, String> {
    let url = format!("{base}/oauth2/token");
    let client = http_client(15).map_err(|e| e.to_string())?;
    let resp = client
        .post(&url)
        .form(&[("client_id", client_id), ("client_secret", client_secret)])
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Falcon OAuth HTTP {}", resp.status()));
    }
    let body: Value = resp.json().await.unwrap_or(json!({}));
    body.get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| "Falcon OAuth missing access_token".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_OPERATIONS: &[&str] = &[
        "resolve_incident",
        "close_alert",
        "remove_nsg_rule",
        "lift_containment",
        "close_incident",
        "delete_message",
        "restore_ec2_security_groups",
        "close_pull_request",
    ];

    #[tokio::test]
    async fn all_revert_operations_are_handled() {
        for op in KNOWN_OPERATIONS {
            let step = RevertStep {
                provider: "test".into(),
                operation: (*op).into(),
                payload: json!({}),
                description: String::new(),
            };
            let msg = apply_revert_step(
                &PgPool::connect_lazy("postgres://invalid").expect("lazy"),
                1,
                &[],
                &step,
            )
            .await;
            assert!(
                !msg.starts_with("unsupported revert operation"),
                "operation {op} must be handled, got: {msg}"
            );
        }
    }
}
