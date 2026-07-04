//! AWS EC2 host isolation via security-group quarantine.

use async_trait::async_trait;
use aws_config::Region;
use serde_json::json;
use sqlx::Row;

use super::{AdapterContext, AdapterError, IsolateHostAdapter};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct AwsEc2IsolateAdapter;

#[async_trait]
impl IsolateHostAdapter for AwsEc2IsolateAdapter {
    fn provider_id(&self) -> &'static str {
        "aws_ec2"
    }

    async fn isolate(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        if ctx.cmd.dry_run {
            return Ok(AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: None,
                detail: "dry_run: would quarantine EC2 instance".into(),
                payload: json!({ "target": ctx.cmd.target_id }),
                revert_steps: vec![],
                verify_probe: None,
            });
        }

        let instance_id = resolve_instance_id(ctx).await?;
        let region = config_str(&ctx.integration.config, &["region", "aws_region"])
            .unwrap_or_else(|| "us-east-1".to_string());
        let forensic_cidr = config_str(
            &ctx.integration.config,
            &["forensic_source_cidr", "forensic_cidr"],
        )
        .or_else(|| std::env::var("WEISSMAN_FORENSIC_CIDR").ok())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| AdapterError::Config("forensic_source_cidr required".into()))?;
        let ports_csv = config_str(&ctx.integration.config, &["forensic_ports_csv"])
            .unwrap_or_else(|| "22,443".to_string());
        let allow_dns = ctx
            .integration
            .config
            .get("allow_dns_egress")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let vpc_dns = config_str(&ctx.integration.config, &["vpc_dns_cidr"])
            .unwrap_or_else(|| "169.254.169.253/32".to_string());

        let (role_arn, ext_id) = load_client_aws_role(ctx).await?;
        if role_arn.is_empty() {
            return Err(AdapterError::Config(
                "client aws_cross_account_role_arn required".into(),
            ));
        }

        let aws_cfg = crate::cloud_integration_engine::CrossAccountAwsConfig {
            role_arn,
            external_id: ext_id,
            session_name: format!("weissman-soar-{}", ctx.cmd.tenant_id),
        };

        let detail = crate::cloud_containment_engine::execute_aws_containment(
            &aws_cfg,
            &region,
            &instance_id,
            &forensic_cidr,
            &ports_csv,
            allow_dns,
            &vpc_dns,
        )
        .await
        .map_err(AdapterError::Provider)?;

        let payload = json!({
            "instance_id": instance_id,
            "region": region,
            "forensic_cidr": forensic_cidr,
            "ports_csv": ports_csv,
            "quarantine_detail": detail,
        });

        let outcome = AdapterOutcome {
            provider: self.provider_id().into(),
            external_ref: Some(instance_id.clone()),
            detail: detail.clone(),
            payload: payload.clone(),
            revert_steps: self.revert_steps(&AdapterOutcome {
                provider: self.provider_id().into(),
                external_ref: Some(instance_id),
                detail,
                payload,
                revert_steps: vec![],
                verify_probe: None,
            }),
            verify_probe: None,
        };
        Ok(outcome)
    }

    async fn verify_isolated(
        &self,
        target: &str,
        ports: &[u16],
        _payload: &serde_json::Value,
    ) -> Result<bool, AdapterError> {
        let probe_host = if target.starts_with("i-") {
            resolve_public_ip_hint(target)
                .await
                .unwrap_or_else(|| target.to_string())
        } else {
            target.to_string()
        };

        let ports_use: Vec<u16> = if ports.is_empty() {
            super::default_verify_ports()
        } else {
            ports.to_vec()
        };

        let port_count = ports_use.len() as u32;
        let mut unreachable = 0u32;
        for port in &ports_use {
            if tcp_probe_unreachable(&probe_host, *port).await {
                unreachable += 1;
            }
        }
        let required = port_count.saturating_sub(1).max(1);
        Ok(unreachable >= required)
    }

    fn revert_steps(&self, outcome: &AdapterOutcome) -> Vec<RevertStep> {
        let instance_id = outcome
            .external_ref
            .clone()
            .or_else(|| {
                outcome
                    .payload
                    .get("instance_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let region = outcome
            .payload
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1");
        vec![RevertStep {
            provider: self.provider_id().into(),
            operation: "restore_ec2_security_groups".into(),
            payload: json!({
                "instance_id": instance_id,
                "region": region,
                "action": "detach_quarantine_sg_restore_previous",
            }),
            description: format!("Restore pre-quarantine security groups on {instance_id}"),
        }]
    }
}

async fn resolve_instance_id(ctx: &AdapterContext<'_>) -> Result<String, AdapterError> {
    let target = ctx.cmd.target_id.trim();
    if target.starts_with("i-") && target.len() >= 10 {
        return Ok(target.to_string());
    }
    let Some(client_id) = ctx.cmd.client_id else {
        return Err(AdapterError::Config(
            "target must be EC2 instance id (i-…) or provide client context".into(),
        ));
    };
    let Ok(mut tx) = crate::db::begin_tenant_tx(ctx.pool, ctx.cmd.tenant_id).await else {
        return Err(AdapterError::Config("tenant tx failed".into()));
    };
    let row = sqlx::query(
        r#"SELECT label, metadata FROM risk_graph_nodes
           WHERE client_id = $1 AND (lower(label) = lower($2) OR metadata ILIKE '%' || $2 || '%')
           LIMIT 1"#,
    )
    .bind(client_id)
    .bind(target)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AdapterError::Config(e.to_string()))?;
    let _ = tx.commit().await;
    if let Some(r) = row {
        let meta: String = r.try_get("metadata").unwrap_or_default();
        if let Some(iid) = extract_instance_id(&meta) {
            return Ok(iid);
        }
        let label: String = r.try_get("label").unwrap_or_default();
        if label.starts_with("i-") {
            return Ok(label);
        }
    }
    Err(AdapterError::Config(format!(
        "cannot resolve EC2 instance id for target {target}"
    )))
}

fn extract_instance_id(s: &str) -> Option<String> {
    for word in s.split(|c: char| !c.is_alphanumeric() && c != '-') {
        if word.starts_with("i-") && word.len() >= 10 {
            return Some(word.to_string());
        }
    }
    None
}

async fn load_client_aws_role(ctx: &AdapterContext<'_>) -> Result<(String, String), AdapterError> {
    let role_from_int = config_str(
        &ctx.integration.config,
        &["role_arn", "aws_cross_account_role_arn"],
    );
    let ext_from_int = config_str(&ctx.integration.config, &["external_id", "aws_external_id"])
        .unwrap_or_default();
    if let Some(arn) = role_from_int.filter(|s| !s.is_empty()) {
        return Ok((arn, ext_from_int));
    }
    let Some(client_id) = ctx.cmd.client_id else {
        return Ok((String::new(), String::new()));
    };
    let Ok(mut tx) = crate::db::begin_tenant_tx(ctx.pool, ctx.cmd.tenant_id).await else {
        return Err(AdapterError::Config("tenant tx".into()));
    };
    let row = sqlx::query(
        "SELECT COALESCE(trim(aws_cross_account_role_arn),'') AS arn, COALESCE(trim(aws_external_id),'') AS ext FROM clients WHERE id = $1",
    )
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AdapterError::Config(e.to_string()))?;
    let _ = tx.commit().await;
    match row {
        Some(r) => Ok((
            r.try_get("arn").unwrap_or_default(),
            r.try_get("ext").unwrap_or_default(),
        )),
        None => Ok((String::new(), String::new())),
    }
}

async fn resolve_public_ip_hint(_instance_id: &str) -> Option<String> {
    None
}

async fn tcp_probe_unreachable(host: &str, port: u16) -> bool {
    let addr = format!("{host}:{port}");
    let Ok(stream) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    else {
        return true;
    };
    stream.is_err()
}

pub async fn tcp_probe_unreachable_batch(
    host: &str,
    ports: &[u16],
) -> Result<bool, super::AdapterError> {
    let ports_use: Vec<u16> = if ports.is_empty() {
        super::default_verify_ports()
    } else {
        ports.to_vec()
    };
    let port_count = ports_use.len() as u32;
    let mut unreachable = 0u32;
    for port in &ports_use {
        if tcp_probe_unreachable(host, *port).await {
            unreachable += 1;
        }
    }
    let required = port_count.saturating_sub(1).max(1);
    Ok(unreachable >= required)
}
