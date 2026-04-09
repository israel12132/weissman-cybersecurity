//! Worker execution for `deception_cloud_deploy` async jobs (cloud honeytoken injection).

use crate::db;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, serde::Deserialize)]
struct DeployRequest {
    asset_ids: Vec<i64>,
    s3_bucket: Option<String>,
    s3_object_key: Option<String>,
    s3_region: Option<String>,
    ssm_parameter_path: Option<String>,
}

pub async fn run_deception_cloud_deploy(
    app_pool: Arc<PgPool>,
    tenant_id: i64,
    deployment_id: Uuid,
) -> Result<Value, String> {
    let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let row = sqlx::query(
        r#"SELECT client_id, status, request_json FROM deception_cloud_deployments
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(deployment_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let Some(row) = row else {
        let _ = tx.rollback().await;
        return Err("deployment not found".into());
    };

    let client_id: i64 = row.try_get("client_id").map_err(|e| e.to_string())?;
    let status: String = row.try_get("status").map_err(|e| e.to_string())?;
    let req_json: sqlx::types::Json<Value> = row.try_get("request_json").map_err(|e| e.to_string())?;

    if status == "active" {
        let _ = tx.commit().await;
        return Ok(json!({
            "ok": true,
            "message": "deployment already active",
            "deployment_id": deployment_id,
            "status": status,
        }));
    }

    sqlx::query(
        r#"UPDATE deception_cloud_deployments SET status = 'deploying', updated_at = now()
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(deployment_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let _ = tx.commit().await.map_err(|e| e.to_string())?;

    let body: DeployRequest = serde_json::from_value(req_json.0.clone()).map_err(|e| e.to_string())?;

    let mut tx = db::begin_tenant_tx(app_pool.as_ref(), tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let crow = sqlx::query(
        "SELECT COALESCE(trim(aws_cross_account_role_arn),'') AS arn, COALESCE(trim(aws_external_id),'') AS ext FROM clients WHERE id = $1 AND tenant_id = $2",
    )
    .bind(client_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await.map_err(|e| e.to_string())?;

    let (role_arn, ext) = match crow {
        Some(r) => (
            r.try_get::<String, _>("arn").unwrap_or_default(),
            r.try_get::<String, _>("ext").unwrap_or_default(),
        ),
        None => {
            mark_failed(app_pool.as_ref(), tenant_id, deployment_id, "client not found").await;
            return Ok(json!({
                "ok": false,
                "deployment_id": deployment_id,
                "status": "failed",
                "error": "client not found",
            }));
        }
    };

    if role_arn.is_empty() {
        mark_failed(
            app_pool.as_ref(),
            tenant_id,
            deployment_id,
            "aws_cross_account_role_arn not configured",
        )
        .await;
        return Ok(json!({
            "ok": false,
            "deployment_id": deployment_id,
            "status": "failed",
            "error": "aws_cross_account_role_arn not configured",
        }));
    }

    let aws_cfg = crate::cloud_integration_engine::CrossAccountAwsConfig {
        role_arn,
        external_id: ext,
        session_name: "weissman-deception-deploy".into(),
    };

    let (sdk, home_region) = match crate::cloud_integration_engine::assume_role_sdk_config(&aws_cfg).await {
        Ok(x) => x,
        Err(e) => {
            let msg = e.to_string();
            mark_failed(app_pool.as_ref(), tenant_id, deployment_id, &msg).await;
            return Ok(json!({
                "ok": false,
                "deployment_id": deployment_id,
                "status": "failed",
                "error": msg,
            }));
        }
    };

    let region = body
        .s3_region
        .as_deref()
        .map(|s| aws_config::Region::new(s.to_string()))
        .unwrap_or_else(|| home_region.clone());

    let targets = crate::deception_deployment_engine::InjectionTargets {
        s3_bucket: body.s3_bucket.clone(),
        s3_object_key: body.s3_object_key.clone(),
        ssm_parameter_path: body.ssm_parameter_path.clone(),
    };

    let Ok(mut tx) = db::begin_tenant_tx(app_pool.as_ref(), tenant_id).await else {
        mark_failed(app_pool.as_ref(), tenant_id, deployment_id, "database unavailable").await;
        return Ok(json!({
            "ok": false,
            "deployment_id": deployment_id,
            "status": "failed",
            "error": "database unavailable",
        }));
    };

    let mut deployed = 0u32;
    let mut errors: Vec<String> = vec![];
    for aid in &body.asset_ids {
        let rec = sqlx::query(
            "SELECT id, asset_type, token_value FROM deception_assets WHERE id = $1 AND client_id = $2",
        )
        .bind(aid)
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten();
        let Some(rec) = rec else {
            errors.push(format!("asset {} not found", aid));
            continue;
        };
        let atype: String = rec.try_get("asset_type").unwrap_or_default();
        let tok: String = rec.try_get("token_value").unwrap_or_default();
        match crate::deception_deployment_engine::deploy_honeytoken_injection(
            &sdk, &region, &atype, &tok, &targets,
        )
        .await
        {
            Ok(out) => {
                let _ = sqlx::query(
                    r#"UPDATE deception_assets SET deployment_location = $1, cloud_injection_uri = $2, status = 'deployed' WHERE id = $3"#,
                )
                .bind(&out.detail)
                .bind(&out.uri)
                .bind(aid)
                .execute(&mut *tx)
                .await;
                deployed += 1;
            }
            Err(e) => errors.push(format!("asset {}: {}", aid, e)),
        }
    }

    let result_body = json!({
        "deployed": deployed,
        "errors": errors,
    });

    let failed = deployed == 0 && !body.asset_ids.is_empty();
    let new_status = if failed { "failed" } else { "active" };
    let last_err = if failed {
        Some(
            errors
                .join("; ")
                .chars()
                .take(4000)
                .collect::<String>(),
        )
    } else {
        None
    };

    sqlx::query(
        r#"UPDATE deception_cloud_deployments SET status = $3, result_json = $4, last_error = $5,
              updated_at = now()
           WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(deployment_id)
    .bind(tenant_id)
    .bind(new_status)
    .bind(sqlx::types::Json(result_body.clone()))
    .bind(last_err.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let _ = tx.commit().await.map_err(|e| e.to_string())?;

    Ok(json!({
        "ok": !failed,
        "deployment_id": deployment_id,
        "status": new_status,
        "deployed": deployed,
        "errors": errors,
    }))
}

async fn mark_failed(pool: &PgPool, tenant_id: i64, deployment_id: Uuid, msg: &str) {
    if let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await {
        let short = msg.chars().take(4000).collect::<String>();
        let _ = sqlx::query(
            r#"UPDATE deception_cloud_deployments SET status = 'failed', last_error = $3, updated_at = now()
               WHERE id = $1 AND tenant_id = $2"#,
        )
        .bind(deployment_id)
        .bind(tenant_id)
        .bind(&short)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
}
