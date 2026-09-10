//! SEV-2 when a SOAR execution or verification task stays non-terminal > 5 minutes.

use serde_json::json;
use sqlx::{PgPool, Row};
use std::time::Duration;

const STALE_AFTER_SECS: i64 = 300;

/// Scan every active tenant for stuck SOAR work and fire a SEV-2 once per row.
pub async fn alert_stale_work(app_pool: &PgPool, auth_pool: &PgPool) -> Result<u64, String> {
    let tenants = match weissman_db::active_tenant_ids(auth_pool).await {
        Ok(ids) if !ids.is_empty() => ids,
        _ => weissman_db::active_tenant_ids(app_pool)
            .await
            .map_err(|e| e.to_string())?,
    };
    let mut n = 0u64;
    for tenant_id in tenants {
        n += alert_stale_executions(app_pool, tenant_id).await?;
        n += alert_stale_verifications(app_pool, tenant_id).await?;
    }
    Ok(n)
}

async fn alert_stale_executions(pool: &PgPool, tenant_id: i64) -> Result<u64, String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Ok(0);
    };
    let rows = sqlx::query(
        r#"SELECT id, action_kind, status, target_id, EXTRACT(EPOCH FROM (now() - updated_at))::bigint AS age_secs
           FROM soar_action_executions
           WHERE status IN ('queued', 'acquired', 'executing', 'verifying', 'pending_hitl')
             AND stale_alerted_at IS NULL
             AND updated_at < now() - make_interval(secs => $1)
           LIMIT 32"#,
    )
    .bind(STALE_AFTER_SECS)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let mut fired = 0u64;
    for r in rows {
        let id: uuid::Uuid = r.try_get("id").unwrap_or_else(|_| uuid::Uuid::nil());
        let kind: String = r.try_get("action_kind").unwrap_or_default();
        let status: String = r.try_get("status").unwrap_or_default();
        let target: String = r.try_get("target_id").unwrap_or_default();
        let age: i64 = r.try_get("age_secs").unwrap_or(0);
        let _ = sqlx::query(
            "UPDATE soar_action_executions SET stale_alerted_at = now() WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await;
        fired += 1;
        let details = json!({
            "severity": "sev2",
            "action_kind": kind,
            "status": status,
            "target_id": target,
            "age_secs": age,
            "execution_id": id,
        })
        .to_string();
        let _ = crate::audit_log::insert_audit(
            &mut tx,
            tenant_id,
            None,
            "soar-stale",
            "soar.stale_execution",
            &details,
            "",
        )
        .await;
        tracing::error!(
            target: "soar_stale",
            tenant_id,
            execution_id = %id,
            action_kind = %kind,
            status = %status,
            age_secs = age,
            "SEV-2: SOAR execution pending longer than 5 minutes"
        );
        metrics::counter!("weissman_soar_stale_alert_total", "kind" => "execution").increment(1);
    }
    let _ = tx.commit().await;
    Ok(fired)
}

async fn alert_stale_verifications(pool: &PgPool, tenant_id: i64) -> Result<u64, String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Ok(0);
    };
    let rows = sqlx::query(
        r#"SELECT id, execution_id, probe_type, status,
                  EXTRACT(EPOCH FROM (now() - created_at))::bigint AS age_secs
           FROM soar_verification_tasks
           WHERE status IN ('pending', 'running')
             AND stale_alerted_at IS NULL
             AND created_at < now() - make_interval(secs => $1)
           LIMIT 32"#,
    )
    .bind(STALE_AFTER_SECS)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let mut fired = 0u64;
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let exec: uuid::Uuid = r
            .try_get("execution_id")
            .unwrap_or_else(|_| uuid::Uuid::nil());
        let probe: String = r.try_get("probe_type").unwrap_or_default();
        let age: i64 = r.try_get("age_secs").unwrap_or(0);
        let _ = sqlx::query(
            "UPDATE soar_verification_tasks SET stale_alerted_at = now() WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await;
        fired += 1;
        let details = json!({
            "severity": "sev2",
            "execution_id": exec,
            "probe_type": probe,
            "age_secs": age,
            "verification_id": id,
        })
        .to_string();
        let _ = crate::audit_log::insert_audit(
            &mut tx,
            tenant_id,
            None,
            "soar-stale",
            "soar.stale_verification",
            &details,
            "",
        )
        .await;
        tracing::error!(
            target: "soar_stale",
            tenant_id,
            verification_id = id,
            execution_id = %exec,
            probe_type = %probe,
            age_secs = age,
            "SEV-2: SOAR verification pending longer than 5 minutes"
        );
        metrics::counter!("weissman_soar_stale_alert_total", "kind" => "verification").increment(1);
    }
    let _ = tx.commit().await;
    Ok(fired)
}

/// How long a row may sit before the SEV-2 fires (tests + docs).
#[must_use]
pub fn stale_after() -> Duration {
    Duration::from_secs(STALE_AFTER_SECS as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_minute_threshold() {
        assert_eq!(stale_after(), Duration::from_secs(300));
    }
}
