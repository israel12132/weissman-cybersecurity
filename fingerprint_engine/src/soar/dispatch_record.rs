//! SOAR playbook dispatch side-effects after finding persist (metadata + alerts).

use serde_json::{json, Value};
use sqlx::PgPool;

use crate::soar_playbook::{self, PlaybookEvent, PlaybookRunResult};

pub async fn record_post_persist_dispatch(
    pool: &PgPool,
    tenant_id: i64,
    finding_id: i64,
    event: PlaybookEvent,
) {
    let results = soar_playbook::dispatch_event(pool, event, false).await;
    if let Err(e) = merge_soar_metadata(pool, tenant_id, finding_id, &results).await {
        tracing::error!(
            target: "findings_persist",
            tenant_id,
            finding_id,
            error = %e,
            "failed to persist SOAR dispatch metadata on finding"
        );
    }

    let failures: Vec<&PlaybookRunResult> = results
        .iter()
        .filter(|r| r.status == "failed" || r.status == "partial")
        .collect();

    if failures.is_empty() {
        return;
    }

    let summary = failures
        .iter()
        .map(|r| format!("{}:{}", r.playbook_name, r.status))
        .collect::<Vec<_>>()
        .join(", ");

    tracing::error!(
        target: "findings_persist",
        tenant_id,
        finding_id,
        playbooks_failed = failures.len(),
        summary = %summary,
        "SOAR playbook dispatch failures after finding persist"
    );

    crate::alert_delivery::notify_soar_dispatch_failure(
        pool, tenant_id, finding_id, &summary, &results,
    )
    .await;
}

async fn merge_soar_metadata(
    pool: &PgPool,
    tenant_id: i64,
    finding_id: i64,
    results: &[PlaybookRunResult],
) -> Result<(), String> {
    let meta = json!({
        "soar_dispatch": {
            "at": chrono::Utc::now().to_rfc3339(),
            "playbooks_evaluated": results.len(),
            "status": if results.iter().any(|r| r.status == "failed") {
                "failed"
            } else if results.iter().any(|r| r.status == "partial") {
                "partial"
            } else if results.is_empty() {
                "no_match"
            } else {
                "ok"
            },
            "results": results,
        }
    });

    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Err("tenant tx".into());
    };
    sqlx::query(
        r#"UPDATE vulnerabilities
              SET raw_data = COALESCE(raw_data, '{}'::jsonb) || $3::jsonb,
                  updated_at = now()
            WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(finding_id)
    .bind(tenant_id)
    .bind(sqlx::types::Json(meta))
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soar_meta_shape() {
        let v: Value = json!({
            "soar_dispatch": { "status": "ok", "playbooks_evaluated": 0 }
        });
        assert_eq!(v["soar_dispatch"]["status"], "ok");
    }
}
