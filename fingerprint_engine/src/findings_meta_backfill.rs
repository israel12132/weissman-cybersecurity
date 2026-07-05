//! One-time / periodic backfill: downgrade legacy meta-analytical rows persisted
//! before [`findings_meta::apply_meta_finding_policy`] shipped.

use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::sync::Arc;
use std::time::Duration;

const BATCH_LIMIT: i64 = 400;

/// Reclassify stored meta findings for one tenant (severity column + raw_data JSONB).
/// Must run inside a tenant-scoped transaction — `vulnerabilities` is RLS-protected.
pub async fn run_meta_findings_backfill_for_tenant(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<usize, String> {
    let mut updated = 0usize;
    let mut after_id = 0i64;

    loop {
        let rows = sqlx::query(
            r#"SELECT id, source, title, severity, raw_data
                 FROM vulnerabilities
                WHERE id > $1
                  AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE')
                  AND (
                        lower(COALESCE(severity, '')) IN ('critical', 'high')
                     OR COALESCE((raw_data->>'cvss_score')::float8, 0) > 3.9
                  )
                ORDER BY id
                LIMIT $2"#,
        )
        .bind(after_id)
        .bind(BATCH_LIMIT)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| format!("select meta candidates: {e}"))?;

        if rows.is_empty() {
            break;
        }

        let batch_len = rows.len();
        for row in rows {
            let id: i64 = row.try_get("id").map_err(|e| e.to_string())?;
            after_id = id;
            let source: String = row.try_get("source").unwrap_or_default();
            let title: String = row.try_get("title").unwrap_or_default();
            let severity: String = row.try_get("severity").unwrap_or_default();
            let mut raw_data: Value = row.try_get("raw_data").unwrap_or(json!({}));

            let probe = json!({
                "title": title,
                "category": raw_data.get("category").or_else(|| raw_data.get("phase")),
                "finding_kind": raw_data.get("finding_kind"),
                "type": raw_data.get("type"),
            });
            if !crate::findings_meta::is_meta_analytical_finding(&source, &probe) {
                continue;
            }

            let category = raw_data
                .get("category")
                .or_else(|| raw_data.get("phase"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let (new_sev, new_cvss) =
                crate::findings_meta::meta_severity_and_cvss(&title, category);
            let new_mitre = crate::findings_meta::meta_mitre_technique(&source, &title, category);
            let effective_risk = ((new_cvss * 10.0).round() / 10.0).min(3.9);

            if let Some(obj) = raw_data.as_object_mut() {
                obj.insert("severity".to_string(), json!(new_sev));
                obj.insert("cvss_score".to_string(), json!(new_cvss));
                obj.insert("cvss".to_string(), json!(new_cvss));
                obj.insert("mitre_attack".to_string(), json!(new_mitre));
                obj.insert("finding_kind".to_string(), json!("meta_analytical"));
                obj.insert(
                    "meta_downgraded".to_string(),
                    json!({
                        "reason": "backfill_analytical_synthesis",
                        "original_severity": severity,
                    }),
                );
            }

            sqlx::query(
                r#"UPDATE vulnerabilities
                      SET severity = $2,
                          raw_data = $3,
                          effective_risk = $4
                    WHERE id = $1"#,
            )
            .bind(id)
            .bind(new_sev)
            .bind(sqlx::types::Json(raw_data))
            .bind(effective_risk)
            .execute(&mut **tx)
            .await
            .map_err(|e| format!("update id={id}: {e}"))?;
            updated += 1;
        }

        if batch_len < BATCH_LIMIT as usize {
            break;
        }
    }

    Ok(updated)
}

/// Reclassify stored meta findings across all active tenants.
pub async fn run_meta_findings_backfill(pool: &PgPool) -> Result<usize, String> {
    let tenants: Vec<i64> = sqlx::query_scalar("SELECT id FROM tenants WHERE active = true")
        .fetch_all(pool)
        .await
        .map_err(|e| format!("list tenants: {e}"))?;

    let mut total = 0usize;
    for tenant_id in tenants {
        let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
            .await
            .map_err(|e| format!("begin tenant {tenant_id} tx: {e}"))?;
        let n = run_meta_findings_backfill_for_tenant(&mut tx).await?;
        tx.commit()
            .await
            .map_err(|e| format!("commit tenant {tenant_id}: {e}"))?;
        total += n;
    }
    Ok(total)
}

/// Background loop: first pass at boot, then hourly until a pass updates zero rows.
pub fn bootstrap_meta_findings_backfill(pool: Arc<PgPool>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(8)).await;
        loop {
            match run_meta_findings_backfill(pool.as_ref()).await {
                Ok(n) => {
                    if n > 0 {
                        tracing::info!(
                            target: "findings_meta_backfill",
                            updated = n,
                            "Meta findings backfill pass complete"
                        );
                    }
                }
                Err(e) => tracing::warn!(
                    target: "findings_meta_backfill",
                    error = %e,
                    "Meta findings backfill failed"
                ),
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}
