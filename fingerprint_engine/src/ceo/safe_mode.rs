//! CEO-only toggle for `global_safe_mode` (same DB effect as enterprise settings patch).

use sqlx::PgPool;

pub async fn set_tenant_global_safe_mode(
    app_pool: &PgPool,
    auth_pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    global_safe_mode: bool,
    client_ip: &str,
) -> Result<(), String> {
    let actor = crate::audit_log::user_email_for_id(auth_pool, user_id).await;
    let mut tx = crate::db::begin_tenant_tx(app_pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let s = if global_safe_mode { "true" } else { "false" };
    sqlx::query(
        r#"INSERT INTO system_configs (tenant_id, key, value, description)
           VALUES ($1, 'global_safe_mode', $2, 'Production-safe scan throttling')
           ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value"#,
    )
    .bind(tenant_id)
    .bind(s)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = crate::audit_log::insert_audit(
        &mut tx,
        tenant_id,
        Some(user_id),
        &actor,
        "ceo_safe_mode_toggled",
        &format!("global_safe_mode={s}"),
        client_ip,
    )
    .await;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}
