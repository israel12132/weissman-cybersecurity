//! Persist LLM token counts per tenant (`tenant_llm_usage`).

use sqlx::PgPool;

/// Record one completion's token usage (billing / abuse analytics). Uses tenant-scoped transaction (RLS).
pub async fn log_tenant_llm_usage(
    pool: &PgPool,
    tenant_id: i64,
    prompt_tokens: u32,
    completion_tokens: u32,
    model: &str,
    operation: &str,
) -> Result<(), sqlx::Error> {
    let total = prompt_tokens.saturating_add(completion_tokens);
    let mut tx = crate::begin_tenant_tx(pool, tenant_id).await?;
    sqlx::query(
        r#"INSERT INTO tenant_llm_usage
           (tenant_id, prompt_tokens, completion_tokens, total_tokens, model, operation)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(tenant_id)
    .bind(prompt_tokens as i32)
    .bind(completion_tokens as i32)
    .bind(total as i32)
    .bind(model)
    .bind(operation)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
