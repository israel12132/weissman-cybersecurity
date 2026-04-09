//! Predictive vulnerability analysis via LLM (OpenAI-compatible / vLLM). Code is scored for toxic patterns and logical-flow issues.
//! Also reviews [`security_events`] rows for auth-plane abuse (credential stuffing, cross-tenant bursts).

use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;
use weissman_engines::openai_chat;

const LLM_TIMEOUT_SECS: u64 = 20;
const SECURITY_EVENTS_LLM_TIMEOUT_SECS: u64 = 90;

/// Analyze code content via LLM. Returns JSON array of { pattern, severity, snippet }. No hardcoded pattern list.
pub async fn analyze_content_llm(
    content: &str,
    source_hint: &str,
    llm_base: &str,
    llm_model: &str,
    llm_tenant_id: Option<i64>,
) -> Vec<Value> {
    let chunk = content.chars().take(4000).collect::<String>();
    let prompt = format!(
        r#"Analyze this code for security issues. Consider: dynamic execution (eval/exec/system), SQL concatenation, unsafe deserialization, hardcoded secrets, disabled SSL verification, path traversal, command injection.
Return ONLY a valid JSON array of objects. Each object: {{ "pattern": "short label", "severity": "critical"|"high"|"medium"|"low", "snippet": "relevant line or phrase" }}.
If no issues found return [].
Code (source: {}):
```
{}
```
JSON array only:"#,
        source_hint, chunk
    );
    let client = openai_chat::llm_http_client(LLM_TIMEOUT_SECS);
    let model = openai_chat::resolve_llm_model(llm_model);
    let text = match openai_chat::chat_completion_text(
        &client,
        llm_base,
        &model,
        None,
        &prompt,
        0.3,
        2048,
        llm_tenant_id,
        "predictive_analyzer",
        true,
    )
    .await
    {
        Ok(t) => t,
        Err(_) => return vec![],
    };
    let extracted = text
        .lines()
        .find(|l| l.trim().starts_with('['))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| text.to_string());
    let arr: Vec<Value> = serde_json::from_str(&extracted).unwrap_or_default();
    arr.into_iter()
        .filter(|o| o.get("pattern").is_some())
        .map(|o| {
            let pattern = o
                .get("pattern")
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            let severity = o
                .get("severity")
                .and_then(|s| s.as_str())
                .unwrap_or("medium")
                .to_string();
            let snippet = o
                .get("snippet")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .chars()
                .take(200)
                .collect::<String>();
            serde_json::json!({
                "title": format!("Predictive: {}", pattern),
                "severity": severity,
                "source": "predictive_analyzer",
                "source_hint": source_hint,
                "snippet_preview": snippet,
            })
        })
        .collect()
}

/// Periodically sends recent `security_events` to vLLM (set `WEISSMAN_SECURITY_EVENTS_LLM_INTERVAL_SECS`, min 600).
pub fn spawn_security_events_llm_loop(app_pool: Arc<PgPool>, telemetry: Arc<Sender<String>>) {
    let secs: u64 = std::env::var("WEISSMAN_SECURITY_EVENTS_LLM_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if secs == 0 {
        return;
    }
    let every = secs.max(600);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(every));
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) = run_security_events_llm_cycle(&app_pool, &telemetry).await {
                tracing::warn!(target: "predictive_analyzer", error = %e, "security_events LLM cycle failed");
            }
        }
    });
}

async fn run_security_events_llm_cycle(
    pool: &PgPool,
    telemetry: &Sender<String>,
) -> Result<(), String> {
    let tid: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE active = true ORDER BY id LIMIT 1")
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or(1);
    let mut tx = crate::db::begin_tenant_tx(pool, tid)
        .await
        .map_err(|e| e.to_string())?;
    let llm_base: String = sqlx::query_scalar(
        "SELECT COALESCE(trim(value),'') FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
    )
    .bind(tid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or_default();
    let llm_model: String = sqlx::query_scalar(
        "SELECT COALESCE(trim(value),'') FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'",
    )
    .bind(tid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or_default();
    let _ = tx.commit().await;
    if llm_base.trim().is_empty() {
        return Ok(());
    }
    let rows: Vec<String> = sqlx::query_scalar(
        r#"SELECT coalesce(event_type,'') || ' | tenant:' || coalesce(tenant_id::text,'') ||
               ' | ip:' || coalesce(host(client_ip)::text,'null') || ' | ' || left(coalesce(details::text,''), 400)
           FROM security_events ORDER BY id DESC LIMIT 120"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;
    if rows.is_empty() {
        return Ok(());
    }
    let excerpt = rows.join("\n");
    let client = openai_chat::llm_http_client(SECURITY_EVENTS_LLM_TIMEOUT_SECS);
    let model = openai_chat::resolve_llm_model(&llm_model);
    let prompt = format!(
        r#"You are a database security analyst. Given recent auth/BYPASSRLS security_events lines, identify slow credential stuffing, cross-tenant probing, or automation. Reply ONLY minified JSON: {{"risk":"low"|"elevated"|"high","summary":"one sentence","indicators":["..."]}}
Lines:
{}
"#,
        excerpt
    );
    let text = openai_chat::chat_completion_text(
        &client,
        &llm_base,
        &model,
        Some("JSON only."),
        &prompt,
        0.2,
        512,
        Some(tid),
        "predictive_security_events",
        true,
    )
    .await
    .map_err(|e| e.to_string())?;
    let _ = telemetry.send(
        json!({
            "event": "security_events_llm_review",
            "severity": "info",
            "chars": text.len(),
        })
        .to_string(),
    );
    tracing::info!(target: "predictive_analyzer", review = %text.chars().take(500).collect::<String>(), "security_events LLM review");
    Ok(())
}
