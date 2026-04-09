//! Periodic vLLM review of recent `audit_logs` for probe-like patterns.
//! Does **not** rebind listening ports in-process (would tear down active sessions). When enabled,
//! writes a JSON hint file for an external supervisor and emits telemetry.

use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;

pub fn spawn_sovereign_self_scan_loop(app_pool: Arc<PgPool>, telemetry: Arc<Sender<String>>) {
    let secs: u64 = std::env::var("WEISSMAN_SOVEREIGN_SELF_SCAN_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if secs == 0 {
        return;
    }
    let interval_secs = secs.max(300);
    tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) = run_sovereign_self_scan(&app_pool, &telemetry).await {
                tracing::warn!(target: "sovereign_self_scan", error = %e, "cycle failed");
            }
        }
    });
}

async fn run_sovereign_self_scan(
    pool: &PgPool,
    telemetry: &Sender<String>,
) -> Result<(), String> {
    let tenant_id: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE active = true ORDER BY id LIMIT 1")
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no active tenant".to_string())?;

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let llm_base: String = sqlx::query_scalar(
        "SELECT COALESCE(trim(value),'') FROM system_configs WHERE tenant_id = $1 AND key = 'llm_base_url'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or_default();
    let llm_model: String = sqlx::query_scalar(
        "SELECT COALESCE(trim(value),'') FROM system_configs WHERE tenant_id = $1 AND key = 'llm_model'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or_default();
    let lines: Vec<String> = sqlx::query_scalar(
        r#"SELECT action_type || ' | ' || COALESCE(details,'') || ' | ' || COALESCE(ip_address,'')
           FROM audit_logs WHERE tenant_id = $1 ORDER BY id DESC LIMIT 50"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    if llm_base.trim().is_empty() {
        return Ok(());
    }

    let excerpt = lines.join("\n");
    let client = weissman_engines::openai_chat::llm_http_client(90);
    let model = weissman_engines::openai_chat::resolve_llm_model(&llm_model);
    let user = format!(
        "You are a defensive SOC lead. Given recent audit log lines, respond ONLY minified JSON: \
         {{\"threat_level\":\"low\"|\"elevated\",\"recommend_internal_bind_port_rotation\":bool,\"rationale\":\"short\"}}\n\n{}",
        excerpt
    );
    let text = weissman_engines::openai_chat::chat_completion_text(
        &client,
        &llm_base,
        &model,
        Some("JSON only. No markdown."),
        &user,
        0.15,
        400,
        Some(tenant_id),
        "sovereign_self_scan",
        true,
    )
    .await
    .map_err(|e| e.to_string())?;

    let _ = telemetry.send(
        json!({
            "event": "sovereign_self_scan",
            "severity": "info",
            "llm_excerpt_chars": text.len(),
        })
        .to_string(),
    );

    let v: serde_json::Value = serde_json::from_str(text.trim())
        .or_else(|_| {
            let s = text.trim();
            let start = s.find('{').unwrap_or(0);
            let end = s.rfind('}').map(|i| i + 1).unwrap_or(s.len());
            serde_json::from_str(&s[start..end])
        })
        .unwrap_or(json!({}));

    let elevated = v
        .get("threat_level")
        .and_then(|x| x.as_str())
        .unwrap_or("low")
        .eq_ignore_ascii_case("elevated");
    let rotate = v
        .get("recommend_internal_bind_port_rotation")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    if elevated && rotate
        && matches!(
            std::env::var("WEISSMAN_SOVEREIGN_EMIT_PORT_ROTATION_HINT").as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
    {
        let dir = std::env::var("WEISSMAN_SOVEREIGN_STATE_DIR").unwrap_or_else(|_| "/tmp".into());
        let port: u16 = 20000 + (rand::random::<u16>() % 15000);
        let hint = json!({
            "suggested_bind_port": port,
            "ts_unix": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            "note": "External supervisor must restart listeners; in-process rotation is not performed.",
        });
        let path = format!("{dir}/weissman_sovereign_port_hint.json");
        if let Err(e) = std::fs::write(&path, hint.to_string()) {
            tracing::warn!(target: "sovereign_self_scan", error = %e, path = %path, "hint write failed");
        } else {
            tracing::warn!(
                target: "sovereign_self_scan",
                path = %path,
                port,
                "emitted bind-port rotation hint for external orchestrator"
            );
        }
    }

    Ok(())
}
