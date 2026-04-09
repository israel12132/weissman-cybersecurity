#!/usr/bin/env python3
"""Emit src/server_handlers_rest.inc — run from fingerprint_engine/."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "server_handlers_rest.inc"


def w(s: str) -> str:
    return s.rstrip() + "\n\n"


parts: list[str] = []

# --- api_health
parts.append(
    w(
        """async fn api_health(State(state): State<Arc<AppState>>) -> Response {
    let uptime_secs = state.started_at.elapsed().as_secs();
    let postgres_ok = sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(&state.app_pool).await.is_ok();
    let scanning = server_orchestrator::is_scanning_active();
    let (engines, safe_mode) = if postgres_ok {
        let tid = match sqlx::query_scalar::<_, i64>("SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1")
            .fetch_optional(&state.auth_pool)
            .await
            .ok()
            .flatten()
        {
            Some(t) => t,
            None => (StatusCode::OK, Json(json!({"ok": true, "uptime_secs": uptime_secs, "postgres_ok": true, "scanning_active": scanning, "active_engines": [], "global_safe_mode": false}))).into_response()
                .into_response()
                .map(|_| unreachable!())
                .unwrap_or(0),
        };
        if let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, tid).await {
            let eng = sqlx::query_scalar::<_, String>("SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'active_engines'")
                .bind(tid)
                .fetch_optional(&mut *tx)
                .await
                .ok()
                .flatten()
                .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
                .unwrap_or_default();
            let safe = sqlx::query_scalar::<_, String>("SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'global_safe_mode'")
                .bind(tid)
                .fetch_optional(&mut *tx)
                .await
                .ok()
                .flatten()
                .map(|s| s == "true" || s == "1")
                .unwrap_or(false);
            let _ = tx.commit().await;
            (eng, safe)
        } else {
            (vec![], false)
        }
    } else {
        (vec![], false)
    };
    (StatusCode::OK, Json(json!({
        "ok": true,
        "uptime_secs": uptime_secs,
        "postgres_ok": postgres_ok,
        "scanning_active": scanning,
        "active_engines": engines,
        "global_safe_mode": safe_mode,
    }))).into_response()
}"""
    )
)

OUT.write_text("".join(parts))
print("wrote", OUT, OUT.stat().st_size)
