#!/usr/bin/env python3
"""Generate src/server_handlers_sqlx.inc — run from fingerprint_engine directory."""
from pathlib import Path

# fmt: off
OUT = Path(__file__).resolve().parent.parent / "src" / "server_handlers_sqlx.inc"

def w(*lines):
    return "\n".join(lines) + "\n\n"

parts = []

parts.append(w(
"async fn api_dashboard_stats(State(state): State<Arc<AppState>>, Extension(auth): Extension<AuthContext>) -> Response {",
"    let Ok(mut tx) = db::begin_tenant_tx(&state.app_pool, auth.tenant_id).await else {",
"        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({\"total_vulnerabilities\":0,\"active_scans\":0,\"security_score\":0,\"assets_monitored\":0,\"threats_mitigated\":0}))).into_response();",
"    };",
"    let vuln_count: i64 = sqlx::query_scalar::<_, i64>(\"SELECT COUNT(*)::bigint FROM vulnerabilities\").fetch_one(&mut *tx).await.unwrap_or(0);",
"    let client_count: i64 = sqlx::query_scalar::<_, i64>(\"SELECT COUNT(*)::bigint FROM clients\").fetch_one(&mut *tx).await.unwrap_or(0);",
"    let score: i64 = sqlx::query_scalar::<_, String>(\"SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1\")",
"        .fetch_optional(&mut *tx).await.ok().flatten()",
"        .and_then(|s| serde_json::from_str::<Value>(&s).ok())",
"        .and_then(|j| {",
"            let by = j.get(\"by_severity\")?.as_object()?;",
"            let crit = by.get(\"critical\").and_then(Value::as_i64).unwrap_or(0);",
"            let high = by.get(\"high\").and_then(Value::as_i64).unwrap_or(0);",
"            let med = by.get(\"medium\").and_then(Value::as_i64).unwrap_or(0);",
"            Some((100i64 - crit * 25 - high * 15 - med * 5).max(0))",
"        }).unwrap_or(0);",
"    let summary_json: Option<Value> = sqlx::query_scalar::<_, String>(\"SELECT summary FROM report_runs ORDER BY created_at DESC LIMIT 1\")",
"        .fetch_optional(&mut *tx).await.ok().flatten()",
"        .and_then(|s| serde_json::from_str::<Value>(&s).ok());",
"    let _ = tx.commit().await;",
"    let active = server_orchestrator::is_scanning_active();",
"    let attack_surface_targets = summary_json.as_ref().and_then(|j| j.get(\"attack_surface_targets\")).and_then(Value::as_u64).unwrap_or(0) as i64;",
"    let attack_surface_paths = summary_json.as_ref().and_then(|j| j.get(\"attack_surface_paths\")).and_then(Value::as_u64).unwrap_or(0) as i64;",
"    (StatusCode::OK, Json(json!({",
"        \"total_vulnerabilities\": vuln_count,",
"        \"active_scans\": if active { 1 } else { 0 },",
"        \"security_score\": score,",
"        \"assets_monitored\": client_count,",
"        \"threats_mitigated\": vuln_count,",
"        \"attack_surface_targets\": attack_surface_targets,",
"        \"attack_surface_paths\": attack_surface_paths,",
"    }))).into_response()",
"}",
))

OUT.write_text("".join(parts))
print("wrote", OUT, "bytes", OUT.stat().st_size)
