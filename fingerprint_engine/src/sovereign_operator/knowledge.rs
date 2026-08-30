//! Canonical + live knowledge snapshot for the Sovereign Operator.
//! Live-only: engine registry from compiled IDs, jobs/findings/logs from Postgres.

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use weissman_core::models::engine::production_engine_ids;

const ARCHITECTURE: &str = r#"Weissman is a Rust-first closed-loop offensive security platform.
Execution path: API enqueue → weissman_async_jobs → weissman-worker → engine_dispatch::run_engine → findings_persist → WS/SSE.
Owner plane: is_superadmin OR role=ceo. Sovereign Operator listens only to that plane.
Findings are live probes (OAST / sandbox marker). RoE default is safe_proofs — proof without destruction.
Engine code is compiled Rust; the operator retunes job_params and re-dispatches. Code changes go through self_improve HITL (PENDING_APPROVAL → PR), never in-process mutation of main.
Ask Weissman is NL→SQL read-only. Supreme Council is multi-model debate. Neither is the Sovereign Operator.
Canonical encyclopedia: docs/sales/WEISSMAN-PLATFORM-ENCYCLOPEDIA.md (product map: weissman-server, weissman-worker, weissman-agent, PostgreSQL, Redis, Command Center SPA, engines, findings, agents, billing, SOC, Council/Ask, admin).
Canonical registry: PRODUCTION_ENGINE_IDS (compiled) + frontend/src/lib/enginesRegistry.js.
"#;

pub async fn build_snapshot(pool: &PgPool, tenant_id: i64) -> Result<Value, String> {
    let ids = production_engine_ids();
    let sample: Vec<&str> = ids.iter().copied().take(48).collect();
    let jobs = recent_jobs(pool, tenant_id).await.unwrap_or_default();
    let clusters = recent_clusters(pool, tenant_id).await.unwrap_or_default();
    let logs = crate::sovereign_operator::log_stream::list_recent(pool, tenant_id, 40)
        .await
        .unwrap_or_default();
    let fail_classes = failure_classes_from_jobs(&jobs);
    Ok(json!({
        "architecture": ARCHITECTURE,
        "production_engine_count": ids.len(),
        "engine_sample": sample,
        "job_kinds_operator_may_enqueue": crate::sovereign_operator::tools::ALLOWED_JOB_KINDS,
        "recent_jobs": jobs,
        "recent_clusters": clusters,
        "recent_engine_logs": logs,
        "failure_classes": fail_classes,
        "encyclopedia_path": "docs/sales/WEISSMAN-PLATFORM-ENCYCLOPEDIA.md",
        "registry": "PRODUCTION_ENGINE_IDS",
        "live": true,
    }))
}

pub fn snapshot_prompt_text(snap: &Value) -> String {
    let mut s = String::new();
    s.push_str(ARCHITECTURE);
    if let Some(n) = snap.get("production_engine_count").and_then(Value::as_u64) {
        s.push_str(&format!("\nProduction engines: {n}. Sample: "));
        if let Some(arr) = snap.get("engine_sample").and_then(Value::as_array) {
            let names: Vec<&str> = arr.iter().filter_map(Value::as_str).collect();
            s.push_str(&names.join(", "));
        }
    }
    s.push_str("\n\nRecent jobs:\n");
    s.push_str(
        &serde_json::to_string_pretty(snap.get("recent_jobs").unwrap_or(&json!([])))
            .unwrap_or_default(),
    );
    s.push_str("\n\nFinding clusters:\n");
    s.push_str(
        &serde_json::to_string_pretty(snap.get("recent_clusters").unwrap_or(&json!([])))
            .unwrap_or_default(),
    );
    s.push_str("\n\nEngine logs (live tape):\n");
    s.push_str(
        &serde_json::to_string_pretty(snap.get("recent_engine_logs").unwrap_or(&json!([])))
            .unwrap_or_default(),
    );
    if s.len() > 14000 {
        s.truncate(14000);
        s.push_str("\n…truncated");
    }
    s
}

async fn recent_jobs(pool: &PgPool, tenant_id: i64) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id::text AS id, kind, status,
                  COALESCE(result_json->'resilience'->>'failure_class','') AS failure_class,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ts
           FROM weissman_async_jobs
           ORDER BY created_at DESC
           LIMIT 20"#,
    )
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<String,_>("id").ok(),
                "kind": r.try_get::<String,_>("kind").ok(),
                "status": r.try_get::<String,_>("status").ok(),
                "failure_class": r.try_get::<String,_>("failure_class").ok(),
                "ts": r.try_get::<String,_>("ts").ok(),
            })
        })
        .collect())
}

async fn recent_clusters(pool: &PgPool, tenant_id: i64) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, target, cwe, title, member_count, engines, max_severity, status
           FROM weissman_finding_clusters
           ORDER BY last_seen_at DESC NULLS LAST
           LIMIT 15"#,
    )
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.commit().await;
    let rows = match rows {
        Ok(r) => r,
        Err(_) => return Ok(vec![]),
    };
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").ok(),
                "target": r.try_get::<String,_>("target").ok(),
                "cwe": r.try_get::<Option<String>,_>("cwe").ok().flatten(),
                "title": r.try_get::<Option<String>,_>("title").ok().flatten(),
                "member_count": r.try_get::<i32,_>("member_count").ok(),
                "engines": r.try_get::<Vec<String>,_>("engines").ok(),
                "max_severity": r.try_get::<Option<String>,_>("max_severity").ok().flatten(),
                "status": r.try_get::<Option<String>,_>("status").ok().flatten(),
            })
        })
        .collect())
}

fn failure_classes_from_jobs(jobs: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for j in jobs {
        if let Some(c) = j.get("failure_class").and_then(Value::as_str) {
            let c = c.trim();
            if !c.is_empty() && !out.iter().any(|x: &String| x == c) {
                out.push(c.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_mentions_live_probes() {
        assert!(ARCHITECTURE.contains("safe_proofs"));
        assert!(ARCHITECTURE.contains("engine_dispatch::run_engine"));
        assert!(ARCHITECTURE.contains("WEISSMAN-PLATFORM-ENCYCLOPEDIA.md"));
        assert!(ARCHITECTURE.contains("PRODUCTION_ENGINE_IDS"));
    }

    #[test]
    fn prompt_truncates_huge_snapshot() {
        let huge = json!({
            "recent_jobs": ["x".repeat(20000)],
            "recent_clusters": [],
            "recent_engine_logs": [],
            "production_engine_count": 563,
            "engine_sample": ["osint"],
        });
        let t = snapshot_prompt_text(&huge);
        assert!(t.len() <= 14120);
    }
}
