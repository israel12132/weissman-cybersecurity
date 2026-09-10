//! Owner-authorized live PoC scripts — poc_sandbox + OAST, proof without destruction.

use super::memory;
use super::tools::ToolOutcome;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

pub async fn run_script(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    args: &Value,
) -> ToolOutcome {
    let target = args
        .get("target")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if target.is_empty() {
        return ToolOutcome {
            ok: false,
            name: "script".into(),
            detail: "target required".into(),
            payload: json!({}),
        };
    }
    let method = args
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .trim()
        .to_ascii_uppercase();
    let method = if matches!(method.as_str(), "GET" | "POST" | "HEAD") {
        method
    } else {
        "GET".into()
    };
    let payload = args
        .get("payload")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let marker = args
        .get("marker")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let oast = args.get("oast_token").and_then(Value::as_str);

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "script".into(),
                detail: e.to_string(),
                payload: json!({}),
            };
        }
    };
    let verdict =
        crate::poc_sandbox::verify_poc(&target, &method, &payload, &marker, oast, &client).await;
    let verdict_json = serde_json::to_value(&verdict).unwrap_or(json!({}));
    let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return ToolOutcome {
                ok: false,
                name: "script".into(),
                detail: e.to_string(),
                payload: verdict_json,
            };
        }
    };
    let id: Result<i64, _> = sqlx::query_scalar(
        r#"INSERT INTO weissman_sovereign_scripts
               (tenant_id, client_id, target, method, payload, marker, verdict, verified)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&target)
    .bind(&method)
    .bind(&payload)
    .bind(&marker)
    .bind(&verdict_json)
    .bind(verdict.verified)
    .fetch_one(&mut *tx)
    .await;
    let _ = tx.commit().await;
    let script_id = id.ok();
    let _ = memory::remember(
        pool,
        tenant_id,
        client_id,
        if verdict.verified { "proof" } else { "script" },
        "sovereign_script",
        &target,
        json!({
            "script_id": script_id,
            "method": method,
            "payload": payload,
            "marker": marker,
            "verdict": verdict_json,
        }),
        &verdict.evidence_preview,
        verdict.verified,
    )
    .await;
    ToolOutcome {
        ok: verdict.executed,
        name: "script".into(),
        detail: if verdict.verified {
            format!(
                "sandbox verified signal={} executor={} sha={}",
                verdict.signal, verdict.executor, verdict.evidence_sha256
            )
        } else {
            format!(
                "sandbox ran executed={} verified=false signal={} {}",
                verdict.executed,
                verdict.signal,
                verdict.error.clone().unwrap_or_default()
            )
        },
        payload: json!({
            "script_id": script_id,
            "verdict": verdict_json,
            "roe_mode": "safe_proofs",
        }),
    }
}

pub async fn list_scripts(pool: &PgPool, tenant_id: i64, limit: i64) -> Result<Vec<Value>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        r#"SELECT id, target, method, payload, marker, verdict, verified,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ts
           FROM weissman_sovereign_scripts
           ORDER BY id DESC
           LIMIT $1"#,
    )
    .bind(limit.clamp(1, 100))
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").ok(),
                "target": r.try_get::<String,_>("target").ok(),
                "method": r.try_get::<String,_>("method").ok(),
                "payload": r.try_get::<String,_>("payload").ok(),
                "marker": r.try_get::<String,_>("marker").ok(),
                "verdict": r.try_get::<Value,_>("verdict").ok().unwrap_or(json!({})),
                "verified": r.try_get::<bool,_>("verified").ok(),
                "ts": r.try_get::<String,_>("ts").ok(),
            })
        })
        .collect())
}
