//! Living System Memory — shared proofs, failures, paths, hosts, payloads.
//! Written from live engine results and sandbox scripts. Read by the knowledge bus.

use crate::engine_result::EngineResult;
use crate::live_knowledge_bus::LiveSlice;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;

pub async fn hydrate(pool: &PgPool, tenant_id: i64, engine_id: &str, target: &str) -> LiveSlice {
    let host = host_of(target);
    let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
        Ok(t) => t,
        Err(_) => return LiveSlice::default(),
    };
    let rows = sqlx::query(
        r#"SELECT kind, engine_id, target, body, evidence, verified
           FROM weissman_sovereign_memory
           WHERE tenant_id = $1
             AND created_at > now() - interval '14 days'
             AND (
               $2 = '' OR target ILIKE '%' || $2 || '%'
               OR body::text ILIKE '%' || $2 || '%'
             )
             AND ($3 = '' OR engine_id = $3 OR engine_id = '')
           ORDER BY verified DESC, id DESC
           LIMIT 80"#,
    )
    .bind(tenant_id)
    .bind(&host)
    .bind(engine_id.trim())
    .fetch_all(&mut *tx)
    .await;
    let _ = tx.commit().await;
    let Ok(rows) = rows else {
        return LiveSlice::default();
    };
    let mut paths = Vec::new();
    let mut hosts = Vec::new();
    let mut payloads = Vec::new();
    let mut from_memory = 0usize;
    for r in rows {
        from_memory += 1;
        let kind: String = r.try_get("kind").unwrap_or_default();
        let body: Value = r.try_get("body").unwrap_or(json!({}));
        let tgt: String = r.try_get("target").unwrap_or_default();
        match kind.as_str() {
            "path" => {
                if let Some(p) = body.get("path").and_then(Value::as_str) {
                    paths.push(p.to_string());
                }
            }
            "host" => {
                if let Some(h) = body.get("host").and_then(Value::as_str) {
                    hosts.push(h.to_string());
                } else if !tgt.is_empty() {
                    hosts.push(host_of(&tgt));
                }
            }
            "payload" | "proof" => {
                if let Some(p) = body.get("payload").and_then(Value::as_str) {
                    payloads.push(p.to_string());
                }
                if let Some(p) = body.get("path").and_then(Value::as_str) {
                    paths.push(p.to_string());
                }
            }
            _ => {}
        }
    }
    if !host.is_empty() {
        hosts.push(host);
    }
    let slice = LiveSlice {
        degraded_static: paths.is_empty() && payloads.is_empty() && hosts.len() <= 1,
        paths: unique(paths),
        hosts: unique(hosts),
        payloads: unique(payloads),
        from_memory,
    };
    slice
}

pub fn ingest_run(
    pool: Option<Arc<PgPool>>,
    tenant_id: i64,
    client_id: Option<i64>,
    engine_id: &str,
    target: &str,
    result: &EngineResult,
) {
    let Some(pool) = pool else {
        return;
    };
    if tenant_id <= 0 {
        return;
    };
    let engine_id = engine_id.trim().to_string();
    let target = target.to_string();
    let failed = result.status.eq_ignore_ascii_case("error")
        || result.status.eq_ignore_ascii_case("failed")
        || result.status.eq_ignore_ascii_case("timeout");
    let findings = result.findings.clone();
    let message = result.message.clone();
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _ = persist_run(
                pool.as_ref(),
                tenant_id,
                client_id,
                &engine_id,
                &target,
                &findings,
                &message,
                failed,
            )
            .await;
        });
    }
}

async fn persist_run(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    engine_id: &str,
    target: &str,
    findings: &[Value],
    message: &str,
    failed: bool,
) -> Result<(), String> {
    if failed {
        remember(
            pool,
            tenant_id,
            client_id,
            "failure",
            engine_id,
            target,
            json!({ "message": message }),
            message,
            false,
        )
        .await?;
        return Ok(());
    }
    for f in findings {
        let path = f
            .get("path")
            .or_else(|| f.get("url"))
            .or_else(|| f.get("value"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let payload = f
            .get("payload")
            .or_else(|| f.get("evidence"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let host = host_of(if path.starts_with("http") {
            path
        } else {
            target
        });
        if !host.is_empty() {
            remember(
                pool,
                tenant_id,
                client_id,
                "host",
                engine_id,
                target,
                json!({ "host": host }),
                "",
                true,
            )
            .await?;
        }
        if let Some(p) = path_only(path) {
            remember(
                pool,
                tenant_id,
                client_id,
                "path",
                engine_id,
                target,
                json!({ "path": p }),
                "",
                true,
            )
            .await?;
        }
        if !payload.is_empty() {
            remember(
                pool,
                tenant_id,
                client_id,
                "payload",
                engine_id,
                target,
                json!({ "payload": payload, "path": path }),
                payload,
                true,
            )
            .await?;
        }
        remember(
            pool,
            tenant_id,
            client_id,
            "proof",
            engine_id,
            target,
            json!({ "finding": f, "message": message }),
            message,
            true,
        )
        .await?;
    }
    Ok(())
}

const KINDS: &[&str] = &[
    "path", "host", "payload", "proof", "failure", "script", "note",
];

pub fn kind_allowed(kind: &str) -> bool {
    KINDS.iter().any(|k| *k == kind)
}

pub async fn remember(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    kind: &str,
    engine_id: &str,
    target: &str,
    body: Value,
    evidence: &str,
    verified: bool,
) -> Result<i64, String> {
    if !kind_allowed(kind) {
        return Err(format!("memory kind '{kind}' is not allowed"));
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO weissman_sovereign_memory
               (tenant_id, client_id, kind, engine_id, target, body, evidence, verified)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(kind)
    .bind(engine_id)
    .bind(target)
    .bind(&body)
    .bind(evidence)
    .bind(verified)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(id)
}

pub async fn list_recent(
    pool: &PgPool,
    tenant_id: i64,
    kind: Option<&str>,
    limit: i64,
) -> Result<Vec<Value>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        r#"SELECT id, kind, engine_id, target, body, evidence, verified,
                  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ts
           FROM weissman_sovereign_memory
           WHERE ($1::text IS NULL OR kind = $1)
           ORDER BY id DESC
           LIMIT $2"#,
    )
    .bind(kind)
    .bind(limit.clamp(1, 200))
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<i64,_>("id").ok(),
                "kind": r.try_get::<String,_>("kind").ok(),
                "engine_id": r.try_get::<String,_>("engine_id").ok(),
                "target": r.try_get::<String,_>("target").ok(),
                "body": r.try_get::<Value,_>("body").ok().unwrap_or(json!({})),
                "evidence": r.try_get::<String,_>("evidence").ok(),
                "verified": r.try_get::<bool,_>("verified").ok(),
                "ts": r.try_get::<String,_>("ts").ok(),
            })
        })
        .collect())
}

fn host_of(target: &str) -> String {
    let t = target.trim();
    let t = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    t.split('/')
        .next()
        .unwrap_or(t)
        .split(':')
        .next()
        .unwrap_or(t)
        .to_ascii_lowercase()
}

fn path_only(raw: &str) -> Option<String> {
    let r = raw.trim();
    if r.starts_with('/') {
        return Some(r.split('?').next().unwrap_or(r).to_string());
    }
    if let Some(rest) = r
        .strip_prefix("https://")
        .or_else(|| r.strip_prefix("http://"))
    {
        if let Some(i) = rest.find('/') {
            let p = rest[i..].split('?').next().unwrap_or("");
            if p.len() > 1 {
                return Some(p.to_string());
            }
        }
    }
    None
}

fn unique(v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for s in v {
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        if seen.insert(t.to_string()) {
            out.push(t.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_strips_url() {
        assert_eq!(host_of("https://API.Example.com:443/x"), "api.example.com");
    }

    #[test]
    fn path_from_url() {
        assert_eq!(
            path_only("https://ex.test/admin/login?x=1").as_deref(),
            Some("/admin/login")
        );
    }

    #[test]
    fn kinds_are_closed() {
        assert!(kind_allowed("proof"));
        assert!(!kind_allowed("drop_table"));
    }
}
