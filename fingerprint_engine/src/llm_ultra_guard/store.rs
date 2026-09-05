//! Persistence for guard events, quarantine, and RAG integrity — tenant-scoped RLS.

use crate::llm_ultra_guard::{rag, tuning, GuardContext, GuardReport, Verdict};
use serde_json::json;
use sqlx::{PgPool, Row};

#[derive(Debug, Clone, serde::Serialize)]
pub struct GuardEventRow {
    pub id: i64,
    pub engine_id: String,
    pub verdict: String,
    pub score: f32,
    pub latency_us: i64,
    pub fingerprint: String,
    pub techniques: Vec<String>,
    pub excerpt: String,
    pub created_at: String,
}

pub async fn persist_event(
    pool: &PgPool,
    ctx: &GuardContext,
    engine_id: &str,
    report: &GuardReport,
) -> Result<Option<i64>, String> {
    let Some(tenant_id) = ctx.tenant_id else {
        return Ok(None);
    };
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rec = sqlx::query(
        r#"INSERT INTO llm_guard_events (
                tenant_id, client_id, user_id, engine_id, source, verdict, score,
                injection_score, jailbreak_score, latency_us, fingerprint, simhash,
                techniques, cwes, flags, prompt_excerpt, detail
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,
                $8,$9,$10,$11,$12,
                $13,$14,$15,$16,$17
            ) RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(ctx.client_id)
    .bind(ctx.user_id)
    .bind(engine_id)
    .bind(ctx.source)
    .bind(report.verdict.as_str())
    .bind(report.score)
    .bind(report.injection_score)
    .bind(report.jailbreak_score)
    .bind(report.latency_us as i64)
    .bind(&report.fingerprint)
    .bind(report.simhash as i64)
    .bind(&report.techniques.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(&report.cwes.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(report.flags as i32)
    .bind(&report.excerpt)
    .bind(report.to_json())
    .fetch_one(&mut *tx)
    .await;

    let id = match rec {
        Ok(row) => row.try_get::<i64, _>("id").unwrap_or(0),
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(e.to_string());
        }
    };

    if matches!(report.verdict, Verdict::Quarantine) {
        let _ = sqlx::query(
            r#"INSERT INTO llm_guard_quarantine (tenant_id, event_id, prompt_hash, status)
               VALUES ($1,$2,$3,'pending')"#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&report.fingerprint)
        .execute(&mut *tx)
        .await;
    }

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(Some(id))
}

pub async fn list_recent_events(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> Result<Vec<GuardEventRow>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let rows = sqlx::query(
        r#"SELECT id, engine_id, verdict, score, latency_us, fingerprint,
                  techniques, prompt_excerpt, created_at
             FROM llm_guard_events
            ORDER BY created_at DESC
            LIMIT $1"#,
    )
    .bind(limit.clamp(1, 200))
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| GuardEventRow {
            id: r.try_get("id").unwrap_or(0),
            engine_id: r.try_get("engine_id").unwrap_or_default(),
            verdict: r.try_get("verdict").unwrap_or_default(),
            score: r.try_get::<f32, _>("score").unwrap_or(0.0),
            latency_us: r.try_get("latency_us").unwrap_or(0),
            fingerprint: r.try_get("fingerprint").unwrap_or_default(),
            techniques: r.try_get::<Vec<String>, _>("techniques").unwrap_or_default(),
            excerpt: r.try_get("prompt_excerpt").unwrap_or_default(),
            created_at: r
                .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                .map(|t| t.to_rfc3339())
                .unwrap_or_default(),
        })
        .collect())
}

/// Live RAG integrity pass over `supreme_council_memory` for this tenant.
pub async fn rag_integrity_snapshot(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<serde_json::Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let _ = sqlx::query(&format!("SET LOCAL hnsw.ef_search = {}", tuning::HNSW_EF_SEARCH))
        .execute(&mut *tx)
        .await;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM supreme_council_memory WHERE embedding_vec IS NOT NULL",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    // Sample recent vectors as text form "[v1,v2,...]" and verify norms.
    let rows = sqlx::query(
        r#"SELECT id, source, left(brief_excerpt, 180) AS excerpt,
                  embedding_vec::text AS vec_text,
                  embedding_sha256, embedding_norm
             FROM supreme_council_memory
            WHERE embedding_vec IS NOT NULL
            ORDER BY created_at DESC
            LIMIT 40"#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let mut checked = 0u32;
    let mut outliers = 0u32;
    let mut missing_hash = 0u32;
    let mut samples = Vec::new();
    for r in &rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let text: String = r.try_get("vec_text").unwrap_or_default();
        let stored_hash: Option<String> = r.try_get("embedding_sha256").ok().flatten();
        let stored_norm: Option<f32> = r.try_get("embedding_norm").ok().flatten();
        if let Some(vec) = parse_pgvector(&text) {
            checked += 1;
            let verdict = rag::verify_embedding(&vec, None);
            if !verdict.ok {
                outliers += 1;
            }
            if stored_hash.as_deref().unwrap_or("").is_empty() {
                missing_hash += 1;
            }
            samples.push(json!({
                "id": id,
                "source": r.try_get::<String, _>("source").unwrap_or_default(),
                "excerpt": r.try_get::<String, _>("excerpt").unwrap_or_default(),
                "ok": verdict.ok,
                "l2_norm": verdict.l2_norm,
                "stored_norm": stored_norm,
                "sha256": verdict.sha256,
                "stored_sha256": stored_hash,
                "reason": verdict.reason,
            }));
        }
    }
    let _ = tx.commit().await;
    Ok(json!({
        "vectors": count,
        "sampled": checked,
        "outliers": outliers,
        "missing_integrity_hash": missing_hash,
        "hnsw_ef_search": tuning::HNSW_EF_SEARCH,
        "hnsw_m": tuning::HNSW_M,
        "samples": samples,
    }))
}

fn parse_pgvector(text: &str) -> Option<Vec<f32>> {
    let t = text.trim().trim_start_matches('[').trim_end_matches(']');
    if t.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(tuning::VECTOR_DIM);
    for part in t.split(',') {
        out.push(part.trim().parse::<f32>().ok()?);
    }
    Some(out)
}
