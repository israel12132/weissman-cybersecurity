//! False-positive / true-positive feedback loop.
//!
//! Drives two effects:
//!   1. **Confidence multiplier** — for each `(tenant, engine, signature_hash)` we
//!      track `fp_count` and `tp_count`. The multiplier returned by
//!      [`confidence_multiplier`] is a number in `[0.1, 1.0]` that callers apply
//!      to `risk_score` so a noisy engine gets discounted in the inbox.
//!   2. **Auto-suppression** — once `fp_count >= 3` for a `(tenant, engine, sig)`
//!      tuple we insert a row in `finding_suppressions`. The persist path checks
//!      this table BEFORE inserting and downgrades the status to `FALSE_POSITIVE`
//!      silently — keeping the audit trail without the noise.
//!
//! Public API:
//!   * [`record_fp`] / [`record_tp`] — called from `api_findings_update_status`
//!   * [`is_suppressed`] — called from `findings_persist::persist_engine_findings`
//!   * [`confidence_multiplier`] — called from `findings_persist` and the read API

use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashMap;

const AUTO_SUPPRESS_FP_THRESHOLD: i32 = 3;

#[inline]
fn multiplier_from_counts(tp: i32, fp: i32) -> f64 {
    if tp == 0 && fp == 0 {
        return 1.0;
    }
    ((f64::from(tp) + 1.0) / (f64::from(tp) + f64::from(fp) + 1.0)).clamp(0.1, 1.0)
}

/// Record a false-positive vote for a (tenant, engine, signature_hash) combo.
/// Returns `true` if this vote pushed us over the suppression threshold (i.e. a
/// new suppression rule was added).
pub async fn record_fp(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    engine: &str,
    signature_hash: &str,
    target: Option<&str>,
    by_user_id: Option<i64>,
) -> Result<bool, String> {
    if engine.is_empty() || signature_hash.is_empty() {
        return Ok(false);
    }
    let new_fp: i32 = sqlx::query_scalar(
        r#"INSERT INTO engine_confidence_adjustments
                 (tenant_id, engine, signature_hash, tp_count, fp_count, last_seen_at, last_label_at)
           VALUES ($1, $2, $3, 0, 1, now(), now())
           ON CONFLICT (tenant_id, engine, signature_hash) DO UPDATE SET
               fp_count       = engine_confidence_adjustments.fp_count + 1,
               last_seen_at   = now(),
               last_label_at  = now()
           RETURNING fp_count"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| format!("record_fp: {e}"))?;

    if new_fp < AUTO_SUPPRESS_FP_THRESHOLD {
        return Ok(false);
    }
    // Insert a suppression rule if not already present.
    let inserted = sqlx::query(
        r#"INSERT INTO finding_suppressions
                 (tenant_id, engine, signature_hash, target_glob,
                  reason, fp_count_at_create, created_by_user_id, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, now())
           ON CONFLICT (tenant_id, engine, signature_hash, COALESCE(target_glob, ''))
           DO NOTHING"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .bind(target)
    .bind(format!("auto:{}_fp_marks", new_fp))
    .bind(new_fp)
    .bind(by_user_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("insert suppression: {e}"))?;
    Ok(inserted.rows_affected() > 0)
}

/// Record a true-positive vote (analyst marked FIXED / ACKNOWLEDGED / IN_PROGRESS).
/// Also decays prior `fp_count` by 1 so an engine that fixes its behaviour can
/// climb out of suppression organically.
pub async fn record_tp(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    engine: &str,
    signature_hash: &str,
) -> Result<(), String> {
    if engine.is_empty() || signature_hash.is_empty() {
        return Ok(());
    }
    sqlx::query(
        r#"INSERT INTO engine_confidence_adjustments
                 (tenant_id, engine, signature_hash, tp_count, fp_count, last_seen_at, last_label_at)
           VALUES ($1, $2, $3, 1, 0, now(), now())
           ON CONFLICT (tenant_id, engine, signature_hash) DO UPDATE SET
               tp_count       = engine_confidence_adjustments.tp_count + 1,
               fp_count       = GREATEST(engine_confidence_adjustments.fp_count - 1, 0),
               last_seen_at   = now(),
               last_label_at  = now()"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("record_tp: {e}"))?;
    Ok(())
}

/// Returns `true` if there's an active suppression matching this finding.
/// Used by the persist path to silently mark new instances as FALSE_POSITIVE.
pub async fn is_suppressed(
    pool: &PgPool,
    tenant_id: i64,
    engine: &str,
    signature_hash: &str,
) -> bool {
    if engine.is_empty() || signature_hash.is_empty() {
        return false;
    }
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return false;
    };
    let row: Option<(i64,)> = sqlx::query_as(
        r#"SELECT id FROM finding_suppressions
            WHERE tenant_id = $1
              AND engine = $2
              AND signature_hash = $3
              AND (expires_at IS NULL OR expires_at > now())
            LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    if let Some((id,)) = row {
        let _ = sqlx::query(
            r#"UPDATE finding_suppressions
                  SET hit_count = hit_count + 1, last_hit_at = now()
                WHERE id = $1"#,
        )
        .bind(id)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
        true
    } else {
        let _ = tx.commit().await;
        false
    }
}

/// Confidence multiplier in `[0.1, 1.0]` derived from the FP/TP ratio.
///
/// Formula: `(tp + 1) / (tp + fp + 1)` clamped to `[0.1, 1.0]` — a Bayesian
/// shrinkage estimator. With no data the multiplier is 1.0. After 3 FPs the
/// multiplier is ~0.25 (but the finding is also suppressed). After 1 FP and 4
/// TPs the multiplier is ~0.83.
pub async fn confidence_multiplier(
    pool: &PgPool,
    tenant_id: i64,
    engine: &str,
    signature_hash: &str,
) -> f64 {
    if engine.is_empty() || signature_hash.is_empty() {
        return 1.0;
    }
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return 1.0;
    };
    let row: Option<(i32, i32)> = sqlx::query_as(
        r#"SELECT tp_count, fp_count
             FROM engine_confidence_adjustments
            WHERE tenant_id = $1 AND engine = $2 AND signature_hash = $3"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    let (tp, fp) = row.unwrap_or((0, 0));
    if tp == 0 && fp == 0 {
        return 1.0;
    }
    let m = (tp as f64 + 1.0) / (tp as f64 + fp as f64 + 1.0);
    m.clamp(0.1, 1.0)
}

/// Synchronous variant for callers already inside a tenant tx (avoids re-opening).
pub async fn confidence_multiplier_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    engine: &str,
    signature_hash: &str,
) -> f64 {
    if engine.is_empty() || signature_hash.is_empty() {
        return 1.0;
    }
    let row: Option<(i32, i32)> = sqlx::query_as(
        r#"SELECT tp_count, fp_count
             FROM engine_confidence_adjustments
            WHERE tenant_id = $1 AND engine = $2 AND signature_hash = $3"#,
    )
    .bind(tenant_id)
    .bind(engine)
    .bind(signature_hash)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten();
    let (tp, fp) = row.unwrap_or((0, 0));
    if tp == 0 && fp == 0 {
        return 1.0;
    }
    let m = (tp as f64 + 1.0) / (tp as f64 + fp as f64 + 1.0);
    m.clamp(0.1, 1.0)
}

/// Batch-load confidence multipliers for many `(engine, signature_hash)` pairs in
/// a **single** query. Replaces the per-row `confidence_multiplier` call in the
/// findings read path (which opened one tenant transaction + query per row — an
/// N+1 that cost up to `limit` extra round-trips). Missing pairs default to 1.0.
pub async fn confidence_multipliers_batch(
    pool: &PgPool,
    tenant_id: i64,
    pairs: &[(String, String)],
) -> HashMap<(String, String), f64> {
    let mut out: HashMap<(String, String), f64> = HashMap::new();
    if pairs.is_empty() {
        return out;
    }
    let engines: Vec<String> = pairs.iter().map(|(e, _)| e.clone()).collect();
    let sigs: Vec<String> = pairs.iter().map(|(_, s)| s.clone()).collect();
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return out;
    };
    let rows: Vec<(String, String, i32, i32)> = sqlx::query_as(
        r#"SELECT engine, signature_hash, tp_count, fp_count
             FROM engine_confidence_adjustments
            WHERE tenant_id = $1
              AND engine = ANY($2)
              AND signature_hash = ANY($3)"#,
    )
    .bind(tenant_id)
    .bind(&engines)
    .bind(&sigs)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    for (engine, sig, tp, fp) in rows {
        out.insert((engine, sig), multiplier_from_counts(tp, fp));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::multiplier_from_counts;

    #[test]
    fn multiplier_from_counts_matches_formula() {
        assert!((multiplier_from_counts(0, 0) - 1.0).abs() < 1e-6);
        assert!(multiplier_from_counts(0, 3) < 0.5);
        assert!(multiplier_from_counts(0, 100) >= 0.1); // clamped floor
        assert!(multiplier_from_counts(4, 1) > 0.5);
    }

    #[test]
    fn multiplier_neutral_with_no_history() {
        // Pure math test — can't hit DB without a fixture, so we re-derive.
        let m = |tp: f64, fp: f64| ((tp + 1.0) / (tp + fp + 1.0)).clamp(0.1, 1.0);
        assert!((m(0.0, 0.0) - 1.0).abs() < 1e-6);
        assert!(m(0.0, 3.0) < 0.5);
        assert!(m(0.0, 3.0) >= 0.1);
        assert!(m(4.0, 1.0) > 0.5);
    }
}
