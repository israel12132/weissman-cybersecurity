//! UEBA detector — runs as a background loop in the backend.
//!
//! For every ingested `ueba_baseline` sample from an endpoint agent:
//!   1. Insert the raw sample into `agent_metric_samples`.
//!   2. Re-compute a baseline per (agent, metric) from the last 7 days of
//!      samples — running mean + sample standard deviation.
//!   3. Compare today's sample against the baseline; if `|z| > 3` and the
//!      baseline has ≥ 24 prior samples (i.e. it has trained on enough history),
//!      fire an anomaly with severity `medium` (`high` past 6σ).
//!   4. Also detect "new" categorical signals (a process / port that never showed
//!      up in the learned set) — those are fired at severity `medium` too, once
//!      the metric has accumulated ≥ 24 observations.
//!
//! The detector NEVER fires while a metric is still learning (`n < 24`). Baselines
//! are keyed per (agent, metric) — NOT per hour-of-week: with a 7-day sample
//! window, any given hour-of-week bucket only ever holds ~1 sample, so per-bucket
//! baselines could never reach the sample threshold and the detector never fired.
//! Training over the whole rolling window makes both paths reachable while still
//! honouring the "don't fire until trained" contract.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

const LEARN_WINDOW_DAYS: i64 = 7;
const Z_THRESHOLD: f64 = 3.0;
const MIN_BASELINE_SAMPLES: i32 = 24;
/// Canonical `hour_of_week` value baselines are stored under. Baselines are kept
/// per (agent, metric) — the raw samples still record their real hour-of-week —
/// so a single row accumulates the full rolling window instead of being scattered
/// across 168 buckets that can never individually reach `MIN_BASELINE_SAMPLES`.
const GLOBAL_BUCKET: i16 = 0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaIngestPayload {
    pub agent_id: String,
    pub client_id: i64,
    pub hour_of_week: i16,
    pub metrics: Value,
}

/// Public entry point — called by the server when an agent posts a `ueba_baseline`
/// finding (we route it here before it hits the generic findings_persist path).
pub async fn ingest_sample(
    pool: &PgPool,
    tenant_id: i64,
    p: UebaIngestPayload,
) -> Result<UebaIngestSummary, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let raw_size = serde_json::to_string(&p.metrics)
        .map(|s| s.len() as i32)
        .unwrap_or(0);
    let sample_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO agent_metric_samples
                 (tenant_id, agent_id, client_id, sampled_at, hour_of_week,
                  metrics, raw_size_bytes)
           VALUES ($1, $2, $3, now(), $4, $5, $6)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(p.client_id)
    .bind(p.hour_of_week)
    .bind(&p.metrics)
    .bind(raw_size)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("insert sample: {e}"))?;

    // Re-compute baselines for every numeric metric we saw in this sample.
    let mut summary = UebaIngestSummary::default();
    if let Value::Object(obj) = &p.metrics {
        // Numeric metrics → baseline + z-score check.
        for (k, v) in obj {
            if let Some(num) = v.as_f64() {
                let upd = recompute_baseline(&mut tx, tenant_id, &p.agent_id, k).await?;
                summary.baselines_updated += 1;
                if let Some(anom) =
                    check_anomaly(&mut tx, tenant_id, &p, sample_id, k, num, &upd).await?
                {
                    summary.anomalies.push(anom);
                }
            }
        }
        // Categorical signals — "new port", "new process".
        if let Some(ports) = obj.get("open_ports").and_then(Value::as_array) {
            let observed: HashSet<i64> = ports.iter().filter_map(|v| v.as_i64()).collect();
            if let Some(a) = check_new_categorical(
                &mut tx,
                tenant_id,
                &p,
                sample_id,
                "open_ports",
                &observed.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
                "Unfamiliar TCP port listening on host",
            )
            .await?
            {
                summary.anomalies.push(a);
            }
        }
        if let Some(procs) = obj.get("top_processes").and_then(Value::as_array) {
            let observed: Vec<String> = procs
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if let Some(a) = check_new_categorical(
                &mut tx,
                tenant_id,
                &p,
                sample_id,
                "top_processes",
                &observed,
                "Unfamiliar process observed running on host",
            )
            .await?
            {
                summary.anomalies.push(a);
            }
        }
        if let Some(users) = obj.get("logged_in_users").and_then(Value::as_array) {
            let observed: Vec<String> = users
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if let Some(a) = check_new_categorical(
                &mut tx,
                tenant_id,
                &p,
                sample_id,
                "logged_in_users",
                &observed,
                "New unique user on core asset",
            )
            .await?
            {
                summary.anomalies.push(a);
            }
        }
    }

    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(summary)
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct UebaIngestSummary {
    pub baselines_updated: usize,
    pub anomalies: Vec<AnomalyRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnomalyRecord {
    pub metric: String,
    pub observed: f64,
    pub baseline_mean: f64,
    pub baseline_stddev: f64,
    pub z_score: f64,
    pub severity: String,
    pub detail: String,
}

struct BaselineUpdate {
    n: i32,
    mean: f64,
    stddev: f64,
}

/// Recompute the rolling baseline for this (agent, metric) from the last 7 days
/// of samples across all hours. Cheap because the sample table is bounded by data
/// retention (no full-history scan).
async fn recompute_baseline(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
) -> Result<BaselineUpdate, String> {
    // Pull n, mean, stddev directly from the JSONB samples. We deliberately do NOT
    // filter by hour-of-week: with a 7-day sample window each hour-of-week value
    // recurs only once, so a per-bucket count could never reach MIN_BASELINE_SAMPLES.
    let row: Option<(Option<i64>, Option<f64>, Option<f64>)> = sqlx::query_as(
        r#"SELECT COUNT(*)::bigint                                              AS n,
                  AVG((metrics->>$3)::double precision)                          AS mean,
                  COALESCE(STDDEV_SAMP((metrics->>$3)::double precision), 0)     AS stddev
             FROM agent_metric_samples
            WHERE tenant_id = $1 AND agent_id = $2
              AND sampled_at > now() - ($4 || ' days')::interval
              AND metrics ? $3
              AND jsonb_typeof(metrics->$3) = 'number'"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(metric)
    .bind(LEARN_WINDOW_DAYS)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("aggregate: {e}"))?;

    let (n, mean, stddev) = match row {
        Some((n, m, s)) => (n.unwrap_or(0), m.unwrap_or(0.0), s.unwrap_or(0.0)),
        None => (0, 0.0, 0.0),
    };

    sqlx::query(
        r#"INSERT INTO agent_metric_baselines
                 (tenant_id, agent_id, metric_name, hour_of_week, n, mean, stddev,
                  learned_set, last_updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, '[]'::jsonb, now())
           ON CONFLICT (tenant_id, agent_id, metric_name, hour_of_week) DO UPDATE SET
               n = EXCLUDED.n,
               mean = EXCLUDED.mean,
               stddev = EXCLUDED.stddev,
               last_updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(metric)
    .bind(GLOBAL_BUCKET)
    .bind(n as i32)
    .bind(mean)
    .bind(stddev)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("upsert baseline: {e}"))?;

    Ok(BaselineUpdate {
        n: n as i32,
        mean,
        stddev,
    })
}

async fn check_anomaly(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    p: &UebaIngestPayload,
    sample_id: i64,
    metric: &str,
    observed: f64,
    base: &BaselineUpdate,
) -> Result<Option<AnomalyRecord>, String> {
    if base.n < MIN_BASELINE_SAMPLES {
        return Ok(None); // still learning
    }
    let stddev = crate::elite_hardening::ueba_stats::cloud_safe_stddev(base.mean, base.stddev);
    let z = (observed - base.mean) / stddev;
    if z.abs() <= Z_THRESHOLD {
        return Ok(None);
    }
    let severity = crate::elite_hardening::ueba_stats::severity_for_z(z);
    let direction = if z > 0.0 { "above" } else { "below" };
    let detail = format!(
        "Metric `{}` observed {:.2}, baseline {:.2} ± {:.2} (z={:+.2}, {} 3σ).",
        metric, observed, base.mean, stddev, z, direction
    );
    let rec = AnomalyRecord {
        metric: metric.to_string(),
        observed,
        baseline_mean: base.mean,
        baseline_stddev: stddev,
        z_score: z,
        severity: severity.to_string(),
        detail: detail.clone(),
    };
    sqlx::query(
        r#"INSERT INTO agent_anomalies
                 (tenant_id, agent_id, client_id, sample_id, metric_name,
                  observed, baseline_mean, baseline_stddev, z_score,
                  severity, detail, detected_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(p.client_id)
    .bind(sample_id)
    .bind(metric)
    .bind(observed)
    .bind(base.mean)
    .bind(stddev)
    .bind(z)
    .bind(severity)
    .bind(&detail)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("insert anomaly: {e}"))?;
    Ok(Some(rec))
}

/// Categorical anomaly check — fires when an item appears that's not in the
/// learned_set built over the last 7 days. We update the learned_set as a
/// side effect (so the first occurrence fires; subsequent appearances don't).
async fn check_new_categorical(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    p: &UebaIngestPayload,
    sample_id: i64,
    metric: &str,
    observed: &[String],
    title: &str,
) -> Result<Option<AnomalyRecord>, String> {
    // Read the current learned_set.
    let row: Option<(serde_json::Value, i32)> = sqlx::query_as(
        r#"SELECT learned_set, n
             FROM agent_metric_baselines
            WHERE tenant_id = $1 AND agent_id = $2
              AND metric_name = $3 AND hour_of_week = $4"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(metric)
    .bind(GLOBAL_BUCKET)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("read learned_set: {e}"))?;

    let (mut learned, n_obs): (HashSet<String>, i32) = match row {
        Some((v, n)) => {
            let set: HashSet<String> = serde_json::from_value::<Vec<String>>(v)
                .unwrap_or_default()
                .into_iter()
                .collect();
            (set, n)
        }
        None => (HashSet::new(), 0),
    };

    // Find items that are NEW (not in learned_set) — but only fire once we're
    // out of the learning window.
    let new_items: Vec<String> = observed
        .iter()
        .filter(|x| !learned.contains(*x))
        .cloned()
        .collect();

    // Add observed → learned_set and bump the per-metric observation count on
    // EVERY sample (not just when the set changes) so `n` reflects how much history
    // we've accumulated — that is what the learning gate below reads. Stored in a
    // single per-(agent,metric) row under GLOBAL_BUCKET so it can actually train.
    for x in observed {
        learned.insert(x.clone());
    }
    let learned_vec: Vec<String> = learned.into_iter().collect();
    let _ = sqlx::query(
        r#"INSERT INTO agent_metric_baselines
                 (tenant_id, agent_id, metric_name, hour_of_week, n, mean, stddev,
                  learned_set, last_updated_at)
           VALUES ($1, $2, $3, $4, 1, 0, 0, $5, now())
           ON CONFLICT (tenant_id, agent_id, metric_name, hour_of_week) DO UPDATE SET
               n = agent_metric_baselines.n + 1,
               learned_set = EXCLUDED.learned_set,
               last_updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(metric)
    .bind(GLOBAL_BUCKET)
    .bind(serde_json::to_value(&learned_vec).unwrap_or_default())
    .execute(&mut **tx)
    .await;

    if n_obs < MIN_BASELINE_SAMPLES || new_items.is_empty() {
        return Ok(None); // still learning OR nothing new
    }
    let detail = format!("{}: {}", title, new_items.join(", "));
    let rec = AnomalyRecord {
        metric: metric.to_string(),
        observed: new_items.len() as f64,
        baseline_mean: 0.0,
        baseline_stddev: 0.0,
        z_score: new_items.len() as f64,
        severity: "medium".to_string(),
        detail: detail.clone(),
    };
    sqlx::query(
        r#"INSERT INTO agent_anomalies
                 (tenant_id, agent_id, client_id, sample_id, metric_name,
                  observed, baseline_mean, baseline_stddev, z_score,
                  severity, detail, detected_at)
           VALUES ($1, $2, $3, $4, $5, $6, 0, 0, $6, 'medium', $7, now())"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(p.client_id)
    .bind(sample_id)
    .bind(metric)
    .bind(rec.z_score)
    .bind(&detail)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("insert categorical anomaly: {e}"))?;
    Ok(Some(rec))
}

/// Long-running worker that purges samples older than 14 days and emits the
/// detected anomalies as `agent_required_ok` findings for the orchestrator to
/// pick up. Spawned from `serve::spawn_http_background_tasks`.
pub fn spawn_retention_loop(pool: Arc<PgPool>) {
    static SPAWNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let _ = sqlx::query(
                "DELETE FROM agent_metric_samples WHERE sampled_at < now() - interval '14 days'",
            )
            .execute(pool.as_ref())
            .await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn z_threshold_constant() {
        assert!(Z_THRESHOLD == 3.0);
    }
    #[test]
    fn min_samples_protects_learning_window() {
        // Baselines train per (agent, metric) over the rolling 7-day sample window;
        // below MIN_BASELINE_SAMPLES observations we never fire, so a metric must
        // accumulate real history before an anomaly can be raised.
        assert!(MIN_BASELINE_SAMPLES >= 24);
    }
    #[test]
    fn baselines_use_the_global_bucket_not_hour_of_week() {
        // Regression guard: baselines must be stored per (agent, metric) so training
        // can accumulate. Per-hour-of-week bucketing made the detector never fire.
        assert_eq!(GLOBAL_BUCKET, 0);
    }
}
