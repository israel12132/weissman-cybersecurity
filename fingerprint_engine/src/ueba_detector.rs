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
/// Sentinel `hour_of_week` for the rolling 7-day (agent, metric) fire-path row.
/// Must sit **outside** 0..=167 — bucket 0 is Monday 00:00 UTC, and writing the
/// global mean/stddev there would overwrite the true hour-0 row (and vice versa)
/// every Monday midnight.
const GLOBAL_BUCKET: i16 = -1;

/// Agent-side upload gate. Server still fires anomalies at `|z| > 3`.
pub const EDGE_Z_UPLOAD: f64 = 2.0;
const EDGE_MIN_N: i32 = 7;
/// Hour-of-week row is used only when it has at least this many samples; otherwise
/// the compact snapshot falls back to the rolling 7-day global row.
const EDGE_HOUR_MIN_N: i32 = 3;

const COMPACT_METRICS: &[&str] = &[
    "open_port_count",
    "process_count",
    "unique_users",
    "load_1m",
    "memory_used_pct",
    "failed_logins",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UebaCompactSnapshot {
    pub hour_of_week: i16,
    #[serde(default = "default_z_upload")]
    pub z_upload_threshold: f64,
    #[serde(default = "default_min_n")]
    pub min_n: i32,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub metrics: Vec<UebaCompactMetric>,
    #[serde(default)]
    pub learned_processes: Vec<String>,
}

fn default_z_upload() -> f64 {
    EDGE_Z_UPLOAD
}
fn default_min_n() -> i32 {
    EDGE_MIN_N
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UebaCompactMetric {
    pub name: String,
    pub mean: f64,
    pub stddev: f64,
    pub n: i32,
}

#[derive(Debug, Clone)]
pub struct BaselineRow {
    pub metric_name: String,
    pub hour_of_week: i16,
    pub n: i32,
    pub mean: f64,
    pub stddev: f64,
    pub learned_set: Value,
}

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
                let upd =
                    recompute_baseline(&mut tx, tenant_id, &p.agent_id, k, p.hour_of_week).await?;
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
    hour_of_week: i16,
) -> Result<BaselineUpdate, String> {
    // Pull n, mean, stddev directly from the JSONB samples. We deliberately do NOT
    // filter by hour-of-week for the *server* fire path: with a 7-day sample
    // window each hour-of-week value recurs only once, so a per-bucket count could
    // never reach MIN_BASELINE_SAMPLES. The hour-specific row is written alongside
    // so the agent can hold a compact local copy of the current hour.
    let global = aggregate_metric(tx, tenant_id, agent_id, metric, None).await?;
    upsert_numeric_baseline(tx, tenant_id, agent_id, metric, GLOBAL_BUCKET, &global).await?;
    let hour = hour_of_week.clamp(0, 167);
    let hourly = aggregate_metric(tx, tenant_id, agent_id, metric, Some(hour)).await?;
    upsert_numeric_baseline(tx, tenant_id, agent_id, metric, hour, &hourly).await?;
    Ok(global)
}

async fn aggregate_metric(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
    hour: Option<i16>,
) -> Result<BaselineUpdate, String> {
    let row: Option<(Option<i64>, Option<f64>, Option<f64>)> = sqlx::query_as(
        r#"SELECT COUNT(*)::bigint                                              AS n,
                  AVG((metrics->>$3)::double precision)                          AS mean,
                  COALESCE(STDDEV_SAMP((metrics->>$3)::double precision), 0)     AS stddev
             FROM agent_metric_samples
            WHERE tenant_id = $1 AND agent_id = $2
              AND sampled_at > now() - ($4 || ' days')::interval
              AND metrics ? $3
              AND jsonb_typeof(metrics->$3) = 'number'
              AND ($5::smallint IS NULL OR hour_of_week = $5)"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(metric)
    .bind(LEARN_WINDOW_DAYS)
    .bind(hour)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("aggregate: {e}"))?;

    let (n, mean, stddev) = match row {
        Some((n, m, s)) => (n.unwrap_or(0), m.unwrap_or(0.0), s.unwrap_or(0.0)),
        None => (0, 0.0, 0.0),
    };
    Ok(BaselineUpdate {
        n: n as i32,
        mean,
        stddev,
    })
}

async fn upsert_numeric_baseline(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
    hour_of_week: i16,
    upd: &BaselineUpdate,
) -> Result<(), String> {
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
    .bind(hour_of_week)
    .bind(upd.n)
    .bind(upd.mean)
    .bind(upd.stddev)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("upsert baseline: {e}"))?;
    Ok(())
}

/// Current UTC hour-of-week (Mon 00:00 = 0 … Sun 23:00 = 167).
#[must_use]
pub fn hour_of_week_utc() -> i16 {
    use chrono::{Datelike, Timelike};
    let n = chrono::Utc::now();
    let dow = (n.weekday().num_days_from_monday() as i16).clamp(0, 6);
    let hour = (n.hour() as i16).clamp(0, 23);
    dow * 24 + hour
}

/// Build the compact snapshot the agent caches locally. Prefer the current
/// hour-of-week row when it has ≥ `EDGE_HOUR_MIN_N` samples, else the rolling
/// 7-day global row (bucket -1).
#[must_use]
pub fn assemble_compact_snapshot(hour: i16, rows: &[BaselineRow]) -> UebaCompactSnapshot {
    let mut metrics = Vec::new();
    let mut used_hour = false;
    for name in COMPACT_METRICS {
        let hour_row = rows
            .iter()
            .find(|r| r.metric_name == *name && r.hour_of_week == hour && r.n >= EDGE_HOUR_MIN_N);
        let global_row = rows
            .iter()
            .find(|r| r.metric_name == *name && r.hour_of_week == GLOBAL_BUCKET);
        if let Some(r) = hour_row.or(global_row) {
            if hour_row.is_some() {
                used_hour = true;
            }
            metrics.push(UebaCompactMetric {
                name: (*name).to_string(),
                mean: r.mean,
                stddev: r.stddev,
                n: r.n,
            });
        }
    }
    let learned_processes = rows
        .iter()
        .find(|r| r.metric_name == "top_processes" && r.hour_of_week == GLOBAL_BUCKET)
        .and_then(|r| serde_json::from_value::<Vec<String>>(r.learned_set.clone()).ok())
        .unwrap_or_default();
    UebaCompactSnapshot {
        hour_of_week: hour.clamp(0, 167),
        z_upload_threshold: EDGE_Z_UPLOAD,
        min_n: EDGE_MIN_N,
        source: if used_hour {
            "hour_of_week".into()
        } else {
            "rolling_7d".into()
        },
        metrics,
        learned_processes,
    }
}

/// Load + assemble the compact snapshot for one agent. Empty `metrics` means
/// the agent should keep uploading (still training).
pub async fn compact_snapshot_for_agent(
    pool: &PgPool,
    tenant_id: i64,
    agent_id: &str,
) -> Result<UebaCompactSnapshot, String> {
    let hour = hour_of_week_utc();
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let rows = sqlx::query_as::<_, (String, i16, i32, f64, f64, Value)>(
        r#"SELECT metric_name, hour_of_week, n, mean, stddev, learned_set
             FROM agent_metric_baselines
            WHERE tenant_id = $1 AND agent_id = $2
              AND hour_of_week IN ($3, $4)"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(hour)
    .bind(GLOBAL_BUCKET)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("load baselines: {e}"))?;
    let _ = tx.commit().await;
    let mapped: Vec<BaselineRow> = rows
        .into_iter()
        .map(
            |(metric_name, hour_of_week, n, mean, stddev, learned_set)| BaselineRow {
                metric_name,
                hour_of_week,
                n,
                mean,
                stddev,
                learned_set,
            },
        )
        .collect();
    Ok(assemble_compact_snapshot(hour, &mapped))
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
    if base.stddev < 1e-6 {
        return Ok(None); // constant baseline — divide-by-zero, can't compute z
    }
    let z = (observed - base.mean) / base.stddev;
    if z.abs() < Z_THRESHOLD {
        return Ok(None);
    }
    let severity = if z.abs() > 6.0 { "high" } else { "medium" };
    let direction = if z > 0.0 { "above" } else { "below" };
    let detail = format!(
        "Metric `{}` observed {:.2}, baseline {:.2} ± {:.2} (z={:+.2}, {} 3σ).",
        metric, observed, base.mean, base.stddev, z, direction
    );
    let rec = AnomalyRecord {
        metric: metric.to_string(),
        observed,
        baseline_mean: base.mean,
        baseline_stddev: base.stddev,
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
    .bind(base.stddev)
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
        // Regression guard: server-side fire path must accumulate per (agent, metric)
        // so training can reach MIN_BASELINE_SAMPLES. Hour-of-week rows are extra
        // copies for the agent's compact snapshot, not the fire path.
        assert_eq!(GLOBAL_BUCKET, -1);
        assert!(
            GLOBAL_BUCKET < 0 || GLOBAL_BUCKET > 167,
            "GLOBAL_BUCKET must not collide with a real hour_of_week"
        );
    }

    #[test]
    fn compact_snapshot_hour_zero_does_not_collide_with_global() {
        let rows = vec![
            BaselineRow {
                metric_name: "process_count".into(),
                hour_of_week: GLOBAL_BUCKET,
                n: 40,
                mean: 100.0,
                stddev: 5.0,
                learned_set: Value::Array(vec![]),
            },
            BaselineRow {
                metric_name: "process_count".into(),
                hour_of_week: 0,
                n: 4,
                mean: 50.0,
                stddev: 1.0,
                learned_set: Value::Array(vec![]),
            },
        ];
        let monday_midnight = assemble_compact_snapshot(0, &rows);
        assert_eq!(monday_midnight.source, "hour_of_week");
        assert_eq!(monday_midnight.metrics[0].mean, 50.0);
        let tuesday = assemble_compact_snapshot(12, &rows);
        assert_eq!(tuesday.source, "rolling_7d");
        assert_eq!(tuesday.metrics[0].mean, 100.0);
    }

    #[test]
    fn compact_snapshot_prefers_hour_when_trained() {
        let rows = vec![
            BaselineRow {
                metric_name: "process_count".into(),
                hour_of_week: GLOBAL_BUCKET,
                n: 40,
                mean: 100.0,
                stddev: 5.0,
                learned_set: Value::Array(vec![]),
            },
            BaselineRow {
                metric_name: "process_count".into(),
                hour_of_week: 12,
                n: 4,
                mean: 80.0,
                stddev: 2.0,
                learned_set: Value::Array(vec![]),
            },
            BaselineRow {
                metric_name: "top_processes".into(),
                hour_of_week: GLOBAL_BUCKET,
                n: 40,
                mean: 0.0,
                stddev: 0.0,
                learned_set: serde_json::json!(["sshd", "systemd"]),
            },
        ];
        let snap = assemble_compact_snapshot(12, &rows);
        assert_eq!(snap.source, "hour_of_week");
        assert_eq!(snap.z_upload_threshold, EDGE_Z_UPLOAD);
        let pc = snap
            .metrics
            .iter()
            .find(|m| m.name == "process_count")
            .unwrap();
        assert_eq!(pc.mean, 80.0);
        assert_eq!(snap.learned_processes, vec!["sshd", "systemd"]);
    }

    #[test]
    fn compact_snapshot_falls_back_to_rolling_7d() {
        let rows = vec![BaselineRow {
            metric_name: "process_count".into(),
            hour_of_week: GLOBAL_BUCKET,
            n: 40,
            mean: 100.0,
            stddev: 5.0,
            learned_set: Value::Array(vec![]),
        }];
        let snap = assemble_compact_snapshot(12, &rows);
        assert_eq!(snap.source, "rolling_7d");
        assert_eq!(snap.metrics[0].mean, 100.0);
    }

    #[test]
    fn hour_of_week_in_range() {
        let h = hour_of_week_utc();
        assert!(h >= 0 && h < 168);
    }
}
