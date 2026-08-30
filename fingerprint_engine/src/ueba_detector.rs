//! UEBA detector — runs as a background loop in the backend.
//!
//! For every ingested `ueba_baseline` sample from an endpoint agent:
//!   0. Drop the tick (no INSERT, no z-score) when `sampling_failed` is set or
//!      `process_count` is missing/zero — a blocked syscall is not mass process
//!      death and must not page isolate_host.
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
    /// HMAC-SHA256 (hex) over the canonical snapshot. Empty until `ueba_snapshot_mac::sign`.
    #[serde(default)]
    pub mac: String,
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
    /// Rolling 7-day (agent, metric) row from `agent_metric_baselines_global`.
    pub is_global: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaIngestPayload {
    pub agent_id: String,
    pub client_id: i64,
    pub hour_of_week: i16,
    pub metrics: Value,
}

/// Why this sample must not enter z-score or `agent_metric_samples`.
///
/// `process_count = 0` from a blocked `NtQuerySystemInformation` looks like
/// mass process death (`Z < -6` vs a live baseline) and can page isolate_host.
#[must_use]
pub fn ueba_sample_skip_reason(metrics: &Value) -> Option<&'static str> {
    let Some(obj) = metrics.as_object() else {
        return Some("invalid_metrics");
    };
    if obj.get("sampling_failed").and_then(Value::as_bool) == Some(true) {
        return Some("sampling_failed");
    }
    match obj.get("process_count").and_then(Value::as_f64) {
        Some(n) if n <= 0.0 => Some("empty_process_count"),
        None => Some("missing_process_count"),
        Some(_) => None,
    }
}

/// Public entry point — called by the server when an agent posts a `ueba_baseline`
/// finding (we route it here before it hits the generic findings_persist path).
pub async fn ingest_sample(
    pool: &PgPool,
    tenant_id: i64,
    p: UebaIngestPayload,
) -> Result<UebaIngestSummary, String> {
    if let Some(reason) = ueba_sample_skip_reason(&p.metrics) {
        tracing::warn!(
            target: "ueba",
            agent_id = %p.agent_id,
            reason,
            "UEBA sample skipped — syscall/empty table is not a z-score event"
        );
        let eval = match record_sampling_failure(pool, tenant_id, &p, reason).await {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(
                    target: "ueba",
                    agent_id = %p.agent_id,
                    error = %e,
                    "telemetry-error counter write failed"
                );
                SamplingFailureEval::default()
            }
        };
        // SOAR + Postgres stay live for every skip after the threshold. The
        // 15-minute window only gates on-call paging (last_alerted_at), never
        // the blinded lock or the event log — cooldown abuse must not hide a
        // pulse of NtQuerySystemInformation / /proc blocks.
        if eval.persist_event {
            fire_telemetry_blinding_alert(pool, tenant_id, &p, reason, eval.consecutive).await;
        }
        return Ok(UebaIngestSummary {
            skipped: true,
            skip_reason: Some(reason.to_string()),
            consecutive_failures: eval.consecutive,
            blinding_alert: eval.persist_event,
            oncall_paged: eval.page_oncall,
            ..Default::default()
        });
    }
    if let Err(e) = reset_sampling_failures(pool, tenant_id, &p.agent_id).await {
        tracing::warn!(
            target: "ueba",
            agent_id = %p.agent_id,
            error = %e,
            "failed to clear telemetry-error streak after a healthy sample"
        );
    }
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
    #[serde(default)]
    pub skipped: bool,
    #[serde(default)]
    pub skip_reason: Option<String>,
    #[serde(default)]
    pub consecutive_failures: i32,
    #[serde(default)]
    pub blinding_alert: bool,
    /// True when the 15-minute on-call page window elapsed. Never used to
    /// suppress SOAR or `agent_anomalies` rows.
    #[serde(default)]
    pub oncall_paged: bool,
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
    upsert_global_numeric(tx, tenant_id, agent_id, metric, &global).await?;
    let hour = hour_of_week.clamp(0, 167);
    let hourly = aggregate_metric(tx, tenant_id, agent_id, metric, Some(hour)).await?;
    upsert_hourly_baseline(tx, tenant_id, agent_id, metric, hour, &hourly).await?;
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

async fn upsert_hourly_baseline(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
    hour_of_week: i16,
    upd: &BaselineUpdate,
) -> Result<(), String> {
    let hour = hour_of_week.clamp(0, 167);
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
    .bind(hour)
    .bind(upd.n)
    .bind(upd.mean)
    .bind(upd.stddev)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("upsert hourly baseline: {e}"))?;
    Ok(())
}

async fn upsert_global_numeric(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
    upd: &BaselineUpdate,
) -> Result<(), String> {
    sqlx::query(
        r#"INSERT INTO agent_metric_baselines_global
                 (tenant_id, agent_id, metric_name, n, mean, stddev,
                  learned_set, last_updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, '[]'::jsonb, now())
           ON CONFLICT (tenant_id, agent_id, metric_name) DO UPDATE SET
               n = EXCLUDED.n,
               mean = EXCLUDED.mean,
               stddev = EXCLUDED.stddev,
               last_updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(metric)
    .bind(upd.n)
    .bind(upd.mean)
    .bind(upd.stddev)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("upsert global baseline: {e}"))?;
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
/// 7-day global row (`agent_metric_baselines_global`).
#[must_use]
pub fn assemble_compact_snapshot(hour: i16, rows: &[BaselineRow]) -> UebaCompactSnapshot {
    let mut metrics = Vec::new();
    let mut used_hour = false;
    for name in COMPACT_METRICS {
        let hour_row = rows.iter().find(|r| {
            r.metric_name == *name
                && !r.is_global
                && r.hour_of_week == hour
                && r.n >= EDGE_HOUR_MIN_N
        });
        let global_row = rows.iter().find(|r| r.metric_name == *name && r.is_global);
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
        .find(|r| r.metric_name == "top_processes" && r.is_global)
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
        mac: String::new(),
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
    let hourly = sqlx::query_as::<_, (String, i16, i32, f64, f64, Value)>(
        r#"SELECT metric_name, hour_of_week, n, mean, stddev, learned_set
             FROM agent_metric_baselines
            WHERE tenant_id = $1 AND agent_id = $2
              AND hour_of_week = $3"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(hour)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("load hourly baselines: {e}"))?;
    let global = sqlx::query_as::<_, (String, i32, f64, f64, Value)>(
        r#"SELECT metric_name, n, mean, stddev, learned_set
             FROM agent_metric_baselines_global
            WHERE tenant_id = $1 AND agent_id = $2"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("load global baselines: {e}"))?;
    let _ = tx.commit().await;
    let mut mapped: Vec<BaselineRow> = hourly
        .into_iter()
        .map(
            |(metric_name, hour_of_week, n, mean, stddev, learned_set)| BaselineRow {
                metric_name,
                hour_of_week,
                n,
                mean,
                stddev,
                learned_set,
                is_global: false,
            },
        )
        .collect();
    mapped.extend(
        global
            .into_iter()
            .map(|(metric_name, n, mean, stddev, learned_set)| BaselineRow {
                metric_name,
                hour_of_week: 0,
                n,
                mean,
                stddev,
                learned_set,
                is_global: true,
            }),
    );
    let mut snap = assemble_compact_snapshot(hour, &mapped);
    crate::ueba_snapshot_mac::sign(&mut snap, tenant_id, agent_id);
    Ok(snap)
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
             FROM agent_metric_baselines_global
            WHERE tenant_id = $1 AND agent_id = $2
              AND metric_name = $3"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(metric)
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
    // we've accumulated — that is what the learning gate below reads. Stored in
    // agent_metric_baselines_global so hour_of_week stays a physical 0..=167 clock.
    for x in observed {
        learned.insert(x.clone());
    }
    let learned_vec: Vec<String> = learned.into_iter().collect();
    let _ = sqlx::query(
        r#"INSERT INTO agent_metric_baselines_global
                 (tenant_id, agent_id, metric_name, n, mean, stddev,
                  learned_set, last_updated_at)
           VALUES ($1, $2, $3, 1, 0, 0, $4, now())
           ON CONFLICT (tenant_id, agent_id, metric_name) DO UPDATE SET
               n = agent_metric_baselines_global.n + 1,
               learned_set = EXCLUDED.learned_set,
               last_updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(metric)
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

/// Consecutive skipped samples before a Telemetry Blinding critical alert.
pub const TELEMETRY_BLINDING_THRESHOLD: i32 = 3;
/// On-call page (email/SMS) cooldown. Does **not** silence Postgres or SOAR.
pub const TELEMETRY_BLINDING_ONCALL_SECS: i64 = 900;
#[deprecated(note = "on-call window only; use TELEMETRY_BLINDING_ONCALL_SECS")]
pub const TELEMETRY_BLINDING_REALERT_SECS: i64 = TELEMETRY_BLINDING_ONCALL_SECS;

#[derive(Debug, Clone, Copy, Default)]
pub struct SamplingFailureEval {
    pub consecutive: i32,
    /// Host is blinded (streak ≥ 3). Persist anomaly + SOAR every skip. No cooldown.
    pub persist_event: bool,
    /// Page on-call. 15-minute window. Must not gate persist_event.
    pub page_oncall: bool,
}

/// State-machine / SOAR rule: once blinded, every subsequent skip is an event.
#[must_use]
pub fn should_persist_telemetry_blinding(consecutive: i32) -> bool {
    consecutive >= TELEMETRY_BLINDING_THRESHOLD
}

/// Email/SMS only. APT pulsing inside this window still lands in Postgres + SOAR.
#[must_use]
pub fn should_page_oncall_telemetry_blinding(
    consecutive: i32,
    seconds_since_last_page: Option<i64>,
) -> bool {
    if !should_persist_telemetry_blinding(consecutive) {
        return false;
    }
    match seconds_since_last_page {
        None => true,
        Some(s) => s >= TELEMETRY_BLINDING_ONCALL_SECS,
    }
}

/// Backward-compatible name: this is the **persist/SOAR** rule (no cooldown).
#[must_use]
pub fn should_alert_telemetry_blinding(
    consecutive: i32,
    _seconds_since_last_alert: Option<i64>,
) -> bool {
    should_persist_telemetry_blinding(consecutive)
}

async fn record_sampling_failure(
    pool: &PgPool,
    tenant_id: i64,
    p: &UebaIngestPayload,
    reason: &str,
) -> Result<SamplingFailureEval, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    let sample_error = p
        .metrics
        .get("sample_error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(reason);
    let row: Option<(i32, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        r#"INSERT INTO agent_telemetry_errors
                 (tenant_id, agent_id, client_id, consecutive_failures,
                  last_error, last_failed_at)
           VALUES ($1, $2, $3, 1, $4, now())
           ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
               consecutive_failures = agent_telemetry_errors.consecutive_failures + 1,
               last_error = EXCLUDED.last_error,
               last_failed_at = now(),
               client_id = EXCLUDED.client_id
           RETURNING consecutive_failures, last_alerted_at"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(p.client_id)
    .bind(sample_error)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("upsert telemetry errors: {e}"))?;
    let (consecutive, last_alerted_at) = row.unwrap_or((1, None));
    let secs_since_page = last_alerted_at.map(|ts| (chrono::Utc::now() - ts).num_seconds());
    let persist_event = should_persist_telemetry_blinding(consecutive);
    let page_oncall = should_page_oncall_telemetry_blinding(consecutive, secs_since_page);
    if persist_event {
        sqlx::query(
            r#"INSERT INTO agent_anomalies
                     (tenant_id, agent_id, client_id, sample_id, metric_name,
                      observed, baseline_mean, baseline_stddev, z_score,
                      severity, detail, detected_at)
               VALUES ($1, $2, $3, NULL, 'telemetry_blinding',
                       $4, 0, 0, $4, 'critical', $5, now())"#,
        )
        .bind(tenant_id)
        .bind(&p.agent_id)
        .bind(p.client_id)
        .bind(consecutive as f64)
        .bind(format!(
            "Telemetry Blinding Attack Detected: {consecutive} consecutive sampling failures ({sample_error})"
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("insert blinding anomaly: {e}"))?;
    }
    if page_oncall {
        sqlx::query(
            r#"UPDATE agent_telemetry_errors
                  SET last_alerted_at = now()
                WHERE tenant_id = $1 AND agent_id = $2"#,
        )
        .bind(tenant_id)
        .bind(&p.agent_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("stamp on-call page: {e}"))?;
    }
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(SamplingFailureEval {
        consecutive,
        persist_event,
        page_oncall,
    })
}

async fn reset_sampling_failures(
    pool: &PgPool,
    tenant_id: i64,
    agent_id: &str,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;
    sqlx::query("DELETE FROM agent_telemetry_errors WHERE tenant_id = $1 AND agent_id = $2")
        .bind(tenant_id)
        .bind(agent_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("clear telemetry errors: {e}"))?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(())
}

async fn fire_telemetry_blinding_alert(
    pool: &PgPool,
    tenant_id: i64,
    p: &UebaIngestPayload,
    reason: &str,
    consecutive: i32,
) {
    let finding = serde_json::json!({
        "title": "Telemetry Blinding Attack Detected",
        "severity": "critical",
        "description": format!(
            "Endpoint agent {} reported {consecutive} consecutive host-observation failures ({reason}). Process/port inventory is being suppressed — treat as possible NtQuerySystemInformation / /proc tampering, not a quiet host.",
            p.agent_id
        ),
        "mitre_attack": "T1562.001",
        "kind": "telemetry_blinding",
        "agent_id": p.agent_id,
        "consecutive_failures": consecutive,
        "skip_reason": reason,
        "sample_error": p.metrics.get("sample_error"),
        "source": "agent",
    });
    match crate::findings_persist::persist_engine_findings(
        pool,
        tenant_id,
        Some(p.client_id),
        "telemetry_blinding",
        &p.agent_id,
        std::slice::from_ref(&finding),
    )
    .await
    {
        Ok(_) => tracing::error!(
            target: "ueba",
            agent_id = %p.agent_id,
            consecutive,
            "Telemetry Blinding Attack Detected — critical finding persisted for SOAR"
        ),
        Err(e) => tracing::error!(
            target: "ueba",
            agent_id = %p.agent_id,
            error = %e,
            "failed to persist Telemetry Blinding finding"
        ),
    }
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
    fn global_baseline_is_not_a_clock_sentinel() {
        // Regression: rolling 7-day fire-path rows live in
        // agent_metric_baselines_global, not hour_of_week = -1. Monday 00:00
        // (bucket 0) must remain a physical clock value.
        let rows = vec![BaselineRow {
            metric_name: "process_count".into(),
            hour_of_week: 0,
            n: 4,
            mean: 50.0,
            stddev: 1.0,
            learned_set: Value::Array(vec![]),
            is_global: false,
        }];
        let snap = assemble_compact_snapshot(0, &rows);
        assert_eq!(snap.hour_of_week, 0);
        assert!(snap.mac.is_empty());
    }

    #[test]
    fn compact_snapshot_hour_zero_does_not_collide_with_global() {
        let rows = vec![
            BaselineRow {
                metric_name: "process_count".into(),
                hour_of_week: 0,
                n: 40,
                mean: 100.0,
                stddev: 5.0,
                learned_set: Value::Array(vec![]),
                is_global: true,
            },
            BaselineRow {
                metric_name: "process_count".into(),
                hour_of_week: 0,
                n: 4,
                mean: 50.0,
                stddev: 1.0,
                learned_set: Value::Array(vec![]),
                is_global: false,
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
                hour_of_week: 0,
                n: 40,
                mean: 100.0,
                stddev: 5.0,
                learned_set: Value::Array(vec![]),
                is_global: true,
            },
            BaselineRow {
                metric_name: "process_count".into(),
                hour_of_week: 12,
                n: 4,
                mean: 80.0,
                stddev: 2.0,
                learned_set: Value::Array(vec![]),
                is_global: false,
            },
            BaselineRow {
                metric_name: "top_processes".into(),
                hour_of_week: 0,
                n: 40,
                mean: 0.0,
                stddev: 0.0,
                learned_set: serde_json::json!(["sshd", "systemd"]),
                is_global: true,
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
            hour_of_week: 0,
            n: 40,
            mean: 100.0,
            stddev: 5.0,
            learned_set: Value::Array(vec![]),
            is_global: true,
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

    #[test]
    fn sampling_failed_flag_skips_z_score() {
        let metrics = serde_json::json!({
            "sampling_failed": true,
            "sample_error": "syscall:NtQuerySystemInformation",
            "open_port_count": 0
        });
        assert_eq!(ueba_sample_skip_reason(&metrics), Some("sampling_failed"));
    }

    #[test]
    fn empty_process_count_is_not_mass_deletion() {
        let metrics = serde_json::json!({"process_count": 0, "open_port_count": 0});
        assert_eq!(
            ueba_sample_skip_reason(&metrics),
            Some("empty_process_count")
        );
        // (0 - 80) / 5 = -16 would have been a high anomaly and isolate_host.
        let z = (0.0_f64 - 80.0) / 5.0;
        assert!(
            z < -6.0,
            "zero-count vs live baseline is Z < -6; skip must fire first"
        );
    }

    #[test]
    fn healthy_inventory_is_ingested() {
        let metrics = serde_json::json!({"process_count": 87, "open_port_count": 12});
        assert_eq!(ueba_sample_skip_reason(&metrics), None);
    }

    #[test]
    fn blinding_alert_fires_on_third_consecutive_failure() {
        assert!(!should_persist_telemetry_blinding(1));
        assert!(!should_persist_telemetry_blinding(2));
        assert!(should_persist_telemetry_blinding(3));
        assert!(should_persist_telemetry_blinding(4));
        // Cooldown must NOT silence SOAR / Postgres. A 30s block + 5s clear +
        // 10min block inside the old 15-minute window still persists.
        assert!(
            should_alert_telemetry_blinding(4, Some(60)),
            "SOAR/event log is not cooldown-gated"
        );
        assert!(
            !should_page_oncall_telemetry_blinding(4, Some(60)),
            "on-call page (email/SMS) keeps the 15-minute window"
        );
        assert!(should_page_oncall_telemetry_blinding(
            4,
            Some(TELEMETRY_BLINDING_ONCALL_SECS)
        ));
        assert_eq!(TELEMETRY_BLINDING_THRESHOLD, 3);
    }
}
