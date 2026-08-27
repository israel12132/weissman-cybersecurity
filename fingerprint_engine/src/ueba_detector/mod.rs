//! UEBA detector — ingest, rolling baselines, categorical anomalies, retention.
//!
//! Public surface is unchanged for callers (`ingest_sample`, `UebaIngestPayload`,
//! `spawn_retention_loop`) so WebSocket findings and HTTP ingest keep working.

mod categorical;
mod health;
mod ingest;
mod retention;
mod soar;
mod stats;
mod time;
mod validate;

pub use health::{
    as_json as health_json, failsafe, host_cpu_busy_pct, set_failsafe, snapshot as health_snapshot,
    UebaHealth,
};
pub use ingest::{enqueue, gzip_json, spawn_ingest_worker, EnqueueError};
pub use retention::{
    run_retention_once, spawn_baseline_recompute_loop, spawn_retention_loop, RetentionReport,
};
pub use stats::{z_score, z_threshold_for};
pub use validate::{public_error, sanitize_metrics, IngestReject};

use categorical::{
    in_whitelist, is_os_baseline, ports_as_i32, uniqueness_score, LearnedSet, LEARNED_SET_CAP,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use stats::{
    combined_score, effective_stddev, metric_weight, min_delta_for, sanitize_f64, severity_for_z,
    sigma_floor_for, winsorize, Ewmv, DEFAULT_Z_THRESHOLD, HIGH_Z,
};
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use time::{
    adjacent_hours, clock_skew_secs, distinct_weekdays, hour_of_week_utc,
    is_boundary_false_positive, is_offhours, learning_complete, offhours_multiplier,
    should_update_baseline, CLOCK_SKEW_WARN_SECS,
};
use validate::{
    sanitize_process_name, validate_agent_id, validate_hour, validate_nonce, MAX_NONCE_LEN,
};

/// Canonical firing baseline is per (agent, metric) under this hour-of-week sentinel.
/// Raw samples still store the real UTC hour-of-week for temporal smoothing.
const GLOBAL_BUCKET: i16 = 0;
const MIN_BASELINE_SAMPLES: i32 = 24;
const DECAY_LAMBDA: f64 = 0.97;

// Re-export so existing `assert!(Z_THRESHOLD == 3.0)` tests still compile if they import it.
pub const Z_THRESHOLD: f64 = DEFAULT_Z_THRESHOLD;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaIngestPayload {
    pub agent_id: String,
    #[serde(default)]
    pub client_id: i64,
    #[serde(default)]
    pub hour_of_week: i16,
    pub metrics: Value,
    #[serde(default)]
    pub seq: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub sampled_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub metrics_gz: Option<String>,
    #[serde(default)]
    pub hardware_id: Option<String>,
    #[serde(default)]
    pub source_ip: Option<String>,
    /// Not part of the wire schema — set by the ingest worker.
    #[serde(default, skip)]
    pub require_live_session: bool,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct UebaIngestSummary {
    pub baselines_updated: usize,
    pub anomalies: Vec<AnomalyRecord>,
    #[serde(default)]
    pub learning: bool,
    #[serde(default)]
    pub discarded: bool,
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

struct TenantPolicy {
    learn_window_days: i64,
    business_start: i16,
    business_end: i16,
    holiday_dates: Vec<chrono::NaiveDate>,
    treat_holidays_as_weekend: bool,
}

impl Default for TenantPolicy {
    fn default() -> Self {
        Self {
            learn_window_days: 7,
            business_start: 8,
            business_end: 18,
            holiday_dates: Vec::new(),
            treat_holidays_as_weekend: true,
        }
    }
}

/// Serialize ingest per agent so a 32-sample reconnect batch cannot race EWMV.
fn agent_ingest_gate(agent_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    static GATES: OnceLock<dashmap::DashMap<String, Arc<tokio::sync::Mutex<()>>>> = OnceLock::new();
    let map = GATES.get_or_init(dashmap::DashMap::new);
    map.entry(agent_id.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Public entry point — called by the ingest worker (and tests).
pub async fn ingest_sample(
    pool: &PgPool,
    tenant_id: i64,
    mut p: UebaIngestPayload,
) -> Result<UebaIngestSummary, String> {
    validate_agent_id(&p.agent_id).map_err(|_| "invalid ingest payload".to_string())?;
    p.hour_of_week =
        validate_hour(p.hour_of_week).map_err(|_| "invalid ingest payload".to_string())?;
    ingest::maybe_decompress_metrics(&mut p);
    sanitize_metrics(&mut p.metrics).map_err(|_| "invalid ingest payload".to_string())?;

    if health::disk_free_pct("/")
        .map(|pct| pct < 10.0)
        .unwrap_or(false)
    {
        health::set_failsafe(true);
        return Ok(UebaIngestSummary {
            discarded: true,
            ..UebaIngestSummary::default()
        });
    }

    let _agent_serial = agent_ingest_gate(&p.agent_id).lock().await;

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|_| "ingest failed".to_string())?;

    let policy = load_policy(&mut tx, tenant_id).await.unwrap_or_default();

    let agent_row: Option<(i64, bool, i64, String, Option<DateTime<Utc>>)> = sqlx::query_as(
        r#"SELECT client_id, COALESCE(is_learning, true), COALESCE(last_sample_seq, 0),
                  COALESCE(hardware_id, ''), last_sample_at
             FROM endpoint_agents
            WHERE tenant_id = $1 AND agent_uuid = $2::uuid"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;

    let Some((bound_client, mut is_learning, last_seq, stored_hw, last_sample_at)) = agent_row
    else {
        let _ = tx.rollback().await;
        return Err("ingest failed".into());
    };
    if p.client_id != 0 && p.client_id != bound_client {
        let _ = tx.rollback().await;
        return Err("agent out of client scope".into());
    }
    p.client_id = bound_client;

    if let Some(hw) = p
        .hardware_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if stored_hw.is_empty() {
            let _ = sqlx::query(
                "UPDATE endpoint_agents SET hardware_id = $1 WHERE tenant_id = $2 AND agent_uuid = $3::uuid",
            )
            .bind(hw)
            .bind(tenant_id)
            .bind(&p.agent_id)
            .execute(&mut *tx)
            .await;
        } else if stored_hw != hw {
            let _ = tx.rollback().await;
            return Err("agent out of client scope".into());
        }
    }

    if let Some(ip) = p.source_ip.as_deref() {
        if !ip_in_client_scope(&mut tx, tenant_id, p.client_id, ip)
            .await
            .unwrap_or(true)
        {
            let _ = tx.rollback().await;
            return Err("agent out of client scope".into());
        }
    }

    if p.require_live_session {
        let live = crate::endpoint_agents::AgentRegistry::global()
            .is_online(&p.agent_id)
            .await;
        if !live {
            let _ = tx.rollback().await;
            return Err("no live agent session".into());
        }
    }

    if let Some(seq) = p.seq {
        if seq > 0 && seq <= last_seq {
            let _ = tx.rollback().await;
            return Err("replay rejected".into());
        }
    }
    if let Some(nonce) = p.nonce.as_deref() {
        if !validate_nonce(nonce) {
            let _ = tx.rollback().await;
            return Err("invalid ingest payload".into());
        }
        let inserted: bool = sqlx::query_scalar(
            r#"INSERT INTO ueba_ingest_nonces (tenant_id, agent_id, nonce, seq, seen_at)
               VALUES ($1, $2, $3, $4, now())
               ON CONFLICT (tenant_id, agent_id, nonce) DO NOTHING
               RETURNING true"#,
        )
        .bind(tenant_id)
        .bind(&p.agent_id)
        .bind(nonce)
        .bind(p.seq.unwrap_or(0))
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "ingest failed".to_string())?
        .unwrap_or(false);
        if !inserted {
            let _ = tx.rollback().await;
            return Err("replay rejected".into());
        }
    }

    let received = Utc::now();
    let sampled_at = p.sampled_at.unwrap_or(received);
    // Delayed samples map to their original hour-of-week (UTC), not arrival time.
    p.hour_of_week = hour_of_week_utc(sampled_at);
    if clock_skew_secs(sampled_at, received) > CLOCK_SKEW_WARN_SECS {
        tracing::warn!(
            target: "ueba_ingest",
            agent_id = %p.agent_id,
            skew_secs = clock_skew_secs(sampled_at, received),
            "agent clock skew exceeds 5 minutes"
        );
    }

    let raw_size = serde_json::to_string(&p.metrics)
        .map(|s| s.len() as i32)
        .unwrap_or(0);
    let open_ports: Vec<i32> = p
        .metrics
        .get("open_ports")
        .and_then(Value::as_array)
        .map(|a| ports_as_i32(a))
        .unwrap_or_default();

    let source_ip: Option<std::net::IpAddr> = p.source_ip.as_deref().and_then(|s| s.parse().ok());
    let sample_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO agent_metric_samples
                 (tenant_id, agent_id, client_id, sampled_at, ingested_at, hour_of_week,
                  metrics, raw_size_bytes, seq, nonce, open_ports, source_ip)
           VALUES ($1, $2, $3, $4, now(), $5, $6, $7, $8, $9, $10, $11::inet)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(p.client_id)
    .bind(sampled_at)
    .bind(p.hour_of_week)
    .bind(&p.metrics)
    .bind(raw_size)
    .bind(p.seq)
    .bind(&p.nonce)
    .bind(&open_ports)
    .bind(source_ip.map(|a| a.to_string()))
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;

    let _ = sqlx::query(
        r#"UPDATE endpoint_agents
              SET last_sample_seq = CASE
                      WHEN $1::bigint IS NULL THEN last_sample_seq
                      ELSE GREATEST(COALESCE(last_sample_seq, 0), $1)
                  END,
                  last_sample_at = GREATEST(COALESCE(last_sample_at, $2), $2)
            WHERE tenant_id = $3 AND agent_uuid = $4::uuid"#,
    )
    .bind(p.seq)
    .bind(sampled_at)
    .bind(tenant_id)
    .bind(&p.agent_id)
    .execute(&mut *tx)
    .await;

    let apply_baseline = should_update_baseline(
        sampled_at,
        received,
        last_sample_at,
        policy.learn_window_days,
    );

    let whitelist = load_whitelist(&mut tx, tenant_id, p.client_id)
        .await
        .unwrap_or_default();

    let mut summary = UebaIngestSummary {
        learning: is_learning,
        ..UebaIngestSummary::default()
    };

    let offhours = is_offhours(
        p.hour_of_week,
        sampled_at,
        policy.business_start,
        policy.business_end,
        &policy.holiday_dates,
        policy.treat_holidays_as_weekend,
    );

    if apply_baseline {
        if let Value::Object(obj) = &p.metrics {
            let mut z_pairs: Vec<(f64, f64)> = Vec::new();
            for (k, v) in obj {
                if let Some(num) = v.as_f64() {
                    if k == "uptime_seconds" {
                        handle_uptime(&mut tx, tenant_id, &p, sample_id, num, is_learning).await?;
                        continue;
                    }
                    let upd =
                        update_ewmv(&mut tx, tenant_id, &p.agent_id, k, num, DECAY_LAMBDA).await?;
                    summary.baselines_updated += 1;
                    if let Some(anom) = check_anomaly(
                        &mut tx,
                        tenant_id,
                        &p,
                        sample_id,
                        k,
                        num,
                        &upd,
                        is_learning,
                        offhours,
                    )
                    .await?
                    {
                        z_pairs.push((metric_weight(k), anom.z_score));
                        summary.anomalies.push(anom);
                    }
                }
            }
            if combined_score(&z_pairs) >= HIGH_Z && !is_learning {
                // Joint deviation across metrics — extra high-severity row.
                if let Some(a) = insert_anomaly_row(
                    &mut tx,
                    tenant_id,
                    &p,
                    sample_id,
                    "multivariate",
                    combined_score(&z_pairs),
                    0.0,
                    1.0,
                    combined_score(&z_pairs),
                    "high",
                    "Joint UEBA deviation across multiple host metrics",
                )
                .await?
                {
                    summary.anomalies.push(a);
                }
            }

            if let Some(ports) = obj.get("open_ports").and_then(Value::as_array) {
                let observed: Vec<String> = ports_as_i32(ports)
                    .into_iter()
                    .map(|n| n.to_string())
                    .collect();
                if let Some(a) = check_new_categorical(
                    &mut tx,
                    tenant_id,
                    &p,
                    sample_id,
                    "open_ports",
                    &observed,
                    "Unfamiliar TCP port listening on host",
                    is_learning,
                    &whitelist,
                )
                .await?
                {
                    summary.anomalies.push(a);
                }
            }
            if let Some(procs) = obj.get("top_processes").and_then(Value::as_array) {
                let observed: Vec<String> = procs
                    .iter()
                    .filter_map(|v| v.as_str().map(sanitize_process_name))
                    .filter(|s| !s.is_empty())
                    .collect();
                if let Some(a) = check_new_categorical(
                    &mut tx,
                    tenant_id,
                    &p,
                    sample_id,
                    "top_processes",
                    &observed,
                    "Unfamiliar process observed running on host",
                    is_learning,
                    &whitelist,
                )
                .await?
                {
                    summary.anomalies.push(a);
                }
            }
            if let Some(lm) = obj.get("listen_map").and_then(Value::as_array) {
                let observed: Vec<String> = lm
                    .iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                if let Some(a) = check_new_categorical(
                    &mut tx,
                    tenant_id,
                    &p,
                    sample_id,
                    "listen_map",
                    &observed,
                    "Known port opened by an unfamiliar process",
                    is_learning,
                    &whitelist,
                )
                .await?
                {
                    summary.anomalies.push(a);
                }
            }
        }
    }

    let hours: Vec<i16> = sqlx::query_scalar(
        r#"SELECT DISTINCT hour_of_week FROM agent_metric_samples
            WHERE tenant_id = $1 AND agent_id = $2
              AND sampled_at > now() - ($3 || ' days')::interval"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(policy.learn_window_days)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let days = distinct_weekdays(&hours);
    let n_samples: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM agent_metric_samples
            WHERE tenant_id = $1 AND agent_id = $2
              AND sampled_at > now() - ($3 || ' days')::interval"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(policy.learn_window_days)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);
    let trained = learning_complete(n_samples as i32, MIN_BASELINE_SAMPLES, days);
    if is_learning && trained {
        let _ = sqlx::query(
            r#"UPDATE endpoint_agents
                  SET is_learning = false, learning_completed_at = now()
                WHERE tenant_id = $1 AND agent_uuid = $2::uuid"#,
        )
        .bind(tenant_id)
        .bind(&p.agent_id)
        .execute(&mut *tx)
        .await;
        is_learning = false;
    }
    summary.learning = is_learning;
    if is_learning {
        summary.anomalies.clear();
    }

    // Sample-gap / mute detection: expected cadence is ~15 min; a drop without matching
    // load collapse is a muting attempt. Never fire while the agent is still learning.
    if !is_learning {
        detect_sample_gap(&mut tx, tenant_id, &p, sample_id).await?;
    }

    tx.commit().await.map_err(|_| "ingest failed".to_string())?;

    if !summary.anomalies.is_empty() {
        soar::spawn_post_commit(
            pool.clone(),
            tenant_id,
            p.client_id,
            p.agent_id.clone(),
            summary.anomalies.clone(),
            offhours,
        );
    }
    health::note_ingest();
    Ok(summary)
}

async fn load_policy(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
) -> Result<TenantPolicy, sqlx::Error> {
    let row: Option<(i32, i16, i16, bool, Vec<chrono::NaiveDate>)> = sqlx::query_as(
        r#"SELECT learn_window_days, business_hours_start, business_hours_end,
                  treat_holidays_as_weekend, COALESCE(holiday_dates, ARRAY[]::date[])
             FROM ueba_tenant_policy WHERE tenant_id = $1"#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(match row {
        Some((w, s, e, hol, dates)) => TenantPolicy {
            learn_window_days: time::clamp_learn_window_days(w as i64),
            business_start: s,
            business_end: e,
            holiday_dates: dates,
            treat_holidays_as_weekend: hol,
        },
        None => TenantPolicy::default(),
    })
}

async fn load_whitelist(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
) -> Result<HashSet<String>, sqlx::Error> {
    let rows: Vec<String> = sqlx::query_scalar(
        r#"SELECT process_name FROM ueba_process_whitelist
            WHERE tenant_id = $1 AND (client_id IS NULL OR client_id = $2)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|s| sanitize_process_name(&s))
        .collect())
}

async fn ip_in_client_scope(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
    ip: &str,
) -> Result<bool, sqlx::Error> {
    let ranges: String = sqlx::query_scalar(
        "SELECT COALESCE(ip_ranges, '[]') FROM clients WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or_else(|| "[]".into());
    let parsed: Vec<String> = serde_json::from_str(&ranges).unwrap_or_default();
    if parsed.is_empty() {
        return Ok(true);
    }
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return Ok(false);
    };
    for cidr in parsed {
        if let Ok(net) = cidr.parse::<ipnetwork::IpNetwork>() {
            if net.contains(addr) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

async fn update_ewmv(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
    observed: f64,
    lambda: f64,
) -> Result<BaselineUpdate, String> {
    let row: Option<(i32, f64, f64, f64, f64, f64, f64)> = sqlx::query_as(
        r#"SELECT n, mean, stddev, COALESCE(welford_m2, 0), COALESCE(mad, 0),
                  COALESCE(ewmv_w, 0), COALESCE(ewmv_v2, 0)
             FROM agent_metric_baselines
            WHERE tenant_id = $1 AND agent_id = $2
              AND metric_name = $3 AND hour_of_week = $4"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(metric)
    .bind(GLOBAL_BUCKET)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;

    let mut e = match row {
        Some((n, mean, _sd, m2, _, w, v2)) => Ewmv::from_parts(n, mean, m2, w, v2),
        None => Ewmv::default(),
    };
    let clipped = winsorize(observed, e.mean, e.stddev());
    e.update(clipped, lambda);
    let mad = e.stddev() / stats::MAD_TO_SIGMA;
    let stddev = effective_stddev(e.stddev(), mad).max(sigma_floor_for(metric));

    sqlx::query(
        r#"INSERT INTO agent_metric_baselines
                 (tenant_id, agent_id, metric_name, hour_of_week, n, mean, stddev,
                  welford_m2, mad, ewmv_w, ewmv_v2, learned_set, last_updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, '{}'::jsonb, now())
           ON CONFLICT (tenant_id, agent_id, metric_name, hour_of_week) DO UPDATE SET
               n = EXCLUDED.n,
               mean = EXCLUDED.mean,
               stddev = EXCLUDED.stddev,
               welford_m2 = EXCLUDED.welford_m2,
               mad = EXCLUDED.mad,
               ewmv_w = EXCLUDED.ewmv_w,
               ewmv_v2 = EXCLUDED.ewmv_v2,
               last_updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(metric)
    .bind(GLOBAL_BUCKET)
    .bind(e.n as i32)
    .bind(sanitize_f64(e.mean))
    .bind(sanitize_f64(stddev))
    .bind(sanitize_f64(e.s))
    .bind(sanitize_f64(mad))
    .bind(sanitize_f64(e.w))
    .bind(sanitize_f64(e.v2))
    .execute(&mut **tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;

    Ok(BaselineUpdate {
        n: e.n as i32,
        mean: e.mean,
        stddev,
    })
}

async fn check_anomaly(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    p: &UebaIngestPayload,
    sample_id: i64,
    metric: &str,
    observed: f64,
    base: &BaselineUpdate,
    is_learning: bool,
    offhours: bool,
) -> Result<Option<AnomalyRecord>, String> {
    if is_learning || base.n < MIN_BASELINE_SAMPLES {
        return Ok(None);
    }
    let thresh = z_threshold_for(metric);
    if !thresh.is_finite() {
        return Ok(None);
    }
    let delta = (observed - base.mean).abs();
    if delta < min_delta_for(metric) {
        return Ok(None);
    }
    let mut z = stats::z_score(observed, base.mean, base.stddev);
    z *= offhours_multiplier(offhours);
    if z.abs() < thresh {
        return Ok(None);
    }
    // Temporal smoothing: a lone spike on an hour boundary against quiet neighbours is dropped.
    let (prev_h, next_h) = adjacent_hours(p.hour_of_week);
    let z_prev = bucket_z(tx, tenant_id, &p.agent_id, metric, prev_h, observed).await;
    let z_next = bucket_z(tx, tenant_id, &p.agent_id, metric, next_h, observed).await;
    if is_boundary_false_positive(z, z_prev, z_next, thresh) {
        return Ok(None);
    }
    let mut severity = severity_for_z(z).to_string();
    if offhours && (severity == "medium") {
        severity = "high".into();
    }
    let direction = if z > 0.0 { "above" } else { "below" };
    let detail = format!(
        "Metric `{metric}` observed {:.2}, baseline {:.2} ± {:.2} (z={:+.2}, {direction} {thresh}σ).",
        observed, base.mean, base.stddev, z
    );
    insert_anomaly_row(
        tx,
        tenant_id,
        p,
        sample_id,
        metric,
        observed,
        base.mean,
        base.stddev,
        z,
        &severity,
        &detail,
    )
    .await
}

async fn bucket_z(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
    hour: i16,
    observed: f64,
) -> Option<f64> {
    let row: Option<(f64, f64)> = sqlx::query_as(
        r#"SELECT mean, stddev FROM agent_metric_baselines
            WHERE tenant_id = $1 AND agent_id = $2 AND metric_name = $3 AND hour_of_week = $4"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(metric)
    .bind(hour)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten();
    row.map(|(m, s)| stats::z_score(observed, m, s))
}

async fn handle_uptime(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    p: &UebaIngestPayload,
    sample_id: i64,
    observed: f64,
    is_learning: bool,
) -> Result<(), String> {
    let prev: Option<f64> = sqlx::query_scalar(
        r#"SELECT mean FROM agent_metric_baselines
            WHERE tenant_id = $1 AND agent_id = $2 AND metric_name = 'uptime_seconds'
              AND hour_of_week = $3"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(GLOBAL_BUCKET)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten();
    let reset = p
        .metrics
        .get("uptime_reset")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || prev.map(|v| observed + 60.0 < v).unwrap_or(false);
    // Always store the current value as the "mean" so the next sample can delta.
    let _ = sqlx::query(
        r#"INSERT INTO agent_metric_baselines
                 (tenant_id, agent_id, metric_name, hour_of_week, n, mean, stddev, learned_set, last_updated_at)
           VALUES ($1, $2, 'uptime_seconds', $3, 1, $4, 0, '{}'::jsonb, now())
           ON CONFLICT (tenant_id, agent_id, metric_name, hour_of_week) DO UPDATE SET
               mean = EXCLUDED.mean, last_updated_at = now(), n = agent_metric_baselines.n + 1"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(GLOBAL_BUCKET)
    .bind(sanitize_f64(observed))
    .execute(&mut **tx)
    .await;
    if reset && !is_learning {
        let _ = insert_anomaly_row(
            tx,
            tenant_id,
            p,
            sample_id,
            "uptime_seconds",
            observed,
            prev.unwrap_or(0.0),
            0.0,
            0.0,
            "info",
            "Host uptime reset (reboot); excluded from z-score",
        )
        .await?;
    }
    Ok(())
}

async fn check_new_categorical(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    p: &UebaIngestPayload,
    sample_id: i64,
    metric: &str,
    observed: &[String],
    title: &str,
    is_learning: bool,
    whitelist: &HashSet<String>,
) -> Result<Option<AnomalyRecord>, String> {
    let row: Option<(Value, i32)> = sqlx::query_as(
        r#"SELECT learned_set, n FROM agent_metric_baselines
            WHERE tenant_id = $1 AND agent_id = $2 AND metric_name = $3 AND hour_of_week = $4"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(metric)
    .bind(GLOBAL_BUCKET)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;

    let n_obs = row.as_ref().map(|(_, n)| *n).unwrap_or(0);
    let mut learned = match row {
        Some((v, _)) => LearnedSet::from_json(&v),
        None => LearnedSet::default(),
    };
    let now = Utc::now().timestamp();
    let process_names = metric == "top_processes" || metric == "listen_map";
    let mut novel = learned.observe(observed, now, process_names);
    novel.retain(|x| !in_whitelist(x, whitelist) && !is_os_baseline(x));
    if learned.seen.len() > LEARNED_SET_CAP {
        learned.prune(now);
    }
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
    .bind(learned.to_json())
    .execute(&mut **tx)
    .await;

    if is_learning || n_obs < MIN_BASELINE_SAMPLES || novel.is_empty() {
        return Ok(None);
    }
    if metric == "top_processes" {
        let token = novel.first().cloned().unwrap_or_default();
        let uniq = fleet_uniqueness(tx, tenant_id, p.client_id, &token)
            .await
            .unwrap_or(1.0);
        if uniq < 0.4 {
            return Ok(None);
        }
    }
    let detail = format!("{}: {}", title, novel.join(", "));
    insert_anomaly_row(
        tx,
        tenant_id,
        p,
        sample_id,
        metric,
        novel.len() as f64,
        0.0,
        0.0,
        novel.len() as f64,
        "medium",
        &detail,
    )
    .await
}

async fn insert_anomaly_row(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    p: &UebaIngestPayload,
    sample_id: i64,
    metric: &str,
    observed: f64,
    mean: f64,
    stddev: f64,
    z: f64,
    severity: &str,
    detail: &str,
) -> Result<Option<AnomalyRecord>, String> {
    // Auto-suppress: 3× FP on this (agent, metric) signature.
    let suppressed: bool = sqlx::query_scalar(
        r#"SELECT COALESCE(auto_suppressed, false) FROM ueba_metric_suppressions
            WHERE tenant_id = $1 AND agent_id = $2 AND metric_name = $3"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(metric)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten()
    .unwrap_or(false);
    if suppressed {
        return Ok(None);
    }
    sqlx::query(
        r#"INSERT INTO agent_anomalies
                 (tenant_id, agent_id, client_id, sample_id, metric_name,
                  observed, baseline_mean, baseline_stddev, z_score,
                  severity, detail, detected_at, created_at, hour_of_week, weighted_score, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), now(), $12, $13, 'open')"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(p.client_id)
    .bind(if sample_id > 0 { Some(sample_id) } else { None })
    .bind(metric)
    .bind(sanitize_f64(observed))
    .bind(sanitize_f64(mean))
    .bind(sanitize_f64(stddev))
    .bind(sanitize_f64(z))
    .bind(severity)
    .bind(detail)
    .bind(p.hour_of_week)
    .bind(sanitize_f64(z.abs() * metric_weight(metric)))
    .execute(&mut **tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;
    Ok(Some(AnomalyRecord {
        metric: metric.to_string(),
        observed,
        baseline_mean: mean,
        baseline_stddev: stddev,
        z_score: z,
        severity: severity.to_string(),
        detail: detail.to_string(),
    }))
}

async fn fleet_uniqueness(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
    detail: &str,
) -> Result<f64, sqlx::Error> {
    let fleet: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM endpoint_agents WHERE tenant_id = $1 AND client_id = $2",
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_one(&mut **tx)
    .await?;
    let token = detail.trim();
    let hosts: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(DISTINCT agent_id) FROM agent_metric_baselines
            WHERE tenant_id = $1 AND metric_name = 'top_processes'
              AND learned_set::text LIKE '%' || $2 || '%'"#,
    )
    .bind(tenant_id)
    .bind(token.chars().take(48).collect::<String>())
    .fetch_one(&mut **tx)
    .await
    .unwrap_or(1);
    Ok(uniqueness_score(hosts, fleet))
}

async fn detect_sample_gap(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    p: &UebaIngestPayload,
    sample_id: i64,
) -> Result<(), String> {
    let prev: Option<DateTime<Utc>> = sqlx::query_scalar(
        r#"SELECT sampled_at FROM agent_metric_samples
            WHERE tenant_id = $1 AND agent_id = $2 AND id <> (
                SELECT MAX(id) FROM agent_metric_samples
                 WHERE tenant_id = $1 AND agent_id = $2
            )
            ORDER BY sampled_at DESC LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten();
    let Some(prev) = prev else {
        return Ok(());
    };
    let gap = (Utc::now() - prev).num_minutes();
    // Expected cadence ≈ 15 min; > 90 min without a matching load collapse is muting.
    if gap < 90 {
        return Ok(());
    }
    let load = p
        .metrics
        .get("load_1m")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    if load < 0.05 {
        return Ok(());
    }
    let _ = insert_anomaly_row(
        tx,
        tenant_id,
        p,
        sample_id,
        "sample_gap",
        gap as f64,
        15.0,
        1.0,
        ((gap as f64) - 15.0) / 15.0,
        "high",
        &format!("UEBA sample gap of {gap} minutes while host load remained {load:.2}"),
    )
    .await?;
    Ok(())
}

/// Disposition (FP / approved) with audit + 3× auto-suppress.
pub async fn dispose_anomaly(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    user_label: &str,
    anomaly_id: i64,
    status: &str,
    reason: &str,
) -> Result<(), String> {
    let status = match status {
        "false_positive" | "approved" | "open" => status,
        _ => return Err("invalid disposition".into()),
    };
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|_| "ingest failed".to_string())?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT agent_id, metric_name FROM agent_anomalies WHERE id = $1")
            .bind(anomaly_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| "ingest failed".to_string())?;
    let Some((agent_id, metric)) = row else {
        return Err("not found".into());
    };
    sqlx::query(
        r#"UPDATE agent_anomalies
              SET status = $1, disposition_reason = $2, disposition_by = $3
            WHERE id = $4"#,
    )
    .bind(status)
    .bind(reason)
    .bind(user_id)
    .bind(anomaly_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;
    crate::audit_log::insert_audit(
        &mut tx,
        tenant_id,
        Some(user_id),
        user_label,
        "ueba_anomaly_disposition",
        &format!(
            "id={anomaly_id} status={status} reason={reason} metric={metric} agent={agent_id}"
        ),
        "",
    )
    .await
    .map_err(|_| "ingest failed".to_string())?;
    if status == "false_positive" {
        sqlx::query(
            r#"INSERT INTO ueba_metric_suppressions
                     (tenant_id, agent_id, metric_name, fp_count, auto_suppressed, updated_at)
               VALUES ($1, $2, $3, 1, false, now())
               ON CONFLICT (tenant_id, agent_id, metric_name) DO UPDATE SET
                   fp_count = ueba_metric_suppressions.fp_count + 1,
                   auto_suppressed = (ueba_metric_suppressions.fp_count + 1) >= 3,
                   updated_at = now()"#,
        )
        .bind(tenant_id)
        .bind(&agent_id)
        .bind(&metric)
        .execute(&mut *tx)
        .await
        .map_err(|_| "ingest failed".to_string())?;
    }
    tx.commit().await.map_err(|_| "ingest failed".to_string())?;
    Ok(())
}

pub async fn upsert_policy(
    pool: &PgPool,
    tenant_id: i64,
    learn_window_days: i64,
    business_start: i16,
    business_end: i16,
    treat_holidays_as_weekend: bool,
    holiday_dates: Vec<chrono::NaiveDate>,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|_| "ingest failed".to_string())?;
    sqlx::query(
        r#"INSERT INTO ueba_tenant_policy
               (tenant_id, learn_window_days, business_hours_start, business_hours_end,
                treat_holidays_as_weekend, holiday_dates)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (tenant_id) DO UPDATE SET
               learn_window_days = EXCLUDED.learn_window_days,
               business_hours_start = EXCLUDED.business_hours_start,
               business_hours_end = EXCLUDED.business_hours_end,
               treat_holidays_as_weekend = EXCLUDED.treat_holidays_as_weekend,
               holiday_dates = EXCLUDED.holiday_dates"#,
    )
    .bind(tenant_id)
    .bind(time::clamp_learn_window_days(learn_window_days) as i32)
    .bind(business_start.clamp(0, 23))
    .bind(business_end.clamp(1, 24))
    .bind(treat_holidays_as_weekend)
    .bind(&holiday_dates)
    .execute(&mut *tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;
    tx.commit().await.map_err(|_| "ingest failed".to_string())?;
    Ok(())
}

pub async fn load_policy_public(pool: &PgPool, tenant_id: i64) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|_| "ingest failed".to_string())?;
    let p = load_policy(&mut tx, tenant_id).await.unwrap_or_default();
    let _ = tx.commit().await;
    Ok(serde_json::json!({
        "learn_window_days": p.learn_window_days,
        "business_hours_start": p.business_start,
        "business_hours_end": p.business_end,
        "treat_holidays_as_weekend": p.treat_holidays_as_weekend,
        "holiday_dates": p.holiday_dates,
    }))
}

pub async fn fleet_snapshot(pool: &PgPool, tenant_id: i64) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|_| "ingest failed".to_string())?;
    let rows = sqlx::query(
        r#"SELECT a.agent_uuid::text, a.hostname, a.client_id, COALESCE(a.is_learning, true) AS is_learning,
                  a.last_sample_at, a.last_seen_at,
                  (SELECT COUNT(*) FROM agent_anomalies an
                    WHERE an.tenant_id = a.tenant_id AND an.agent_id = a.agent_uuid::text
                      AND an.detected_at > now() - interval '24 hours') AS anomalies_24h
             FROM endpoint_agents a
            WHERE a.tenant_id = $1
            ORDER BY a.last_seen_at DESC NULLS LAST
            LIMIT 500"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;
    let _ = tx.commit().await;
    let agents: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "agent_id": r.try_get::<String, _>("agent_uuid").unwrap_or_default(),
                "hostname": r.try_get::<String, _>("hostname").unwrap_or_default(),
                "client_id": r.try_get::<i64, _>("client_id").unwrap_or(0),
                "is_learning": r.try_get::<bool, _>("is_learning").unwrap_or(true),
                "last_sample_at": r.try_get::<Option<DateTime<Utc>>, _>("last_sample_at").ok().flatten().map(|d| d.to_rfc3339()),
                "last_seen_at": r.try_get::<Option<DateTime<Utc>>, _>("last_seen_at").ok().flatten().map(|d| d.to_rfc3339()),
                "anomalies_24h": r.try_get::<i64, _>("anomalies_24h").unwrap_or(0),
            })
        })
        .collect();
    Ok(serde_json::json!({ "ok": true, "agents": agents }))
}

pub async fn whitelist_list(pool: &PgPool, tenant_id: i64) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|_| "ingest failed".to_string())?;
    let rows = sqlx::query(
        r#"SELECT id, client_id, process_name, reason, created_at
             FROM ueba_process_whitelist WHERE tenant_id = $1 ORDER BY id DESC LIMIT 500"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;
    let _ = tx.commit().await;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "id": r.try_get::<i64, _>("id").unwrap_or(0),
                "client_id": r.try_get::<Option<i64>, _>("client_id").ok().flatten(),
                "process_name": r.try_get::<String, _>("process_name").unwrap_or_default(),
                "reason": r.try_get::<String, _>("reason").unwrap_or_default(),
                "created_at": r.try_get::<DateTime<Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
            })
        })
        .collect();
    Ok(serde_json::json!({ "ok": true, "items": items }))
}

pub async fn whitelist_add(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    client_id: Option<i64>,
    process_name: &str,
    reason: &str,
) -> Result<i64, String> {
    let name = sanitize_process_name(process_name);
    if name.is_empty() {
        return Err("invalid process name".into());
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|_| "ingest failed".to_string())?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO ueba_process_whitelist
               (tenant_id, client_id, process_name, reason, created_by)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&name)
    .bind(reason)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| "ingest failed".to_string())?;
    tx.commit().await.map_err(|_| "ingest failed".to_string())?;
    Ok(id)
}

pub async fn whitelist_delete(pool: &PgPool, tenant_id: i64, id: i64) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|_| "ingest failed".to_string())?;
    sqlx::query("DELETE FROM ueba_process_whitelist WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|_| "ingest failed".to_string())?;
    tx.commit().await.map_err(|_| "ingest failed".to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn z_threshold_constant() {
        assert!((Z_THRESHOLD - 3.0).abs() < 1e-12);
    }

    #[test]
    fn min_samples_protects_learning_window() {
        assert!(MIN_BASELINE_SAMPLES >= 24);
    }

    #[test]
    fn baselines_use_the_global_bucket_not_hour_of_week() {
        assert_eq!(GLOBAL_BUCKET, 0);
    }

    #[test]
    fn learned_set_cap_leaves_room_for_k8s_churn() {
        assert!(LEARNED_SET_CAP >= 1500);
    }

    #[test]
    fn payload_defaults_do_not_require_new_fields() {
        let p: UebaIngestPayload = serde_json::from_value(serde_json::json!({
            "agent_id": "a",
            "client_id": 1,
            "hour_of_week": 3,
            "metrics": {"load_1m": 0.2}
        }))
        .unwrap();
        assert!(p.nonce.is_none());
        assert_eq!(p.hour_of_week, 3);
        let p2: UebaIngestPayload = serde_json::from_value(serde_json::json!({
            "agent_id": "a",
            "metrics": {"load_1m": 0.2}
        }))
        .unwrap();
        assert_eq!(p2.client_id, 0);
        assert_eq!(p2.hour_of_week, 0);
    }
}

// Silence unused MAX_NONCE_LEN in some builds.
#[allow(dead_code)]
const _NONCE: usize = MAX_NONCE_LEN;
