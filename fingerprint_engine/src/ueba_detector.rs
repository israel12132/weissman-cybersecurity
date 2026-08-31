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
//! Hybrid baseline (week-1 → week-2):
//!   * Until 168 global samples (`hour_of_week = -1`) the detector compares
//!     against the global bucket.
//!   * From the second week it prefers the specific `hour_of_week` bucket
//!     (via `elite_hardening::ueba_stats`, hour n ≥ 3), falling back to global
//!     when that hour is still thin.
//! The detector NEVER fires while the chosen baseline is still learning
//! (`n < 24`). Hour buckets are updated incrementally (Welford) so they can
//! actually accumulate across weeks; the global row is recomputed from the
//! rolling 7-day sample window. Scoring uses cloud-safe stddev.
//!
//! Never-before-seen ports and processes fire after the learning window **and**
//! after a short onboarding grace (15–30 minutes from `endpoint_agents.enrolled_at`,
//! default 20). During grace, items are **not** blindly written into `learned_set`:
//! they must pass signature deny-lists, live threat-intel, and the OS/name
//! whitelist or a sovereign SHA-256 allow-list (`ueba_onboarding`). Fleet majority
//! never grants Learn. Failures page the SOC as an onboarding hijack.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

const LEARN_WINDOW_DAYS: i64 = 7;
const Z_THRESHOLD: f64 = 3.0;

/// Adaptive z-score floor: quiet hosts (low CV) use a slightly lower bar;
/// noisy hosts require a higher deviation before we page.
#[must_use]
pub fn adaptive_z_threshold(mean: f64, stddev: f64) -> f64 {
    let cv = if mean.abs() > 1e-9 {
        (stddev / mean.abs()).abs()
    } else {
        stddev.abs()
    };
    (Z_THRESHOLD + (cv - 0.15).clamp(-0.5, 2.0)).clamp(2.5, 5.0)
}

/// Redact usernames, emails, and home paths from UEBA metric JSON before persist.
#[must_use]
pub fn scrub_ueba_metrics(metrics: &Value) -> Value {
    match metrics {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                let key_l = k.to_ascii_lowercase();
                if key_l.contains("user")
                    || key_l.contains("email")
                    || key_l.contains("home")
                    || key_l == "path"
                    || key_l.ends_with("_path")
                {
                    out.insert(k.clone(), Value::String("[redacted]".into()));
                } else {
                    out.insert(k.clone(), scrub_ueba_metrics(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(scrub_ueba_metrics).collect()),
        Value::String(s) => Value::String(scrub_pii_string(s)),
        other => other.clone(),
    }
}

fn scrub_pii_string(s: &str) -> String {
    let mut out = s.to_string();
    if out.contains('@') && out.contains('.') {
        out = "[redacted-email]".into();
    }
    if let Some(rest) = out.strip_prefix("/home/") {
        let user = rest.split('/').next().unwrap_or("");
        if !user.is_empty() {
            out = out.replacen(&format!("/home/{user}"), "/home/[user]", 1);
        }
    }
    if let Some(rest) = out.strip_prefix("/Users/") {
        let user = rest.split('/').next().unwrap_or("");
        if !user.is_empty() {
            out = out.replacen(&format!("/Users/{user}"), "/Users/[user]", 1);
        }
    }
    out
}
const MIN_BASELINE_SAMPLES: i32 = 24;
/// Switch from global-only compare to hour-of-week once a full week of hourly
/// samples has landed (~168). Below this we stay on the global bucket.
const HYBRID_SWITCH_SAMPLES: i32 = 168;
/// Canonical global baseline key. Raw samples still store the real hour (0..=167).
/// Stored as -1 so Sunday-midnight (hour 0) cannot collide with the global row.
const GLOBAL_BUCKET: i16 = -1;
/// Default onboarding grace: 20 minutes. Clamp is 15–30 minutes.
const DEFAULT_ONBOARDING_GRACE_SECS: i64 = 20 * 60;
const MIN_ONBOARDING_GRACE_SECS: i64 = 15 * 60;
const MAX_ONBOARDING_GRACE_SECS: i64 = 30 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaIngestPayload {
    pub agent_id: String,
    pub client_id: i64,
    pub hour_of_week: i16,
    pub metrics: Value,
}

/// Seconds after first enrollment during which new ports/processes are learned
/// silently. Operator override `WEISSMAN_UEBA_ONBOARDING_GRACE_SECS` is clamped
/// to 15–30 minutes so a typo cannot disable the storm shield or extend it forever.
#[must_use]
pub fn onboarding_grace_secs() -> i64 {
    std::env::var("WEISSMAN_UEBA_ONBOARDING_GRACE_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(DEFAULT_ONBOARDING_GRACE_SECS)
        .clamp(MIN_ONBOARDING_GRACE_SECS, MAX_ONBOARDING_GRACE_SECS)
}

#[must_use]
pub fn in_onboarding_grace(enrolled_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now.signed_duration_since(enrolled_at).num_seconds() < onboarding_grace_secs()
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
    let scrubbed = scrub_ueba_metrics(&p.metrics);
    let raw_size = serde_json::to_string(&scrubbed)
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
    .bind(&scrubbed)
    .bind(raw_size)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("insert sample: {e}"))?;

    let enrolled_at: Option<DateTime<Utc>> = if let Ok(uuid) = p.agent_id.parse::<uuid::Uuid>() {
        sqlx::query_scalar(
            "SELECT enrolled_at FROM endpoint_agents
              WHERE tenant_id = $1 AND agent_uuid = $2",
        )
        .bind(tenant_id)
        .bind(uuid)
        .fetch_optional(&mut *tx)
        .await
        .ok()
        .flatten()
    } else {
        None
    };
    let onboarding_grace = enrolled_at
        .map(|ts| in_onboarding_grace(ts, Utc::now()))
        .unwrap_or(false);

    // Re-compute baselines for every numeric metric we saw in this sample.
    let mut summary = UebaIngestSummary::default();
    if let Value::Object(obj) = &scrubbed {
        // Numeric metrics → baseline + z-score check.
        for (k, v) in obj {
            if let Some(num) = v.as_f64() {
                let global = recompute_global_baseline(&mut tx, tenant_id, &p.agent_id, k).await?;
                let _hour = upsert_hour_baseline(
                    &mut tx,
                    tenant_id,
                    &p.agent_id,
                    k,
                    hour_bucket(p.hour_of_week),
                    num,
                )
                .await?;
                summary.baselines_updated += 1;
                if let Some(anom) =
                    check_anomaly(&mut tx, tenant_id, &p, sample_id, k, num, &global).await?
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
                onboarding_grace,
                None,
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
            let proc_hashes: HashMap<String, String> = obj
                .get("top_process_hashes")
                .and_then(Value::as_object)
                .map(|o| {
                    o.iter()
                        .filter_map(|(k, v)| {
                            v.as_str()
                                .map(|h| h.trim().to_ascii_lowercase())
                                .filter(|h| h.len() == 64)
                                .map(|h| (k.clone(), h))
                        })
                        .collect()
                })
                .unwrap_or_default();
            if let Some(a) = check_new_categorical(
                &mut tx,
                tenant_id,
                &p,
                sample_id,
                "top_processes",
                &observed,
                "Unfamiliar process observed running on host",
                onboarding_grace,
                Some(&proc_hashes),
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
                false,
                None,
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

#[derive(Debug, Clone)]
struct BaselineUpdate {
    n: i32,
    mean: f64,
    stddev: f64,
}

fn hour_bucket(hour_of_week: i16) -> i16 {
    hour_of_week.clamp(0, 167)
}

/// Welford one-step update so hour-of-week buckets accumulate across weeks.
fn welford_add(prev: Option<(i32, f64, f64)>, x: f64) -> (i32, f64, f64) {
    let (n0, mean0, std0) = prev.unwrap_or((0, 0.0, 0.0));
    let n = n0 + 1;
    let delta = x - mean0;
    let mean = mean0 + delta / (n as f64);
    let m2 = if n0 > 1 {
        std0 * std0 * (n0 as f64 - 1.0)
    } else {
        0.0
    } + delta * (x - mean);
    let stddev = if n > 1 {
        (m2 / (n as f64 - 1.0)).max(0.0).sqrt()
    } else {
        0.0
    };
    (n, mean, stddev)
}

/// Until 168 global samples use the global bucket; afterwards prefer the
/// hour-of-week row when it has trained (≥24), else fall back to global.
fn pick_compare_baseline(
    global: &BaselineUpdate,
    hour: Option<&BaselineUpdate>,
) -> (BaselineUpdate, &'static str) {
    if global.n < HYBRID_SWITCH_SAMPLES {
        return (global.clone(), "global");
    }
    if let Some(h) = hour {
        if h.n >= MIN_BASELINE_SAMPLES {
            return (h.clone(), "hour_of_week");
        }
    }
    (global.clone(), "global_fallback")
}

/// Recompute the rolling GLOBAL baseline (`hour_of_week = -1`) from the last
/// 7 days of samples across all hours.
async fn recompute_global_baseline(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
) -> Result<BaselineUpdate, String> {
    // Global lane: last 7 days across every hour. Hour-specific Welford rows
    // are updated separately so week-2+ can compare against hour_of_week.
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

async fn upsert_hour_baseline(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
    hour: i16,
    observed: f64,
) -> Result<BaselineUpdate, String> {
    let prev: Option<(i32, f64, f64)> = sqlx::query_as(
        r#"SELECT n, mean, stddev
             FROM agent_metric_baselines
            WHERE tenant_id = $1 AND agent_id = $2
              AND metric_name = $3 AND hour_of_week = $4"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(metric)
    .bind(hour)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("read hour baseline: {e}"))?;

    let (n, mean, stddev) = welford_add(prev, observed);

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
    .bind(n)
    .bind(mean)
    .bind(stddev)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("upsert hour baseline: {e}"))?;

    Ok(BaselineUpdate { n, mean, stddev })
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
        return Ok(None); // still learning (Phase A)
    }
    let global = crate::elite_hardening::ueba_stats::BaselineStats {
        n: base.n,
        mean: base.mean,
        stddev: base.stddev,
        hour_of_week: crate::elite_hardening::ueba_stats::GLOBAL_HOUR_SENTINEL,
    };
    let hour_stats = if matches!(
        crate::elite_hardening::ueba_stats::hybrid_phase(base.n),
        crate::elite_hardening::ueba_stats::HybridPhase::HourThenGlobal
    ) {
        fetch_hour_baseline(tx, tenant_id, &p.agent_id, metric, p.hour_of_week).await
    } else {
        None
    };
    let Some(scoring) =
        crate::elite_hardening::ueba_stats::pick_scoring_baseline(global, hour_stats)
    else {
        return Ok(None);
    };
    let stddev =
        crate::elite_hardening::ueba_stats::cloud_safe_stddev(scoring.mean, scoring.stddev);
    let z = (observed - scoring.mean) / stddev;
    if z.abs() <= Z_THRESHOLD {
        return Ok(None);
    }
    let severity = crate::elite_hardening::ueba_stats::severity_for_z(z);
    let direction = if z > 0.0 { "above" } else { "below" };
    let bucket = if scoring.hour_of_week < 0 {
        "global".to_string()
    } else {
        format!("hour_of_week={}", scoring.hour_of_week)
    };
    let detail = format!(
        "Metric `{}` observed {:.2}, baseline {:.2} ± {:.2} (z={:+.2}, {} 3σ, {bucket}).",
        metric, observed, scoring.mean, stddev, z, direction
    );
    let rec = AnomalyRecord {
        metric: metric.to_string(),
        observed,
        baseline_mean: scoring.mean,
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
    .bind(scoring.mean)
    .bind(stddev)
    .bind(z)
    .bind(severity)
    .bind(&detail)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("insert anomaly: {e}"))?;
    Ok(Some(rec))
}

async fn fetch_hour_baseline(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
    hour_of_week: i16,
) -> Option<crate::elite_hardening::ueba_stats::BaselineStats> {
    let row: Option<(i64, Option<f64>, Option<f64>)> = sqlx::query_as(
        r#"SELECT n, mean, stddev
             FROM agent_metric_hour_baselines
            WHERE tenant_id = $1 AND agent_id = $2
              AND metric_name = $3 AND hour_of_week = $4"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(metric)
    .bind(hour_of_week)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten();
    let (n, mean, stddev) = row?;
    Some(crate::elite_hardening::ueba_stats::BaselineStats {
        n: n as i32,
        mean: mean.unwrap_or(0.0),
        stddev: stddev.unwrap_or(0.0),
        hour_of_week,
    })
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
    onboarding_grace: bool,
    binary_hashes: Option<&HashMap<String, String>>,
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

    let mut hijack: Vec<String> = Vec::new();
    if onboarding_grace && (metric == "open_ports" || metric == "top_processes") {
        for item in &new_items {
            let hash = crate::ueba_onboarding::item_binary_hash(item, binary_hashes);
            let sig = crate::ueba_onboarding::signature_denies(metric, item);
            let ti =
                crate::ueba_onboarding::threat_intel_hit(tx, tenant_id, metric, item, hash).await;
            let wl = crate::ueba_onboarding::on_global_whitelist(metric, item);
            let sov = crate::ueba_onboarding::on_sovereign_binary_allowlist_tx(tx, hash).await;
            match crate::ueba_onboarding::decide_onboarding_item(metric, item, sig, ti, wl, sov) {
                crate::ueba_onboarding::OnboardingDecision::Learn => {
                    learned.insert(item.clone());
                }
                crate::ueba_onboarding::OnboardingDecision::RejectAndAlert => {
                    hijack.push(item.clone());
                }
            }
        }
        // Existing learned items stay. Rejected hijack items never enter the set.
    } else {
        for x in observed {
            learned.insert(x.clone());
        }
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

    if new_items.is_empty() && hijack.is_empty() {
        return Ok(None);
    }
    if onboarding_grace && (metric == "open_ports" || metric == "top_processes") {
        if hijack.is_empty() {
            return Ok(None);
        }
        let detail = format!(
            "Onboarding hijack: process/port failed signature, threat-intel, OS whitelist, or sovereign SHA-256 allow-list: {}",
            hijack.join(", ")
        );
        let rec = AnomalyRecord {
            metric: metric.to_string(),
            observed: hijack.len() as f64,
            baseline_mean: 0.0,
            baseline_stddev: 0.0,
            z_score: hijack.len() as f64,
            severity: "high".to_string(),
            detail: detail.clone(),
        };
        sqlx::query(
            r#"INSERT INTO agent_anomalies
                     (tenant_id, agent_id, client_id, sample_id, metric_name,
                      observed, baseline_mean, baseline_stddev, z_score,
                      severity, detail, detected_at)
               VALUES ($1, $2, $3, $4, $5, $6, 0, 0, $6, $7, $8, now())"#,
        )
        .bind(tenant_id)
        .bind(&p.agent_id)
        .bind(p.client_id)
        .bind(sample_id)
        .bind(metric)
        .bind(hijack.len() as f64)
        .bind("high")
        .bind(&detail)
        .execute(&mut **tx)
        .await
        .map_err(|e| format!("insert onboarding hijack: {e}"))?;
        return Ok(Some(rec));
    }
    let learning = n_obs < MIN_BASELINE_SAMPLES;
    let extreme_categorical = metric == "open_ports" || metric == "top_processes";
    if learning && !extreme_categorical {
        return Ok(None);
    }
    let severity = if learning { "high" } else { "medium" };
    let detail = if learning {
        format!(
            "{} (fired during learning — never-before-seen): {}",
            title,
            new_items.join(", ")
        )
    } else {
        format!("{}: {}", title, new_items.join(", "))
    };
    let rec = AnomalyRecord {
        metric: metric.to_string(),
        observed: new_items.len() as f64,
        baseline_mean: 0.0,
        baseline_stddev: 0.0,
        z_score: new_items.len() as f64,
        severity: severity.to_string(),
        detail: detail.clone(),
    };
    sqlx::query(
        r#"INSERT INTO agent_anomalies
                 (tenant_id, agent_id, client_id, sample_id, metric_name,
                  observed, baseline_mean, baseline_stddev, z_score,
                  severity, detail, detected_at)
           VALUES ($1, $2, $3, $4, $5, $6, 0, 0, $6, $7, $8, now())"#,
    )
    .bind(tenant_id)
    .bind(&p.agent_id)
    .bind(p.client_id)
    .bind(sample_id)
    .bind(metric)
    .bind(rec.z_score)
    .bind(severity)
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
    use chrono::Utc;
    use serde_json::json;
    #[test]
    fn z_threshold_constant() {
        assert!(Z_THRESHOLD == 3.0);
    }
    #[test]
    fn adaptive_threshold_rises_with_noise() {
        let quiet = adaptive_z_threshold(100.0, 1.0);
        let noisy = adaptive_z_threshold(100.0, 80.0);
        assert!(quiet < noisy);
        assert!(quiet >= 2.5 && noisy <= 5.0);
    }
    #[test]
    fn scrub_redacts_username_and_email() {
        let v = json!({
            "username": "ada",
            "open_ports": [22, 443],
            "cmd": "/home/ada/.ssh/id_rsa"
        });
        let s = scrub_ueba_metrics(&v);
        assert_eq!(s["username"], "[redacted]");
        assert_eq!(s["open_ports"][0], 22);
        assert!(s["cmd"].as_str().unwrap().contains("/home/[user]"));
    }
    #[test]
    fn min_samples_protects_numeric_learning_window() {
        // Numeric z-score stays silent until trained. During onboarding grace,
        // ports/processes must pass fleet whitelist + TI + signatures before they
        // enter learned_set; hijacks still page.
        assert!(MIN_BASELINE_SAMPLES >= 24);
    }

    #[test]
    fn onboarding_grace_covers_cold_start_window() {
        let enrolled = Utc::now() - chrono::Duration::minutes(5);
        assert!(in_onboarding_grace(enrolled, Utc::now()));
        let aged = Utc::now() - chrono::Duration::minutes(45);
        assert!(!in_onboarding_grace(aged, Utc::now()));
        let secs = onboarding_grace_secs();
        assert!(secs >= 15 * 60 && secs <= 30 * 60);
    }

    #[test]
    fn onboarding_grace_secs_clamps() {
        let parsed = |raw: Option<&str>| {
            raw.and_then(|s| s.trim().parse::<i64>().ok())
                .unwrap_or(DEFAULT_ONBOARDING_GRACE_SECS)
                .clamp(MIN_ONBOARDING_GRACE_SECS, MAX_ONBOARDING_GRACE_SECS)
        };
        assert_eq!(parsed(Some("60")), MIN_ONBOARDING_GRACE_SECS);
        assert_eq!(parsed(Some("99999")), MAX_ONBOARDING_GRACE_SECS);
        assert_eq!(parsed(Some("1200")), 1200);
        assert_eq!(parsed(None), DEFAULT_ONBOARDING_GRACE_SECS);
    }
    #[test]
    fn global_bucket_is_minus_one() {
        assert_eq!(GLOBAL_BUCKET, -1);
        assert_eq!(HYBRID_SWITCH_SAMPLES, 168);
        assert_eq!(hour_bucket(-5), 0);
        assert_eq!(hour_bucket(200), 167);
    }

    #[test]
    fn hybrid_uses_global_until_168_then_hour_with_fallback() {
        let global_early = BaselineUpdate {
            n: 40,
            mean: 10.0,
            stddev: 1.0,
        };
        let hour_thin = BaselineUpdate {
            n: 3,
            mean: 99.0,
            stddev: 2.0,
        };
        let (picked, lane) = pick_compare_baseline(&global_early, Some(&hour_thin));
        assert_eq!(lane, "global");
        assert_eq!(picked.mean, 10.0);

        let global_ready = BaselineUpdate {
            n: 168,
            mean: 10.0,
            stddev: 1.0,
        };
        let (picked, lane) = pick_compare_baseline(&global_ready, Some(&hour_thin));
        assert_eq!(lane, "global_fallback");
        assert_eq!(picked.mean, 10.0);

        let hour_ready = BaselineUpdate {
            n: 24,
            mean: 42.0,
            stddev: 2.0,
        };
        let (picked, lane) = pick_compare_baseline(&global_ready, Some(&hour_ready));
        assert_eq!(lane, "hour_of_week");
        assert_eq!(picked.mean, 42.0);
    }

    #[test]
    fn welford_tracks_running_mean() {
        let mut state = None;
        for x in [1.0, 3.0, 5.0] {
            state = Some(welford_add(state, x));
        }
        let (n, mean, _) = state.unwrap();
        assert_eq!(n, 3);
        assert!((mean - 3.0).abs() < 1e-9);
    }

    #[test]
    fn hybrid_scoring_kicks_in_after_a_full_week() {
        assert_eq!(
            crate::elite_hardening::ueba_stats::hybrid_phase(MIN_BASELINE_SAMPLES),
            crate::elite_hardening::ueba_stats::HybridPhase::GlobalOnly
        );
        assert_eq!(
            crate::elite_hardening::ueba_stats::hybrid_phase(168),
            crate::elite_hardening::ueba_stats::HybridPhase::HourThenGlobal
        );
        assert_eq!(
            crate::elite_hardening::ueba_stats::GLOBAL_HOUR_SENTINEL,
            GLOBAL_BUCKET
        );
    }
}
