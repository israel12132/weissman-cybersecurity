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
//! Numeric z-score stays silent until the metric has ≥ 24 samples. Never-before-seen
//! ports and processes fire after the learning window **and** after a short onboarding
//! grace (15–30 minutes from `endpoint_agents.enrolled_at`, default 20). During grace,
//! items are **not** blindly written into `learned_set`: they must pass signature
//! deny-lists, live threat-intel, and the OS/name whitelist or a sovereign
//! SHA-256 allow-list (`ueba_onboarding`). Fleet majority never grants Learn.
//! Failures page the SOC as an onboarding hijack.

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
/// Default onboarding grace: 20 minutes. Clamp is 15–30 minutes.
const DEFAULT_ONBOARDING_GRACE_SECS: i64 = 20 * 60;
const MIN_ONBOARDING_GRACE_SECS: i64 = 15 * 60;
const MAX_ONBOARDING_GRACE_SECS: i64 = 30 * 60;
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
    if base.stddev < 1e-6 {
        return Ok(None); // constant baseline — divide-by-zero, can't compute z
    }
    let z = (observed - base.mean) / base.stddev;
    let threshold = adaptive_z_threshold(base.mean, base.stddev);
    if z.abs() < threshold {
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
    fn baselines_use_the_global_bucket_not_hour_of_week() {
        // Regression guard: baselines must be stored per (agent, metric) so training
        // can accumulate. Per-hour-of-week bucketing made the detector never fire.
        assert_eq!(GLOBAL_BUCKET, 0);
    }
}
