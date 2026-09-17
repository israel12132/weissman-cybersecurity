//! Extended UEBA behavioural models.
//!
//! The baseline detector (`ueba_detector`) scores each (agent, metric,
//! hour-of-week) with an adaptive z-score. This module adds the models a
//! world-class UEBA needs on top of that per-host baseline:
//!
//!   * [`peer`]   — cohort (peer-group) **robust** baselines using median +
//!                  MAD → modified z-score. Robust statistics resist the
//!                  masking/swamping that mean+stddev suffer when a host is
//!                  already anomalous during training, and let a brand-new host
//!                  inherit its cohort's baseline on day one.
//!   * [`risk`]   — a decayed, explainable per-entity risk score. Signals
//!                  (z-score anomalies, IOC sightings, new-process events) add
//!                  weight; the score decays exponentially so a host that goes
//!                  quiet cools off. Contributors are retained for "why".
//!
//! (C2-beacon periodicity and exfil volumetrics live in the already-wired
//! `ndr_beacon` / NDR-flow path, not here, to avoid duplicate detectors.)
//!
//! The pure math lives here and is unit-tested; persistence uses the runtime
//! `sqlx` API against the `ueba_entity_risk` / `ueba_peer_baselines` tables.

// ════════════════════════════════════════════════════════════════════════════
pub mod peer {
    //! Cohort robust baselining: median + MAD → modified z-score.

    /// Gaussian consistency constant: robust sigma ≈ 1.4826 · MAD.
    pub const MAD_TO_SIGMA: f64 = 1.4826;
    /// 0.6745 = Φ⁻¹(0.75); modified z = 0.6745·(x − median)/MAD.
    pub const MODIFIED_Z_CONST: f64 = 0.6745;

    /// Median of a slice (sorts a copy). Returns 0.0 for empty input.
    #[must_use]
    pub fn median(values: &[f64]) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
        if v.is_empty() {
            return 0.0;
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = v.len();
        if n % 2 == 1 {
            v[n / 2]
        } else {
            (v[n / 2 - 1] + v[n / 2]) / 2.0
        }
    }

    /// Median Absolute Deviation about the median.
    #[must_use]
    pub fn mad(values: &[f64], med: f64) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        let devs: Vec<f64> = values
            .iter()
            .filter(|x| x.is_finite())
            .map(|x| (x - med).abs())
            .collect();
        median(&devs)
    }

    /// Robust sigma from MAD.
    #[must_use]
    pub fn robust_sigma(mad_value: f64) -> f64 {
        MAD_TO_SIGMA * mad_value
    }

    /// Modified (robust) z-score of `x` given a cohort median + MAD. When MAD is
    /// zero (a perfectly flat cohort), falls back to a small epsilon so a true
    /// departure still scores, but identical values score 0.
    #[must_use]
    pub fn modified_z(x: f64, med: f64, mad_value: f64) -> f64 {
        let denom = if mad_value.abs() < 1e-9 {
            // Flat cohort: any deviation is notable, but avoid divide-by-zero.
            if (x - med).abs() < 1e-9 {
                return 0.0;
            }
            1e-6
        } else {
            mad_value
        };
        MODIFIED_Z_CONST * (x - med) / denom
    }

    /// The canonical cohort key for an OS string.
    #[must_use]
    pub fn cohort_key_for_os(os: &str) -> String {
        let o = os.trim().to_ascii_lowercase();
        if o.is_empty() {
            "fleet".to_string()
        } else {
            format!("os:{o}")
        }
    }

    /// Percentile (nearest-rank) of a slice, p in 0..=100.
    #[must_use]
    pub fn percentile(values: &[f64], p: f64) -> f64 {
        if values.is_empty() {
            return 0.0;
        }
        let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
        if v.is_empty() {
            return 0.0;
        }
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let rank = (p.clamp(0.0, 100.0) / 100.0 * (v.len() as f64 - 1.0)).round() as usize;
        v[rank.min(v.len() - 1)]
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn median_odd_even_and_empty() {
            assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
            assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), 2.5);
            assert_eq!(median(&[]), 0.0);
        }

        #[test]
        fn mad_is_robust_to_outlier() {
            // One wild outlier barely moves MAD, unlike stddev.
            let data = [10.0, 10.0, 10.0, 10.0, 1000.0];
            let med = median(&data);
            let m = mad(&data, med);
            assert_eq!(med, 10.0);
            assert_eq!(m, 0.0); // four identical values dominate
        }

        #[test]
        fn modified_z_flags_departure_and_ignores_identical() {
            let data = [10.0, 11.0, 9.0, 10.0, 10.0, 11.0, 9.0];
            let med = median(&data);
            let m = mad(&data, med);
            assert!(modified_z(10.0, med, m).abs() < 1.0);
            assert!(
                modified_z(50.0, med, m).abs() > 3.5,
                "big departure must score high"
            );
        }

        #[test]
        fn flat_cohort_zero_for_same_value() {
            assert_eq!(modified_z(5.0, 5.0, 0.0), 0.0);
            assert!(modified_z(9.0, 5.0, 0.0).abs() > 3.5);
        }

        #[test]
        fn cohort_key_normalizes() {
            assert_eq!(cohort_key_for_os("Linux"), "os:linux");
            assert_eq!(cohort_key_for_os(""), "fleet");
        }

        #[test]
        fn percentile_bounds() {
            let d = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
            assert_eq!(percentile(&d, 0.0), 1.0);
            assert_eq!(percentile(&d, 100.0), 10.0);
            assert!(percentile(&d, 95.0) >= 9.0);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════════
pub mod peer_store {
    //! Persistence + live scoring for cohort (peer-group) robust baselines.
    //!
    //! [`recompute_and_store`] rebuilds median/MAD/p95 baselines per
    //! (cohort, metric, hour-of-week) from recent endpoint samples. [`peer_outliers`]
    //! scores each host's latest sample against its cohort baseline with the
    //! modified z-score, surfacing hosts that deviate from their peers even when
    //! their *own* history looks normal (e.g. a freshly-compromised box that has
    //! always been compromised since enrollment).

    use super::peer;
    use serde_json::{json, Value};
    use sqlx::{PgPool, Row};
    use std::collections::HashMap;

    const LEARN_DAYS: i64 = 14;
    const SAMPLE_CAP: i64 = 20_000;
    const MIN_COHORT_N: usize = 8;
    const OUTLIER_Z: f64 = 3.5;

    /// Numeric metrics we baseline per cohort.
    pub const METRICS: &[&str] = &[
        "open_port_count",
        "process_count",
        "unique_users",
        "failed_logins",
        "conn_count",
        "conn_fail_count",
        "memory_used_pct",
        "thread_count",
    ];

    fn num(metrics: &Value, key: &str) -> Option<f64> {
        metrics.get(key).and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_u64().map(|x| x as f64))
                .or_else(|| v.as_i64().map(|x| x as f64))
        })
    }

    fn cohorts_for(metrics: &Value) -> Vec<String> {
        let os = metrics.get("os").and_then(Value::as_str).unwrap_or("");
        let mut c = vec!["fleet".to_string()];
        c.push(peer::cohort_key_for_os(os));
        c.dedup();
        c
    }

    /// Rebuild all cohort baselines for a tenant from the last 14 days of samples.
    /// Returns the number of baseline rows written.
    pub async fn recompute_and_store(pool: &PgPool, tenant_id: i64) -> Result<u64, String> {
        let rows = {
            let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
                .await
                .map_err(|e| format!("tenant tx: {e}"))?;
            let r = sqlx::query(
                r#"SELECT hour_of_week, metrics
                     FROM agent_metric_samples
                    WHERE sampled_at > now() - make_interval(days => $1)
                    ORDER BY sampled_at DESC
                    LIMIT $2"#,
            )
            .bind(LEARN_DAYS as i32)
            .bind(SAMPLE_CAP)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| format!("samples: {e}"))?;
            let _ = tx.commit().await;
            r
        };

        // (cohort, metric, hour) → values
        let mut buckets: HashMap<(String, String, i16), Vec<f64>> = HashMap::new();
        for row in &rows {
            let hour: i16 = row.try_get("hour_of_week").unwrap_or(0);
            let metrics: Value = row.try_get("metrics").unwrap_or(Value::Null);
            let cohorts = cohorts_for(&metrics);
            for m in METRICS {
                if let Some(v) = num(&metrics, m) {
                    for c in &cohorts {
                        buckets
                            .entry((c.clone(), (*m).to_string(), hour))
                            .or_default()
                            .push(v);
                    }
                }
            }
        }

        let mut written = 0u64;
        let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
            .await
            .map_err(|e| format!("tenant tx2: {e}"))?;
        for ((cohort, metric, hour), values) in &buckets {
            if values.len() < MIN_COHORT_N {
                continue;
            }
            let med = peer::median(values);
            let mad = peer::mad(values, med);
            let p95 = peer::percentile(values, 95.0);
            let n = values.len() as f64;
            let mean = values.iter().sum::<f64>() / n;
            let var = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
            let stddev = var.sqrt();
            sqlx::query(
                r#"INSERT INTO ueba_peer_baselines
                     (tenant_id, cohort, metric_name, hour_of_week, n, median, mad, p95, mean, stddev, last_updated_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now())
                   ON CONFLICT (tenant_id, cohort, metric_name, hour_of_week) DO UPDATE SET
                     n = EXCLUDED.n, median = EXCLUDED.median, mad = EXCLUDED.mad,
                     p95 = EXCLUDED.p95, mean = EXCLUDED.mean, stddev = EXCLUDED.stddev,
                     last_updated_at = now()"#,
            )
            .bind(tenant_id)
            .bind(cohort)
            .bind(metric)
            .bind(*hour)
            .bind(values.len() as i32)
            .bind(med)
            .bind(mad)
            .bind(p95)
            .bind(mean)
            .bind(stddev)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("upsert baseline: {e}"))?;
            written += 1;
        }
        tx.commit().await.map_err(|e| format!("commit: {e}"))?;
        Ok(written)
    }

    /// Score each host's latest sample against its OS-cohort baseline. Returns
    /// the deviating (metric, host) pairs with |modified z| over threshold.
    pub async fn peer_outliers(
        pool: &PgPool,
        tenant_id: i64,
        limit: i64,
    ) -> Result<Vec<Value>, String> {
        let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
            .await
            .map_err(|e| format!("tenant tx: {e}"))?;

        // Load baselines into a lookup.
        let brows = sqlx::query(
            r#"SELECT cohort, metric_name, hour_of_week, n, median, mad
                 FROM ueba_peer_baselines"#,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("baselines: {e}"))?;
        let mut base: HashMap<(String, String, i16), (i32, f64, f64)> = HashMap::new();
        for r in &brows {
            let k = (
                r.try_get::<String, _>("cohort").unwrap_or_default(),
                r.try_get::<String, _>("metric_name").unwrap_or_default(),
                r.try_get::<i16, _>("hour_of_week").unwrap_or(0),
            );
            base.insert(
                k,
                (
                    r.try_get::<i32, _>("n").unwrap_or(0),
                    r.try_get::<f64, _>("median").unwrap_or(0.0),
                    r.try_get::<f64, _>("mad").unwrap_or(0.0),
                ),
            );
        }

        // Latest sample per agent (last 2 days).
        let srows = sqlx::query(
            r#"SELECT DISTINCT ON (agent_id) agent_id, client_id, hour_of_week, metrics, sampled_at
                 FROM agent_metric_samples
                WHERE sampled_at > now() - interval '2 days'
                ORDER BY agent_id, sampled_at DESC"#,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("samples: {e}"))?;
        let _ = tx.commit().await;

        let mut out = Vec::new();
        for r in &srows {
            let agent_id: String = r.try_get("agent_id").unwrap_or_default();
            let client_id: Option<i64> = r.try_get("client_id").ok();
            let hour: i16 = r.try_get("hour_of_week").unwrap_or(0);
            let metrics: Value = r.try_get("metrics").unwrap_or(Value::Null);
            let os = metrics.get("os").and_then(Value::as_str).unwrap_or("");
            let cohort = peer::cohort_key_for_os(os);
            for m in METRICS {
                let Some(observed) = num(&metrics, m) else {
                    continue;
                };
                let Some((n, med, mad)) = base.get(&(cohort.clone(), (*m).to_string(), hour))
                else {
                    continue;
                };
                if (*n as usize) < MIN_COHORT_N {
                    continue;
                }
                let z = peer::modified_z(observed, *med, *mad);
                if z.abs() >= OUTLIER_Z {
                    out.push(json!({
                        "agent_id": agent_id,
                        "client_id": client_id,
                        "metric": m,
                        "observed": observed,
                        "cohort": cohort,
                        "cohort_median": med,
                        "cohort_mad": mad,
                        "modified_z": (z * 100.0).round() / 100.0,
                        "severity": if z.abs() >= 6.0 { "high" } else { "medium" },
                        "sampled_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("sampled_at").ok().map(|d| d.to_rfc3339()),
                    }));
                }
            }
        }
        out.sort_by(|a, b| {
            let za = a
                .get("modified_z")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                .abs();
            let zb = b
                .get("modified_z")
                .and_then(Value::as_f64)
                .unwrap_or(0.0)
                .abs();
            zb.partial_cmp(&za).unwrap_or(std::cmp::Ordering::Equal)
        });
        out.truncate(limit.clamp(1, 500) as usize);
        Ok(out)
    }
}

// ════════════════════════════════════════════════════════════════════════════
pub mod risk {
    //! Decayed, explainable per-entity risk scoring.

    use serde_json::{json, Value};
    use sqlx::{PgPool, Row};

    /// Risk half-life in hours — a quiet entity's score halves each day.
    pub const HALF_LIFE_HOURS: f64 = 24.0;
    /// Keep at most this many contributing signals for explainability.
    pub const MAX_CONTRIBUTORS: usize = 24;

    /// Exponentially decay a prior score over `dt_hours`.
    #[must_use]
    pub fn decay_score(prev: f64, dt_hours: f64) -> f64 {
        if dt_hours <= 0.0 {
            return prev;
        }
        prev * 2f64.powf(-dt_hours / HALF_LIFE_HOURS)
    }

    /// Map an accumulated score to a severity band.
    #[must_use]
    pub fn severity_for_score(score: f64) -> &'static str {
        if score >= 90.0 {
            "critical"
        } else if score >= 60.0 {
            "high"
        } else if score >= 30.0 {
            "medium"
        } else if score >= 10.0 {
            "low"
        } else {
            "info"
        }
    }

    /// Weight contributed by a z-score anomaly of given severity.
    #[must_use]
    pub fn anomaly_weight(z_abs: f64, severity: &str) -> f64 {
        let base = match severity.trim().to_ascii_lowercase().as_str() {
            "critical" => 40.0,
            "high" => 25.0,
            "medium" => 12.0,
            "low" => 5.0,
            _ => 2.0,
        };
        // Scale a little by how far past the threshold we are.
        base + (z_abs.max(0.0) - 3.0).clamp(0.0, 6.0) * 2.0
    }

    /// Weight contributed by an IOC sighting of given severity (stronger than a
    /// statistical anomaly — it's a confirmed known-bad).
    #[must_use]
    pub fn ioc_sighting_weight(severity: &str) -> f64 {
        match severity.trim().to_ascii_lowercase().as_str() {
            "critical" => 60.0,
            "high" => 45.0,
            "medium" => 25.0,
            "low" => 12.0,
            _ => 8.0,
        }
    }

    /// Record a risk event for an entity: decays the prior score to now, adds
    /// `weight`, updates peak + contributors, and upserts. Returns the new score.
    pub async fn record_risk_event(
        pool: &PgPool,
        tenant_id: i64,
        entity_type: &str,
        entity_id: &str,
        client_id: Option<i64>,
        weight: f64,
        contributor: &str,
    ) -> Result<f64, String> {
        if weight <= 0.0 {
            return Ok(0.0);
        }
        let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
            .await
            .map_err(|e| format!("tenant tx: {e}"))?;

        let existing = sqlx::query(
            r#"SELECT risk_score, peak_score, event_count, contributors,
                      EXTRACT(EPOCH FROM (now() - last_decay_at))::double precision AS age_secs
                 FROM ueba_entity_risk
                WHERE entity_type = $1 AND entity_id = $2"#,
        )
        .bind(entity_type)
        .bind(entity_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("select: {e}"))?;

        let (decayed, peak, count, mut contributors) = match existing {
            Some(r) => {
                let prev: f64 = r.try_get("risk_score").unwrap_or(0.0);
                let peak: f64 = r.try_get("peak_score").unwrap_or(0.0);
                let count: i32 = r.try_get("event_count").unwrap_or(0);
                let age_secs: f64 = r.try_get("age_secs").unwrap_or(0.0);
                let contributors: Value = r.try_get("contributors").unwrap_or_else(|_| json!([]));
                (
                    decay_score(prev, age_secs / 3600.0),
                    peak,
                    count,
                    contributors,
                )
            }
            None => (0.0, 0.0, 0, json!([])),
        };

        let new_score = (decayed + weight).min(1000.0);
        let new_peak = peak.max(new_score);
        let severity = severity_for_score(new_score);

        // Prepend the new contributor; keep the most recent MAX_CONTRIBUTORS.
        let entry = json!({
            "signal": contributor,
            "weight": (weight * 10.0).round() / 10.0,
            "at": chrono::Utc::now().to_rfc3339(),
        });
        if let Some(arr) = contributors.as_array_mut() {
            arr.insert(0, entry);
            arr.truncate(MAX_CONTRIBUTORS);
        } else {
            contributors = json!([entry]);
        }

        sqlx::query(
            r#"INSERT INTO ueba_entity_risk
                 (tenant_id, entity_type, entity_id, client_id, risk_score, peak_score,
                  severity, event_count, contributors, last_event_at, last_decay_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now(), now(), now())
               ON CONFLICT (tenant_id, entity_type, entity_id) DO UPDATE SET
                   client_id     = COALESCE(EXCLUDED.client_id, ueba_entity_risk.client_id),
                   risk_score    = EXCLUDED.risk_score,
                   peak_score    = EXCLUDED.peak_score,
                   severity      = EXCLUDED.severity,
                   event_count   = ueba_entity_risk.event_count + 1,
                   contributors  = EXCLUDED.contributors,
                   last_event_at = now(),
                   last_decay_at = now(),
                   updated_at    = now()"#,
        )
        .bind(tenant_id)
        .bind(entity_type)
        .bind(entity_id)
        .bind(client_id)
        .bind(new_score)
        .bind(new_peak)
        .bind(severity)
        .bind(count + 1)
        .bind(&contributors)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("upsert: {e}"))?;

        tx.commit().await.map_err(|e| format!("commit: {e}"))?;
        Ok(new_score)
    }

    /// Top entities by current (decay-adjusted) risk for the API.
    pub async fn top_entities(
        pool: &PgPool,
        tenant_id: i64,
        limit: i64,
    ) -> Result<Vec<Value>, String> {
        let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
            .await
            .map_err(|e| format!("tenant tx: {e}"))?;
        let rows = sqlx::query(
            r#"SELECT entity_type, entity_id, client_id, risk_score, peak_score, severity,
                      event_count, contributors, last_event_at,
                      EXTRACT(EPOCH FROM (now() - last_decay_at))::double precision AS age_secs
                 FROM ueba_entity_risk
                ORDER BY risk_score DESC
                LIMIT $1"#,
        )
        .bind(limit.clamp(1, 500))
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("query: {e}"))?;
        let _ = tx.commit().await;

        Ok(rows
            .into_iter()
            .map(|r| {
                let stored: f64 = r.try_get("risk_score").unwrap_or(0.0);
                let age_secs: f64 = r.try_get("age_secs").unwrap_or(0.0);
                let live = decay_score(stored, age_secs / 3600.0);
                json!({
                    "entity_type": r.try_get::<String, _>("entity_type").unwrap_or_default(),
                    "entity_id":   r.try_get::<String, _>("entity_id").unwrap_or_default(),
                    "client_id":   r.try_get::<i64, _>("client_id").ok(),
                    "risk_score":  (live.round() as i64),
                    "peak_score":  (r.try_get::<f64, _>("peak_score").unwrap_or(0.0).round() as i64),
                    "severity":    severity_for_score(live),
                    "event_count": r.try_get::<i32, _>("event_count").unwrap_or(0),
                    "contributors": r.try_get::<Value, _>("contributors").unwrap_or_else(|_| json!([])),
                    "last_event_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("last_event_at").ok().map(|d| d.to_rfc3339()),
                })
            })
            .collect())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn decay_halves_each_half_life() {
            let d = decay_score(100.0, HALF_LIFE_HOURS);
            assert!((d - 50.0).abs() < 1e-6);
            assert_eq!(decay_score(100.0, 0.0), 100.0);
        }

        #[test]
        fn severity_bands_are_monotonic() {
            assert_eq!(severity_for_score(5.0), "info");
            assert_eq!(severity_for_score(15.0), "low");
            assert_eq!(severity_for_score(45.0), "medium");
            assert_eq!(severity_for_score(70.0), "high");
            assert_eq!(severity_for_score(95.0), "critical");
        }

        #[test]
        fn ioc_weight_exceeds_anomaly_weight_at_same_severity() {
            assert!(ioc_sighting_weight("high") > anomaly_weight(3.0, "high"));
        }

        #[test]
        fn anomaly_weight_scales_with_z() {
            assert!(anomaly_weight(9.0, "high") > anomaly_weight(3.0, "high"));
        }
    }
}
