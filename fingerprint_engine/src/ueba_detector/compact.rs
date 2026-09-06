//! Compact hour-of-week snapshot pushed to agents on Welcome / UebaBaseline.
//!
//! Rolling EWMV state lives in `agent_metric_baselines_global` so `hour_of_week`
//! stays a physical 0..=167 clock (Monday 00:00 must not collide with a sentinel).
//! Hourly overlay rows stay in `agent_metric_baselines` when they have enough
//! samples; otherwise the agent falls back to the rolling 7-day global row.

use chrono::Utc;
use serde_json::Value;
use sqlx::PgPool;

use super::categorical::LearnedSet;
use super::time::hour_of_week_utc;
use super::{UebaCompactMetric, UebaCompactSnapshot, GLOBAL_BUCKET};

/// Agent-side upload gate. Server still fires anomalies at `|z| > 3`.
pub const EDGE_Z_UPLOAD: f64 = 2.0;
const EDGE_MIN_N: i32 = 7;
/// Hour-of-week row is used only when it has at least this many samples.
const EDGE_HOUR_MIN_N: i32 = 3;

const COMPACT_METRICS: &[&str] = &[
    "open_port_count",
    "process_count",
    "unique_users",
    "load_1m",
    "memory_used_pct",
    "failed_logins",
];

#[derive(Debug, Clone)]
pub struct BaselineRow {
    pub metric_name: String,
    pub hour_of_week: i16,
    pub n: i32,
    pub mean: f64,
    pub stddev: f64,
    pub learned_set: Value,
    /// Rolling 7-day (agent, metric) row — never hour 0.
    pub is_global: bool,
}

fn learned_process_names(v: &Value) -> Vec<String> {
    let mut names: Vec<String> = LearnedSet::from_json(v).seen.keys().cloned().collect();
    names.sort();
    names
}

/// Build the compact snapshot the agent caches locally. Prefer the current
/// hour-of-week row when it has ≥ `EDGE_HOUR_MIN_N` samples, else the rolling
/// 7-day global row.
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
        .map(|r| learned_process_names(&r.learned_set))
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
    let hour = hour_of_week_utc(Utc::now());
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
    // Live EWMV state: dedicated global table (72000) plus any leftover
    // GLOBAL_BUCKET=-1 rows if a deployment still holds them.
    let global = sqlx::query_as::<_, (String, i32, f64, f64, Value)>(
        r#"SELECT metric_name, n, mean, stddev, learned_set
             FROM agent_metric_baselines_global
            WHERE tenant_id = $1 AND agent_id = $2"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let sentinel = sqlx::query_as::<_, (String, i32, f64, f64, Value)>(
        r#"SELECT metric_name, n, mean, stddev, learned_set
             FROM agent_metric_baselines
            WHERE tenant_id = $1 AND agent_id = $2
              AND hour_of_week = $3"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .bind(GLOBAL_BUCKET)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
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
    mapped.extend(global.into_iter().map(
        |(metric_name, n, mean, stddev, learned_set)| BaselineRow {
            metric_name,
            hour_of_week: GLOBAL_BUCKET,
            n,
            mean,
            stddev,
            learned_set,
            is_global: true,
        },
    ));
    let have_global: std::collections::HashSet<String> = mapped
        .iter()
        .filter(|r| r.is_global)
        .map(|r| r.metric_name.clone())
        .collect();
    mapped.extend(
        sentinel
            .into_iter()
            .filter(|(metric_name, _, _, _, _)| !have_global.contains(metric_name))
            .map(|(metric_name, n, mean, stddev, learned_set)| BaselineRow {
                metric_name,
                hour_of_week: GLOBAL_BUCKET,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_baseline_is_not_a_clock_sentinel() {
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
                hour_of_week: GLOBAL_BUCKET,
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
            hour_of_week: GLOBAL_BUCKET,
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
}
