//! Edge UEBA gate — local z-score vs the compact hour-of-week snapshot.
//!
//! The server still computes the 7-day rolling baseline. The agent holds a
//! compressed copy of mean/stddev for the current `hour_of_week` (falling back
//! to the rolling-7d global row when that hour has too few samples) and only
//! uploads a raw sample when:
//!   * still training (`n < min_n`), or
//!   * any gated numeric metric has `|z| > 2`, or
//!   * a process name appears that is not in the learned set.
//!
//! Quiet ticks stay on the endpoint. That is the 95% traffic cut.

use crate::protocol::UebaCompactSnapshot;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::RwLock;

/// Agent-side upload threshold. Server-side anomaly fire stays at |z| > 3.
pub const Z_UPLOAD: f64 = 2.0;
const MIN_N_DEFAULT: i32 = 7;

const GATED_METRICS: &[&str] = &[
    "open_port_count",
    "process_count",
    "unique_users",
    "load_1m",
    "memory_used_pct",
    "failed_logins",
];

static SNAPSHOT: RwLock<Option<UebaCompactSnapshot>> = RwLock::new(None);

pub fn install(snapshot: UebaCompactSnapshot) {
    if let Ok(mut g) = SNAPSHOT.write() {
        *g = Some(snapshot);
    }
}

#[must_use]
pub fn current() -> Option<UebaCompactSnapshot> {
    SNAPSHOT.read().ok().and_then(|g| g.clone())
}

#[derive(Debug, Clone, PartialEq)]
pub enum Gate {
    /// Send the raw sample (training, |z|>2, or new process).
    Upload { reason: String, z_max: f64 },
    /// Keep the sample local; report TaskDone with zero findings.
    Suppress { z_max: f64 },
}

#[must_use]
pub fn decide(metrics: &Value, hour_of_week: u8) -> Gate {
    let snap = current();
    decide_with(metrics, hour_of_week, snap.as_ref())
}

#[must_use]
pub fn decide_with(metrics: &Value, hour_of_week: u8, snap: Option<&UebaCompactSnapshot>) -> Gate {
    let Some(snap) = snap else {
        return Gate::Upload {
            reason: "no_local_baseline".into(),
            z_max: 0.0,
        };
    };
    let threshold = if snap.z_upload_threshold > 0.0 {
        snap.z_upload_threshold
    } else {
        Z_UPLOAD
    };
    let min_n = if snap.min_n > 0 {
        snap.min_n
    } else {
        MIN_N_DEFAULT
    };

    let mut z_max = 0.0_f64;
    let mut trained_any = false;
    for name in GATED_METRICS {
        let Some(observed) = metrics.get(*name).and_then(Value::as_f64) else {
            continue;
        };
        let Some(stat) = snap.metric(name) else {
            continue;
        };
        if stat.n < min_n {
            return Gate::Upload {
                reason: format!("training:{name}:n={}", stat.n),
                z_max,
            };
        }
        trained_any = true;
        let z = z_score(observed, stat.mean, stat.stddev);
        z_max = z_max.max(z.abs());
        if z.abs() > threshold {
            return Gate::Upload {
                reason: format!("z:{name}:{z:.2}"),
                z_max: z.abs(),
            };
        }
    }

    if let Some(new_proc) = first_new_process(metrics, &snap.learned_processes) {
        return Gate::Upload {
            reason: format!("new_process:{new_proc}"),
            z_max,
        };
    }

    if !trained_any {
        return Gate::Upload {
            reason: "no_gated_stats".into(),
            z_max,
        };
    }

    let _ = hour_of_week; // snapshot is already the hour (or rolling-7d fallback)
    Gate::Suppress { z_max }
}

fn z_score(observed: f64, mean: f64, stddev: f64) -> f64 {
    if stddev.abs() < 1e-9 {
        if (observed - mean).abs() < 1e-9 {
            0.0
        } else {
            // Constant baseline broke — treat as a deviation worth uploading.
            99.0
        }
    } else {
        (observed - mean) / stddev
    }
}

fn first_new_process(metrics: &Value, learned: &[String]) -> Option<String> {
    if learned.is_empty() {
        return None; // still learning the set; numeric gate handles training
    }
    let set: HashSet<&str> = learned.iter().map(String::as_str).collect();
    let procs = metrics.get("top_processes")?.as_array()?;
    for p in procs {
        let Some(name) = p.as_str() else { continue };
        if !set.contains(name) {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::UebaCompactMetric;
    use serde_json::json;

    fn snap(n: i32, mean: f64, stddev: f64, procs: &[&str]) -> UebaCompactSnapshot {
        UebaCompactSnapshot {
            hour_of_week: 10,
            z_upload_threshold: Z_UPLOAD,
            min_n: 7,
            source: "rolling_7d".into(),
            metrics: vec![
                UebaCompactMetric {
                    name: "process_count".into(),
                    mean,
                    stddev,
                    n,
                },
                UebaCompactMetric {
                    name: "open_port_count".into(),
                    mean: 8.0,
                    stddev: 1.0,
                    n,
                },
            ],
            learned_processes: procs.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn missing_snapshot_uploads() {
        let m = json!({"process_count": 10.0});
        match decide_with(&m, 10, None) {
            Gate::Upload { reason, .. } => assert_eq!(reason, "no_local_baseline"),
            Gate::Suppress { .. } => panic!("should upload"),
        }
    }

    #[test]
    fn training_window_uploads() {
        let m = json!({"process_count": 10.0, "open_port_count": 8.0, "top_processes": ["sshd"]});
        let s = snap(3, 10.0, 1.0, &["sshd"]);
        match decide_with(&m, 10, Some(&s)) {
            Gate::Upload { reason, .. } => assert!(reason.starts_with("training:")),
            Gate::Suppress { .. } => panic!("n=3 must still train"),
        }
    }

    #[test]
    fn quiet_tick_is_suppressed() {
        let m = json!({
            "process_count": 10.4,
            "open_port_count": 8.2,
            "top_processes": ["sshd", "systemd"]
        });
        let s = snap(24, 10.0, 1.0, &["sshd", "systemd", "cron"]);
        match decide_with(&m, 10, Some(&s)) {
            Gate::Suppress { z_max } => assert!(z_max < Z_UPLOAD),
            Gate::Upload { reason, .. } => panic!("quiet tick leaked: {reason}"),
        }
    }

    #[test]
    fn z_above_two_uploads() {
        let m = json!({
            "process_count": 15.0, // z = (15-10)/1 = 5
            "open_port_count": 8.0,
            "top_processes": ["sshd"]
        });
        let s = snap(24, 10.0, 1.0, &["sshd"]);
        match decide_with(&m, 10, Some(&s)) {
            Gate::Upload { reason, z_max } => {
                assert!(reason.contains("process_count"));
                assert!(z_max > 2.0);
            }
            Gate::Suppress { .. } => panic!("|z|=5 must upload"),
        }
    }

    #[test]
    fn new_process_uploads_even_when_z_quiet() {
        let m = json!({
            "process_count": 10.0,
            "open_port_count": 8.0,
            "top_processes": ["sshd", "weird.sh"]
        });
        let s = snap(24, 10.0, 1.0, &["sshd"]);
        match decide_with(&m, 10, Some(&s)) {
            Gate::Upload { reason, .. } => assert!(reason.contains("weird.sh")),
            Gate::Suppress { .. } => panic!("new process must upload"),
        }
    }

    #[test]
    fn z_upload_constant_is_two() {
        assert_eq!(Z_UPLOAD, 2.0);
    }
}
