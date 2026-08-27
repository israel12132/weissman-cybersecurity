//! Categorical UEBA: learned sets, process/port normalisation, whitelist, aging, uniqueness.
//!
//! A hard cap of 500 plus oldest-first eviction thrashes on K8s / dev hosts: the same
//! legitimate short-lived process falls out of the set and re-alerts as "new". We keep a
//! bounded set (1 500) with hit counts, evict lowest-hit among the oldest, remember evictions
//! for 7 days so a return is a resurrection not a novel, and never alert on a built-in OS
//! process baseline. Tenant / fleet whitelist still wins.

use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::validate::sanitize_process_name;

pub const LEARNED_SET_CAP: usize = 1500;
pub const LEARNED_SET_MAX_AGE_DAYS: i64 = 30;
pub const EVICTED_RESURRECT_DAYS: i64 = 7;
const EVICTED_KEY: &str = "_evicted";

/// Built-in fleet OS / supervisor names. Sanitized (basename, lower, no `.exe`).
const OS_BASELINE: &[&str] = &[
    "systemd",
    "sshd",
    "ssh",
    "cron",
    "crond",
    "init",
    "kthreadd",
    "containerd",
    "containerd-shim",
    "kubelet",
    "kube-proxy",
    "dockerd",
    "docker-proxy",
    "weissman-agent",
    "weissman_agent",
    "svchost",
    "lsass",
    "csrss",
    "services",
    "smss",
    "wininit",
    "winlogon",
    "conhost",
    "dwm",
    "explorer",
    "launchd",
    "kernel_task",
    "syslogd",
    "windowserver",
];

#[derive(Debug, Clone, Copy, Default)]
pub struct LearnedEntry {
    pub last_seen: i64,
    pub hits: u64,
}

#[derive(Debug, Clone, Default)]
pub struct LearnedSet {
    /// item → last-seen + hit count
    pub seen: HashMap<String, LearnedEntry>,
    /// recently evicted item → unix epoch of eviction (resurrection window)
    pub evicted: HashMap<String, i64>,
}

impl LearnedSet {
    pub fn from_json(v: &Value) -> Self {
        let mut seen = HashMap::new();
        let mut evicted = HashMap::new();
        match v {
            Value::Array(arr) => {
                for x in arr {
                    if let Some(s) = x.as_str() {
                        seen.insert(
                            s.to_string(),
                            LearnedEntry {
                                last_seen: 0,
                                hits: 1,
                            },
                        );
                    } else if let Some(n) = x.as_i64() {
                        seen.insert(
                            n.to_string(),
                            LearnedEntry {
                                last_seen: 0,
                                hits: 1,
                            },
                        );
                    }
                }
            }
            Value::Object(map) => {
                for (k, val) in map {
                    if k == EVICTED_KEY {
                        if let Value::Object(inner) = val {
                            for (ek, ev) in inner {
                                evicted.insert(ek.clone(), ev.as_i64().unwrap_or(0));
                            }
                        }
                        continue;
                    }
                    seen.insert(k.clone(), parse_entry(val));
                }
            }
            _ => {}
        }
        Self { seen, evicted }
    }

    pub fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        for (k, e) in &self.seen {
            obj.insert(
                k.clone(),
                serde_json::json!({ "t": e.last_seen, "n": e.hits }),
            );
        }
        if !self.evicted.is_empty() {
            let ev: serde_json::Map<String, Value> = self
                .evicted
                .iter()
                .map(|(k, ts)| (k.clone(), Value::from(*ts)))
                .collect();
            obj.insert(EVICTED_KEY.to_string(), Value::Object(ev));
        }
        Value::Object(obj)
    }

    #[allow(dead_code)]
    pub fn names_vec(&self) -> Vec<String> {
        self.seen.keys().cloned().collect()
    }

    /// Record `items`. Returns names that are novel (not previously learned, not
    /// a 7-day resurrection, and — when `process_names` — not an OS baseline).
    pub fn observe(&mut self, items: &[String], now_unix: i64, process_names: bool) -> Vec<String> {
        let mut novel = Vec::new();
        for raw in items {
            let key = sanitize_process_name(raw);
            if key.is_empty() {
                continue;
            }
            if process_names && is_os_baseline(raw) {
                continue;
            }
            if let Some(entry) = self.seen.get_mut(&key) {
                entry.last_seen = now_unix;
                entry.hits = entry.hits.saturating_add(1);
                continue;
            }
            if let Some(&evicted_at) = self.evicted.get(&key) {
                let age = now_unix.saturating_sub(evicted_at);
                if age <= EVICTED_RESURRECT_DAYS * 86_400 {
                    self.evicted.remove(&key);
                    self.seen.insert(
                        key,
                        LearnedEntry {
                            last_seen: now_unix,
                            hits: 1,
                        },
                    );
                    continue;
                }
                self.evicted.remove(&key);
            }
            novel.push(key.clone());
            self.seen.insert(
                key,
                LearnedEntry {
                    last_seen: now_unix,
                    hits: 1,
                },
            );
        }
        self.prune(now_unix);
        novel
    }

    pub fn prune(&mut self, now_unix: i64) {
        let cutoff = now_unix.saturating_sub(LEARNED_SET_MAX_AGE_DAYS * 86_400);
        self.seen
            .retain(|_, e| e.last_seen == 0 || e.last_seen >= cutoff);
        let evict_cut = now_unix.saturating_sub(EVICTED_RESURRECT_DAYS * 86_400);
        self.evicted.retain(|_, ts| *ts >= evict_cut);
        if self.seen.len() <= LEARNED_SET_CAP {
            if self.evicted.len() > LEARNED_SET_CAP {
                let mut ev: Vec<(String, i64)> =
                    self.evicted.iter().map(|(k, v)| (k.clone(), *v)).collect();
                ev.sort_by_key(|(_, ts)| *ts);
                let drop_n = self.evicted.len() - LEARNED_SET_CAP;
                for (k, _) in ev.into_iter().take(drop_n) {
                    self.evicted.remove(&k);
                }
            }
            return;
        }
        // Lowest hits among the oldest: sort hits asc, then last_seen asc.
        let mut items: Vec<(String, u64, i64)> = self
            .seen
            .iter()
            .map(|(k, e)| (k.clone(), e.hits, e.last_seen))
            .collect();
        items.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
        let drop_n = self.seen.len() - LEARNED_SET_CAP;
        for (k, _, _) in items.into_iter().take(drop_n) {
            self.seen.remove(&k);
            self.evicted.insert(k, now_unix);
        }
    }
}

fn parse_entry(val: &Value) -> LearnedEntry {
    match val {
        Value::Number(n) => LearnedEntry {
            last_seen: n.as_i64().unwrap_or(0),
            hits: 1,
        },
        Value::Object(map) => LearnedEntry {
            last_seen: map.get("t").and_then(Value::as_i64).unwrap_or(0),
            hits: map.get("n").and_then(Value::as_u64).unwrap_or(1).max(1),
        },
        _ => LearnedEntry {
            last_seen: val.as_i64().unwrap_or(0),
            hits: 1,
        },
    }
}

/// True for well-known OS / supervisor processes (and `port:process` listen-map keys).
pub fn is_os_baseline(name: &str) -> bool {
    let raw = name.trim().to_ascii_lowercase();
    if raw.starts_with("kworker")
        || raw.contains("/kworker")
        || raw.starts_with("ksoftirqd")
        || raw.starts_with("irq/")
    {
        return true;
    }
    if OS_BASELINE.contains(&sanitize_process_name(name).as_str()) {
        return true;
    }
    if let Some((_, proc)) = raw.rsplit_once(':') {
        if OS_BASELINE.contains(&sanitize_process_name(proc).as_str()) {
            return true;
        }
    }
    false
}

pub fn ports_as_i32(values: &[Value]) -> Vec<i32> {
    let mut out: Vec<i32> = values
        .iter()
        .filter_map(|v| v.as_i64())
        .filter(|n| (1..=65535).contains(n))
        .map(|n| n as i32)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

pub fn in_whitelist(name: &str, whitelist: &HashSet<String>) -> bool {
    let n = sanitize_process_name(name);
    if n.is_empty() {
        return false;
    }
    whitelist.contains(&n) || whitelist.contains(name)
}

/// Global uniqueness: a process seen on `hosts_with` of `fleet_size` hosts is less anomalous.
pub fn uniqueness_score(hosts_with: i64, fleet_size: i64) -> f64 {
    if fleet_size <= 1 {
        return 1.0;
    }
    let frac = (hosts_with.max(1) as f64) / (fleet_size as f64);
    // 1.0 = unique to this host; ~0.15 = present on most of the fleet.
    (1.0 - frac).clamp(0.15, 1.0)
}

/// Port opened by an unfamiliar process is more severe than a new port on a known daemon.
#[allow(dead_code)]
pub fn port_process_mismatch(port: i32, process: &str, known: &HashSet<String>) -> bool {
    let p = sanitize_process_name(process);
    let key = format!("{port}:{p}");
    !known.contains(&key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn learned_set_caps_and_ages() {
        let mut s = LearnedSet::default();
        let now = 1_700_000_000;
        let novel = s.observe(&["nginx".into(), "python3".into()], now, true);
        assert_eq!(novel.len(), 2);
        let again = s.observe(&["nginx".into()], now + 10, true);
        assert!(again.is_empty());
        assert_eq!(s.seen.get("nginx").map(|e| e.hits), Some(2));
        s.observe(&["old".into()], now - 40 * 86_400, true);
        s.prune(now);
        assert!(!s.seen.contains_key("old"));
        for i in 0..1600 {
            s.observe(&[format!("p{i}")], now, true);
        }
        assert!(s.seen.len() <= LEARNED_SET_CAP);
    }

    #[test]
    fn os_baseline_never_novel_and_skips_cap() {
        let mut s = LearnedSet::default();
        let now = 1_700_000_000;
        let novel = s.observe(
            &["sshd".into(), "systemd".into(), "kworker/0:1".into()],
            now,
            true,
        );
        assert!(novel.is_empty());
        assert!(s.seen.is_empty());
        assert!(is_os_baseline("22:sshd"));
        assert!(!is_os_baseline("4444:nc"));
    }

    #[test]
    fn evicted_item_resurrects_without_novel() {
        let mut s = LearnedSet::default();
        let now = 1_700_000_000;
        s.seen.insert(
            "node".into(),
            LearnedEntry {
                last_seen: now,
                hits: 1,
            },
        );
        s.evicted.insert("node".into(), now);
        s.seen.remove("node");
        let novel = s.observe(&["node".into()], now + 3600, true);
        assert!(novel.is_empty(), "7-day resurrection must not re-alert");
        assert!(s.seen.contains_key("node"));
        assert!(!s.evicted.contains_key("node"));
    }

    #[test]
    fn evicts_low_hits_before_high_hits() {
        let mut s = LearnedSet::default();
        let now = 1_700_000_000;
        for i in 0..LEARNED_SET_CAP {
            s.seen.insert(
                format!("keep{i}"),
                LearnedEntry {
                    last_seen: now,
                    hits: 50,
                },
            );
        }
        s.seen.insert(
            "rare".into(),
            LearnedEntry {
                last_seen: now - 100,
                hits: 1,
            },
        );
        s.prune(now);
        assert!(!s.seen.contains_key("rare"));
        assert!(s.evicted.contains_key("rare"));
        assert_eq!(s.seen.len(), LEARNED_SET_CAP);
    }

    #[test]
    fn legacy_numeric_json_hydrates() {
        let v = json!({"nginx": 1700000000, "sshd": 1700000001});
        let s = LearnedSet::from_json(&v);
        assert_eq!(s.seen.get("nginx").map(|e| e.hits), Some(1));
        assert_eq!(
            s.seen.get("nginx").map(|e| e.last_seen),
            Some(1_700_000_000)
        );
        let round = LearnedSet::from_json(&s.to_json());
        assert_eq!(round.seen.get("nginx").map(|e| e.hits), Some(1));
    }

    #[test]
    fn uniqueness_scales() {
        assert!((uniqueness_score(1, 20) - 1.0).abs() < 0.05 || uniqueness_score(1, 20) > 0.9);
        assert!(uniqueness_score(20, 20) < uniqueness_score(1, 20));
    }

    #[test]
    fn ports_as_i32_filters() {
        let v = json!([22, 80, 99999, -1, 443]);
        assert_eq!(ports_as_i32(v.as_array().unwrap()), vec![22, 80, 443]);
    }
}
