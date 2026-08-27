//! Categorical UEBA: learned sets, process/port normalisation, whitelist, aging, uniqueness.

use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::validate::sanitize_process_name;

pub const LEARNED_SET_CAP: usize = 500;
pub const LEARNED_SET_MAX_AGE_DAYS: i64 = 30;

#[derive(Debug, Clone, Default)]
pub struct LearnedSet {
    /// item → unix epoch seconds of last observation
    pub seen: HashMap<String, i64>,
}

impl LearnedSet {
    pub fn from_json(v: &Value) -> Self {
        let mut seen = HashMap::new();
        match v {
            Value::Array(arr) => {
                for x in arr {
                    if let Some(s) = x.as_str() {
                        seen.insert(s.to_string(), 0);
                    } else if let Some(n) = x.as_i64() {
                        seen.insert(n.to_string(), 0);
                    }
                }
            }
            Value::Object(map) => {
                for (k, val) in map {
                    let ts = val.as_i64().unwrap_or(0);
                    seen.insert(k.clone(), ts);
                }
            }
            _ => {}
        }
        Self { seen }
    }

    pub fn to_json(&self) -> Value {
        let obj: serde_json::Map<String, Value> = self
            .seen
            .iter()
            .map(|(k, ts)| (k.clone(), Value::from(*ts)))
            .collect();
        Value::Object(obj)
    }

    #[allow(dead_code)]
    pub fn names_vec(&self) -> Vec<String> {
        self.seen.keys().cloned().collect()
    }

    pub fn observe(&mut self, items: &[String], now_unix: i64) -> Vec<String> {
        let mut novel = Vec::new();
        for raw in items {
            let key = sanitize_process_name(raw);
            if key.is_empty() {
                continue;
            }
            if !self.seen.contains_key(&key) {
                novel.push(key.clone());
            }
            self.seen.insert(key, now_unix);
        }
        self.prune(now_unix);
        novel
    }

    pub fn prune(&mut self, now_unix: i64) {
        let cutoff = now_unix.saturating_sub(LEARNED_SET_MAX_AGE_DAYS * 86_400);
        self.seen.retain(|_, ts| *ts == 0 || *ts >= cutoff);
        if self.seen.len() <= LEARNED_SET_CAP {
            return;
        }
        let mut items: Vec<(String, i64)> =
            self.seen.iter().map(|(k, v)| (k.clone(), *v)).collect();
        items.sort_by_key(|(_, ts)| *ts);
        let drop_n = self.seen.len() - LEARNED_SET_CAP;
        for (k, _) in items.into_iter().take(drop_n) {
            self.seen.remove(&k);
        }
    }
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
        let novel = s.observe(&["nginx".into(), "sshd".into()], now);
        assert_eq!(novel.len(), 2);
        let again = s.observe(&["nginx".into()], now + 10);
        assert!(again.is_empty());
        s.observe(&["old".into()], now - 40 * 86_400);
        s.prune(now);
        assert!(!s.seen.contains_key("old"));
        for i in 0..600 {
            s.observe(&[format!("p{i}")], now);
        }
        assert!(s.seen.len() <= LEARNED_SET_CAP);
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
