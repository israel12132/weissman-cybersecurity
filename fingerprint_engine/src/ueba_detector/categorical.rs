//! Categorical UEBA: learned sets, process/port normalisation, whitelist, aging, uniqueness.
//!
//! Names do **not** enter the approved baseline on first sighting. They sit in
//! `_probation` until either 24h of consistent observation on this host, or fleet
//! consensus (≥3 other agents). Least-hits eviction applies only to probation, so
//! a compile-loop of random binaries cannot eject weekly backup jobs.

use serde_json::Value;
use std::collections::{HashMap, HashSet};

use super::validate::sanitize_process_name;

pub const LEARNED_SET_CAP: usize = 1500;
pub const LEARNED_SET_MAX_AGE_DAYS: i64 = 30;
pub const EVICTED_RESURRECT_DAYS: i64 = 7;
/// 24h of consistent observation on *this* host before a name is approved.
pub const PROBATION_SECS: i64 = 24 * 3600;
/// Distinct *other* agents in the tenant that must already know the name.
pub const FLEET_CONSENSUS_OTHERS: i64 = 3;
const EVICTED_KEY: &str = "_evicted";
const PROBATION_KEY: &str = "_probation";

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
    pub first_seen: i64,
    pub hits: u64,
}

impl LearnedEntry {
    fn new(now: i64) -> Self {
        Self {
            last_seen: now,
            first_seen: now,
            hits: 1,
        }
    }

    fn legacy(ts: i64) -> Self {
        Self {
            last_seen: ts,
            first_seen: ts,
            hits: 1,
        }
    }

    fn to_json(self) -> Value {
        serde_json::json!({ "t": self.last_seen, "n": self.hits, "t0": self.first_seen })
    }
}

fn tenure_ok(e: &LearnedEntry, now: i64) -> bool {
    e.hits >= 2 && now.saturating_sub(e.first_seen) >= PROBATION_SECS
}

#[derive(Debug, Clone, Default)]
pub struct LearnedSet {
    /// Approved baseline (24h tenure or fleet consensus). Least-hits must not evict these.
    pub seen: HashMap<String, LearnedEntry>,
    /// Candidates. Random compile-loop names die here and never touch `seen`.
    pub probation: HashMap<String, LearnedEntry>,
    /// recently evicted item → unix epoch of eviction (resurrection window)
    pub evicted: HashMap<String, i64>,
}

impl LearnedSet {
    pub fn from_json(v: &Value) -> Self {
        let mut seen = HashMap::new();
        let mut probation = HashMap::new();
        let mut evicted = HashMap::new();
        match v {
            Value::Array(arr) => {
                for x in arr {
                    if let Some(s) = x.as_str() {
                        seen.insert(s.to_string(), LearnedEntry::legacy(0));
                    } else if let Some(n) = x.as_i64() {
                        seen.insert(n.to_string(), LearnedEntry::legacy(0));
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
                    if k == PROBATION_KEY {
                        if let Value::Object(inner) = val {
                            for (pk, pv) in inner {
                                probation.insert(pk.clone(), parse_entry(pv));
                            }
                        }
                        continue;
                    }
                    if k.starts_with('_') {
                        continue;
                    }
                    seen.insert(k.clone(), parse_entry(val));
                }
            }
            _ => {}
        }
        Self {
            seen,
            probation,
            evicted,
        }
    }

    pub fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        for (k, e) in &self.seen {
            obj.insert(k.clone(), e.to_json());
        }
        if !self.probation.is_empty() {
            let p: serde_json::Map<String, Value> = self
                .probation
                .iter()
                .map(|(k, e)| (k.clone(), e.to_json()))
                .collect();
            obj.insert(PROBATION_KEY.to_string(), Value::Object(p));
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

    /// Record `items`. Returns names that are not yet approved (first sighting or
    /// still on probation). OS baseline never appears. A 24h tenure on this host
    /// promotes probation → seen. Fleet consensus is applied by the caller.
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
                    self.seen.insert(key, LearnedEntry::new(now_unix));
                    continue;
                }
                self.evicted.remove(&key);
            }
            if let Some(entry) = self.probation.get_mut(&key) {
                entry.last_seen = now_unix;
                entry.hits = entry.hits.saturating_add(1);
                continue;
            }
            novel.push(key.clone());
            self.probation.insert(key, LearnedEntry::new(now_unix));
        }
        self.promote_by_tenure(now_unix);
        self.prune(now_unix);
        novel
    }

    pub fn try_fleet_promote(&mut self, key: &str, other_hosts: i64, now_unix: i64) -> bool {
        if other_hosts < FLEET_CONSENSUS_OTHERS {
            return false;
        }
        if !self.probation.contains_key(key) {
            return false;
        }
        self.promote_key(key, now_unix);
        true
    }

    fn promote_by_tenure(&mut self, now_unix: i64) {
        let due: Vec<String> = self
            .probation
            .iter()
            .filter(|(_, e)| tenure_ok(e, now_unix))
            .map(|(k, _)| k.clone())
            .collect();
        for k in due {
            self.promote_key(&k, now_unix);
        }
    }

    fn promote_key(&mut self, key: &str, now_unix: i64) {
        if let Some(mut e) = self.probation.remove(key) {
            e.last_seen = now_unix;
            self.seen.insert(key.to_string(), e);
        }
    }

    pub fn prune(&mut self, now_unix: i64) {
        let cutoff = now_unix.saturating_sub(LEARNED_SET_MAX_AGE_DAYS * 86_400);
        self.seen
            .retain(|_, e| e.last_seen == 0 || e.last_seen >= cutoff);
        self.probation
            .retain(|_, e| e.last_seen == 0 || e.last_seen >= cutoff);
        let evict_cut = now_unix.saturating_sub(EVICTED_RESURRECT_DAYS * 86_400);
        self.evicted.retain(|_, ts| *ts >= evict_cut);
        if self.probation.len() > LEARNED_SET_CAP {
            let mut items: Vec<(String, u64, i64)> = self
                .probation
                .iter()
                .map(|(k, e)| (k.clone(), e.hits, e.last_seen))
                .collect();
            items.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
            let drop_n = self.probation.len() - LEARNED_SET_CAP;
            for (k, _, _) in items.into_iter().take(drop_n) {
                self.probation.remove(&k);
                self.evicted.insert(k, now_unix);
            }
        }
        if self.evicted.len() > LEARNED_SET_CAP {
            let mut ev: Vec<(String, i64)> =
                self.evicted.iter().map(|(k, v)| (k.clone(), *v)).collect();
            ev.sort_by_key(|(_, ts)| *ts);
            let drop_n = self.evicted.len() - LEARNED_SET_CAP;
            for (k, _) in ev.into_iter().take(drop_n) {
                self.evicted.remove(&k);
            }
        }
    }
}

fn parse_entry(val: &Value) -> LearnedEntry {
    match val {
        Value::Number(n) => {
            let ts = n.as_i64().unwrap_or(0);
            LearnedEntry::legacy(ts)
        }
        Value::Object(map) => {
            let last = map.get("t").and_then(Value::as_i64).unwrap_or(0);
            let first = map.get("t0").and_then(Value::as_i64).unwrap_or(last);
            LearnedEntry {
                last_seen: last,
                first_seen: first,
                hits: map.get("n").and_then(Value::as_u64).unwrap_or(1).max(1),
            }
        }
        _ => LearnedEntry::legacy(val.as_i64().unwrap_or(0)),
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
        assert!(
            s.seen.is_empty(),
            "first sighting is probation, not approved"
        );
        let again = s.observe(&["nginx".into()], now + 10, true);
        assert!(again.is_empty());
        assert_eq!(s.probation.get("nginx").map(|e| e.hits), Some(2));
        s.observe(&["old".into()], now - 40 * 86_400, true);
        s.prune(now);
        assert!(!s.probation.contains_key("old"));
        for i in 0..1600 {
            s.observe(&[format!("p{i}")], now, true);
        }
        assert!(s.probation.len() <= LEARNED_SET_CAP);
        assert!(s.seen.len() <= LEARNED_SET_CAP);
    }

    #[test]
    fn tenure_promotes_after_24h() {
        let mut s = LearnedSet::default();
        let now = 1_700_000_000;
        s.observe(&["backup".into()], now, true);
        s.observe(&["backup".into()], now + 60, true);
        assert!(s.seen.is_empty());
        s.observe(&["backup".into()], now + PROBATION_SECS + 1, true);
        assert!(s.seen.contains_key("backup"));
        assert!(!s.probation.contains_key("backup"));
    }

    #[test]
    fn fleet_consensus_promotes_without_24h() {
        let mut s = LearnedSet::default();
        let now = 1_700_000_000;
        s.observe(&["fleet-daemon".into()], now, true);
        assert!(s.try_fleet_promote("fleet-daemon", FLEET_CONSENSUS_OTHERS, now));
        assert!(s.seen.contains_key("fleet-daemon"));
        assert!(!s.try_fleet_promote("missing", FLEET_CONSENSUS_OTHERS, now));
        let mut s2 = LearnedSet::default();
        s2.observe(&["solo".into()], now, true);
        assert!(!s2.try_fleet_promote("solo", 2, now));
        assert!(s2.probation.contains_key("solo"));
    }

    #[test]
    fn poison_names_do_not_evict_approved() {
        let mut s = LearnedSet::default();
        let now = 1_700_000_000;
        s.seen.insert(
            "backup".into(),
            LearnedEntry {
                last_seen: now,
                first_seen: now - PROBATION_SECS * 7,
                hits: 4,
            },
        );
        for i in 0..2000 {
            s.observe(&[format!("tmp{i}")], now, true);
        }
        assert!(
            s.seen.contains_key("backup"),
            "weekly backup must survive a compile-loop flood"
        );
        assert!(s.probation.len() <= LEARNED_SET_CAP);
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
        assert!(s.probation.is_empty());
        assert!(is_os_baseline("22:sshd"));
        assert!(!is_os_baseline("4444:nc"));
    }

    #[test]
    fn evicted_item_resurrects_without_novel() {
        let mut s = LearnedSet::default();
        let now = 1_700_000_000;
        s.evicted.insert("node".into(), now);
        let novel = s.observe(&["node".into()], now + 3600, true);
        assert!(novel.is_empty(), "7-day resurrection must not re-alert");
        assert!(s.seen.contains_key("node"));
        assert!(!s.evicted.contains_key("node"));
    }

    #[test]
    fn evicts_low_hits_from_probation_only() {
        let mut s = LearnedSet::default();
        let now = 1_700_000_000;
        for i in 0..LEARNED_SET_CAP {
            s.probation.insert(
                format!("keep{i}"),
                LearnedEntry {
                    last_seen: now,
                    first_seen: now,
                    hits: 50,
                },
            );
        }
        s.probation.insert(
            "rare".into(),
            LearnedEntry {
                last_seen: now - 100,
                first_seen: now - 100,
                hits: 1,
            },
        );
        s.prune(now);
        assert!(!s.probation.contains_key("rare"));
        assert!(s.evicted.contains_key("rare"));
        assert_eq!(s.probation.len(), LEARNED_SET_CAP);
    }

    #[test]
    fn legacy_numeric_json_hydrates_as_approved() {
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
