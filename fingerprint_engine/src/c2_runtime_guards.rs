//! Runtime guards for the Advanced C2 & Covert Exfil assessment engine.
//!
//! Assessment-only. These primitives stop *the platform* from falling over:
//! tenant scan locks (Redis `SET NX EX`), in-memory + Redis sliding-window DNS
//! dedup (never hot-write raw DNS queries to Postgres), and the 2 MiB media
//! ceiling used by the stego layer.
//!
//! Redis key: `weissman:c2_scan_lock:{tenant_id}` — 300s TTL.

use redis::AsyncCommands;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Hard safety ceiling for any public-media body the stego layer will buffer.
pub const MAX_MEDIA_FILE_SIZE_BYTES: usize = 2 * 1024 * 1024;

/// Image analysis (entropy / χ² / EXIF walk) must finish inside this bound.
pub const MEDIA_ANALYSIS_TIMEOUT: Duration = Duration::from_millis(100);

/// Tenant C2 scan lock TTL (seconds). Matches `SET … NX EX 300`.
pub const C2_SCAN_LOCK_TTL_SECS: u64 = 300;

/// Sliding window for DNS observation dedup (in-process + Redis).
pub const DNS_DEDUP_WINDOW: Duration = Duration::from_secs(3600);

const LOCK_PREFIX: &str = "weissman:c2_scan_lock:";
const DNS_SEEN_PREFIX: &str = "weissman:dns_covert_seen:";
const DNS_SUMMARY_PREFIX: &str = "weissman:dns_covert_summary:";

const REDIS_OP_TIMEOUT: Duration = Duration::from_secs(2);

// ── Redis client (optional) ─────────────────────────────────────────────────

struct RedisGuards {
    client: redis::Client,
}

fn redis_shared() -> Option<&'static RedisGuards> {
    static S: OnceLock<Option<RedisGuards>> = OnceLock::new();
    S.get_or_init(|| {
        let url = std::env::var("REDIS_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let client = redis::Client::open(url).ok()?;
        tracing::info!(target: "c2_runtime_guards", "C2 scan lock / DNS aggregate Redis enabled");
        Some(RedisGuards { client })
    })
    .as_ref()
}

async fn redis_conn(
    client: &redis::Client,
) -> redis::RedisResult<redis::aio::MultiplexedConnection> {
    let mut conn =
        tokio::time::timeout(REDIS_OP_TIMEOUT, client.get_multiplexed_async_connection())
            .await
            .map_err(|_| {
                redis::RedisError::from((redis::ErrorKind::IoError, "redis connect timeout"))
            })??;
    conn.set_response_timeout(REDIS_OP_TIMEOUT);
    Ok(conn)
}

// ── Scan lock ────────────────────────────────────────────────────────────────

/// Outcome of `SET weissman:c2_scan_lock:{tenant} NX EX 300`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanLockOutcome {
    Acquired,
    /// Another C2 scan is in-flight for this tenant. `ttl_secs` is a Retry-After hint.
    Held {
        ttl_secs: u64,
    },
    /// Redis is required (URL configured) but the SET could not be issued.
    Unavailable,
}

/// Atomic `SET key locked NX EX 300` against an explicit Redis client.
///
/// Returns `Ok(true)` when the lock was created, `Ok(false)` when it already exists.
pub async fn acquire_scan_lock(
    redis_client: &redis::Client,
    tenant_id: i64,
) -> Result<bool, redis::RedisError> {
    let mut conn = redis_conn(redis_client).await?;
    let lock_key = format!("{LOCK_PREFIX}{tenant_id}");
    let acquired: Option<String> = redis::cmd("SET")
        .arg(&lock_key)
        .arg("locked")
        .arg("NX")
        .arg("EX")
        .arg(C2_SCAN_LOCK_TTL_SECS)
        .query_async(&mut conn)
        .await?;
    Ok(acquired.is_some())
}

/// Best-effort TTL remaining on the tenant lock (0 when missing).
pub async fn scan_lock_ttl_secs(
    redis_client: &redis::Client,
    tenant_id: i64,
) -> Result<u64, redis::RedisError> {
    let mut conn = redis_conn(redis_client).await?;
    let lock_key = format!("{LOCK_PREFIX}{tenant_id}");
    let ttl: i64 = conn.ttl(lock_key).await?;
    Ok(if ttl > 0 {
        ttl as u64
    } else {
        C2_SCAN_LOCK_TTL_SECS
    })
}

/// Release the lock so a failed enqueue can retry immediately.
pub async fn release_scan_lock(
    redis_client: &redis::Client,
    tenant_id: i64,
) -> Result<(), redis::RedisError> {
    let mut conn = redis_conn(redis_client).await?;
    let lock_key = format!("{LOCK_PREFIX}{tenant_id}");
    let _: () = conn.del(lock_key).await?;
    Ok(())
}

fn local_locks() -> &'static Mutex<HashMap<i64, Instant>> {
    static M: OnceLock<Mutex<HashMap<i64, Instant>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn local_acquire(tenant_id: i64) -> ScanLockOutcome {
    let mut map = match local_locks().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    map.retain(|_, exp| *exp > now);
    if let Some(exp) = map.get(&tenant_id) {
        let ttl_secs = exp.saturating_duration_since(now).as_secs().max(1);
        return ScanLockOutcome::Held { ttl_secs };
    }
    map.insert(tenant_id, now + Duration::from_secs(C2_SCAN_LOCK_TTL_SECS));
    ScanLockOutcome::Acquired
}

fn local_release(tenant_id: i64) {
    let mut map = match local_locks().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    map.remove(&tenant_id);
}

/// Acquire the per-tenant C2 scan lock (Redis when configured, in-process otherwise).
pub async fn try_acquire_c2_scan_lock(tenant_id: i64) -> ScanLockOutcome {
    if let Some(rg) = redis_shared() {
        match acquire_scan_lock(&rg.client, tenant_id).await {
            Ok(true) => ScanLockOutcome::Acquired,
            Ok(false) => {
                let ttl_secs = scan_lock_ttl_secs(&rg.client, tenant_id)
                    .await
                    .unwrap_or(C2_SCAN_LOCK_TTL_SECS);
                ScanLockOutcome::Held { ttl_secs }
            }
            Err(e) => {
                tracing::error!(
                    target: "c2_runtime_guards",
                    error = %e,
                    tenant_id,
                    "C2 scan lock SET NX failed"
                );
                ScanLockOutcome::Unavailable
            }
        }
    } else {
        local_acquire(tenant_id)
    }
}

/// Drop the lock after a failed enqueue (or tests).
pub async fn release_c2_scan_lock(tenant_id: i64) {
    if let Some(rg) = redis_shared() {
        let _ = release_scan_lock(&rg.client, tenant_id).await;
    }
    local_release(tenant_id);
}

#[must_use]
pub fn c2_scan_conflict_body(ttl_secs: u64) -> Value {
    json!({
        "ok": false,
        "code": "c2_scan_lock",
        "detail": "A C2 covert-exfil assessment is already running for this tenant. Parallel launches are rejected to protect FAIR accounting and worker capacity.",
        "retry_after_seconds": ttl_secs,
    })
}

// ── DNS sliding-window aggregation ──────────────────────────────────────────

/// One live DNS observation. Never written to Postgres as-is.
#[derive(Debug, Clone)]
pub struct DnsObservation {
    pub qtype: String,
    pub host: String,
    pub entropy: Option<f64>,
    pub txt_len: Option<usize>,
    pub min_ttl: Option<i32>,
    pub extra: Value,
}

impl DnsObservation {
    /// Validated covert-channel anomaly — the only class that may become a PG summary row.
    #[must_use]
    pub fn is_validated_anomaly(&self) -> bool {
        self.entropy.map(|e| e > 4.5).unwrap_or(false)
            || self.txt_len.map(|l| l > 200).unwrap_or(false)
            || self.min_ttl.map(|t| t <= 1).unwrap_or(false)
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.host.to_ascii_lowercase().as_bytes());
        h.update(b"|");
        h.update(self.qtype.as_bytes());
        h.update(b"|");
        if let Some(e) = self.entropy {
            h.update(format!("{e:.3}").as_bytes());
        }
        h.update(b"|");
        if let Some(l) = self.txt_len {
            h.update(l.to_le_bytes());
        }
        h.update(b"|");
        if let Some(t) = self.min_ttl {
            h.update(t.to_le_bytes());
        }
        hex::encode(h.finalize())
    }
}

/// Hourly anomaly summary — the only row type persisted to `dns_covert_query_audits`.
#[derive(Debug, Clone)]
pub struct DnsHourlySummary {
    pub host: String,
    pub hour_utc: chrono::DateTime<chrono::Utc>,
    pub query_count: u64,
    pub unique_qtypes: Vec<String>,
    pub max_entropy: f64,
    pub min_ttl: Option<i32>,
    pub max_txt_len: usize,
}

impl DnsHourlySummary {
    #[must_use]
    pub fn evidence(&self) -> Value {
        json!({
            "kind": "hourly_anomaly_summary",
            "query_count": self.query_count,
            "unique_qtypes": self.unique_qtypes,
            "max_entropy": self.max_entropy,
            "min_ttl": self.min_ttl,
            "max_txt_len": self.max_txt_len,
            "hour_utc": self.hour_utc.to_rfc3339(),
            "raw_queries_persisted": false,
        })
    }
}

/// Truncate `now` to the UTC hour (stable conflict key).
#[must_use]
pub fn hour_utc_bucket(now: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    let ts = now.timestamp().div_euclid(3600) * 3600;
    chrono::DateTime::from_timestamp(ts, 0).unwrap_or(now)
}

fn dns_window() -> &'static Mutex<HashMap<String, Instant>> {
    static W: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(HashMap::new()))
}

/// In-memory sliding-window SET NX. `true` = first sighting in the window.
#[must_use]
pub fn sliding_window_accept(key: &str, ttl: Duration) -> bool {
    let mut map = match dns_window().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let now = Instant::now();
    map.retain(|_, exp| *exp > now);
    if map.contains_key(key) {
        return false;
    }
    map.insert(key.to_string(), now + ttl);
    true
}

/// Drop duplicate observations inside one scan (same host/qtype/content).
#[must_use]
pub fn dedup_dns_observations(obs: &[DnsObservation]) -> Vec<DnsObservation> {
    let mut seen = HashSet::new();
    obs.iter()
        .filter(|o| seen.insert(o.fingerprint()))
        .cloned()
        .collect()
}

/// Fold observations into **at most one summary per host**. Hosts with no validated
/// anomaly produce **zero** rows — Postgres never sees raw queries or clean traffic.
#[must_use]
pub fn aggregate_dns_anomaly_summaries(
    obs: &[DnsObservation],
    hour_utc: chrono::DateTime<chrono::Utc>,
) -> Vec<DnsHourlySummary> {
    let deduped = dedup_dns_observations(obs);
    let mut by_host: BTreeMap<String, (u64, HashSet<String>, f64, Option<i32>, usize, bool)> =
        BTreeMap::new();
    for o in &deduped {
        let entry =
            by_host
                .entry(o.host.clone())
                .or_insert((0, HashSet::new(), 0.0, None, 0, false));
        entry.0 += 1;
        entry.1.insert(o.qtype.clone());
        if let Some(e) = o.entropy {
            if e > entry.2 {
                entry.2 = e;
            }
        }
        if let Some(ttl) = o.min_ttl {
            entry.3 = Some(match entry.3 {
                Some(prev) => prev.min(ttl),
                None => ttl,
            });
        }
        if let Some(len) = o.txt_len {
            entry.4 = entry.4.max(len);
        }
        entry.5 |= o.is_validated_anomaly();
    }
    by_host
        .into_iter()
        .filter(|(_, v)| v.5)
        .map(
            |(host, (count, qtypes, max_entropy, min_ttl, max_txt_len, _))| {
                let mut unique_qtypes: Vec<String> = qtypes.into_iter().collect();
                unique_qtypes.sort();
                DnsHourlySummary {
                    host,
                    hour_utc,
                    query_count: count,
                    unique_qtypes,
                    max_entropy,
                    min_ttl,
                    max_txt_len,
                }
            },
        )
        .collect()
}

/// Redis SET NX on a per-observation fingerprint. `None` = Redis down (caller uses memory).
async fn redis_mark_dns_seen(tenant_id: i64, fingerprint: &str) -> Option<bool> {
    let rg = redis_shared()?;
    let mut conn = redis_conn(&rg.client).await.ok()?;
    let key = format!("{DNS_SEEN_PREFIX}{tenant_id}:{fingerprint}");
    let acquired: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(DNS_DEDUP_WINDOW.as_secs())
        .query_async(&mut conn)
        .await
        .ok()?;
    Some(acquired.is_some())
}

/// Redis SET NX so only one replica flushes a given (tenant, host, hour) summary.
pub async fn redis_claim_dns_summary_flush(
    tenant_id: i64,
    host: &str,
    hour_utc: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Some(rg) = redis_shared() else {
        let key = format!(
            "pgflush:{tenant_id}:{}:{}",
            host.to_ascii_lowercase(),
            hour_utc.timestamp()
        );
        return sliding_window_accept(&key, DNS_DEDUP_WINDOW);
    };
    let Ok(mut conn) = redis_conn(&rg.client).await else {
        let key = format!(
            "pgflush:{tenant_id}:{}:{}",
            host.to_ascii_lowercase(),
            hour_utc.timestamp()
        );
        return sliding_window_accept(&key, DNS_DEDUP_WINDOW);
    };
    let bucket = hour_utc.format("%Y-%m-%d-%H").to_string();
    let key = format!(
        "{DNS_SUMMARY_PREFIX}{tenant_id}:{}:{bucket}",
        host.to_ascii_lowercase()
    );
    let acquired: Option<String> = redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(DNS_DEDUP_WINDOW.as_secs())
        .query_async(&mut conn)
        .await
        .unwrap_or(None);
    acquired.is_some()
}

/// Filter observations through the sliding window (memory + Redis). Duplicates are dropped
/// before aggregation so a chatty resolver cannot inflate `query_count`.
pub async fn window_filter_dns_observations(
    tenant_id: i64,
    obs: Vec<DnsObservation>,
) -> Vec<DnsObservation> {
    let mut out = Vec::with_capacity(obs.len());
    for o in obs {
        let fp = o.fingerprint();
        let local_key = format!("dnsseen:{tenant_id}:{fp}");
        if !sliding_window_accept(&local_key, DNS_DEDUP_WINDOW) {
            continue;
        }
        if let Some(false) = redis_mark_dns_seen(tenant_id, &fp).await {
            continue;
        }
        out.push(o);
    }
    out
}

// ── Media bomb helpers (pure; used by the stego layer + unit tests) ───────────

#[must_use]
pub fn media_content_length_rejected(content_length: u64) -> bool {
    content_length as usize > MAX_MEDIA_FILE_SIZE_BYTES
}

/// `true` if appending `chunk_len` would exceed the hard ceiling.
#[must_use]
pub fn media_chunk_would_exceed(accumulated: usize, chunk_len: usize) -> bool {
    accumulated.saturating_add(chunk_len) > MAX_MEDIA_FILE_SIZE_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_ceiling_is_2_mib() {
        assert_eq!(MAX_MEDIA_FILE_SIZE_BYTES, 2 * 1024 * 1024);
        assert!(media_content_length_rejected((2 * 1024 * 1024) as u64 + 1));
        assert!(!media_content_length_rejected(2 * 1024 * 1024));
        assert!(media_chunk_would_exceed(MAX_MEDIA_FILE_SIZE_BYTES - 10, 11));
        assert!(!media_chunk_would_exceed(100, 50));
    }

    #[test]
    fn dns_anomaly_rules() {
        let clean = DnsObservation {
            qtype: "TXT".into(),
            host: "example.com".into(),
            entropy: Some(3.1),
            txt_len: Some(40),
            min_ttl: Some(300),
            extra: json!({}),
        };
        assert!(!clean.is_validated_anomaly());
        let long = DnsObservation {
            txt_len: Some(201),
            ..clean.clone()
        };
        assert!(long.is_validated_anomaly());
        let hot = DnsObservation {
            entropy: Some(4.51),
            ..clean.clone()
        };
        assert!(hot.is_validated_anomaly());
        let ttl0 = DnsObservation {
            min_ttl: Some(0),
            ..clean
        };
        assert!(ttl0.is_validated_anomaly());
    }

    #[test]
    fn many_observations_collapse_to_one_summary_per_host() {
        let hour = hour_utc_bucket(chrono::Utc::now());
        let mut obs = Vec::new();
        for i in 0..50 {
            obs.push(DnsObservation {
                qtype: "TXT".into(),
                host: "evil.example".into(),
                entropy: Some(4.6 + (i as f64) * 0.001),
                txt_len: Some(80 + i),
                min_ttl: Some(300),
                extra: json!({"i": i}),
            });
        }
        obs.push(DnsObservation {
            qtype: "A".into(),
            host: "evil.example".into(),
            entropy: None,
            txt_len: None,
            min_ttl: Some(1),
            extra: json!({}),
        });
        // Clean host — must not produce a row.
        obs.push(DnsObservation {
            qtype: "TXT".into(),
            host: "benign.example".into(),
            entropy: Some(2.0),
            txt_len: Some(20),
            min_ttl: Some(600),
            extra: json!({}),
        });
        let sums = aggregate_dns_anomaly_summaries(&obs, hour);
        assert_eq!(sums.len(), 1, "only the anomalous host is persisted");
        assert_eq!(sums[0].host, "evil.example");
        assert_eq!(sums[0].query_count, 51);
        assert!(sums[0].max_entropy > 4.5);
        assert_eq!(sums[0].min_ttl, Some(1));
        assert_eq!(sums[0].max_txt_len, 80 + 49);
    }

    #[test]
    fn duplicate_fingerprints_do_not_inflate_count() {
        let hour = hour_utc_bucket(chrono::Utc::now());
        let o = DnsObservation {
            qtype: "TXT".into(),
            host: "dup.example".into(),
            entropy: Some(5.0),
            txt_len: Some(30),
            min_ttl: None,
            extra: json!({}),
        };
        let sums = aggregate_dns_anomaly_summaries(&[o.clone(), o.clone(), o], hour);
        assert_eq!(sums.len(), 1);
        assert_eq!(sums[0].query_count, 1);
    }

    #[test]
    fn sliding_window_rejects_second_sighting() {
        let key = format!("test-window-{}", uuid::Uuid::new_v4());
        assert!(sliding_window_accept(&key, Duration::from_secs(60)));
        assert!(!sliding_window_accept(&key, Duration::from_secs(60)));
    }

    #[test]
    fn hour_bucket_is_stable_inside_the_hour() {
        let a = chrono::DateTime::from_timestamp(1_700_000_100, 0).unwrap();
        let b = chrono::DateTime::from_timestamp(1_700_000_999, 0).unwrap();
        assert_eq!(hour_utc_bucket(a), hour_utc_bucket(b));
        assert_eq!(hour_utc_bucket(a).timestamp() % 3600, 0);
    }

    #[tokio::test]
    async fn scan_lock_second_acquire_is_held() {
        let tenant = 9_000_000 + (uuid::Uuid::new_v4().as_u128() % 1_000_000) as i64;
        let first = try_acquire_c2_scan_lock(tenant).await;
        match first {
            ScanLockOutcome::Unavailable => {
                // REDIS_URL is set but Redis is unreachable — skip integration.
                return;
            }
            ScanLockOutcome::Acquired => {}
            other => panic!("expected Acquired, got {other:?}"),
        }
        let second = try_acquire_c2_scan_lock(tenant).await;
        assert!(
            matches!(second, ScanLockOutcome::Held { .. }),
            "second acquire must 409-equivalent, got {second:?}"
        );
        release_c2_scan_lock(tenant).await;
        let third = try_acquire_c2_scan_lock(tenant).await;
        assert_eq!(third, ScanLockOutcome::Acquired);
        release_c2_scan_lock(tenant).await;
    }

    #[test]
    fn conflict_body_has_stable_code() {
        let v = c2_scan_conflict_body(300);
        assert_eq!(v.get("code").and_then(Value::as_str), Some("c2_scan_lock"));
        assert_eq!(v.get("ok").and_then(Value::as_bool), Some(false));
    }
}
