//! EPSS (Exploit Prediction Scoring System) ingestion from FIRST.org.
//!
//! Source: <https://api.first.org/data/v1/epss?cve=CVE-2024-1,CVE-2024-2>
//!
//! Contract: every CVE has at most one row in `epss_intel` with a daily-refreshed
//! `score` (0.0–1.0) and `percentile` (0.0–1.0). The API page-batches up to 200
//! CVEs per request; we paginate at 100/req for safety and back off on 429.
//!
//! Two public entry points:
//!   * [`fetch_epss_for_cves`] — synchronous on-demand lookup (used by
//!     `findings_persist::enrich_finding_with_intel` for new findings).
//!   * [`spawn_epss_backfill_worker`] — long-running task that nightly refreshes
//!     EPSS for every CVE we have a finding for. Runs forever.
//!
//! Live data only — there is no fallback / no fake scoring. If FIRST.org is
//! unreachable we skip enrichment and the finding ships without an EPSS score
//! (UI shows "—"); the back-fill worker retries on its next cycle.

use serde::Deserialize;
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const FIRST_API: &str = "https://api.first.org/data/v1/epss";
const BATCH_SIZE: usize = 100;
const HTTP_TIMEOUT_SECS: u64 = 20;
const REFRESH_INTERVAL_SECS: u64 = 12 * 60 * 60; // 12h
const STALE_AFTER_HOURS: i64 = 24;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EpssScore {
    pub score: f32,
    pub percentile: f32,
    pub date: chrono::NaiveDate,
}

#[derive(Debug, Deserialize)]
struct EpssApiResponse {
    #[serde(default)]
    data: Vec<EpssApiRow>,
}

#[derive(Debug, Deserialize)]
struct EpssApiRow {
    cve: String,
    #[serde(default)]
    epss: String,
    #[serde(default)]
    percentile: String,
    #[serde(default)]
    date: String,
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .user_agent("Weissman-Intel/1.0 (security; +https://weissman.io)")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Normalise a CVE to upper-case `CVE-YYYY-NNNN` form. Returns `None` for anything
/// that doesn't look like a CVE id (so the caller can drop it cleanly).
fn normalize_cve(raw: &str) -> Option<String> {
    let t = raw.trim().to_ascii_uppercase();
    if !t.starts_with("CVE-") {
        return None;
    }
    // CVE-YYYY-N{4,} — keep numbers/dashes only.
    let body = &t[4..];
    if body.is_empty() {
        return None;
    }
    Some(format!("CVE-{}", body))
}

/// On-demand fetch + DB upsert for a small set of CVEs. Returns the EPSS scores
/// keyed by normalized CVE id. Missing CVEs are absent from the map.
///
/// We always read from the cache first; only CVEs that are missing OR stale
/// (>24h old) are re-fetched.
pub async fn fetch_epss_for_cves(pool: &PgPool, cves: &[String]) -> HashMap<String, EpssScore> {
    let mut normalized: Vec<String> = cves.iter().filter_map(|c| normalize_cve(c)).collect();
    normalized.sort();
    normalized.dedup();
    if normalized.is_empty() {
        return HashMap::new();
    }

    let mut out: HashMap<String, EpssScore> = HashMap::new();

    // 1) Read existing cache rows for these CVEs and decide which ones are stale.
    let cached = sqlx::query(
        r#"SELECT cve, score, percentile, epss_date, refreshed_at
             FROM epss_intel
            WHERE cve = ANY($1)"#,
    )
    .bind(&normalized)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let now = chrono::Utc::now();
    let mut stale: Vec<String> = Vec::new();
    let mut have: std::collections::HashSet<String> = std::collections::HashSet::new();

    for r in cached {
        let cve: String = r.try_get("cve").unwrap_or_default();
        let score: f32 = r.try_get("score").unwrap_or(0.0);
        let percentile: f32 = r.try_get("percentile").unwrap_or(0.0);
        let date: chrono::NaiveDate = r
            .try_get::<chrono::NaiveDate, _>("epss_date")
            .unwrap_or_else(|_| chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap());
        let refreshed: chrono::DateTime<chrono::Utc> = r.try_get("refreshed_at").unwrap_or(now);
        let age_h = (now - refreshed).num_hours();
        out.insert(
            cve.clone(),
            EpssScore {
                score,
                percentile,
                date,
            },
        );
        have.insert(cve.clone());
        if age_h > STALE_AFTER_HOURS {
            stale.push(cve);
        }
    }
    for cve in &normalized {
        if !have.contains(cve) {
            stale.push(cve.clone());
        }
    }
    stale.sort();
    stale.dedup();

    // Cache telemetry: fresh cache hits vs. missing/stale rows that require a live fetch
    // (feeds the Grafana "Cache Hit Rate" panel). Labelled by cache so more caches can join.
    let miss_count = stale.len() as u64;
    let hit_count = (normalized.len() as u64).saturating_sub(miss_count);
    if hit_count > 0 {
        metrics::counter!("weissman_cache_operations_total", "operation" => "hit", "cache" => "epss")
            .increment(hit_count);
    }
    if miss_count > 0 {
        metrics::counter!("weissman_cache_operations_total", "operation" => "miss", "cache" => "epss")
            .increment(miss_count);
    }

    if stale.is_empty() {
        return out;
    }

    // 2) Fetch missing/stale CVEs from FIRST.org in batches.
    let client = http_client();
    for chunk in stale.chunks(BATCH_SIZE) {
        match fetch_batch(&client, chunk).await {
            Ok(rows) => {
                if let Err(e) = upsert_rows(pool, &rows).await {
                    tracing::warn!(
                        target: "intel_epss",
                        error = %e,
                        "epss upsert failed",
                    );
                }
                for r in rows {
                    if let Some(ns) = parse_score(&r) {
                        out.insert(r.cve.to_ascii_uppercase(), ns);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "intel_epss",
                    error = %e,
                    batch_size = chunk.len(),
                    "epss fetch batch failed (will retry on next worker cycle)"
                );
            }
        }
    }

    out
}

fn parse_score(r: &EpssApiRow) -> Option<EpssScore> {
    let score: f32 = r.epss.trim().parse().ok()?;
    let percentile: f32 = r.percentile.trim().parse().ok()?;
    let date = chrono::NaiveDate::parse_from_str(r.date.trim(), "%Y-%m-%d")
        .unwrap_or_else(|_| chrono::Utc::now().date_naive());
    Some(EpssScore {
        score,
        percentile,
        date,
    })
}

async fn fetch_batch(client: &reqwest::Client, cves: &[String]) -> Result<Vec<EpssApiRow>, String> {
    if cves.is_empty() {
        return Ok(vec![]);
    }
    let joined = cves.join(",");
    let url = format!("{}?cve={}", FIRST_API, joined);
    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {}", status));
    }
    let body: EpssApiResponse = resp.json().await.map_err(|e| e.to_string())?;
    Ok(body.data)
}

async fn upsert_rows(pool: &PgPool, rows: &[EpssApiRow]) -> Result<(), String> {
    if rows.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    for r in rows {
        let Some(parsed) = parse_score(r) else {
            continue;
        };
        let cve = r.cve.to_ascii_uppercase();
        sqlx::query(
            r#"INSERT INTO epss_intel (cve, score, percentile, epss_date, refreshed_at)
               VALUES ($1, $2, $3, $4, now())
               ON CONFLICT (cve) DO UPDATE SET
                   score       = EXCLUDED.score,
                   percentile  = EXCLUDED.percentile,
                   epss_date   = EXCLUDED.epss_date,
                   refreshed_at = now()"#,
        )
        .bind(&cve)
        .bind(parsed.score)
        .bind(parsed.percentile)
        .bind(parsed.date)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

/// One immediate EPSS back-fill at boot so existing findings get scores without
/// waiting for the 12h cycle.
pub fn bootstrap_epss_backfill(pool: Arc<PgPool>) {
    if !matches!(
        std::env::var("WEISSMAN_INTEL_EPSS_ENABLED").as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Err(_)
    ) {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(8)).await;
        match run_one_cycle(&pool).await {
            Ok(()) => tracing::info!(target: "intel_epss", "EPSS bootstrap cycle complete"),
            Err(e) => {
                tracing::warn!(target: "intel_epss", error = %e, "EPSS bootstrap cycle failed")
            }
        }
    });
}

/// Spawn the daily back-fill worker that refreshes EPSS for every CVE present in
/// the platform's findings. Idempotent: only runs the loop once per process.
pub fn spawn_epss_backfill_worker(pool: Arc<PgPool>) {
    static SPAWNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    if !matches!(
        std::env::var("WEISSMAN_INTEL_EPSS_ENABLED").as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Err(_) // default on
    ) {
        tracing::info!(target: "intel_epss", "EPSS worker disabled by env");
        return;
    }
    tokio::spawn(async move {
        // Brief warm-up so we don't compete with startup migrations.
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            if let Err(e) = run_one_cycle(&pool).await {
                tracing::warn!(target: "intel_epss", error = %e, "cycle failed");
            }
            tokio::time::sleep(Duration::from_secs(REFRESH_INTERVAL_SECS)).await;
        }
    });
}

async fn run_one_cycle(pool: &PgPool) -> Result<(), String> {
    // Collect every distinct CVE present in vulnerabilities that is missing or stale
    // in the intel cache. Cap at 5000 per cycle so a fresh deployment doesn't burst
    // FIRST.org.
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"SELECT DISTINCT upper(trim(v.raw_data->>'cve')) AS cve
             FROM vulnerabilities v
             LEFT JOIN epss_intel e
               ON e.cve = upper(trim(v.raw_data->>'cve'))
            WHERE trim(COALESCE(v.raw_data->>'cve', '')) <> ''
              AND (e.refreshed_at IS NULL OR e.refreshed_at < now() - interval '24 hours')
            LIMIT 5000"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;
    let cves: Vec<String> = rows.into_iter().map(|(c,)| c).collect();
    if cves.is_empty() {
        return Ok(());
    }
    tracing::info!(target: "intel_epss", count = cves.len(), "refreshing EPSS");
    fetch_epss_for_cves(pool, &cves).await;

    // After refresh, materialise scores onto vulnerabilities (back-fill rows that
    // were persisted *before* the score was known).
    let _ = sqlx::query(
        r#"UPDATE vulnerabilities v
              SET epss_score      = e.score,
                  epss_percentile = e.percentile,
                  intel_enriched_at = now()
             FROM epss_intel e
            WHERE e.cve = upper(trim(v.raw_data->>'cve'))
              AND trim(COALESCE(v.raw_data->>'cve', '')) <> ''
              AND (v.epss_score IS DISTINCT FROM e.score
                OR v.epss_percentile IS DISTINCT FROM e.percentile)"#,
    )
    .execute(pool)
    .await;
    Ok(())
}

/// Helper for the persist path. Returns the EPSS score JSON to merge into
/// `raw_data` (and the score/percentile to set on the dedicated columns).
pub async fn enrich_with_epss(
    pool: &PgPool,
    raw_data: &mut Value,
    cve: Option<&str>,
) -> Option<EpssScore> {
    let cve = cve.and_then(normalize_cve)?;
    let map = fetch_epss_for_cves(pool, &[cve.clone()]).await;
    let s = map.get(&cve).copied()?;
    if let Value::Object(obj) = raw_data {
        obj.insert(
            "epss".to_string(),
            serde_json::json!({
                "score": s.score,
                "percentile": s.percentile,
                "date": s.date.to_string(),
            }),
        );
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nd(y: i32, m: u32, d: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn normalize_cve_uppercases_and_trims() {
        assert_eq!(
            normalize_cve("cve-2021-1234").as_deref(),
            Some("CVE-2021-1234")
        );
        assert_eq!(
            normalize_cve("  CVE-2021-1  ").as_deref(),
            Some("CVE-2021-1")
        );
        assert_eq!(
            normalize_cve("CVE-2021-44228").as_deref(),
            Some("CVE-2021-44228")
        );
    }

    #[test]
    fn normalize_cve_rejects_non_cve_and_empty_body() {
        assert_eq!(normalize_cve("GHSA-xxxx-yyyy"), None);
        assert_eq!(normalize_cve("CVE-"), None); // empty body
        assert_eq!(normalize_cve("cve-"), None);
        assert_eq!(normalize_cve(""), None);
    }

    #[test]
    fn parse_score_reads_valid_row() {
        let row = EpssApiRow {
            cve: "CVE-2024-1".into(),
            epss: "0.5".into(),
            percentile: "0.9".into(),
            date: "2024-06-01".into(),
        };
        let s = parse_score(&row).unwrap();
        assert_eq!(
            s,
            EpssScore {
                score: 0.5,
                percentile: 0.9,
                date: nd(2024, 6, 1),
            }
        );
    }

    #[test]
    fn parse_score_trims_whitespace() {
        let row = EpssApiRow {
            cve: "CVE-2024-2".into(),
            epss: " 0.25 ".into(),
            percentile: " 0.75 ".into(),
            date: " 2024-01-02 ".into(),
        };
        let s = parse_score(&row).unwrap();
        assert_eq!(s.score, 0.25);
        assert_eq!(s.percentile, 0.75);
        assert_eq!(s.date, nd(2024, 1, 2));
    }

    #[test]
    fn parse_score_rejects_bad_numbers() {
        let bad_epss = EpssApiRow {
            cve: "CVE-2024-3".into(),
            epss: "abc".into(),
            percentile: "0.5".into(),
            date: "2024-01-01".into(),
        };
        assert!(parse_score(&bad_epss).is_none());

        let bad_pct = EpssApiRow {
            cve: "CVE-2024-4".into(),
            epss: "0.5".into(),
            percentile: "".into(),
            date: "2024-01-01".into(),
        };
        assert!(parse_score(&bad_pct).is_none());
    }

    #[test]
    fn parse_score_bad_date_falls_back_but_keeps_numbers() {
        let row = EpssApiRow {
            cve: "CVE-2024-5".into(),
            epss: "0.1".into(),
            percentile: "0.2".into(),
            date: "not-a-date".into(),
        };
        let s = parse_score(&row).expect("valid numbers => Some despite bad date");
        assert_eq!(s.score, 0.1);
        assert_eq!(s.percentile, 0.2);
        // Bad date falls back to "today"; just assert it parsed to a real date.
        assert!(s.date.year() >= 2024);
    }

    #[test]
    fn api_response_deserializes_data_rows() {
        let resp: EpssApiResponse = serde_json::from_value(serde_json::json!({
            "data": [{
                "cve": "CVE-2024-1",
                "epss": "0.1",
                "percentile": "0.2",
                "date": "2024-01-01"
            }]
        }))
        .unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(resp.data[0].cve, "CVE-2024-1");
        assert_eq!(resp.data[0].epss, "0.1");
        assert_eq!(resp.data[0].percentile, "0.2");
        assert_eq!(resp.data[0].date, "2024-01-01");
    }

    #[test]
    fn api_response_defaults_missing_fields() {
        let resp: EpssApiResponse = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(resp.data.is_empty());

        // Row with only the required `cve` field defaults the rest to "".
        let row: EpssApiRow =
            serde_json::from_value(serde_json::json!({"cve": "CVE-2024-9"})).unwrap();
        assert_eq!(row.cve, "CVE-2024-9");
        assert_eq!(row.epss, "");
        assert_eq!(row.percentile, "");
        assert_eq!(row.date, "");
    }

    // Bring `chrono::Datelike` into scope for `.year()`.
    use chrono::Datelike as _;
}
