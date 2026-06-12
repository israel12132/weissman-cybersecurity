//! CISA Known Exploited Vulnerabilities (KEV) ingestion.
//!
//! Source: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
//!
//! CISA publishes the full KEV catalog as a single JSON file (~1.5 MB, ~1300 CVEs).
//! We download the entire feed, parse it, and upsert each entry into `kev_intel`.
//! Refresh cadence: every 6 hours (CISA updates a few times per week).
//!
//! There is no per-CVE lookup API. Either we have a local mirror of the feed and
//! join, or we don't. So this module's job is purely to keep the mirror fresh.
//!
//! Two public entry points:
//!   * [`is_kev_listed`] — synchronous lookup against the local mirror (used by the
//!     persist path when a finding has a CVE).
//!   * [`spawn_kev_refresh_worker`] — long-running task that refreshes the mirror.

use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const HTTP_TIMEOUT_SECS: u64 = 60;
const REFRESH_INTERVAL_SECS: u64 = 6 * 60 * 60; // 6h

#[derive(Debug, Clone)]
pub struct KevEntry {
    pub cve: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: Option<chrono::NaiveDate>,
    pub short_description: String,
    pub required_action: String,
    pub due_date: Option<chrono::NaiveDate>,
    pub known_ransomware_use: bool,
    pub notes: String,
}

#[derive(Debug, Deserialize)]
struct KevFeed {
    #[serde(default)]
    vulnerabilities: Vec<KevApiRow>,
}

#[derive(Debug, Deserialize)]
struct KevApiRow {
    #[serde(rename = "cveID", default)]
    cve_id: String,
    #[serde(rename = "vendorProject", default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(rename = "vulnerabilityName", default)]
    vulnerability_name: String,
    #[serde(rename = "dateAdded", default)]
    date_added: String,
    #[serde(rename = "shortDescription", default)]
    short_description: String,
    #[serde(rename = "requiredAction", default)]
    required_action: String,
    #[serde(rename = "dueDate", default)]
    due_date: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    known_ransomware_use: String, // "Known" | "Unknown"
    #[serde(default)]
    notes: String,
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .user_agent("Weissman-Intel/1.0 (security; +https://weissman.io)")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn parse_date(s: &str) -> Option<chrono::NaiveDate> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    chrono::NaiveDate::parse_from_str(t, "%Y-%m-%d").ok()
}

fn normalize_cve(raw: &str) -> String {
    raw.trim().to_ascii_uppercase()
}

/// Download the full KEV feed and upsert every row. Returns the number of rows.
pub async fn refresh_kev_catalog(pool: &PgPool) -> Result<usize, String> {
    let client = http_client();
    let resp = client.get(KEV_URL).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let feed: KevFeed = resp.json().await.map_err(|e| e.to_string())?;
    let mut count = 0usize;

    // Postgres can comfortably take a 1500-row INSERT; we keep transactions short
    // anyway to play nicely with other writers.
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    for row in feed.vulnerabilities {
        let cve = normalize_cve(&row.cve_id);
        if cve.is_empty() {
            continue;
        }
        let kr = row.known_ransomware_use.trim().eq_ignore_ascii_case("Known");
        sqlx::query(
            r#"INSERT INTO kev_intel (
                   cve, vendor_project, product, vulnerability_name,
                   date_added, short_description, required_action,
                   due_date, known_ransomware_use, notes, refreshed_at
               ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
               ON CONFLICT (cve) DO UPDATE SET
                   vendor_project        = EXCLUDED.vendor_project,
                   product               = EXCLUDED.product,
                   vulnerability_name    = EXCLUDED.vulnerability_name,
                   date_added            = EXCLUDED.date_added,
                   short_description     = EXCLUDED.short_description,
                   required_action       = EXCLUDED.required_action,
                   due_date              = EXCLUDED.due_date,
                   known_ransomware_use  = EXCLUDED.known_ransomware_use,
                   notes                 = EXCLUDED.notes,
                   refreshed_at          = now()"#,
        )
        .bind(&cve)
        .bind(&row.vendor_project)
        .bind(&row.product)
        .bind(&row.vulnerability_name)
        .bind(parse_date(&row.date_added))
        .bind(&row.short_description)
        .bind(&row.required_action)
        .bind(parse_date(&row.due_date))
        .bind(kr)
        .bind(&row.notes)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        count += 1;
    }
    tx.commit().await.map_err(|e| e.to_string())?;

    // Materialise kev flags onto vulnerabilities (back-fill rows persisted before
    // the feed had this CVE).
    let _ = sqlx::query(
        r#"UPDATE vulnerabilities v
              SET kev_listed           = TRUE,
                  kev_known_ransomware = k.known_ransomware_use,
                  kev_due_date         = k.due_date,
                  intel_enriched_at    = now()
             FROM kev_intel k
            WHERE k.cve = upper(v.raw_data->>'cve')
              AND (v.kev_listed = FALSE
                OR v.kev_known_ransomware IS DISTINCT FROM k.known_ransomware_use
                OR v.kev_due_date IS DISTINCT FROM k.due_date)"#,
    )
    .execute(pool)
    .await;

    Ok(count)
}

/// Synchronous lookup against the local mirror — used by the persist path.
pub async fn is_kev_listed(pool: &PgPool, cve: &str) -> Option<KevEntry> {
    let cve = normalize_cve(cve);
    if !cve.starts_with("CVE-") {
        return None;
    }
    let row = sqlx::query(
        r#"SELECT cve, vendor_project, product, vulnerability_name, date_added,
                  short_description, required_action, due_date,
                  known_ransomware_use, notes
             FROM kev_intel
            WHERE cve = $1"#,
    )
    .bind(&cve)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()?;
    use sqlx::Row;
    Some(KevEntry {
        cve,
        vendor_project: row.try_get("vendor_project").unwrap_or_default(),
        product: row.try_get("product").unwrap_or_default(),
        vulnerability_name: row.try_get("vulnerability_name").unwrap_or_default(),
        date_added: row.try_get("date_added").ok(),
        short_description: row.try_get("short_description").unwrap_or_default(),
        required_action: row.try_get("required_action").unwrap_or_default(),
        due_date: row.try_get("due_date").ok(),
        known_ransomware_use: row.try_get("known_ransomware_use").unwrap_or(false),
        notes: row.try_get("notes").unwrap_or_default(),
    })
}

/// One immediate KEV catalog refresh at boot (before the periodic loop).
/// Ensures `kev_listed` is populated on first login without waiting 6h.
pub fn bootstrap_kev_catalog(pool: Arc<PgPool>) {
    if !matches!(
        std::env::var("WEISSMAN_INTEL_KEV_ENABLED").as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Err(_)
    ) {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        match refresh_kev_catalog(&pool).await {
            Ok(n) => tracing::info!(target: "intel_kev", rows = n, "KEV bootstrap refresh complete"),
            Err(e) => tracing::warn!(target: "intel_kev", error = %e, "KEV bootstrap refresh failed"),
        }
    });
}

/// Long-running background refresh of the KEV mirror.
pub fn spawn_kev_refresh_worker(pool: Arc<PgPool>) {
    static SPAWNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if SPAWNED.set(()).is_err() {
        return;
    }
    if !matches!(
        std::env::var("WEISSMAN_INTEL_KEV_ENABLED").as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Err(_)
    ) {
        tracing::info!(target: "intel_kev", "KEV worker disabled by env");
        return;
    }
    tokio::spawn(async move {
        // First refresh happens 15s after boot so the rest of the stack is warm.
        tokio::time::sleep(Duration::from_secs(15)).await;
        loop {
            match refresh_kev_catalog(&pool).await {
                Ok(n) => tracing::info!(target: "intel_kev", rows = n, "KEV catalog refreshed"),
                Err(e) => tracing::warn!(target: "intel_kev", error = %e, "KEV refresh failed"),
            }
            tokio::time::sleep(Duration::from_secs(REFRESH_INTERVAL_SECS)).await;
        }
    });
}
