//! Phase 5: Global zero-day ingestion — GitHub Advisories, NVD (NIST API), OSV.dev lookups;
//! LLM structuring via `identity_classifier::threat_chatter_to_exploit_signature_llm`;
//! SBOM match → emergency `run_cycle_async` across all tenants.

use crate::identity_classifier;
use crate::regex_util::never_matches;
use crate::orchestrator;
use crate::threat_intel_engine::{self, ThreatFeedItem};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

static LAST_EMERGENCY_SCAN_MS: AtomicU64 = AtomicU64::new(0);

const EMERGENCY_COOLDOWN_SECS: u64 = 900;
const LLM_BASE_DEFAULT: &str = "http://127.0.0.1:8000/v1";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug)]
pub enum GitHubAdvisoryFetchError {
    ApiTokenMissing,
    HttpClient(String),
    HttpSend(String),
    HttpStatus(u16),
    Json(String),
    NotArray,
}

impl std::fmt::Display for GitHubAdvisoryFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitHubAdvisoryFetchError::ApiTokenMissing => write!(f, "GITHUB_TOKEN not set"),
            GitHubAdvisoryFetchError::HttpClient(s) => write!(f, "client: {}", s),
            GitHubAdvisoryFetchError::HttpSend(s) => write!(f, "request: {}", s),
            GitHubAdvisoryFetchError::HttpStatus(c) => write!(f, "HTTP {}", c),
            GitHubAdvisoryFetchError::Json(s) => write!(f, "json: {}", s),
            GitHubAdvisoryFetchError::NotArray => write!(f, "response was not a JSON array"),
        }
    }
}

impl std::error::Error for GitHubAdvisoryFetchError {}

/// Fetch recent GitHub Security Advisories. **`GITHUB_TOKEN` required** (authenticated REST).
pub async fn fetch_github_advisories(
    limit: u32,
) -> Result<Vec<ThreatFeedItem>, GitHubAdvisoryFetchError> {
    let token = std::env::var("GITHUB_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(token) = token else {
        tracing::error!(
            target: "github_advisories",
            "GITHUB_TOKEN is not set — GitHub advisory ingestion disabled"
        );
        return Err(GitHubAdvisoryFetchError::ApiTokenMissing);
    };
    let cache_key = format!("gh:{}", limit.min(30));
    if let Some(hit) = crate::intel_http_cache::github_advisories_cache()
        .get(&cache_key)
        .await
    {
        if let Ok(parsed) = serde_json::from_slice::<Value>(hit.as_ref()) {
            return parse_github_advisory_array(&parsed);
        }
    }
    let client = crate::outbound_http::external_json_client()
        .map_err(|e| GitHubAdvisoryFetchError::HttpClient(e.to_string()))?;
    let url = format!(
        "https://api.github.com/advisories?per_page={}",
        limit.min(30)
    );
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static("WeissmanThreatIngest/1.0"),
    );
    headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))
            .map_err(|e| GitHubAdvisoryFetchError::HttpClient(e.to_string()))?,
    );
    let bytes = crate::outbound_http::get_bytes_with_retry(&client, &url, headers, 4, Some("github"))
        .await
        .map_err(|e| GitHubAdvisoryFetchError::HttpSend(e.to_string()))?;
    let _ = crate::intel_http_cache::github_advisories_cache()
        .insert(cache_key, std::sync::Arc::new(bytes.clone()))
        .await;
    let arr: Value = serde_json::from_slice(&bytes).map_err(|e| GitHubAdvisoryFetchError::Json(e.to_string()))?;
    parse_github_advisory_array(&arr)
}

fn parse_github_advisory_array(arr: &Value) -> Result<Vec<ThreatFeedItem>, GitHubAdvisoryFetchError> {
    let Some(items) = arr.as_array() else {
        return Err(GitHubAdvisoryFetchError::NotArray);
    };
    let mut out = Vec::new();
    for v in items {
        let ghsa = v
            .get("ghsa_id")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        let title = v
            .get("summary")
            .or_else(|| v.get("description"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .chars()
            .take(500)
            .collect::<String>();
        let desc = v
            .get("description")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .chars()
            .take(4000)
            .collect::<String>();
        let sev = v
            .get("severity")
            .and_then(|x| x.as_str())
            .unwrap_or("medium")
            .to_string();
        let published = v
            .get("published_at")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        out.push(ThreatFeedItem {
            source: "github_advisory".into(),
            external_id: ghsa,
            title: title.clone(),
            description: if desc.is_empty() { title } else { desc },
            severity: sev,
            published_at: published,
        });
    }
    Ok(out)
}

/// Query OSV for a single CVE id (enrichment); returns summary text if found.
pub async fn fetch_osv_cve_summary(cve_id: &str) -> Option<String> {
    let id = cve_id.trim();
    if !id.to_uppercase().starts_with("CVE-") {
        return None;
    }
    let cache = crate::intel_http_cache::osv_summary_cache();
    if let Some(hit) = cache.get(id).await {
        return Some(hit.as_ref().clone());
    }
    let client = crate::outbound_http::external_json_client().ok()?;
    let url = format!("https://api.osv.dev/v1/vulns/{}", id);
    let headers = reqwest::header::HeaderMap::new();
    let bytes = crate::outbound_http::get_bytes_with_retry(&client, &url, headers, 3, Some("osv"))
        .await
        .map_err(|e| {
            tracing::warn!(target: "osv", error = %e, cve_id = %id, "OSV lookup failed");
            e
        })
        .ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    let summary = v
        .get("summary")
        .or_else(|| v.get("details"))
        .and_then(|x| x.as_str())
        .map(|s| s.chars().take(2000).collect::<String>());
    if let Some(ref s) = summary {
        let _ = cache.insert(id.to_string(), std::sync::Arc::new(s.clone())).await;
    }
    summary
}

fn packages_from_signature(sig: &Value) -> Vec<String> {
    let mut pkgs: Vec<String> = sig
        .get("packages")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.trim().to_lowercase()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    pkgs.sort();
    pkgs.dedup();
    pkgs
}

fn severity_is_critical(item: &ThreatFeedItem, sig: &Value) -> bool {
    let s1 = item.severity.to_lowercase();
    if s1.contains("critical") {
        return true;
    }
    if let Some(sg) = sig.get("severity_guess").and_then(|x| x.as_str()) {
        return sg.to_lowercase() == "critical";
    }
    false
}

async fn persist_ingest_event(
    pool: &PgPool,
    tenant_id: i64,
    item: &ThreatFeedItem,
    matched: &[String],
    sig: &Value,
) -> Result<(), sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let pkgs_json = serde_json::to_string(matched).unwrap_or_else(|_| "[]".into());
    let sig_json = serde_json::to_string(sig).unwrap_or_else(|_| "{}".into());
    sqlx::query(
        r#"INSERT INTO threat_ingest_events (tenant_id, source, external_id, title, severity, matched_packages, exploit_signature_json)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (tenant_id, source, external_id) DO UPDATE SET
             title = EXCLUDED.title,
             severity = EXCLUDED.severity,
             matched_packages = EXCLUDED.matched_packages,
             exploit_signature_json = EXCLUDED.exploit_signature_json"#,
    )
    .bind(tenant_id)
    .bind(&item.source)
    .bind(&item.external_id)
    .bind(&item.title)
    .bind(&item.severity)
    .bind(&pkgs_json)
    .bind(&sig_json)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

async fn sbom_clients_matching(
    pool: &PgPool,
    tenant_id: i64,
    packages: &[String],
) -> Result<Vec<(i64, String)>, sqlx::Error> {
    if packages.is_empty() {
        return Ok(vec![]);
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let mut hits = Vec::new();
    for pkg in packages {
        let rows = sqlx::query(
            r#"SELECT DISTINCT client_id, package_name FROM client_sbom_components
               WHERE tenant_id = $1 AND lower(package_name) = lower($2)"#,
        )
        .bind(tenant_id)
        .bind(pkg)
        .fetch_all(&mut *tx)
        .await?;
        for r in rows {
            let cid: i64 = r.try_get("client_id").unwrap_or(0);
            let pn: String = r.try_get("package_name").unwrap_or_default();
            if cid > 0 {
                hits.push((cid, pn));
            }
        }
    }
    let _ = tx.commit().await;
    hits.sort_by_key(|x| x.0);
    hits.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    Ok(hits)
}

fn trigger_emergency_global_scan(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    telemetry: Arc<broadcast::Sender<String>>,
    reason: Value,
) {
    let now_ms = now_secs().saturating_mul(1000);
    let last = LAST_EMERGENCY_SCAN_MS.load(Ordering::SeqCst);
    if now_ms.saturating_sub(last) < EMERGENCY_COOLDOWN_SECS.saturating_mul(1000) {
        return;
    }
    LAST_EMERGENCY_SCAN_MS.store(now_ms, Ordering::SeqCst);
    let _ = telemetry.send(
        json!({
            "event": "emergency_swarm_scan",
            "severity": "critical",
            "message": "Zero-day / SBOM correlation — starting global orchestrator cycle",
            "detail": reason,
        })
        .to_string(),
    );
    tokio::spawn(async move {
        let Ok(permit) = crate::scan_concurrency::acquire_full_scan_permit().await else {
            metrics::counter!("weissman_emergency_scan_skipped_total", "reason" => "concurrency_timeout")
                .increment(1);
            return;
        };
        let _permit = permit;
        let tel = telemetry.clone();
        let _ = crate::panic_shield::catch_unwind_future(
            "emergency_global_cycle",
            async move {
                orchestrator::run_cycle_async(app_pool, intel_pool, auth_pool, Some(tel)).await;
            },
        )
        .await;
    });
}

/// One ingestion pass: fetch feeds, LLM signatures, SBOM match, optional emergency scan.
pub async fn run_ingest_cycle(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    telemetry: Arc<broadcast::Sender<String>>,
    llm_base: &str,
    llm_model: &str,
) {
    let mut items = match fetch_github_advisories(20).await {
        Ok(v) => v,
        Err(e) => {
            if matches!(e, GitHubAdvisoryFetchError::ApiTokenMissing) {
                tracing::error!(
                    target: "threat_ingest",
                    error = %e,
                    "GitHub advisory feed skipped — set GITHUB_TOKEN for authenticated GitHub API"
                );
            } else {
                tracing::warn!(
                    target: "threat_ingest",
                    error = %e,
                    "GitHub Security Advisories fetch failed; continuing with other feeds only"
                );
            }
            vec![]
        }
    };
    items.extend(threat_intel_engine::fetch_nvd_recent(3).await);

    let tenant_ids: Vec<i64> =
        sqlx::query_scalar::<_, i64>("SELECT id FROM tenants WHERE active = true ORDER BY id")
            .fetch_all(auth_pool.as_ref())
            .await
            .unwrap_or_default();

    for item in items {
        let mut chatter = format!("{}\n{}", item.title, item.description);
        if let Some(cve) = extract_cve(&item.title).or_else(|| extract_cve(&item.description)) {
            if let Some(osv) = fetch_osv_cve_summary(&cve).await {
                chatter.push_str("\nOSV: ");
                chatter.push_str(&osv);
            }
        }

        let sig = identity_classifier::threat_chatter_to_exploit_signature_llm(
            &chatter,
            llm_base,
            llm_model,
            None,
        )
        .await
                .unwrap_or_else(|| {
                    json!({
                        "packages": [],
                        "cve_id": Value::Null,
                        "severity_guess": item.severity.to_lowercase(),
                        "safe_probe": Value::Null,
                    })
                });

        let pkgs = packages_from_signature(&sig);
        let critical = severity_is_critical(&item, &sig);
        let mut triggered_emergency = false;

        for &tid in &tenant_ids {
            let hits = match sbom_clients_matching(app_pool.as_ref(), tid, &pkgs).await {
                Ok(h) => h,
                Err(_) => continue,
            };
            if hits.is_empty() {
                continue;
            }
            let matched_names: Vec<String> = hits.iter().map(|(_, p)| p.clone()).collect();
            if let Err(e) =
                persist_ingest_event(app_pool.as_ref(), tid, &item, &matched_names, &sig).await
            {
                eprintln!("[Weissman][Ingest] persist tenant {}: {}", tid, e);
            }
            let _ = telemetry.send(
                json!({
                    "event": "threat_ingest_sbom_hit",
                    "severity": if critical { "critical" } else { "high" },
                    "tenant_id": tid.to_string(),
                    "external_id": item.external_id,
                    "matched": matched_names,
                })
                .to_string(),
            );
            if critical && !triggered_emergency {
                triggered_emergency = true;
                trigger_emergency_global_scan(
                    app_pool.clone(),
                    intel_pool.clone(),
                    auth_pool.clone(),
                    telemetry.clone(),
                    json!({
                        "source": item.source,
                        "external_id": item.external_id,
                        "title": item.title,
                    }),
                );
            }
        }
    }
}

fn cve_regex() -> &'static regex::Regex {
    static R: OnceLock<regex::Regex> = OnceLock::new();
    R.get_or_init(|| regex::Regex::new(r"CVE-\d{4}-\d+").unwrap_or_else(|_| never_matches()))
}

fn extract_cve(text: &str) -> Option<String> {
    cve_regex().find(text).map(|m| m.as_str().to_uppercase())
}

/// Background worker: `WEISSMAN_THREAT_INGEST_CRON=1`, interval `WEISSMAN_THREAT_INGEST_INTERVAL_SECS` (min 600, default 3600).
pub fn spawn_ingest_worker(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
    telemetry: Arc<broadcast::Sender<String>>,
) {
    tokio::spawn(async move {
        let interval_secs: u64 = std::env::var("WEISSMAN_THREAT_INGEST_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|&n| n >= 600)
            .unwrap_or(3600);
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if std::env::var("WEISSMAN_THREAT_INGEST_CRON")
                .map(|v| v != "1" && !v.eq_ignore_ascii_case("true"))
                .unwrap_or(true)
            {
                continue;
            }
            let llm_base = std::env::var("WEISSMAN_LLM_BASE_URL")
                .or_else(|_| std::env::var("LLM_BASE_URL"))
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| LLM_BASE_DEFAULT.to_string());
            let llm_model = std::env::var("WEISSMAN_LLM_MODEL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_default();
            run_ingest_cycle(
                app_pool.clone(),
                intel_pool.clone(),
                auth_pool.clone(),
                telemetry.clone(),
                &llm_base,
                &llm_model,
            )
            .await;
        }
    });
}
