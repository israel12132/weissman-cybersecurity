//! Back-fill CVE identifiers and EPSS/KEV columns on existing findings.
//!
//! Many engines (e.g. supply_chain) store OSV GHSA ids without populating `cve`.
//! We resolve GHSA → CVE via the public OSV API, then materialize intel scores.

use serde_json::Value;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;

const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns/";
const HTTP_TIMEOUT_SECS: u64 = 20;
const BATCH_LIMIT: i64 = 500;

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .user_agent("Weissman-Intel/1.0 (security; +https://weissman.io)")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn normalize_cve(raw: &str) -> Option<String> {
    let t = raw.trim().to_ascii_uppercase();
    if t.starts_with("CVE-") && t.len() > 8 {
        Some(t)
    } else {
        None
    }
}

/// Extract the first CVE from a finding JSON or stored raw_data blob.
pub fn extract_cve_from_value(v: &Value) -> Option<String> {
    for key in ["cve", "cve_id", "cveId"] {
        if let Some(s) = v.get(key).and_then(Value::as_str) {
            if let Some(c) = normalize_cve(s) {
                return Some(c);
            }
        }
    }
    if let Some(arr) = v.get("cves").and_then(Value::as_array) {
        for item in arr {
            if let Some(s) = item.as_str() {
                if let Some(c) = normalize_cve(s) {
                    return Some(c);
                }
            }
        }
    }
    if let Some(arr) = v.get("osv_ids").and_then(Value::as_array) {
        for item in arr {
            if let Some(s) = item.as_str() {
                if let Some(c) = normalize_cve(s) {
                    return Some(c);
                }
            }
        }
    }
    // Nested engine payload (`raw_data.raw` shape).
    if let Some(raw) = v.get("raw") {
        if let Some(c) = extract_cve_from_value(raw) {
            return Some(c);
        }
    }
    None
}

async fn resolve_osv_id_to_cve(client: &reqwest::Client, osv_id: &str) -> Option<String> {
    let id = osv_id.trim();
    if id.is_empty() {
        return None;
    }
    if let Some(c) = normalize_cve(id) {
        return Some(c);
    }
    let url = format!("{OSV_VULN_URL}{id}");
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let data: Value = resp.json().await.ok()?;
    if let Some(arr) = data.get("aliases").and_then(Value::as_array) {
        for a in arr {
            if let Some(s) = a.as_str() {
                if let Some(c) = normalize_cve(s) {
                    return Some(c);
                }
            }
        }
    }
    None
}

async fn resolve_cve_for_row(client: &reqwest::Client, raw_data: &Value) -> Option<String> {
    if let Some(c) = extract_cve_from_value(raw_data) {
        return Some(c);
    }
    let osv_ids = raw_data
        .get("raw")
        .and_then(|r| r.get("osv_ids"))
        .or_else(|| raw_data.get("osv_ids"))
        .and_then(Value::as_array)?;
    for item in osv_ids {
        let id = item.as_str()?;
        if let Some(c) = resolve_osv_id_to_cve(client, id).await {
            return Some(c);
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    None
}

/// One pass: populate missing CVE ids, refresh EPSS cache, materialize scores + KEV flags.
pub async fn run_findings_intel_backfill(pool: &PgPool) -> Result<(usize, usize), String> {
    let client = http_client();

    let rows = sqlx::query(
        r#"SELECT id, raw_data
             FROM vulnerabilities
            WHERE (epss_score IS NULL AND NOT kev_listed)
               OR trim(COALESCE(raw_data->>'cve', '')) = ''
            ORDER BY id
            LIMIT $1"#,
    )
    .bind(BATCH_LIMIT)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    let mut cve_updates = 0usize;
    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let raw_data: Value = r
            .try_get::<Value, _>("raw_data")
            .unwrap_or(Value::Null);
        let Some(cve) = resolve_cve_for_row(&client, &raw_data).await else {
            continue;
        };
        let mut patched = raw_data.clone();
        if let Value::Object(obj) = &mut patched {
            obj.insert("cve".into(), Value::String(cve.clone()));
        }
        let res = sqlx::query(
            r#"UPDATE vulnerabilities
                  SET raw_data = $2::jsonb,
                      intel_enriched_at = COALESCE(intel_enriched_at, now())
                WHERE id = $1"#,
        )
        .bind(id)
        .bind(&patched)
        .execute(pool)
        .await;
        if res.is_ok() {
            cve_updates += 1;
        }
    }

    // Refresh EPSS mirror for all distinct non-empty CVEs in findings.
    let cve_rows: Vec<(String,)> = sqlx::query_as(
        r#"SELECT DISTINCT upper(trim(raw_data->>'cve')) AS cve
             FROM vulnerabilities
            WHERE trim(COALESCE(raw_data->>'cve', '')) <> ''"#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    let cves: Vec<String> = cve_rows.into_iter().map(|(c,)| c).collect();
    if !cves.is_empty() {
        crate::intel_epss::fetch_epss_for_cves(pool, &cves).await;
    }

    let epss_res = sqlx::query(
        r#"UPDATE vulnerabilities v
              SET epss_score       = e.score,
                  epss_percentile  = e.percentile,
                  intel_enriched_at = now()
             FROM epss_intel e
            WHERE e.cve = upper(trim(v.raw_data->>'cve'))
              AND trim(COALESCE(v.raw_data->>'cve', '')) <> ''
              AND (v.epss_score IS DISTINCT FROM e.score
                OR v.epss_percentile IS DISTINCT FROM e.percentile)"#,
    )
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;

    let kev_res = sqlx::query(
        r#"UPDATE vulnerabilities v
              SET kev_listed           = true,
                  kev_known_ransomware = k.known_ransomware_use,
                  kev_due_date         = k.due_date,
                  intel_enriched_at    = now()
             FROM kev_intel k
            WHERE k.cve = upper(trim(v.raw_data->>'cve'))
              AND trim(COALESCE(v.raw_data->>'cve', '')) <> ''
              AND NOT v.kev_listed"#,
    )
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?;

    Ok((cve_updates, epss_res.rows_affected() as usize + kev_res.rows_affected() as usize))
}

pub fn bootstrap_findings_intel_backfill(pool: Arc<PgPool>) {
    if !matches!(
        std::env::var("WEISSMAN_INTEL_EPSS_ENABLED").as_deref(),
        Ok("1") | Ok("true") | Ok("yes") | Err(_)
    ) {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(12)).await;
        match run_findings_intel_backfill(pool.as_ref()).await {
            Ok((cve_n, intel_n)) => {
                tracing::info!(
                    target: "intel_backfill",
                    cve_rows_updated = cve_n,
                    intel_rows_updated = intel_n,
                    "Findings intel backfill complete"
                );
            }
            Err(e) => {
                tracing::warn!(target: "intel_backfill", error = %e, "Findings intel backfill failed");
            }
        }
    });
}
