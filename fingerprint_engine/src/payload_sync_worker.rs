//! Autonomous Payload Sync Engine (Live Ammo Feeder).
//! Real async fetching from live sources (GitHub Raw nuclei-templates). No mocks. 60-day dynamic_payloads.

use chrono::Utc;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

const SYNC_INTERVAL_SECS: u64 = 12 * 3600; // 12 hours
const ROLLING_DAYS: i64 = 60;

/// One row to insert into dynamic_payloads. source_url = actual fetch URL for transparency.
#[derive(Debug)]
pub struct PayloadRow {
    pub target_library: String,
    pub payload_data: String,
    pub source: String,
    pub source_url: String,
}

fn parse_nuclei_yaml_to_native(
    yaml_body: &str,
    template_id: &str,
    source_url: &str,
) -> Option<PayloadRow> {
    let v: Value = serde_yaml::from_str(yaml_body).ok()?;
    let http = v.get("http")?;
    let reqs = http.as_array()?;
    let first = reqs.first()?;
    let method = first.get("method").and_then(Value::as_str).unwrap_or("GET");
    let path = first
        .get("path")
        .and_then(|p| p.as_str())
        .or_else(|| {
            first
                .get("path")
                .and_then(|p| p.as_array())
                .and_then(|a| a.first())
                .and_then(Value::as_str)
        })
        .unwrap_or("/");
    let body = first.get("body").and_then(Value::as_str).unwrap_or("");
    let payload_data = if method.eq_ignore_ascii_case("POST") && !body.is_empty() {
        body.to_string()
    } else {
        path.to_string()
    };
    if payload_data.is_empty() {
        return None;
    }
    Some(PayloadRow {
        target_library: format!("Nuclei-{}", template_id),
        payload_data,
        source: "nuclei-templates".to_string(),
        source_url: source_url.to_string(),
    })
}

const NUCLEI_RAW_BASE: &str =
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main";
const NUCLEI_TEMPLATE_PATHS: &[&str] = &[
    "http/cves/2024/CVE-2024-3400.yaml",
    "http/exposures/configs/nginx-status.yaml",
    "http/cves/2022/CVE-2022-42889.yaml",
    "http/cves/2017/CVE-2017-7525.yaml",
    "http/cves/2015/CVE-2015-4852.yaml",
    "http/cves/2020/CVE-2020-1747.yaml",
];

pub(crate) async fn fetch_from_sources_async() -> Vec<PayloadRow> {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Weissman-PayloadSync/1.0")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(target: "payload_sync", error = %e, "failed to build HTTP client");
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for path in NUCLEI_TEMPLATE_PATHS {
        let url = format!("{}/{}", NUCLEI_RAW_BASE, path);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(target: "payload_sync", %url, error = %e, "template fetch failed");
                continue;
            }
        };
        if !resp.status().is_success() {
            warn!(
                target: "payload_sync",
                %url,
                status = %resp.status(),
                "template fetch non-success status"
            );
            continue;
        }
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                warn!(target: "payload_sync", %url, error = %e, "template read body failed");
                continue;
            }
        };
        let lib = path
            .split('/')
            .next_back()
            .unwrap_or("nuclei")
            .replace(".yaml", "");
        if let Some(row) = parse_nuclei_yaml_to_native(&body, &lib, &url) {
            out.push(row);
        } else {
            out.push(PayloadRow {
                target_library: format!("Nuclei-{}", lib),
                payload_data: body,
                source: "nuclei-templates".to_string(),
                source_url: url,
            });
        }
    }
    out
}

async fn persist_payloads(
    intel_pool: &PgPool,
    app_pool: &PgPool,
    auth_pool: &PgPool,
    rows: &[PayloadRow],
) -> Result<(), sqlx::Error> {
    for r in rows {
        sqlx::query(
            "INSERT INTO dynamic_payloads (target_library, payload_data, source, source_url) VALUES ($1, $2, $3, $4)",
        )
        .bind(&r.target_library)
        .bind(&r.payload_data)
        .bind(&r.source)
        .bind(&r.source_url)
        .execute(intel_pool)
        .await?;
    }
    sqlx::query(
        "DELETE FROM dynamic_payloads WHERE added_at < now() - ($1::bigint * interval '1 day')",
    )
    .bind(ROLLING_DAYS)
    .execute(intel_pool)
    .await?;

    let now = Utc::now().to_rfc3339();
    let tenant_ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM tenants WHERE active = true")
        .fetch_all(auth_pool)
        .await?;

    for tid in tenant_ids {
        let mut tx = crate::db::begin_tenant_tx(app_pool, tid).await?;
        sqlx::query(
            "INSERT INTO system_configs (tenant_id, key, value, description) VALUES ($1, 'payload_sync_last_at', $2, 'Last run of autonomous payload sync')
             ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(tid)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO system_configs (tenant_id, key, value, description) VALUES ($1, 'payload_sync_active', 'true', 'Auto-Sync Active')
             ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(tid)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// Run one full sync cycle: fetch from live sources, write global payloads on `intel_pool`, upsert per-tenant sync keys on `app_pool`.
pub async fn run_sync_cycle_async(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
) {
    let rows = fetch_from_sources_async().await;
    if let Err(e) = persist_payloads(
        intel_pool.as_ref(),
        app_pool.as_ref(),
        auth_pool.as_ref(),
        &rows,
    )
    .await
    {
        tracing::error!(target: "payload_sync", error = %e, "persist to database failed");
        return;
    }
    tracing::info!(
        target: "payload_sync",
        count = rows.len(),
        "payload sync cycle complete"
    );
}

/// Worker loop: first run after 10s, then every 12h.
pub async fn run_worker_loop(
    app_pool: Arc<PgPool>,
    intel_pool: Arc<PgPool>,
    auth_pool: Arc<PgPool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(SYNC_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::time::sleep(Duration::from_secs(10)).await;
    loop {
        run_sync_cycle_async(app_pool.clone(), intel_pool.clone(), auth_pool.clone()).await;
        interval.tick().await;
    }
}
