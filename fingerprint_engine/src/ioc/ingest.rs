//! Feed orchestration + per-tenant retrohunt.
//!
//! [`run_all_feeds`] pulls every configured source, upserts into the global
//! store, records a per-source audit row, then expires stale indicators.
//!
//! [`retrohunt_tenant`] loads the active global indicator set plus the tenant's
//! watchlist into a [`MatchSet`], then replays recent endpoint telemetry
//! (process hashes shipped in `agent_metric_samples`) against it — a newly
//! ingested indicator thus surfaces historical compromise without waiting for
//! the next agent poll. Each hit is a tenant-scoped `ioc_sightings` row and
//! bumps the entity's UEBA risk score (IOC ⇄ UEBA fusion).

use super::feeds::{self, FeedSource};
use super::store::{self, SightingInput};
use super::IocType;
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use std::time::Instant;

/// Outcome of one feed source this cycle.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FeedOutcome {
    pub source: String,
    pub status: String,
    pub fetched: i32,
    pub inserted: i32,
    pub updated: i32,
    pub error: String,
}

/// Aggregate result of a full ingestion cycle.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IngestReport {
    pub outcomes: Vec<FeedOutcome>,
    pub total_fetched: i64,
    pub total_inserted: i64,
    pub total_updated: i64,
    pub expired: i64,
}

/// Run every configured feed once. Never panics; a failing feed is recorded and
/// the cycle continues with the others.
pub async fn run_all_feeds(pool: &PgPool) -> IngestReport {
    // Load dashboard-managed feed credentials (DB) into the process cache before
    // deciding which feeds are configured / fetching them.
    super::creds::refresh_from_db(pool).await;
    let feeds_to_run = feeds::enabled_feeds();
    let mut report = IngestReport {
        outcomes: Vec::new(),
        total_fetched: 0,
        total_inserted: 0,
        total_updated: 0,
        expired: 0,
    };
    for source in feeds_to_run {
        report.outcomes.push(run_one_feed(pool, source).await);
    }
    for o in &report.outcomes {
        report.total_fetched += i64::from(o.fetched);
        report.total_inserted += i64::from(o.inserted);
        report.total_updated += i64::from(o.updated);
    }
    report.expired = store::expire_stale(pool).await.unwrap_or(0) as i64;
    tracing::info!(
        target: "ioc_feeds",
        fetched = report.total_fetched,
        inserted = report.total_inserted,
        updated = report.total_updated,
        expired = report.expired,
        "IOC feed cycle complete"
    );
    report
}

async fn run_one_feed(pool: &PgPool, source: FeedSource) -> FeedOutcome {
    let started = Instant::now();
    let run_id = store::start_feed_run(pool, source.as_str()).await.ok();
    let (status, fetched, inserted, updated, error) = match feeds::fetch(source).await {
        Ok(indicators) => {
            let fetched = indicators.len() as i32;
            match store::upsert_indicators(pool, &indicators).await {
                Ok((ins, upd)) => ("ok", fetched, ins as i32, upd as i32, String::new()),
                Err(e) => ("error", fetched, 0, 0, format!("persist: {e}")),
            }
        }
        Err(feeds::FeedError::NotConfigured(k)) => {
            ("skipped", 0, 0, 0, format!("not configured ({k})"))
        }
        Err(e) => ("error", 0, 0, 0, e.to_string()),
    };
    let dur = started.elapsed().as_millis() as i64;
    if let Some(id) = run_id {
        let _ =
            store::finish_feed_run(pool, id, status, fetched, inserted, updated, &error, dur).await;
    }
    if status == "error" {
        tracing::warn!(target: "ioc_feeds", source = source.as_str(), error = %error, "feed failed");
    }
    FeedOutcome {
        source: source.as_str().to_string(),
        status: status.to_string(),
        fetched,
        inserted,
        updated,
        error,
    }
}

/// Result of a tenant retrohunt.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetrohuntReport {
    pub observables_scanned: i64,
    pub matches: i64,
    pub sightings_created: i64,
}

const RETRO_SAMPLE_LIMIT: i64 = 5000;
const RETRO_MATCHSET_CAP: i64 = 500_000;

/// Replay recent endpoint telemetry for a tenant against the active indicator
/// set + the tenant watchlist. Records a sighting (and a risk bump) per hit.
pub async fn retrohunt_tenant(pool: &PgPool, tenant_id: i64) -> Result<RetrohuntReport, String> {
    let mut matchset = store::load_active_matchset(pool, RETRO_MATCHSET_CAP)
        .await
        .map_err(|e| format!("load indicators: {e}"))?;
    // Merge the tenant's own watchlist into the same matcher.
    if let Ok(wl) = store::load_watchlist_matchset(pool, tenant_id).await {
        matchset.merge(wl);
    }
    if matchset.is_empty() {
        return Ok(RetrohuntReport {
            observables_scanned: 0,
            matches: 0,
            sightings_created: 0,
        });
    }

    // Pull recent samples' metrics JSON for this tenant.
    let samples = {
        let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
            .await
            .map_err(|e| format!("tenant tx: {e}"))?;
        let rows = sqlx::query(
            r#"SELECT agent_id, client_id, metrics
                 FROM agent_metric_samples
                WHERE sampled_at > now() - interval '7 days'
                ORDER BY sampled_at DESC
                LIMIT $1"#,
        )
        .bind(RETRO_SAMPLE_LIMIT)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("samples query: {e}"))?;
        let _ = tx.commit().await;
        rows
    };

    if samples.len() as i64 >= RETRO_SAMPLE_LIMIT {
        tracing::warn!(
            target: "ioc",
            tenant_id,
            limit = RETRO_SAMPLE_LIMIT,
            "retrohunt sample window hit the cap; older telemetry not scanned this cycle"
        );
    }

    let mut scanned = 0i64;
    let mut matches = 0i64;
    let mut sightings = 0i64;
    // Dedup (agent, value) so a recurring hash doesn't spam sightings (or re-bump
    // risk) each cycle. Pre-seed from the last 48h of persisted sightings so the
    // dedup survives across scheduler runs, not just within a single sweep.
    let mut seen: HashSet<(String, String)> = store::recent_sighting_keys(pool, tenant_id, 48)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();

    for row in samples {
        let agent_id: String = row.try_get("agent_id").unwrap_or_default();
        let client_id: Option<i64> = row.try_get("client_id").ok();
        let metrics: Value = row.try_get("metrics").unwrap_or(Value::Null);
        for (ty, value) in observables_from_metrics(&metrics) {
            scanned += 1;
            if let Some(hit) = matchset.match_observable(ty, &value) {
                matches += 1;
                let key = (agent_id.clone(), hit.value_norm.clone());
                if !seen.insert(key) {
                    continue;
                }
                let input = SightingInput {
                    client_id,
                    agent_id: agent_id.clone(),
                    indicator_id: None,
                    ioc_type: hit.ioc_type.as_str().to_string(),
                    value: hit.value_norm.clone(),
                    context: context_for(ty),
                    finding_id: None,
                    severity: hit.severity.clone(),
                    confidence: hit.confidence,
                    source: hit.source.clone(),
                    detail: format!(
                        "retrohunt: endpoint {} observable matched {} indicator",
                        ty.as_str(),
                        hit.source
                    ),
                };
                if store::record_sighting(pool, tenant_id, &input)
                    .await
                    .is_ok()
                {
                    sightings += 1;
                    // Fuse into UEBA risk: a confirmed IOC on a host is a strong signal.
                    let weight = crate::ueba_models::risk::ioc_sighting_weight(&hit.severity);
                    let _ = crate::ueba_models::risk::record_risk_event(
                        pool,
                        tenant_id,
                        "agent",
                        &agent_id,
                        client_id,
                        weight,
                        &format!("ioc:{}:{}", hit.source, hit.value_norm),
                    )
                    .await;
                }
            }
        }
    }

    Ok(RetrohuntReport {
        observables_scanned: scanned,
        matches,
        sightings_created: sightings,
    })
}

fn context_for(ty: IocType) -> String {
    match ty {
        IocType::Sha256 | IocType::Sha1 | IocType::Md5 => "agent_process_hash".to_string(),
        IocType::Ipv4 | IocType::Ipv6 | IocType::Cidr => "agent_remote_ip".to_string(),
        IocType::Domain => "agent_dns".to_string(),
        _ => "agent_telemetry".to_string(),
    }
}

/// Extract host observables (process hashes + any shipped remote IPs/domains)
/// from a `ueba_sample` metrics object.
pub fn observables_from_metrics(metrics: &Value) -> Vec<(IocType, String)> {
    let mut out = Vec::new();
    let Some(obj) = metrics.as_object() else {
        return out;
    };
    // process_sha256: ["<hex>", ...]
    if let Some(arr) = obj.get("process_sha256").and_then(Value::as_array) {
        for h in arr.iter().filter_map(Value::as_str) {
            if h.len() == 64 {
                out.push((IocType::Sha256, h.to_string()));
            }
        }
    }
    // top_process_hashes: {"name": "<hex>", ...}
    if let Some(map) = obj.get("top_process_hashes").and_then(Value::as_object) {
        for v in map.values().filter_map(Value::as_str) {
            if v.len() == 64 {
                out.push((IocType::Sha256, v.to_string()));
            }
        }
    }
    // Optional remote observables a future agent sample may ship.
    if let Some(arr) = obj.get("remote_ips").and_then(Value::as_array) {
        for ip in arr.iter().filter_map(Value::as_str) {
            // Classify so IPv6 peers aren't mislabeled as IPv4.
            let ty = super::guess_type(ip)
                .filter(|t| matches!(t, IocType::Ipv4 | IocType::Ipv6))
                .unwrap_or(IocType::Ipv4);
            out.push((ty, ip.to_string()));
        }
    }
    if let Some(arr) = obj.get("dns_queries").and_then(Value::as_array) {
        for d in arr.iter().filter_map(Value::as_str) {
            out.push((IocType::Domain, d.to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn observables_extracts_hashes_from_both_shapes() {
        let m = json!({
            "process_sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "top_process_hashes": {"nginx": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            "remote_ips": ["1.2.3.4"],
            "dns_queries": ["evil.com"]
        });
        let obs = observables_from_metrics(&m);
        assert!(obs.iter().any(|(t, _)| *t == IocType::Sha256));
        assert!(obs
            .iter()
            .any(|(t, v)| *t == IocType::Ipv4 && v == "1.2.3.4"));
        assert!(obs
            .iter()
            .any(|(t, v)| *t == IocType::Domain && v == "evil.com"));
        // Two distinct hashes.
        assert_eq!(obs.iter().filter(|(t, _)| *t == IocType::Sha256).count(), 2);
    }

    #[test]
    fn observables_empty_on_non_object() {
        assert!(observables_from_metrics(&Value::Null).is_empty());
        assert!(observables_from_metrics(&json!({})).is_empty());
    }

    #[test]
    fn context_maps_type_to_channel() {
        assert_eq!(context_for(IocType::Sha256), "agent_process_hash");
        assert_eq!(context_for(IocType::Ipv4), "agent_remote_ip");
        assert_eq!(context_for(IocType::Domain), "agent_dns");
    }
}
