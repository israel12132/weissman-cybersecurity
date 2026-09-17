//! Persistence for the IOC store.
//!
//! * The indicator store (`ioc_indicators`) and feed audit (`ioc_feed_runs`)
//!   are GLOBAL — queried straight off the pool (no RLS / no tenant GUC).
//! * Sightings and the watchlist are tenant-scoped — every access goes through
//!   [`crate::db::begin_tenant_tx`] so Postgres RLS enforces isolation.
//!
//! All queries use the runtime `sqlx::query` API (not the compile-time macros),
//! matching the rest of the codebase — so no `.sqlx` offline cache is required.

use super::decay;
use super::matching::{LoadedIndicator, MatchSet};
use super::{Indicator, IocType};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

/// Upsert a batch of indicators into the global store.
/// Returns `(inserted, updated)` counts using the `xmax = 0` freshness trick.
pub async fn upsert_indicators(
    pool: &PgPool,
    indicators: &[Indicator],
) -> Result<(u64, u64), sqlx::Error> {
    let mut inserted = 0u64;
    let mut updated = 0u64;
    for ind in indicators {
        if !ind.is_valid() {
            continue;
        }
        let ttl_days = decay::default_ttl_days(ind.ioc_type) as i32;
        let tags = Value::Array(ind.tags.iter().cloned().map(Value::String).collect());
        let row = sqlx::query(
            r#"INSERT INTO ioc_indicators
                 (ioc_type, value, value_norm, source, confidence, severity, tlp,
                  malware_family, mitre, tags, reference_url,
                  first_seen, last_seen, expires_at, active, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
                       now(), now(), now() + make_interval(days => $12), true, now(), now())
               ON CONFLICT (ioc_type, value_norm, source) DO UPDATE SET
                   last_seen     = now(),
                   updated_at    = now(),
                   active        = true,
                   expires_at    = now() + make_interval(days => $12),
                   -- Keep the strongest signal we have ever seen for this key.
                   confidence    = GREATEST(ioc_indicators.confidence, EXCLUDED.confidence),
                   severity      = EXCLUDED.severity,
                   malware_family= CASE WHEN EXCLUDED.malware_family <> '' THEN EXCLUDED.malware_family ELSE ioc_indicators.malware_family END,
                   tags          = EXCLUDED.tags
               RETURNING (xmax = 0) AS inserted"#,
        )
        .bind(ind.ioc_type.as_str())
        .bind(&ind.value)
        .bind(&ind.value_norm)
        .bind(&ind.source)
        .bind(i16::from(ind.confidence))
        .bind(&ind.severity)
        .bind(&ind.tlp)
        .bind(&ind.malware_family)
        .bind(&ind.mitre)
        .bind(&tags)
        .bind(&ind.reference_url)
        .bind(ttl_days)
        .fetch_one(pool)
        .await?;
        if row.try_get::<bool, _>("inserted").unwrap_or(false) {
            inserted += 1;
        } else {
            updated += 1;
        }
    }
    Ok((inserted, updated))
}

/// Record the start of a feed run; returns the run id.
pub async fn start_feed_run(pool: &PgPool, source: &str) -> Result<i64, sqlx::Error> {
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO ioc_feed_runs (source, status, started_at)
           VALUES ($1, 'running', now()) RETURNING id"#,
    )
    .bind(source)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

/// Finalize a feed run with outcome + counters.
#[allow(clippy::too_many_arguments)]
pub async fn finish_feed_run(
    pool: &PgPool,
    run_id: i64,
    status: &str,
    fetched: i32,
    inserted: i32,
    updated: i32,
    error: &str,
    duration_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"UPDATE ioc_feed_runs
              SET status = $2, fetched = $3, inserted = $4, updated = $5,
                  error = $6, duration_ms = $7, finished_at = now()
            WHERE id = $1"#,
    )
    .bind(run_id)
    .bind(status)
    .bind(fetched)
    .bind(inserted)
    .bind(updated)
    .bind(error)
    .bind(duration_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Deactivate indicators past their hard expiry. Returns the number retired.
pub async fn expire_stale(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        r#"UPDATE ioc_indicators SET active = false, updated_at = now()
            WHERE active = true AND expires_at IS NOT NULL AND expires_at < now()"#,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

/// Recent feed-run health rows for the API.
pub async fn recent_feed_runs(pool: &PgPool, limit: i64) -> Result<Vec<Value>, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT source, status, fetched, inserted, updated, error,
                  started_at, finished_at, duration_ms
             FROM ioc_feed_runs ORDER BY started_at DESC LIMIT $1"#,
    )
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "source":      r.try_get::<String, _>("source").unwrap_or_default(),
                "status":      r.try_get::<String, _>("status").unwrap_or_default(),
                "fetched":     r.try_get::<i32, _>("fetched").unwrap_or(0),
                "inserted":    r.try_get::<i32, _>("inserted").unwrap_or(0),
                "updated":     r.try_get::<i32, _>("updated").unwrap_or(0),
                "error":       r.try_get::<String, _>("error").unwrap_or_default(),
                "duration_ms": r.try_get::<i64, _>("duration_ms").unwrap_or(0),
                "started_at":  r.try_get::<chrono::DateTime<chrono::Utc>, _>("started_at").ok().map(|d| d.to_rfc3339()),
                "finished_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("finished_at").ok().map(|d| d.to_rfc3339()),
            })
        })
        .collect())
}

/// Aggregate store stats for the feed-health dashboard.
pub async fn indicator_stats(pool: &PgPool) -> Result<Value, sqlx::Error> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ioc_indicators WHERE active = true")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    let by_type = sqlx::query(
        r#"SELECT ioc_type, COUNT(*)::bigint AS n FROM ioc_indicators
            WHERE active = true GROUP BY ioc_type ORDER BY n DESC"#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    let by_source = sqlx::query(
        r#"SELECT source, COUNT(*)::bigint AS n FROM ioc_indicators
            WHERE active = true GROUP BY source ORDER BY n DESC"#,
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    Ok(json!({
        "total": total,
        "by_type": by_type.into_iter().map(|r| json!({
            "type": r.try_get::<String,_>("ioc_type").unwrap_or_default(),
            "count": r.try_get::<i64,_>("n").unwrap_or(0),
        })).collect::<Vec<_>>(),
        "by_source": by_source.into_iter().map(|r| json!({
            "source": r.try_get::<String,_>("source").unwrap_or_default(),
            "count": r.try_get::<i64,_>("n").unwrap_or(0),
        })).collect::<Vec<_>>(),
    }))
}

/// Query indicators for the API, applying decay to report effective confidence.
pub async fn query_indicators(
    pool: &PgPool,
    type_filter: Option<&str>,
    source_filter: Option<&str>,
    search: Option<&str>,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    // Escape LIKE metacharacters so a user searching for "10.0.0.0_24" or a
    // literal "%" matches literally rather than as a wildcard.
    let search_like = search.map(|s| {
        let escaped = s
            .trim()
            .to_ascii_lowercase()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        format!("%{escaped}%")
    });
    let rows = sqlx::query(
        r#"SELECT id, ioc_type, value, value_norm, source, confidence, severity, tlp,
                  malware_family, mitre, tags, reference_url,
                  first_seen, last_seen, expires_at,
                  EXTRACT(EPOCH FROM (now() - first_seen))::double precision AS age_secs
             FROM ioc_indicators
            WHERE active = true
              AND ($1::text IS NULL OR ioc_type = $1)
              AND ($2::text IS NULL OR source = $2)
              AND ($3::text IS NULL OR lower(value_norm) LIKE $3 ESCAPE '\')
            ORDER BY last_seen DESC
            LIMIT $4"#,
    )
    .bind(type_filter)
    .bind(source_filter)
    .bind(search_like.as_deref())
    .bind(limit.clamp(1, 2000))
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(row_to_indicator_json).collect())
}

fn row_to_indicator_json(r: sqlx::postgres::PgRow) -> Value {
    let base_conf: i16 = r.try_get("confidence").unwrap_or(0);
    let type_str: String = r.try_get("ioc_type").unwrap_or_default();
    let age_secs: f64 = r.try_get("age_secs").unwrap_or(0.0);
    let ioc_type = IocType::from_str_lenient(&type_str).unwrap_or(IocType::Domain);
    let eff = decay::effective_confidence(base_conf.max(0) as u8, age_secs / 86_400.0, ioc_type);
    json!({
        "id":             r.try_get::<i64, _>("id").unwrap_or(0),
        "type":           type_str,
        "value":          r.try_get::<String, _>("value").unwrap_or_default(),
        "source":         r.try_get::<String, _>("source").unwrap_or_default(),
        "confidence":     base_conf,
        "effective_confidence": (eff.round() as i64),
        "severity":       r.try_get::<String, _>("severity").unwrap_or_default(),
        "tlp":            r.try_get::<String, _>("tlp").unwrap_or_default(),
        "malware_family": r.try_get::<String, _>("malware_family").unwrap_or_default(),
        "mitre":          r.try_get::<String, _>("mitre").unwrap_or_default(),
        "tags":           r.try_get::<Value, _>("tags").unwrap_or_else(|_| json!([])),
        "reference_url":  r.try_get::<String, _>("reference_url").unwrap_or_default(),
        "first_seen":     r.try_get::<chrono::DateTime<chrono::Utc>, _>("first_seen").ok().map(|d| d.to_rfc3339()),
        "last_seen":      r.try_get::<chrono::DateTime<chrono::Utc>, _>("last_seen").ok().map(|d| d.to_rfc3339()),
    })
}

/// Load the active indicator set into a [`MatchSet`], applying decay so retired
/// indicators never match. Capped at `max` rows (newest first) for bounded memory.
pub async fn load_active_matchset(pool: &PgPool, max: i64) -> Result<MatchSet, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT ioc_type, value_norm, source, severity, confidence,
                  EXTRACT(EPOCH FROM (now() - first_seen))::double precision AS age_secs
             FROM ioc_indicators
            WHERE active = true
            ORDER BY last_seen DESC
            LIMIT $1"#,
    )
    .bind(max.clamp(1, 1_000_000))
    .fetch_all(pool)
    .await?;
    let mut ms = MatchSet::new();
    for r in rows {
        let type_str: String = r.try_get("ioc_type").unwrap_or_default();
        let Some(ioc_type) = IocType::from_str_lenient(&type_str) else {
            continue;
        };
        let base: i16 = r.try_get("confidence").unwrap_or(0);
        let age_secs: f64 = r.try_get("age_secs").unwrap_or(0.0);
        let eff = decay::effective_confidence(base.max(0) as u8, age_secs / 86_400.0, ioc_type);
        if eff < decay::RETIRE_CONFIDENCE {
            continue;
        }
        ms.insert(LoadedIndicator {
            ioc_type,
            value_norm: r.try_get::<String, _>("value_norm").unwrap_or_default(),
            source: r.try_get::<String, _>("source").unwrap_or_default(),
            severity: r.try_get::<String, _>("severity").unwrap_or_default(),
            confidence: eff.round() as u8,
        });
    }
    Ok(ms)
}

/// Build the bounded, endpoint-evaluable indicator payload pushed to agents for
/// the `ioc_endpoint_match` detection: `{sha256, ipv4, ipv6, cidr, domains}`.
/// Highest-confidence first, capped per class so the push stays lean.
pub async fn endpoint_match_payload(pool: &PgPool, per_class: i64) -> serde_json::Value {
    let cap = per_class.clamp(1, 20_000);
    // Only the classes the endpoint agent can actually evaluate on live host
    // telemetry: SHA-256 process hashes and remote IPv4/IPv6/CIDR peers. The
    // agent has no DNS-cache reader, so domains would be shipped-but-unmatched;
    // sha1/md5 aren't collected either. Don't waste the fetch budget on them.
    let rows = sqlx::query(
        r#"SELECT ioc_type, value_norm FROM ioc_indicators
            WHERE active = true
              AND ioc_type IN ('sha256','ipv4','ipv6','cidr')
            ORDER BY confidence DESC, last_seen DESC
            LIMIT $1"#,
    )
    .bind(cap * 4)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut sha256: Vec<String> = Vec::new();
    let mut ipv4: Vec<String> = Vec::new();
    let mut ipv6: Vec<String> = Vec::new();
    let mut cidr: Vec<String> = Vec::new();
    for r in rows {
        let t: String = r.try_get("ioc_type").unwrap_or_default();
        let v: String = r.try_get("value_norm").unwrap_or_default();
        if v.is_empty() {
            continue;
        }
        match t.as_str() {
            "sha256" if (sha256.len() as i64) < cap => sha256.push(v),
            "ipv4" if (ipv4.len() as i64) < cap => ipv4.push(v),
            "ipv6" if (ipv6.len() as i64) < cap => ipv6.push(v),
            "cidr" if (cidr.len() as i64) < cap => cidr.push(v),
            _ => {}
        }
    }
    json!({
        "ueba_ioc_push": true,
        "sha256": sha256,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "cidr": cidr,
    })
}

// ─── Tenant-scoped: sightings ───────────────────────────────────────────────

/// A single sighting to persist.
#[derive(Debug, Clone)]
pub struct SightingInput {
    pub client_id: Option<i64>,
    pub agent_id: String,
    pub indicator_id: Option<i64>,
    pub ioc_type: String,
    pub value: String,
    pub context: String,
    pub finding_id: Option<String>,
    pub severity: String,
    pub confidence: u8,
    pub source: String,
    pub detail: String,
}

/// Insert a sighting within a tenant transaction. Returns its new id.
pub async fn record_sighting(
    pool: &PgPool,
    tenant_id: i64,
    s: &SightingInput,
) -> Result<i64, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO ioc_sightings
             (tenant_id, client_id, agent_id, indicator_id, ioc_type, value,
              context, finding_id, severity, confidence, source, detail, seen_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now())
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(s.client_id)
    .bind(&s.agent_id)
    .bind(s.indicator_id)
    .bind(&s.ioc_type)
    .bind(&s.value)
    .bind(&s.context)
    .bind(s.finding_id.as_deref())
    .bind(&s.severity)
    .bind(i16::from(s.confidence))
    .bind(&s.source)
    .bind(&s.detail)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Keys `(agent_id, value)` of sightings seen within the last `since_hours`,
/// used to suppress duplicate retrohunt sightings (and duplicate risk bumps)
/// across scheduler cycles. Bounded to a sane cap.
pub async fn recent_sighting_keys(
    pool: &PgPool,
    tenant_id: i64,
    since_hours: i64,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT agent_id, value FROM ioc_sightings
            WHERE seen_at > now() - make_interval(hours => $1)
            LIMIT 200000"#,
    )
    .bind(since_hours.clamp(1, 720) as i32)
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.try_get::<String, _>("agent_id").unwrap_or_default(),
                r.try_get::<String, _>("value").unwrap_or_default(),
            )
        })
        .collect())
}

/// Query recent sightings for a tenant.
pub async fn query_sightings(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, client_id, agent_id, ioc_type, value, context, finding_id,
                  severity, confidence, source, detail, seen_at
             FROM ioc_sightings
            ORDER BY seen_at DESC LIMIT $1"#,
    )
    .bind(limit.clamp(1, 1000))
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id":         r.try_get::<i64, _>("id").unwrap_or(0),
                "client_id":  r.try_get::<i64, _>("client_id").ok(),
                "agent_id":   r.try_get::<String, _>("agent_id").unwrap_or_default(),
                "type":       r.try_get::<String, _>("ioc_type").unwrap_or_default(),
                "value":      r.try_get::<String, _>("value").unwrap_or_default(),
                "context":    r.try_get::<String, _>("context").unwrap_or_default(),
                "finding_id": r.try_get::<String, _>("finding_id").ok(),
                "severity":   r.try_get::<String, _>("severity").unwrap_or_default(),
                "confidence": r.try_get::<i16, _>("confidence").unwrap_or(0),
                "source":     r.try_get::<String, _>("source").unwrap_or_default(),
                "detail":     r.try_get::<String, _>("detail").unwrap_or_default(),
                "seen_at":    r.try_get::<chrono::DateTime<chrono::Utc>, _>("seen_at").ok().map(|d| d.to_rfc3339()),
            })
        })
        .collect())
}

// ─── Tenant-scoped: watchlist ───────────────────────────────────────────────

/// Add a custom watchlist indicator for a tenant. Upserts on (type, value_norm).
pub async fn add_watchlist(
    pool: &PgPool,
    tenant_id: i64,
    ioc_type: IocType,
    raw_value: &str,
    severity: &str,
    note: &str,
    created_by: &str,
) -> Result<i64, sqlx::Error> {
    let refanged = super::refang(raw_value);
    let value_norm = super::normalize_value(ioc_type, &refanged);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let id: i64 = sqlx::query_scalar(
        r#"INSERT INTO ioc_watchlist
             (tenant_id, ioc_type, value, value_norm, severity, confidence, note, created_by, active, created_at)
           VALUES ($1,$2,$3,$4,$5,90,$6,$7,true, now())
           ON CONFLICT (tenant_id, ioc_type, value_norm) DO UPDATE SET
             severity = EXCLUDED.severity, note = EXCLUDED.note, active = true
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(ioc_type.as_str())
    .bind(&refanged)
    .bind(&value_norm)
    .bind(severity)
    .bind(note)
    .bind(created_by)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// List a tenant's active watchlist.
pub async fn list_watchlist(
    pool: &PgPool,
    tenant_id: i64,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, ioc_type, value, severity, confidence, note, created_by, created_at
             FROM ioc_watchlist WHERE active = true
            ORDER BY created_at DESC LIMIT $1"#,
    )
    .bind(limit.clamp(1, 1000))
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id":         r.try_get::<i64, _>("id").unwrap_or(0),
                "type":       r.try_get::<String, _>("ioc_type").unwrap_or_default(),
                "value":      r.try_get::<String, _>("value").unwrap_or_default(),
                "severity":   r.try_get::<String, _>("severity").unwrap_or_default(),
                "confidence": r.try_get::<i16, _>("confidence").unwrap_or(0),
                "note":       r.try_get::<String, _>("note").unwrap_or_default(),
                "created_by": r.try_get::<String, _>("created_by").unwrap_or_default(),
                "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at").ok().map(|d| d.to_rfc3339()),
            })
        })
        .collect())
}

/// Soft-delete (deactivate) a watchlist entry for a tenant.
pub async fn delete_watchlist(pool: &PgPool, tenant_id: i64, id: i64) -> Result<bool, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let res = sqlx::query("UPDATE ioc_watchlist SET active = false WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(res.rows_affected() > 0)
}

/// Load a tenant's watchlist into a MatchSet (merged into retrohunt matching).
pub async fn load_watchlist_matchset(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<MatchSet, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT ioc_type, value_norm, severity, confidence
             FROM ioc_watchlist WHERE active = true LIMIT 100000"#,
    )
    .fetch_all(&mut *tx)
    .await?;
    let _ = tx.commit().await;
    let mut ms = MatchSet::new();
    for r in rows {
        let type_str: String = r.try_get("ioc_type").unwrap_or_default();
        let Some(ioc_type) = IocType::from_str_lenient(&type_str) else {
            continue;
        };
        ms.insert(LoadedIndicator {
            ioc_type,
            value_norm: r.try_get::<String, _>("value_norm").unwrap_or_default(),
            source: "watchlist".into(),
            severity: r
                .try_get::<String, _>("severity")
                .unwrap_or_else(|_| "high".into()),
            confidence: r.try_get::<i16, _>("confidence").unwrap_or(90).max(0) as u8,
        });
    }
    Ok(ms)
}
