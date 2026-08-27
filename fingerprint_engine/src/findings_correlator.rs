//! Findings correlation & deduplication.
//!
//! Different engines often detect the *same vulnerability* from different angles
//! (e.g. `asm`, `leak_hunter`, and `bola_idor` may all flag the same IDOR on the
//! same endpoint). Naïvely persisting each as a separate `vulnerabilities` row
//! creates 3 tickets for 1 problem — analyst fatigue, distorted KPIs.
//!
//! This module collapses those signals into **finding clusters**. A cluster is
//! identified by the triple `(target, vuln_signature, cwe)` hashed to SHA-256
//! after uniform filtered normalisation (`finding_identity`). Each
//! `vulnerabilities` row points to its cluster via `cluster_id`. The cluster
//! row carries the *aggregate* (max severity, engines list, CVE set, KEV flag,
//! first/last seen) plus a **corroboration boost**: when network and agent
//! planes both fire on the same identity, severity jumps to Critical.
//!
//! `upsert_cluster_for_finding` runs from the **cluster ingest worker** after the
//! persist transaction commits — never inside the hot findings write TX.

use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};

use crate::finding_identity::{
    self, corroborate_cluster_severity, corroboration_cvss_floor, derive_vuln_signature,
    engine_plane, normalize_cwe, normalize_target,
};

/// Stable cluster identity: sha256(normalised_target | normalised_signature | normalised_cwe).
///
/// We intentionally exclude `engine` — that's the whole point of correlation: two
/// engines that fire on the same vuln must land in the same cluster.
pub fn build_cluster_key(target: &str, vuln_signature: &str, cwe: &str) -> String {
    finding_identity::build_cluster_key(target, vuln_signature, cwe)
}

/// Severity weight for `MAX(...)` rollups. Higher = worse.
fn sev_weight(s: &str) -> i32 {
    finding_identity::sev_weight(s)
}

#[derive(Debug, Clone, Default)]
pub struct ClusterAttrs<'a> {
    pub target: &'a str,
    pub engine: &'a str,
    pub source: &'a str,
    pub title: &'a str,
    pub severity: &'a str,
    pub cwe: &'a str,
    pub cve: Option<&'a str>,
    pub cvss: Option<f64>,
    pub epss_score: Option<f32>,
    pub kev_listed: bool,
    /// True only when the underlying `vulnerabilities` row was freshly INSERTed (not a
    /// re-detection). Controls whether `member_count` is incremented, so the corroboration
    /// count reflects distinct members rather than how many times the cluster was rescanned.
    pub is_new_member: bool,
    /// Pre-computed signature from persist (avoids re-deriving from a stub finding).
    pub vuln_signature: Option<&'a str>,
    /// Persist-time cluster key (hinted route template). When set, upsert must
    /// not re-hash from a hint-less target or public vs admin paths collide.
    pub cluster_key: Option<&'a str>,
}

/// Upsert a cluster row for a single finding. Returns the cluster `id` so the
/// caller can write it onto `vulnerabilities.cluster_id`.
pub async fn upsert_cluster_for_finding(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
    finding: &Value,
    attrs: ClusterAttrs<'_>,
) -> Result<(i64, String), String> {
    let signature = attrs
        .vuln_signature
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| derive_vuln_signature(finding, attrs.title));
    let key = attrs
        .cluster_key
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| build_cluster_key(attrs.target, &signature, attrs.cwe));
    let target_norm = normalize_target(attrs.target);
    let cwe_norm = normalize_cwe(attrs.cwe);
    let plane = engine_plane(attrs.engine);

    // Atomic upsert + aggregate refresh in one statement. arrays are accumulated
    // with `array_distinct(... || ARRAY[...])` so engines/sources/cves grow but
    // never duplicate. `max_severity` here is the *native* member-max; corroboration
    // (cross-plane / multi-engine) is applied in a follow-up UPDATE from the
    // merged `engines` array so the boost sees every detector, not just this one.
    let sev_w_new = sev_weight(attrs.severity);
    // Only a genuinely new member grows member_count; a re-detection (upsert UPDATE branch on
    // `vulnerabilities`) must add 0, else the corroboration count inflates once per rescan.
    let member_inc: i32 = if attrs.is_new_member { 1 } else { 0 };
    let cvss_new = attrs.cvss.unwrap_or(0.0);
    let epss_new: f32 = attrs.epss_score.unwrap_or(0.0);
    let cve_arr: Vec<String> = attrs
        .cve
        .map(|c| vec![c.trim().to_ascii_uppercase()])
        .unwrap_or_default();

    let row = sqlx::query(
        r#"
        INSERT INTO weissman_finding_clusters (
            tenant_id, client_id, cluster_key, target, cwe, vuln_signature, title,
            member_count, engines, sources, cves,
            max_severity, native_severity, watermark_severity, max_cvss, max_epss, kev_listed,
            engine_planes, corroboration_boost,
            status, first_seen_at, last_seen_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            1, ARRAY[$8]::text[], ARRAY[$9]::text[], $10::text[],
            $11, $11, $11, $12, $13, $14,
            ARRAY[$17]::text[], 'none',
            'OPEN', now(), now(), now()
        )
        ON CONFLICT (tenant_id, client_id, cluster_key) DO UPDATE SET
            member_count   = weissman_finding_clusters.member_count + $16::int,
            engines        = (
                SELECT ARRAY(SELECT DISTINCT unnest(weissman_finding_clusters.engines || ARRAY[$8::text]))
            ),
            sources        = (
                SELECT ARRAY(SELECT DISTINCT unnest(weissman_finding_clusters.sources || ARRAY[$9::text]))
            ),
            cves           = (
                SELECT ARRAY(SELECT DISTINCT unnest(weissman_finding_clusters.cves    || $10::text[]))
            ),
            engine_planes  = (
                SELECT ARRAY(SELECT DISTINCT unnest(weissman_finding_clusters.engine_planes || ARRAY[$17::text]))
            ),
            native_severity = CASE
                WHEN $15::int > (CASE weissman_finding_clusters.native_severity
                                     WHEN 'critical' THEN 5
                                     WHEN 'high'     THEN 4
                                     WHEN 'medium'   THEN 3
                                     WHEN 'low'      THEN 2
                                     WHEN 'info'     THEN 1
                                     ELSE 0 END)
                THEN $11
                ELSE weissman_finding_clusters.native_severity
            END,
            max_cvss       = GREATEST(COALESCE(weissman_finding_clusters.max_cvss, 0), $12),
            max_epss       = GREATEST(COALESCE(weissman_finding_clusters.max_epss, 0), $13),
            kev_listed     = weissman_finding_clusters.kev_listed OR $14,
            title          = CASE WHEN $11 = 'critical' AND weissman_finding_clusters.native_severity <> 'critical'
                                  THEN $7
                                  ELSE weissman_finding_clusters.title END,
            last_seen_at   = now(),
            updated_at     = now()
        RETURNING id, engines, native_severity, watermark_severity, corroboration_boost
        "#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&key)
    .bind(&target_norm)
    .bind(&cwe_norm)
    .bind(&signature)
    .bind(attrs.title)
    .bind(attrs.engine)
    .bind(attrs.source)
    .bind(&cve_arr)
    .bind(attrs.severity)
    .bind(cvss_new)
    .bind(epss_new)
    .bind(attrs.kev_listed)
    .bind(sev_w_new)
    .bind(member_inc)
    .bind(plane)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| format!("cluster upsert: {e}"))?;

    let id: i64 = row.try_get("id").unwrap_or(0);
    let engines: Vec<String> = row.try_get("engines").unwrap_or_default();
    let native: String = row
        .try_get::<Option<String>, _>("native_severity")
        .ok()
        .flatten()
        .unwrap_or_else(|| attrs.severity.to_string());
    let watermark: String = row
        .try_get::<Option<String>, _>("watermark_severity")
        .ok()
        .flatten()
        .unwrap_or_else(|| native.clone());
    let prev_boost: String = row
        .try_get::<Option<String>, _>("corroboration_boost")
        .ok()
        .flatten()
        .unwrap_or_else(|| "none".to_string());

    apply_corroboration_boost(tx, id, &native, &watermark, &prev_boost, &engines).await?;
    Ok((id, key))
}

/// Recompute effective `max_severity` from the merged engine set.
/// Cross-plane (network + agent) corroboration jumps the cluster to Critical.
async fn apply_corroboration_boost(
    tx: &mut Transaction<'_, Postgres>,
    cluster_id: i64,
    native: &str,
    watermark: &str,
    prev_boost: &str,
    engines: &[String],
) -> Result<(), String> {
    let outcome = corroborate_cluster_severity(native, engines);
    let max_severity = finding_identity::monotonic_severity(watermark, &outcome.severity);
    let boost = finding_identity::monotonic_boost(prev_boost, &outcome.boost);
    let cvss_floor = corroboration_cvss_floor(&boost, &max_severity);
    sqlx::query(
        r#"UPDATE weissman_finding_clusters SET
                max_severity = $2,
                watermark_severity = $2,
                native_severity = $3,
                corroboration_boost = $4,
                engine_planes = $5,
                max_cvss = GREATEST(COALESCE(max_cvss, 0), $6),
                updated_at = now()
              WHERE id = $1"#,
    )
    .bind(cluster_id)
    .bind(&max_severity)
    .bind(&outcome.native_severity)
    .bind(&boost)
    .bind(&outcome.engine_planes)
    .bind(cvss_floor)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("cluster corroboration: {e}"))?;
    Ok(())
}

/// Propagate a cluster status change (analyst marks ACKNOWLEDGED / FIXED / FALSE_POSITIVE
/// on the cluster) down to all member vulnerabilities. Returns rows affected.
pub async fn cascade_cluster_status(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    cluster_id: i64,
    new_status: &str,
) -> Result<u64, String> {
    let res = sqlx::query(
        r#"UPDATE vulnerabilities
              SET status = $3,
                  updated_at = now()
            WHERE tenant_id = $1
              AND cluster_id = $2"#,
    )
    .bind(tenant_id)
    .bind(cluster_id)
    .bind(new_status)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("cascade status: {e}"))?;
    Ok(res.rows_affected())
}

/// Re-derive a cluster's aggregated fields from its current members. Useful when
/// a member is deleted or moves clusters; not called on the hot path but handy
/// for admin tools and integrity checks.
#[allow(dead_code)]
pub async fn recompute_cluster(
    tx: &mut Transaction<'_, Postgres>,
    cluster_id: i64,
) -> Result<(), String> {
    sqlx::query(
        r#"
        UPDATE weissman_finding_clusters c SET
            member_count = sub.cnt,
            native_severity = COALESCE(sub.max_sev, 'info'),
            max_severity = CASE
                WHEN (CASE COALESCE(sub.max_sev, 'info')
                    WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2 ELSE 1 END)
                  > (CASE COALESCE(c.watermark_severity, c.max_severity)
                    WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2 ELSE 1 END)
                THEN COALESCE(sub.max_sev, 'info')
                ELSE COALESCE(c.watermark_severity, c.max_severity)
            END,
            watermark_severity = CASE
                WHEN (CASE COALESCE(sub.max_sev, 'info')
                    WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2 ELSE 1 END)
                  > (CASE COALESCE(c.watermark_severity, c.max_severity)
                    WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2 ELSE 1 END)
                THEN COALESCE(sub.max_sev, 'info')
                ELSE COALESCE(c.watermark_severity, c.max_severity)
            END,
            max_cvss     = GREATEST(COALESCE(c.max_cvss, 0), COALESCE(sub.max_cvss, 0)),
            engines      = COALESCE(sub.engines, ARRAY[]::text[]),
            sources      = COALESCE(sub.sources, ARRAY[]::text[]),
            kev_listed   = COALESCE(sub.kev, FALSE),
            last_seen_at = COALESCE(sub.last_seen, c.last_seen_at),
            updated_at   = now()
        FROM (
            SELECT
                COUNT(*)::int                                                         AS cnt,
                ARRAY(SELECT DISTINCT source FROM vulnerabilities WHERE cluster_id = $1) AS sources,
                ARRAY(SELECT DISTINCT raw_data->>'engine' FROM vulnerabilities WHERE cluster_id = $1 AND raw_data->>'engine' IS NOT NULL) AS engines,
                (SELECT (CASE
                    WHEN MAX(CASE lower(severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END) = 5 THEN 'critical'
                    WHEN MAX(CASE lower(severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END) = 4 THEN 'high'
                    WHEN MAX(CASE lower(severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END) = 3 THEN 'medium'
                    WHEN MAX(CASE lower(severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END) = 2 THEN 'low'
                    ELSE 'info' END)
                 FROM vulnerabilities WHERE cluster_id = $1) AS max_sev,
                MAX(COALESCE((raw_data->>'cvss_score')::real, 0))::real  AS max_cvss,
                BOOL_OR(kev_listed)                                      AS kev,
                MAX(last_seen_at)                                        AS last_seen
            FROM vulnerabilities
            WHERE cluster_id = $1
        ) sub
        WHERE c.id = $1
        "#,
    )
    .bind(cluster_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("recompute_cluster: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_is_url_tolerant() {
        let a = build_cluster_key("https://EXAMPLE.com/foo/", "xss_reflected", "CWE-79");
        let b = build_cluster_key("https://example.com/foo", "XSS_Reflected", "cwe-79");
        let c = build_cluster_key("https://example.com/foo?x=1", "xss_reflected", "CWE-79");
        assert_eq!(a, b);
        assert_eq!(a, c);
        let d = build_cluster_key(
            "https://example.com:54321/foo?session=abc",
            "xss_reflected?token=1",
            "CWE-79",
        );
        assert_eq!(a, d);
    }
    #[test]
    fn distinct_targets_distinct_clusters() {
        let a = build_cluster_key("https://x.com/foo", "xss_reflected", "CWE-79");
        let b = build_cluster_key("https://y.com/foo", "xss_reflected", "CWE-79");
        assert_ne!(a, b);
        let public = build_cluster_key(
            "https://api.corp/api/v1/public/image/6c084089-0aec",
            "xss",
            "CWE-79",
        );
        let admin = build_cluster_key(
            "https://api.corp/api/v1/admin/billing/6c084089-0aec",
            "xss",
            "CWE-79",
        );
        assert_ne!(public, admin);
    }
    #[test]
    fn severity_max_picks_critical() {
        assert!(sev_weight("critical") > sev_weight("high"));
        assert!(sev_weight("low") > sev_weight("info"));
        assert_eq!(finding_identity::weight_to_sev(5), "critical");
    }
}
