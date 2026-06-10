//! Findings correlation & deduplication.
//!
//! Different engines often detect the *same vulnerability* from different angles
//! (e.g. `asm`, `leak_hunter`, and `bola_idor` may all flag the same IDOR on the
//! same endpoint). Naïvely persisting each as a separate `vulnerabilities` row
//! creates 3 tickets for 1 problem — analyst fatigue, distorted KPIs.
//!
//! This module collapses those signals into **finding clusters**. A cluster is
//! identified by the triple `(target, vuln_signature, cwe)` hashed to SHA-256.
//! Each `vulnerabilities` row points to its cluster via `cluster_id`. The cluster
//! row carries the *aggregate* (max severity, engines list, CVE set, KEV flag,
//! first/last seen) so the inbox can show one card per real-world issue.
//!
//! `upsert_cluster_for_finding` is called from `findings_persist::persist_engine_findings`
//! immediately AFTER the vulnerability row exists, inside the same transaction.

use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};

/// Stable cluster identity: lowercase(target) | normalised(signature) | normalised(cwe).
///
/// We intentionally exclude `engine` — that's the whole point of correlation: two
/// engines that fire on the same vuln must land in the same cluster.
pub fn build_cluster_key(target: &str, vuln_signature: &str, cwe: &str) -> String {
    let target_norm = target.trim().to_ascii_lowercase();
    // Strip query / fragments / trailing slash so /foo/?id=1 == /foo == /foo/ for clustering.
    let target_norm = strip_volatile_url_parts(&target_norm);
    let sig_norm = vuln_signature.trim().to_ascii_lowercase();
    let cwe_norm = cwe.trim().to_ascii_uppercase().replace(' ', "");

    let mut h = Sha256::new();
    h.update(target_norm.as_bytes());
    h.update(b"|");
    h.update(sig_norm.as_bytes());
    h.update(b"|");
    h.update(cwe_norm.as_bytes());
    hex::encode(h.finalize())
}

fn strip_volatile_url_parts(url: &str) -> String {
    let u = url.split('#').next().unwrap_or(url);
    let u = u.split('?').next().unwrap_or(u);
    let u = u.trim_end_matches('/');
    u.to_string()
}

/// Derive a stable vulnerability signature from a raw engine finding. This is the
/// "what" of the issue (XSS in `/foo`, SQL injection in `id` param, etc.) — NOT
/// the "where" (target stays separate so two distinct hosts cluster separately).
///
/// Priority order — first non-empty wins:
///   1. `signature` / `rule_id` / `vuln_signature` (explicit from engine)
///   2. `type` (taxonomy bucket, e.g. "xss_reflected")
///   3. `cve` / `cve_id`
///   4. lowercased + diacritic-stripped first 80 chars of the title
fn derive_vuln_signature(finding: &Value, fallback_title: &str) -> String {
    for k in ["signature", "rule_id", "vuln_signature", "rule"] {
        if let Some(s) = finding.get(k).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_ascii_lowercase();
            }
        }
    }
    if let Some(t) = finding.get("type").and_then(Value::as_str) {
        let s = t.trim();
        if !s.is_empty() {
            return s.to_ascii_lowercase();
        }
    }
    for k in ["cve", "cve_id"] {
        if let Some(c) = finding.get(k).and_then(Value::as_str) {
            let s = c.trim();
            if !s.is_empty() {
                return s.to_ascii_uppercase();
            }
        }
    }
    fallback_title
        .chars()
        .take(80)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Severity weight for `MAX(...)` rollups. Higher = worse.
fn sev_weight(s: &str) -> i32 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}
#[allow(dead_code)]
fn weight_to_sev(w: i32) -> &'static str {
    match w {
        5 => "critical",
        4 => "high",
        3 => "medium",
        2 => "low",
        1 => "info",
        _ => "info",
    }
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
    let signature = derive_vuln_signature(finding, attrs.title);
    let key = build_cluster_key(attrs.target, &signature, attrs.cwe);
    let target_norm = strip_volatile_url_parts(&attrs.target.to_ascii_lowercase());

    // Atomic upsert + aggregate refresh in one statement. arrays are accumulated
    // with `array_distinct(... || ARRAY[...])` so engines/sources/cves grow but
    // never duplicate.
    let sev_w_new = sev_weight(attrs.severity);
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
            max_severity, max_cvss, max_epss, kev_listed,
            status, first_seen_at, last_seen_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            1, ARRAY[$8]::text[], ARRAY[$9]::text[], $10::text[],
            $11, $12, $13, $14,
            'OPEN', now(), now(), now()
        )
        ON CONFLICT (tenant_id, client_id, cluster_key) DO UPDATE SET
            member_count   = weissman_finding_clusters.member_count + 1,
            engines        = (
                SELECT ARRAY(SELECT DISTINCT unnest(weissman_finding_clusters.engines || ARRAY[$8::text]))
            ),
            sources        = (
                SELECT ARRAY(SELECT DISTINCT unnest(weissman_finding_clusters.sources || ARRAY[$9::text]))
            ),
            cves           = (
                SELECT ARRAY(SELECT DISTINCT unnest(weissman_finding_clusters.cves    || $10::text[]))
            ),
            max_severity   = CASE
                WHEN $15::int > (CASE weissman_finding_clusters.max_severity
                                     WHEN 'critical' THEN 5
                                     WHEN 'high'     THEN 4
                                     WHEN 'medium'   THEN 3
                                     WHEN 'low'      THEN 2
                                     WHEN 'info'     THEN 1
                                     ELSE 0 END)
                THEN $11
                ELSE weissman_finding_clusters.max_severity
            END,
            max_cvss       = GREATEST(COALESCE(weissman_finding_clusters.max_cvss, 0), $12),
            max_epss       = GREATEST(COALESCE(weissman_finding_clusters.max_epss, 0), $13),
            kev_listed     = weissman_finding_clusters.kev_listed OR $14,
            title          = CASE WHEN $11 = 'critical' AND weissman_finding_clusters.max_severity <> 'critical'
                                  THEN $7
                                  ELSE weissman_finding_clusters.title END,
            last_seen_at   = now(),
            updated_at     = now()
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&key)
    .bind(&target_norm)
    .bind(attrs.cwe)
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
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| format!("cluster upsert: {e}"))?;

    let id: i64 = row.try_get("id").unwrap_or(0);
    Ok((id, key))
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
            max_severity = COALESCE(sub.max_sev, 'info'),
            max_cvss     = sub.max_cvss,
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
    }
    #[test]
    fn distinct_targets_distinct_clusters() {
        let a = build_cluster_key("https://x.com/foo", "xss_reflected", "CWE-79");
        let b = build_cluster_key("https://y.com/foo", "xss_reflected", "CWE-79");
        assert_ne!(a, b);
    }
    #[test]
    fn severity_max_picks_critical() {
        assert!(sev_weight("critical") > sev_weight("high"));
        assert!(sev_weight("low") > sev_weight("info"));
        assert_eq!(weight_to_sev(5), "critical");
    }
}
