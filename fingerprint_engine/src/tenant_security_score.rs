//! Tenant client security score — open-finding posture per tenant (not platform self-score).
//!
//! Uses per-asset normalization and log-scaled penalties so large but mostly-medium
//! estates do not collapse to zero while critical/high findings still move the needle.

use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantSeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
}

/// Aggregated open severities with meta-normalization applied at read time.
#[derive(Debug, Clone)]
pub struct OpenSeverityAggregate {
    pub counts: TenantSeverityCounts,
    pub by_severity: HashMap<String, i64>,
    /// Rows stored as critical/high but normalized down to info/low.
    pub meta_reclassified: i64,
    /// Stored DB critical before normalization.
    pub raw_critical: i64,
}

/// Per-asset denominator: affected clients when any exist, else total fleet size.
pub fn asset_basis(clients_with_findings: i64, total_clients: i64) -> i64 {
    let basis = if clients_with_findings > 0 {
        clients_with_findings
    } else {
        total_clients
    };
    basis.max(1)
}

/// Compute a 0–100 integer security score from open critical/high/medium counts.
pub fn compute_score(
    counts: TenantSeverityCounts,
    clients_with_findings: i64,
    total_clients: i64,
) -> i64 {
    const W_CRIT: f64 = 15.0;
    const W_HIGH: f64 = 10.0;
    const W_MED: f64 = 5.0;

    let basis = asset_basis(clients_with_findings, total_clients) as f64;
    let crit_norm = counts.critical.max(0) as f64 / basis;
    let high_norm = counts.high.max(0) as f64 / basis;
    let med_norm = counts.medium.max(0) as f64 / basis;

    let penalty = W_CRIT * (1.0 + crit_norm).ln()
        + W_HIGH * (1.0 + high_norm).ln()
        + W_MED * (1.0 + med_norm).ln();

    (100.0 - penalty).round().clamp(0.0, 100.0) as i64
}

/// Stable JSON contract for dashboard `scoring` metadata.
pub fn scoring_metadata(aggregate: &OpenSeverityAggregate) -> Value {
    serde_json::json!({
        "method": "log_per_asset_severity",
        "description": "100 minus log-scaled per-asset severity penalties (diminishing returns on volume)",
        "normalization": {
            "denominator": "max(1, clients_with_findings if > 0 else total_clients)"
        },
        "weights": {
            "critical": { "coefficient": 15, "term": "ln(1 + critical / asset_basis)" },
            "high":     { "coefficient": 10, "term": "ln(1 + high / asset_basis)" },
            "medium":   { "coefficient": 5,  "term": "ln(1 + medium / asset_basis)" }
        },
        "included_severities": ["critical", "high", "medium"],
        "range": [0, 100],
        "meta_analytical_reclassified": aggregate.meta_reclassified,
        "actionable_critical": aggregate.counts.critical,
        "stored_critical_before_meta": aggregate.raw_critical,
    })
}

/// Live score from tenant-scoped transaction (open findings only, meta-normalized).
pub async fn fetch_live_score(tx: &mut Transaction<'_, Postgres>) -> i64 {
    let agg = aggregate_normalized_open_severities(tx)
        .await
        .unwrap_or_default();
    let total_clients: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM clients")
        .fetch_one(&mut **tx)
        .await
        .unwrap_or(0);
    let clients_with_findings: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT client_id)::bigint FROM vulnerabilities
          WHERE COALESCE(status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')",
    )
    .fetch_one(&mut **tx)
    .await
    .unwrap_or(0);
    compute_score(agg.counts, clients_with_findings, total_clients)
}

/// Count open findings by normalized severity (meta synthesis downgraded at read time).
pub async fn aggregate_normalized_open_severities(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<OpenSeverityAggregate, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT source, title, severity, raw_data
             FROM vulnerabilities
            WHERE COALESCE(status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')"#,
    )
    .fetch_all(&mut **tx)
    .await?;

    let mut by_severity: HashMap<String, i64> = HashMap::new();
    let mut meta_reclassified = 0i64;
    let mut raw_critical = 0i64;

    for row in rows {
        let source: String = row.try_get("source").unwrap_or_default();
        let title: String = row.try_get("title").unwrap_or_default();
        let stored_sev: String = row
            .try_get("severity")
            .unwrap_or_else(|_| "info".to_string());
        let raw_data: Value = row.try_get("raw_data").unwrap_or(Value::Null);

        if stored_sev.eq_ignore_ascii_case("critical") {
            raw_critical += 1;
        }

        let cvss = raw_data
            .get("cvss_score")
            .or_else(|| raw_data.get("cvss"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let mitre = raw_data
            .get("mitre_attack")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let (norm_sev, _, _) = crate::findings_meta::normalize_meta_display(
            &source,
            &title,
            &stored_sev,
            cvss,
            &mitre,
            &raw_data,
        );

        if !stored_sev.eq_ignore_ascii_case(&norm_sev)
            && (stored_sev.eq_ignore_ascii_case("critical")
                || stored_sev.eq_ignore_ascii_case("high"))
        {
            meta_reclassified += 1;
        }

        let key = norm_sev.to_ascii_lowercase();
        *by_severity.entry(key).or_insert(0) += 1;
    }

    let get = |k: &str| by_severity.get(k).copied().unwrap_or(0);
    Ok(OpenSeverityAggregate {
        counts: TenantSeverityCounts {
            critical: get("critical"),
            high: get("high"),
            medium: get("medium"),
        },
        by_severity,
        meta_reclassified,
        raw_critical,
    })
}

impl Default for OpenSeverityAggregate {
    fn default() -> Self {
        Self {
            counts: TenantSeverityCounts {
                critical: 0,
                high: 0,
                medium: 0,
            },
            by_severity: HashMap::new(),
            meta_reclassified: 0,
            raw_critical: 0,
        }
    }
}

/// Per-client actionable critical counts (meta synthesis excluded).
pub async fn normalized_critical_by_client(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<HashMap<i64, i64>, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT client_id, source, title, severity, raw_data
             FROM vulnerabilities
            WHERE COALESCE(status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')"#,
    )
    .fetch_all(&mut **tx)
    .await?;

    let mut by_client: HashMap<i64, i64> = HashMap::new();
    for row in rows {
        let client_id: i64 = row.try_get("client_id").unwrap_or(0);
        let source: String = row.try_get("source").unwrap_or_default();
        let title: String = row.try_get("title").unwrap_or_default();
        let stored_sev: String = row
            .try_get("severity")
            .unwrap_or_else(|_| "info".to_string());
        let raw_data: Value = row.try_get("raw_data").unwrap_or(Value::Null);

        let cvss = raw_data
            .get("cvss_score")
            .or_else(|| raw_data.get("cvss"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let mitre = raw_data
            .get("mitre_attack")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let (norm_sev, _, _) = crate::findings_meta::normalize_meta_display(
            &source,
            &title,
            &stored_sev,
            cvss,
            &mitre,
            &raw_data,
        );

        if norm_sev.eq_ignore_ascii_case("critical") {
            *by_client.entry(client_id).or_insert(0) += 1;
        }
    }

    Ok(by_client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manageable_volume_stays_above_zero() {
        // 495 medium across 5 affected assets — old linear formula pinned at 0.
        let score = compute_score(
            TenantSeverityCounts {
                critical: 0,
                high: 0,
                medium: 495,
            },
            5,
            10,
        );
        assert!(
            score > 0,
            "manageable medium-only volume should not zero out"
        );
        assert!(
            score >= 70,
            "expected ~77 for 495 medium / 5 assets, got {score}"
        );
    }

    #[test]
    fn criticals_penalize_meaningfully() {
        let baseline = compute_score(
            TenantSeverityCounts {
                critical: 0,
                high: 0,
                medium: 20,
            },
            5,
            5,
        );
        let with_crit = compute_score(
            TenantSeverityCounts {
                critical: 10,
                high: 0,
                medium: 20,
            },
            5,
            5,
        );
        assert!(with_crit < baseline - 10);
    }

    #[test]
    fn score_clamped_0_100() {
        let catastrophic = compute_score(
            TenantSeverityCounts {
                critical: 500,
                high: 500,
                medium: 500,
            },
            1,
            1,
        );
        assert_eq!(catastrophic, 0);

        let pristine = compute_score(
            TenantSeverityCounts {
                critical: 0,
                high: 0,
                medium: 0,
            },
            0,
            0,
        );
        assert_eq!(pristine, 100);
    }
}
