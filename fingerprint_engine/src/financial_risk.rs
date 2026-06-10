//! Financial blast-radius scoring.
//!
//! Quant model derived from FAIR (Factor Analysis of Information Risk):
//!   * **SLE** (Single Loss Expectancy) = `asset_value_usd × loss_magnitude_pct`
//!     For our model `loss_magnitude_pct = max(CVSS impact_score, 0.5)` capped at 1.0.
//!   * **ARO** (Annualised Rate of Occurrence) ≈ `EPSS × 12` (EPSS is 30-day prob).
//!     For KEV-listed CVEs we floor at 1.0 (assumed at least one event/year).
//!   * **ALE** (Annualised Loss Expectancy) = `SLE × ARO × risk_loss_discount`.
//!
//! Roll-up per client:
//!   * `total_asset_value_usd` — sum of business_value_usd across all nodes
//!     (NULL nodes counted at `clients.default_asset_value_usd`).
//!   * `sle_worst_usd` — biggest SLE if a single critical+KEV+exposed asset
//!     blows up. Used as the headline number ("$X at risk").
//!   * `ale_annualised_usd` — expected dollar loss this year. Used for board reports.
//!
//! Apply tag rules: every node with a tag matching `client_asset_value_rules.tag`
//! gets that rule's value (rule with the highest value wins on conflict).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientFinancialRisk {
    pub client_id: i64,
    pub total_asset_value_usd: i64,
    pub crown_jewel_value_usd: i64,
    pub sle_worst_usd: i64,
    pub ale_annualised_usd: i64,
    pub top_contributors: Vec<TopContributor>,
    pub default_asset_value_usd: i64,
    pub risk_loss_discount: f32,
    pub computed_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopContributor {
    pub node_id: i64,
    pub label: String,
    pub graph_key: String,
    pub node_type: String,
    pub business_value_usd: i64,
    pub crown_jewel: bool,
    pub kev_present: bool,
    pub max_cvss: f32,
    pub max_epss: f32,
    pub sle_usd: i64,
    pub ale_usd: i64,
}

/// Apply per-client tag → value rules to risk_graph_nodes. Idempotent. Returns
/// number of nodes updated. Should be called at onboarding and any time rules
/// or tags change.
pub async fn apply_tag_rules(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<u64, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    // Set business_value_usd for any node whose tags array intersects a rule's tag,
    // picking the MAX matching rule (so "kms" + "tier:prod" yields the bigger of
    // the two values). Idempotent on subsequent calls.
    let res = sqlx::query(
        r#"WITH best AS (
              SELECT n.id AS node_id, MAX(r.business_value_usd)::bigint AS val
                FROM risk_graph_nodes n
                JOIN client_asset_value_rules r
                  ON r.tenant_id = n.tenant_id
                 AND r.client_id = n.client_id
                 AND lower(r.tag) = ANY (
                       SELECT lower(t) FROM unnest(n.tags) AS t
                     )
               WHERE n.tenant_id = $1 AND n.client_id = $2
               GROUP BY n.id
           )
           UPDATE risk_graph_nodes n
              SET business_value_usd = best.val
             FROM best
            WHERE n.id = best.node_id
              AND (n.business_value_usd IS NULL OR n.business_value_usd <> best.val)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(res.rows_affected())
}

/// Compute (and persist) the financial blast-radius for a client.
pub async fn compute_and_store(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<ClientFinancialRisk, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    // Pull client-level defaults first.
    let (default_value, discount): (i64, f32) = sqlx::query_as(
        "SELECT default_asset_value_usd, risk_loss_discount
           FROM clients WHERE id = $1",
    )
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or((10_000, 0.30));

    // For every node, compute SLE = value × impact + KEV/EPSS-multiplied ALE.
    // We join vulnerabilities to find the worst current finding per node.
    let rows = sqlx::query(
        r#"SELECT n.id, n.label, n.graph_key, n.node_type, n.crown_jewel,
                  COALESCE(n.business_value_usd, $3)               AS value,
                  COALESCE(MAX((v.raw_data->>'cvss_score')::real), 0)::real AS max_cvss,
                  COALESCE(MAX(v.epss_score), 0)::real             AS max_epss,
                  BOOL_OR(COALESCE(v.kev_listed, FALSE))           AS kev
             FROM risk_graph_nodes n
             LEFT JOIN vulnerabilities v
               ON v.risk_node_id = n.id
              AND COALESCE(v.status,'OPEN') NOT IN ('FIXED','FALSE_POSITIVE')
            WHERE n.tenant_id = $1 AND n.client_id = $2
            GROUP BY n.id"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(default_value)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let mut total_value: i64 = 0;
    let mut crown_value: i64 = 0;
    let mut sle_worst: i64 = 0;
    let mut ale_total: i64 = 0;
    let mut contributors: Vec<TopContributor> = Vec::with_capacity(rows.len());

    for r in rows {
        let id: i64 = r.try_get("id").unwrap_or(0);
        let label: String = r.try_get("label").unwrap_or_default();
        let graph_key: String = r.try_get("graph_key").unwrap_or_default();
        let node_type: String = r.try_get("node_type").unwrap_or_default();
        let crown: bool = r.try_get("crown_jewel").unwrap_or(false);
        let value: i64 = r.try_get("value").unwrap_or(default_value);
        let cvss: f32 = r.try_get("max_cvss").unwrap_or(0.0);
        let epss: f32 = r.try_get("max_epss").unwrap_or(0.0);
        let kev: bool = r.try_get("kev").unwrap_or(false);

        total_value += value;
        if crown { crown_value += value; }

        let sle = single_loss_expectancy(value, cvss);
        let ale = annual_loss_expectancy(sle, epss, kev, discount);

        if sle > sle_worst { sle_worst = sle; }
        ale_total = ale_total.saturating_add(ale);

        contributors.push(TopContributor {
            node_id: id,
            label,
            graph_key,
            node_type,
            business_value_usd: value,
            crown_jewel: crown,
            kev_present: kev,
            max_cvss: cvss,
            max_epss: epss,
            sle_usd: sle,
            ale_usd: ale,
        });
    }
    // Top-N contributors by ALE for the UI roll-up.
    contributors.sort_by(|a, b| b.ale_usd.cmp(&a.ale_usd));
    contributors.truncate(15);

    // Persist a snapshot for fast UI loads.
    let contributors_json: Value = serde_json::to_value(&contributors).unwrap_or(json!([]));
    let _ = sqlx::query(
        r#"INSERT INTO client_financial_risk_snapshots
                 (tenant_id, client_id, computed_at,
                  total_asset_value_usd, sle_worst_usd, ale_annualised_usd,
                  crown_jewel_value_usd, top_contributors)
           VALUES ($1, $2, now(), $3, $4, $5, $6, $7)"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(total_value)
    .bind(sle_worst)
    .bind(ale_total)
    .bind(crown_value)
    .bind(&contributors_json)
    .execute(&mut *tx)
    .await;
    tx.commit().await.map_err(|e| e.to_string())?;

    Ok(ClientFinancialRisk {
        client_id,
        total_asset_value_usd: total_value,
        crown_jewel_value_usd: crown_value,
        sle_worst_usd: sle_worst,
        ale_annualised_usd: ale_total,
        top_contributors: contributors,
        default_asset_value_usd: default_value,
        risk_loss_discount: discount,
        computed_at_unix: chrono::Utc::now().timestamp(),
    })
}

/// Read latest snapshot from DB; returns None if never computed.
pub async fn latest_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<Option<ClientFinancialRisk>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT total_asset_value_usd, sle_worst_usd, ale_annualised_usd,
                  crown_jewel_value_usd, top_contributors, computed_at,
                  (SELECT default_asset_value_usd FROM clients WHERE id = $2) AS dv,
                  (SELECT risk_loss_discount     FROM clients WHERE id = $2) AS rd
             FROM client_financial_risk_snapshots
            WHERE tenant_id = $1 AND client_id = $2
            ORDER BY computed_at DESC
            LIMIT 1"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;
    let Some(r) = row else { return Ok(None) };
    let top: Vec<TopContributor> = serde_json::from_value(
        r.try_get::<Value, _>("top_contributors").unwrap_or(json!([])),
    ).unwrap_or_default();
    let computed_at: chrono::DateTime<chrono::Utc> = r.try_get("computed_at").unwrap_or_else(|_| chrono::Utc::now());
    Ok(Some(ClientFinancialRisk {
        client_id,
        total_asset_value_usd: r.try_get("total_asset_value_usd").unwrap_or(0),
        crown_jewel_value_usd: r.try_get("crown_jewel_value_usd").unwrap_or(0),
        sle_worst_usd: r.try_get("sle_worst_usd").unwrap_or(0),
        ale_annualised_usd: r.try_get("ale_annualised_usd").unwrap_or(0),
        top_contributors: top,
        default_asset_value_usd: r.try_get("dv").unwrap_or(10_000),
        risk_loss_discount: r.try_get("rd").unwrap_or(0.30),
        computed_at_unix: computed_at.timestamp(),
    }))
}

// ── Math helpers ────────────────────────────────────────────────────────────

/// Single Loss Expectancy = asset value × loss magnitude.
/// Loss magnitude derived from CVSS (0..10): floor at 50%, scale to 100% at CVSS 10.
fn single_loss_expectancy(asset_value_usd: i64, cvss: f32) -> i64 {
    if asset_value_usd <= 0 {
        return 0;
    }
    let lm = ((cvss as f64) / 10.0).clamp(0.5, 1.0);
    ((asset_value_usd as f64) * lm) as i64
}

/// Annual Loss Expectancy = SLE × annualised exploit probability × discount factor.
/// EPSS reports 30-day probability — multiply by 12 to get annualised. KEV-listed
/// floors annualised probability at 1.0 (assumed at least one attempt/year).
fn annual_loss_expectancy(sle_usd: i64, epss: f32, kev: bool, discount: f32) -> i64 {
    if sle_usd <= 0 {
        return 0;
    }
    let mut aro = (epss as f64) * 12.0; // annualised rate of occurrence
    if kev {
        aro = aro.max(1.0);
    }
    aro = aro.clamp(0.0, 12.0); // can't fire more than once per month on average
    let disc = (discount as f64).clamp(0.0, 1.0);
    ((sle_usd as f64) * aro * disc) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sle_scales_with_cvss() {
        // critical (CVSS 9.8) on a $100k asset → ~98k
        let sle = single_loss_expectancy(100_000, 9.8);
        assert!(sle > 95_000 && sle <= 100_000);
    }
    #[test]
    fn sle_floors_at_half() {
        // info-only (CVSS 0) still costs 50% of asset value (info = data exposure
        // potential we can't ignore).
        let sle = single_loss_expectancy(100_000, 0.0);
        assert_eq!(sle, 50_000);
    }
    #[test]
    fn ale_kev_floors_aro_at_one() {
        let sle = 100_000;
        let ale_no_kev = annual_loss_expectancy(sle, 0.0, false, 0.30);
        let ale_kev = annual_loss_expectancy(sle, 0.0, true, 0.30);
        assert_eq!(ale_no_kev, 0);
        assert_eq!(ale_kev, 30_000); // sle * 1.0 ARO * 0.30 discount
    }
    #[test]
    fn ale_uses_epss_when_no_kev() {
        // EPSS 0.50 ≈ 6 events/yr × 0.3 discount × $100k = $180k
        let ale = annual_loss_expectancy(100_000, 0.50, false, 0.30);
        assert!(ale > 170_000 && ale < 190_000);
    }
    #[test]
    fn ale_clamps_at_twelve_events_yr() {
        // EPSS 1.0 × 12 = 12 events; can't go higher.
        let ale = annual_loss_expectancy(100_000, 1.0, true, 1.0);
        assert_eq!(ale, 1_200_000); // 100k × 12 × 1.0
    }
}
