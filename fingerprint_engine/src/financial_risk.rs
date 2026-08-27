//! Financial blast-radius scoring.
//!
//! Quant model derived from FAIR (Factor Analysis of Information Risk):
//!   * **SLE** (Single Loss Expectancy) = `asset_value_usd × loss_magnitude_pct`
//!     For our model `loss_magnitude_pct = max(CVSS impact_score, 0.5)` capped at 1.0.
//!   * **ARO** (Annualised Rate of Occurrence) ≈ `EPSS × 12` (EPSS is 30-day prob).
//!     For KEV-listed CVEs we floor at 1.0 (assumed at least one event/year).
//!   * **ALE** (Annualised Loss Expectancy) = `SLE × ARO × risk_loss_discount`.
//!     `risk_loss_discount` is the existing likelihood control (FAIR "decay").
//!
//! This module is the **only** source of Command Center / PDF Intelligence /
//! Kill-Chain Commander executive dollars. Do not invent a second FAIR. Do not
//! convert Micro-Severity (`severity × criticality × exposure`) into USD.
//! Missing inputs → [`FairHeadline::cannot_price`] (fail-visible), never a made-up figure.
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

/// Canonical executive headline. Method is always FAIR blast-radius — never the
/// Micro-Severity linear product.
pub const METHOD_FAIR: &str = "fair_usd_blast_radius";
pub const CANNOT_PRICE_NO_SNAPSHOT: &str =
    "Cannot price — no FAIR blast-radius snapshot (asset valuations / risk graph missing). Weissman will not invent a dollar figure.";
pub const CANNOT_PRICE_NO_ASSETS: &str =
    "Cannot price — FAIR inputs are empty (no valued risk-graph assets). Weissman will not invent a dollar figure.";
pub const CANNOT_PRICE_NO_SCOPE: &str =
    "Cannot price — no client FAIR snapshots in this tenant yet. Set asset values or recompute /api/financial-risk/:id?recompute=1.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FairInputsUsed {
    pub asset_value: bool,
    pub epss: bool,
    pub kev: bool,
    /// Existing FAIR likelihood control (`clients.risk_loss_discount`).
    pub risk_loss_discount: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FairHeadline {
    pub method: String,
    pub priced: bool,
    pub cannot_price_reason: Option<String>,
    pub ale_annualised_usd: Option<i64>,
    pub sle_worst_usd: Option<i64>,
    pub total_asset_value_usd: Option<i64>,
    pub crown_jewel_value_usd: Option<i64>,
    pub client_id: Option<i64>,
    pub computed_at_unix: Option<i64>,
    pub expression: String,
    pub inputs: FairInputsUsed,
}

impl Default for FairHeadline {
    fn default() -> Self {
        Self::cannot_price(CANNOT_PRICE_NO_SNAPSHOT)
    }
}

impl FairHeadline {
    #[must_use]
    pub fn cannot_price(reason: impl Into<String>) -> Self {
        Self {
            method: METHOD_FAIR.into(),
            priced: false,
            cannot_price_reason: Some(reason.into()),
            ale_annualised_usd: None,
            sle_worst_usd: None,
            total_asset_value_usd: None,
            crown_jewel_value_usd: None,
            client_id: None,
            computed_at_unix: None,
            expression: "SLE = asset_value × clamp(CVSS/10, 0.5, 1.0); ALE = SLE × clamp(EPSS×12, 0..12) × discount (KEV floors ARO at 1.0/yr)".into(),
            inputs: FairInputsUsed {
                asset_value: false,
                epss: false,
                kev: false,
                risk_loss_discount: None,
            },
        }
    }

    /// Fail-visible line for PDF / cockpit / kill-chain CEO tiles.
    #[must_use]
    pub fn display_line(&self) -> String {
        if self.priced {
            format!(
                "FAIR USD blast-radius  ALE ${}  ·  worst-case SLE ${}",
                fmt_usd(self.ale_annualised_usd.unwrap_or(0)),
                fmt_usd(self.sle_worst_usd.unwrap_or(0)),
            )
        } else {
            self.cannot_price_reason
                .clone()
                .unwrap_or_else(|| CANNOT_PRICE_NO_SNAPSHOT.into())
        }
    }
}

/// Convert a stored FAIR snapshot into an executive headline. Zero-valued
/// snapshots are cannot-price (no fake $0 residual risk).
#[must_use]
pub fn headline_from_risk(risk: &ClientFinancialRisk) -> FairHeadline {
    let has_value = risk.total_asset_value_usd > 0
        || risk.sle_worst_usd > 0
        || risk.ale_annualised_usd > 0
        || risk.crown_jewel_value_usd > 0;
    if !has_value {
        let mut h = FairHeadline::cannot_price(CANNOT_PRICE_NO_ASSETS);
        h.client_id = Some(risk.client_id);
        h.computed_at_unix = Some(risk.computed_at_unix);
        h.inputs.risk_loss_discount = Some(risk.risk_loss_discount);
        return h;
    }
    let epss = risk.top_contributors.iter().any(|c| c.max_epss > 0.0);
    let kev = risk.top_contributors.iter().any(|c| c.kev_present);
    FairHeadline {
        method: METHOD_FAIR.into(),
        priced: true,
        cannot_price_reason: None,
        ale_annualised_usd: Some(risk.ale_annualised_usd),
        sle_worst_usd: Some(risk.sle_worst_usd),
        total_asset_value_usd: Some(risk.total_asset_value_usd),
        crown_jewel_value_usd: Some(risk.crown_jewel_value_usd),
        client_id: Some(risk.client_id),
        computed_at_unix: Some(risk.computed_at_unix),
        expression: "SLE = asset_value × clamp(CVSS/10, 0.5, 1.0); ALE = SLE × clamp(EPSS×12, 0..12) × discount (KEV floors ARO at 1.0/yr)".into(),
        inputs: FairInputsUsed {
            asset_value: risk.total_asset_value_usd > 0 || risk.default_asset_value_usd > 0,
            epss,
            kev,
            risk_loss_discount: Some(risk.risk_loss_discount),
        },
    }
}

/// Cockpit / PDF / kill-chain scoring envelope. Headline is FAIR only;
/// Micro-Severity is nested and labeled as SOC ranking — never residual USD.
#[must_use]
pub fn executive_scoring_contract(
    fair: &FairHeadline,
    micro_local_score: Option<f64>,
) -> Value {
    json!({
        "method": METHOD_FAIR,
        "fair": fair,
        "micro_severity": crate::micro_severity::api_object(micro_local_score),
    })
}

/// Latest snapshot, computing once when missing. Never invents USD.
pub async fn headline_for_client(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> FairHeadline {
    match latest_snapshot(pool, tenant_id, client_id).await {
        Ok(Some(s)) => return headline_from_risk(&s),
        Ok(None) => {}
        Err(e) => {
            return FairHeadline::cannot_price(format!("Cannot price — FAIR snapshot read failed: {e}"));
        }
    }
    match compute_and_store(pool, tenant_id, client_id).await {
        Ok(s) => headline_from_risk(&s),
        Err(e) => FairHeadline::cannot_price(format!("Cannot price — FAIR computation failed: {e}")),
    }
}

/// Tenant roll-up of **existing** FAIR snapshots. Does not invent dollars for
/// clients that have never been priced.
pub async fn headline_for_tenant(pool: &PgPool, tenant_id: i64) -> FairHeadline {
    let mut tx = match crate::db::begin_tenant_tx(pool, tenant_id).await {
        Ok(t) => t,
        Err(e) => {
            return FairHeadline::cannot_price(format!("Cannot price — database unavailable: {e}"));
        }
    };
    let rows = sqlx::query(
        r#"SELECT DISTINCT ON (client_id)
                  client_id, total_asset_value_usd, sle_worst_usd, ale_annualised_usd,
                  crown_jewel_value_usd, computed_at
             FROM client_financial_risk_snapshots
            WHERE tenant_id = $1
            ORDER BY client_id, computed_at DESC"#,
    )
    .bind(tenant_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;
    if rows.is_empty() {
        return FairHeadline::cannot_price(CANNOT_PRICE_NO_SCOPE);
    }
    let mut ale: i64 = 0;
    let mut sle_worst: i64 = 0;
    let mut assets: i64 = 0;
    let mut crown: i64 = 0;
    let mut latest: i64 = 0;
    let mut any = false;
    for r in rows {
        let a: i64 = r.try_get("ale_annualised_usd").unwrap_or(0);
        let s: i64 = r.try_get("sle_worst_usd").unwrap_or(0);
        let t: i64 = r.try_get("total_asset_value_usd").unwrap_or(0);
        let c: i64 = r.try_get("crown_jewel_value_usd").unwrap_or(0);
        if t > 0 || s > 0 || a > 0 || c > 0 {
            any = true;
        }
        ale = ale.saturating_add(a);
        if s > sle_worst {
            sle_worst = s;
        }
        assets = assets.saturating_add(t);
        crown = crown.saturating_add(c);
        if let Ok(ts) = r.try_get::<chrono::DateTime<chrono::Utc>, _>("computed_at") {
            latest = latest.max(ts.timestamp());
        }
    }
    if !any {
        return FairHeadline::cannot_price(CANNOT_PRICE_NO_ASSETS);
    }
    FairHeadline {
        method: METHOD_FAIR.into(),
        priced: true,
        cannot_price_reason: None,
        ale_annualised_usd: Some(ale),
        sle_worst_usd: Some(sle_worst),
        total_asset_value_usd: Some(assets),
        crown_jewel_value_usd: Some(crown),
        client_id: None,
        computed_at_unix: if latest > 0 { Some(latest) } else { None },
        expression: "Portfolio FAIR roll-up of latest client_financial_risk_snapshots (ALE summed, worst-case SLE = max client SLE)".into(),
        inputs: FairInputsUsed {
            asset_value: assets > 0,
            epss: true,
            kev: true,
            risk_loss_discount: None,
        },
    }
}

fn fmt_usd(n: i64) -> String {
    let neg = n < 0;
    let s = n.abs().to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    let body: String = out.chars().rev().collect();
    if neg {
        format!("-{body}")
    } else {
        body
    }
}

/// Apply per-client tag → value rules to risk_graph_nodes. Idempotent. Returns
/// number of nodes updated. Should be called at onboarding and any time rules
/// or tags change.
pub async fn apply_tag_rules(pool: &PgPool, tenant_id: i64, client_id: i64) -> Result<u64, String> {
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
        if crown {
            crown_value += value;
        }

        let sle = single_loss_expectancy(value, cvss);
        let ale = annual_loss_expectancy(sle, epss, kev, discount);

        if sle > sle_worst {
            sle_worst = sle;
        }
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
        r.try_get::<Value, _>("top_contributors")
            .unwrap_or(json!([])),
    )
    .unwrap_or_default();
    let computed_at: chrono::DateTime<chrono::Utc> = r
        .try_get("computed_at")
        .unwrap_or_else(|_| chrono::Utc::now());
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

    fn sample_risk(ale: i64, sle: i64, assets: i64) -> ClientFinancialRisk {
        ClientFinancialRisk {
            client_id: 7,
            total_asset_value_usd: assets,
            crown_jewel_value_usd: 0,
            sle_worst_usd: sle,
            ale_annualised_usd: ale,
            top_contributors: vec![TopContributor {
                node_id: 1,
                label: "www".into(),
                graph_key: "host:www".into(),
                node_type: "host".into(),
                business_value_usd: assets,
                crown_jewel: false,
                kev_present: true,
                max_cvss: 9.8,
                max_epss: 0.8,
                sle_usd: sle,
                ale_usd: ale,
            }],
            default_asset_value_usd: 10_000,
            risk_loss_discount: 0.30,
            computed_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn headline_prices_from_fair_snapshot_not_micro_severity() {
        let h = headline_from_risk(&sample_risk(180_000, 98_000, 100_000));
        assert!(h.priced);
        assert_eq!(h.method, METHOD_FAIR);
        assert_eq!(h.ale_annualised_usd, Some(180_000));
        assert_eq!(h.sle_worst_usd, Some(98_000));
        assert!(h.inputs.epss && h.inputs.kev && h.inputs.asset_value);
        assert!(h.cannot_price_reason.is_none());
        let contract = executive_scoring_contract(&h, Some(25.0));
        assert_eq!(contract["method"], METHOD_FAIR);
        assert_eq!(contract["fair"]["ale_annualised_usd"], 180_000);
        assert_eq!(contract["micro_severity"]["method"], crate::micro_severity::METHOD);
        assert_eq!(contract["micro_severity"]["not_residual_financial_risk"], true);
        assert_eq!(contract["micro_severity"]["score"], 25.0);
        // Linear product must not leak into FAIR dollars.
        assert_ne!(
            contract["fair"]["ale_annualised_usd"],
            contract["micro_severity"]["score"]
        );
    }

    #[test]
    fn headline_fail_visible_when_fair_inputs_empty() {
        let h = headline_from_risk(&sample_risk(0, 0, 0));
        assert!(!h.priced);
        assert!(h.ale_annualised_usd.is_none());
        assert!(h.sle_worst_usd.is_none());
        assert!(h
            .cannot_price_reason
            .as_deref()
            .unwrap()
            .contains("Cannot price"));
        assert!(!h.display_line().contains('$'));
    }

    #[test]
    fn cannot_price_never_emits_dollar_fields() {
        let h = FairHeadline::cannot_price("Cannot price — test");
        assert!(!h.priced);
        assert!(h.ale_annualised_usd.is_none());
        assert_eq!(h.method, METHOD_FAIR);
        let contract = executive_scoring_contract(&h, Some(99.0));
        assert!(contract["fair"]["ale_annualised_usd"].is_null());
        assert!(contract.get("scoring").is_none());
        assert_eq!(contract["method"], METHOD_FAIR);
        assert_ne!(
            contract["method"].as_str(),
            Some(crate::micro_severity::METHOD)
        );
    }

    #[test]
    fn executive_api_handlers_wire_existing_fair_not_linear_product() {
        let exec = include_str!("server_handlers_sqlx.inc");
        assert!(exec.contains("crate::financial_risk::headline_for_client"));
        assert!(exec.contains("crate::financial_risk::headline_for_tenant"));
        assert!(exec.contains("\"headline_risk\": fair"));
        assert!(exec.contains("executive_scoring_contract"));
        assert!(
            !exec.contains("micro_severity::score("),
            "exec-kpis must not convert Micro-Severity product into USD"
        );

        let pdf = include_str!("server_handlers_pdf_intelligence.inc");
        assert!(pdf.contains("\"fair\": snap.fair"));
        assert!(pdf.contains("\"headline_risk\": snap.fair"));
        assert!(pdf.contains("executive_scoring_contract"));
        assert!(!pdf.contains("micro_severity::score("));

        let kcc = include_str!("kill_chain_commander.rs");
        assert!(kcc.contains("headline_for_client"));
        assert!(kcc.contains("apply_fair_headline"));
        assert!(kcc.contains("priced_usd: None"));
        assert!(
            !kcc.contains("USD_DIVISOR"),
            "kill-chain must not convert linear product into USD"
        );
    }
}
