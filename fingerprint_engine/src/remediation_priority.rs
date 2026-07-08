//! Global remediation-priority engine — the "fix-first" program for a whole client.
//!
//! Per-engine scans already emit their own remediation lists, but nobody fuses them: a CISO ends
//! up with dozens of separate queues and no single answer to "what do we fix first, across
//! everything?". This module answers exactly that by composing the intelligence the platform
//! already computes:
//!
//!   1. **Real risk** — each finding's `effective_risk` (0..10), which already folds in EPSS
//!      exploit-probability and CISA KEV known-exploited status at persist time.
//!   2. **Attack-graph centrality** — a finding sitting on a risk-graph *choke point* (a node many
//!      attack paths traverse) is worth more than an equally-severe leaf: fixing it collapses many
//!      paths at once.
//!   3. **Root-cause grouping** — findings that share one fix (same correlation cluster, or same
//!      CWE on the same asset) are collapsed into ONE remediation item, so the program ranks
//!      *actions*, not symptoms, and rewards a fix that closes many findings.
//!
//! The scoring is deterministic and evidence-backed (no model calls); the DB loader reads only
//! live rows. The result is a single ranked program with a plain-language rationale per item.

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// One finding as consumed by the prioritizer. Built from live DB rows by [`load_and_rank`].
#[derive(Debug, Clone)]
pub struct FindingInput {
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub cwe: String,
    pub asset: String,
    /// EPSS/KEV-adjusted risk (0..10). `None` when never risk-ranked → falls back to severity.
    pub effective_risk: Option<f64>,
    pub epss: Option<f64>,
    pub kev: bool,
    pub kev_ransomware: bool,
    /// Correlation cluster id — findings that share one share a root cause / one fix.
    pub cluster_id: Option<i64>,
    /// True when this finding's risk-graph node is a choke point (high betweenness proxy).
    pub on_choke_point: bool,
}

/// One ranked remediation action (a root-cause group), highest priority first.
#[derive(Debug, Clone, Serialize)]
pub struct RemediationItem {
    pub rank: usize,
    pub priority_score: f64,
    pub title: String,
    pub cwe: String,
    pub asset: String,
    /// How many findings this single remediation closes.
    pub closes_findings: usize,
    pub kev: bool,
    pub kev_ransomware: bool,
    pub on_choke_point: bool,
    pub max_effective_risk: f64,
    pub max_epss: Option<f64>,
    pub rationale: String,
    pub finding_ids: Vec<String>,
}

/// KEV floor: a known-exploited vuln is fix-first regardless of a modest CVSS.
const KEV_FLOOR: f64 = 85.0;
/// Ransomware-associated KEV floor — the highest urgency tier.
const KEV_RANSOMWARE_FLOOR: f64 = 95.0;
/// Multiplier applied when any finding in the group sits on an attack-path choke point.
const CHOKE_POINT_MULTIPLIER: f64 = 1.25;
/// Per-extra-finding efficiency bonus (one fix closing N findings is worth more), and its cap.
const FIX_EFFICIENCY_PER_FINDING: f64 = 1.5;
const FIX_EFFICIENCY_CAP: f64 = 15.0;

/// Map a categorical severity to an approximate 0..10 risk when a finding was never risk-ranked.
fn severity_fallback_risk(severity: &str) -> f64 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => 9.0,
        "high" => 7.5,
        "medium" => 5.0,
        "low" => 2.5,
        _ => 1.0,
    }
}

fn effective_or_fallback(f: &FindingInput) -> f64 {
    f.effective_risk
        .filter(|v| *v > 0.0)
        .unwrap_or_else(|| severity_fallback_risk(&f.severity))
}

/// Stable root-cause key: prefer the correlation cluster; else CWE+asset (same weakness, same
/// place → same fix); else the finding itself. Guarantees findings that share a fix group together.
fn group_key(f: &FindingInput) -> String {
    if let Some(cid) = f.cluster_id {
        return format!("cluster:{cid}");
    }
    let cwe = f.cwe.trim().to_ascii_lowercase();
    let asset = f.asset.trim().to_ascii_lowercase();
    if !cwe.is_empty() && !asset.is_empty() {
        return format!("cwe:{cwe}|asset:{asset}");
    }
    format!("finding:{}", f.finding_id)
}

/// Pure scoring for one root-cause group. Returns the 0..100 priority and the rationale.
/// `group` must be non-empty.
fn score_group(group: &[FindingInput]) -> (f64, String) {
    let max_risk = group
        .iter()
        .map(effective_or_fallback)
        .fold(0.0_f64, f64::max);
    let any_choke = group.iter().any(|f| f.on_choke_point);
    let any_kev = group.iter().any(|f| f.kev);
    let any_ransom = group.iter().any(|f| f.kev_ransomware);
    let count = group.len();

    let mut score = max_risk * 10.0; // 0..100
    let mut reasons: Vec<String> = Vec::new();
    reasons.push(format!("base risk {max_risk:.1}/10"));

    if any_choke {
        score *= CHOKE_POINT_MULTIPLIER;
        reasons.push("on attack-path choke point".to_string());
    }
    if count > 1 {
        let bonus =
            ((count - 1) as f64 * FIX_EFFICIENCY_PER_FINDING).min(FIX_EFFICIENCY_CAP);
        score += bonus;
        reasons.push(format!("one fix closes {count} findings"));
    }
    if any_ransom {
        score = score.max(KEV_RANSOMWARE_FLOOR);
        reasons.push("KEV — ransomware-associated".to_string());
    } else if any_kev {
        score = score.max(KEV_FLOOR);
        reasons.push("KEV — known exploited in the wild".to_string());
    }

    let score = (score.clamp(0.0, 100.0) * 10.0).round() / 10.0;
    (score, reasons.join("; "))
}

/// Rank live findings into a deduplicated, priority-ordered remediation program.
/// Deterministic: ties break by findings-closed desc, then title, then group key.
#[must_use]
pub fn rank(findings: &[FindingInput]) -> Vec<RemediationItem> {
    // Group by root cause. BTreeMap keeps grouping deterministic before the final sort.
    let mut groups: BTreeMap<String, Vec<FindingInput>> = BTreeMap::new();
    for f in findings {
        groups.entry(group_key(f)).or_default().push(f.clone());
    }

    let mut items: Vec<RemediationItem> = groups
        .into_values()
        .map(|group| {
            let (score, rationale) = score_group(&group);
            // Representative = the highest-risk member (what the analyst reads first).
            let rep = group
                .iter()
                .max_by(|a, b| {
                    effective_or_fallback(a)
                        .partial_cmp(&effective_or_fallback(b))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .expect("group is non-empty");
            let max_risk = group.iter().map(effective_or_fallback).fold(0.0, f64::max);
            let max_epss = group
                .iter()
                .filter_map(|f| f.epss)
                .fold(None, |acc: Option<f64>, e| Some(acc.map_or(e, |a| a.max(e))));
            let mut finding_ids: Vec<String> =
                group.iter().map(|f| f.finding_id.clone()).collect();
            finding_ids.sort();
            finding_ids.dedup();
            RemediationItem {
                rank: 0, // assigned after sort
                priority_score: score,
                title: rep.title.clone(),
                cwe: rep.cwe.clone(),
                asset: rep.asset.clone(),
                closes_findings: finding_ids.len(),
                kev: group.iter().any(|f| f.kev),
                kev_ransomware: group.iter().any(|f| f.kev_ransomware),
                on_choke_point: group.iter().any(|f| f.on_choke_point),
                max_effective_risk: (max_risk * 10.0).round() / 10.0,
                max_epss,
                rationale,
                finding_ids,
            }
        })
        .collect();

    items.sort_by(|a, b| {
        b.priority_score
            .partial_cmp(&a.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.closes_findings.cmp(&a.closes_findings))
            .then(a.title.cmp(&b.title))
    });
    for (i, it) in items.iter_mut().enumerate() {
        it.rank = i + 1;
    }
    items
}

/// Load open findings for a client (joined to risk-graph choke-point flags) and rank them.
/// Read-only; RLS-scoped via the caller's tenant transaction helper.
pub async fn load_and_rank(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> Result<Value, String> {
    use sqlx::Row;

    let limit = limit.clamp(1, 5000);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;

    let rows = sqlx::query(
        r#"SELECT v.finding_id,
                  COALESCE(v.title, '')                                   AS title,
                  COALESCE(v.severity, '')                                AS severity,
                  COALESCE(v.raw_data->>'cwe', '')                        AS cwe,
                  COALESCE(v.raw_data->>'target', v.raw_data->>'url', '') AS asset,
                  v.effective_risk,
                  v.epss_score,
                  COALESCE(v.kev_listed, false)                           AS kev,
                  COALESCE(v.kev_known_ransomware, false)                 AS kev_ransomware,
                  v.cluster_id,
                  COALESCE(n.is_choke_point, false)                       AS on_choke_point
             FROM vulnerabilities v
             LEFT JOIN risk_graph_nodes n
                    ON n.tenant_id = v.tenant_id
                   AND n.client_id = v.client_id
                   AND n.node_type = 'finding'
                   AND n.external_id = v.finding_id
            WHERE v.tenant_id = $1
              AND v.client_id = $2
              AND COALESCE(v.status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED')
            ORDER BY v.effective_risk DESC NULLS LAST, v.id DESC
            LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    let findings: Vec<FindingInput> = rows
        .iter()
        .filter_map(|r| {
            let finding_id: String = r.try_get("finding_id").ok()?;
            if finding_id.is_empty() {
                return None;
            }
            Some(FindingInput {
                finding_id,
                title: r.try_get("title").unwrap_or_default(),
                severity: r.try_get("severity").unwrap_or_default(),
                cwe: r.try_get("cwe").unwrap_or_default(),
                asset: r.try_get("asset").unwrap_or_default(),
                effective_risk: r.try_get::<Option<f64>, _>("effective_risk").unwrap_or(None),
                epss: r
                    .try_get::<Option<f32>, _>("epss_score")
                    .unwrap_or(None)
                    .map(f64::from),
                kev: r.try_get("kev").unwrap_or(false),
                kev_ransomware: r.try_get("kev_ransomware").unwrap_or(false),
                cluster_id: r.try_get::<Option<i64>, _>("cluster_id").unwrap_or(None),
                on_choke_point: r.try_get("on_choke_point").unwrap_or(false),
            })
        })
        .collect();

    let total_findings = findings.len();
    let program = rank(&findings);
    let kev_actions = program.iter().filter(|i| i.kev).count();
    let choke_actions = program.iter().filter(|i| i.on_choke_point).count();

    Ok(json!({
        "ok": true,
        "client_id": client_id,
        "total_findings": total_findings,
        "remediation_actions": program.len(),
        "kev_actions": kev_actions,
        "choke_point_actions": choke_actions,
        "program": program,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, sev: &str, er: Option<f64>) -> FindingInput {
        FindingInput {
            finding_id: id.to_string(),
            title: format!("finding {id}"),
            severity: sev.to_string(),
            cwe: "CWE-89".to_string(),
            asset: "app.example.com".to_string(),
            effective_risk: er,
            epss: None,
            kev: false,
            kev_ransomware: false,
            cluster_id: None,
            on_choke_point: false,
        }
    }

    #[test]
    fn higher_effective_risk_ranks_first() {
        let mut a = f("a", "medium", Some(9.5));
        a.cwe = "CWE-79".into(); // distinct group from b
        let b = f("b", "medium", Some(3.0));
        let program = rank(&[b, a]);
        assert_eq!(program[0].finding_ids, vec!["a"]);
        assert!(program[0].priority_score > program[1].priority_score);
    }

    #[test]
    fn kev_medium_beats_high_cvss_non_kev() {
        // A medium-CVSS finding that is KEV must outrank a high-CVSS finding that is not.
        let mut kev = f("kev", "medium", Some(5.0));
        kev.kev = true;
        kev.cwe = "CWE-79".into();
        let high = f("high", "high", Some(7.9));
        let program = rank(&[high, kev]);
        assert_eq!(program[0].finding_ids, vec!["kev"]);
        assert!(program[0].priority_score >= KEV_FLOOR);
    }

    #[test]
    fn ransomware_kev_is_top_tier() {
        let mut r = f("r", "medium", Some(4.0));
        r.kev = true;
        r.kev_ransomware = true;
        let program = rank(&[r]);
        assert!(program[0].priority_score >= KEV_RANSOMWARE_FLOOR);
        assert!(program[0].rationale.contains("ransomware"));
    }

    #[test]
    fn same_cluster_collapses_into_one_action() {
        let mut a = f("a", "high", Some(7.0));
        let mut b = f("b", "high", Some(7.0));
        let mut c = f("c", "high", Some(7.0));
        a.cluster_id = Some(42);
        b.cluster_id = Some(42);
        c.cluster_id = Some(42);
        let program = rank(&[a, b, c]);
        assert_eq!(program.len(), 1, "one cluster => one remediation action");
        assert_eq!(program[0].closes_findings, 3);
        assert!(program[0].rationale.contains("closes 3"));
    }

    #[test]
    fn choke_point_boosts_priority() {
        let plain = f("plain", "high", Some(7.0));
        let mut choke = f("choke", "high", Some(7.0));
        choke.finding_id = "choke".into();
        choke.cwe = "CWE-79".into(); // separate group
        choke.on_choke_point = true;
        let program = rank(&[plain, choke]);
        let choke_item = program.iter().find(|i| i.on_choke_point).unwrap();
        let plain_item = program.iter().find(|i| !i.on_choke_point).unwrap();
        assert!(choke_item.priority_score > plain_item.priority_score);
    }

    #[test]
    fn unranked_finding_uses_severity_fallback_not_zero() {
        // effective_risk None must not sink a critical to the bottom.
        let crit = f("crit", "critical", None);
        let program = rank(&[crit]);
        assert!(program[0].priority_score >= 85.0);
    }

    #[test]
    fn ranks_are_contiguous_from_one() {
        let items = vec![
            f("a", "high", Some(7.0)),
            {
                let mut x = f("b", "low", Some(2.0));
                x.cwe = "CWE-16".into();
                x
            },
        ];
        let program = rank(&items);
        assert_eq!(program[0].rank, 1);
        assert_eq!(program[1].rank, 2);
    }
}
