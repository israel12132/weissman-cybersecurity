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
    /// True when the affected asset is a designated crown jewel (business-critical).
    pub crown_jewel: bool,
    /// Business-value multiplier for the asset (risk_graph_nodes.asset_value, default 1.0).
    pub asset_value: f64,
    /// Optional financial blast-radius estimate for the asset, in USD.
    pub business_value_usd: Option<i64>,
    /// Age in whole days since the finding was first discovered (`discovered_at`). Drives the
    /// remediation SLA / overdue clock. `None` when unknown → the action is never marked breached.
    pub first_seen_days: Option<i64>,
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
    /// True when any finding in the group affects a crown-jewel asset.
    pub crown_jewel: bool,
    /// Largest financial blast-radius (USD) among the group's assets, if known.
    pub business_value_usd: Option<i64>,
    pub max_effective_risk: f64,
    pub max_epss: Option<f64>,
    /// Age of the OLDEST finding in this group (most conservative for the SLA clock), in days.
    pub oldest_finding_age_days: Option<i64>,
    /// Remediation SLA for this action: target window, remaining days, and breach state.
    pub sla: SlaStatus,
    /// Framework controls this fix helps satisfy (advisory crosswalk keyed on CWE). Lets a CISO
    /// see the audit-coverage payoff of a fix, deduped across the group's CWEs.
    pub compliance: Vec<ControlRef>,
    pub rationale: String,
    pub finding_ids: Vec<String>,
}

/// A control/requirement in an external framework that a remediation helps satisfy.
/// This is an advisory crosswalk, not a certification claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlRef {
    /// e.g. "OWASP Top 10 2021", "NIST 800-53r5", "PCI DSS 4.0".
    pub framework: &'static str,
    /// The control/requirement id within that framework, e.g. "A03:2021", "SI-10", "6.2.4".
    pub control: &'static str,
    /// Short human title for the control.
    pub title: &'static str,
}

/// Where an action stands against its remediation SLA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaState {
    /// Past its due date — a breach that must be reported.
    Overdue,
    /// Inside the window but close to the deadline (≤20% of the window remaining).
    DueSoon,
    /// Comfortably within the window.
    OnTrack,
    /// Age unknown, so the clock cannot be evaluated.
    Unknown,
}

/// A remediation SLA verdict for one action. Deterministic given (urgency, age).
#[derive(Debug, Clone, Serialize)]
pub struct SlaStatus {
    /// Allowed remediation window in calendar days (see the SLA_* constants for the policy).
    pub target_days: i64,
    /// Plain-language reason the window is what it is (drives the policy audit trail).
    pub basis: String,
    pub age_days: Option<i64>,
    /// `target_days - age_days`; negative once breached. `None` when age is unknown.
    pub due_in_days: Option<i64>,
    pub state: SlaState,
    pub breached: bool,
}

/// KEV floor: a known-exploited vuln is fix-first regardless of a modest CVSS.
const KEV_FLOOR: f64 = 85.0;
/// Ransomware-associated KEV floor — the highest urgency tier.
const KEV_RANSOMWARE_FLOOR: f64 = 95.0;
/// Multiplier applied when any finding in the group sits on an attack-path choke point.
const CHOKE_POINT_MULTIPLIER: f64 = 1.25;
/// Multiplier applied when the affected asset is a designated crown jewel (business-critical).
const CROWN_JEWEL_MULTIPLIER: f64 = 1.3;
/// Bounds on the per-asset business-value multiplier (risk_graph_nodes.asset_value).
const ASSET_VALUE_MIN: f64 = 0.25;
const ASSET_VALUE_MAX: f64 = 3.0;
/// Per-extra-finding efficiency bonus (one fix closing N findings is worth more), and its cap.
const FIX_EFFICIENCY_PER_FINDING: f64 = 1.5;
const FIX_EFFICIENCY_CAP: f64 = 15.0;

// --- Remediation SLA policy (calendar days) -------------------------------------------------
// Windows are aligned with CISA BOD 22-01 (known-exploited vulns get an aggressive, fixed clock)
// and common NIST-aligned vuln-management practice for everything else. KEV overrides severity:
// a known-exploited medium is more urgent than a theoretical critical.
/// Ransomware-associated KEV — the tightest window; active campaigns exploit these immediately.
const SLA_KEV_RANSOMWARE_DAYS: i64 = 7;
/// Known-exploited (CISA KEV) — BOD 22-01 posture for recently-added entries.
const SLA_KEV_DAYS: i64 = 14;
/// Critical risk (effective_risk ≥ 9.0) not on KEV.
const SLA_CRITICAL_DAYS: i64 = 15;
/// High risk (≥ 7.0).
const SLA_HIGH_DAYS: i64 = 30;
/// Medium risk (≥ 4.0).
const SLA_MEDIUM_DAYS: i64 = 90;
/// Low / informational.
const SLA_LOW_DAYS: i64 = 180;

/// Pick the SLA window (days) and its human-readable basis for one action's urgency.
/// KEV precedence mirrors the scoring floors: exploited-in-the-wild beats a high CVSS.
fn sla_target(kev: bool, kev_ransomware: bool, max_effective_risk: f64) -> (i64, &'static str) {
    if kev_ransomware {
        (SLA_KEV_RANSOMWARE_DAYS, "KEV — ransomware-associated")
    } else if kev {
        (SLA_KEV_DAYS, "KEV — known exploited in the wild")
    } else if max_effective_risk >= 9.0 {
        (SLA_CRITICAL_DAYS, "critical risk")
    } else if max_effective_risk >= 7.0 {
        (SLA_HIGH_DAYS, "high risk")
    } else if max_effective_risk >= 4.0 {
        (SLA_MEDIUM_DAYS, "medium risk")
    } else {
        (SLA_LOW_DAYS, "low risk")
    }
}

/// Evaluate an action against its SLA. Pure: the same (urgency, age) always yields the same
/// verdict, so ranking stays deterministic and testable. `age_days == None` → `Unknown`, never a
/// breach (we don't invent a deadline for a finding whose discovery time we don't know).
fn evaluate_sla(
    kev: bool,
    kev_ransomware: bool,
    max_effective_risk: f64,
    age_days: Option<i64>,
) -> SlaStatus {
    let (target_days, basis) = sla_target(kev, kev_ransomware, max_effective_risk);
    match age_days {
        Some(age) => {
            let due_in = target_days - age;
            // "Due soon" = within 20% of the window (at least 1 day) of the deadline.
            let soon = ((target_days as f64) * 0.2).ceil().max(1.0) as i64;
            let state = if due_in < 0 {
                SlaState::Overdue
            } else if due_in <= soon {
                SlaState::DueSoon
            } else {
                SlaState::OnTrack
            };
            SlaStatus {
                target_days,
                basis: basis.to_string(),
                age_days: Some(age),
                due_in_days: Some(due_in),
                state,
                breached: due_in < 0,
            }
        }
        None => SlaStatus {
            target_days,
            basis: basis.to_string(),
            age_days: None,
            due_in_days: None,
            state: SlaState::Unknown,
            breached: false,
        },
    }
}

/// Parse a CWE id ("CWE-89", "cwe89", "89") to its numeric id. `None` if it isn't a CWE number.
fn cwe_number(cwe: &str) -> Option<u32> {
    let digits: String = cwe.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// Advisory crosswalk from a weakness (CWE) to framework controls a fix helps satisfy.
///
/// Mappings favour published, defensible crosswalks: the OWASP Top 10 2021 category comes from
/// MITRE/OWASP's own CWE→category mapping; NIST 800-53r5 and PCI DSS 4.0 entries use the
/// well-established control most directly addressed by the weakness. Unknown CWEs return empty —
/// we never invent coverage. Returned refs are deduped by (framework, control) upstream.
fn controls_for_cwe(cwe: &str) -> Vec<ControlRef> {
    let Some(n) = cwe_number(cwe) else {
        return Vec::new();
    };
    // Helper category refs reused across related CWEs.
    let injection = ControlRef {
        framework: "OWASP Top 10 2021",
        control: "A03:2021",
        title: "Injection",
    };
    let broken_access = ControlRef {
        framework: "OWASP Top 10 2021",
        control: "A01:2021",
        title: "Broken Access Control",
    };
    let crypto_fail = ControlRef {
        framework: "OWASP Top 10 2021",
        control: "A02:2021",
        title: "Cryptographic Failures",
    };
    let authn_fail = ControlRef {
        framework: "OWASP Top 10 2021",
        control: "A07:2021",
        title: "Identification and Authentication Failures",
    };
    let si10 = ControlRef {
        framework: "NIST 800-53r5",
        control: "SI-10",
        title: "Information Input Validation",
    };
    let ia5 = ControlRef {
        framework: "NIST 800-53r5",
        control: "IA-5",
        title: "Authenticator Management",
    };
    let ia2 = ControlRef {
        framework: "NIST 800-53r5",
        control: "IA-2",
        title: "Identification and Authentication",
    };
    let sc8 = ControlRef {
        framework: "NIST 800-53r5",
        control: "SC-8",
        title: "Transmission Confidentiality and Integrity",
    };
    let ac6 = ControlRef {
        framework: "NIST 800-53r5",
        control: "AC-6",
        title: "Least Privilege",
    };

    match n {
        // --- Injection family -------------------------------------------------------------
        89 => vec![
            injection,
            si10,
            ControlRef { framework: "PCI DSS 4.0", control: "6.2.4", title: "Injection prevention" },
        ],
        79 => vec![
            injection,
            si10,
            ControlRef { framework: "PCI DSS 4.0", control: "6.2.4", title: "XSS prevention" },
        ],
        77 | 78 | 94 | 943 => vec![injection, si10],
        90 | 91 | 611 => vec![injection, si10],
        // --- Broken access control --------------------------------------------------------
        22 | 23 | 35 => vec![
            broken_access,
            si10,
            ControlRef { framework: "NIST 800-53r5", control: "AC-3", title: "Access Enforcement" },
        ],
        639 | 862 | 863 | 425 => vec![
            broken_access,
            ControlRef { framework: "NIST 800-53r5", control: "AC-3", title: "Access Enforcement" },
        ],
        352 => vec![
            broken_access,
            ControlRef { framework: "OWASP ASVS 4.0", control: "V4.2.2", title: "CSRF defenses" },
        ],
        918 => vec![ControlRef {
            framework: "OWASP Top 10 2021",
            control: "A10:2021",
            title: "Server-Side Request Forgery",
        }],
        732 => vec![
            broken_access,
            ac6,
            ControlRef { framework: "PCI DSS 4.0", control: "7.2.1", title: "Least-privilege access" },
        ],
        // --- Cryptographic failures -------------------------------------------------------
        327 | 326 | 328 => vec![
            crypto_fail,
            ControlRef { framework: "NIST 800-53r5", control: "SC-13", title: "Cryptographic Protection" },
        ],
        319 | 311 => vec![
            crypto_fail,
            sc8,
            ControlRef { framework: "PCI DSS 4.0", control: "4.2.1", title: "Encrypt data in transit" },
        ],
        // --- AuthN / secrets --------------------------------------------------------------
        798 | 259 | 321 => vec![
            authn_fail,
            ia5,
            ControlRef { framework: "PCI DSS 4.0", control: "8.3.1", title: "No hardcoded credentials" },
        ],
        287 | 306 | 288 => vec![
            authn_fail,
            ia2,
            ControlRef { framework: "PCI DSS 4.0", control: "8.3", title: "Strong authentication" },
        ],
        522 | 640 => vec![authn_fail, ia5],
        // --- Misconfiguration / exposure --------------------------------------------------
        16 | 1004 | 614 => vec![ControlRef {
            framework: "OWASP Top 10 2021",
            control: "A05:2021",
            title: "Security Misconfiguration",
        }],
        200 | 209 | 532 => vec![
            crypto_fail,
            ControlRef { framework: "NIST 800-53r5", control: "SC-28", title: "Protection of Information at Rest" },
        ],
        _ => Vec::new(),
    }
}

/// Union the crosswalk over a group's distinct CWEs, deduped by (framework, control).
fn compliance_for_group(group: &[FindingInput]) -> Vec<ControlRef> {
    let mut out: Vec<ControlRef> = Vec::new();
    for f in group {
        for ctrl in controls_for_cwe(&f.cwe) {
            if !out.iter().any(|c| c.framework == ctrl.framework && c.control == ctrl.control) {
                out.push(ctrl);
            }
        }
    }
    // Deterministic order for stable output.
    out.sort_by(|a, b| a.framework.cmp(b.framework).then(a.control.cmp(b.control)));
    out
}

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
    let any_crown = group.iter().any(|f| f.crown_jewel);
    // Highest asset-value multiplier in the group drives it (most valuable asset dominates).
    let max_asset_value = group.iter().map(|f| f.asset_value).fold(0.0_f64, f64::max);
    let asset_value = if max_asset_value > 0.0 {
        max_asset_value.clamp(ASSET_VALUE_MIN, ASSET_VALUE_MAX)
    } else {
        1.0
    };
    let count = group.len();

    let mut score = max_risk * 10.0; // 0..100
    let mut reasons: Vec<String> = Vec::new();
    reasons.push(format!("base risk {max_risk:.1}/10"));

    if any_choke {
        score *= CHOKE_POINT_MULTIPLIER;
        reasons.push("on attack-path choke point".to_string());
    }
    if any_crown {
        score *= CROWN_JEWEL_MULTIPLIER;
        reasons.push("protects a crown-jewel asset".to_string());
    }
    if (asset_value - 1.0).abs() > f64::EPSILON {
        score *= asset_value;
        reasons.push(format!("asset value x{asset_value:.2}"));
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
            let kev = group.iter().any(|f| f.kev);
            let kev_ransomware = group.iter().any(|f| f.kev_ransomware);
            // Oldest finding drives the SLA clock (most conservative — the group has been open at
            // least this long). Uses the full-precision max_risk, not the display-rounded value.
            let oldest_age = group.iter().filter_map(|f| f.first_seen_days).max();
            let sla = evaluate_sla(kev, kev_ransomware, max_risk, oldest_age);
            let compliance = compliance_for_group(&group);
            RemediationItem {
                rank: 0, // assigned after sort
                priority_score: score,
                title: rep.title.clone(),
                cwe: rep.cwe.clone(),
                asset: rep.asset.clone(),
                closes_findings: finding_ids.len(),
                kev,
                kev_ransomware,
                on_choke_point: group.iter().any(|f| f.on_choke_point),
                crown_jewel: group.iter().any(|f| f.crown_jewel),
                business_value_usd: group.iter().filter_map(|f| f.business_value_usd).max(),
                max_effective_risk: (max_risk * 10.0).round() / 10.0,
                max_epss,
                oldest_finding_age_days: oldest_age,
                sla,
                compliance,
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
                  COALESCE(n.is_choke_point, false)                       AS on_choke_point,
                  COALESCE(n.crown_jewel, false)                          AS crown_jewel,
                  COALESCE(n.asset_value, 1.0)                            AS asset_value,
                  n.business_value_usd                                    AS business_value_usd,
                  FLOOR(EXTRACT(EPOCH FROM (now() - v.discovered_at)) / 86400.0)::bigint
                                                                          AS first_seen_days
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
                crown_jewel: r.try_get("crown_jewel").unwrap_or(false),
                asset_value: r
                    .try_get::<f32, _>("asset_value")
                    .map(f64::from)
                    .unwrap_or(1.0),
                business_value_usd: r
                    .try_get::<Option<i64>, _>("business_value_usd")
                    .unwrap_or(None),
                first_seen_days: r
                    .try_get::<Option<i64>, _>("first_seen_days")
                    .unwrap_or(None)
                    .map(|d| d.max(0)),
            })
        })
        .collect();

    let total_findings = findings.len();
    let program = rank(&findings);
    let kev_actions = program.iter().filter(|i| i.kev).count();
    let choke_actions = program.iter().filter(|i| i.on_choke_point).count();
    let crown_jewel_actions = program.iter().filter(|i| i.crown_jewel).count();
    let overdue_actions = program
        .iter()
        .filter(|i| i.sla.state == SlaState::Overdue)
        .count();
    let due_soon_actions = program
        .iter()
        .filter(|i| i.sla.state == SlaState::DueSoon)
        .count();
    let actions_mapped_to_controls = program.iter().filter(|i| !i.compliance.is_empty()).count();
    let mut compliance_frameworks: Vec<&'static str> = program
        .iter()
        .flat_map(|i| i.compliance.iter().map(|c| c.framework))
        .collect();
    compliance_frameworks.sort_unstable();
    compliance_frameworks.dedup();

    Ok(json!({
        "ok": true,
        "client_id": client_id,
        "total_findings": total_findings,
        "remediation_actions": program.len(),
        "kev_actions": kev_actions,
        "choke_point_actions": choke_actions,
        "crown_jewel_actions": crown_jewel_actions,
        "overdue_actions": overdue_actions,
        "due_soon_actions": due_soon_actions,
        "actions_mapped_to_controls": actions_mapped_to_controls,
        "compliance_frameworks": compliance_frameworks,
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
            crown_jewel: false,
            asset_value: 1.0,
            business_value_usd: None,
            first_seen_days: None,
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
    fn crown_jewel_boosts_priority() {
        let plain = f("plain", "high", Some(7.0));
        let mut jewel = f("jewel", "high", Some(7.0));
        jewel.cwe = "CWE-79".into(); // separate group
        jewel.crown_jewel = true;
        let program = rank(&[plain, jewel]);
        let jewel_item = program.iter().find(|i| i.crown_jewel).unwrap();
        let plain_item = program.iter().find(|i| !i.crown_jewel).unwrap();
        assert!(jewel_item.priority_score > plain_item.priority_score);
        assert!(jewel_item.rationale.contains("crown-jewel"));
    }

    #[test]
    fn high_asset_value_boosts_priority_and_default_is_neutral() {
        let neutral = f("neutral", "medium", Some(5.0)); // asset_value 1.0 => unchanged
        let mut valuable = f("valuable", "medium", Some(5.0));
        valuable.cwe = "CWE-79".into(); // separate group
        valuable.asset_value = 3.0;
        let program = rank(&[neutral, valuable]);
        let v = program.iter().find(|i| i.finding_ids == vec!["valuable"]).unwrap();
        let n = program.iter().find(|i| i.finding_ids == vec!["neutral"]).unwrap();
        assert!(v.priority_score > n.priority_score);
        // Default asset_value must not perturb the base score (5.0 * 10 = 50.0).
        assert_eq!(n.priority_score, 50.0);
    }

    #[test]
    fn business_value_usd_is_surfaced_as_group_max() {
        let mut a = f("a", "high", Some(7.0));
        let mut b = f("b", "high", Some(7.0)); // same CWE-89 + asset => one group
        a.business_value_usd = Some(1_000_000);
        b.business_value_usd = Some(5_000_000);
        let program = rank(&[a, b]);
        assert_eq!(program.len(), 1);
        assert_eq!(program[0].business_value_usd, Some(5_000_000));
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

    #[test]
    fn kev_gets_tighter_sla_than_equal_risk_non_kev() {
        let mut kev = f("kev", "medium", Some(5.0));
        kev.kev = true;
        let non_kev = f("non", "medium", Some(5.0));
        assert!(
            evaluate_sla(true, false, 5.0, None).target_days
                < evaluate_sla(false, false, 5.0, None).target_days
        );
        // sanity: the constructed findings carry the flags used above
        assert!(kev.kev && !non_kev.kev);
    }

    #[test]
    fn ransomware_kev_has_the_tightest_window() {
        assert_eq!(
            evaluate_sla(true, true, 3.0, None).target_days,
            SLA_KEV_RANSOMWARE_DAYS
        );
        assert!(SLA_KEV_RANSOMWARE_DAYS < SLA_KEV_DAYS);
    }

    #[test]
    fn overdue_when_age_exceeds_window() {
        // KEV window is 14 days; a finding open 30 days is breached.
        let sla = evaluate_sla(true, false, 5.0, Some(30));
        assert_eq!(sla.state, SlaState::Overdue);
        assert!(sla.breached);
        assert_eq!(sla.due_in_days, Some(14 - 30));
    }

    #[test]
    fn due_soon_inside_the_final_fifth_of_the_window() {
        // High risk => 30-day window; soon threshold = ceil(30*0.2)=6. Age 25 => due_in 5 <= 6.
        let sla = evaluate_sla(false, false, 7.5, Some(25));
        assert_eq!(sla.state, SlaState::DueSoon);
        assert!(!sla.breached);
    }

    #[test]
    fn on_track_early_in_the_window() {
        let sla = evaluate_sla(false, false, 7.5, Some(1));
        assert_eq!(sla.state, SlaState::OnTrack);
    }

    #[test]
    fn unknown_age_is_never_a_breach() {
        let sla = evaluate_sla(true, true, 9.9, None);
        assert_eq!(sla.state, SlaState::Unknown);
        assert!(!sla.breached);
        assert_eq!(sla.due_in_days, None);
    }

    #[test]
    fn cwe_number_parses_common_forms() {
        assert_eq!(cwe_number("CWE-89"), Some(89));
        assert_eq!(cwe_number("cwe89"), Some(89));
        assert_eq!(cwe_number("89"), Some(89));
        assert_eq!(cwe_number(""), None);
        assert_eq!(cwe_number("n/a"), None);
    }

    #[test]
    fn sqli_maps_to_injection_controls() {
        let ctrls = controls_for_cwe("CWE-89");
        assert!(ctrls
            .iter()
            .any(|c| c.framework == "OWASP Top 10 2021" && c.control == "A03:2021"));
        assert!(ctrls.iter().any(|c| c.framework == "NIST 800-53r5"));
    }

    #[test]
    fn unknown_cwe_maps_to_no_controls() {
        assert!(controls_for_cwe("CWE-99999").is_empty());
        assert!(controls_for_cwe("").is_empty());
    }

    #[test]
    fn group_compliance_dedups_across_same_cwe() {
        // Two SQLi findings on the same asset collapse into one action; controls must not double.
        let a = f("a", "high", Some(7.0));
        let b = f("b", "high", Some(7.0)); // same CWE-89 + asset => same group
        let program = rank(&[a, b]);
        assert_eq!(program.len(), 1);
        let controls = &program[0].compliance;
        let owasp = controls
            .iter()
            .filter(|c| c.framework == "OWASP Top 10 2021")
            .count();
        assert_eq!(owasp, 1, "no duplicate OWASP entry from two same-CWE findings");
        assert!(!controls.is_empty());
    }

    #[test]
    fn group_sla_uses_the_oldest_finding() {
        // Same cluster: one finding is fresh, one is old. The old one drives the clock.
        let mut fresh = f("fresh", "high", Some(7.5));
        let mut old = f("old", "high", Some(7.5));
        fresh.cluster_id = Some(9);
        old.cluster_id = Some(9);
        fresh.first_seen_days = Some(2);
        old.first_seen_days = Some(40); // > 30-day high-risk window
        let program = rank(&[fresh, old]);
        assert_eq!(program.len(), 1);
        assert_eq!(program[0].oldest_finding_age_days, Some(40));
        assert_eq!(program[0].sla.state, SlaState::Overdue);
    }
}
