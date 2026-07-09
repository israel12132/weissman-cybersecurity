//! Per-client MITRE ATT&CK *exposure* — the live counterpart to the static coverage matrix.
//!
//! `attack_coverage` answers "which techniques can our engines detect?". This module answers the
//! operational question a SOC actually asks: "which techniques is THIS client exposed to right
//! now, and how badly?" It aggregates the ATT&CK technique ids the engines already stamp onto
//! findings into a technique ranking and a tactic rollup, grounding technique/tactic names in the
//! curated [`crate::attack_coverage`] catalog (never inventing a mapping we can't back).
//!
//! Technique ids are scattered across keys (`mitre`, `mitre_attack`, `mitre_techniques`,
//! `technique`, `techniques`) and shapes (a bare string or an array), so extraction normalises all
//! of them. Scoring is pure and deterministic; the DB loader reads only live rows (RLS-scoped).

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Keys a finding may carry its ATT&CK technique id(s) under, across the engine fleet.
const TECHNIQUE_KEYS: [&str; 5] = [
    "mitre",
    "mitre_attack",
    "mitre_techniques",
    "technique",
    "techniques",
];

const UNMAPPED_TACTIC: &str = "Unmapped";

/// True if `s` looks like an ATT&CK Enterprise technique id: `T####` with an optional `.###`
/// sub-technique. Guards against junk landing in a "technique" field.
fn is_technique_id(s: &str) -> bool {
    if s.as_bytes().first() != Some(&b'T') {
        return false;
    }
    let rest = &s[1..];
    match rest.split_once('.') {
        Some((base, sub)) => {
            base.len() == 4
                && base.bytes().all(|b| b.is_ascii_digit())
                && (1..=3).contains(&sub.len())
                && sub.bytes().all(|b| b.is_ascii_digit())
        }
        None => rest.len() == 4 && rest.bytes().all(|b| b.is_ascii_digit()),
    }
}

fn collect_from_str(raw: &str, out: &mut Vec<String>) {
    let id = raw.trim().to_ascii_uppercase();
    if is_technique_id(&id) && !out.contains(&id) {
        out.push(id);
    }
}

/// Extract every distinct, well-formed ATT&CK technique id a finding declares (deduped per finding).
#[must_use]
pub fn techniques_of(finding: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Some(obj) = finding.as_object() else {
        return out;
    };
    for key in TECHNIQUE_KEYS {
        match obj.get(key) {
            Some(Value::String(s)) => collect_from_str(s, &mut out),
            Some(Value::Array(arr)) => {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        collect_from_str(s, &mut out);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn norm_severity(sev: &str) -> &'static str {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "info" | "informational" => "info",
        _ => "other",
    }
}

/// Per-technique exposure: how many findings map to it, by severity, plus curated metadata.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TechniqueStat {
    pub technique: String,
    /// Curated technique name, when the id resolves against the coverage catalog.
    pub name: Option<String>,
    /// Curated ATT&CK tactic, or "Unmapped" when the id isn't in the catalog.
    pub tactic: String,
    pub count: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub other: usize,
}

/// Per-tactic rollup across a client's exposed techniques.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TacticStat {
    pub tactic: String,
    pub technique_count: usize,
    pub finding_count: usize,
}

#[derive(Debug, Default)]
struct Acc {
    count: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    other: usize,
}

impl Acc {
    fn bump(&mut self, sev: &str) {
        self.count += 1;
        match sev {
            "critical" => self.critical += 1,
            "high" => self.high += 1,
            "medium" => self.medium += 1,
            "low" => self.low += 1,
            "info" => self.info += 1,
            _ => self.other += 1,
        }
    }
}

/// Aggregate findings into an ATT&CK exposure ranking. Each `finding` should carry a `severity`
/// string and technique id(s). Deterministic: sorted by finding-count desc, then technique id asc.
#[must_use]
pub fn aggregate(findings: &[Value]) -> Vec<TechniqueStat> {
    let mut by_tech: BTreeMap<String, Acc> = BTreeMap::new();
    for f in findings {
        let sev = norm_severity(f.get("severity").and_then(Value::as_str).unwrap_or(""));
        for tech in techniques_of(f) {
            by_tech.entry(tech).or_default().bump(sev);
        }
    }
    let mut stats: Vec<TechniqueStat> = by_tech
        .into_iter()
        .map(|(technique, a)| {
            let meta = crate::attack_coverage::lookup(&technique);
            TechniqueStat {
                name: meta.map(|m| m.name.to_string()),
                tactic: meta.map_or_else(|| UNMAPPED_TACTIC.to_string(), |m| m.tactic.to_string()),
                technique,
                count: a.count,
                critical: a.critical,
                high: a.high,
                medium: a.medium,
                low: a.low,
                info: a.info,
                other: a.other,
            }
        })
        .collect();
    stats.sort_by(|a, b| b.count.cmp(&a.count).then(a.technique.cmp(&b.technique)));
    stats
}

/// Roll technique stats up to tactics. Deterministic: sorted by finding-count desc, then tactic asc.
#[must_use]
pub fn tactic_rollup(stats: &[TechniqueStat]) -> Vec<TacticStat> {
    let mut by_tactic: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for s in stats {
        let e = by_tactic.entry(s.tactic.clone()).or_insert((0, 0));
        e.0 += 1; // technique_count
        e.1 += s.count; // finding_count
    }
    let mut out: Vec<TacticStat> = by_tactic
        .into_iter()
        .map(|(tactic, (technique_count, finding_count))| TacticStat {
            tactic,
            technique_count,
            finding_count,
        })
        .collect();
    out.sort_by(|a, b| {
        b.finding_count
            .cmp(&a.finding_count)
            .then(a.tactic.cmp(&b.tactic))
    });
    out
}

/// Load a client's live findings and aggregate ATT&CK exposure. Read-only; RLS-scoped.
pub async fn load_and_aggregate(
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
        r#"SELECT COALESCE(raw_data, '{}'::jsonb) AS rd,
                  COALESCE(severity, '')          AS severity
             FROM vulnerabilities
            WHERE tenant_id = $1
              AND client_id = $2
              AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE', 'VERIFIED_FIXED')
            ORDER BY id DESC
            LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let _ = tx.commit().await;

    let findings: Vec<Value> = rows
        .iter()
        .map(|r| {
            let mut v: Value = r.try_get("rd").unwrap_or_else(|_| json!({}));
            if !v.is_object() {
                v = json!({});
            }
            if let Some(obj) = v.as_object_mut() {
                // The row's severity column is authoritative over any stale copy in raw_data.
                obj.insert(
                    "severity".to_string(),
                    json!(r.try_get::<String, _>("severity").unwrap_or_default()),
                );
            }
            v
        })
        .collect();

    let coverage = aggregate(&findings);
    let tactics = tactic_rollup(&coverage);
    let findings_with_technique = findings
        .iter()
        .filter(|f| !techniques_of(f).is_empty())
        .count();

    Ok(json!({
        "ok": true,
        "client_id": client_id,
        "findings_analyzed": findings.len(),
        "findings_with_technique": findings_with_technique,
        "unique_techniques": coverage.len(),
        "tactics": tactics,
        "techniques": coverage,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technique_id_shape_is_validated() {
        assert!(is_technique_id("T1190"));
        assert!(is_technique_id("T1204.002"));
        assert!(!is_technique_id("T119")); // too short
        assert!(!is_technique_id("T11900")); // too long base
        assert!(!is_technique_id("X1190")); // wrong prefix
        assert!(!is_technique_id("T1190.")); // empty sub
        assert!(!is_technique_id("T1190.abcd")); // non-numeric/oversized sub
        assert!(!is_technique_id("initial-access"));
    }

    #[test]
    fn extracts_from_string_and_array_and_normalises_case() {
        assert_eq!(techniques_of(&json!({ "mitre": "t1190" })), vec!["T1190"]);
        assert_eq!(
            techniques_of(&json!({ "mitre": ["T1190", "T1505", "junk"] })),
            vec!["T1190", "T1505"]
        );
    }

    #[test]
    fn merges_across_keys_and_dedups_per_finding() {
        let f = json!({
            "mitre": "T1190",
            "mitre_attack": "T1190",              // duplicate id, different key
            "mitre_techniques": ["T1059", "T1190"],
            "technique": "T1505",
        });
        let mut got = techniques_of(&f);
        got.sort();
        assert_eq!(got, vec!["T1059", "T1190", "T1505"]);
    }

    #[test]
    fn missing_or_nonobject_yields_nothing() {
        assert!(techniques_of(&json!({})).is_empty());
        assert!(techniques_of(&json!({ "mitre": 42 })).is_empty());
        assert!(techniques_of(&json!("not an object")).is_empty());
    }

    #[test]
    fn aggregate_ranks_by_count_then_id_with_severity_breakdown() {
        let findings = vec![
            json!({ "severity": "critical", "mitre": "T1190" }),
            json!({ "severity": "high", "mitre": ["T1190", "T1059"] }),
            json!({ "severity": "medium", "mitre": "T1059" }),
            json!({ "severity": "low", "technique": "T1505" }),
        ];
        let cov = aggregate(&findings);
        // T1190 and T1059 both appear twice; tie breaks by id asc.
        assert_eq!(cov[0].technique, "T1059");
        assert_eq!(cov[0].count, 2);
        assert_eq!(cov[1].technique, "T1190");
        assert_eq!(cov[1].critical, 1);
        assert_eq!(cov[1].high, 1);
        assert_eq!(cov[2].technique, "T1505");
        assert_eq!(cov[2].low, 1);
    }

    #[test]
    fn a_finding_counts_once_per_technique_not_per_duplicate_key() {
        let findings = vec![json!({
            "severity": "high",
            "mitre": "T1190",
            "mitre_attack": "T1190",
        })];
        let cov = aggregate(&findings);
        assert_eq!(cov.len(), 1);
        assert_eq!(cov[0].count, 1);
        assert_eq!(cov[0].high, 1);
    }

    #[test]
    fn techniques_are_enriched_from_curated_catalog() {
        // T1190 is curated (Initial Access); an unknown-but-valid id falls back to Unmapped.
        let findings = vec![
            json!({ "severity": "high", "mitre": "T1190" }),
            json!({ "severity": "low", "mitre": "T1999" }),
        ];
        let cov = aggregate(&findings);
        let t1190 = cov.iter().find(|s| s.technique == "T1190").unwrap();
        assert_eq!(t1190.tactic, "Initial Access");
        assert_eq!(t1190.name.as_deref(), Some("Exploit Public-Facing Application"));
        let t1999 = cov.iter().find(|s| s.technique == "T1999").unwrap();
        assert_eq!(t1999.tactic, "Unmapped");
        assert!(t1999.name.is_none());
    }

    #[test]
    fn base_id_resolves_against_curated_sub_technique() {
        // Catalog has T1059.008; a finding reporting bare T1059 should still resolve to Execution.
        let cov = aggregate(&[json!({ "severity": "high", "mitre": "T1059" })]);
        assert_eq!(cov[0].tactic, "Execution");
    }

    #[test]
    fn tactic_rollup_groups_and_orders_by_finding_count() {
        let findings = vec![
            json!({ "severity": "high", "mitre": "T1190" }), // Initial Access
            json!({ "severity": "high", "mitre": "T1566" }), // Initial Access
            json!({ "severity": "high", "mitre": "T1046" }), // Discovery
        ];
        let cov = aggregate(&findings);
        let tactics = tactic_rollup(&cov);
        assert_eq!(tactics[0].tactic, "Initial Access");
        assert_eq!(tactics[0].technique_count, 2);
        assert_eq!(tactics[0].finding_count, 2);
        assert!(tactics.iter().any(|t| t.tactic == "Discovery"));
    }
}
