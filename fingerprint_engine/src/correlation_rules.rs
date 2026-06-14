//! Multi-stage temporal correlation — detection engineering beyond dedup.
//!
//! The existing `findings_correlator` clusters *duplicate* findings; it does not reason about an
//! attacker progressing through stages over time. This module adds **ordered, time-windowed
//! correlation**: a rule fires when a sequence of kill-chain stages (e.g. recon → initial access →
//! privilege escalation → exfiltration) is observed **in order, for the same target, within a time
//! window**. That converts a stream of isolated events into a single high-confidence incident.
//!
//! Everything here is deterministic and unit-tested; there is no LLM and no I/O.

use serde::Serialize;

/// A normalized security event placed on the kill chain.
#[derive(Debug, Clone, Serialize)]
pub struct CorrEvent {
    pub ts: i64,
    pub target: String,
    /// Kill-chain stage category, e.g. `recon`, `initial_access`, `execution`,
    /// `privilege_escalation`, `lateral_movement`, `exfiltration`, `impact`.
    pub category: String,
    pub signature: String,
    pub severity: String,
}

impl CorrEvent {
    pub fn new(ts: i64, target: &str, category: &str, signature: &str, severity: &str) -> Self {
        Self {
            ts,
            target: target.to_string(),
            category: category.to_string(),
            signature: signature.to_string(),
            severity: severity.to_string(),
        }
    }
}

/// One stage of a rule: matches an event whose category is in `categories`.
#[derive(Debug, Clone, Serialize)]
pub struct StageMatch {
    pub label: String,
    pub categories: Vec<String>,
}

impl StageMatch {
    pub fn new(label: &str, categories: &[&str]) -> Self {
        Self {
            label: label.to_string(),
            categories: categories.iter().map(|s| s.to_string()).collect(),
        }
    }
    fn matches(&self, ev: &CorrEvent) -> bool {
        self.categories.iter().any(|c| c == &ev.category)
    }
}

/// An ordered, time-windowed correlation rule, evaluated per target.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationRule {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub window_secs: i64,
    pub stages: Vec<StageMatch>,
}

/// A fired correlation: the ordered matched events for one target within the window.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationHit {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub target: String,
    pub started_ts: i64,
    pub ended_ts: i64,
    pub span_secs: i64,
    pub matched: Vec<CorrEvent>,
}

impl CorrelationHit {
    /// Stable idempotency key for the incident (rule + target + window bounds), hex SHA-256.
    pub fn incident_key(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.rule_id.as_bytes());
        h.update([0u8]);
        h.update(self.target.as_bytes());
        h.update([0u8]);
        h.update(self.started_ts.to_le_bytes());
        h.update(self.ended_ts.to_le_bytes());
        let d = h.finalize();
        let mut out = String::with_capacity(64);
        for b in d {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "target": self.target,
            "started_ts": self.started_ts,
            "ended_ts": self.ended_ts,
            "span_secs": self.span_secs,
            "stages": self.matched.iter().map(|e| serde_json::json!({
                "ts": e.ts, "category": e.category, "signature": e.signature, "severity": e.severity,
            })).collect::<Vec<_>>(),
        })
    }
}

/// Try to match all stages in order, anchoring stage 0 at `anchor`. Returns the matched indices.
fn match_from(stages: &[StageMatch], evs: &[CorrEvent], anchor: usize) -> Option<Vec<usize>> {
    if stages.is_empty() || anchor >= evs.len() || !stages[0].matches(&evs[anchor]) {
        return None;
    }
    let mut picked = vec![anchor];
    let mut idx = anchor + 1;
    for stage in &stages[1..] {
        while idx < evs.len() && !stage.matches(&evs[idx]) {
            idx += 1;
        }
        if idx >= evs.len() {
            return None;
        }
        picked.push(idx);
        idx += 1;
    }
    Some(picked)
}

/// Evaluate one rule against a set of events. Events are grouped by target, sorted by time, and
/// scanned for non-overlapping ordered stage sequences that complete within `window_secs`.
pub fn evaluate(rule: &CorrelationRule, events: &[CorrEvent]) -> Vec<CorrelationHit> {
    if rule.stages.is_empty() {
        return Vec::new();
    }
    // Group by target.
    let mut by_target: std::collections::BTreeMap<String, Vec<CorrEvent>> =
        std::collections::BTreeMap::new();
    for e in events {
        by_target
            .entry(e.target.clone())
            .or_default()
            .push(e.clone());
    }

    let mut hits = Vec::new();
    for (target, mut evs) in by_target {
        evs.sort_by_key(|e| e.ts);
        let mut i = 0usize;
        while i < evs.len() {
            if let Some(picked) = match_from(&rule.stages, &evs, i) {
                let start_ts = evs[picked[0]].ts;
                let end_ts = evs[*picked.last().unwrap()].ts;
                let span = end_ts - start_ts;
                if span >= 0 && span <= rule.window_secs {
                    hits.push(CorrelationHit {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: rule.severity.clone(),
                        target: target.clone(),
                        started_ts: start_ts,
                        ended_ts: end_ts,
                        span_secs: span,
                        matched: picked.iter().map(|&p| evs[p].clone()).collect(),
                    });
                    // Continue after the last matched event (non-overlapping).
                    i = picked[picked.len() - 1] + 1;
                    continue;
                }
            }
            i += 1;
        }
    }
    hits
}

/// Evaluate a set of rules and return all hits.
pub fn evaluate_all(rules: &[CorrelationRule], events: &[CorrEvent]) -> Vec<CorrelationHit> {
    rules.iter().flat_map(|r| evaluate(r, events)).collect()
}

/// Persist correlation incidents idempotently (tenant-scoped under RLS). Returns the number of
/// newly-inserted rows; re-running with the same windows is a no-op thanks to `incident_key`.
pub async fn persist_incidents(
    pool: &sqlx::PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    hits: &[CorrelationHit],
) -> Result<usize, sqlx::Error> {
    if hits.is_empty() {
        return Ok(0);
    }
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let mut inserted = 0usize;
    for h in hits {
        let stages_json = serde_json::to_string(
            &h.matched
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "ts": e.ts, "category": e.category,
                        "signature": e.signature, "severity": e.severity,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".to_string());

        let res = sqlx::query(
            r#"INSERT INTO weissman_correlation_incidents
                 (tenant_id, client_id, rule_id, rule_name, severity, target,
                  started_ts, ended_ts, span_secs, incident_key, stages)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
               ON CONFLICT (tenant_id, incident_key) DO NOTHING"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(&h.rule_id)
        .bind(&h.rule_name)
        .bind(&h.severity)
        .bind(&h.target)
        .bind(h.started_ts)
        .bind(h.ended_ts)
        .bind(h.span_secs)
        .bind(h.incident_key())
        .bind(stages_json)
        .execute(&mut *tx)
        .await?;
        inserted += res.rows_affected() as usize;
    }
    tx.commit().await?;
    Ok(inserted)
}

/// Classify a finding into a kill-chain stage from its MITRE technique / type / title.
pub fn classify_stage(mitre: &str, kind: &str, title: &str) -> &'static str {
    let m = mitre.to_ascii_uppercase();
    let hay = format!(
        "{} {}",
        kind.to_ascii_lowercase(),
        title.to_ascii_lowercase()
    );
    // MITRE tactic prefixes first (most reliable), then keyword fallback.
    if m.starts_with("T1595") || m.starts_with("T1592") || m.starts_with("T1590") {
        return "recon";
    }
    if m.starts_with("T1190") || m.starts_with("T1133") || m.starts_with("T1078") {
        return "initial_access";
    }
    if m.starts_with("T1059") || m.starts_with("T1203") {
        return "execution";
    }
    if m.starts_with("T1068") || m.starts_with("T1548") {
        return "privilege_escalation";
    }
    if m.starts_with("T1021") || m.starts_with("T1210") {
        return "lateral_movement";
    }
    if m.starts_with("T1567") || m.starts_with("T1041") || m.starts_with("T1530") {
        return "exfiltration";
    }
    if m.starts_with("T1486") || m.starts_with("T1485") {
        return "impact";
    }
    if hay.contains("recon") || hay.contains("scan") || hay.contains("enumerat") {
        return "recon";
    }
    if hay.contains("exploit") || hay.contains("rce") || hay.contains("injection") {
        return "initial_access";
    }
    if hay.contains("privilege") || hay.contains("escalat") {
        return "privilege_escalation";
    }
    if hay.contains("exfil") || hay.contains("leak") {
        return "exfiltration";
    }
    "other"
}

/// Build correlation events from findings. `ts_for` supplies a timestamp for a finding (e.g. its
/// `discovered_at`); when absent the caller can pass the index, but real callers should pass real
/// timestamps for the window logic to be meaningful.
pub fn events_from_findings<F>(findings: &[serde_json::Value], ts_for: F) -> Vec<CorrEvent>
where
    F: Fn(usize, &serde_json::Value) -> i64,
{
    findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let mitre = str_field(f, "mitre_attack");
            let kind = str_field(f, "type");
            let title = str_field(f, "title");
            let target = {
                let t = str_field(f, "target");
                if t.is_empty() {
                    str_field(f, "value")
                } else {
                    t
                }
            };
            let stage = classify_stage(&mitre, &kind, &title);
            CorrEvent::new(
                ts_for(i, f),
                &target,
                stage,
                &title,
                &str_field(f, "severity"),
            )
        })
        .collect()
}

fn str_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// A default rule pack. Extend per-tenant via stored rules.
pub fn default_rules() -> Vec<CorrelationRule> {
    vec![CorrelationRule {
        id: "intrusion_progression".to_string(),
        name: "Intrusion progression (recon → access → priv-esc → exfil)".to_string(),
        severity: "critical".to_string(),
        window_secs: 3600,
        stages: vec![
            StageMatch::new("recon", &["recon"]),
            StageMatch::new("access", &["initial_access", "execution"]),
            StageMatch::new("priv_esc", &["privilege_escalation"]),
            StageMatch::new("exfil", &["exfiltration", "impact"]),
        ],
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> CorrelationRule {
        CorrelationRule {
            id: "test".into(),
            name: "test".into(),
            severity: "high".into(),
            window_secs: 600,
            stages: vec![
                StageMatch::new("a", &["recon"]),
                StageMatch::new("b", &["initial_access"]),
                StageMatch::new("c", &["exfiltration"]),
            ],
        }
    }

    #[test]
    fn ordered_within_window_fires() {
        let evs = vec![
            CorrEvent::new(100, "t1", "recon", "scan", "info"),
            CorrEvent::new(200, "t1", "initial_access", "rce", "high"),
            CorrEvent::new(300, "t1", "exfiltration", "dump", "critical"),
        ];
        let hits = evaluate(&rule(), &evs);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched.len(), 3);
        assert_eq!(hits[0].span_secs, 200);
        assert_eq!(hits[0].target, "t1");
    }

    #[test]
    fn out_of_order_does_not_fire() {
        // exfil happens before access → no ordered match.
        let evs = vec![
            CorrEvent::new(100, "t1", "recon", "scan", "info"),
            CorrEvent::new(200, "t1", "exfiltration", "dump", "critical"),
            CorrEvent::new(300, "t1", "initial_access", "rce", "high"),
        ];
        let hits = evaluate(&rule(), &evs);
        assert!(hits.is_empty());
    }

    #[test]
    fn outside_window_does_not_fire() {
        let evs = vec![
            CorrEvent::new(0, "t1", "recon", "scan", "info"),
            CorrEvent::new(100, "t1", "initial_access", "rce", "high"),
            CorrEvent::new(5000, "t1", "exfiltration", "dump", "critical"), // span 5000 > 600
        ];
        let hits = evaluate(&rule(), &evs);
        assert!(hits.is_empty());
    }

    #[test]
    fn targets_are_isolated() {
        // Stages split across two targets must not correlate into one hit.
        let evs = vec![
            CorrEvent::new(100, "t1", "recon", "scan", "info"),
            CorrEvent::new(200, "t2", "initial_access", "rce", "high"),
            CorrEvent::new(300, "t1", "exfiltration", "dump", "critical"),
        ];
        let hits = evaluate(&rule(), &evs);
        assert!(hits.is_empty());
    }

    #[test]
    fn partial_chain_does_not_fire() {
        let evs = vec![
            CorrEvent::new(100, "t1", "recon", "scan", "info"),
            CorrEvent::new(200, "t1", "initial_access", "rce", "high"),
        ];
        let hits = evaluate(&rule(), &evs);
        assert!(hits.is_empty());
    }

    #[test]
    fn classify_stage_maps_mitre() {
        assert_eq!(classify_stage("T1190", "", ""), "initial_access");
        assert_eq!(classify_stage("T1068", "", ""), "privilege_escalation");
        assert_eq!(classify_stage("T1567", "", ""), "exfiltration");
        assert_eq!(
            classify_stage("", "recon_engine", "subdomain scan"),
            "recon"
        );
    }

    #[test]
    fn default_rule_fires_on_full_progression() {
        let findings = vec![
            serde_json::json!({"mitre_attack":"T1595","type":"recon","title":"scan","severity":"info","target":"app.example.com"}),
            serde_json::json!({"mitre_attack":"T1190","type":"poe","title":"rce","severity":"critical","target":"app.example.com"}),
            serde_json::json!({"mitre_attack":"T1068","type":"privesc","title":"sudo","severity":"high","target":"app.example.com"}),
            serde_json::json!({"mitre_attack":"T1567","type":"exfil","title":"dump","severity":"critical","target":"app.example.com"}),
        ];
        // Monotonic timestamps 60s apart → within the 3600s window.
        let evs = events_from_findings(&findings, |i, _| 1000 + (i as i64) * 60);
        let hits = evaluate_all(&default_rules(), &evs);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "intrusion_progression");
        assert_eq!(hits[0].matched.len(), 4);
    }

    #[test]
    fn incident_key_is_stable_and_window_sensitive() {
        let base = CorrelationHit {
            rule_id: "r".into(),
            rule_name: "n".into(),
            severity: "high".into(),
            target: "t1".into(),
            started_ts: 100,
            ended_ts: 300,
            span_secs: 200,
            matched: vec![],
        };
        let same = base.clone();
        let mut diff = base.clone();
        diff.ended_ts = 400;
        assert_eq!(base.incident_key(), same.incident_key());
        assert_ne!(base.incident_key(), diff.incident_key());
        assert_eq!(base.incident_key().len(), 64);
    }
}
