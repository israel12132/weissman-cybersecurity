//! **Risk Superposition Collapse Engine** — multi-engine Bayesian belief fusion + STRIPS planning.
//!
//! Weak signals from hundreds of engines exist in *superposition* until independent corroboration
//! collapses them into high-confidence attack chains no single scanner can emit. All inputs are
//! live tenant DB state; zero LLM hallucination.

use crate::arsenal_config::{finding_rich, Evidence};
use crate::attack_chain_planner::{self, AttackChain, Fact};
use crate::attack_path;
use crate::correlation_rules::{self, CorrEvent, CorrelationRule};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding};
use crate::engine_result::{print_result, EngineResult};
use crate::financial_risk;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};

const ENGINE_ID: &str = "risk_superposition_collapse";
const MITRE: &str = "T1595";

#[derive(Debug, Clone)]
pub struct SuperpositionConfig {
    pub weak_signal_threshold: f64,
    pub collapsed_belief_threshold: f64,
    pub min_corroboration_engines: usize,
    pub max_clusters: i64,
    pub max_findings: i64,
    pub include_attack_paths: bool,
    pub include_belief_fusion: bool,
    pub include_strips_collapse: bool,
    pub include_toxic_combinations: bool,
    pub include_temporal_correlation: bool,
    pub include_financial_ale: bool,
    pub fusion_mode: FusionMode,
    pub temporal_decay_halflife_hours: f64,
    pub kev_belief_boost: f64,
    pub member_count_boost: f64,
    pub max_fusion_findings: usize,
    pub max_graph_paths: usize,
    pub max_planner_expansions: usize,
    pub planner_goals: Vec<String>,
    pub require_weak_for_collapse: bool,
    pub min_weak_clusters: usize,
    pub attack_path_top_k: usize,
    pub emit_choke_points: bool,
    pub posture_penalty_per_chain: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FusionMode {
    NoisyOr,
    LogOdds,
    Hybrid,
}

impl SuperpositionConfig {
    pub fn from_params(params: &Value) -> Self {
        let fusion_mode = match params
            .get("fusion_mode")
            .and_then(Value::as_str)
            .unwrap_or("hybrid")
            .to_ascii_lowercase()
            .as_str()
        {
            "noisy_or" => FusionMode::NoisyOr,
            "log_odds" => FusionMode::LogOdds,
            _ => FusionMode::Hybrid,
        };
        let goals_raw = params
            .get("planner_goals")
            .and_then(Value::as_str)
            .unwrap_or("impact:objective,access:crown_jewel,data:db_read");
        let planner_goals: Vec<String> = goals_raw
            .split([',', '\n'])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            weak_signal_threshold: pf64(params, "weak_signal_threshold", 4.0).clamp(0.0, 10.0),
            collapsed_belief_threshold: pf64(params, "collapsed_belief_threshold", 0.55)
                .clamp(0.05, 0.99),
            min_corroboration_engines: pi64(params, "min_corroboration_engines", 2) as usize,
            max_clusters: pi64(params, "max_clusters", 500),
            max_findings: pi64(params, "max_findings", 1000),
            include_attack_paths: pbool(params, "include_attack_paths", true),
            include_belief_fusion: pbool(params, "include_belief_fusion", true),
            include_strips_collapse: pbool(params, "include_strips_collapse", true),
            include_toxic_combinations: pbool(params, "include_toxic_combinations", true),
            include_temporal_correlation: pbool(params, "include_temporal_correlation", true),
            include_financial_ale: pbool(params, "include_financial_ale", true),
            fusion_mode,
            temporal_decay_halflife_hours: pf64(params, "temporal_decay_halflife_hours", 168.0)
                .max(0.0),
            kev_belief_boost: pf64(params, "kev_belief_boost", 0.15).clamp(0.0, 0.5),
            member_count_boost: pf64(params, "member_count_boost", 0.05).clamp(0.0, 0.3),
            max_fusion_findings: pi64(params, "max_fusion_findings", 20) as usize,
            max_graph_paths: pi64(params, "max_graph_paths", 5) as usize,
            max_planner_expansions: pi64(params, "max_planner_expansions", 50_000) as usize,
            planner_goals: if planner_goals.is_empty() {
                vec![
                    "impact:objective".into(),
                    "access:crown_jewel".into(),
                    "data:db_read".into(),
                ]
            } else {
                planner_goals
            },
            require_weak_for_collapse: pbool(params, "require_weak_for_collapse", false),
            min_weak_clusters: pi64(params, "min_weak_clusters_for_collapse", 1) as usize,
            attack_path_top_k: pi64(params, "attack_path_top_k", 10) as usize,
            emit_choke_points: pbool(params, "emit_choke_points", true),
            posture_penalty_per_chain: pi64(params, "posture_penalty_per_chain", 12) as u32,
        }
    }

    pub fn fuse(&self, probs: &[f64]) -> f64 {
        match self.fusion_mode {
            FusionMode::NoisyOr => noisy_or_belief(probs),
            FusionMode::LogOdds => log_odds_fusion(probs),
            FusionMode::Hybrid => {
                let a = noisy_or_belief(probs);
                let b = log_odds_fusion(probs);
                a.max(b)
            }
        }
    }
}

#[derive(Debug, Clone)]
struct ClusterEvidence {
    id: i64,
    target: String,
    title: String,
    cwe: String,
    vuln_signature: String,
    member_count: i32,
    engines: Vec<String>,
    max_severity: String,
    kev_listed: bool,
    avg_effective_risk: f64,
    avg_confidence: f64,
    max_epss: f64,
    age_hours: f64,
}

/// Independent corroboration (noisy-or): `1 − ∏(1 − pᵢ)`.
#[must_use]
pub fn noisy_or_belief(probs: &[f64]) -> f64 {
    if probs.is_empty() {
        return 0.0;
    }
    let product: f64 = probs
        .iter()
        .map(|p| 1.0 - p.clamp(0.0, 1.0))
        .product();
    (1.0 - product).clamp(0.0, 1.0)
}

/// Cumulative-odds fusion — sums independent odds (aggressive lift for corroborating weak signals).
#[must_use]
pub fn log_odds_fusion(probs: &[f64]) -> f64 {
    if probs.is_empty() {
        return 0.0;
    }
    let odds_sum: f64 = probs
        .iter()
        .map(|p| {
            let p = p.clamp(0.01, 0.99);
            p / (1.0 - p)
        })
        .sum();
    (odds_sum / (1.0 + odds_sum)).clamp(0.0, 1.0)
}

#[must_use]
pub fn temporal_decay(age_hours: f64, halflife_hours: f64) -> f64 {
    if halflife_hours <= 0.0 {
        return 1.0;
    }
    0.5_f64.powf((age_hours / halflife_hours).max(0.0))
}

#[must_use]
pub fn risk_to_belief(effective_risk: f64, confidence: f64) -> f64 {
    ((effective_risk / 10.0) * confidence.clamp(0.1, 1.0)).clamp(0.0, 1.0)
}

#[must_use]
pub fn cluster_belief(c: &ClusterEvidence, cfg: &SuperpositionConfig) -> f64 {
    let mut b = risk_to_belief(c.avg_effective_risk, c.avg_confidence);
    b *= temporal_decay(c.age_hours, cfg.temporal_decay_halflife_hours);
    if c.kev_listed {
        b = (b + cfg.kev_belief_boost).min(1.0);
    }
    if c.member_count > 1 {
        let boost = (c.member_count as f64 - 1.0) * cfg.member_count_boost;
        b = (b + boost).min(1.0);
    }
    if c.max_epss > 0.0 {
        b = (b + c.max_epss * 0.1).min(1.0);
    }
    b
}

#[must_use]
pub fn is_weak_cluster(c: &ClusterEvidence, weak_threshold: f64) -> bool {
    if c.avg_effective_risk < weak_threshold {
        return true;
    }
    matches!(
        c.max_severity.to_ascii_lowercase().as_str(),
        "info" | "low" | "medium"
    )
}

fn pbool(params: &Value, key: &str, default: bool) -> bool {
    params.get(key).and_then(Value::as_bool).unwrap_or(default)
}

fn pf64(params: &Value, key: &str, default: f64) -> f64 {
    params
        .get(key)
        .and_then(|v| v.as_f64())
        .unwrap_or(default)
}

fn pi64(params: &Value, key: &str, default: i64) -> i64 {
    params
        .get(key)
        .and_then(|v| v.as_i64())
        .unwrap_or(default)
        .clamp(1, 500_000)
}

fn belief_to_severity(belief: f64) -> &'static str {
    if belief >= 0.85 {
        "critical"
    } else if belief >= 0.70 {
        "high"
    } else if belief >= 0.50 {
        "medium"
    } else {
        "low"
    }
}

fn finding_category(f: &Value) -> String {
    let hay = format!(
        "{} {} {}",
        f.get("type").and_then(Value::as_str).unwrap_or(""),
        f.get("title").and_then(Value::as_str).unwrap_or(""),
        f.get("category").and_then(Value::as_str).unwrap_or(""),
    )
    .to_ascii_lowercase();
    if hay.contains("exfil") || hay.contains("leak") {
        return "exfiltration".into();
    }
    if hay.contains("priv") || hay.contains("escal") {
        return "privilege_escalation".into();
    }
    if hay.contains("lateral") {
        return "lateral_movement".into();
    }
    if hay.contains("cred") || hay.contains("password") || hay.contains("auth") {
        return "initial_access".into();
    }
    if hay.contains("recon") || hay.contains("osint") || hay.contains("asm") {
        return "recon".into();
    }
    "execution".into()
}

async fn load_clusters(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> Result<Vec<ClusterEvidence>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;

    let rows = sqlx::query(
        r#"SELECT c.id, c.target, c.title, c.cwe, c.vuln_signature,
                  c.member_count, c.engines, c.max_severity, c.kev_listed,
                  COALESCE(AVG(v.effective_risk), 0)::float8 AS avg_effective_risk,
                  COALESCE(AVG(v.confidence_multiplier), 1.0)::float8 AS avg_confidence,
                  COALESCE(MAX(v.epss_score), 0)::float8 AS max_epss,
                  EXTRACT(EPOCH FROM (now() - c.last_seen_at)) / 3600.0 AS age_hours
             FROM weissman_finding_clusters c
             LEFT JOIN vulnerabilities v
               ON v.cluster_id = c.id
              AND COALESCE(v.status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE')
            WHERE c.tenant_id = $1 AND c.client_id = $2
              AND UPPER(c.status) = 'OPEN'
            GROUP BY c.id
            ORDER BY c.member_count DESC, avg_effective_risk DESC NULLS LAST
            LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("load clusters: {e}"))?;

    let _ = tx.commit().await;

    Ok(rows
        .into_iter()
        .map(|r| ClusterEvidence {
            id: r.try_get("id").unwrap_or(0),
            target: r.try_get("target").unwrap_or_default(),
            title: r.try_get("title").unwrap_or_default(),
            cwe: r.try_get("cwe").unwrap_or_default(),
            vuln_signature: r.try_get("vuln_signature").unwrap_or_default(),
            member_count: r.try_get("member_count").unwrap_or(0),
            engines: r.try_get("engines").unwrap_or_default(),
            max_severity: r.try_get("max_severity").unwrap_or_default(),
            kev_listed: r.try_get("kev_listed").unwrap_or(false),
            avg_effective_risk: r.try_get("avg_effective_risk").unwrap_or(0.0),
            avg_confidence: r.try_get("avg_confidence").unwrap_or(1.0),
            max_epss: r.try_get("max_epss").unwrap_or(0.0),
            age_hours: r.try_get("age_hours").unwrap_or(0.0),
        })
        .collect())
}

async fn load_raw_findings(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    limit: i64,
) -> Result<Vec<Value>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;

    let rows = sqlx::query(
        r#"SELECT COALESCE(v.raw_data, '{}'::jsonb) AS rd,
                  COALESCE(v.title, '') AS title,
                  COALESCE(v.severity, '') AS severity,
                  COALESCE(v.source, '') AS source,
                  v.effective_risk,
                  v.confidence_multiplier,
                  COALESCE(EXTRACT(EPOCH FROM v.discovered_at)::bigint, 0) AS ts,
                  c.engines
             FROM vulnerabilities v
             LEFT JOIN weissman_finding_clusters c ON c.id = v.cluster_id
            WHERE v.tenant_id = $1 AND v.client_id = $2
              AND COALESCE(v.status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE')
            ORDER BY v.effective_risk DESC NULLS LAST, v.discovered_at DESC
            LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("load findings: {e}"))?;

    let _ = tx.commit().await;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let mut v: Value = r.try_get("rd").unwrap_or_else(|_| json!({}));
        if !v.is_object() {
            v = json!({});
        }
        if let Some(obj) = v.as_object_mut() {
            obj.entry("title")
                .or_insert_with(|| json!(r.try_get::<String, _>("title").unwrap_or_default()));
            obj.entry("severity")
                .or_insert_with(|| json!(r.try_get::<String, _>("severity").unwrap_or_default()));
            obj.entry("source")
                .or_insert_with(|| json!(r.try_get::<String, _>("source").unwrap_or_default()));
            if let Ok(er) = r.try_get::<f64, _>("effective_risk") {
                obj.insert("effective_risk".to_string(), json!(er));
            }
            if let Ok(cm) = r.try_get::<f64, _>("confidence_multiplier") {
                obj.insert("confidence_multiplier".to_string(), json!(cm));
            }
            if let Ok(engines) = r.try_get::<Vec<String>, _>("engines") {
                obj.insert("cluster_engines".to_string(), json!(engines));
            }
            if let Ok(ts) = r.try_get::<i64, _>("ts") {
                obj.insert("ts".to_string(), json!(ts));
            }
        }
        out.push(v);
    }
    Ok(out)
}

fn cluster_as_finding(c: &ClusterEvidence) -> Value {
    json!({
        "type": c.vuln_signature,
        "title": c.title,
        "severity": c.max_severity,
        "cwe": c.cwe,
        "target": c.target,
        "engines": c.engines,
        "kev_listed": c.kev_listed,
    })
}

fn fact_belief_map(
    clusters: &[ClusterEvidence],
    findings: &[Value],
    cfg: &SuperpositionConfig,
) -> HashMap<Fact, Vec<(i64, f64, bool)>> {
    let mut map: HashMap<Fact, Vec<(i64, f64, bool)>> = HashMap::new();

    for c in clusters {
        let belief = cluster_belief(c, cfg);
        let weak = is_weak_cluster(c, cfg.weak_signal_threshold);
        for fact in attack_chain_planner::facts_from_findings(&[cluster_as_finding(c)]) {
            map.entry(fact).or_default().push((c.id, belief, weak));
        }
    }
    for rf in findings {
        let er = rf.get("effective_risk").and_then(Value::as_f64).unwrap_or(3.0);
        let cm = rf
            .get("confidence_multiplier")
            .and_then(Value::as_f64)
            .unwrap_or(1.0);
        let belief = risk_to_belief(er, cm);
        for fact in attack_chain_planner::facts_from_findings(&[rf.clone()]) {
            map.entry(fact).or_default().push((0, belief, belief < 0.4));
        }
    }

    for entries in map.values_mut() {
        let mut by_id: HashMap<i64, (f64, bool)> = HashMap::new();
        for (id, b, w) in entries.drain(..) {
            by_id
                .entry(id)
                .and_modify(|(eb, ew)| {
                    if b > *eb {
                        *eb = b;
                    }
                    *ew = *ew || w;
                })
                .or_insert((b, w));
        }
        *entries = by_id
            .into_iter()
            .map(|(id, (b, w))| (id, b, w))
            .collect();
    }
    map
}

fn build_initial_facts(
    fact_map: &HashMap<Fact, Vec<(i64, f64, bool)>>,
    cfg: &SuperpositionConfig,
    clusters: &[ClusterEvidence],
) -> HashSet<Fact> {
    let mut facts: HashSet<Fact> = HashSet::new();
    for (fact, entries) in fact_map {
        let probs: Vec<f64> = entries.iter().map(|(_, b, _)| *b).collect();
        let fused = cfg.fuse(&probs);
        let engine_count: HashSet<&str> = clusters
            .iter()
            .filter(|c| entries.iter().any(|(id, _, _)| *id == c.id))
            .flat_map(|c| c.engines.iter().map(String::as_str))
            .collect();
        if fused >= cfg.collapsed_belief_threshold
            || engine_count.len() >= cfg.min_corroboration_engines
        {
            facts.insert(fact.clone());
        }
    }
    facts
}

fn weak_clusters_in_chain(
    clusters: &[ClusterEvidence],
    fact_map: &HashMap<Fact, Vec<(i64, f64, bool)>>,
    chain_facts: &HashSet<Fact>,
) -> Vec<i64> {
    let mut ids = HashSet::new();
    for fact in chain_facts {
        if let Some(entries) = fact_map.get(fact) {
            for (id, _, weak) in entries {
                if *weak && *id > 0 {
                    ids.insert(*id);
                }
            }
        }
    }
    ids.into_iter()
        .filter(|id| clusters.iter().any(|c| c.id == *id))
        .collect()
}

struct ToxicPair {
    facts: [&'static str; 2],
    label: &'static str,
    mitre: &'static str,
}

const TOXIC_PAIRS: &[ToxicPair] = &[
    ToxicPair {
        facts: ["vuln:ssrf", "cloud:exposed"],
        label: "SSRF + cloud exposure → metadata credential theft",
        mitre: "T1552.005",
    },
    ToxicPair {
        facts: ["cred:leaked", "service:web"],
        label: "Leaked credentials + public web → foothold",
        mitre: "T1078",
    },
    ToxicPair {
        facts: ["vuln:authz", "service:web"],
        label: "Authorization gap + web API → data access",
        mitre: "T1190",
    },
    ToxicPair {
        facts: ["vuln:rce", "service:web"],
        label: "RCE primitive + internet-facing web",
        mitre: "T1190",
    },
    ToxicPair {
        facts: ["vuln:sqli", "service:web"],
        label: "SQLi + web tier → database read path",
        mitre: "T1190",
    },
    ToxicPair {
        facts: ["access:foothold", "cloud:exposed"],
        label: "Foothold + cloud misconfig → lateral pivot",
        mitre: "T1021",
    },
];

fn emit_toxic_combinations(
    target: &str,
    facts: &HashSet<Fact>,
    fact_map: &HashMap<Fact, Vec<(i64, f64, bool)>>,
    cfg: &SuperpositionConfig,
) -> Vec<Value> {
    let mut out = Vec::new();
    for pair in TOXIC_PAIRS {
        if !facts.contains(pair.facts[0]) || !facts.contains(pair.facts[1]) {
            continue;
        }
        let probs: Vec<f64> = [pair.facts[0], pair.facts[1]]
            .iter()
            .filter_map(|f| fact_map.get(*f))
            .flat_map(|e| e.iter().map(|(_, b, _)| *b))
            .collect();
        let fused = cfg.fuse(&probs);
        if fused < cfg.collapsed_belief_threshold {
            continue;
        }
        let ev = Evidence::new()
            .with("fact_a", pair.facts[0])
            .with("fact_b", pair.facts[1])
            .with("collapsed_belief", format!("{:.3}", fused))
            .check("toxic_pair_observed", true, pair.label);
        out.push(finding_rich(
            ENGINE_ID,
            &format!("Toxic collapse: {} (belief {:.0}%)", pair.label, fused * 100.0),
            belief_to_severity(fused),
            pair.mitre,
            &format!(
                "Independent weak signals for `{}` and `{}` collapsed into a high-confidence \
                 toxic combination — a breach pattern no single-engine alert describes.",
                pair.facts[0], pair.facts[1]
            ),
            target,
            fused,
            ev,
        ));
    }
    out
}

fn emit_belief_fusion_findings(
    target: &str,
    fact_map: &HashMap<Fact, Vec<(i64, f64, bool)>>,
    clusters: &[ClusterEvidence],
    cfg: &SuperpositionConfig,
) -> Vec<Value> {
    let mut findings = Vec::new();
    for (fact, entries) in fact_map {
        let probs: Vec<f64> = entries.iter().map(|(_, b, _)| *b).collect();
        let fused = cfg.fuse(&probs);
        if fused < cfg.collapsed_belief_threshold {
            continue;
        }
        let contributing: Vec<&ClusterEvidence> = clusters
            .iter()
            .filter(|c| entries.iter().any(|(id, _, _)| *id == c.id))
            .collect();
        let engine_set: HashSet<&str> = contributing
            .iter()
            .flat_map(|c| c.engines.iter().map(String::as_str))
            .collect();
        if engine_set.len() < cfg.min_corroboration_engines
            && contributing.len() < cfg.min_corroboration_engines
        {
            continue;
        }
        let engine_list: Vec<&str> = engine_set.into_iter().collect();
        let cluster_ids: Vec<i64> = contributing.iter().map(|c| c.id).collect();
        let ev = Evidence::new()
            .with("collapsed_belief", format!("{:.3}", fused))
            .with("fusion_mode", format!("{:?}", cfg.fusion_mode))
            .with("planning_fact", fact.clone())
            .with("engines", engine_list.join(", "))
            .with(
                "cluster_ids",
                cluster_ids
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .check("noisy_or_fusion", true, fused);
        findings.push(finding_rich(
            ENGINE_ID,
            &format!(
                "Superposition fusion: {} engines corroborate `{}` (belief {:.0}%)",
                engine_list.len(),
                fact,
                fused * 100.0
            ),
            belief_to_severity(fused),
            MITRE,
            &format!(
                "Fused via {:?}. Fact `{}` reached {:.1}% collapsed confidence from {} engine(s) \
                 across {} cluster(s).",
                cfg.fusion_mode,
                fact,
                fused * 100.0,
                engine_list.len(),
                cluster_ids.len()
            ),
            target,
            fused,
            ev,
        ));
    }
    findings.sort_by(|a, b| {
        let ca = a.get("confidence").and_then(Value::as_f64).unwrap_or(0.0);
        let cb = b.get("confidence").and_then(Value::as_f64).unwrap_or(0.0);
        cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
    });
    findings.truncate(cfg.max_fusion_findings);
    findings
}

fn emit_collapse_finding(
    target: &str,
    goal: &str,
    chain: &AttackChain,
    fused_belief: f64,
    weak_cluster_ids: &[i64],
    clusters: &[ClusterEvidence],
    cfg: &SuperpositionConfig,
) -> Value {
    let weak_titles: Vec<String> = clusters
        .iter()
        .filter(|c| weak_cluster_ids.contains(&c.id))
        .map(|c| format!("{} ({})", c.title, c.max_severity))
        .take(8)
        .collect();

    let ev = Evidence::new()
        .with("goal", goal)
        .with("collapsed_belief", format!("{:.3}", fused_belief))
        .with("fusion_mode", format!("{:?}", cfg.fusion_mode))
        .with(
            "weak_clusters",
            weak_cluster_ids
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
        .with("weak_signals", weak_titles.join(" | "))
        .with("mitre_path", chain.mitre_path.join(" → "))
        .with("planner_steps", chain.steps.len())
        .with("attack_chain", chain.to_json())
        .check("strips_reached_goal", chain.reached_goal, goal);
    finding_rich(
        ENGINE_ID,
        &format!(
            "Collapse → {}: {} weak signals → MITRE chain (belief {:.0}%)",
            goal,
            weak_cluster_ids.len(),
            fused_belief * 100.0
        ),
        belief_to_severity(fused_belief),
        chain
            .mitre_path
            .first()
            .map(String::as_str)
            .unwrap_or(MITRE),
        &format!(
            "STRIPS planner reached `{}` from fused multi-engine state ({:?} fusion). \
             {} weak cluster(s). MITRE: {}. Cost: {}.",
            goal,
            cfg.fusion_mode,
            weak_cluster_ids.len(),
            chain.mitre_path.join(" → "),
            chain.total_cost
        ),
        target,
        fused_belief,
        ev,
    )
}

fn compute_posture_grade(collapse_count: usize, max_belief: f64, penalty_per: u32) -> (u32, &'static str) {
    let penalty = (collapse_count as u32).saturating_mul(penalty_per)
        + ((max_belief * 40.0) as u32).min(40);
    let score = 100u32.saturating_sub(penalty);
    let grade = match score {
        0..=10 => "F",
        11..=25 => "D",
        26..=40 => "C",
        41..=55 => "B",
        56..=70 => "A",
        71..=85 => "A+",
        _ => "S",
    };
    (score, grade)
}

fn findings_to_corr_events(findings: &[Value]) -> Vec<CorrEvent> {
    findings
        .iter()
        .filter_map(|f| {
            let ts = f.get("ts").and_then(Value::as_i64).unwrap_or(0);
            let target = f
                .get("target")
                .and_then(Value::as_str)
                .or_else(|| f.get("target_url").and_then(Value::as_str))
                .unwrap_or("");
            if target.is_empty() {
                return None;
            }
            let sig = f
                .get("type")
                .and_then(Value::as_str)
                .or_else(|| f.get("title").and_then(Value::as_str))
                .unwrap_or("event");
            let sev = f
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("medium");
            Some(CorrEvent::new(
                ts,
                target,
                &finding_category(f),
                sig,
                sev,
            ))
        })
        .collect()
}

fn default_temporal_rules() -> Vec<CorrelationRule> {
    vec![
        CorrelationRule {
            id: "superposition_recon_to_impact".into(),
            name: "Recon → Initial Access → Impact".into(),
            severity: "critical".into(),
            window_secs: 86_400 * 30,
            stages: vec![
                correlation_rules::StageMatch::new("recon", &["recon"]),
                correlation_rules::StageMatch::new("initial_access", &["initial_access", "execution"]),
                correlation_rules::StageMatch::new("impact", &["exfiltration", "privilege_escalation"]),
            ],
        },
        CorrelationRule {
            id: "superposition_web_to_exfil".into(),
            name: "Web execution → Exfiltration".into(),
            severity: "high".into(),
            window_secs: 86_400 * 14,
            stages: vec![
                correlation_rules::StageMatch::new("execution", &["execution"]),
                correlation_rules::StageMatch::new("exfil", &["exfiltration"]),
            ],
        },
    ]
}

pub async fn run_risk_superposition_collapse_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let cfg = SuperpositionConfig::from_params(&ctx.job_params);

    let (Some(pool), Some(tenant_id), Some(client_id)) =
        (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id)
    else {
        return EngineResult::ok(
            vec![finding(
                ENGINE_ID,
                "Risk Superposition Collapse requires DB + tenant context",
                "info",
                MITRE,
                "Run from Command Center with an enrolled client. Fuses live finding clusters — \
                 run offensive engines first to seed evidence.",
                target,
            )],
            "Risk Superposition Collapse: awaiting DB context",
        );
    };

    let clusters = match load_clusters(pool, tenant_id, client_id, cfg.max_clusters).await {
        Ok(c) => c,
        Err(e) => return EngineResult::error(&format!("cluster load failed: {e}")),
    };

    if clusters.is_empty() {
        return empty_ok(ENGINE_ID, target);
    }

    let raw_findings = load_raw_findings(pool, tenant_id, client_id, cfg.max_findings)
        .await
        .unwrap_or_default();

    let fact_map = fact_belief_map(&clusters, &raw_findings, &cfg);
    let initial_facts = build_initial_facts(&fact_map, &cfg, &clusters);

    let mut findings: Vec<Value> = Vec::new();
    let mut collapse_count = 0usize;
    let mut max_belief = 0.0f64;

    if cfg.include_belief_fusion {
        for f in emit_belief_fusion_findings(target, &fact_map, &clusters, &cfg) {
            if let Some(b) = f.get("confidence").and_then(Value::as_f64) {
                max_belief = max_belief.max(b);
            }
            findings.push(f);
        }
    }

    if cfg.include_toxic_combinations {
        for f in emit_toxic_combinations(target, &initial_facts, &fact_map, &cfg) {
            if let Some(b) = f.get("confidence").and_then(Value::as_f64) {
                max_belief = max_belief.max(b);
            }
            findings.push(f);
        }
    }

    if cfg.include_strips_collapse {
        let techniques = attack_chain_planner::default_technique_library();
        for goal in &cfg.planner_goals {
            if initial_facts.contains(goal.as_str()) {
                continue;
            }
            if let Some(chain) = attack_chain_planner::plan(
                &initial_facts,
                &techniques,
                goal,
                cfg.max_planner_expansions,
            ) {
                let probs: Vec<f64> = fact_map
                    .values()
                    .flat_map(|entries| entries.iter().map(|(_, b, _)| *b))
                    .collect();
                let fused = cfg.fuse(&probs);
                max_belief = max_belief.max(fused);
                let weak_ids = weak_clusters_in_chain(&clusters, &fact_map, &initial_facts);
                let weak_ok = !cfg.require_weak_for_collapse
                    || weak_ids.len() >= cfg.min_weak_clusters;
                if weak_ok && (fused >= cfg.collapsed_belief_threshold || !weak_ids.is_empty()) {
                    findings.push(emit_collapse_finding(
                        target,
                        goal,
                        &chain,
                        fused,
                        &weak_ids,
                        &clusters,
                        &cfg,
                    ));
                    collapse_count += 1;
                }
            }
        }
    }

    if cfg.include_temporal_correlation {
        let events = findings_to_corr_events(&raw_findings);
        let rules = default_temporal_rules();
        for hit in correlation_rules::evaluate_all(&rules, &events) {
            let belief = 0.72;
            max_belief = max_belief.max(belief);
            let ev = Evidence::new()
                .with("rule_id", &hit.rule_id)
                .with("span_secs", hit.span_secs)
                .with("stages", hit.to_json())
                .check("temporal_correlation", true, &hit.rule_name);
            findings.push(finding_rich(
                ENGINE_ID,
                &format!("Temporal collapse: {} on {}", hit.rule_name, hit.target),
                hit.severity.as_str(),
                "T1078",
                &format!(
                    "Ordered kill-chain stages observed within {}s on {} — multi-stage progression \
                     collapsed from live finding timestamps.",
                    hit.span_secs, hit.target
                ),
                target,
                belief,
                ev,
            ));
        }
    }

    if cfg.include_attack_paths {
        match attack_path::compute_and_store(
            pool,
            tenant_id,
            client_id,
            Some(cfg.attack_path_top_k),
        )
        .await
        {
            Ok(snapshot) if !snapshot.paths.is_empty() => {
                for path in snapshot.paths.iter().take(cfg.max_graph_paths) {
                    let belief = (path.risk / 10.0).clamp(0.0, 1.0);
                    max_belief = max_belief.max(belief);
                    let steps: Vec<String> = path
                        .steps
                        .iter()
                        .map(|s| format!("{} ({})", s.label, s.edge_type))
                        .collect();
                    let ev = Evidence::new()
                        .with("hops", path.hops)
                        .with("path_risk", format!("{:.1}", path.risk))
                        .with("path_cost", format!("{:.3}", path.cost))
                        .with("steps", steps.join(" → "))
                        .check("graph_path_live", true, path.risk);
                    findings.push(finding_rich(
                        ENGINE_ID,
                        &format!(
                            "Graph collapse: internet → crown jewel in {} hops (risk {:.1}/10)",
                            path.hops, path.risk
                        ),
                        belief_to_severity(belief),
                        "T1021",
                        &format!(
                            "Live risk-graph path. Cost {:.3}. KEV hops: {}.",
                            path.cost, path.kev_hops
                        ),
                        target,
                        belief,
                        ev,
                    ));
                }
                if cfg.emit_choke_points && !snapshot.choke_points.is_empty() {
                    let top = &snapshot.choke_points[0];
                    findings.push(finding(
                        ENGINE_ID,
                        &format!(
                            "Choke point: {} ({}% of top paths)",
                            top.label, top.coverage_pct
                        ),
                        "high",
                        MITRE,
                        &format!(
                            "Patching `{}` breaks {} top attack paths simultaneously.",
                            top.graph_key, top.coverage
                        ),
                        target,
                    ));
                }
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(%e, "attack_path unavailable"),
        }
    }

    if cfg.include_financial_ale {
        if let Ok(fin) = financial_risk::compute_and_store(pool, tenant_id, client_id).await {
            if fin.ale_annualised_usd > 0 || fin.sle_worst_usd > 0 {
                let belief = ((fin.ale_annualised_usd as f64).ln_1p() / 20.0).clamp(0.2, 0.95);
                max_belief = max_belief.max(belief);
                let ev = Evidence::new()
                    .with("ale_annualised_usd", fin.ale_annualised_usd)
                    .with("sle_worst_usd", fin.sle_worst_usd)
                    .with("crown_jewel_value_usd", fin.crown_jewel_value_usd)
                    .check("fair_financial_model", true, fin.ale_annualised_usd);
                findings.push(finding_rich(
                    ENGINE_ID,
                    &format!(
                        "Financial collapse: ${} ALE / ${} worst-case SLE",
                        fin.ale_annualised_usd, fin.sle_worst_usd
                    ),
                    if fin.sle_worst_usd > 1_000_000 {
                        "critical"
                    } else if fin.sle_worst_usd > 100_000 {
                        "high"
                    } else {
                        "medium"
                    },
                    "T1565",
                    "FAIR-derived annualised loss expectancy fused with collapsed attack chains — \
                     board-grade dollar risk from live graph + findings.",
                    target,
                    belief,
                    ev,
                ));
            }
        }
    }

    let (score, grade) = compute_posture_grade(
        collapse_count,
        max_belief,
        cfg.posture_penalty_per_chain,
    );
    let posture_conf = (max_belief.max(1.0 - score as f64 / 100.0)).clamp(0.0, 1.0);
    let ev = Evidence::new()
        .with("posture_score", score)
        .with("posture_grade", grade)
        .with("cluster_count", clusters.len())
        .with("collapse_chains", collapse_count)
        .with("fusion_mode", format!("{:?}", cfg.fusion_mode))
        .with("facts_in_superposition", initial_facts.len())
        .check("live_cluster_fusion", true, clusters.len());
    findings.push(finding_rich(
        ENGINE_ID,
        &format!(
            "Superposition posture: {} ({}/100) — {} chains, max belief {:.0}%",
            grade,
            score,
            collapse_count,
            max_belief * 100.0
        ),
        if score <= 40 {
            "critical"
        } else if score <= 55 {
            "high"
        } else if score <= 70 {
            "medium"
        } else {
            "low"
        },
        MITRE,
        &format!(
            "{} clusters, {} planning facts, {:?} fusion. Lower score = more collapses.",
            clusters.len(),
            initial_facts.len(),
            cfg.fusion_mode
        ),
        target,
        posture_conf,
        ev,
    ));

    let msg = format!(
        "Risk Superposition Collapse: {} clusters → {} findings, posture {}/100 ({})",
        clusters.len(),
        findings.len(),
        score,
        grade
    );
    EngineResult::ok(findings, msg)
}

pub async fn run_risk_superposition_collapse(target: &str, ctx: &EngineRunContext) {
    print_result(run_risk_superposition_collapse_result(target, ctx).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noisy_or_fuses_independent_beliefs() {
        let fused = noisy_or_belief(&[0.3, 0.3, 0.3]);
        assert!(fused > 0.3);
        assert!((fused - 0.657).abs() < 0.01);
    }

    #[test]
    fn log_odds_lifts_multiple_weak_signals() {
        let fused = log_odds_fusion(&[0.25, 0.25, 0.25]);
        assert!(fused > 0.25);
    }

    #[test]
    fn hybrid_is_at_least_either_mode() {
        let cfg = SuperpositionConfig {
            fusion_mode: FusionMode::Hybrid,
            ..SuperpositionConfig::from_params(&json!({}))
        };
        let probs = [0.3, 0.35, 0.28];
        let h = cfg.fuse(&probs);
        assert!(h >= noisy_or_belief(&probs));
        assert!(h >= log_odds_fusion(&probs));
    }

    #[test]
    fn temporal_decay_halves_at_halflife() {
        assert!((temporal_decay(168.0, 168.0) - 0.5).abs() < 0.01);
        assert_eq!(temporal_decay(10.0, 0.0), 1.0);
    }

    #[test]
    fn weak_cluster_detected() {
        let weak = ClusterEvidence {
            id: 1,
            target: "https://x".into(),
            title: "leak".into(),
            cwe: "CWE-200".into(),
            vuln_signature: "leak".into(),
            member_count: 2,
            engines: vec!["asm".into(), "osint".into()],
            max_severity: "medium".into(),
            kev_listed: false,
            avg_effective_risk: 2.5,
            avg_confidence: 0.9,
            max_epss: 0.0,
            age_hours: 1.0,
        };
        assert!(is_weak_cluster(&weak, 4.0));
    }

    #[test]
    fn fused_facts_enable_planning() {
        let clusters = vec![ClusterEvidence {
            id: 1,
            target: "https://app".into(),
            title: "SSRF on web API endpoint".into(),
            cwe: "CWE-918".into(),
            vuln_signature: "ssrf".into(),
            member_count: 3,
            engines: vec!["ssrf_advanced".into(), "asm".into(), "osint".into()],
            max_severity: "medium".into(),
            kev_listed: false,
            avg_effective_risk: 3.5,
            avg_confidence: 0.85,
            max_epss: 0.4,
            age_hours: 2.0,
        }];
        let cfg = SuperpositionConfig::from_params(&json!({
            "collapsed_belief_threshold": 0.35,
            "min_corroboration_engines": 2
        }));
        let findings = vec![json!({"type":"ssrf","title":"SSRF","severity":"medium","target":"https://app"})];
        let fact_map = fact_belief_map(&clusters, &findings, &cfg);
        let initial = build_initial_facts(&fact_map, &cfg, &clusters);
        assert!(initial.contains("service:web"));
        assert!(initial.contains("vuln:ssrf"));
    }
}
