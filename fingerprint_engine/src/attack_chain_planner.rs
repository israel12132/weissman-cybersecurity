//! State-grounded autonomous attack-chain planner.
//!
//! World-class autonomous offense is not "ask an LLM to imagine a kill chain" — it is **planning
//! over observed state**. This module models the engagement as a classical planning problem:
//!
//!   * a [`WorldState`] is a set of grounded **facts** (e.g. `service:web`, `vuln:rce`,
//!     `cred:leaked`, `access:foothold`) — every initial fact traces back to a real observation via
//!     [`facts_from_findings`];
//!   * a [`Technique`] has **preconditions** (facts it needs) and **effects** (facts it grants),
//!     each mapped to a MITRE ATT&CK ID and a cost;
//!   * [`plan`] runs a deterministic **uniform-cost (Dijkstra) forward search** from the observed
//!     facts to a goal fact and returns the cheapest realizable [`AttackChain`].
//!
//! The planner can never invent capability: a technique is only applied when *all* of its
//! preconditions are already in the state, and the state is seeded only from evidence. If the goal
//! is unreachable from what was actually observed, [`plan`] returns `None` (no fabricated path).

use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};

/// A grounded fact. Namespaced `domain:detail` strings keep the model open while staying readable
/// (e.g. `service:web`, `vuln:sqli`, `access:privileged`, `impact:objective`).
pub type Fact = String;

/// An attack technique modeled as a STRIPS-style operator.
#[derive(Debug, Clone, Serialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub mitre: String,
    pub preconditions: Vec<Fact>,
    pub effects: Vec<Fact>,
    pub cost: u32,
}

impl Technique {
    pub fn new(
        id: &str,
        name: &str,
        mitre: &str,
        preconditions: &[&str],
        effects: &[&str],
        cost: u32,
    ) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            mitre: mitre.to_string(),
            preconditions: preconditions.iter().map(|s| s.to_string()).collect(),
            effects: effects.iter().map(|s| s.to_string()).collect(),
            cost,
        }
    }

    fn applicable(&self, state: &HashSet<Fact>) -> bool {
        self.preconditions.iter().all(|p| state.contains(p))
    }

    /// Applicable AND grants at least one fact not already present (prevents no-op cycles).
    fn productive(&self, state: &HashSet<Fact>) -> bool {
        self.applicable(state) && self.effects.iter().any(|e| !state.contains(e))
    }
}

/// One realized step in a planned chain.
#[derive(Debug, Clone, Serialize)]
pub struct PlannedStep {
    pub technique_id: String,
    pub name: String,
    pub mitre: String,
    pub cost: u32,
    /// Facts that were newly gained by applying this step.
    pub gained: Vec<Fact>,
}

/// A complete, cost-ordered attack chain from observed state to the goal.
#[derive(Debug, Clone, Serialize)]
pub struct AttackChain {
    pub goal: Fact,
    pub reached_goal: bool,
    pub total_cost: u32,
    pub steps: Vec<PlannedStep>,
    /// MITRE ATT&CK technique IDs in execution order.
    pub mitre_path: Vec<String>,
}

impl AttackChain {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "goal": self.goal,
            "reached_goal": self.reached_goal,
            "total_cost": self.total_cost,
            "mitre_path": self.mitre_path,
            "steps": self.steps.iter().map(|s| serde_json::json!({
                "technique_id": s.technique_id,
                "name": s.name,
                "mitre": s.mitre,
                "cost": s.cost,
                "gained": s.gained,
            })).collect::<Vec<_>>(),
        })
    }
}

fn canonical(state: &HashSet<Fact>) -> String {
    let mut v: Vec<&str> = state.iter().map(String::as_str).collect();
    v.sort_unstable();
    v.join("|")
}

/// Node in the search frontier.
struct Node {
    cost: u32,
    state: HashSet<Fact>,
    steps: Vec<PlannedStep>,
}

/// Deterministic uniform-cost (Dijkstra) forward search from `initial` facts to `goal`.
///
/// `max_expansions` bounds the search so a pathological technique library can't run unbounded.
/// Returns the cheapest chain that reaches `goal`, or `None` if it is unreachable from the observed
/// facts within the bound.
pub fn plan(
    initial: &HashSet<Fact>,
    techniques: &[Technique],
    goal: &str,
    max_expansions: usize,
) -> Option<AttackChain> {
    if initial.contains(goal) {
        return Some(AttackChain {
            goal: goal.to_string(),
            reached_goal: true,
            total_cost: 0,
            steps: Vec::new(),
            mitre_path: Vec::new(),
        });
    }

    // Deterministic technique order for reproducible tie-breaking.
    let mut techs: Vec<&Technique> = techniques.iter().collect();
    techs.sort_by(|a, b| a.id.cmp(&b.id));

    // BinaryHeap is a max-heap; use Reverse(cost) for min-cost-first. `seq` is a stable tie-breaker.
    let mut heap: BinaryHeap<(Reverse<u32>, Reverse<usize>, usize)> = BinaryHeap::new();
    let mut nodes: Vec<Node> = Vec::new();
    let mut best_cost: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    nodes.push(Node {
        cost: 0,
        state: initial.clone(),
        steps: Vec::new(),
    });
    heap.push((Reverse(0), Reverse(0), 0));
    best_cost.insert(canonical(initial), 0);

    let mut expansions = 0usize;

    while let Some((Reverse(cost), _, idx)) = heap.pop() {
        // Skip stale heap entries (a cheaper path to this state was already processed).
        let cur_key = canonical(&nodes[idx].state);
        if best_cost.get(&cur_key).copied().unwrap_or(u32::MAX) < cost {
            continue;
        }
        if nodes[idx].state.contains(goal) {
            let chain = &nodes[idx];
            let mitre_path = chain.steps.iter().map(|s| s.mitre.clone()).collect();
            return Some(AttackChain {
                goal: goal.to_string(),
                reached_goal: true,
                total_cost: chain.cost,
                steps: chain.steps.clone(),
                mitre_path,
            });
        }

        expansions += 1;
        if expansions > max_expansions {
            break;
        }

        for t in &techs {
            if !t.productive(&nodes[idx].state) {
                continue;
            }
            let mut next_state = nodes[idx].state.clone();
            let mut gained = Vec::new();
            for e in &t.effects {
                if next_state.insert(e.clone()) {
                    gained.push(e.clone());
                }
            }
            let next_cost = cost.saturating_add(t.cost);
            let key = canonical(&next_state);
            if best_cost.get(&key).copied().unwrap_or(u32::MAX) <= next_cost {
                continue;
            }
            best_cost.insert(key, next_cost);

            let mut next_steps = nodes[idx].steps.clone();
            next_steps.push(PlannedStep {
                technique_id: t.id.clone(),
                name: t.name.clone(),
                mitre: t.mitre.clone(),
                cost: t.cost,
                gained,
            });
            let new_idx = nodes.len();
            nodes.push(Node {
                cost: next_cost,
                state: next_state,
                steps: next_steps,
            });
            heap.push((Reverse(next_cost), Reverse(new_idx), new_idx));
        }
    }

    None
}

/// A curated, MITRE-mapped library of common chaining operators. These are generic capability
/// transitions (initial access → execution → priv-esc → lateral → impact), not target-specific.
pub fn default_technique_library() -> Vec<Technique> {
    vec![
        Technique::new(
            "exploit_rce_web",
            "Exploit public-facing app (RCE)",
            "T1190",
            &["service:web", "vuln:rce"],
            &["access:foothold", "exec:code"],
            3,
        ),
        Technique::new(
            "exploit_sqli_web",
            "Exploit public-facing app (SQLi)",
            "T1190",
            &["service:web", "vuln:sqli"],
            &["data:db_read", "access:foothold"],
            4,
        ),
        Technique::new(
            "exploit_ssrf_metadata",
            "SSRF to cloud metadata credential theft",
            "T1552.005",
            &["service:web", "vuln:ssrf", "cloud:exposed"],
            &["cred:leaked"],
            4,
        ),
        Technique::new(
            "valid_accounts",
            "Use leaked/valid credentials",
            "T1078",
            &["cred:leaked"],
            &["access:foothold"],
            2,
        ),
        Technique::new(
            "abuse_authz",
            "Authorization bypass / IDOR to sensitive data",
            "T1190",
            &["service:web", "vuln:authz"],
            &["data:db_read"],
            3,
        ),
        Technique::new(
            "privilege_escalation",
            "Local privilege escalation",
            "T1068",
            &["access:foothold"],
            &["access:privileged"],
            5,
        ),
        Technique::new(
            "lateral_movement",
            "Lateral movement to internal segment",
            "T1021",
            &["access:privileged"],
            &["access:internal"],
            4,
        ),
        Technique::new(
            "reach_crown_jewel",
            "Reach crown-jewel asset",
            "T1021",
            &["access:internal"],
            &["access:crown_jewel"],
            3,
        ),
        Technique::new(
            "exfiltrate_db",
            "Exfiltrate database contents",
            "T1567",
            &["data:db_read"],
            &["impact:objective"],
            3,
        ),
        Technique::new(
            "exfiltrate_crown_jewel",
            "Exfiltrate crown-jewel data",
            "T1567",
            &["access:crown_jewel"],
            &["impact:objective"],
            2,
        ),
    ]
}

/// Bridge real findings to grounded planning facts. Only evidence-backed facts are produced; the
/// planner downstream cannot invent capability beyond what is observed here.
pub fn facts_from_findings(findings: &[serde_json::Value]) -> HashSet<Fact> {
    let mut facts: HashSet<Fact> = HashSet::new();
    for f in findings {
        let kind = field(f, "type");
        let title = field(f, "title");
        let mitre = field(f, "mitre_attack");
        let category = field(f, "category");
        let hay = format!(
            "{} {} {} {}",
            kind.to_ascii_lowercase(),
            title.to_ascii_lowercase(),
            mitre.to_ascii_lowercase(),
            category.to_ascii_lowercase()
        );
        let severity = field(f, "severity").to_ascii_lowercase();
        let verified = f.get("verified").and_then(serde_json::Value::as_bool) == Some(true)
            || f.get("sandbox_verified")
                .and_then(serde_json::Value::as_bool)
                == Some(true);

        if hay.contains("http")
            || hay.contains("web")
            || hay.contains("graphql")
            || hay.contains("tls")
            || hay.contains("api")
            // T1190 (Exploit Public-Facing Application) inherently implies an exposed service.
            || mitre.to_ascii_uppercase().starts_with("T1190")
        {
            facts.insert("service:web".to_string());
        }
        if hay.contains("sqli") || hay.contains("sql injection") || hay.contains("sql_injection") {
            facts.insert("vuln:sqli".to_string());
        }
        if hay.contains("rce")
            || hay.contains("remote code")
            || hay.contains("command injection")
            || hay.contains("deserial")
        {
            facts.insert("vuln:rce".to_string());
        }
        if hay.contains("ssrf") {
            facts.insert("vuln:ssrf".to_string());
        }
        if hay.contains("idor") || hay.contains("bola") || hay.contains("authoriz") {
            facts.insert("vuln:authz".to_string());
        }
        if hay.contains("secret")
            || hay.contains("credential")
            || hay.contains("leak")
            || hay.contains("api key")
        {
            facts.insert("cred:leaked".to_string());
        }
        if hay.contains("cloud")
            || hay.contains("s3")
            || hay.contains("metadata")
            || hay.contains("iam")
        {
            facts.insert("cloud:exposed".to_string());
        }
        // A verified high/critical exploit is direct evidence of a foothold.
        if verified && (severity == "critical" || severity == "high") {
            facts.insert("access:foothold".to_string());
        }
    }
    facts
}

fn field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Convenience: plan from real findings toward a goal using the default technique library.
pub fn plan_from_findings(findings: &[serde_json::Value], goal: &str) -> Option<AttackChain> {
    // Group findings by asset (normalized host) and plan PER ASSET. Merging every finding into
    // one global fact set would collapse, e.g., SSRF on host A + RCE on host B + a leaked cred on
    // host C into a single fabricated cross-host kill chain that exists on no real system and
    // crosses hosts with no proven connectivity. Return the strongest grounded per-asset chain.
    let mut by_asset: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    for f in findings {
        by_asset
            .entry(finding_asset_key(f))
            .or_default()
            .push(f.clone());
    }
    let lib = default_technique_library();
    by_asset
        .values()
        .filter_map(|group| plan(&facts_from_findings(group), &lib, goal, 50_000))
        .max_by_key(|chain| (chain.reached_goal, chain.steps.len()))
}

/// Normalized host a finding pertains to, so attack-chain planning stays within one asset.
/// Empty string groups findings with no locatable host together (a conservative shared bucket).
fn finding_asset_key(f: &serde_json::Value) -> String {
    for key in ["target", "url", "host", "asset", "evidence_url"] {
        let v = field(f, key);
        let t = v.trim();
        if !t.is_empty() {
            return crate::engine_probes::extract_host(t);
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> HashSet<Fact> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn finds_full_chain_from_rce_to_impact() {
        let initial = set(&["service:web", "vuln:rce"]);
        let chain = plan(
            &initial,
            &default_technique_library(),
            "impact:objective",
            50_000,
        )
        .expect("a chain should exist from web+rce to impact");
        assert!(chain.reached_goal);
        assert!(!chain.steps.is_empty());
        // Must begin by exploiting the public-facing app.
        assert_eq!(chain.steps[0].mitre, "T1190");
        // The end state achieves the objective.
        assert_eq!(
            chain
                .steps
                .last()
                .unwrap()
                .gained
                .iter()
                .any(|g| g == "impact:objective"),
            true
        );
        assert!(chain.total_cost > 0);
    }

    #[test]
    fn unreachable_goal_returns_none() {
        // Only a web service observed, no exploitable vuln and no creds → no foothold possible.
        let initial = set(&["service:web"]);
        let chain = plan(
            &initial,
            &default_technique_library(),
            "impact:objective",
            50_000,
        );
        assert!(
            chain.is_none(),
            "must not fabricate a path without evidence"
        );
    }

    #[test]
    fn prefers_cheaper_path() {
        // Both a leaked credential (cheap foothold, cost 2) and an SQLi path exist; planner should
        // reach foothold via valid_accounts (cost 2) rather than a more expensive route.
        let initial = set(&["service:web", "vuln:sqli", "cred:leaked"]);
        let chain = plan(
            &initial,
            &default_technique_library(),
            "access:foothold",
            50_000,
        )
        .expect("foothold reachable");
        assert_eq!(chain.total_cost, 2);
        assert_eq!(chain.steps.len(), 1);
        assert_eq!(chain.steps[0].technique_id, "valid_accounts");
    }

    #[test]
    fn goal_already_satisfied_is_zero_cost() {
        let initial = set(&["access:foothold"]);
        let chain = plan(
            &initial,
            &default_technique_library(),
            "access:foothold",
            50_000,
        )
        .expect("trivially reached");
        assert!(chain.reached_goal);
        assert_eq!(chain.total_cost, 0);
        assert!(chain.steps.is_empty());
    }

    #[test]
    fn facts_grounding_from_verified_rce_finding() {
        let findings = vec![serde_json::json!({
            "type": "poe_synthesis",
            "title": "Weaponized vulnerability — TRUE PoE verified",
            "severity": "critical",
            "verified": true,
            "mitre_attack": "T1190",
        })];
        let facts = facts_from_findings(&findings);
        assert!(facts.contains("service:web"));
        assert!(facts.contains("access:foothold"));
    }

    #[test]
    fn unverified_low_finding_grants_no_foothold() {
        let findings = vec![serde_json::json!({
            "type": "graphql_deep_attack",
            "title": "GraphQL introspection enabled",
            "severity": "high",
            "verified": false,
        })];
        let facts = facts_from_findings(&findings);
        assert!(facts.contains("service:web"));
        assert!(!facts.contains("access:foothold"));
    }

    #[test]
    fn end_to_end_plan_from_findings() {
        let findings = vec![
            serde_json::json!({"type":"http_feedback_fuzz","title":"RCE via command injection","severity":"critical","verified":true}),
        ];
        let chain = plan_from_findings(&findings, "impact:objective")
            .expect("verified RCE should yield an objective chain");
        assert!(chain.reached_goal);
        assert!(
            chain.mitre_path.contains(&"T1068".to_string())
                || chain.mitre_path.contains(&"T1567".to_string())
        );
    }
}
