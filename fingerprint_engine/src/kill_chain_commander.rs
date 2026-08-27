//! Live Kill-Chain Commander.
//!
//! Composes an attack path (recon → foothold → identity → privilege → impact)
//! exclusively from persisted findings, assets, jobs, and privilege-escalation
//! events for one bound customer. Empty corpus is a visible failure — never a
//! fabricated APT narrative.
//!
//! Business-risk pricing is a published formula, not a magic number:
//! `severity_weight × asset_criticality × exposure`.

use crate::attack_coverage;
use crate::attack_exposure;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const STAGES: [&str; 5] = ["recon", "foothold", "identity", "privilege", "impact"];

pub const EMPTY_NO_CLIENT: &str = "Kill-chain composition requires a bound customer. Assigned-client sessions are auto-scoped; staff must select a client. Weissman will not mix tenants into one attack path.";
pub const EMPTY_NO_FINDINGS: &str = "No live findings for this customer. Run engines against the assigned domain, then return — Weissman will not fabricate a kill chain.";
pub const EMPTY_ALL_CLOSED: &str = "All persisted findings are closed or false-positive — no live attack path remains. Weissman will not invent stages.";

const SEV_CRITICAL: f64 = 5.0;
const SEV_HIGH: f64 = 4.0;
const SEV_MEDIUM: f64 = 3.0;
const SEV_LOW: f64 = 2.0;
const SEV_INFO: f64 = 1.0;
const CRIT_CROWN: f64 = 2.5;
const EXP_INTERNET: f64 = 2.0;
const EXP_INTERNAL: f64 = 1.0;
const USD_DIVISOR: f64 = 10.0;
const TOP_FIXES: usize = 3;
const PROOF_SNIPPET_CHARS: usize = 280;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComposeRequest {
    pub client_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MitreCite {
    pub id: String,
    pub name: Option<String>,
    pub tactic: Option<String>,
    /// `finding_raw_data` or `engine_catalog` — never invented.
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormulaInputs {
    pub severity: String,
    pub severity_weight: f64,
    pub asset_criticality: f64,
    pub exposure: String,
    pub exposure_weight: f64,
    pub asset_label: Option<String>,
    pub internet_facing: bool,
    pub crown_jewel: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CitedFinding {
    pub id: i64,
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub status: String,
    pub proof_snippet: Option<String>,
    pub mitre: Vec<MitreCite>,
    pub confidence: f64,
    pub classification_basis: String,
    pub risk_points: f64,
    pub priced_usd: Option<i64>,
    pub formula_inputs: FormulaInputs,
}

#[derive(Debug, Clone, Serialize)]
pub struct StageNode {
    pub stage: String,
    pub label: String,
    pub mitre_tactics: Vec<String>,
    pub finding_count: usize,
    pub max_confidence: f64,
    pub stage_risk_points: f64,
    pub findings: Vec<CitedFinding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StageEdge {
    pub from: String,
    pub to: String,
    pub reason: String,
    pub shared_assets: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopFix {
    pub id: i64,
    pub finding_id: String,
    pub title: String,
    pub stage: String,
    pub risk_points: f64,
    pub priced_usd: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormulaSpec {
    pub name: String,
    pub expression: String,
    pub severity_weights: BTreeMap<String, f64>,
    pub criticality: BTreeMap<String, String>,
    pub exposure: BTreeMap<String, f64>,
    pub usd_overlay: String,
    pub residual: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Pricing {
    pub formula: FormulaSpec,
    pub total_risk_points: f64,
    pub residual_if_top3_fixed: f64,
    pub residual_reduction_pct: f64,
    pub top3_fixes: Vec<TopFix>,
    pub total_priced_usd: Option<i64>,
    pub residual_priced_usd: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Honesty {
    pub live_evidence_only: bool,
    pub no_fabricated_apt: bool,
    pub fail_closed_empty: bool,
    pub client_bound: bool,
    pub formula_published: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobCite {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub engine: Option<String>,
    pub target: Option<String>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KillChainSnapshot {
    pub ok: bool,
    pub live: bool,
    pub client_id: Option<i64>,
    pub client_name: Option<String>,
    pub primary_domain: Option<String>,
    pub stages: Vec<StageNode>,
    pub edges: Vec<StageEdge>,
    pub pricing: Pricing,
    pub jobs: Vec<JobCite>,
    pub assets_considered: usize,
    pub findings_considered: usize,
    pub empty_reason: Option<String>,
    pub honesty: Honesty,
}

#[derive(Debug, Clone)]
pub struct LiveFinding {
    pub id: i64,
    pub finding_id: String,
    pub client_id: i64,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub description: String,
    pub status: String,
    pub proof: Option<String>,
    pub poc_exploit: Option<String>,
    pub raw_data: Value,
    pub kev_listed: bool,
    pub epss_score: Option<f32>,
    pub risk_node_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct LiveAsset {
    pub id: i64,
    pub client_id: i64,
    pub label: String,
    pub graph_key: String,
    pub node_type: String,
    pub internet_exposed: bool,
    pub crown_jewel: bool,
    pub asset_value: f32,
    pub business_value_usd: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct LiveJob {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub engine: Option<String>,
    pub target: Option<String>,
    pub client_id: Option<i64>,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PrivEscEvent {
    pub id: i64,
    pub client_id: i64,
    pub from_context: String,
    pub to_context: String,
    pub method: String,
    pub url: String,
    pub severity: String,
}

#[must_use]
pub fn formula_spec() -> FormulaSpec {
    let mut severity_weights = BTreeMap::new();
    severity_weights.insert("critical".into(), SEV_CRITICAL);
    severity_weights.insert("high".into(), SEV_HIGH);
    severity_weights.insert("medium".into(), SEV_MEDIUM);
    severity_weights.insert("low".into(), SEV_LOW);
    severity_weights.insert("info".into(), SEV_INFO);

    let mut criticality = BTreeMap::new();
    criticality.insert("crown_jewel".into(), format!("{CRIT_CROWN}"));
    criticality.insert(
        "other".into(),
        "max(1.0, asset_value) from risk_graph_nodes".into(),
    );

    let mut exposure = BTreeMap::new();
    exposure.insert("internet_facing".into(), EXP_INTERNET);
    exposure.insert("internal".into(), EXP_INTERNAL);

    FormulaSpec {
        name: "Weissman live business-risk points".into(),
        expression: "severity_weight × asset_criticality × exposure".into(),
        severity_weights,
        criticality,
        exposure,
        usd_overlay: format!(
            "priced_usd = round(risk_points × (business_value_usd OR client.default_asset_value_usd) / {USD_DIVISOR}) — omitted when no dollar valuation exists"
        ),
        residual: format!(
            "Recompute total after removing the top {TOP_FIXES} findings by risk_points (the highest-leverage live fixes)."
        ),
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn norm_sev(raw: &str) -> &'static str {
    let s = raw.trim().to_ascii_lowercase();
    if s.contains("crit") {
        "critical"
    } else if s.contains("high") {
        "high"
    } else if s.contains("med") {
        "medium"
    } else if s.contains("low") {
        "low"
    } else {
        "info"
    }
}

fn severity_weight(sev: &str) -> f64 {
    match sev {
        "critical" => SEV_CRITICAL,
        "high" => SEV_HIGH,
        "medium" => SEV_MEDIUM,
        "low" => SEV_LOW,
        _ => SEV_INFO,
    }
}

fn is_active_status(status: &str) -> bool {
    match status.trim().to_ascii_uppercase().as_str() {
        "FIXED" | "FALSE_POSITIVE" | "CLOSED" | "REMEDIATED" => false,
        _ => true,
    }
}

fn snippet(raw: Option<&str>) -> Option<String> {
    let s = raw.map(str::trim).filter(|x| !x.is_empty())?;
    if s.chars().count() <= PROOF_SNIPPET_CHARS {
        Some(s.to_string())
    } else {
        let cut: String = s.chars().take(PROOF_SNIPPET_CHARS).collect();
        Some(format!("{cut}…"))
    }
}

fn is_private_host(host: &str) -> bool {
    let h = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    let h = h.split('%').next().unwrap_or(&h);
    if h == "localhost" || h == "127.0.0.1" || h == "::1" || h.ends_with(".local") {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v) => {
                v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified()
            }
            std::net::IpAddr::V6(v) => v.is_loopback() || v.is_unspecified(),
        };
    }
    false
}

fn finding_host(f: &LiveFinding) -> Option<String> {
    let keys = ["target", "host", "url", "hostname", "asset", "endpoint"];
    if let Some(obj) = f.raw_data.as_object() {
        for k in keys {
            if let Some(s) = obj.get(k).and_then(Value::as_str) {
                if let Some(h) = host_from_url_or_host(s) {
                    return Some(h);
                }
            }
        }
    }
    host_from_url_or_host(&f.title)
}

fn host_from_url_or_host(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if let Ok(u) = url::Url::parse(t) {
        return u.host_str().map(|h| h.to_ascii_lowercase());
    }
    if let Ok(u) = url::Url::parse(&format!("https://{t}")) {
        return u.host_str().map(|h| h.to_ascii_lowercase());
    }
    let token = t.split('/').next().unwrap_or(t);
    let token = token.split(':').next().unwrap_or(token).trim();
    if token.contains('.') || token.parse::<std::net::IpAddr>().is_ok() {
        Some(token.to_ascii_lowercase())
    } else {
        None
    }
}

fn parse_primary_domain(domains_raw: &str) -> Option<String> {
    let trimmed = domains_raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        match v {
            Value::Array(arr) => {
                for item in arr {
                    match item {
                        Value::String(s) if !s.trim().is_empty() => {
                            return Some(s.trim().trim_start_matches("*.").to_ascii_lowercase());
                        }
                        Value::Object(o) => {
                            for k in ["primary", "domain", "name", "host"] {
                                if let Some(s) = o.get(k).and_then(Value::as_str) {
                                    if !s.trim().is_empty() {
                                        return Some(
                                            s.trim().trim_start_matches("*.").to_ascii_lowercase(),
                                        );
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Value::String(s) if !s.trim().is_empty() => {
                return Some(s.trim().trim_start_matches("*.").to_ascii_lowercase());
            }
            Value::Object(o) => {
                for k in ["primary", "domain", "name", "host"] {
                    if let Some(s) = o.get(k).and_then(Value::as_str) {
                        if !s.trim().is_empty() {
                            return Some(
                                s.trim().trim_start_matches("*.").to_ascii_lowercase(),
                            );
                        }
                    }
                }
                if let Some(arr) = o.get("domains").and_then(Value::as_array) {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            if !s.trim().is_empty() {
                                return Some(
                                    s.trim().trim_start_matches("*.").to_ascii_lowercase(),
                                );
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let first = trimmed
        .trim_start_matches(['[', '"', ' '])
        .split([',', ' ', ';'])
        .next()
        .unwrap_or("")
        .trim_matches(['"', ']', ' ']);
    if first.is_empty() {
        None
    } else {
        Some(first.trim_start_matches("*.").to_ascii_lowercase())
    }
}

fn match_asset<'a>(
    f: &LiveFinding,
    assets: &'a [LiveAsset],
    primary_domain: Option<&str>,
) -> Option<&'a LiveAsset> {
    if let Some(nid) = f.risk_node_id {
        if let Some(a) = assets.iter().find(|a| a.id == nid) {
            return Some(a);
        }
    }
    let host = finding_host(f);
    if let Some(ref h) = host {
        if let Some(a) = assets.iter().find(|a| {
            let lab = a.label.to_ascii_lowercase();
            let key = a.graph_key.to_ascii_lowercase();
            lab.contains(h) || key.contains(h) || (h.contains(&lab) && lab.len() > 3)
        }) {
            return Some(a);
        }
    }
    if let (Some(h), Some(dom)) = (host.as_deref(), primary_domain) {
        if h == dom || h.ends_with(&format!(".{dom}")) {
            return assets.iter().find(|a| a.internet_exposed);
        }
    }
    None
}

fn exposure_for(
    f: &LiveFinding,
    asset: Option<&LiveAsset>,
    primary_domain: Option<&str>,
) -> (String, f64, bool) {
    if let Some(a) = asset {
        if a.internet_exposed {
            return ("internet_facing".into(), EXP_INTERNET, true);
        }
        return ("internal".into(), EXP_INTERNAL, false);
    }
    if let Some(h) = finding_host(f) {
        if is_private_host(&h) {
            return ("internal".into(), EXP_INTERNAL, false);
        }
        if let Some(dom) = primary_domain {
            if h == dom || h.ends_with(&format!(".{dom}")) {
                return ("internet_facing".into(), EXP_INTERNET, true);
            }
        }
        // Public-looking hostname without an asset flag: do not inflate. Internal default.
        return ("internal".into(), EXP_INTERNAL, false);
    }
    ("internal".into(), EXP_INTERNAL, false)
}

fn criticality_for(asset: Option<&LiveAsset>) -> (f64, bool) {
    match asset {
        Some(a) if a.crown_jewel => (CRIT_CROWN, true),
        Some(a) => (f64::from(a.asset_value).max(1.0), false),
        None => (1.0, false),
    }
}

fn confidence_of(f: &LiveFinding, proof: Option<&str>) -> f64 {
    let mut c = 0.50_f64;
    if proof.is_some() {
        c += 0.30;
    }
    if f.poc_exploit
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .is_some()
    {
        c += 0.08;
    }
    if f.kev_listed {
        c += 0.07;
    }
    if f.epss_score.unwrap_or(0.0) >= 0.5 {
        c += 0.05;
    }
    round2(c.clamp(0.35, 0.99))
}

fn mitre_for(f: &LiveFinding) -> Vec<MitreCite> {
    let mut out: Vec<MitreCite> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for id in attack_exposure::techniques_of(&f.raw_data) {
        if !seen.insert(id.clone()) {
            continue;
        }
        let meta = attack_coverage::lookup(&id);
        out.push(MitreCite {
            id,
            name: meta.map(|t| t.name.to_string()),
            tactic: meta.map(|t| t.tactic.to_string()),
            source: "finding_raw_data".into(),
        });
    }
    let eng = f
        .source
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    if !eng.is_empty() {
        for t in attack_coverage::catalog() {
            if t.engines.iter().any(|e| *e == eng) && seen.insert(t.id.to_string()) {
                out.push(MitreCite {
                    id: t.id.to_string(),
                    name: Some(t.name.to_string()),
                    tactic: Some(t.tactic.to_string()),
                    source: "engine_catalog".into(),
                });
            }
            if out.len() >= 6 {
                break;
            }
        }
    }
    out
}

fn tactic_to_stage(tactic: &str) -> Option<&'static str> {
    let t = tactic.to_ascii_lowercase();
    if t.contains("recon") || t.contains("discovery") {
        Some("recon")
    } else if t.contains("credential") {
        Some("identity")
    } else if t.contains("privilege") || t.contains("lateral") || t.contains("persistence") {
        Some("privilege")
    } else if t.contains("exfil")
        || t.contains("impact")
        || t.contains("collection")
        || t.contains("command and control")
        || t == "c2"
    {
        Some("impact")
    } else if t.contains("initial access")
        || t.contains("execution")
        || t.contains("resource development")
    {
        Some("foothold")
    } else {
        None
    }
}

fn classify_stage(f: &LiveFinding, mitre: &[MitreCite]) -> (&'static str, &'static str) {
    for m in mitre {
        if m.source == "finding_raw_data" {
            if let Some(tac) = m.tactic.as_deref().and_then(tactic_to_stage) {
                return (tac, "mitre_tactic");
            }
        }
    }
    let src = f.source.to_ascii_lowercase().replace(['-', ' '], "_");
    let blob = format!(
        "{} {} {}",
        src,
        f.title.to_ascii_lowercase(),
        f.description.to_ascii_lowercase()
    );

    const IDENTITY: &[&str] = &[
        "kerberos",
        "password_spray",
        "saml",
        "oauth",
        "jwt",
        "credential",
        "passwd",
        "ntlm",
        "mimikatz",
        "pass_the_hash",
        "pass-the-hash",
        "asreproast",
        "kerberoast",
        "idp",
        "sso",
        "token",
        "session_hijack",
    ];
    const PRIV: &[&str] = &[
        "privilege",
        "privesc",
        "priv_esc",
        "sudo",
        "iam",
        "rbac",
        "kernel_exploit",
        "lateral",
        "persistence",
        "rootkit",
        "admin",
        "escalat",
    ];
    const IMPACT: &[&str] = &[
        "ransom",
        "exfil",
        "destruct",
        "wiper",
        "ddos",
        "denial",
        "data_exfil",
        "impact",
        "crypto_miner",
        "wipe",
        "availability",
    ];
    const RECON: &[&str] = &[
        "osint",
        "asm",
        "recon",
        "subdomain",
        "dns",
        "leak_hunter",
        "discovery",
        "shodan",
        "typosquat",
        "whois",
        "enum",
        "fingerprint",
        "email_dns",
        "darkweb",
        "dark_web",
    ];
    const FOOTHOLD: &[&str] = &[
        "xss",
        "sqli",
        "rce",
        "ssrf",
        "lfi",
        "rfi",
        "xxe",
        "ssti",
        "upload",
        "cve",
        "exploit",
        "log4shell",
        "deserialization",
        "smuggl",
        "idor",
        "bola",
        "graphql",
        "auth_bypass",
        "unauth",
        "rce_engine",
        "file_upload",
    ];

    for k in IDENTITY {
        if blob.contains(k) {
            return ("identity", "keyword");
        }
    }
    for k in PRIV {
        if blob.contains(k) {
            return ("privilege", "keyword");
        }
    }
    for k in IMPACT {
        if blob.contains(k) {
            return ("impact", "keyword");
        }
    }
    for k in RECON {
        if blob.contains(k) {
            return ("recon", "keyword");
        }
    }
    for k in FOOTHOLD {
        if blob.contains(k) {
            return ("foothold", "keyword");
        }
    }
    for m in mitre {
        if let Some(tac) = m.tactic.as_deref().and_then(tactic_to_stage) {
            return (tac, "engine_catalog");
        }
    }
    ("foothold", "default_initial_access")
}

fn stage_label(stage: &str) -> &'static str {
    match stage {
        "recon" => "Reconnaissance",
        "foothold" => "Foothold",
        "identity" => "Identity",
        "privilege" => "Privilege",
        "impact" => "Impact",
        _ => "Unknown",
    }
}

fn stage_tactics(stage: &str) -> Vec<String> {
    match stage {
        "recon" => vec!["Reconnaissance".into(), "Discovery".into()],
        "foothold" => vec!["Initial Access".into(), "Execution".into()],
        "identity" => vec!["Credential Access".into()],
        "privilege" => vec!["Privilege Escalation".into(), "Lateral Movement".into()],
        "impact" => vec!["Exfiltration".into(), "Impact".into()],
        _ => vec![],
    }
}

fn empty_snapshot(
    client_id: Option<i64>,
    client_name: Option<String>,
    primary_domain: Option<String>,
    reason: String,
    jobs: Vec<JobCite>,
    assets_considered: usize,
    findings_considered: usize,
) -> KillChainSnapshot {
    KillChainSnapshot {
        ok: true,
        live: true,
        client_id,
        client_name,
        primary_domain,
        stages: STAGES
            .iter()
            .map(|s| StageNode {
                stage: (*s).into(),
                label: stage_label(s).into(),
                mitre_tactics: stage_tactics(s),
                finding_count: 0,
                max_confidence: 0.0,
                stage_risk_points: 0.0,
                findings: vec![],
            })
            .collect(),
        edges: vec![],
        pricing: Pricing {
            formula: formula_spec(),
            total_risk_points: 0.0,
            residual_if_top3_fixed: 0.0,
            residual_reduction_pct: 0.0,
            top3_fixes: vec![],
            total_priced_usd: None,
            residual_priced_usd: None,
        },
        jobs,
        assets_considered,
        findings_considered,
        empty_reason: Some(reason),
        honesty: Honesty {
            live_evidence_only: true,
            no_fabricated_apt: true,
            fail_closed_empty: true,
            client_bound: client_id.is_some(),
            formula_published: true,
        },
    }
}

/// Pure composer — filters to `client_id` (defense in depth vs. SQL). Unit-tested.
pub fn compose_chain(
    client_id: Option<i64>,
    client_name: Option<String>,
    primary_domain: Option<String>,
    default_asset_value_usd: i64,
    findings: Vec<LiveFinding>,
    assets: Vec<LiveAsset>,
    jobs: Vec<LiveJob>,
    priv_esc: Vec<PrivEscEvent>,
) -> KillChainSnapshot {
    let jobs_out: Vec<JobCite> = jobs
        .iter()
        .filter(|j| client_id.is_none() || j.client_id == client_id)
        .take(25)
        .map(|j| JobCite {
            id: j.id.clone(),
            kind: j.kind.clone(),
            status: j.status.clone(),
            engine: j.engine.clone(),
            target: j.target.clone(),
            created_at: j.created_at.clone(),
        })
        .collect();

    let Some(cid) = client_id else {
        return empty_snapshot(
            None,
            client_name,
            primary_domain,
            EMPTY_NO_CLIENT.into(),
            jobs_out,
            assets.len(),
            findings.len(),
        );
    };

    let assets: Vec<LiveAsset> = assets.into_iter().filter(|a| a.client_id == cid).collect();
    let findings: Vec<LiveFinding> = findings
        .into_iter()
        .filter(|f| f.client_id == cid)
        .collect();
    let priv_esc: Vec<PrivEscEvent> = priv_esc
        .into_iter()
        .filter(|e| e.client_id == cid)
        .collect();
    let findings_considered = findings.len();
    let assets_considered = assets.len();

    if findings.is_empty() && priv_esc.is_empty() {
        return empty_snapshot(
            Some(cid),
            client_name,
            primary_domain,
            EMPTY_NO_FINDINGS.into(),
            jobs_out,
            assets_considered,
            findings_considered,
        );
    }

    let active: Vec<LiveFinding> = findings
        .into_iter()
        .filter(|f| is_active_status(&f.status))
        .collect();
    if active.is_empty() && priv_esc.is_empty() {
        return empty_snapshot(
            Some(cid),
            client_name,
            primary_domain,
            EMPTY_ALL_CLOSED.into(),
            jobs_out,
            assets_considered,
            findings_considered,
        );
    }

    let domain = primary_domain.as_deref();
    let mut by_stage: HashMap<&'static str, Vec<CitedFinding>> = HashMap::new();
    for s in STAGES {
        by_stage.insert(s, Vec::new());
    }

    for f in &active {
        let mitre = mitre_for(f);
        let (stage, basis) = classify_stage(f, &mitre);
        let asset = match_asset(f, &assets, domain);
        let (exp_label, exp_w, internet) = exposure_for(f, asset, domain);
        let (crit, crown) = criticality_for(asset);
        let sev = norm_sev(&f.severity);
        let sw = severity_weight(sev);
        let risk = round2(sw * crit * exp_w);
        let usd_base =
            asset
                .and_then(|a| a.business_value_usd)
                .or(if default_asset_value_usd > 0 {
                    Some(default_asset_value_usd)
                } else {
                    None
                });
        let priced = usd_base.map(|v| ((risk * (v as f64) / USD_DIVISOR).round()) as i64);
        let proof = snippet(f.proof.as_deref()).or_else(|| snippet(f.poc_exploit.as_deref()));
        let cited = CitedFinding {
            id: f.id,
            finding_id: f.finding_id.clone(),
            title: f.title.clone(),
            severity: sev.into(),
            source: f.source.clone(),
            status: f.status.clone(),
            proof_snippet: proof.clone(),
            mitre,
            confidence: confidence_of(f, proof.as_deref()),
            classification_basis: basis.into(),
            risk_points: risk,
            priced_usd: priced,
            formula_inputs: FormulaInputs {
                severity: sev.into(),
                severity_weight: sw,
                asset_criticality: round2(crit),
                exposure: exp_label,
                exposure_weight: exp_w,
                asset_label: asset.map(|a| a.label.clone()),
                internet_facing: internet,
                crown_jewel: crown,
            },
        };
        by_stage.entry(stage).or_default().push(cited);
    }

    for ev in &priv_esc {
        let proof = snippet(Some(&format!(
            "{} {} → {} ({})",
            ev.method, ev.from_context, ev.to_context, ev.url
        )));
        let sev = norm_sev(&ev.severity);
        let sw = severity_weight(sev);
        let risk = round2(sw * 1.0 * EXP_INTERNAL);
        by_stage.entry("privilege").or_default().push(CitedFinding {
            id: ev.id,
            finding_id: format!("priv-esc:{}", ev.id),
            title: format!(
                "Privilege escalation {} → {}",
                ev.from_context, ev.to_context
            ),
            severity: sev.into(),
            source: "privilege_escalation_events".into(),
            status: "OPEN".into(),
            proof_snippet: proof,
            mitre: vec![MitreCite {
                id: "T1068".into(),
                name: attack_coverage::lookup("T1068").map(|t| t.name.to_string()),
                tactic: attack_coverage::lookup("T1068").map(|t| t.tactic.to_string()),
                source: "engine_catalog".into(),
            }],
            confidence: 0.88,
            classification_basis: "priv_esc_event".into(),
            risk_points: risk,
            priced_usd: if default_asset_value_usd > 0 {
                Some(((risk * (default_asset_value_usd as f64) / USD_DIVISOR).round()) as i64)
            } else {
                None
            },
            formula_inputs: FormulaInputs {
                severity: sev.into(),
                severity_weight: sw,
                asset_criticality: 1.0,
                exposure: "internal".into(),
                exposure_weight: EXP_INTERNAL,
                asset_label: None,
                internet_facing: false,
                crown_jewel: false,
            },
        });
    }

    for list in by_stage.values_mut() {
        list.sort_by(|a, b| {
            b.risk_points
                .partial_cmp(&a.risk_points)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    let stages: Vec<StageNode> = STAGES
        .iter()
        .map(|s| {
            let findings = by_stage.get(s).cloned().unwrap_or_default();
            let max_c = findings
                .iter()
                .map(|f| f.confidence)
                .fold(0.0_f64, f64::max);
            let pts = round2(findings.iter().map(|f| f.risk_points).sum::<f64>());
            StageNode {
                stage: (*s).into(),
                label: stage_label(s).into(),
                mitre_tactics: stage_tactics(s),
                finding_count: findings.len(),
                max_confidence: round2(max_c),
                stage_risk_points: pts,
                findings,
            }
        })
        .collect();

    let mut edges: Vec<StageEdge> = Vec::new();
    for pair in STAGES.windows(2) {
        let from = pair[0];
        let to = pair[1];
        let a = by_stage.get(from).map(|v| v.as_slice()).unwrap_or(&[]);
        let b = by_stage.get(to).map(|v| v.as_slice()).unwrap_or(&[]);
        if a.is_empty() || b.is_empty() {
            continue;
        }
        let mut shared: BTreeSet<String> = BTreeSet::new();
        for fa in a {
            if let Some(la) = fa.formula_inputs.asset_label.as_deref() {
                for fb in b {
                    if fb.formula_inputs.asset_label.as_deref() == Some(la) {
                        shared.insert(la.to_string());
                    }
                }
            }
        }
        let conf = round2(
            ((a.iter().map(|x| x.confidence).fold(0.0, f64::max)
                + b.iter().map(|x| x.confidence).fold(0.0, f64::max))
                / 2.0)
                .min(0.99),
        );
        let reason = if shared.is_empty() {
            format!(
                "Sequential live evidence: {} findings in {from} precede {} findings in {to}",
                a.len(),
                b.len()
            )
        } else {
            format!(
                "Shared live assets between {from} and {to}: {}",
                shared.iter().cloned().collect::<Vec<_>>().join(", ")
            )
        };
        edges.push(StageEdge {
            from: from.into(),
            to: to.into(),
            reason,
            shared_assets: shared.into_iter().collect(),
            confidence: conf,
        });
    }

    let mut ranked: Vec<(String, CitedFinding)> = Vec::new();
    for (stage, list) in &by_stage {
        for f in list {
            ranked.push(((*stage).to_string(), f.clone()));
        }
    }
    ranked.sort_by(|a, b| {
        b.1.risk_points
            .partial_cmp(&a.1.risk_points)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.id.cmp(&b.1.id))
    });
    let total_points = round2(ranked.iter().map(|(_, f)| f.risk_points).sum::<f64>());
    let total_usd: Option<i64> = {
        let sum: i64 = ranked.iter().filter_map(|(_, f)| f.priced_usd).sum();
        if ranked.iter().any(|(_, f)| f.priced_usd.is_some()) {
            Some(sum)
        } else {
            None
        }
    };
    let top3: Vec<TopFix> = ranked
        .iter()
        .take(TOP_FIXES)
        .map(|(stage, f)| TopFix {
            id: f.id,
            finding_id: f.finding_id.clone(),
            title: f.title.clone(),
            stage: stage.clone(),
            risk_points: f.risk_points,
            priced_usd: f.priced_usd,
        })
        .collect();
    let top3_pts: f64 = top3.iter().map(|t| t.risk_points).sum();
    let residual = round2((total_points - top3_pts).max(0.0));
    let reduction = if total_points > 0.0 {
        round2(((total_points - residual) / total_points) * 100.0)
    } else {
        0.0
    };
    let residual_usd = total_usd.map(|t| {
        let drop: i64 = top3.iter().filter_map(|x| x.priced_usd).sum();
        (t - drop).max(0)
    });

    KillChainSnapshot {
        ok: true,
        live: true,
        client_id: Some(cid),
        client_name,
        primary_domain,
        stages,
        edges,
        pricing: Pricing {
            formula: formula_spec(),
            total_risk_points: total_points,
            residual_if_top3_fixed: residual,
            residual_reduction_pct: reduction,
            top3_fixes: top3,
            total_priced_usd: total_usd,
            residual_priced_usd: residual_usd,
        },
        jobs: jobs_out,
        assets_considered,
        findings_considered,
        empty_reason: None,
        honesty: Honesty {
            live_evidence_only: true,
            no_fabricated_apt: true,
            fail_closed_empty: true,
            client_bound: true,
            formula_published: true,
        },
    }
}

pub fn compose_or_conflict(snap: &KillChainSnapshot) -> Result<Value, String> {
    if let Some(reason) = &snap.empty_reason {
        return Err(reason.clone());
    }
    serde_json::to_value(snap).map_err(|e| e.to_string())
}

pub fn snapshot_json(snap: &KillChainSnapshot) -> Value {
    json!({
        "ok": snap.ok,
        "live": snap.live,
        "client_id": snap.client_id,
        "client_name": snap.client_name,
        "primary_domain": snap.primary_domain,
        "stages": snap.stages,
        "edges": snap.edges,
        "pricing": snap.pricing,
        "jobs": snap.jobs,
        "assets_considered": snap.assets_considered,
        "findings_considered": snap.findings_considered,
        "empty_reason": snap.empty_reason,
        "honesty": snap.honesty,
        "stage_order": STAGES,
    })
}

pub async fn load_snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
) -> Result<KillChainSnapshot, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("db: {e}"))?;

    let (client_name, domains_raw, default_usd): (Option<String>, String, i64) = if let Some(cid) =
        client_id
    {
        let row = sqlx::query(
                "SELECT name, COALESCE(domains,'[]') AS domains, COALESCE(default_asset_value_usd, 0)::bigint AS def_usd FROM clients WHERE id = $1",
            )
            .bind(cid)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("client: {e}"))?;
        match row {
            Some(r) => (
                r.try_get::<String, _>("name").ok(),
                r.try_get::<String, _>("domains")
                    .unwrap_or_else(|_| "[]".into()),
                r.try_get::<i64, _>("def_usd").unwrap_or(0),
            ),
            None => {
                let _ = tx.commit().await;
                return Ok(empty_snapshot(
                    Some(cid),
                    None,
                    None,
                    EMPTY_NO_FINDINGS.into(),
                    vec![],
                    0,
                    0,
                ));
            }
        }
    } else {
        (None, "[]".into(), 0)
    };
    let primary_domain = parse_primary_domain(&domains_raw);

    let finding_rows = if let Some(cid) = client_id {
        sqlx::query(
            r#"SELECT id, finding_id, client_id, COALESCE(title,'') AS title, COALESCE(severity,'') AS severity,
                      COALESCE(source,'') AS source, COALESCE(description,'') AS description,
                      COALESCE(status,'OPEN') AS status, proof, poc_exploit,
                      COALESCE(raw_data, '{}'::jsonb) AS raw_data,
                      COALESCE(kev_listed, false) AS kev_listed, epss_score, risk_node_id
                 FROM vulnerabilities
                WHERE client_id = $1
                ORDER BY discovered_at DESC
                LIMIT 4000"#,
        )
        .bind(cid)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("findings: {e}"))?
    } else {
        Vec::new()
    };

    let findings: Vec<LiveFinding> = finding_rows
        .into_iter()
        .filter_map(|r| {
            Some(LiveFinding {
                id: r.try_get("id").ok()?,
                finding_id: r.try_get("finding_id").unwrap_or_default(),
                client_id: r.try_get("client_id").ok()?,
                title: r.try_get("title").unwrap_or_default(),
                severity: r.try_get("severity").unwrap_or_default(),
                source: r.try_get("source").unwrap_or_default(),
                description: r.try_get("description").unwrap_or_default(),
                status: r.try_get("status").unwrap_or_else(|_| "OPEN".into()),
                proof: r.try_get::<Option<String>, _>("proof").ok().flatten(),
                poc_exploit: r.try_get::<Option<String>, _>("poc_exploit").ok().flatten(),
                raw_data: r
                    .try_get::<Value, _>("raw_data")
                    .unwrap_or_else(|_| json!({})),
                kev_listed: r.try_get::<bool, _>("kev_listed").unwrap_or(false),
                epss_score: r.try_get::<Option<f32>, _>("epss_score").ok().flatten(),
                risk_node_id: r.try_get::<Option<i64>, _>("risk_node_id").ok().flatten(),
            })
        })
        .collect();

    let asset_rows = if let Some(cid) = client_id {
        sqlx::query(
            r#"SELECT id, client_id, COALESCE(label,'') AS label, COALESCE(graph_key,'') AS graph_key,
                      COALESCE(node_type,'') AS node_type,
                      COALESCE(internet_exposed, false) AS internet_exposed,
                      COALESCE(crown_jewel, false) AS crown_jewel,
                      COALESCE(asset_value, 1.0) AS asset_value,
                      business_value_usd
                 FROM risk_graph_nodes
                WHERE client_id = $1
                LIMIT 4000"#,
        )
        .bind(cid)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("assets: {e}"))?
    } else {
        Vec::new()
    };
    let assets: Vec<LiveAsset> = asset_rows
        .into_iter()
        .filter_map(|r| {
            Some(LiveAsset {
                id: r.try_get("id").ok()?,
                client_id: r.try_get("client_id").ok()?,
                label: r.try_get("label").unwrap_or_default(),
                graph_key: r.try_get("graph_key").unwrap_or_default(),
                node_type: r.try_get("node_type").unwrap_or_default(),
                internet_exposed: r.try_get("internet_exposed").unwrap_or(false),
                crown_jewel: r.try_get("crown_jewel").unwrap_or(false),
                asset_value: r.try_get("asset_value").unwrap_or(1.0),
                business_value_usd: r
                    .try_get::<Option<i64>, _>("business_value_usd")
                    .ok()
                    .flatten(),
            })
        })
        .collect();

    let job_rows = if let Some(cid) = client_id {
        sqlx::query(
            r#"SELECT id::text AS id, kind, status, COALESCE(payload, '{}'::jsonb) AS payload, created_at
                 FROM weissman_async_jobs
                WHERE tenant_id = $1
                  AND (
                        payload->>'client_id' = $2::text
                        OR (jsonb_typeof(payload->'client_id') = 'number' AND (payload->>'client_id')::bigint = $2)
                      )
                ORDER BY created_at DESC
                LIMIT 25"#,
        )
        .bind(tenant_id)
        .bind(cid)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };
    let jobs: Vec<LiveJob> = job_rows
        .into_iter()
        .map(|r| {
            let payload: Value = r.try_get("payload").unwrap_or(Value::Null);
            LiveJob {
                id: r.try_get::<String, _>("id").unwrap_or_default(),
                kind: r.try_get("kind").unwrap_or_default(),
                status: r.try_get("status").unwrap_or_default(),
                engine: payload
                    .get("engine")
                    .and_then(Value::as_str)
                    .map(|s| s.to_string()),
                target: payload
                    .get("target")
                    .and_then(Value::as_str)
                    .map(|s| s.to_string()),
                client_id: payload.get("client_id").and_then(|v| {
                    v.as_i64()
                        .or_else(|| v.as_u64().and_then(|n| i64::try_from(n).ok()))
                        .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
                }),
                created_at: r
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                    .ok()
                    .map(|d| d.to_rfc3339()),
            }
        })
        .collect();

    let priv_rows = if let Some(cid) = client_id {
        sqlx::query(
            r#"SELECT id, client_id, COALESCE(from_context,'') AS from_context,
                      COALESCE(to_context,'') AS to_context, COALESCE(method,'') AS method,
                      COALESCE(url,'') AS url, COALESCE(severity,'critical') AS severity
                 FROM privilege_escalation_events
                WHERE client_id = $1
                ORDER BY created_at DESC
                LIMIT 200"#,
        )
        .bind(cid)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default()
    } else {
        Vec::new()
    };
    let priv_esc: Vec<PrivEscEvent> = priv_rows
        .into_iter()
        .filter_map(|r| {
            Some(PrivEscEvent {
                id: r.try_get("id").ok()?,
                client_id: r.try_get("client_id").ok()?,
                from_context: r.try_get("from_context").unwrap_or_default(),
                to_context: r.try_get("to_context").unwrap_or_default(),
                method: r.try_get("method").unwrap_or_default(),
                url: r.try_get("url").unwrap_or_default(),
                severity: r.try_get("severity").unwrap_or_else(|_| "critical".into()),
            })
        })
        .collect();

    let _ = tx.commit().await;
    Ok(compose_chain(
        client_id,
        client_name,
        primary_domain,
        default_usd,
        findings,
        assets,
        jobs,
        priv_esc,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(
        id: i64,
        client_id: i64,
        source: &str,
        title: &str,
        sev: &str,
        proof: Option<&str>,
        raw: Value,
    ) -> LiveFinding {
        LiveFinding {
            id,
            finding_id: format!("F-{id}"),
            client_id,
            title: title.into(),
            severity: sev.into(),
            source: source.into(),
            description: title.into(),
            status: "OPEN".into(),
            proof: proof.map(|s| s.into()),
            poc_exploit: None,
            raw_data: raw,
            kev_listed: false,
            epss_score: None,
            risk_node_id: None,
        }
    }

    fn live_shaped_corpus(client: i64) -> (Vec<LiveFinding>, Vec<LiveAsset>) {
        let assets = vec![
            LiveAsset {
                id: 10,
                client_id: client,
                label: "www.example.com".into(),
                graph_key: "host:www.example.com".into(),
                node_type: "host".into(),
                internet_exposed: true,
                crown_jewel: false,
                asset_value: 1.2,
                business_value_usd: Some(50_000),
            },
            LiveAsset {
                id: 11,
                client_id: client,
                label: "idp.example.com".into(),
                graph_key: "host:idp.example.com".into(),
                node_type: "identity".into(),
                internet_exposed: true,
                crown_jewel: true,
                asset_value: 2.0,
                business_value_usd: Some(250_000),
            },
        ];
        let findings = vec![
            finding(
                1,
                client,
                "osint",
                "Public subdomain www.example.com enumerated",
                "medium",
                Some("DNS A record 93.184.216.34 for www.example.com"),
                json!({"target": "www.example.com", "mitre_techniques": ["T1595"]}),
            ),
            finding(
                2,
                client,
                "sqli_engine",
                "Unauthenticated SQL injection on /login",
                "critical",
                Some("HTTP 200 from boolean-based probe on id="),
                json!({"target": "https://www.example.com/login", "mitre": "T1190"}),
            ),
            finding(
                3,
                client,
                "password_spray",
                "Valid credential accepted on idp.example.com",
                "high",
                Some("HTTP 302 to /app after spray of known user"),
                json!({"host": "idp.example.com", "mitre_attack": ["T1110"]}),
            ),
            finding(
                4,
                client,
                "privilege_escalation",
                "Role bound to admin after token reuse",
                "high",
                Some("PUT /iam/role returned 204"),
                json!({"target": "idp.example.com", "techniques": ["T1068"]}),
            ),
            finding(
                5,
                client,
                "data_exfil_engine",
                "Bulk export endpoint reachable after admin session",
                "critical",
                Some("GET /export.csv returned 200 with PII columns"),
                json!({"target": "www.example.com", "mitre_techniques": ["T1041"]}),
            ),
        ];
        (findings, assets)
    }

    #[test]
    fn empty_corpus_fail_closed() {
        let snap = compose_chain(
            Some(1),
            Some("Acme".into()),
            Some("example.com".into()),
            10_000,
            vec![],
            vec![],
            vec![],
            vec![],
        );
        assert!(snap
            .empty_reason
            .as_ref()
            .unwrap()
            .contains("No live findings"));
        assert!(compose_or_conflict(&snap).is_err());
        assert!(snap.honesty.fail_closed_empty);
        assert!(snap.stages.iter().all(|s| s.finding_count == 0));
    }

    #[test]
    fn unbound_client_fail_closed() {
        let snap = compose_chain(None, None, None, 0, vec![], vec![], vec![], vec![]);
        assert_eq!(snap.empty_reason.as_deref(), Some(EMPTY_NO_CLIENT));
        assert!(compose_or_conflict(&snap)
            .unwrap_err()
            .contains("bound customer"));
    }

    #[test]
    fn graph_from_fixture_live_shaped_findings() {
        let (findings, assets) = live_shaped_corpus(1);
        let snap = compose_chain(
            Some(1),
            Some("Example".into()),
            Some("example.com".into()),
            10_000,
            findings,
            assets,
            vec![],
            vec![],
        );
        assert!(snap.empty_reason.is_none());
        let counts: BTreeMap<_, _> = snap
            .stages
            .iter()
            .map(|s| (s.stage.as_str(), s.finding_count))
            .collect();
        assert!(counts["recon"] >= 1, "osint must land in recon");
        assert!(counts["foothold"] >= 1, "sqli must land in foothold");
        assert!(
            counts["identity"] >= 1,
            "password spray must land in identity"
        );
        assert!(counts["privilege"] >= 1);
        assert!(counts["impact"] >= 1);
        assert!(!snap.edges.is_empty());
        for st in &snap.stages {
            for f in &st.findings {
                assert!(!f.finding_id.is_empty());
                assert!(f.proof_snippet.is_some(), "live proof required in fixture");
                assert!(!f.mitre.is_empty(), "MITRE cite required");
                assert!(f.confidence >= 0.35 && f.confidence <= 0.99);
                let expr = f.formula_inputs.severity_weight
                    * f.formula_inputs.asset_criticality
                    * f.formula_inputs.exposure_weight;
                assert!((expr - f.risk_points).abs() < 0.02);
            }
        }
        let sqli = snap
            .stages
            .iter()
            .flat_map(|s| s.findings.iter())
            .find(|f| f.id == 2)
            .expect("sqli");
        assert!(sqli.formula_inputs.internet_facing);
        assert_eq!(sqli.formula_inputs.exposure_weight, EXP_INTERNET);
        assert_eq!(
            snap.pricing.formula.expression,
            "severity_weight × asset_criticality × exposure"
        );
        assert!(snap.pricing.total_risk_points > 0.0);
        assert!(snap.pricing.residual_if_top3_fixed < snap.pricing.total_risk_points);
        assert_eq!(snap.pricing.top3_fixes.len(), 3);
        assert!(compose_or_conflict(&snap).is_ok());
        let blob = serde_json::to_string(&snap.stages).unwrap();
        assert!(!blob.contains("APT29"), "must not invent APT names");
        assert!(!blob.contains("Lazarus"));
    }

    #[test]
    fn scoped_client_isolation_drops_other_tenant_findings() {
        let (mut a, assets_a) = live_shaped_corpus(1);
        let (b, assets_b) = live_shaped_corpus(2);
        a.extend(b);
        let mut assets = assets_a;
        assets.extend(assets_b);
        let snap = compose_chain(
            Some(1),
            Some("One".into()),
            Some("example.com".into()),
            10_000,
            a,
            assets,
            vec![LiveJob {
                id: "j-other".into(),
                kind: "scan".into(),
                status: "completed".into(),
                engine: Some("osint".into()),
                target: Some("other.test".into()),
                client_id: Some(2),
                created_at: None,
            }],
            vec![PrivEscEvent {
                id: 99,
                client_id: 2,
                from_context: "user".into(),
                to_context: "root".into(),
                method: "PUT".into(),
                url: "https://other.test/iam".into(),
                severity: "critical".into(),
            }],
        );
        let ids: Vec<i64> = snap
            .stages
            .iter()
            .flat_map(|s| s.findings.iter().map(|f| f.id))
            .collect();
        assert!(ids.contains(&1) && ids.contains(&5));
        assert!(!ids.contains(&99), "client 2 priv-esc must not leak");
        assert!(snap.jobs.is_empty(), "client 2 jobs must not leak");
        for f in snap.stages.iter().flat_map(|s| s.findings.iter()) {
            assert!(
                f.finding_id.starts_with("F-") || f.finding_id.starts_with("priv-esc:"),
                "{}",
                f.finding_id
            );
        }
    }

    #[test]
    fn residual_matches_removing_top3() {
        let (findings, assets) = live_shaped_corpus(1);
        let snap = compose_chain(
            Some(1),
            Some("Example".into()),
            Some("example.com".into()),
            10_000,
            findings,
            assets,
            vec![],
            vec![],
        );
        let all: f64 = snap
            .stages
            .iter()
            .flat_map(|s| s.findings.iter())
            .map(|f| f.risk_points)
            .sum();
        let drop: f64 = snap.pricing.top3_fixes.iter().map(|t| t.risk_points).sum();
        assert!((snap.pricing.total_risk_points - round2(all)).abs() < 0.05);
        assert!((snap.pricing.residual_if_top3_fixed - round2((all - drop).max(0.0))).abs() < 0.05);
    }

    #[test]
    fn primary_domain_from_json_array() {
        assert_eq!(
            parse_primary_domain(r#"["example.com","www.example.com"]"#).as_deref(),
            Some("example.com")
        );
        assert_eq!(
            parse_primary_domain(r#"{"primary":"acme.test"}"#).as_deref(),
            Some("acme.test")
        );
        assert_eq!(
            parse_primary_domain(r#"{"domains":["portal.acme.test"]}"#).as_deref(),
            Some("portal.acme.test")
        );
    }

    #[test]
    fn closed_findings_fail_closed() {
        let mut f = finding(1, 1, "osint", "x", "high", Some("p"), json!({}));
        f.status = "FIXED".into();
        let snap = compose_chain(Some(1), None, None, 0, vec![f], vec![], vec![], vec![]);
        assert_eq!(snap.empty_reason.as_deref(), Some(EMPTY_ALL_CLOSED));
    }
}
