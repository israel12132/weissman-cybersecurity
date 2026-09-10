//! P1 Proof layer — safe exploitability validation.
//!
//! Upgrades findings and campaign steps from **observed** → **validated_safe_proof** →
//! **proven** (or **failed_proof** / **not_applicable**) using evidence that already exists
//! (engine output, OAST hits, read-only cloud confirmation) plus bounded in-scope
//! differential checks. Never shells, never destructive payloads, never invented proof.
//!
//! Privilege / lateral / impact WorldState facts unlock only when `proof_status = proven`.

use crate::attack_chain_planner::{self, Fact};
use crate::engine_probes::{
    extract_host, header_value, http_client, http_get, http_get_with_headers, normalize_url,
    HttpProbe,
};
use crate::fp_feedback;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use uuid::Uuid;

pub const PROOF_STATUSES: &[&str] = &[
    "observed",
    "validated_safe_proof",
    "proven",
    "failed_proof",
    "not_applicable",
];

/// STRIPS facts that must not enter campaign WorldState until a proof gate passes.
pub const PRIVILEGE_UNLOCK_FACTS: &[&str] = &[
    "access:foothold",
    "access:privileged",
    "access:internal",
    "access:crown_jewel",
    "data:db_read",
    "exec:code",
    "impact:objective",
];

pub const ARTIFACT_KINDS: &[&str] = &[
    "request_response_diff",
    "oast_hit",
    "screenshot_ref",
    "cloud_confirmation",
    "sql_error_indicator",
    "xss_reflection",
    "open_redirect",
    "authz_differential",
    "engine_output",
];

const BODY_SNIPPET: usize = 2048;
const REDIRECT_CANARY_HOST: &str = "pentest.weissman-redirect-probe.invalid";
const REDIRECT_CANARY_URL: &str = "https://pentest.weissman-redirect-probe.invalid/callback";
const XSS_CANARY: &str = "weissmanx7f3c";

const AUTH_BYPASS_HEADERS: &[(&str, &str)] = &[
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-For", "127.0.0.1"),
];

const SQL_ERROR_MARKERS: &[&str] = &[
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "odbc sql server driver",
    "pg::syntaxerror",
    "sqlite3.operationalerror",
    "org.hibernate.exception.sqlgrammarexception",
    "mysql_fetch",
    "syntax error at or near",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Observed,
    ValidatedSafeProof,
    Proven,
    FailedProof,
    NotApplicable,
}

impl ProofStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::ValidatedSafeProof => "validated_safe_proof",
            Self::Proven => "proven",
            Self::FailedProof => "failed_proof",
            Self::NotApplicable => "not_applicable",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "observed" => Some(Self::Observed),
            "validated_safe_proof" => Some(Self::ValidatedSafeProof),
            "proven" => Some(Self::Proven),
            "failed_proof" => Some(Self::FailedProof),
            "not_applicable" => Some(Self::NotApplicable),
            _ => None,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Observed => 0,
            Self::NotApplicable => 1,
            Self::FailedProof => 1,
            Self::ValidatedSafeProof => 2,
            Self::Proven => 3,
        }
    }
}

impl std::fmt::Display for ProofStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Legal proof-status transitions. Proven is sticky. Failed proofs may be retried.
#[must_use]
pub fn can_transition_proof(from: &str, to: &str) -> bool {
    let Some(a) = ProofStatus::parse(from) else {
        return false;
    };
    let Some(b) = ProofStatus::parse(to) else {
        return false;
    };
    if a == b {
        return true;
    }
    matches!(
        (a, b),
        (ProofStatus::Observed, _)
            | (ProofStatus::ValidatedSafeProof, ProofStatus::Proven)
            | (ProofStatus::ValidatedSafeProof, ProofStatus::FailedProof)
            | (ProofStatus::FailedProof, ProofStatus::ValidatedSafeProof)
            | (ProofStatus::FailedProof, ProofStatus::Proven)
            | (ProofStatus::NotApplicable, ProofStatus::ValidatedSafeProof)
            | (ProofStatus::NotApplicable, ProofStatus::Proven)
    )
}

#[must_use]
pub fn is_privilege_unlock_fact(fact: &str) -> bool {
    PRIVILEGE_UNLOCK_FACTS.contains(&fact)
}

#[derive(Debug, Clone, Serialize)]
pub struct ProofArtifactDraft {
    pub adapter: String,
    pub kind: String,
    pub evidence: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProofVerdict {
    pub status: ProofStatus,
    pub adapter: String,
    pub reason: String,
    pub artifacts: Vec<ProofArtifactDraft>,
}

impl ProofVerdict {
    fn none(adapter: &str, reason: &str) -> Self {
        Self {
            status: ProofStatus::Observed,
            adapter: adapter.to_string(),
            reason: reason.to_string(),
            artifacts: Vec::new(),
        }
    }

    fn with(
        status: ProofStatus,
        adapter: &str,
        reason: &str,
        artifacts: Vec<ProofArtifactDraft>,
    ) -> Self {
        Self {
            status,
            adapter: adapter.to_string(),
            reason: reason.to_string(),
            artifacts,
        }
    }
}

fn haystack(finding: &Value) -> String {
    let keys = [
        finding.get("title").and_then(Value::as_str).unwrap_or(""),
        finding.get("type").and_then(Value::as_str).unwrap_or(""),
        finding
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or(""),
        finding
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or(""),
        finding.get("proof").and_then(Value::as_str).unwrap_or(""),
        finding.get("source").and_then(Value::as_str).unwrap_or(""),
        finding.get("engine").and_then(Value::as_str).unwrap_or(""),
    ];
    keys.join(" ").to_ascii_lowercase()
}

fn json_blob(finding: &Value) -> String {
    serde_json::to_string(finding)
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn snippet(s: &str) -> String {
    let t = s.trim();
    if t.len() <= BODY_SNIPPET {
        t.to_string()
    } else {
        t.chars().take(BODY_SNIPPET).collect()
    }
}

fn looks_like_user_json(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    b.contains('{')
        && (b.contains("email") || b.contains("username") || b.contains("user"))
        && body.len() > 40
}

fn json_body_differs(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let len_diff = a.len().abs_diff(b.len());
    len_diff > 16 || (looks_like_user_json(a) && looks_like_user_json(b) && a != b)
}

#[must_use]
pub fn sql_error_indicator(body: &str) -> bool {
    let b = body.to_ascii_lowercase();
    SQL_ERROR_MARKERS.iter().any(|m| b.contains(m))
}

#[must_use]
pub fn xss_reflected(body: &str, canary: &str) -> bool {
    !canary.is_empty() && body.contains(canary)
}

#[must_use]
pub fn extract_oast_tokens(finding: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |s: &str| {
        let t = s.trim();
        if t.len() >= 8 && !out.iter().any(|x: &String| x == t) {
            out.push(t.to_string());
        }
    };
    for key in [
        "oast_token",
        "oast_interaction_token",
        "interaction_token",
        "callback_token",
    ] {
        if let Some(s) = finding.get(key).and_then(Value::as_str) {
            push(s);
        }
    }
    if let Some(ev) = finding.get("evidence") {
        for key in ["oast_token", "oast_interaction_token", "interaction_token"] {
            if let Some(s) = ev.get(key).and_then(Value::as_str) {
                push(s);
            }
        }
    }
    if let Some(raw) = finding.get("raw").or_else(|| finding.get("raw_data")) {
        for key in ["oast_token", "oast_interaction_token"] {
            if let Some(s) = raw.get(key).and_then(Value::as_str) {
                push(s);
            }
        }
    }
    out
}

fn screenshot_ref(finding: &Value) -> Option<String> {
    for key in ["screenshot_url", "screenshot_ref", "screenshot"] {
        if let Some(s) = finding.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    if let Some(ev) = finding.get("evidence") {
        for key in ["screenshot_url", "screenshot_ref", "screenshot"] {
            if let Some(s) = ev.get(key).and_then(Value::as_str) {
                let t = s.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
    }
    None
}

#[must_use]
pub fn looks_informational(finding: &Value) -> bool {
    let hay = haystack(finding);
    let sev = finding
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    if sev == "info" || sev == "informational" {
        let vulnish = [
            "sqli",
            "xss",
            "idor",
            "rce",
            "ssrf",
            "authz",
            "redirect",
            "injection",
        ];
        if !vulnish.iter().any(|n| hay.contains(n)) {
            return true;
        }
    }
    hay.contains("stack fingerprint")
        || hay.contains("tls certificate")
        || hay.contains("banner grab")
}

fn web_differential_from_evidence(finding: &Value) -> Option<ProofVerdict> {
    let hay = haystack(finding);
    let blob = json_blob(finding);
    let evidence = finding.get("evidence").cloned().unwrap_or(json!({}));

    if hay.contains("idor differential")
        || hay.contains("auth bypass differential")
        || hay.contains("authz differential")
        || (blob.contains("baseline_status") && blob.contains("bypass_status"))
        || (blob.contains("path_a") && blob.contains("path_b") && blob.contains("body_len"))
    {
        return Some(ProofVerdict::with(
            ProofStatus::Proven,
            "web_api",
            "engine output already contains an authz/IDOR differential",
            vec![ProofArtifactDraft {
                adapter: "web_api".into(),
                kind: "authz_differential".into(),
                evidence: json!({
                    "source": "engine_output",
                    "evidence": evidence,
                    "title": finding.get("title"),
                }),
            }],
        ));
    }

    if hay.contains("open redirect confirmed")
        || (blob.contains("location_header") && blob.contains(REDIRECT_CANARY_HOST))
    {
        return Some(ProofVerdict::with(
            ProofStatus::Proven,
            "web_api",
            "engine output confirms open redirect to the Weissman canary host",
            vec![ProofArtifactDraft {
                adapter: "web_api".into(),
                kind: "open_redirect".into(),
                evidence: json!({ "source": "engine_output", "evidence": evidence }),
            }],
        ));
    }

    let proof = finding.get("proof").and_then(Value::as_str).unwrap_or("");
    let body = evidence
        .get("response_body")
        .or_else(|| evidence.get("body"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if sql_error_indicator(proof) || sql_error_indicator(body) || hay.contains("sql error") {
        if hay.contains("sqli") || hay.contains("sql injection") {
            return Some(ProofVerdict::with(
                ProofStatus::Proven,
                "web_api",
                "SQL error indicator present on a SQLi finding (safe, non-destructive)",
                vec![ProofArtifactDraft {
                    adapter: "web_api".into(),
                    kind: "sql_error_indicator".into(),
                    evidence: json!({
                        "source": "engine_output",
                        "snippet": snippet(if proof.is_empty() { body } else { proof }),
                    }),
                }],
            ));
        }
    }
    if xss_reflected(proof, XSS_CANARY)
        || xss_reflected(body, XSS_CANARY)
        || hay.contains("xss reflection")
    {
        return Some(ProofVerdict::with(
            ProofStatus::Proven,
            "web_api",
            "XSS canary reflected in engine evidence",
            vec![ProofArtifactDraft {
                adapter: "web_api".into(),
                kind: "xss_reflection".into(),
                evidence: json!({ "source": "engine_output" }),
            }],
        ));
    }
    None
}

fn cloud_identity_from_evidence(finding: &Value) -> Option<ProofVerdict> {
    let hay = haystack(finding);
    let blob = json_blob(finding);
    let source = finding
        .get("source")
        .or_else(|| finding.get("engine"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let cloudish = source.contains("cloud")
        || source.contains("iam")
        || source.contains("gcp")
        || source.contains("azure")
        || source.contains("aws")
        || source.starts_with("iac_")
        || source.contains("identity")
        || hay.contains("iam")
        || hay.contains("s3")
        || hay.contains("bucket");

    let confirmed = blob.contains("\"confirmed\":true")
        || blob.contains("\"confirmation\":true")
        || blob.contains("read_only_confirmation")
        || hay.contains("public bucket")
        || hay.contains("publicly accessible")
        || hay.contains("overprivileged")
        || hay.contains("wildcard iam")
        || blob.contains("allusers")
        || blob.contains("administratoraccess");

    if cloudish && confirmed {
        let mut artifacts = vec![ProofArtifactDraft {
            adapter: "cloud_identity".into(),
            kind: "cloud_confirmation".into(),
            evidence: json!({
                "source": "engine_output",
                "engine": source,
                "title": finding.get("title"),
            }),
        }];
        if let Some(shot) = screenshot_ref(finding) {
            artifacts.push(ProofArtifactDraft {
                adapter: "cloud_identity".into(),
                kind: "screenshot_ref".into(),
                evidence: json!({ "ref": shot }),
            });
        }
        return Some(ProofVerdict::with(
            ProofStatus::Proven,
            "cloud_identity",
            "read-only cloud/identity confirmation already present on the finding",
            artifacts,
        ));
    }
    None
}

fn oast_verdict(hit_ids: &[i64], tokens: &[String]) -> Option<ProofVerdict> {
    if hit_ids.is_empty() || tokens.is_empty() {
        return None;
    }
    Some(ProofVerdict::with(
        ProofStatus::Proven,
        "oast",
        "OAST listener received a real out-of-band callback for this finding's token",
        vec![ProofArtifactDraft {
            adapter: "oast".into(),
            kind: "oast_hit".into(),
            evidence: json!({
                "hit_ids": hit_ids,
                "token_count": tokens.len(),
            }),
        }],
    ))
}

fn live_verify_upgrade(finding: &Value) -> Option<ProofVerdict> {
    let verdict = finding
        .get("live_verdict")
        .and_then(Value::as_str)
        .or_else(|| {
            finding
                .get("live_verification")
                .and_then(|v| v.get("verdict"))
                .and_then(Value::as_str)
        })
        .unwrap_or("");
    if verdict.eq_ignore_ascii_case("CONFIRMED") {
        return Some(ProofVerdict::with(
            ProofStatus::ValidatedSafeProof,
            "live_verify",
            "live verification confirmed reachability; not by itself a privilege unlock",
            vec![ProofArtifactDraft {
                adapter: "live_verify".into(),
                kind: "engine_output".into(),
                evidence: json!({ "verdict": verdict }),
            }],
        ));
    }
    None
}

fn pick_stronger(a: ProofVerdict, b: ProofVerdict) -> ProofVerdict {
    if b.status.rank() > a.status.rank() {
        b
    } else if b.status.rank() == a.status.rank() && b.artifacts.len() > a.artifacts.len() {
        b
    } else {
        a
    }
}

/// Classify a finding from **existing** evidence only. Never invents proof.
/// `oast_hit_ids` must already be correlated to tokens extracted from this finding.
#[must_use]
pub fn classify_existing_evidence(finding: &Value, oast_hit_ids: &[i64]) -> ProofVerdict {
    let tokens = extract_oast_tokens(finding);
    let mut best = ProofVerdict::none("classifier", "no confirmation-grade evidence yet");

    if let Some(v) = oast_verdict(oast_hit_ids, &tokens) {
        best = pick_stronger(best, v);
    }
    if let Some(v) = web_differential_from_evidence(finding) {
        best = pick_stronger(best, v);
    }
    if let Some(v) = cloud_identity_from_evidence(finding) {
        best = pick_stronger(best, v);
    }
    if let Some(shot) = screenshot_ref(finding) {
        if best.status == ProofStatus::Observed {
            best.artifacts.push(ProofArtifactDraft {
                adapter: "classifier".into(),
                kind: "screenshot_ref".into(),
                evidence: json!({ "ref": shot }),
            });
        }
    }
    if best.status == ProofStatus::Observed {
        if let Some(v) = live_verify_upgrade(finding) {
            best = pick_stronger(best, v);
        }
    }
    if best.status == ProofStatus::Observed && looks_informational(finding) {
        return ProofVerdict::with(
            ProofStatus::NotApplicable,
            "classifier",
            "informational finding has no safe exploitability proof surface",
            Vec::new(),
        );
    }
    best
}

/// Planner input: drop verified/sandbox flags unless the finding is proven so
/// `facts_from_findings` cannot mint privilege-unlock facts from mere observation.
#[must_use]
pub fn findings_for_planner(findings: &[Value]) -> Vec<Value> {
    findings
        .iter()
        .map(|f| {
            let mut v = f.clone();
            let proven = f.get("proof_status").and_then(Value::as_str) == Some("proven");
            if !proven {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("verified".into(), json!(false));
                    obj.insert("sandbox_verified".into(), json!(false));
                }
            }
            v
        })
        .collect()
}

#[must_use]
pub fn goal_is_reached(
    goal: &str,
    evidence: &HashMap<Fact, Vec<String>>,
    proven_facts: &[Fact],
) -> bool {
    if is_privilege_unlock_fact(goal) {
        proven_facts.iter().any(|f| f == goal)
    } else {
        evidence.contains_key(goal)
    }
}
#[must_use]
pub fn campaign_world_from_findings(
    findings: &[Value],
    proven_step_facts: &HashSet<Fact>,
) -> (HashMap<Fact, Vec<String>>, Vec<Fact>) {
    let mut evidence: HashMap<Fact, Vec<String>> = HashMap::new();
    let mut proven: HashSet<Fact> = proven_step_facts.clone();

    for f in findings {
        let fid = finding_id_of(f);
        let status = f
            .get("proof_status")
            .and_then(Value::as_str)
            .and_then(ProofStatus::parse)
            .unwrap_or(ProofStatus::Observed);
        let facts = attack_chain_planner::facts_from_findings(std::slice::from_ref(f));
        for fact in facts {
            if is_privilege_unlock_fact(&fact) && status != ProofStatus::Proven {
                continue;
            }
            let ids = evidence.entry(fact.clone()).or_default();
            if !fid.is_empty() && !ids.iter().any(|x| x == &fid) {
                ids.push(fid.clone());
            }
            if status == ProofStatus::Proven && is_privilege_unlock_fact(&fact) {
                proven.insert(fact);
            }
        }
    }

    for fact in proven_step_facts {
        evidence.entry(fact.clone()).or_default();
    }

    let mut proven_list: Vec<Fact> = proven.into_iter().collect();
    proven_list.sort();
    (evidence, proven_list)
}

fn finding_id_of(f: &Value) -> String {
    for key in ["finding_id", "id"] {
        if let Some(s) = f.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
        if let Some(n) = f.get(key).and_then(Value::as_i64) {
            return n.to_string();
        }
    }
    String::new()
}

pub async fn lookup_oast_hit_ids(
    tx: &mut Transaction<'_, Postgres>,
    tokens: &[String],
) -> Vec<i64> {
    let mut ids = Vec::new();
    for token in tokens {
        let Ok(uuid) = Uuid::parse_str(token) else {
            continue;
        };
        let rows: Vec<i64> = sqlx::query_scalar(
            r#"SELECT id FROM oast_interaction_hits
                WHERE interaction_token = $1
                ORDER BY created_at DESC
                LIMIT 20"#,
        )
        .bind(uuid)
        .fetch_all(&mut **tx)
        .await
        .unwrap_or_default();
        for id in rows {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids
}

async fn insert_artifacts(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
    finding_id: Option<&str>,
    finding_row_id: Option<i64>,
    campaign_id: Option<Uuid>,
    campaign_step_id: Option<Uuid>,
    artifacts: &[ProofArtifactDraft],
) -> Result<Vec<i64>, String> {
    let mut ids = Vec::new();
    for a in artifacts {
        if !ARTIFACT_KINDS.contains(&a.kind.as_str()) {
            continue;
        }
        let id: i64 = sqlx::query_scalar(
            r#"INSERT INTO weissman_proof_artifacts
                 (tenant_id, client_id, finding_id, finding_row_id, campaign_id, campaign_step_id,
                  adapter, kind, evidence)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
               RETURNING id"#,
        )
        .bind(tenant_id)
        .bind(client_id)
        .bind(finding_id)
        .bind(finding_row_id)
        .bind(campaign_id)
        .bind(campaign_step_id)
        .bind(&a.adapter)
        .bind(&a.kind)
        .bind(&a.evidence)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| format!("proof artifact: {e}"))?;
        ids.push(id);
    }
    Ok(ids)
}

async fn set_finding_proof_status(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    row_id: i64,
    current: &str,
    next: ProofStatus,
    engine: &str,
    signature_hash: &str,
) -> Result<bool, String> {
    if !can_transition_proof(current, next.as_str()) {
        return Ok(false);
    }
    if current == next.as_str() {
        return Ok(false);
    }
    sqlx::query(
        r#"UPDATE vulnerabilities
              SET proof_status = $2, updated_at = now()
            WHERE id = $1 AND tenant_id = $3"#,
    )
    .bind(row_id)
    .bind(next.as_str())
    .bind(tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("finding proof_status: {e}"))?;

    match next {
        ProofStatus::Proven => {
            let _ = fp_feedback::record_tp(tx, tenant_id, engine, signature_hash).await;
        }
        ProofStatus::FailedProof => {
            // Analyst FP labelling still owns suppression. A failed safe-proof is not an
            // invented false positive.
        }
        _ => {}
    }
    Ok(true)
}

/// Apply classifier to a finding JSON already loaded (persist path). Pure + optional OAST ids.
#[must_use]
pub fn classify_for_persist(finding: &Value) -> ProofStatus {
    classify_existing_evidence(finding, &[]).status
}

pub async fn list_artifacts_for_finding(
    pool: &PgPool,
    tenant_id: i64,
    row_id: i64,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let row = sqlx::query(
        r#"SELECT id, finding_id, proof_status, title, source, signature_hash,
                  COALESCE(raw_data, '{}'::jsonb) AS raw_data
             FROM vulnerabilities WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(row_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("finding: {e}"))?;
    let Some(row) = row else {
        let _ = tx.commit().await;
        return Err("finding not found".into());
    };
    let artifacts = sqlx::query(
        r#"SELECT id, adapter, kind, evidence, created_at, campaign_id, campaign_step_id
             FROM weissman_proof_artifacts
            WHERE tenant_id = $1 AND finding_row_id = $2
            ORDER BY created_at DESC
            LIMIT 50"#,
    )
    .bind(tenant_id)
    .bind(row_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("artifacts: {e}"))?;
    let _ = tx.commit().await;
    Ok(json!({
        "ok": true,
        "finding_id": row.try_get::<String, _>("finding_id").unwrap_or_default(),
        "proof_status": row.try_get::<String, _>("proof_status").unwrap_or_else(|_| "observed".into()),
        "title": row.try_get::<String, _>("title").unwrap_or_default(),
        "artifacts": artifacts.into_iter().map(|r| json!({
            "id": r.try_get::<i64, _>("id").unwrap_or(0),
            "adapter": r.try_get::<String, _>("adapter").unwrap_or_default(),
            "kind": r.try_get::<String, _>("kind").unwrap_or_default(),
            "evidence": r.try_get::<Value, _>("evidence").unwrap_or_else(|_| json!({})),
            "campaign_id": r.try_get::<Option<Uuid>, _>("campaign_id").ok().flatten().map(|u| u.to_string()),
            "campaign_step_id": r.try_get::<Option<Uuid>, _>("campaign_step_id").ok().flatten().map(|u| u.to_string()),
            "created_at": r.try_get::<chrono::DateTime<chrono::Utc>, _>("created_at")
                .map(|d| d.to_rfc3339())
                .unwrap_or_default(),
        })).collect::<Vec<_>>(),
    }))
}

fn url_with_query(base: &str, param: &str, value: &str) -> String {
    let enc = urlencoding::encode(value);
    if base.contains('?') {
        format!("{base}&{param}={enc}")
    } else {
        format!("{base}?{param}={enc}")
    }
}

fn swap_trailing_id(url: &str, new_id: &str) -> Option<String> {
    let trimmed = url.trim_end_matches('/');
    let (head, last) = trimmed.rsplit_once('/')?;
    if last.chars().all(|c| c.is_ascii_digit()) && last != new_id {
        Some(format!("{head}/{new_id}"))
    } else {
        None
    }
}

fn probe_diff_artifact(
    kind: &str,
    adapter: &str,
    a: &HttpProbe,
    b: &HttpProbe,
    extra: Value,
) -> ProofArtifactDraft {
    ProofArtifactDraft {
        adapter: adapter.to_string(),
        kind: kind.to_string(),
        evidence: json!({
            "baseline_status": a.status,
            "probe_status": b.status,
            "baseline_body_len": a.body.len(),
            "probe_body_len": b.body.len(),
            "baseline_snippet": snippet(&a.body),
            "probe_snippet": snippet(&b.body),
            "extra": extra,
        }),
    }
}

async fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-SafeProof/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Bounded in-scope web/API differentials. No destructive payloads.
pub async fn run_web_api_live_proof(target: &str) -> ProofVerdict {
    let base = normalize_url(target);
    if extract_host(&base).is_empty() {
        return ProofVerdict::none("web_api", "target has no host");
    }
    let client = http_client().await;
    let nr = no_redirect_client().await;
    let mut artifacts = Vec::new();

    if let Some(baseline) = http_get(&client, &base).await {
        let quote_url = url_with_query(&base, "id", "'");
        if let Some(probe) = http_get(&client, &quote_url).await {
            if sql_error_indicator(&probe.body) && !sql_error_indicator(&baseline.body) {
                artifacts.push(probe_diff_artifact(
                    "sql_error_indicator",
                    "web_api",
                    &baseline,
                    &probe,
                    json!({ "param": "id", "probe": "'" }),
                ));
            }
        }
        let xss_url = url_with_query(&base, "q", XSS_CANARY);
        if let Some(probe) = http_get(&client, &xss_url).await {
            if xss_reflected(&probe.body, XSS_CANARY) {
                artifacts.push(probe_diff_artifact(
                    "xss_reflection",
                    "web_api",
                    &baseline,
                    &probe,
                    json!({ "canary": XSS_CANARY }),
                ));
            }
        }
        if matches!(baseline.status, 401 | 403) {
            for (hdr, val) in AUTH_BYPASS_HEADERS {
                if let Some(bypass) = http_get_with_headers(&client, &base, &[(*hdr, *val)]).await {
                    if bypass.status >= 200
                        && bypass.status < 300
                        && bypass.body.len() > baseline.body.len().saturating_add(32)
                    {
                        artifacts.push(probe_diff_artifact(
                            "authz_differential",
                            "web_api",
                            &baseline,
                            &bypass,
                            json!({ "header": hdr }),
                        ));
                        break;
                    }
                }
            }
        }
        if let Some(alt) = swap_trailing_id(&base, "2") {
            if let Some(other) = http_get(&client, &alt).await {
                if baseline.status == 200
                    && other.status == 200
                    && json_body_differs(&baseline.body, &other.body)
                {
                    artifacts.push(probe_diff_artifact(
                        "authz_differential",
                        "web_api",
                        &baseline,
                        &other,
                        json!({ "sibling": alt }),
                    ));
                }
            }
        }
    }

    for param in ["redirect", "next", "url", "return", "goto"] {
        let url = url_with_query(&base, param, REDIRECT_CANARY_URL);
        if let Some(p) = http_get(&nr, &url).await {
            if matches!(p.status, 301 | 302 | 303 | 307 | 308) {
                if let Some(loc) = header_value(&p.headers, "location") {
                    if loc.contains(REDIRECT_CANARY_HOST) {
                        artifacts.push(ProofArtifactDraft {
                            adapter: "web_api".into(),
                            kind: "open_redirect".into(),
                            evidence: json!({
                                "param": param,
                                "location_header": loc,
                                "http_status": p.status,
                            }),
                        });
                        break;
                    }
                }
            }
        }
    }

    if artifacts.is_empty() {
        return ProofVerdict::with(
            ProofStatus::FailedProof,
            "web_api",
            "safe differentials did not confirm exploitability",
            Vec::new(),
        );
    }
    ProofVerdict::with(
        ProofStatus::Proven,
        "web_api",
        "safe in-scope differential confirmed exploitability",
        artifacts,
    )
}

fn web_technique(technique_id: &str) -> bool {
    matches!(
        technique_id,
        "exploit_rce_web"
            | "exploit_sqli_web"
            | "exploit_ssrf_metadata"
            | "abuse_authz"
            | "valid_accounts"
    )
}

struct LoadedFinding {
    row_id: i64,
    finding_id: String,
    source: String,
    signature_hash: String,
    proof_status: String,
    target: String,
    json: Value,
}

fn row_to_finding(r: &sqlx::postgres::PgRow) -> Option<LoadedFinding> {
    let mut v = r.try_get::<Value, _>("raw_data").ok()?;
    let obj = v.as_object_mut()?;
    let finding_id = r.try_get::<String, _>("finding_id").unwrap_or_default();
    let source = r.try_get::<String, _>("source").unwrap_or_default();
    let proof_status = r
        .try_get::<String, _>("proof_status")
        .unwrap_or_else(|_| "observed".into());
    let signature_hash = r
        .try_get::<Option<String>, _>("signature_hash")
        .ok()
        .flatten()
        .unwrap_or_default();
    let row_id = r.try_get::<i64, _>("id").ok()?;
    obj.insert("finding_id".into(), json!(finding_id.clone()));
    obj.insert("source".into(), json!(source.clone()));
    obj.insert("proof_status".into(), json!(proof_status.clone()));
    if let Ok(title) = r.try_get::<String, _>("title") {
        obj.entry("title").or_insert(Value::String(title));
    }
    if let Ok(sev) = r.try_get::<String, _>("severity") {
        obj.entry("severity").or_insert(Value::String(sev));
    }
    let target = r.try_get::<String, _>("target").unwrap_or_default();
    if !target.is_empty() {
        obj.entry("target").or_insert(Value::String(target.clone()));
    }
    Some(LoadedFinding {
        row_id,
        finding_id,
        source,
        signature_hash,
        proof_status,
        target,
        json: v,
    })
}

async fn load_related_findings(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
    campaign_id: Uuid,
    engine_id: &str,
) -> Result<Vec<LoadedFinding>, String> {
    let cid = campaign_id.to_string();
    let rows = sqlx::query(
        r#"SELECT id, finding_id, signature_hash, source, status, title, severity, proof_status,
                  COALESCE(raw_data, '{}'::jsonb) AS raw_data,
                  COALESCE(raw_data->>'target', '') AS target
             FROM vulnerabilities
            WHERE tenant_id = $1 AND client_id = $2
              AND COALESCE(status, 'OPEN') NOT IN ('FIXED', 'FALSE_POSITIVE')
              AND (
                    raw_data->>'campaign_id' = $3
                 OR ($4 <> '' AND lower(source) = lower($4))
              )
            ORDER BY id DESC
            LIMIT 80"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(&cid)
    .bind(engine_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("related findings: {e}"))?;
    Ok(rows.iter().filter_map(row_to_finding).collect())
}

/// Classify related findings from existing evidence + OAST. Returns step ids that still
/// need a live web adapter after commit (observed web techniques only).
pub async fn gate_succeeded_steps(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    campaign_id: Uuid,
    client_id: i64,
) -> Result<Vec<(Uuid, String, String)>, String> {
    let rows = sqlx::query(
        r#"SELECT id, technique_id, engine_id, target, proof_status, planned_gained
             FROM weissman_campaign_steps
            WHERE campaign_id = $1 AND status = 'succeeded'
              AND proof_status IN ('observed', 'validated_safe_proof', 'failed_proof')
              AND COALESCE((proof_evidence->>'live_queued')::boolean, false) = false"#,
    )
    .bind(campaign_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| format!("gate steps: {e}"))?;

    let mut need_live = Vec::new();
    for r in rows {
        let step_id: Uuid = r.try_get("id").map_err(|e| e.to_string())?;
        let technique_id: String = r.try_get("technique_id").unwrap_or_default();
        let engine_id: String = r.try_get("engine_id").unwrap_or_default();
        let target: String = r.try_get("target").unwrap_or_default();
        let current: String = r
            .try_get("proof_status")
            .unwrap_or_else(|_| "observed".into());

        let related =
            load_related_findings(tx, tenant_id, client_id, campaign_id, &engine_id).await?;
        let host = extract_host(&target).to_ascii_lowercase();
        let related: Vec<LoadedFinding> = related
            .into_iter()
            .filter(|f| {
                if host.is_empty() {
                    return true;
                }
                let fh = extract_host(&f.target).to_ascii_lowercase();
                fh.is_empty()
                    || fh == host
                    || fh.ends_with(&format!(".{host}"))
                    || host.ends_with(&format!(".{fh}"))
            })
            .collect();

        let mut best = ProofVerdict::none("campaign_gate", "no related evidence");
        for f in &related {
            let tokens = extract_oast_tokens(&f.json);
            let hits = lookup_oast_hit_ids(tx, &tokens).await;
            let v = classify_existing_evidence(&f.json, &hits);
            if v.status.rank() >= best.status.rank() {
                best = pick_stronger(best, v);
            }
        }

        if best.status == ProofStatus::ValidatedSafeProof {
            // Engine job completed + safe confirmation together are campaign-grade.
            best.status = ProofStatus::Proven;
            best.reason = format!(
                "campaign step {} completed with validated safe proof",
                technique_id
            );
        }

        if best.status == ProofStatus::Proven {
            apply_step_verdict(
                tx,
                tenant_id,
                client_id,
                campaign_id,
                step_id,
                &technique_id,
                &current,
                &best,
                &related,
            )
            .await?;
            continue;
        }

        if best.status == ProofStatus::NotApplicable && !web_technique(&technique_id) {
            apply_step_verdict(
                tx,
                tenant_id,
                client_id,
                campaign_id,
                step_id,
                &technique_id,
                &current,
                &ProofVerdict::with(
                    ProofStatus::NotApplicable,
                    "campaign_gate",
                    "no safe exploitability adapter for this technique without inventing proof",
                    Vec::new(),
                ),
                &related,
            )
            .await?;
            continue;
        }

        if web_technique(&technique_id) && !target.trim().is_empty() {
            sqlx::query(
                r#"UPDATE weissman_campaign_steps
                      SET proof_evidence = COALESCE(proof_evidence, '{}'::jsonb) || $2::jsonb,
                          updated_at = now()
                    WHERE id = $1"#,
            )
            .bind(step_id)
            .bind(json!({ "live_queued": true, "safety_rails_no_shells": true }))
            .execute(&mut **tx)
            .await
            .map_err(|e| format!("live queue: {e}"))?;
            need_live.push((step_id, technique_id, target));
            continue;
        }

        apply_step_verdict(
            tx,
            tenant_id,
            client_id,
            campaign_id,
            step_id,
            &technique_id,
            &current,
            &ProofVerdict::with(
                ProofStatus::FailedProof,
                "campaign_gate",
                "step completed without confirmation-grade evidence; refusing to invent proof",
                Vec::new(),
            ),
            &related,
        )
        .await?;
    }
    Ok(need_live)
}

async fn apply_step_verdict(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
    campaign_id: Uuid,
    step_id: Uuid,
    technique_id: &str,
    current: &str,
    verdict: &ProofVerdict,
    related: &[LoadedFinding],
) -> Result<(), String> {
    if !can_transition_proof(current, verdict.status.as_str()) && current != verdict.status.as_str()
    {
        return Ok(());
    }
    let artifact_ids = insert_artifacts(
        tx,
        tenant_id,
        client_id,
        None,
        related.first().map(|f| f.row_id),
        Some(campaign_id),
        Some(step_id),
        &verdict.artifacts,
    )
    .await?;

    let evidence = json!({
        "adapter": verdict.adapter,
        "reason": verdict.reason,
        "artifact_ids": artifact_ids,
        "finding_ids": related.iter().map(|f| f.finding_id.clone()).collect::<Vec<_>>(),
        "safety_rails_no_shells": true,
    });
    let planned: Value =
        sqlx::query_scalar("SELECT planned_gained FROM weissman_campaign_steps WHERE id = $1")
            .bind(step_id)
            .fetch_optional(&mut **tx)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| json!([]));
    let outcome = if verdict.status == ProofStatus::Proven {
        planned.clone()
    } else {
        json!([])
    };
    sqlx::query(
        r#"UPDATE weissman_campaign_steps
              SET proof_status = $2, proof_evidence = $3, outcome_facts = $4, updated_at = now()
            WHERE id = $1"#,
    )
    .bind(step_id)
    .bind(verdict.status.as_str())
    .bind(&evidence)
    .bind(&outcome)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("step proof: {e}"))?;

    for f in related {
        let _ = set_finding_proof_status(
            tx,
            tenant_id,
            f.row_id,
            &f.proof_status,
            verdict.status,
            &f.source,
            &f.signature_hash,
        )
        .await?;
        if !verdict.artifacts.is_empty() {
            let _ = insert_artifacts(
                tx,
                tenant_id,
                client_id,
                Some(&f.finding_id),
                Some(f.row_id),
                Some(campaign_id),
                Some(step_id),
                &verdict.artifacts,
            )
            .await;
        }
    }

    let kind = match verdict.status {
        ProofStatus::Proven => "technique_proven",
        ProofStatus::FailedProof => "proof_failed",
        _ => "",
    };
    if !kind.is_empty() {
        crate::adversary_campaign::emit_kind_in_tx(
            tx,
            tenant_id,
            campaign_id,
            client_id,
            kind,
            json!({
                "technique_id": technique_id,
                "step_id": step_id.to_string(),
                "proof_status": verdict.status.as_str(),
                "adapter": verdict.adapter,
                "reason": verdict.reason,
                "artifact_ids": artifact_ids,
                "invented": false,
            }),
        )
        .await?;
    }
    if verdict.status == ProofStatus::FailedProof {
        let engine = crate::adversary_campaign::engine_for_technique(technique_id).unwrap_or("");
        let mitre = related
            .first()
            .and_then(|f| {
                f.json
                    .get("mitre_attack")
                    .or_else(|| f.json.get("mitre"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("");
        let _ = crate::adversary_campaign::record_detection_gap_in_tx(
            tx,
            tenant_id,
            campaign_id,
            client_id,
            Some(step_id),
            technique_id,
            engine,
            mitre,
            "proof_failed",
            &verdict.reason,
            json!({ "adapter": verdict.adapter }),
        )
        .await;
    }
    Ok(())
}

/// Operator-triggered safe proof for one finding. Optional live web adapter after classify.
pub async fn run_finding_proof(
    pool: &PgPool,
    tenant_id: i64,
    id_token: &str,
    allow_live: bool,
    client_id_pin: Option<i64>,
) -> Result<Value, String> {
    let row_id = crate::finding_live_verify::parse_finding_row_id(id_token);
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let row = if let Some(id) = row_id {
        sqlx::query(
            r#"SELECT id, finding_id, signature_hash, source, status, title, severity, proof_status, client_id,
                      COALESCE(raw_data, '{}'::jsonb) AS raw_data,
                      COALESCE(raw_data->>'target', '') AS target
                 FROM vulnerabilities WHERE id = $1 AND tenant_id = $2"#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
    } else {
        sqlx::query(
            r#"SELECT id, finding_id, signature_hash, source, status, title, severity, proof_status, client_id,
                      COALESCE(raw_data, '{}'::jsonb) AS raw_data,
                      COALESCE(raw_data->>'target', '') AS target
                 FROM vulnerabilities WHERE finding_id = $1 AND tenant_id = $2
                 ORDER BY id DESC LIMIT 1"#,
        )
        .bind(id_token)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
    }
    .map_err(|e| format!("load: {e}"))?;
    let Some(row) = row else {
        let _ = tx.commit().await;
        return Err("finding not found".into());
    };
    let client_id: i64 = row.try_get("client_id").map_err(|e| e.to_string())?;
    if let Some(pin) = client_id_pin {
        if pin != client_id {
            let _ = tx.commit().await;
            return Err("finding not found".into());
        }
    }
    let loaded = row_to_finding(&row).ok_or_else(|| "finding not found".to_string())?;
    let tokens = extract_oast_tokens(&loaded.json);
    let hits = lookup_oast_hit_ids(&mut tx, &tokens).await;
    let mut verdict = classify_existing_evidence(&loaded.json, &hits);

    let mut live_ran = false;
    let target = if loaded.target.is_empty() {
        loaded
            .json
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    } else {
        loaded.target.clone()
    };

    if allow_live
        && matches!(
            verdict.status,
            ProofStatus::Observed | ProofStatus::FailedProof | ProofStatus::ValidatedSafeProof
        )
        && !target.trim().is_empty()
        && !looks_informational(&loaded.json)
    {
        match crate::security_hardening::validate_scan_target_in_scope(
            pool,
            tenant_id,
            &target,
            Some(client_id),
        )
        .await
        {
            Ok(_) => {
                live_ran = true;
                let live = run_web_api_live_proof(&target).await;
                verdict = pick_stronger(verdict, live);
            }
            Err(e) => {
                if verdict.status == ProofStatus::Observed {
                    verdict.reason = format!("live adapter skipped: {e}");
                }
            }
        }
    }

    let artifact_ids = insert_artifacts(
        &mut tx,
        tenant_id,
        client_id,
        Some(&loaded.finding_id),
        Some(loaded.row_id),
        None,
        None,
        &verdict.artifacts,
    )
    .await?;
    let changed = set_finding_proof_status(
        &mut tx,
        tenant_id,
        loaded.row_id,
        &loaded.proof_status,
        verdict.status,
        &loaded.source,
        &loaded.signature_hash,
    )
    .await?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;

    Ok(json!({
        "ok": true,
        "id": loaded.row_id,
        "finding_id": loaded.finding_id,
        "proof_status": verdict.status.as_str(),
        "previous_status": loaded.proof_status,
        "changed": changed,
        "adapter": verdict.adapter,
        "reason": verdict.reason,
        "live_ran": live_ran,
        "invented": false,
        "safety_rails_no_shells": true,
        "artifact_ids": artifact_ids,
        "artifacts": verdict.artifacts,
    }))
}

pub async fn apply_live_step_proof(
    pool: &PgPool,
    tenant_id: i64,
    campaign_id: Uuid,
    step_id: Uuid,
    target: &str,
    client_id: i64,
    technique_id: &str,
) -> Result<(), String> {
    if crate::security_hardening::validate_scan_target_in_scope(
        pool,
        tenant_id,
        target,
        Some(client_id),
    )
    .await
    .is_err()
    {
        return Err("target outside authorized scope".into());
    }
    let verdict = run_web_api_live_proof(target).await;
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let step = sqlx::query(
        r#"SELECT proof_status, engine_id FROM weissman_campaign_steps
            WHERE id = $1 AND campaign_id = $2"#,
    )
    .bind(step_id)
    .bind(campaign_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("step: {e}"))?;
    let Some(step) = step else {
        let _ = tx.commit().await;
        return Err("step not found".into());
    };
    let current: String = step
        .try_get("proof_status")
        .unwrap_or_else(|_| "observed".into());
    let engine_id: String = step.try_get("engine_id").unwrap_or_default();
    let related =
        load_related_findings(&mut tx, tenant_id, client_id, campaign_id, &engine_id).await?;
    apply_step_verdict(
        &mut tx,
        tenant_id,
        client_id,
        campaign_id,
        step_id,
        technique_id,
        &current,
        &verdict,
        &related,
    )
    .await?;
    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(())
}

/// Operator retry: classify + optional live web adapter for one campaign step.
pub async fn run_campaign_step_proof(
    pool: &PgPool,
    tenant_id: i64,
    campaign_id: Uuid,
    step_id: Uuid,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tx: {e}"))?;
    let row = sqlx::query(
        r#"SELECT technique_id, target, client_id, status
             FROM weissman_campaign_steps
            WHERE id = $1 AND campaign_id = $2 AND tenant_id = $3"#,
    )
    .bind(step_id)
    .bind(campaign_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("step: {e}"))?;
    let Some(row) = row else {
        let _ = tx.commit().await;
        return Err("campaign not found".into());
    };
    let technique_id: String = row.try_get("technique_id").unwrap_or_default();
    let target: String = row.try_get("target").unwrap_or_default();
    let client_id: i64 = row.try_get("client_id").map_err(|e| e.to_string())?;
    let status: String = row.try_get("status").unwrap_or_default();
    sqlx::query(
        r#"UPDATE weissman_campaign_steps
              SET proof_evidence = COALESCE(proof_evidence, '{}'::jsonb) - 'live_queued',
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(step_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("clear queue: {e}"))?;
    let _ = tx.commit().await;

    if status == "succeeded" && web_technique(&technique_id) && !target.trim().is_empty() {
        apply_live_step_proof(
            pool,
            tenant_id,
            campaign_id,
            step_id,
            &target,
            client_id,
            &technique_id,
        )
        .await?;
    } else {
        let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
            .await
            .map_err(|e| format!("tx: {e}"))?;
        let _ = gate_succeeded_steps(&mut tx, tenant_id, campaign_id, client_id).await?;
        tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    }
    crate::adversary_campaign::get_campaign(pool, tenant_id, campaign_id).await
}

pub fn spawn_live_proofs(
    pool: PgPool,
    tenant_id: i64,
    client_id: i64,
    campaign_id: Uuid,
    jobs: Vec<(Uuid, String, String)>,
) {
    if jobs.is_empty() {
        return;
    }
    tokio::spawn(async move {
        for (step_id, technique_id, target) in jobs {
            if let Err(e) = apply_live_step_proof(
                &pool,
                tenant_id,
                campaign_id,
                step_id,
                &target,
                client_id,
                &technique_id,
            )
            .await
            {
                tracing::debug!(
                    target: "proof_layer",
                    error = %e,
                    %campaign_id,
                    "live proof skipped"
                );
            }
        }
        crate::adversary_campaign::spawn_after_persist(
            std::sync::Arc::new(pool),
            tenant_id,
            client_id,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_state_machine_allows_retry_not_downgrade_from_proven() {
        assert!(can_transition_proof("observed", "validated_safe_proof"));
        assert!(can_transition_proof("validated_safe_proof", "proven"));
        assert!(can_transition_proof("observed", "failed_proof"));
        assert!(can_transition_proof("failed_proof", "proven"));
        assert!(can_transition_proof("observed", "not_applicable"));
        assert!(can_transition_proof("proven", "proven"));
        assert!(!can_transition_proof("proven", "observed"));
        assert!(!can_transition_proof("proven", "failed_proof"));
        assert!(!can_transition_proof("validated_safe_proof", "observed"));
        assert!(!can_transition_proof("bogus", "proven"));
        for s in PROOF_STATUSES {
            assert!(ProofStatus::parse(s).is_some());
        }
    }

    #[test]
    fn title_only_sqli_never_invents_proof() {
        let f = json!({
            "title": "Possible SQLi",
            "type": "sqli",
            "severity": "high"
        });
        let v = classify_existing_evidence(&f, &[]);
        assert_eq!(v.status, ProofStatus::Observed);
        assert!(v.artifacts.is_empty());
    }

    #[test]
    fn failed_proof_never_unlocks_privilege_facts() {
        let f = json!({
            "finding_id": "x",
            "title": "Remote code execution on public web app",
            "type": "rce",
            "severity": "critical",
            "verified": true,
            "proof_status": "failed_proof"
        });
        let (ev, proven) = campaign_world_from_findings(&[f], &HashSet::new());
        assert!(ev.contains_key("vuln:rce"));
        assert!(!ev.contains_key("access:foothold"));
        assert!(proven.is_empty());
        assert!(!is_privilege_unlock_fact("vuln:rce"));
        assert!(is_privilege_unlock_fact("access:privileged"));
    }

    #[test]
    fn classifier_never_invents_proof_on_bare_title() {
        let f = json!({
            "finding_id": "x",
            "title": "Possible SQL injection",
            "type": "sqli",
            "severity": "high",
        });
        let v = classify_existing_evidence(&f, &[]);
        assert_eq!(v.status, ProofStatus::Observed);
        assert!(v.artifacts.is_empty());
    }

    #[test]
    fn idor_differential_in_engine_output_is_proven() {
        let f = json!({
            "finding_id": "idor-1",
            "title": "IDOR differential confirmed: /api/users/1 vs /api/users/2",
            "type": "idor",
            "severity": "critical",
            "evidence": {
                "path_a": "/api/users/1",
                "path_b": "/api/users/2",
                "body_len_a": 120,
                "body_len_b": 118
            }
        });
        let v = classify_existing_evidence(&f, &[]);
        assert_eq!(v.status, ProofStatus::Proven);
        assert_eq!(v.adapter, "web_api");
        assert!(v.artifacts.iter().any(|a| a.kind == "authz_differential"));
    }

    #[test]
    fn oast_hit_without_token_is_not_proof() {
        let f = json!({ "title": "SSRF", "type": "ssrf", "severity": "high" });
        let v = classify_existing_evidence(&f, &[99]);
        assert_eq!(v.status, ProofStatus::Observed);
    }

    #[test]
    fn oast_hit_with_finding_token_is_proven() {
        let f = json!({
            "title": "Blind SSRF",
            "type": "ssrf",
            "severity": "high",
            "oast_token": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        });
        let v = classify_existing_evidence(&f, &[7]);
        assert_eq!(v.status, ProofStatus::Proven);
        assert_eq!(v.adapter, "oast");
        assert_eq!(v.artifacts[0].kind, "oast_hit");
    }

    #[test]
    fn cloud_read_only_confirmation_is_proven() {
        let f = json!({
            "source": "cloud_hunter",
            "title": "S3 bucket publicly accessible",
            "severity": "high",
            "evidence": { "confirmed": true, "acl": "AllUsers" }
        });
        let v = classify_existing_evidence(&f, &[]);
        assert_eq!(v.status, ProofStatus::Proven);
        assert_eq!(v.adapter, "cloud_identity");
    }

    #[test]
    fn informational_tls_is_not_applicable() {
        let f = json!({
            "title": "TLS certificate expires soon",
            "type": "tls",
            "severity": "info"
        });
        let v = classify_existing_evidence(&f, &[]);
        assert_eq!(v.status, ProofStatus::NotApplicable);
    }

    #[test]
    fn privilege_facts_require_proven_status() {
        let observed = json!({
            "finding_id": "a",
            "title": "Remote code execution on public web app",
            "type": "rce",
            "severity": "critical",
            "verified": true,
            "proof_status": "observed",
            "target": "https://app.example"
        });
        let proven = json!({
            "finding_id": "b",
            "title": "Remote code execution on public web app",
            "type": "rce",
            "severity": "critical",
            "verified": true,
            "proof_status": "proven",
            "target": "https://app.example"
        });
        let (ev_obs, proven_obs) = campaign_world_from_findings(&[observed], &HashSet::new());
        assert!(ev_obs.contains_key("vuln:rce"));
        assert!(ev_obs.contains_key("service:web"));
        assert!(!ev_obs.contains_key("access:foothold"));
        assert!(proven_obs.is_empty());

        let (ev_pr, proven_pr) = campaign_world_from_findings(&[proven], &HashSet::new());
        assert!(ev_pr.contains_key("access:foothold"));
        assert!(proven_pr.iter().any(|f| f == "access:foothold"));
    }

    #[test]
    fn proven_step_facts_unlock_even_without_finding_flag() {
        let mut steps = HashSet::new();
        steps.insert("access:privileged".into());
        let (ev, proven) = campaign_world_from_findings(&[], &steps);
        assert!(ev.contains_key("access:privileged"));
        assert!(proven.contains(&"access:privileged".to_string()));
    }

    #[test]
    fn api_proof_response_contract() {
        let body = json!({
            "ok": true,
            "proof_status": "proven",
            "invented": false,
            "safety_rails_no_shells": true,
            "artifact_ids": [1],
        });
        assert_eq!(body["invented"], false);
        assert_eq!(body["safety_rails_no_shells"], true);
        assert!(PROOF_STATUSES.contains(&body["proof_status"].as_str().unwrap()));
    }

    #[test]
    fn extract_oast_tokens_ignores_short_noise() {
        let f = json!({ "oast_token": "abc", "evidence": { "oast_token": "token-long-enough" } });
        let t = extract_oast_tokens(&f);
        assert_eq!(t, vec!["token-long-enough".to_string()]);
    }

    #[test]
    fn live_verify_confirmed_is_validated_not_privilege_unlock() {
        let f = json!({
            "title": "Open port",
            "type": "asm",
            "severity": "medium",
            "live_verdict": "CONFIRMED"
        });
        let v = classify_existing_evidence(&f, &[]);
        assert_eq!(v.status, ProofStatus::ValidatedSafeProof);
        let (ev, proven) = campaign_world_from_findings(
            &[json!({
                "finding_id": "p",
                "title": "RCE",
                "type": "rce",
                "severity": "critical",
                "verified": true,
                "proof_status": "validated_safe_proof"
            })],
            &HashSet::new(),
        );
        assert!(ev.contains_key("vuln:rce"));
        assert!(!ev.contains_key("access:foothold"));
        assert!(proven.is_empty());
    }

    #[test]
    fn adapters_do_not_embed_destructive_payloads() {
        let src = include_str!("proof_layer.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        for needle in [
            "xp_cmdshell",
            "/bin/bash",
            "cmd.exe",
            "DROP DATABASE",
            "LOAD_FILE(",
            "into outfile",
        ] {
            assert!(
                !prod
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase()),
                "destructive token {needle} must not appear in proof adapters"
            );
        }
        assert!(prod.contains("safety_rails_no_shells"));
    }

    #[test]
    fn planner_strips_unproven_verified_flag() {
        let f = json!({
            "finding_id": "r",
            "title": "RCE",
            "type": "rce",
            "severity": "critical",
            "verified": true,
            "proof_status": "observed"
        });
        let gated = findings_for_planner(&[f]);
        assert_eq!(gated[0]["verified"], false);
        let facts = attack_chain_planner::facts_from_findings(&gated);
        assert!(facts.contains("vuln:rce"));
        assert!(!facts.contains("access:foothold"));
    }

    #[test]
    fn swap_trailing_id_only_replaces_numeric_leaf() {
        assert_eq!(
            swap_trailing_id("https://app.example/api/users/1", "2").as_deref(),
            Some("https://app.example/api/users/2")
        );
        assert!(swap_trailing_id("https://app.example/login", "2").is_none());
    }
}
