//! Discovery Lab v1 — AI-assisted novel vulnerability discovery on **authorized**
//! tenant assets, plus a responsible-disclosure pack workflow.
//!
//! Candidates are persisted in dedicated tables (not the ordinary findings inbox).
//! Probes reuse `fuzz_core` mutation + anomaly scoring. LLM hypotheses are opt-in
//! and fail-open: a lab run still completes from static mutations when the router
//! is unavailable. Nothing here scans hosts outside tenant-approved scope.

use crate::fp_feedback;
use crate::intel_kev;
use crate::scan_http_client;
use chrono::{DateTime, Utc};
use fuzz_core::{
    is_anomaly, looks_like_sqli_response, reflected_xss_indicated, Mutator, XSS_REFLECTION_TOKEN,
    DANGEROUS_SUFFIXES, SQLI_PROBE_PAYLOADS,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const ENGINE_ID: &str = "discovery_lab";
pub const JOB_KIND: &str = "discovery_lab";

const MAX_PAYLOAD_BYTES: usize = 8192;
const MAX_HYPOTHESES: usize = 8;
const BASELINE_REQUESTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    Candidate,
    Validated,
    Suppressed,
    CustomerRemediation,
    DisclosureReady,
    Disclosed,
}

impl CandidateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Validated => "validated",
            Self::Suppressed => "suppressed",
            Self::CustomerRemediation => "customer_remediation",
            Self::DisclosureReady => "disclosure_ready",
            Self::Disclosed => "disclosed",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "candidate" => Some(Self::Candidate),
            "validated" => Some(Self::Validated),
            "suppressed" => Some(Self::Suppressed),
            "customer_remediation" => Some(Self::CustomerRemediation),
            "disclosure_ready" => Some(Self::DisclosureReady),
            "disclosed" => Some(Self::Disclosed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateAction {
    Validate,
    Suppress,
    Remediation,
    DisclosureReady,
}

impl CandidateAction {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "validate" | "tp" | "true_positive" => Some(Self::Validate),
            "suppress" | "fp" | "false_positive" => Some(Self::Suppress),
            "remediation" | "customer_remediation" => Some(Self::Remediation),
            "disclosure_ready" => Some(Self::DisclosureReady),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::Suppress => "suppress",
            Self::Remediation => "remediation",
            Self::DisclosureReady => "disclosure_ready",
        }
    }
}

/// Strict analyst transitions. `validated` may skip straight to disclosure-ready
/// so a 0-day can go to CERT in parallel with customer remediation.
pub fn transition(from: CandidateStatus, action: CandidateAction) -> Result<CandidateStatus, String> {
    use CandidateAction as A;
    use CandidateStatus as S;
    let next = match (from, action) {
        (S::Candidate, A::Validate) => S::Validated,
        (S::Candidate, A::Suppress) => S::Suppressed,
        (S::Validated, A::Suppress) => S::Suppressed,
        (S::Validated, A::Remediation) => S::CustomerRemediation,
        (S::Validated, A::DisclosureReady) => S::DisclosureReady,
        (S::CustomerRemediation, A::DisclosureReady) => S::DisclosureReady,
        (S::CustomerRemediation, A::Suppress) => S::Suppressed,
        (S::DisclosureReady, A::Suppress) => S::Suppressed,
        _ => {
            return Err(format!(
                "illegal Discovery Lab transition: {} + {}",
                from.as_str(),
                action.as_str()
            ))
        }
    };
    Ok(next)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadClass {
    Sqli,
    Xss,
    Ssti,
    Traversal,
    Ssrf,
    Cmdi,
    KnownSuffix,
    Novel,
}

impl PayloadClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqli => "sqli",
            Self::Xss => "xss",
            Self::Ssti => "ssti",
            Self::Traversal => "traversal",
            Self::Ssrf => "ssrf",
            Self::Cmdi => "cmdi",
            Self::KnownSuffix => "known_suffix",
            Self::Novel => "novel",
        }
    }

    pub fn is_catalogued(self) -> bool {
        !matches!(self, Self::Novel)
    }
}

#[must_use]
pub fn classify_payload(payload: &str) -> PayloadClass {
    let p = payload.trim();
    let lower = p.to_ascii_lowercase();
    if lower.contains(" or 1=1")
        || lower.contains("or '1'='1")
        || lower.contains("union select")
        || lower.contains("pg_sleep")
        || SQLI_PROBE_PAYLOADS.iter().any(|s| p.contains(s))
    {
        return PayloadClass::Sqli;
    }
    if lower.contains("<script")
        || lower.contains("onerror=")
        || lower.contains("onload=")
        || p.contains(XSS_REFLECTION_TOKEN)
    {
        return PayloadClass::Xss;
    }
    if p.contains("{{") || p.contains("${") || p.contains("#{") {
        return PayloadClass::Ssti;
    }
    if p.contains("../") || p.contains("..\\") || lower.contains("%2e%2e") {
        return PayloadClass::Traversal;
    }
    if lower.contains("169.254.169.254") || lower.contains("metadata.google.internal") {
        return PayloadClass::Ssrf;
    }
    if lower.contains("; id") || lower.contains("| id") || lower.contains("$(id)") || lower.contains("`id`")
    {
        return PayloadClass::Cmdi;
    }
    if DANGEROUS_SUFFIXES.iter().any(|s| p.ends_with(s) || p.contains(s)) {
        return PayloadClass::KnownSuffix;
    }
    PayloadClass::Novel
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyKind {
    Crash500,
    SqliBody,
    XssReflect,
    Timing,
    Length,
    Other,
}

impl AnomalyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Crash500 => "crash_500",
            Self::SqliBody => "sqli_body",
            Self::XssReflect => "xss_reflect",
            Self::Timing => "timing",
            Self::Length => "length",
            Self::Other => "other",
        }
    }

    pub fn noisy(self) -> bool {
        matches!(self, Self::Timing | Self::Length)
    }
}

#[derive(Debug, Clone)]
pub struct NoveltyInputs<'a> {
    pub payload: &'a str,
    pub anomaly_kind: AnomalyKind,
    pub llm_hypothesis: bool,
    pub oob_confirmed: bool,
    pub kev_listed: bool,
    pub epss_score: Option<f64>,
    pub has_cve: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NoveltyAssessment {
    pub payload_class: PayloadClass,
    pub novelty_score: f64,
    pub confidence: f64,
    pub fp_routed: bool,
    pub known_intel: &'static str,
}

#[must_use]
pub fn score_finding(input: NoveltyInputs<'_>) -> NoveltyAssessment {
    let payload_class = classify_payload(input.payload);
    let mut novelty = if input.kev_listed {
        0.06
    } else if input.has_cve {
        match input.epss_score {
            Some(s) if s >= 0.7 => 0.16,
            Some(s) if s >= 0.3 => 0.22,
            Some(_) => 0.30,
            None => 0.34,
        }
    } else if payload_class.is_catalogued() && !input.llm_hypothesis {
        0.28
    } else if payload_class.is_catalogued() && input.llm_hypothesis {
        0.46
    } else if input.llm_hypothesis {
        0.84
    } else {
        0.70
    };
    if input.oob_confirmed {
        novelty = (novelty + 0.04).min(0.95);
    }
    if matches!(input.anomaly_kind, AnomalyKind::Crash500) && !payload_class.is_catalogued() {
        novelty = novelty.max(0.78);
    }
    novelty = novelty.clamp(0.0, 1.0);

    let mut confidence = match input.anomaly_kind {
        AnomalyKind::SqliBody | AnomalyKind::XssReflect => 0.78,
        AnomalyKind::Crash500 => 0.64,
        AnomalyKind::Timing | AnomalyKind::Length => 0.36,
        AnomalyKind::Other => 0.42,
    };
    if input.oob_confirmed {
        confidence = confidence.max(0.90);
    }
    if input.llm_hypothesis && payload_class == PayloadClass::Novel {
        confidence = (confidence + 0.04).min(0.95);
    }
    let fp_routed = input.anomaly_kind.noisy() && !input.oob_confirmed;
    if fp_routed {
        confidence = (confidence * 0.72).max(0.10);
    }
    let known_intel = if input.kev_listed {
        "kev"
    } else if input.has_cve {
        "cve"
    } else if payload_class.is_catalogued() {
        "known_signature"
    } else {
        "none"
    };
    NoveltyAssessment {
        payload_class,
        novelty_score: (novelty * 1000.0).round() / 1000.0,
        confidence: confidence.clamp(0.10, 1.0),
        fp_routed,
        known_intel,
    }
}

#[must_use]
pub fn apply_fp_multiplier(confidence: f64, multiplier: f64) -> f64 {
    (confidence * multiplier.clamp(0.1, 1.0)).clamp(0.10, 1.0)
}

#[must_use]
pub fn signature_hash(host: &str, anomaly_kind: AnomalyKind, payload_class: PayloadClass, payload: &str) -> String {
    let family = payload_family_key(payload);
    let material = format!(
        "{ENGINE_ID}|{}|{}|{}|{family}",
        host.trim().to_ascii_lowercase(),
        anomaly_kind.as_str(),
        payload_class.as_str()
    );
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    hasher.update(payload.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn payload_family_key(payload: &str) -> String {
    let class = classify_payload(payload);
    if class.is_catalogued() {
        class.as_str().to_string()
    } else {
        // Keep novel families stable without embedding the full payload (FP grouping).
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        format!("novel:{:x}", hasher.finalize())[..16].to_string()
    }
}

#[derive(Debug, Clone)]
pub struct ProbeEvidence {
    pub target_url: String,
    pub payload: String,
    pub anomaly_type: String,
    pub anomaly_kind: AnomalyKind,
    pub baseline_vs_anomaly: String,
    pub status: u16,
    pub llm_hypothesis: bool,
    pub llm_rationale: Option<String>,
    pub oob_confirmed: bool,
    pub response_excerpt: String,
}

#[derive(Debug, Clone)]
pub struct ScoredCandidateDraft {
    pub title: String,
    pub technical_summary: String,
    pub impact: String,
    pub recommended_fix: String,
    pub anomaly_type: String,
    pub payload_class: String,
    pub signature_hash: String,
    pub novelty_score: f64,
    pub confidence: f64,
    pub kev_listed: bool,
    pub epss_score: Option<f64>,
    pub cve_id: Option<String>,
    pub fp_routed: bool,
    pub llm_hypothesis: bool,
    pub oob_confirmed: bool,
    pub target_url: String,
    pub evidence: Value,
}

#[must_use]
pub fn draft_from_probe(
    evidence: &ProbeEvidence,
    host: &str,
    kev_listed: bool,
    epss_score: Option<f64>,
    cve_id: Option<String>,
    fp_mult: f64,
) -> ScoredCandidateDraft {
    let scored = score_finding(NoveltyInputs {
        payload: &evidence.payload,
        anomaly_kind: evidence.anomaly_kind,
        llm_hypothesis: evidence.llm_hypothesis,
        oob_confirmed: evidence.oob_confirmed,
        kev_listed,
        epss_score,
        has_cve: cve_id.is_some(),
    });
    let confidence = apply_fp_multiplier(scored.confidence, fp_mult);
    let class = scored.payload_class;
    let sig = signature_hash(host, evidence.anomaly_kind, class, &evidence.payload);
    let title = format!(
        "Discovery Lab {} ({})",
        evidence.anomaly_kind.as_str(),
        class.as_str()
    );
    let technical_summary = format!(
        "{} — payload class {}, novelty {:.2}, known intel {}.",
        evidence.anomaly_type,
        class.as_str(),
        scored.novelty_score,
        scored.known_intel
    );
    let impact = match evidence.anomaly_kind {
        AnomalyKind::Crash500 => {
            "Unhandled exception / crash on authorized target. May indicate a memory-unsafety or uncaught injection path."
        }
        AnomalyKind::SqliBody => {
            "SQL error content in the response suggests a query-construction flaw on an authorized asset."
        }
        AnomalyKind::XssReflect => {
            "Probe token reflected without encoding — XSS candidate on an authorized asset."
        }
        AnomalyKind::Timing => {
            "Response-time deviation vs baseline. High false-positive rate; confirm before disclosure."
        }
        AnomalyKind::Length => {
            "Response-length deviation vs baseline. High false-positive rate; confirm before disclosure."
        }
        AnomalyKind::Other => "Anomalous HTTP behaviour under authorized fuzzing.",
    };
    let recommended_fix = match class {
        PayloadClass::Sqli => "Parameterize queries; reject unexpected operators; add WAF + unit tests for injection.",
        PayloadClass::Xss => "Context-aware output encoding; CSP; avoid reflecting unsanitized query values.",
        PayloadClass::Ssti => "Disable template evaluation of user input; sandbox remaining template engines.",
        PayloadClass::Traversal => "Canonicalize paths; deny `..` segments; serve from a fixed document root.",
        PayloadClass::Ssrf => "Block link-local / metadata ranges; allow-list outbound destinations.",
        PayloadClass::Cmdi => "Do not pass user input to a shell; use argv arrays and allow-lists.",
        PayloadClass::KnownSuffix | PayloadClass::Novel => {
            "Harden input validation, add differential tests for this payload family, and re-run Discovery Lab."
        }
    };
    let evidence_json = json!({
        "anomaly_type": evidence.anomaly_type,
        "anomaly_kind": evidence.anomaly_kind.as_str(),
        "payload": evidence.payload,
        "baseline_vs_anomaly": evidence.baseline_vs_anomaly,
        "http_status": evidence.status,
        "llm_hypothesis": evidence.llm_hypothesis,
        "llm_rationale": evidence.llm_rationale,
        "oob_confirmed": evidence.oob_confirmed,
        "response_excerpt": evidence.response_excerpt,
        "known_intel": scored.known_intel,
        "engine": ENGINE_ID,
        "authorized_scope_only": true,
    });
    ScoredCandidateDraft {
        title,
        technical_summary,
        impact: impact.to_string(),
        recommended_fix: recommended_fix.to_string(),
        anomaly_type: evidence.anomaly_type.clone(),
        payload_class: class.as_str().to_string(),
        signature_hash: sig,
        novelty_score: scored.novelty_score,
        confidence,
        kev_listed,
        epss_score,
        cve_id,
        fp_routed: scored.fp_routed,
        llm_hypothesis: evidence.llm_hypothesis,
        oob_confirmed: evidence.oob_confirmed,
        target_url: evidence.target_url.clone(),
        evidence: evidence_json,
    }
}

fn classify_anomaly(label: &str, status: u16, body: &str) -> AnomalyKind {
    let l = label.to_ascii_lowercase();
    if looks_like_sqli_response(body) {
        return AnomalyKind::SqliBody;
    }
    if reflected_xss_indicated(body) || body.contains(XSS_REFLECTION_TOKEN) {
        return AnomalyKind::XssReflect;
    }
    if status == 500 || l.contains("status 500") {
        return AnomalyKind::Crash500;
    }
    if l.contains("response time") {
        return AnomalyKind::Timing;
    }
    if l.contains("content-length") {
        return AnomalyKind::Length;
    }
    AnomalyKind::Other
}

fn intensity_probe_cap(intensity: &str) -> usize {
    match intensity {
        "light" => 8,
        "aggressive" => 24,
        _ => 16,
    }
}

fn static_payloads(cap: usize) -> Vec<(String, bool, Option<String>)> {
    let m = Mutator::new("weissman");
    let mut out = Vec::new();
    out.push((m.bit_flip(), false, None));
    out.push((m.byte_swap(), false, None));
    for i in 0..DANGEROUS_SUFFIXES.len().min(10) {
        out.push((m.dangerous_suffix(i), false, None));
    }
    for p in SQLI_PROBE_PAYLOADS.iter().take(4) {
        out.push(((*p).to_string(), false, None));
    }
    out.truncate(cap);
    out
}

fn append_lab_query(url: &str, payload: &str) -> String {
    fuzz_core::append_query_param(url, "weissman_lab", payload)
}

struct BaselineProbe {
    avg_latency_ms: f64,
    status: u16,
    content_length: usize,
}

async fn establish_baseline(client: &reqwest::Client, url: &str) -> Result<BaselineProbe, String> {
    let mut latencies = Vec::new();
    let mut last_status = 0u16;
    let mut last_len = 0usize;
    for _ in 0..BASELINE_REQUESTS {
        let started = Instant::now();
        let resp = client
            .get(url)
            .header("User-Agent", fuzz_core::USER_AGENT)
            .send()
            .await
            .map_err(|e| format!("baseline request failed: {e}"))?;
        last_status = resp.status().as_u16();
        let body = resp.bytes().await.unwrap_or_default();
        last_len = body.len();
        latencies.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    Ok(BaselineProbe {
        avg_latency_ms: avg_or_zero(&latencies),
        status: last_status,
        content_length: last_len,
    })
}

fn avg_or_zero(v: &[f64]) -> f64 {
    if v.is_empty() {
        0.0
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

fn excerpt(body: &str) -> String {
    body.chars().take(280).collect()
}

async fn send_probe(
    client: &reqwest::Client,
    target_url: &str,
    payload: &str,
    baseline: &BaselineProbe,
    llm: bool,
    rationale: Option<String>,
) -> Option<ProbeEvidence> {
    let url = append_lab_query(target_url, payload);
    let started = Instant::now();
    let resp = client
        .get(&url)
        .header("User-Agent", fuzz_core::USER_AGENT)
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let latency = started.elapsed().as_secs_f64() * 1000.0;
    let bl = fuzz_core::Baseline {
        avg_latency_ms: baseline.avg_latency_ms,
        status: baseline.status,
        content_length: baseline.content_length,
    };
    let mut label = is_anomaly(&bl, status, body.len(), latency);
    if looks_like_sqli_response(&body) {
        label = Some("SQL error pattern in response body".into());
    } else if reflected_xss_indicated(&body) || body.contains(XSS_REFLECTION_TOKEN) {
        label = Some("XSS reflection of probe token".into());
    }
    let anomaly_type = label?;
    let kind = classify_anomaly(&anomaly_type, status, &body);
    Some(ProbeEvidence {
        target_url: url,
        payload: payload.chars().take(MAX_PAYLOAD_BYTES).collect(),
        anomaly_type,
        anomaly_kind: kind,
        baseline_vs_anomaly: format!(
            "status {status} vs {}; len {} vs {}; {latency:.0}ms vs {:.0}ms",
            baseline.status, body.len(), baseline.content_length, baseline.avg_latency_ms
        ),
        status,
        llm_hypothesis: llm,
        llm_rationale: rationale,
        oob_confirmed: false,
        response_excerpt: excerpt(&body),
    })
}

#[derive(Debug, Deserialize)]
struct HypothesisFile {
    #[serde(default)]
    hypotheses: Vec<HypothesisRow>,
}

#[derive(Debug, Deserialize)]
struct HypothesisRow {
    #[serde(default)]
    payload: String,
    #[serde(default)]
    vector: String,
    #[serde(default)]
    rationale: String,
}

fn parse_hypotheses(raw: &str, target_host: &str) -> Vec<(String, bool, Option<String>)> {
    let text = raw.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();
    let parsed = serde_json::from_str::<HypothesisFile>(text)
        .or_else(|_| {
            serde_json::from_str::<Value>(text).and_then(|v| {
                let arr = v
                    .get("payloads")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default();
                Ok(HypothesisFile {
                    hypotheses: arr
                        .into_iter()
                        .filter_map(|x| x.as_str().map(|s| HypothesisRow {
                            payload: s.to_string(),
                            vector: String::new(),
                            rationale: String::new(),
                        }))
                        .collect(),
                })
            })
        })
        .unwrap_or(HypothesisFile {
            hypotheses: Vec::new(),
        });
    let host = target_host.to_ascii_lowercase();
    parsed
        .hypotheses
        .into_iter()
        .filter_map(|h| {
            let p = h.payload.trim().to_string();
            if p.is_empty() || p.len() > MAX_PAYLOAD_BYTES {
                return None;
            }
            // Never follow LLM suggestions that point at a different host.
            if (p.contains("://") || p.contains("http"))
                && !p.to_ascii_lowercase().contains(&host)
            {
                return None;
            }
            let rationale = if h.rationale.trim().is_empty() {
                if h.vector.trim().is_empty() {
                    None
                } else {
                    Some(h.vector)
                }
            } else {
                Some(h.rationale)
            };
            Some((p, true, rationale))
        })
        .take(MAX_HYPOTHESES)
        .collect()
}

async fn llm_hypotheses(
    target_url: &str,
    host: &str,
    tenant_id: i64,
) -> (Vec<(String, bool, Option<String>)>, bool) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (Vec::new(), false),
    };
    let system = Some(
        "You are assisting an authorized Weissman Discovery Lab on a contracted customer asset. \
         Propose HTTP query/body mutations that might reveal previously-unknown handling bugs. \
         Output ONLY JSON: {\"hypotheses\":[{\"payload\":\"...\",\"vector\":\"...\",\"rationale\":\"...\"}]}. \
         No exploit chains, no malware, no scanning of hosts other than the given target. \
         Payloads must be short strings suitable as query values.",
    );
    let user = format!(
        "Authorized target URL: {target_url}\nHost: {host}\nPropose up to {MAX_HYPOTHESES} novel mutation payloads."
    );
    match weissman_engines::llm_router::routed_chat_completion_text_json_object(
        &client,
        system,
        &user,
        0.4,
        1024,
        Some(tenant_id),
        "discovery_lab_hypotheses",
        true,
        None,
    )
    .await
    {
        Ok(text) => (parse_hypotheses(&text, host), true),
        Err(e) => {
            tracing::info!(
                target: "discovery_lab",
                error = %e,
                "LLM hypothesis generation unavailable; continuing with fuzz_core mutations"
            );
            (Vec::new(), false)
        }
    }
}

#[derive(Debug, Clone)]
pub struct LabRunReport {
    pub probes_sent: i32,
    pub anomalies: Vec<ProbeEvidence>,
    pub llm_used: bool,
}

pub async fn run_lab_probes(
    target_url: &str,
    intensity: &str,
    tenant_id: i64,
    host: &str,
) -> Result<LabRunReport, String> {
    let cap = intensity_probe_cap(intensity);
    let client = scan_http_client::scan_http_client(Duration::from_secs(8));
    let baseline = establish_baseline(&client, target_url).await?;
    let mut payloads = static_payloads(cap);
    let mut llm_used = false;
    if intensity != "light" {
        let (extra, used) = llm_hypotheses(target_url, host, tenant_id).await;
        llm_used = used && !extra.is_empty();
        for p in extra {
            if payloads.len() >= cap + MAX_HYPOTHESES {
                break;
            }
            payloads.push(p);
        }
    }
    let mut anomalies = Vec::new();
    let mut sent = 0i32;
    for (payload, llm, rationale) in payloads {
        sent += 1;
        if let Some(ev) = send_probe(&client, target_url, &payload, &baseline, llm, rationale).await
        {
            anomalies.push(ev);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    Ok(LabRunReport {
        probes_sent: sent,
        anomalies,
        llm_used,
    })
}

async fn cached_epss(pool: &PgPool, cve: &str) -> Option<f64> {
    let n = cve.trim().to_ascii_uppercase();
    if !n.starts_with("CVE-") {
        return None;
    }
    sqlx::query_scalar::<_, f64>("SELECT score::float8 FROM epss_intel WHERE cve = $1")
        .bind(&n)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

async fn lookup_cve_intel(pool: &PgPool, cve: &str) -> (bool, Option<f64>) {
    let kev = intel_kev::is_kev_listed(pool, cve).await.is_some();
    let epss = cached_epss(pool, cve).await;
    (kev, epss)
}

const INSERT_CANDIDATE_SQL: &str = r#"INSERT INTO discovery_lab_candidates (
        id, tenant_id, client_id, run_id, status, title, technical_summary, impact,
        recommended_fix, anomaly_type, payload_class, signature_hash, novelty_score,
        confidence, kev_listed, epss_score, cve_id, fp_routed, llm_hypothesis,
        oob_confirmed, target_url, evidence
   ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22
   )
   ON CONFLICT (tenant_id, run_id, signature_hash) DO NOTHING"#;

pub async fn persist_candidates_from_probes(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    run_id: &str,
    host: &str,
    probes: &[ProbeEvidence],
) -> Result<i32, sqlx::Error> {
    let suppressions = fp_feedback::active_suppressions_for_engine(pool, tenant_id, ENGINE_ID).await;
    let mut drafts = Vec::new();
    for ev in probes {
        let cve = crate::intel_findings_backfill::extract_cve_from_value(&json!({
            "title": ev.anomaly_type,
            "description": ev.response_excerpt,
        }));
        let (kev, epss) = if let Some(ref c) = cve {
            lookup_cve_intel(pool, c).await
        } else {
            (false, None)
        };
        drafts.push((ev, draft_from_probe(ev, host, kev, epss, cve, 1.0)));
    }

    let mut inserted = 0i32;
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    for (ev, mut draft) in drafts {
        let mult = fp_feedback::confidence_multiplier_tx(
            &mut tx,
            tenant_id,
            ENGINE_ID,
            &draft.signature_hash,
        )
        .await;
        draft.confidence = apply_fp_multiplier(draft.confidence, mult);
        let suppressed =
            fp_feedback::is_suppressed_by(&suppressions, &draft.signature_hash, &ev.target_url);
        if suppressed {
            draft.fp_routed = true;
        }
        let status = if suppressed {
            CandidateStatus::Suppressed
        } else {
            CandidateStatus::Candidate
        };
        let id = Uuid::new_v4().to_string();
        let rows = sqlx::query(INSERT_CANDIDATE_SQL)
            .bind(&id)
            .bind(tenant_id)
            .bind(client_id)
            .bind(run_id)
            .bind(status.as_str())
            .bind(&draft.title)
            .bind(&draft.technical_summary)
            .bind(&draft.impact)
            .bind(&draft.recommended_fix)
            .bind(&draft.anomaly_type)
            .bind(&draft.payload_class)
            .bind(&draft.signature_hash)
            .bind(draft.novelty_score)
            .bind(draft.confidence)
            .bind(draft.kev_listed)
            .bind(draft.epss_score)
            .bind(&draft.cve_id)
            .bind(draft.fp_routed)
            .bind(draft.llm_hypothesis)
            .bind(draft.oob_confirmed)
            .bind(&draft.target_url)
            .bind(&draft.evidence)
            .execute(&mut *tx)
            .await?;
        if rows.rows_affected() > 0 {
            inserted += 1;
        }
    }
    sqlx::query(
        "UPDATE discovery_lab_runs SET candidates_count = $2, updated_at = now() WHERE id = $1",
    )
    .bind(run_id)
    .bind(inserted)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(inserted)
}

#[derive(Debug, Clone)]
pub struct CreateRunInput {
    pub tenant_id: i64,
    pub client_id: i64,
    pub target_url: String,
    pub target_host: String,
    pub intensity: String,
    pub created_by_user_id: Option<i64>,
}

pub async fn insert_queued_run(
    pool: &PgPool,
    input: &CreateRunInput,
) -> Result<String, sqlx::Error> {
    let id = Uuid::new_v4().to_string();
    let mut tx = crate::db::begin_tenant_tx(pool, input.tenant_id).await?;
    sqlx::query(
        r#"INSERT INTO discovery_lab_runs (
                id, tenant_id, client_id, target_url, target_host, status, intensity, created_by_user_id
           ) VALUES ($1,$2,$3,$4,$5,'queued',$6,$7)"#,
    )
    .bind(&id)
    .bind(input.tenant_id)
    .bind(input.client_id)
    .bind(&input.target_url)
    .bind(&input.target_host)
    .bind(&input.intensity)
    .bind(input.created_by_user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn attach_job_id(
    pool: &PgPool,
    tenant_id: i64,
    run_id: &str,
    job_id: Uuid,
) -> Result<(), sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    sqlx::query("UPDATE discovery_lab_runs SET job_id = $2::uuid, updated_at = now() WHERE id = $1")
        .bind(run_id)
        .bind(job_id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn mark_run_failed(
    pool: &PgPool,
    tenant_id: i64,
    run_id: &str,
    err: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    sqlx::query(
        r#"UPDATE discovery_lab_runs
           SET status = 'failed', last_error = $2, completed_at = now(), updated_at = now()
           WHERE id = $1"#,
    )
    .bind(run_id)
    .bind(err)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Worker entry: probe authorized target, persist candidates, complete the run.
pub async fn execute_lab_job(pool: &PgPool, tenant_id: i64, payload: &Value) -> Result<Value, String> {
    let run_id = payload
        .get("run_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "payload.run_id required".to_string())?;
    let target = payload
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| "payload.target required".to_string())?;
    let host = payload
        .get("validated_scope")
        .and_then(|v| v.get("host"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let intensity = payload
        .get("intensity")
        .and_then(Value::as_str)
        .unwrap_or("normal");
    let client_id = payload
        .get("client_id")
        .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .ok_or_else(|| "payload.client_id required".to_string())?;

    {
        let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
            .await
            .map_err(|e| e.to_string())?;
        sqlx::query(
            r#"UPDATE discovery_lab_runs
               SET status = 'running', started_at = now(), updated_at = now()
               WHERE id = $1"#,
        )
        .bind(run_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
    }

    let report = match run_lab_probes(target, intensity, tenant_id, host).await {
        Ok(r) => r,
        Err(e) => {
            let _ = mark_run_failed(pool, tenant_id, run_id, &e).await;
            return Err(e);
        }
    };

    let persisted = match persist_candidates_from_probes(
        pool,
        tenant_id,
        client_id,
        run_id,
        host,
        &report.anomalies,
    )
    .await
    {
        Ok(n) => n,
        Err(e) => {
            let msg = format!("persist candidates: {e}");
            let _ = mark_run_failed(pool, tenant_id, run_id, &msg).await;
            return Err(msg);
        }
    };

    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query(
        r#"UPDATE discovery_lab_runs
           SET status = 'completed', probes_sent = $2, anomalies_seen = $3, llm_used = $4,
               candidates_count = $5, completed_at = now(), updated_at = now(), last_error = NULL
           WHERE id = $1"#,
    )
    .bind(run_id)
    .bind(report.probes_sent)
    .bind(report.anomalies.len() as i32)
    .bind(report.llm_used)
    .bind(persisted)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;

    Ok(json!({
        "ok": true,
        "kind": JOB_KIND,
        "run_id": run_id,
        "probes_sent": report.probes_sent,
        "anomalies": report.anomalies.len(),
        "candidates": persisted,
        "llm_used": report.llm_used,
    }))
}

fn row_run(r: &sqlx::postgres::PgRow) -> Value {
    let created: DateTime<Utc> = r.try_get("created_at").unwrap_or_else(|_| Utc::now());
    json!({
        "id": r.try_get::<String,_>("id").unwrap_or_default(),
        "client_id": r.try_get::<i64,_>("client_id").unwrap_or(0),
        "job_id": r.try_get::<Option<String>,_>("job_id").unwrap_or(None),
        "target_url": r.try_get::<String,_>("target_url").unwrap_or_default(),
        "target_host": r.try_get::<String,_>("target_host").unwrap_or_default(),
        "status": r.try_get::<String,_>("status").unwrap_or_default(),
        "intensity": r.try_get::<String,_>("intensity").unwrap_or_default(),
        "llm_used": r.try_get::<bool,_>("llm_used").unwrap_or(false),
        "probes_sent": r.try_get::<i32,_>("probes_sent").unwrap_or(0),
        "anomalies_seen": r.try_get::<i32,_>("anomalies_seen").unwrap_or(0),
        "candidates_count": r.try_get::<i32,_>("candidates_count").unwrap_or(0),
        "last_error": r.try_get::<Option<String>,_>("last_error").unwrap_or(None),
        "created_at": created.to_rfc3339(),
        "started_at": r.try_get::<Option<DateTime<Utc>>,_>("started_at").ok().flatten().map(|d| d.to_rfc3339()),
        "completed_at": r.try_get::<Option<DateTime<Utc>>,_>("completed_at").ok().flatten().map(|d| d.to_rfc3339()),
    })
}

fn row_candidate(r: &sqlx::postgres::PgRow) -> Value {
    let created: DateTime<Utc> = r.try_get("created_at").unwrap_or_else(|_| Utc::now());
    json!({
        "id": r.try_get::<String,_>("id").unwrap_or_default(),
        "run_id": r.try_get::<String,_>("run_id").unwrap_or_default(),
        "client_id": r.try_get::<i64,_>("client_id").unwrap_or(0),
        "status": r.try_get::<String,_>("status").unwrap_or_default(),
        "title": r.try_get::<String,_>("title").unwrap_or_default(),
        "technical_summary": r.try_get::<String,_>("technical_summary").unwrap_or_default(),
        "impact": r.try_get::<String,_>("impact").unwrap_or_default(),
        "recommended_fix": r.try_get::<String,_>("recommended_fix").unwrap_or_default(),
        "anomaly_type": r.try_get::<String,_>("anomaly_type").unwrap_or_default(),
        "payload_class": r.try_get::<String,_>("payload_class").unwrap_or_default(),
        "signature_hash": r.try_get::<String,_>("signature_hash").unwrap_or_default(),
        "novelty_score": r.try_get::<f64,_>("novelty_score").unwrap_or(0.0),
        "confidence": r.try_get::<f64,_>("confidence").unwrap_or(0.0),
        "kev_listed": r.try_get::<bool,_>("kev_listed").unwrap_or(false),
        "epss_score": r.try_get::<Option<f64>,_>("epss_score").unwrap_or(None),
        "cve_id": r.try_get::<Option<String>,_>("cve_id").unwrap_or(None),
        "fp_routed": r.try_get::<bool,_>("fp_routed").unwrap_or(false),
        "llm_hypothesis": r.try_get::<bool,_>("llm_hypothesis").unwrap_or(false),
        "oob_confirmed": r.try_get::<bool,_>("oob_confirmed").unwrap_or(false),
        "target_url": r.try_get::<String,_>("target_url").unwrap_or_default(),
        "evidence": r.try_get::<Value,_>("evidence").unwrap_or(json!({})),
        "created_at": created.to_rfc3339(),
        "updated_at": r.try_get::<DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
    })
}

pub async fn list_runs(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = if let Some(cid) = client_id {
        sqlx::query(
            r#"SELECT id, client_id, job_id::text AS job_id, target_url, target_host, status, intensity, llm_used,
                      probes_sent, anomalies_seen, candidates_count, last_error,
                      created_at, started_at, completed_at
               FROM discovery_lab_runs
               WHERE client_id = $1
               ORDER BY created_at DESC LIMIT $2"#,
        )
        .bind(cid)
        .bind(limit.clamp(1, 200))
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query(
            r#"SELECT id, client_id, job_id::text AS job_id, target_url, target_host, status, intensity, llm_used,
                      probes_sent, anomalies_seen, candidates_count, last_error,
                      created_at, started_at, completed_at
               FROM discovery_lab_runs
               ORDER BY created_at DESC LIMIT $1"#,
        )
        .bind(limit.clamp(1, 200))
        .fetch_all(&mut *tx)
        .await?
    };
    tx.commit().await?;
    Ok(rows.iter().map(row_run).collect())
}

pub async fn get_run(pool: &PgPool, tenant_id: i64, run_id: &str) -> Result<Option<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT id, client_id, job_id::text AS job_id, target_url, target_host, status, intensity, llm_used,
                  probes_sent, anomalies_seen, candidates_count, last_error,
                  created_at, started_at, completed_at
           FROM discovery_lab_runs WHERE id = $1"#,
    )
    .bind(run_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.as_ref().map(row_run))
}

pub async fn list_candidates(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    run_id: Option<&str>,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let mut qb = sqlx::QueryBuilder::new(
        r#"SELECT id, run_id, client_id, status, title, technical_summary, impact, recommended_fix,
                  anomaly_type, payload_class, signature_hash, novelty_score, confidence,
                  kev_listed, epss_score, cve_id, fp_routed, llm_hypothesis, oob_confirmed,
                  target_url, evidence, created_at, updated_at
           FROM discovery_lab_candidates WHERE 1=1"#,
    );
    if let Some(cid) = client_id {
        qb.push(" AND client_id = ").push_bind(cid);
    }
    if let Some(rid) = run_id {
        qb.push(" AND run_id = ").push_bind(rid);
    }
    if let Some(st) = status.and_then(CandidateStatus::parse) {
        qb.push(" AND status = ").push_bind(st.as_str());
    }
    qb.push(" ORDER BY novelty_score DESC, created_at DESC LIMIT ");
    qb.push_bind(limit.clamp(1, 500));
    let rows = qb.build().fetch_all(&mut *tx).await?;
    tx.commit().await?;
    Ok(rows.iter().map(row_candidate).collect())
}

pub async fn get_candidate(
    pool: &PgPool,
    tenant_id: i64,
    id: &str,
) -> Result<Option<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT id, run_id, client_id, status, title, technical_summary, impact, recommended_fix,
                  anomaly_type, payload_class, signature_hash, novelty_score, confidence,
                  kev_listed, epss_score, cve_id, fp_routed, llm_hypothesis, oob_confirmed,
                  target_url, evidence, created_at, updated_at
           FROM discovery_lab_candidates WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.as_ref().map(row_candidate))
}

pub async fn apply_candidate_action(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    candidate_id: &str,
    action: CandidateAction,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT id, status, signature_hash, target_url
           FROM discovery_lab_candidates WHERE id = $1 FOR UPDATE"#,
    )
    .bind(candidate_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "candidate not found".to_string())?;
    let current = CandidateStatus::parse(&row.try_get::<String, _>("status").unwrap_or_default())
        .ok_or_else(|| "invalid candidate status".to_string())?;
    let next = transition(current, action)?;
    let sig: String = row.try_get("signature_hash").unwrap_or_default();
    let target: String = row.try_get("target_url").unwrap_or_default();
    sqlx::query(
        "UPDATE discovery_lab_candidates SET status = $2, updated_at = now() WHERE id = $1",
    )
    .bind(candidate_id)
    .bind(next.as_str())
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    match action {
        CandidateAction::Suppress => {
            let _ = fp_feedback::record_fp(&mut tx, tenant_id, ENGINE_ID, &sig, Some(&target), Some(user_id))
                .await;
        }
        CandidateAction::Validate
        | CandidateAction::Remediation
        | CandidateAction::DisclosureReady => {
            let _ = fp_feedback::record_tp(&mut tx, tenant_id, ENGINE_ID, &sig).await;
        }
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    get_candidate(pool, tenant_id, candidate_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "candidate missing after update".into())
}

#[derive(Debug, Clone)]
pub struct DisclosureFields {
    pub title: String,
    pub technical_summary: String,
    pub impact: String,
    pub reproduction: String,
    pub recommended_fix: String,
    pub timeline: String,
    pub recipient: String,
    pub recipient_kind: String,
    pub redact_payloads: bool,
    pub redact_internal_hosts: bool,
    pub redact_customer_ids: bool,
}

impl DisclosureFields {
    pub fn normalize_kind(raw: &str) -> &'static str {
        match raw.trim().to_ascii_lowercase().as_str() {
            "government_cyber" | "gov" | "gov_cyber" => "government_cyber",
            "vendor" => "vendor",
            "coordinator" => "coordinator",
            "other" => "other",
            _ => "national_cert",
        }
    }
}

#[must_use]
pub fn redact_text(input: &str, fields: &DisclosureFields, customer_tokens: &[&str]) -> String {
    let mut s = input.to_string();
    if fields.redact_payloads {
        for needle in ["payload", "weissman_lab=", XSS_REFLECTION_TOKEN] {
            if s.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()) {
                s = "[redacted: payload/reproduction detail]".to_string();
                break;
            }
        }
    }
    if fields.redact_internal_hosts {
        for host in ["127.0.0.1", "localhost", "10.", "192.168.", "169.254.169.254"] {
            if s.contains(host) {
                s = s.replace(host, "[redacted-internal]");
            }
        }
    }
    if fields.redact_customer_ids {
        for tok in customer_tokens {
            if !tok.is_empty() {
                s = s.replace(tok, "[redacted-customer]");
            }
        }
    }
    s
}

#[must_use]
pub fn render_disclosure_markdown(pack: &Value, fields: &DisclosureFields, customer_tokens: &[&str]) -> String {
    let t = |k: &str| {
        pack.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let title = redact_text(&t("title"), fields, customer_tokens);
    let summary = redact_text(&t("technical_summary"), fields, customer_tokens);
    let impact = redact_text(&t("impact"), fields, customer_tokens);
    let repro = redact_text(&t("reproduction"), fields, customer_tokens);
    let fix = redact_text(&t("recommended_fix"), fields, customer_tokens);
    let timeline = redact_text(&t("timeline"), fields, customer_tokens);
    let recipient = t("recipient");
    format!(
        "# Weissman Responsible Disclosure\n\n\
         **Title:** {title}\n\n\
         **Recipient:** {recipient} ({})\n\n\
         **Status:** {}\n\n\
         ## Technical summary\n\n{summary}\n\n\
         ## Impact\n\n{impact}\n\n\
         ## Reproduction (authorized scope only)\n\n{repro}\n\n\
         ## Recommended fix\n\n{fix}\n\n\
         ## Timeline\n\n{timeline}\n\n\
         ---\n\
         Generated by Weissman Discovery Lab. This draft is for coordinated disclosure \
         to the named CERT / government cyber unit. Reproduction steps apply only to \
         assets the customer authorized for assessment.\n",
        t("recipient_kind"),
        t("status")
    )
}

fn pdf_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('(', "\\(").replace(')', "\\)")
}

fn wrap_lines(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for para in s.split('\n') {
        let mut cur = String::new();
        for word in para.split_whitespace() {
            if cur.len() + word.len() + 1 > width {
                if !cur.is_empty() {
                    lines.push(cur);
                    cur = String::new();
                }
            }
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[must_use]
pub fn render_disclosure_pdf(markdown: &str) -> Vec<u8> {
    let lines = wrap_lines(markdown, 90);
    let mut content = String::from("BT /F1 11 Tf 50 740 Td\n");
    let mut y_lines = 0;
    for line in lines.iter().take(48) {
        content.push_str(&format!("({}) Tj\n0 -14 Td\n", pdf_escape(line)));
        y_lines += 1;
    }
    content.push_str("ET\n");
    let stream = content.into_bytes();
    let _ = y_lines;
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".to_string(),
        format!("<< /Length {} >>\nstream\n{}\nendstream", stream.len(), String::from_utf8_lossy(&stream)),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    let mut pdf = String::from("%PDF-1.4\n");
    let mut offsets = vec![0usize];
    for (i, obj) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.push_str(&format!("{} 0 obj\n{}\nendobj\n", i + 1, obj));
    }
    let xref_at = pdf.len();
    pdf.push_str(&format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1));
    for off in offsets.iter().skip(1) {
        pdf.push_str(&format!("{off:010} 00000 n \n"));
    }
    pdf.push_str(&format!(
        "trailer << /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n",
        objects.len() + 1
    ));
    pdf.into_bytes()
}

fn pack_from_row(r: &sqlx::postgres::PgRow) -> Value {
    json!({
        "id": r.try_get::<String,_>("id").unwrap_or_default(),
        "candidate_id": r.try_get::<String,_>("candidate_id").unwrap_or_default(),
        "client_id": r.try_get::<i64,_>("client_id").unwrap_or(0),
        "status": r.try_get::<String,_>("status").unwrap_or_default(),
        "title": r.try_get::<String,_>("title").unwrap_or_default(),
        "technical_summary": r.try_get::<String,_>("technical_summary").unwrap_or_default(),
        "impact": r.try_get::<String,_>("impact").unwrap_or_default(),
        "reproduction": r.try_get::<String,_>("reproduction").unwrap_or_default(),
        "recommended_fix": r.try_get::<String,_>("recommended_fix").unwrap_or_default(),
        "timeline": r.try_get::<String,_>("timeline").unwrap_or_default(),
        "recipient": r.try_get::<String,_>("recipient").unwrap_or_default(),
        "recipient_kind": r.try_get::<String,_>("recipient_kind").unwrap_or_default(),
        "redact_payloads": r.try_get::<bool,_>("redact_payloads").unwrap_or(true),
        "redact_internal_hosts": r.try_get::<bool,_>("redact_internal_hosts").unwrap_or(true),
        "redact_customer_ids": r.try_get::<bool,_>("redact_customer_ids").unwrap_or(true),
        "created_at": r.try_get::<DateTime<Utc>,_>("created_at").ok().map(|d| d.to_rfc3339()),
        "updated_at": r.try_get::<DateTime<Utc>,_>("updated_at").ok().map(|d| d.to_rfc3339()),
    })
}

async fn append_disclosure_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: i64,
    client_id: i64,
    pack_id: &str,
    actor_user_id: Option<i64>,
    from_status: Option<&str>,
    to_status: &str,
    action: &str,
    detail: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO discovery_disclosure_events (
                id, tenant_id, client_id, pack_id, actor_user_id, from_status, to_status, action, detail
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(tenant_id)
    .bind(client_id)
    .bind(pack_id)
    .bind(actor_user_id)
    .bind(from_status)
    .bind(to_status)
    .bind(action)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn create_disclosure_pack(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    candidate_id: &str,
    fields: DisclosureFields,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let cand = sqlx::query(
        r#"SELECT id, client_id, status, title, technical_summary, impact, recommended_fix,
                  target_url, evidence
           FROM discovery_lab_candidates WHERE id = $1 FOR UPDATE"#,
    )
    .bind(candidate_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "candidate not found".to_string())?;
    let st = cand.try_get::<String, _>("status").unwrap_or_default();
    let parsed = CandidateStatus::parse(&st).ok_or_else(|| "invalid candidate status".to_string())?;
    if matches!(parsed, CandidateStatus::Suppressed | CandidateStatus::Candidate) {
        return Err("candidate must be validated before opening a disclosure pack".into());
    }
    let client_id: i64 = cand.try_get("client_id").unwrap_or(0);
    let title = if fields.title.trim().is_empty() {
        cand.try_get::<String, _>("title").unwrap_or_else(|_| "Novel finding".into())
    } else {
        fields.title.clone()
    };
    let summary = if fields.technical_summary.trim().is_empty() {
        cand.try_get::<String, _>("technical_summary").unwrap_or_default()
    } else {
        fields.technical_summary.clone()
    };
    let impact = if fields.impact.trim().is_empty() {
        cand.try_get::<String, _>("impact").unwrap_or_default()
    } else {
        fields.impact.clone()
    };
    let fix = if fields.recommended_fix.trim().is_empty() {
        cand.try_get::<String, _>("recommended_fix").unwrap_or_default()
    } else {
        fields.recommended_fix.clone()
    };
    let target: String = cand.try_get("target_url").unwrap_or_default();
    let reproduction = if fields.reproduction.trim().is_empty() {
        format!(
            "Authorized-scope reproduction against {target}. Payload details are omitted unless redaction is disabled by the analyst."
        )
    } else {
        fields.reproduction.clone()
    };
    let kind = DisclosureFields::normalize_kind(&fields.recipient_kind);
    let pack_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO discovery_disclosure_packs (
                id, tenant_id, client_id, candidate_id, status, title, technical_summary, impact,
                reproduction, recommended_fix, timeline, recipient, recipient_kind,
                redact_payloads, redact_internal_hosts, redact_customer_ids, created_by_user_id
           ) VALUES ($1,$2,$3,$4,'draft',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)"#,
    )
    .bind(&pack_id)
    .bind(tenant_id)
    .bind(client_id)
    .bind(candidate_id)
    .bind(&title)
    .bind(&summary)
    .bind(&impact)
    .bind(&reproduction)
    .bind(&fix)
    .bind(&fields.timeline)
    .bind(&fields.recipient)
    .bind(kind)
    .bind(fields.redact_payloads)
    .bind(fields.redact_internal_hosts)
    .bind(fields.redact_customer_ids)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    append_disclosure_event(
        &mut tx,
        tenant_id,
        client_id,
        &pack_id,
        Some(user_id),
        None,
        "draft",
        "created",
        "disclosure pack opened from Discovery Lab candidate",
    )
    .await
    .map_err(|e| e.to_string())?;
    if parsed != CandidateStatus::DisclosureReady && parsed != CandidateStatus::Disclosed {
        sqlx::query(
            "UPDATE discovery_lab_candidates SET status = 'disclosure_ready', updated_at = now() WHERE id = $1",
        )
        .bind(candidate_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    get_disclosure(pool, tenant_id, &pack_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "pack missing after insert".into())
}

pub async fn get_disclosure(
    pool: &PgPool,
    tenant_id: i64,
    id: &str,
) -> Result<Option<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT id, candidate_id, client_id, status, title, technical_summary, impact, reproduction,
                  recommended_fix, timeline, recipient, recipient_kind, redact_payloads,
                  redact_internal_hosts, redact_customer_ids, created_at, updated_at
           FROM discovery_disclosure_packs WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.as_ref().map(pack_from_row))
}

pub async fn list_disclosures(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    limit: i64,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = if let Some(cid) = client_id {
        sqlx::query(
            r#"SELECT id, candidate_id, client_id, status, title, technical_summary, impact, reproduction,
                      recommended_fix, timeline, recipient, recipient_kind, redact_payloads,
                      redact_internal_hosts, redact_customer_ids, created_at, updated_at
               FROM discovery_disclosure_packs WHERE client_id = $1
               ORDER BY created_at DESC LIMIT $2"#,
        )
        .bind(cid)
        .bind(limit.clamp(1, 200))
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query(
            r#"SELECT id, candidate_id, client_id, status, title, technical_summary, impact, reproduction,
                      recommended_fix, timeline, recipient, recipient_kind, redact_payloads,
                      redact_internal_hosts, redact_customer_ids, created_at, updated_at
               FROM discovery_disclosure_packs
               ORDER BY created_at DESC LIMIT $1"#,
        )
        .bind(limit.clamp(1, 200))
        .fetch_all(&mut *tx)
        .await?
    };
    tx.commit().await?;
    Ok(rows.iter().map(pack_from_row).collect())
}

pub fn parse_disclosure_status(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "draft" => Some("draft"),
        "ready" => Some("ready"),
        "submitted" => Some("submitted"),
        "disclosed" => Some("disclosed"),
        "withdrawn" => Some("withdrawn"),
        _ => None,
    }
}

pub fn disclosure_transition_ok(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("draft", "ready")
            | ("draft", "withdrawn")
            | ("ready", "submitted")
            | ("ready", "withdrawn")
            | ("submitted", "disclosed")
            | ("submitted", "withdrawn")
            | ("ready", "draft")
    )
}

pub async fn update_disclosure(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    pack_id: &str,
    fields: Option<DisclosureFields>,
    new_status: Option<&str>,
) -> Result<Value, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| e.to_string())?;
    let row = sqlx::query(
        r#"SELECT id, client_id, candidate_id, status, title, technical_summary, impact, reproduction,
                  recommended_fix, timeline, recipient, recipient_kind, redact_payloads,
                  redact_internal_hosts, redact_customer_ids
           FROM discovery_disclosure_packs WHERE id = $1 FOR UPDATE"#,
    )
    .bind(pack_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "disclosure pack not found".to_string())?;
    let current: String = row.try_get("status").unwrap_or_default();
    let client_id: i64 = row.try_get("client_id").unwrap_or(0);
    let candidate_id: String = row.try_get("candidate_id").unwrap_or_default();
    if let Some(f) = fields.as_ref() {
        let kind = DisclosureFields::normalize_kind(&f.recipient_kind);
        sqlx::query(
            r#"UPDATE discovery_disclosure_packs SET
                    title = $2, technical_summary = $3, impact = $4, reproduction = $5,
                    recommended_fix = $6, timeline = $7, recipient = $8, recipient_kind = $9,
                    redact_payloads = $10, redact_internal_hosts = $11, redact_customer_ids = $12,
                    updated_at = now()
               WHERE id = $1"#,
        )
        .bind(pack_id)
        .bind(&f.title)
        .bind(&f.technical_summary)
        .bind(&f.impact)
        .bind(&f.reproduction)
        .bind(&f.recommended_fix)
        .bind(&f.timeline)
        .bind(&f.recipient)
        .bind(kind)
        .bind(f.redact_payloads)
        .bind(f.redact_internal_hosts)
        .bind(f.redact_customer_ids)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        append_disclosure_event(
            &mut tx,
            tenant_id,
            client_id,
            pack_id,
            Some(user_id),
            Some(current.as_str()),
            current.as_str(),
            "updated",
            "disclosure pack fields updated",
        )
        .await
        .map_err(|e| e.to_string())?;
    }
    if let Some(ns) = new_status {
        let to = parse_disclosure_status(ns).ok_or_else(|| "invalid disclosure status".to_string())?;
        if !disclosure_transition_ok(&current, to) {
            return Err(format!("illegal disclosure transition: {current} → {to}"));
        }
        sqlx::query(
            "UPDATE discovery_disclosure_packs SET status = $2, updated_at = now() WHERE id = $1",
        )
        .bind(pack_id)
        .bind(to)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        append_disclosure_event(
            &mut tx,
            tenant_id,
            client_id,
            pack_id,
            Some(user_id),
            Some(current.as_str()),
            to,
            "status",
            &format!("status {current} → {to}"),
        )
        .await
        .map_err(|e| e.to_string())?;
        if to == "disclosed" {
            sqlx::query(
                "UPDATE discovery_lab_candidates SET status = 'disclosed', updated_at = now() WHERE id = $1",
            )
            .bind(&candidate_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        }
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    get_disclosure(pool, tenant_id, pack_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "pack missing after update".into())
}

pub async fn list_disclosure_events(
    pool: &PgPool,
    tenant_id: i64,
    pack_id: &str,
) -> Result<Vec<Value>, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let rows = sqlx::query(
        r#"SELECT id, actor_user_id, from_status, to_status, action, detail, occurred_at
           FROM discovery_disclosure_events
           WHERE pack_id = $1
           ORDER BY occurred_at ASC"#,
    )
    .bind(pack_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.try_get::<String,_>("id").unwrap_or_default(),
                "actor_user_id": r.try_get::<Option<i64>,_>("actor_user_id").unwrap_or(None),
                "from_status": r.try_get::<Option<String>,_>("from_status").unwrap_or(None),
                "to_status": r.try_get::<String,_>("to_status").unwrap_or_default(),
                "action": r.try_get::<String,_>("action").unwrap_or_default(),
                "detail": r.try_get::<String,_>("detail").unwrap_or_default(),
                "occurred_at": r.try_get::<DateTime<Utc>,_>("occurred_at").ok().map(|d| d.to_rfc3339()),
            })
        })
        .collect())
}

pub async fn export_disclosure(
    pool: &PgPool,
    tenant_id: i64,
    pack_id: &str,
    format: &str,
    customer_tokens: &[&str],
) -> Result<(String, String, Vec<u8>), String> {
    let pack = get_disclosure(pool, tenant_id, pack_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "disclosure pack not found".to_string())?;
    let fields = DisclosureFields {
        title: pack.get("title").and_then(Value::as_str).unwrap_or("").into(),
        technical_summary: pack
            .get("technical_summary")
            .and_then(Value::as_str)
            .unwrap_or("")
            .into(),
        impact: pack.get("impact").and_then(Value::as_str).unwrap_or("").into(),
        reproduction: pack
            .get("reproduction")
            .and_then(Value::as_str)
            .unwrap_or("")
            .into(),
        recommended_fix: pack
            .get("recommended_fix")
            .and_then(Value::as_str)
            .unwrap_or("")
            .into(),
        timeline: pack.get("timeline").and_then(Value::as_str).unwrap_or("").into(),
        recipient: pack.get("recipient").and_then(Value::as_str).unwrap_or("").into(),
        recipient_kind: pack
            .get("recipient_kind")
            .and_then(Value::as_str)
            .unwrap_or("national_cert")
            .into(),
        redact_payloads: pack
            .get("redact_payloads")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        redact_internal_hosts: pack
            .get("redact_internal_hosts")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        redact_customer_ids: pack
            .get("redact_customer_ids")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    };
    let md = render_disclosure_markdown(&pack, &fields, customer_tokens);
    match format {
        "pdf" => Ok((
            format!("weissman-disclosure-{pack_id}.pdf"),
            "application/pdf".into(),
            render_disclosure_pdf(&md),
        )),
        "json" => {
            let mut redacted = pack.clone();
            if let Some(obj) = redacted.as_object_mut() {
                obj.insert(
                    "technical_summary".into(),
                    json!(redact_text(&fields.technical_summary, &fields, customer_tokens)),
                );
                obj.insert(
                    "reproduction".into(),
                    json!(redact_text(&fields.reproduction, &fields, customer_tokens)),
                );
                obj.insert("markdown".into(), json!(md));
            }
            let bytes = serde_json::to_vec_pretty(&redacted).map_err(|e| e.to_string())?;
            Ok((
                format!("weissman-disclosure-{pack_id}.json"),
                "application/json".into(),
                bytes,
            ))
        }
        _ => Ok((
            format!("weissman-disclosure-{pack_id}.md"),
            "text/markdown; charset=utf-8".into(),
            md.into_bytes(),
        )),
    }
}

pub fn normalize_target_url(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("target required".into());
    }
    if t.starts_with("http://") || t.starts_with("https://") {
        Ok(t.to_string())
    } else {
        Ok(format!("https://{t}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(payload: &str, kind: AnomalyKind, llm: bool) -> ProbeEvidence {
        ProbeEvidence {
            target_url: "https://app.example.test/?weissman_lab=x".into(),
            payload: payload.into(),
            anomaly_type: kind.as_str().into(),
            anomaly_kind: kind,
            baseline_vs_anomaly: "status 500 vs 200".into(),
            status: 500,
            llm_hypothesis: llm,
            llm_rationale: None,
            oob_confirmed: false,
            response_excerpt: "syntax error at or near".into(),
        }
    }

    #[test]
    fn lifecycle_happy_path() {
        let mut s = CandidateStatus::Candidate;
        s = transition(s, CandidateAction::Validate).unwrap();
        s = transition(s, CandidateAction::Remediation).unwrap();
        s = transition(s, CandidateAction::DisclosureReady).unwrap();
        assert_eq!(s, CandidateStatus::DisclosureReady);
    }

    #[test]
    fn validated_may_skip_to_disclosure_ready() {
        let s = transition(CandidateStatus::Candidate, CandidateAction::Validate).unwrap();
        let s = transition(s, CandidateAction::DisclosureReady).unwrap();
        assert_eq!(s, CandidateStatus::DisclosureReady);
    }

    #[test]
    fn cannot_disclose_from_candidate_directly() {
        assert!(transition(CandidateStatus::Candidate, CandidateAction::DisclosureReady).is_err());
        assert!(transition(CandidateStatus::Suppressed, CandidateAction::Validate).is_err());
    }

    #[test]
    fn fp_from_candidate_and_validated() {
        assert_eq!(
            transition(CandidateStatus::Candidate, CandidateAction::Suppress).unwrap(),
            CandidateStatus::Suppressed
        );
        let v = transition(CandidateStatus::Candidate, CandidateAction::Validate).unwrap();
        assert_eq!(
            transition(v, CandidateAction::Suppress).unwrap(),
            CandidateStatus::Suppressed
        );
    }

    #[test]
    fn classify_known_vs_novel() {
        assert_eq!(classify_payload("' OR '1'='1"), PayloadClass::Sqli);
        assert_eq!(
            classify_payload(&format!("<svg onload=alert('{XSS_REFLECTION_TOKEN}')>")),
            PayloadClass::Xss
        );
        assert_eq!(classify_payload("{{7*7}}"), PayloadClass::Ssti);
        assert_eq!(classify_payload("chunked-json-key-reorder-weissman-lab"), PayloadClass::Novel);
    }

    #[test]
    fn novelty_drops_for_kev_and_known_signatures() {
        let known = score_finding(NoveltyInputs {
            payload: "' OR '1'='1",
            anomaly_kind: AnomalyKind::SqliBody,
            llm_hypothesis: false,
            oob_confirmed: false,
            kev_listed: true,
            epss_score: Some(0.97),
            has_cve: true,
        });
        assert!(known.novelty_score < 0.15);
        assert_eq!(known.known_intel, "kev");

        let novel = score_finding(NoveltyInputs {
            payload: "chunked-json-key-reorder-weissman-lab",
            anomaly_kind: AnomalyKind::Crash500,
            llm_hypothesis: true,
            oob_confirmed: true,
            kev_listed: false,
            epss_score: None,
            has_cve: false,
        });
        assert!(novel.novelty_score > 0.8);
        assert!(novel.confidence >= 0.90);
        assert_eq!(novel.payload_class, PayloadClass::Novel);
    }

    #[test]
    fn noisy_timing_is_fp_routed() {
        let s = score_finding(NoveltyInputs {
            payload: "AAAA",
            anomaly_kind: AnomalyKind::Timing,
            llm_hypothesis: false,
            oob_confirmed: false,
            kev_listed: false,
            epss_score: None,
            has_cve: false,
        });
        assert!(s.fp_routed);
        assert!(s.confidence < 0.4);
    }

    #[test]
    fn fp_multiplier_clamps() {
        assert!((apply_fp_multiplier(0.8, 0.25) - 0.20).abs() < 0.001);
        assert_eq!(apply_fp_multiplier(0.8, 0.0), 0.10);
    }

    #[test]
    fn draft_requires_probe_evidence() {
        let d = draft_from_probe(&probe("' OR 1=1--", AnomalyKind::SqliBody, false), "app.example.test", false, None, None, 1.0);
        assert!(d.signature_hash.len() == 64);
        assert_eq!(d.payload_class, "sqli");
        assert_eq!(d.evidence["authorized_scope_only"], true);
    }

    #[test]
    fn hypothesis_json_filters_foreign_hosts() {
        let raw = r#"{"hypotheses":[
            {"payload":"nested%00json","vector":"parser","rationale":"local"},
            {"payload":"https://evil.example/steal","vector":"ssrf","rationale":"no"}
        ]}"#;
        let v = parse_hypotheses(raw, "app.example.test");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "nested%00json");
    }

    #[test]
    fn disclosure_transitions() {
        assert!(disclosure_transition_ok("draft", "ready"));
        assert!(disclosure_transition_ok("ready", "submitted"));
        assert!(disclosure_transition_ok("submitted", "disclosed"));
        assert!(!disclosure_transition_ok("draft", "disclosed"));
        assert!(!disclosure_transition_ok("disclosed", "draft"));
    }

    #[test]
    fn markdown_and_pdf_redact_payloads() {
        let fields = DisclosureFields {
            title: "Novel crash".into(),
            technical_summary: "crash".into(),
            impact: "DoS".into(),
            reproduction: "GET /?weissman_lab=' OR 1=1".into(),
            recommended_fix: "fix".into(),
            timeline: "T0 report".into(),
            recipient: "CERT-IL".into(),
            recipient_kind: "national_cert".into(),
            redact_payloads: true,
            redact_internal_hosts: true,
            redact_customer_ids: true,
        };
        let pack = json!({
            "title": fields.title,
            "technical_summary": fields.technical_summary,
            "impact": fields.impact,
            "reproduction": fields.reproduction,
            "recommended_fix": fields.recommended_fix,
            "timeline": fields.timeline,
            "recipient": fields.recipient,
            "recipient_kind": fields.recipient_kind,
            "status": "draft",
        });
        let md = render_disclosure_markdown(&pack, &fields, &["acme"]);
        assert!(md.contains("Weissman Responsible Disclosure"));
        assert!(md.contains("[redacted: payload/reproduction detail]"));
        let pdf = render_disclosure_pdf(&md);
        assert!(pdf.starts_with(b"%PDF"));
        assert!(pdf.windows(5).any(|w| w == b"%%EOF"));
    }

    #[test]
    fn recipient_kind_aliases() {
        assert_eq!(DisclosureFields::normalize_kind("gov_cyber"), "government_cyber");
        assert_eq!(DisclosureFields::normalize_kind("national_cert"), "national_cert");
        assert_eq!(DisclosureFields::normalize_kind("vendor"), "vendor");
    }
}

