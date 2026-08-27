//! Compile-time enforced evidence gate for vulnerability persistence.
//!
//! **Single source of truth:** only [`findings_persist`] may write new rows to
//! `vulnerabilities`. Every write must pass through [`PersistableFinding`], which
//! requires [`VerifiedEvidence`] — a type that cannot be constructed without
//! passing validation inside this module.
//!
//! Engines and orchestration code produce raw `serde_json::Value` findings.
//! They **must** call [`gate_finding`] / [`gate_findings`] before any persistence
//! path accepts them. The DB writer trait [`VulnerabilitiesWriter`] accepts
//! **only** [`PersistableFinding`], never raw JSON.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// ── Evidence seal (compile-time capability) ─────────────────────────────────

/// Private capability token — only constructible inside this module after validation.
#[derive(Debug, Clone, Copy)]
struct EvidenceSeal;

/// Evidence that passed the gate. Cannot be forged from outside this module.
#[derive(Debug, Clone)]
pub struct VerifiedEvidence {
    proof: String,
    engine_id: String,
    timestamp: String,
    _seal: EvidenceSeal,
}

impl VerifiedEvidence {
    pub fn proof(&self) -> &str {
        &self.proof
    }

    pub fn engine_id(&self) -> &str {
        &self.engine_id
    }

    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }
}

// ── Gated finding (only persistence-eligible type) ────────────────────────────

/// A finding cleared for DB persistence. **No public constructor** — obtain via
/// [`gate_finding`] or [`gate_findings`].
#[derive(Debug, Clone)]
pub struct PersistableFinding {
    engine: String,
    target_url: String,
    normalized: Value,
    evidence: VerifiedEvidence,
    dedup_hash: String,
    finding_id: String,
    severity: String,
}

impl PersistableFinding {
    pub fn engine(&self) -> &str {
        &self.engine
    }

    pub fn target_url(&self) -> &str {
        &self.target_url
    }

    pub fn json(&self) -> &Value {
        &self.normalized
    }

    pub fn evidence(&self) -> &VerifiedEvidence {
        &self.evidence
    }

    pub fn dedup_hash(&self) -> &str {
        &self.dedup_hash
    }

    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }

    pub fn severity(&self) -> &str {
        &self.severity
    }
}

// ── Sealed writer trait (only findings_persist implements) ──────────────────

mod sealed {
    pub trait Sealed {}
}
pub(crate) use sealed::Sealed;

/// DB write surface — accepts **only** [`PersistableFinding`].
pub trait VulnerabilitiesWriter: Sealed {
    /// Pre-flight validation before SQL (defense in depth).
    fn assert_gated(finding: &PersistableFinding) {
        debug_assert!(!finding.finding_id().is_empty());
        debug_assert!(!finding.evidence().proof().is_empty());
    }
}

// ── Cryptographic dedup signature ───────────────────────────────────────────

/// Stable hash over **normalised Target + Vuln_Type + Payload + Engine**.
/// Used as a secondary identity; the primary `finding_id` is
/// [`crate::finding_identity::build_stable_finding_id`].
pub fn build_dedup_hash(target: &str, vuln_type: &str, payload: &str, engine: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(crate::finding_identity::normalize_target(target).as_bytes());
    hasher.update(b"|");
    hasher.update(crate::finding_identity::normalize_signature(vuln_type).as_bytes());
    hasher.update(b"|");
    hasher.update(payload.as_bytes());
    hasher.update(b"|");
    hasher.update(engine.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn extract_vuln_type(f: &Value) -> String {
    crate::finding_identity::derive_vuln_signature(f, "finding")
}

fn extract_payload(f: &Value) -> String {
    for k in [
        "payload",
        "probe_payload",
        "injected_payload",
        "fuzz_payload",
        "poc",
        "poc_text",
        "proof_of_concept",
    ] {
        if let Some(s) = f.get(k).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    if let Some(p) = f
        .get("evidence")
        .and_then(|e| e.get("proof"))
        .and_then(Value::as_str)
    {
        let t = p.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    String::new()
}

fn extract_target(f: &Value, fallback: &str) -> String {
    for key in [
        "target",
        "url",
        "affected_url",
        "target_url",
        "asset_url",
        "host",
    ] {
        if let Some(s) = f.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    fallback.to_string()
}

fn normalize_severity(raw: Option<&str>) -> String {
    let s = raw.unwrap_or("info").trim().to_ascii_lowercase();
    match s.as_str() {
        "critical" | "high" | "medium" | "low" | "info" => s,
        "informational" | "informational " => "info".into(),
        "warning" | "warn" => "medium".into(),
        "error" | "severe" => "high".into(),
        "" => "info".into(),
        _ => "info".into(),
    }
}

fn extract_title(f: &Value, engine: &str) -> String {
    let candidates = [
        "title", "name", "summary", "rule", "finding", "issue", "asset", "type",
    ];
    for key in candidates {
        if let Some(s) = f.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.chars().take(240).collect();
            }
        }
    }
    format!("{} finding", engine)
}

fn extract_description(f: &Value) -> String {
    for key in [
        "description",
        "details",
        "detail",
        "evidence",
        "message",
        "summary",
    ] {
        if let Some(s) = f.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    String::new()
}

/// Validate raw engine JSON, normalize evidence fields, and produce a gated finding.
/// Returns `None` when actionable severities lack proof (evidence gate).
pub fn gate_finding(engine: &str, target: &str, mut raw: Value) -> Option<PersistableFinding> {
    let now = chrono::Utc::now().to_rfc3339();
    let severity = normalize_severity(raw.get("severity").and_then(Value::as_str));

    if let Some(obj) = raw.as_object_mut() {
        obj.entry("engine_id")
            .or_insert_with(|| Value::String(engine.to_string()));
        obj.entry("discovered_at")
            .or_insert_with(|| Value::String(now.clone()));
    }

    let evidence_proof = raw
        .get("evidence")
        .and_then(|e| e.get("proof"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let effective_proof = evidence_proof.or_else(|| {
        for k in [
            "proof",
            "poc",
            "poc_text",
            "proof_of_concept",
            "poc_exploit",
        ] {
            if let Some(s) = raw.get(k).and_then(Value::as_str) {
                let t = s.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
        // Asset-discovery engines (OSINT, ASM, …) emit `value` without a prose description.
        if let Some(v) = raw.get("value").and_then(Value::as_str) {
            let t = v.trim();
            if !t.is_empty() {
                let src = raw.get("source").and_then(Value::as_str).unwrap_or("probe");
                return Some(format!("live {src} observation: {t}"));
            }
        }
        let d = extract_description(&raw);
        if d.is_empty() {
            None
        } else {
            Some(d)
        }
    });

    let proof = match severity.as_str() {
        "critical" | "high" | "medium" => effective_proof.filter(|p| !p.is_empty())?,
        _ => effective_proof.unwrap_or_else(|| {
            extract_title(&raw, engine)
                .chars()
                .take(120)
                .collect::<String>()
        }),
    };

    if let Some(obj) = raw.as_object_mut() {
        let evidence = obj.entry("evidence").or_insert_with(|| json!({}));
        if let Some(ev) = evidence.as_object_mut() {
            ev.entry("engine_id")
                .or_insert_with(|| Value::String(engine.to_string()));
            ev.entry("timestamp")
                .or_insert_with(|| Value::String(now.clone()));
            ev.entry("proof")
                .or_insert_with(|| Value::String(proof.clone()));
        }
    }

    let target_url = crate::finding_identity::normalize_target(&extract_target(&raw, target));
    let vuln_type = extract_vuln_type(&raw);
    let payload = extract_payload(&raw);
    let dedup_hash = build_dedup_hash(&target_url, &vuln_type, &payload, engine);
    // Primary dedup key: cryptographic hash (target + vuln_type + payload + engine).
    let short_hash: String = dedup_hash.chars().take(24).collect();
    let hash_id = format!("{}-{}", engine, short_hash);
    // Legacy ID (CVE/MITRE/signature) for continuity with pre-migration rows.
    let legacy_id = build_legacy_finding_id(engine, &target_url, &raw);
    let finding_id = if legacy_id != hash_id {
        // Prefer legacy when it encodes richer invariant data; fall back to hash_id.
        legacy_id
    } else {
        hash_id
    };

    let evidence = VerifiedEvidence {
        proof,
        engine_id: engine.to_string(),
        timestamp: now,
        _seal: EvidenceSeal,
    };

    Some(PersistableFinding {
        engine: engine.to_string(),
        target_url,
        normalized: raw,
        evidence,
        dedup_hash,
        finding_id,
        severity,
    })
}

/// Gate a batch of raw findings; skips entries that fail the evidence gate.
pub fn gate_findings(engine: &str, target: &str, findings: &[Value]) -> Vec<PersistableFinding> {
    findings
        .iter()
        .cloned()
        .filter_map(|f| gate_finding(engine, target, f))
        .collect()
}

/// Stable finding_id (CVE/MITRE/signature) for cross-scan dedup continuity.
/// Delegates to [`crate::finding_identity::build_stable_finding_id`] so persist,
/// gate, and correlator share one normalised hash.
pub fn build_legacy_finding_id(engine: &str, target: &str, finding: &Value) -> String {
    crate::finding_identity::build_stable_finding_id(engine, target, finding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gate_rejects_actionable_without_proof() {
        let raw = json!({"severity": "high", "title": "RCE"});
        assert!(gate_finding("eng", "https://t.com", raw).is_none());
    }

    #[test]
    fn gate_accepts_with_evidence_proof() {
        let raw = json!({
            "severity": "high",
            "title": "RCE",
            "evidence": {"proof": "HTTP 500 on payload"}
        });
        let gated = gate_finding("eng", "https://t.com", raw).expect("gated");
        assert_eq!(gated.severity(), "high");
        assert!(!gated.dedup_hash().is_empty());
    }

    #[test]
    fn gate_accepts_osint_value_as_proof() {
        let raw = json!({
            "severity": "medium",
            "source": "ct",
            "value": "api.example.com",
            "type": "osint"
        });
        let gated = gate_finding("osint", "https://example.com", raw).expect("gated");
        assert!(gated.evidence().proof().contains("api.example.com"));
    }

    #[test]
    fn dedup_hash_stable_for_same_signature() {
        let a = build_dedup_hash("https://x.com", "sqli", "' OR 1=1", "eng");
        let b = build_dedup_hash("HTTPS://X.COM", "sqli", "' OR 1=1", "eng");
        assert_eq!(a, b);
    }

    #[test]
    fn dedup_hash_changes_with_payload() {
        let a = build_dedup_hash("https://x.com", "sqli", "a", "eng");
        let b = build_dedup_hash("https://x.com", "sqli", "b", "eng");
        assert_ne!(a, b);
    }

    #[test]
    fn finding_id_ignores_ephemeral_port_and_query() {
        let a = json!({
            "severity": "low",
            "title": "XSS",
            "signature": "xss_reflected?sid=1",
            "cwe": "CWE-79",
        });
        let b = json!({
            "severity": "low",
            "title": "XSS",
            "signature": "xss_reflected",
            "cwe": "cwe-79",
        });
        let id1 = build_legacy_finding_id("asm", "https://app.example.com:49152/x?q=1", &a);
        let id2 = build_legacy_finding_id("asm", "https://app.example.com/x", &b);
        assert_eq!(id1, id2);
    }
}
