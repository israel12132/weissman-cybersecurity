//! Persists raw engine findings into the `report_runs` + `vulnerabilities` tables so the
//! Command Center / Vuln Intel / dashboard / CSV/PDF exports actually see what the engines
//! produced.
//!
//! Engines return loosely-typed `serde_json::Value` records. The columns the read-side
//! handler (`api_findings` in `server_handlers_sqlx.inc`) cares about are:
//!
//! * `id`, `finding_id`, `title`, `severity`, `source`, `status`, `description`,
//!   `discovered_at`, `poc_*`
//! * `raw_data` (JSONB) — surfaced through `raw_data.cvss_score`, `raw_data.mitre_attack`,
//!   `raw_data.remediation`, `raw_data.target`, `raw_data.compliance` so the UI can render
//!   the new columns added by the cockpit follow-up PRs.
//!
//! We map common alias keys defensively so any engine that emits `cvss`/`risk`/`description`
//! still produces a useful row.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::db;

/// Lower-case severity from an arbitrary value, defaulting to `info`.
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

/// Best-effort human title from the engine's finding payload.
fn extract_title(f: &Value, engine: &str) -> String {
    let candidates = [
        "title",
        "name",
        "summary",
        "rule",
        "finding",
        "issue",
        "asset",
        "type",
    ];
    for key in candidates {
        if let Some(s) = f.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.chars().take(240).collect();
            }
        }
    }
    if let Some(v) = f.get("value").and_then(Value::as_str) {
        return format!("{} – {}", engine, v.chars().take(180).collect::<String>());
    }
    format!("{} finding", engine)
}

/// Find a usable description / detail string.
fn extract_description(f: &Value) -> String {
    for key in ["description", "details", "detail", "evidence", "message", "summary"] {
        if let Some(s) = f.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    String::new()
}

/// Pull a CVSS-ish score from common keys.
fn extract_cvss(f: &Value) -> f64 {
    for key in ["cvss_score", "cvss", "cvssScore", "score", "risk_score"] {
        if let Some(v) = f.get(key).and_then(Value::as_f64) {
            if v.is_finite() && v >= 0.0 {
                return (v.min(10.0) * 10.0).round() / 10.0;
            }
        }
    }
    0.0
}

fn severity_to_score(sev: &str) -> f64 {
    match sev {
        "critical" => 9.5,
        "high" => 7.5,
        "medium" => 5.0,
        "low" => 3.0,
        _ => 1.0,
    }
}

fn extract_target(f: &Value, fallback: &str) -> String {
    for key in ["target", "url", "affected_url", "target_url", "asset_url", "host"] {
        if let Some(s) = f.get(key).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    fallback.to_string()
}

fn extract_string(f: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = f.get(*k).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    String::new()
}

fn extract_array(f: &Value, keys: &[&str]) -> Value {
    for k in keys {
        if let Some(v) = f.get(*k) {
            if v.is_array() {
                return v.clone();
            }
            if let Some(s) = v.as_str() {
                if !s.trim().is_empty() {
                    return json!([s]);
                }
            }
        }
    }
    Value::Array(vec![])
}

/// Build a stable finding identifier. **Must only hash invariants** — the same engine
/// detecting the same vulnerability on the same target across re-runs must produce the
/// same `finding_id`, otherwise the `ON CONFLICT (finding_id) DO UPDATE` dedup path
/// inserts duplicate rows for every scan.
///
/// We intentionally exclude every volatile field (timestamps, request IDs, HTTP bodies,
/// banner text, host headers, response_ms, …) and only hash the *signature* — the
/// minimal set of fields that uniquely identifies the vulnerability class on this asset.
fn build_finding_id(engine: &str, target: &str, finding: &Value) -> String {
    let cve = extract_string(finding, &["cve", "cve_id", "cveId"]);
    let cwe = extract_string(finding, &["cwe", "cwe_id"]);
    let mitre = extract_string(finding, &["mitre_attack", "mitre", "attack_id"]);
    let signature = extract_string(
        finding,
        &["signature", "rule", "rule_id", "vuln_signature", "type"],
    );
    let title = extract_title(finding, engine);
    let normalized_title = title
        .chars()
        .filter(|c| !c.is_ascii_digit() && !"./_-?#&=".contains(*c))
        .collect::<String>()
        .to_lowercase();

    let mut hasher = Sha256::new();
    hasher.update(engine.as_bytes());
    hasher.update(b"|");
    hasher.update(target.trim().to_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(cve.as_bytes());
    hasher.update(b"|");
    hasher.update(cwe.as_bytes());
    hasher.update(b"|");
    hasher.update(mitre.as_bytes());
    hasher.update(b"|");
    hasher.update(signature.as_bytes());
    hasher.update(b"|");
    hasher.update(normalized_title.as_bytes());
    let digest = hasher.finalize();
    let short: String = digest.iter().take(12).map(|b| format!("{:02x}", b)).collect();
    format!("{}-{}", engine, short)
}

/// Create (or reuse) a report_runs row and insert one row per finding.
/// Returns the number of vulnerabilities rows actually inserted.
pub async fn persist_engine_findings(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    engine: &str,
    target: &str,
    findings: &[Value],
) -> Result<u64, String> {
    if findings.is_empty() || client_id.is_none() {
        return Ok(0);
    }
    let client_id = client_id.unwrap();

    let mut tx = db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("tenant tx: {e}"))?;

    let summary_obj = json!({
        "engine": engine,
        "target": target,
        "findings_count": findings.len(),
    });

    let run_id: i64 = sqlx::query_scalar(
        r#"INSERT INTO report_runs (tenant_id, findings_json, summary, created_at)
           VALUES ($1, $2::jsonb::text, $3::jsonb::text, now())
           RETURNING id"#,
    )
    .bind(tenant_id)
    .bind(Value::Array(findings.to_vec()))
    .bind(summary_obj)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("insert report_runs: {e}"))?;

    let mut inserted: u64 = 0;
    for f in findings {
        let severity = normalize_severity(f.get("severity").and_then(Value::as_str));
        let mut cvss = extract_cvss(f);
        if cvss <= 0.0 {
            cvss = severity_to_score(&severity);
        }
        let title = extract_title(f, engine);
        let description = extract_description(f);
        let target_url = extract_target(f, target);
        let mitre = extract_string(
            f,
            &["mitre_attack", "mitre", "attack_id", "mitre_attack_id"],
        );
        let cwe = extract_string(f, &["cwe", "cwe_id"]);
        let remediation = extract_string(
            f,
            &[
                "remediation",
                "fix",
                "fix_recommendation",
                "recommendation",
                "how_to_fix",
                "solution",
            ],
        );
        let references = extract_array(
            f,
            &["references", "reference", "refs", "links", "external_references"],
        );
        let compliance = extract_array(
            f,
            &["compliance", "compliance_tags", "frameworks", "controls"],
        );
        let poc = extract_string(f, &["poc", "poc_text", "proof_of_concept", "evidence"]);
        let poc_commitment = if !poc.is_empty() {
            let mut h = Sha256::new();
            h.update(poc.as_bytes());
            format!("{:x}", h.finalize())
        } else {
            String::new()
        };
        let confidence = extract_string(f, &["confidence", "certainty"]);

        let raw_data = json!({
            "engine": engine,
            "target": target_url,
            "cvss_score": cvss,
            "mitre_attack": mitre,
            "cwe": cwe,
            "remediation": remediation,
            "references": references,
            "compliance": compliance,
            "confidence": confidence,
            "evidence": f.get("evidence").cloned().unwrap_or(Value::Null),
            "raw": f.clone(),
        });

        let finding_id = build_finding_id(engine, &target_url, f);

        // True dedup: target a UNIQUE (tenant_id, client_id, finding_id) constraint.
        // On a repeat detection we refresh evidence (description/proof/raw_data + run_id)
        // and *do not* reset status — analyst-set workflow states (ACKNOWLEDGED, FIXED,
        // FALSE_POSITIVE) must survive the next scan. last_seen_at tracks recurrence.
        let res = sqlx::query(
            r#"INSERT INTO vulnerabilities
                 (run_id, tenant_id, client_id, finding_id, title, severity, source,
                  description, status, proof, poc_commitment_sha256, raw_data, discovered_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'OPEN', $9, $10, $11, now())
               ON CONFLICT (tenant_id, client_id, finding_id) DO UPDATE SET
                   run_id           = EXCLUDED.run_id,
                   title            = EXCLUDED.title,
                   severity         = EXCLUDED.severity,
                   description      = EXCLUDED.description,
                   proof            = COALESCE(NULLIF(EXCLUDED.proof, ''), vulnerabilities.proof),
                   raw_data         = EXCLUDED.raw_data,
                   updated_at       = now(),
                   last_seen_at     = now(),
                   seen_count       = vulnerabilities.seen_count + 1"#,
        )
        .bind(run_id)
        .bind(tenant_id)
        .bind(client_id)
        .bind(&finding_id)
        .bind(&title)
        .bind(&severity)
        .bind(engine)
        .bind(&description)
        .bind(&poc)
        .bind(&poc_commitment)
        .bind(&raw_data)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("insert vulnerabilities: {e}"))?;

        inserted += res.rows_affected();
    }

    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(inserted)
}
