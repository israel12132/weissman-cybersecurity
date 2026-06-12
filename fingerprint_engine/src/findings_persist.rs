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
use crate::findings_correlator::{self, ClusterAttrs};
use crate::fp_feedback;
use crate::intel_epss;
use crate::intel_kev;
use crate::pentest_memory;

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
    if let Some(v) = f.get("value").and_then(Value::as_str) {
        return format!("{} – {}", engine, v.chars().take(180).collect::<String>());
    }
    format!("{} finding", engine)
}

/// Find a usable description / detail string.
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

fn finding_internet_exposed(f: &Value) -> Option<bool> {
    for k in ["internet_exposed", "exposed", "is_internet_exposed"] {
        if let Some(b) = f.get(k).and_then(Value::as_bool) {
            return Some(b);
        }
    }
    None
}

/// Best-effort: finding JSON → risk_graph_nodes lookup for SOAR `exposed:` triggers.
async fn resolve_internet_exposed(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
    target_url: &str,
    f: &Value,
) -> bool {
    if let Some(b) = finding_internet_exposed(f) {
        return b;
    }
    let host = target_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target_url)
        .split(':')
        .next()
        .unwrap_or("")
        .trim();
    if host.is_empty() {
        return false;
    }
    let Ok(mut tx) = db::begin_tenant_tx(pool, tenant_id).await else {
        return false;
    };
    let exposed = sqlx::query_scalar::<_, bool>(
        r#"SELECT COALESCE(bool_or(internet_exposed), false)
             FROM risk_graph_nodes
            WHERE client_id = $1
              AND (label ILIKE $2 OR graph_key ILIKE $2)"#,
    )
    .bind(client_id)
    .bind(format!("%{host}%"))
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(false);
    let _ = tx.commit().await;
    exposed
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
    let cve = extract_cve_from_finding(finding);
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
    let short: String = digest
        .iter()
        .take(12)
        .map(|b| format!("{:02x}", b))
        .collect();
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
    let client_id = client_id.expect("client_id.is_none() checked above");

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
        let cve = extract_cve_from_finding(f);
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
            &[
                "references",
                "reference",
                "refs",
                "links",
                "external_references",
            ],
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

        // ── Threat-intel enrichment (EPSS + CISA KEV) ───────────────────────
        // When the engine emits a CVE we look it up against our local mirror.
        // Lookups are best-effort: a network blip or missing intel must not
        // block the scan from persisting. Both helpers also write back to the
        // dedicated `epss_score` / `kev_listed` columns.
        let mut epss_score: Option<f32> = None;
        let mut kev_listed: bool = false;
        let mut kev_known_ransomware: bool = false;
        let mut kev_due_date: Option<chrono::NaiveDate> = None;
        let mut raw_data_enriched = json!({
            "engine": engine,
            "target": target_url,
            "cvss_score": cvss,
            "mitre_attack": mitre,
            "cwe": cwe,
            "cve": cve,
            "remediation": remediation,
            "references": references,
            "compliance": compliance,
            "confidence": confidence,
            "evidence": f.get("evidence").cloned().unwrap_or(Value::Null),
            "raw": f.clone(),
        });
        if !cve.is_empty() {
            if let Some(s) =
                intel_epss::enrich_with_epss(pool, &mut raw_data_enriched, Some(&cve)).await
            {
                epss_score = Some(s.score);
            }
            if let Some(k) = intel_kev::is_kev_listed(pool, &cve).await {
                kev_listed = true;
                kev_known_ransomware = k.known_ransomware_use;
                kev_due_date = k.due_date;
                if let Value::Object(obj) = &mut raw_data_enriched {
                    obj.insert(
                        "kev".to_string(),
                        json!({
                            "listed": true,
                            "known_ransomware_use": kev_known_ransomware,
                            "vendor": k.vendor_project,
                            "product": k.product,
                            "due_date": kev_due_date.map(|d| d.to_string()),
                            "required_action": k.required_action,
                            "vulnerability_name": k.vulnerability_name,
                        }),
                    );
                }
            }
        }

        let finding_id = build_finding_id(engine, &target_url, f);

        // ── False-positive feedback / auto-suppression check ────────────────
        // The signature_hash is the same triple used by the correlator so
        // suppression rules transfer naturally across engines hitting the
        // exact same vulnerability. We also need it for record_fp()/record_tp().
        let vuln_signature = derive_vuln_signature_for_persist(f, &title);
        let signature_hash =
            findings_correlator::build_cluster_key(&target_url, &vuln_signature, &cwe);

        // If a suppression rule exists for this combo, demote to FALSE_POSITIVE
        // before insert. We still persist (audit trail) but the inbox stays clean.
        // We have to commit the existing tx to call is_suppressed (which opens its
        // own short-lived tx); cheap because we restart immediately below.
        let suppressed = fp_feedback::is_suppressed(pool, tenant_id, engine, &signature_hash).await;
        let effective_status = if suppressed { "FALSE_POSITIVE" } else { "OPEN" };

        // Re-open the tx if it was committed during the suppression check. We
        // keep one tx per finding for clean rollback semantics.
        // (Implementation note: is_suppressed uses its own tx, so ours is still alive.)

        // True dedup: target a UNIQUE (tenant_id, client_id, finding_id) constraint.
        // On a repeat detection we refresh evidence (description/proof/raw_data + run_id)
        // and *do not* reset status — analyst-set workflow states (ACKNOWLEDGED, FIXED,
        // FALSE_POSITIVE) must survive the next scan. last_seen_at tracks recurrence.
        let upserted_id: i64 = sqlx::query_scalar(
            r#"INSERT INTO vulnerabilities
                 (run_id, tenant_id, client_id, finding_id, title, severity, source,
                  description, status, proof, poc_commitment_sha256, raw_data, discovered_at,
                  signature_hash, epss_score, kev_listed, kev_known_ransomware, kev_due_date,
                  intel_enriched_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $14, $9, $10, $11, now(),
                       $12, $13, $15, $16, $17,
                       CASE WHEN $13 IS NOT NULL OR $15 THEN now() ELSE NULL END)
               ON CONFLICT (tenant_id, client_id, finding_id) DO UPDATE SET
                   run_id               = EXCLUDED.run_id,
                   title                = EXCLUDED.title,
                   severity             = EXCLUDED.severity,
                   description          = EXCLUDED.description,
                   proof                = COALESCE(NULLIF(EXCLUDED.proof, ''), vulnerabilities.proof),
                   raw_data             = EXCLUDED.raw_data,
                   signature_hash       = COALESCE(EXCLUDED.signature_hash, vulnerabilities.signature_hash),
                   epss_score           = COALESCE(EXCLUDED.epss_score, vulnerabilities.epss_score),
                   kev_listed           = vulnerabilities.kev_listed OR EXCLUDED.kev_listed,
                   kev_known_ransomware = vulnerabilities.kev_known_ransomware OR EXCLUDED.kev_known_ransomware,
                   kev_due_date         = COALESCE(EXCLUDED.kev_due_date, vulnerabilities.kev_due_date),
                   intel_enriched_at    = COALESCE(EXCLUDED.intel_enriched_at, vulnerabilities.intel_enriched_at),
                   updated_at           = now(),
                   last_seen_at         = now(),
                   seen_count           = vulnerabilities.seen_count + 1
               RETURNING id"#,
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
        .bind(&raw_data_enriched)
        .bind(&signature_hash)
        .bind(epss_score)
        .bind(effective_status)
        .bind(kev_listed)
        .bind(kev_known_ransomware)
        .bind(kev_due_date)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("insert vulnerabilities: {e}"))?;

        // ── Correlate into a finding_cluster ─────────────────────────────────
        let source_label = engine;
        let cluster = findings_correlator::upsert_cluster_for_finding(
            &mut tx,
            tenant_id,
            client_id,
            f,
            ClusterAttrs {
                target: &target_url,
                engine,
                source: source_label,
                title: &title,
                severity: &severity,
                cwe: &cwe,
                cve: if cve.is_empty() { None } else { Some(&cve) },
                cvss: Some(cvss),
                epss_score,
                kev_listed,
            },
        )
        .await
        .ok();

        // Stamp the new cluster_id onto the vulnerability row.
        if let Some((cid, ref _key)) = cluster {
            let _ = sqlx::query("UPDATE vulnerabilities SET cluster_id = $1 WHERE id = $2")
                .bind(cid)
                .bind(upserted_id)
                .execute(&mut *tx)
                .await;
        }

        inserted += 1;
        let _ = upserted_id; // silence unused warning when not building tests

        // ── Pentest reinforcement memory (fire-and-forget) ───────────────────
        let payload = extract_string(
            f,
            &[
                "payload",
                "probe_payload",
                "injected_payload",
                "fuzz_payload",
            ],
        );
        if !payload.is_empty() && effective_status != "FALSE_POSITIVE" {
            let host = target_url
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or(&target_url)
                .split(':')
                .next()
                .unwrap_or(&target_url)
                .to_string();
            let server_hdr = extract_string(f, &["server", "server_header"]);
            let powered_by = extract_string(f, &["x_powered_by", "powered_by"]);
            let server_opt = if server_hdr.is_empty() {
                None
            } else {
                Some(server_hdr.as_str())
            };
            let powered_opt = if powered_by.is_empty() {
                None
            } else {
                Some(powered_by.as_str())
            };
            let fingerprint =
                pentest_memory::build_target_fingerprint(&host, server_opt, powered_opt, &[]);
            let response_status = f
                .get("response_status")
                .and_then(Value::as_u64)
                .unwrap_or(200) as i32;
            let response_body = f
                .get("response_body")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .or_else(|| {
                    if poc.is_empty() {
                        None
                    } else {
                        Some(poc.clone())
                    }
                });
            let evidence = title.chars().take(240).collect::<String>();
            let pool_mem = (*pool).clone();
            let eng = engine.to_string();
            let cwe_mem = cwe.clone();
            let sig_mem = vuln_signature.clone();
            tokio::spawn(async move {
                let _ = pentest_memory::record_win(
                    &pool_mem,
                    tenant_id,
                    &eng,
                    &cwe_mem,
                    &sig_mem,
                    &payload,
                    &evidence,
                    response_status,
                    response_body.as_deref(),
                    &fingerprint,
                )
                .await;
            });
        }

        let internet_exposed =
            resolve_internet_exposed(pool, tenant_id, client_id, &target_url, f).await;

        // ── SOAR playbook dispatch (fire-and-forget) ────────────────────────
        // Built outside the tx so a slow webhook doesn't extend the DB lock.
        // We snapshot the event here while we still have all the data and
        // tokio::spawn the dispatch after commit.
        let event = crate::soar_playbook::PlaybookEvent {
            kind: "finding_persisted".to_string(),
            tenant_id,
            client_id: Some(client_id),
            finding_id: Some(upserted_id),
            cluster_id: cluster.map(|(cid, _)| cid),
            title: title.clone(),
            severity: severity.clone(),
            source: engine.to_string(),
            target: target_url.clone(),
            status: effective_status.to_string(),
            cvss: Some(cvss as f32),
            epss: epss_score,
            kev: kev_listed,
            kev_known_ransomware,
            cve: if cve.is_empty() {
                None
            } else {
                Some(cve.clone())
            },
            signature_hash: Some(signature_hash.clone()),
            internet_exposed,
        };
        // `PgPool` is internally an Arc, so `(*pool).clone()` is a cheap refcount bump.
        let pool_for_dispatch: PgPool = (*pool).clone();
        tokio::spawn(async move {
            // Best-effort: any failure inside dispatch is logged but doesn't
            // affect the persist transaction.
            let _ = crate::soar_playbook::dispatch_event(&pool_for_dispatch, event, false).await;
        });
    }

    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(inserted)
}

/// Same priority order as `findings_correlator::derive_vuln_signature`, kept here so
/// the persist path doesn't need to expose the helper publicly. Centralising the
/// extraction keeps `signature_hash` identical on both sides.
fn derive_vuln_signature_for_persist(finding: &Value, fallback_title: &str) -> String {
    for k in ["signature", "rule_id", "vuln_signature", "rule"] {
        if let Some(s) = finding.get(k).and_then(Value::as_str) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_ascii_lowercase();
            }
        }
    }
    if let Some(t) = finding.get("type").and_then(Value::as_str) {
        let s = t.trim();
        if !s.is_empty() {
            return s.to_ascii_lowercase();
        }
    }
    for k in ["cve", "cve_id"] {
        if let Some(c) = finding.get(k).and_then(Value::as_str) {
            let s = c.trim();
            if !s.is_empty() {
                return s.to_ascii_uppercase();
            }
        }
    }
    fallback_title
        .chars()
        .take(80)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn extract_cve_from_finding(finding: &Value) -> String {
    crate::intel_findings_backfill::extract_cve_from_value(finding).unwrap_or_default()
}
