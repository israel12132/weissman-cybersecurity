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
use std::sync::LazyLock;
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::db;
use crate::findings_correlator::{self, ClusterAttrs};
use crate::findings_gate::{self, gate_finding, Sealed, VulnerabilitiesWriter};
use crate::fp_feedback;
use crate::intel_epss;
use crate::intel_kev;
use crate::pentest_memory;

/// Bounds the fan-out of the per-finding, fire-and-forget DB side-effects (pentest-memory win
/// recording + SOAR post-persist dispatch). Each such task clones the app pool and acquires a
/// connection; without a cap, a single high-finding scan spawns hundreds of detached tasks that
/// OUTLIVE the scan, saturate the pool, and starve the next scan's `begin_tenant_tx` — surfacing
/// as "database: pool timed out while waiting for an open connection". A small shared cap keeps
/// total background-DB concurrency bounded regardless of finding volume. These are best-effort
/// side effects, so pacing them changes nothing the caller observes. Tunable via
/// `WEISSMAN_POST_PERSIST_DB_CONCURRENCY` (default 6).
static POST_PERSIST_DB_SEM: LazyLock<Semaphore> = LazyLock::new(|| {
    let n = std::env::var("WEISSMAN_POST_PERSIST_DB_CONCURRENCY")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(6);
    Semaphore::new(n)
});

/// Acquire a permit that bounds background post-persist DB work; held for the spawned task's life.
/// `None` only if the (never-closed) semaphore were closed — in which case the task simply proceeds.
async fn post_persist_db_permit() -> Option<SemaphorePermit<'static>> {
    POST_PERSIST_DB_SEM.acquire().await.ok()
}

/// Global concurrency cap for detached background DB tasks spawned by callers *outside* this
/// module's per-finding loop (LLM-usage metering in `observability`, and the pool-starvation
/// contract tests). Same rationale as [`POST_PERSIST_DB_SEM`]: without a bound, a burst of
/// detached `tokio::spawn`s each acquire a pooled connection and, being detached, keep the pool
/// saturated for the full `acquire_timeout` window after the job returns. Bounding makes peak
/// background connection demand `O(permits)`. Override with `WEISSMAN_BG_DB_CONCURRENCY` (default 8).
fn background_db_semaphore() -> &'static tokio::sync::Semaphore {
    static SEM: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SEM.get_or_init(|| {
        let permits = std::env::var("WEISSMAN_BG_DB_CONCURRENCY")
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(8);
        tokio::sync::Semaphore::new(permits)
    })
}

/// Spawn a detached background task that touches the DB, gated by the global
/// [`background_db_semaphore`]. The permit is held for the whole task lifetime, so excess tasks
/// queue on the semaphore instead of storming `pool.acquire()`. This preserves fire-and-forget
/// semantics while hard-capping concurrent pooled-connection demand regardless of call volume.
pub fn spawn_bounded_db_task<Fut>(task: Fut)
where
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        // If the semaphore is ever closed (never in practice) just drop the task.
        let Ok(_permit) = background_db_semaphore().acquire().await else {
            return;
        };
        task.await;
    });
}

/// Lower-case severity from an arbitrary value, defaulting to `info`.
#[allow(dead_code)] // exercised by unit tests; prod call site removed in audit
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
    conn: &mut sqlx::PgConnection,
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
    // Run on the caller's already tenant-scoped batch transaction connection instead of acquiring a
    // SEPARATE pooled connection + `begin_tenant_tx` (BEGIN + SET LOCAL ROLE + set_config + commit)
    // per finding. A high-finding scan otherwise multiplies the persist path's pool churn by the
    // finding count — strict-bounding the per-finding DB footprint to the single batch connection.
    sqlx::query_scalar::<_, bool>(
        r#"SELECT COALESCE(bool_or(internet_exposed), false)
             FROM risk_graph_nodes
            WHERE client_id = $1
              AND (label ILIKE $2 OR graph_key ILIKE $2)"#,
    )
    .bind(client_id)
    .bind(format!("%{host}%"))
    .fetch_one(&mut *conn)
    .await
    .unwrap_or(false)
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

/// Authorized writer — only this type may execute vulnerability INSERT/UPSERT.
struct FindingsPersistWriter;

impl Sealed for FindingsPersistWriter {}

impl VulnerabilitiesWriter for FindingsPersistWriter {}

/// Build a stable finding identifier (delegates to evidence gate).
pub(crate) fn build_finding_id(engine: &str, target: &str, finding: &Value) -> String {
    findings_gate::build_legacy_finding_id(engine, target, finding)
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

    // Cap the batch so a single misbehaving/huge engine result can't open an unbounded write
    // transaction (and a giant findings_json blob). Tunable; the excess is logged, not silently lost.
    let max_persist = std::env::var("WEISSMAN_MAX_PERSIST_FINDINGS")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(5000);
    let findings: &[Value] = if findings.len() > max_persist {
        tracing::warn!(
            target: "findings_persist",
            engine = %engine,
            tenant_id,
            total = findings.len(),
            cap = max_persist,
            "truncating oversized finding batch before persistence"
        );
        &findings[..max_persist]
    } else {
        findings
    };

    // ── Batch threat-intel enrichment BEFORE opening the write transaction ──────────────────
    // EPSS/KEV used to be resolved one CVE at a time *inside* the per-finding loop, each call a
    // separate pool round-trip — and, for EPSS, a live FIRST.org fetch (20s timeout) on a cold
    // cache. A high-finding engine therefore fanned out N sequential network+DB stalls while the
    // write transaction was held open, pinning a connection for minutes and starving the next
    // scan's `begin_tenant_tx` ("pool timed out"). We now resolve ALL of this scan's CVEs in a
    // single batched EPSS fetch + a single `WHERE cve = ANY(...)` KEV query, executed *before* the
    // write tx exists, then look results up from in-memory maps in the loop — zero per-finding
    // network/DB fan-out, and the write tx only ever does fast local DB work.
    let scan_cves: Vec<String> = findings
        .iter()
        .map(extract_cve_from_finding)
        .filter(|c| !c.is_empty())
        .collect();
    let epss_map = intel_epss::fetch_epss_for_cves(pool, &scan_cves).await;
    let kev_map = intel_kev::kev_listed_for_cves(pool, &scan_cves).await;

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

    // Resolve suppression rules ONCE for this (tenant, engine) rather than per finding. All
    // findings in this call share `engine`, so a single query replaces the former per-finding
    // is_suppressed() that opened its own tenant transaction each time (N+1). Matched hashes are
    // collected and their hit_count telemetry is bumped in one statement before commit.
    let active_suppressions =
        fp_feedback::active_suppressions_for_engine(pool, tenant_id, engine).await;
    let mut suppression_hits: Vec<String> = Vec::new();

    let mut inserted: u64 = 0;
    for (finding_index, raw) in findings.iter().cloned().enumerate() {
        let Some(gated) = gate_finding(engine, target, raw) else {
            tracing::warn!(
                target: "findings_persist",
                engine = %engine,
                tenant_id,
                "skipping finding without evidence.proof for actionable severity"
            );
            continue;
        };
        FindingsPersistWriter::assert_gated(&gated);
        let f = gated.json();
        let finding_id = gated.finding_id().to_string();
        let dedup_hash = gated.dedup_hash().to_string();
        let severity = gated.severity().to_string();
        let mut cvss = extract_cvss(&f);
        if cvss <= 0.0 {
            cvss = severity_to_score(&severity);
        }
        let title = extract_title(&f, engine);
        let description = extract_description(&f);
        let target_url = extract_target(&f, target);
        let mitre = extract_string(
            &f,
            &["mitre_attack", "mitre", "attack_id", "mitre_attack_id"],
        );
        let cwe = extract_string(&f, &["cwe", "cwe_id"]);
        let cve = extract_cve_from_finding(&f);
        let remediation = extract_string(
            &f,
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
            &f,
            &[
                "references",
                "reference",
                "refs",
                "links",
                "external_references",
            ],
        );
        let compliance = extract_array(
            &f,
            &["compliance", "compliance_tags", "frameworks", "controls"],
        );
        let poc = extract_string(&f, &["poc", "poc_text", "proof_of_concept", "evidence"]);
        let poc_commitment = if !poc.is_empty() {
            let mut h = Sha256::new();
            h.update(poc.as_bytes());
            format!("{:x}", h.finalize())
        } else {
            String::new()
        };
        let confidence = extract_string(&f, &["confidence", "certainty"]);

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
            "dedup_hash": dedup_hash,
            "raw": f.clone(),
        });
        if !cve.is_empty() {
            // Look up the pre-resolved batch maps (built once before the tx) — no per-finding
            // network fetch or pool round-trip. Key matches both modules' normalization
            // (trim + upper-case for a `CVE-` identifier).
            let cve_key = cve.trim().to_ascii_uppercase();
            if let Some(s) = epss_map.get(&cve_key) {
                epss_score = Some(s.score);
                if let Value::Object(obj) = &mut raw_data_enriched {
                    obj.insert(
                        "epss".to_string(),
                        json!({
                            "score": s.score,
                            "percentile": s.percentile,
                            "date": s.date.to_string(),
                        }),
                    );
                }
            }
            if let Some(k) = kev_map.get(&cve_key) {
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

        // ── Tamper-evident attestation ──────────────────────────────────────
        // Sign the finding's immutable identity (id|title|severity|target) at
        // persist time. On read the server re-derives the digest and verifies it
        // against this receipt, so any out-of-band DB tampering is detectable.
        if let Some((att_digest, att_receipt)) = crate::finding_attestation::attest_finding(
            &finding_id,
            &title,
            &severity,
            &target_url,
            "",
        ) {
            if let Value::Object(obj) = &mut raw_data_enriched {
                obj.insert(
                    "attestation".to_string(),
                    json!({
                        "alg": crate::finding_attestation::ATTEST_ALG,
                        "digest": att_digest,
                        "receipt": att_receipt,
                    }),
                );
            }
        }

        // ── False-positive feedback / auto-suppression check ────────────────
        // The signature_hash is the same triple used by the correlator so
        // suppression rules transfer naturally across engines hitting the
        // exact same vulnerability. We also need it for record_fp()/record_tp().
        let vuln_signature = derive_vuln_signature_for_persist(f, &title);
        let signature_hash =
            findings_correlator::build_cluster_key(&target_url, &vuln_signature, &cwe);
        // Prefer cryptographic dedup hash when correlator signature is empty.
        let signature_hash = if signature_hash.trim().is_empty() {
            dedup_hash.clone()
        } else {
            signature_hash
        };

        // ── Confidence multiplier + effective risk (persist-time, not read-time only) ──
        let conf_mult =
            fp_feedback::confidence_multiplier_tx(&mut tx, tenant_id, engine, &signature_hash)
                .await;
        let base_risk = if cvss > 0.0 {
            cvss
        } else {
            severity_to_score(&severity)
        };
        // Fold live exploit intel (already resolved above) into the platform's core priority
        // score so a KEV-listed / high-EPSS finding outranks a theoretical one with the same CVSS.
        let mut effective = base_risk * conf_mult;
        if let Some(epss) = epss_score {
            // EPSS = P(exploitation within 30d) ∈ [0,1]; boost up to +50%.
            effective *= 1.0 + (epss as f64).clamp(0.0, 1.0) * 0.5;
        }
        if kev_listed {
            // CISA KEV = known-exploited in the wild — never rank below high.
            effective = effective.max(8.5);
            if kev_known_ransomware {
                effective = effective.max(9.5);
            }
        }
        let effective_risk = (effective.min(10.0) * 10.0).round() / 10.0;
        let finding_verified = f.get("verified").and_then(Value::as_bool).unwrap_or(false)
            || f.get("verification_method")
                .and_then(Value::as_str)
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
        let poc_sealed = finding_verified || !poc.is_empty();
        if let Value::Object(obj) = &mut raw_data_enriched {
            obj.insert("confidence_multiplier".to_string(), json!(conf_mult));
            obj.insert("effective_risk".to_string(), json!(effective_risk));
            obj.insert("verified".to_string(), json!(poc_sealed));
            if poc_sealed {
                obj.insert("verification_status".to_string(), json!("verified"));
            } else {
                obj.insert("verification_status".to_string(), json!("unverified"));
            }
        }

        // If a suppression rule exists for this combo, demote to FALSE_POSITIVE before insert. We
        // still persist (audit trail) but the inbox stays clean. Membership is checked against the
        // set preloaded once above (no per-finding round-trip); matched hashes get their hit_count
        // bumped in a single statement before commit.
        let suppressed =
            fp_feedback::is_suppressed_by(&active_suppressions, &signature_hash, &target_url);
        if suppressed {
            suppression_hits.push(signature_hash.clone());
        }
        let effective_status = if suppressed { "FALSE_POSITIVE" } else { "OPEN" };

        // Evidence-doubt: stage uncorroborated actionable findings; admit inventory, proof,
        // KEV, OAST, dual-probe, or confidence ≥ 0.95.
        {
            let mut finding_for_doubt = f.clone();
            if let Value::Object(obj) = &mut finding_for_doubt {
                obj.insert("kev_listed".into(), json!(kev_listed));
                obj.insert("poc_sealed".into(), json!(poc_sealed));
                if !poc.is_empty() {
                    obj.insert("poc".into(), json!(poc.clone()));
                }
            }
            let ckey = crate::elite_hardening::evidence_doubt::corroboration_key(
                &target_url,
                &vuln_signature,
                &poc,
            );
            let distinct =
                distinct_engines_for_key(&mut tx, tenant_id, client_id, &ckey, engine).await;
            let decision = crate::elite_hardening::evidence_doubt::decide(
                engine,
                &severity,
                &finding_for_doubt,
                distinct,
            );
            let _ = upsert_finding_candidate(
                &mut tx,
                tenant_id,
                client_id,
                engine,
                &ckey,
                &severity,
                &title,
                &finding_for_doubt,
                &decision,
            )
            .await;
            match decision {
                crate::elite_hardening::evidence_doubt::AdmitDecision::Stage { reason, .. } => {
                    tracing::info!(
                        target: "findings_persist",
                        engine = %engine,
                        tenant_id,
                        %reason,
                        "staging finding pending corroboration"
                    );
                    continue;
                }
                crate::elite_hardening::evidence_doubt::AdmitDecision::Admit {
                    reason,
                    confidence,
                } => {
                    if let Value::Object(obj) = &mut raw_data_enriched {
                        obj.insert(
                            "evidence_doubt".into(),
                            json!({ "reason": reason, "confidence": confidence }),
                        );
                    }
                }
            }
        }

        // True dedup: target a UNIQUE (tenant_id, client_id, finding_id) constraint.
        // On a repeat detection we refresh evidence (description/proof/raw_data + run_id)
        // and *do not* reset status — analyst-set workflow states (ACKNOWLEDGED, FIXED,
        // FALSE_POSITIVE) must survive the next scan. last_seen_at tracks recurrence.
        let (upserted_id, vuln_is_new): (i64, bool) = sqlx::query_as(
            r#"INSERT INTO vulnerabilities
                 (run_id, tenant_id, client_id, finding_id, title, severity, source,
                  description, status, proof, poc_commitment_sha256, raw_data, discovered_at,
                  signature_hash, epss_score, kev_listed, kev_known_ransomware, kev_due_date,
                  intel_enriched_at, confidence_multiplier, effective_risk, poc_sealed)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now(),
                       $13, $14, $15, $16, $17,
                       CASE WHEN $14 IS NOT NULL OR $15 THEN now() ELSE NULL END,
                       $18, $19, $20)
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
                   confidence_multiplier = EXCLUDED.confidence_multiplier,
                   effective_risk       = EXCLUDED.effective_risk,
                   poc_sealed           = vulnerabilities.poc_sealed OR EXCLUDED.poc_sealed,
                   updated_at           = now(),
                   last_seen_at         = now(),
                   seen_count           = vulnerabilities.seen_count + 1
               RETURNING id, (xmax = 0) AS is_new"#,
        )
        .bind(run_id)
        .bind(tenant_id)
        .bind(client_id)
        .bind(&finding_id)
        .bind(&title)
        .bind(&severity)
        .bind(engine)
        .bind(&description)
        .bind(effective_status)
        .bind(&poc)
        .bind(&poc_commitment)
        .bind(&raw_data_enriched)
        .bind(&signature_hash)
        .bind(epss_score)
        .bind(kev_listed)
        .bind(kev_known_ransomware)
        .bind(kev_due_date)
        .bind(conf_mult)
        .bind(effective_risk)
        .bind(poc_sealed)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("insert vulnerabilities: {e}"))?;

        // PoE exploit sealing (critical/high) — sole authorized post-insert mutation.
        if crate::exploit_crypto::should_seal_poc(poc.as_str(), severity.as_str()) {
            if let Some(key) = crate::exploit_crypto::master_key_bytes() {
                if let Ok(seal) = crate::exploit_crypto::seal_poc(poc.as_str(), &key, &finding_id) {
                    let redacted = "[SEALED — use Command Center «Decrypt Exploit Evidence»]";
                    let _ = sqlx::query(
                        r#"UPDATE vulnerabilities SET poc_sealed = true, poc_ciphertext_b64 = $1,
                           poc_nonce_b64 = $2, poc_commitment_sha256 = $3, poc_zkp_hmac = $4,
                           poc_exploit = $5, updated_at = now()
                           WHERE tenant_id = $6 AND client_id = $7 AND finding_id = $8"#,
                    )
                    .bind(&seal.ciphertext_b64)
                    .bind(&seal.nonce_b64)
                    .bind(&seal.commitment_sha256_hex)
                    .bind(&seal.zkp_hmac_hex)
                    .bind(redacted)
                    .bind(tenant_id)
                    .bind(client_id)
                    .bind(&finding_id)
                    .execute(&mut *tx)
                    .await;
                }
            }
        }

        // ── Correlate into a finding_cluster ─────────────────────────────────
        let source_label = engine;
        let cluster = findings_correlator::upsert_cluster_for_finding(
            &mut tx,
            tenant_id,
            client_id,
            &f,
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
                is_new_member: vuln_is_new,
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

        if crate::critical_infra::is_critical_risk_finding(&f) {
            let eng_alert = engine.to_string();
            let target_alert = target_url.clone();
            let fid_alert = finding_id.clone();
            let title_alert = title.clone();
            let sev_alert = severity.clone();
            tokio::spawn(async move {
                crate::critical_infra::telemetry::emit_critical_risk_finding_persisted(
                    tenant_id,
                    client_id,
                    &eng_alert,
                    &target_alert,
                    &fid_alert,
                    &title_alert,
                    &sev_alert,
                )
                .await;
            });
        }

        // ── Pentest reinforcement memory (fire-and-forget) ───────────────────
        let payload = extract_string(
            &f,
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
            let server_hdr = extract_string(&f, &["server", "server_header"]);
            let powered_by = extract_string(&f, &["x_powered_by", "powered_by"]);
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
                let _permit = post_persist_db_permit().await;
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

        // Reuse the batch tenant transaction's connection (already RLS-scoped to this tenant)
        // instead of acquiring a separate pooled connection + tenant tx per finding.
        let internet_exposed = resolve_internet_exposed(&mut *tx, client_id, &target_url, &f).await;

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
        let pool_for_dispatch: PgPool = (*pool).clone();
        tokio::spawn(async move {
            let _permit = post_persist_db_permit().await;
            crate::soar::dispatch_record::record_post_persist_dispatch(
                &pool_for_dispatch,
                tenant_id,
                upserted_id,
                event,
            )
            .await;
        });
    }

    // Bump hit_count telemetry for every suppression rule that matched this run, in one statement
    // inside the batch transaction (replaces the per-finding UPDATE that is_suppressed used to do).
    fp_feedback::bump_suppression_hits(&mut tx, tenant_id, engine, &suppression_hits).await;

    tx.commit().await.map_err(|e| format!("commit: {e}"))?;

    if inserted > 0 {
        let pool_arc = std::sync::Arc::new((*pool).clone());
        crate::superposition_followup::spawn_after_persist(
            pool_arc,
            tenant_id,
            client_id,
            target.to_string(),
            engine.to_string(),
        );
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn severity_normalization() {
        assert_eq!(normalize_severity(Some("CRITICAL")), "critical");
        assert_eq!(normalize_severity(Some(" High ")), "high");
        assert_eq!(normalize_severity(Some("warn")), "medium");
        assert_eq!(normalize_severity(Some("severe")), "high");
        assert_eq!(normalize_severity(Some("informational")), "info");
        assert_eq!(normalize_severity(Some("")), "info");
        assert_eq!(normalize_severity(None), "info");
        assert_eq!(normalize_severity(Some("nonsense")), "info");
    }

    #[test]
    fn cvss_extraction_clamps_and_guards() {
        assert_eq!(extract_cvss(&json!({"cvss": 7.5})), 7.5);
        assert_eq!(extract_cvss(&json!({"cvss_score": 15.0})), 10.0); // clamped
        assert_eq!(extract_cvss(&json!({"score": -3.0})), 0.0); // negative ignored
        assert_eq!(extract_cvss(&json!({"unrelated": 1})), 0.0);
        assert_eq!(severity_to_score("critical"), 9.5);
        assert_eq!(severity_to_score("info"), 1.0);
    }

    #[test]
    fn effective_risk_clamped_from_base_and_multiplier() {
        let base = severity_to_score("high");
        let conf_mult = 0.83_f64;
        let effective = ((base * conf_mult).min(10.0) * 10.0).round() / 10.0;
        assert!(effective > 0.0 && effective <= 10.0);
        assert_eq!(effective, 6.2); // 7.5 * 0.83 = 6.225 → 6.2
    }

    #[test]
    fn finding_id_is_stable_across_volatile_fields() {
        // Same vulnerability re-detected: only volatile fields differ (timestamps,
        // response time, evidence body) and the target case differs. The stable
        // finding_id MUST be identical so re-scans dedup instead of creating new rows.
        let first = json!({
            "title": "SQL Injection in /login",
            "signature": "sqli",
            "cve": "CVE-2021-1234",
            "response_ms": 12,
            "evidence": "body snapshot A",
            "discovered_at": "2026-01-01T00:00:00Z"
        });
        let rescan = json!({
            "title": "SQL Injection in /login",
            "signature": "sqli",
            "cve": "CVE-2021-1234",
            "response_ms": 987,
            "evidence": "body snapshot Z (totally different)",
            "discovered_at": "2026-06-13T00:00:00Z"
        });
        let id1 = build_finding_id("sqli_engine", "https://Example.com/login", &first);
        let id2 = build_finding_id("sqli_engine", "https://example.com/login", &rescan);
        assert_eq!(
            id1, id2,
            "finding_id must be stable across volatile fields + target case"
        );
        assert!(id1.starts_with("sqli_engine-"));
    }

    #[test]
    fn finding_id_changes_with_signature() {
        let a = json!({"title": "Issue", "signature": "sqli", "cve": "CVE-2021-1234"});
        let b = json!({"title": "Issue", "signature": "xss", "cve": "CVE-2021-1234"});
        let target = "https://example.com/login";
        assert_ne!(
            build_finding_id("eng", target, &a),
            build_finding_id("eng", target, &b),
            "different vulnerability signature must yield a different finding_id"
        );
    }
}

async fn distinct_engines_for_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    client_id: i64,
    key: &str,
    current: &str,
) -> usize {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT engine_id FROM finding_candidates
          WHERE tenant_id = $1 AND client_id = $2 AND corroboration_key = $3",
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(key)
    .fetch_all(&mut **tx)
    .await
    .unwrap_or_default();
    let mut set = std::collections::HashSet::new();
    set.insert(current.to_string());
    for e in rows {
        set.insert(e);
    }
    set.len()
}

async fn upsert_finding_candidate(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    client_id: i64,
    engine: &str,
    key: &str,
    severity: &str,
    title: &str,
    finding: &Value,
    decision: &crate::elite_hardening::evidence_doubt::AdmitDecision,
) -> Result<(), String> {
    let (reason, confidence) = match decision {
        crate::elite_hardening::evidence_doubt::AdmitDecision::Admit { reason, confidence } => {
            (*reason, *confidence)
        }
        crate::elite_hardening::evidence_doubt::AdmitDecision::Stage { reason, confidence } => {
            (*reason, *confidence)
        }
    };
    sqlx::query(
        r#"INSERT INTO finding_candidates
             (tenant_id, client_id, engine_id, corroboration_key, severity, title,
              finding_json, confidence, reason)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (tenant_id, client_id, corroboration_key, engine_id) DO UPDATE SET
               finding_json = EXCLUDED.finding_json,
               confidence = EXCLUDED.confidence,
               reason = EXCLUDED.reason"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .bind(engine)
    .bind(key)
    .bind(severity)
    .bind(title)
    .bind(finding)
    .bind(confidence)
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map(|_| ())
    .or(Ok(()))
}
