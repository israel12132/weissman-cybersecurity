//! Scan → finding mapping + live Cortex XSIAM coverage.
//!
//! Complements `finding_cortex_push`: that module pushes one proven finding.
//! This module stamps every persisted scan finding with `raw_data.scan_bridge`,
//! stores a durable `scan_finding_bridge` row, and (when Cortex is configured)
//! compares proven findings against live `get_alerts` so Command Center can
//! show XDR blind spots. Missing Cortex config fails visibly — never a fake hit.

use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use tokio::sync::Semaphore;

use crate::engine_dispatch::EngineRunContext;
use crate::engine_result::EngineResult;
use crate::finding_cortex_push::{proof_artifact, push_eligibility, push_finding_to_cortex};
use crate::finding_live_verify::FindingRow;
use crate::soar::adapters::cortex_xsiam::{xsiam_has_matching_alert, CortexMode};
use crate::soar::integrations::{load_integrations, IntegrationRecord};

pub const ENGINE_ID: &str = "cortex_proven_finding_bridge";

const MAX_LIST: i64 = 500;
const MAX_FLUSH: usize = 25;
const MAX_XDR_COMPARE: usize = 40;

#[derive(Debug, Clone)]
pub struct BridgeRow {
    pub id: i64,
    pub finding_id: String,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub status: String,
    pub target: String,
    pub client_id: Option<i64>,
    pub raw_data: Value,
    pub discovered_at: String,
    pub signature_hash: String,
    pub report_run_id: Option<i64>,
    pub engine_id: String,
    pub proof_kind: Option<String>,
    pub cortex_status: String,
    pub cortex_external_ref: Option<String>,
    pub xdr_had_matching_alert: Option<bool>,
}

fn live_verdict(raw: &Value) -> Option<String> {
    raw.get("live_verification")
        .and_then(|v| v.get("verdict"))
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_uppercase())
}

fn nested_raw(raw: &Value) -> &Value {
    raw.get("raw").unwrap_or(raw)
}

/// Proof artifact kind on a persisted `raw_data` blob (and nested `raw`).
/// Tamper-evident attestation is not a vulnerability proof.
pub fn proof_kind_from_raw(raw: &Value) -> Option<String> {
    proof_artifact(raw).map(|s| s.to_string())
}

fn merge_sql_proof(raw: &mut Value, sql_proof: Option<String>) {
    let Some(p) = sql_proof.filter(|s| !s.trim().is_empty()) else {
        return;
    };
    if proof_artifact(raw).is_some() {
        return;
    }
    if let Value::Object(o) = raw {
        o.insert("poc".into(), json!(p));
    }
}

/// `raw_data.scan_bridge` stamped at persist time.
pub fn metadata_json(
    report_run_id: i64,
    engine: &str,
    finding_index: usize,
    scan_target: &str,
    proof_kind: Option<&str>,
) -> Value {
    json!({
        "report_run_id": report_run_id,
        "engine_id": engine,
        "finding_index": finding_index,
        "scan_target": scan_target,
        "proof_kind": proof_kind,
        "mapped_at": chrono::Utc::now().to_rfc3339(),
    })
}

pub async fn upsert_mapped_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    finding_pk: i64,
    finding_id: &str,
    report_run_id: i64,
    engine: &str,
    scan_target: &str,
    proof_kind: Option<&str>,
    proof_hash: &str,
) -> Result<(), String> {
    sqlx::query(
        r#"INSERT INTO scan_finding_bridge (
                tenant_id, finding_pk, finding_id, report_run_id, engine_id, scan_target,
                proof_kind, proof_hash, cortex_status, mapped_at, updated_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'mapped', now(), now())
           ON CONFLICT (tenant_id, finding_pk) DO UPDATE SET
                finding_id = EXCLUDED.finding_id,
                report_run_id = EXCLUDED.report_run_id,
                engine_id = EXCLUDED.engine_id,
                scan_target = EXCLUDED.scan_target,
                proof_kind = COALESCE(EXCLUDED.proof_kind, scan_finding_bridge.proof_kind),
                proof_hash = COALESCE(NULLIF(EXCLUDED.proof_hash, ''), scan_finding_bridge.proof_hash),
                cortex_status = CASE
                    WHEN scan_finding_bridge.cortex_status IN ('pushed', 'blind_spot')
                    THEN scan_finding_bridge.cortex_status
                    ELSE EXCLUDED.cortex_status
                END,
                updated_at = now()"#,
    )
    .bind(tenant_id)
    .bind(finding_pk)
    .bind(finding_id)
    .bind(report_run_id)
    .bind(engine)
    .bind(scan_target)
    .bind(proof_kind)
    .bind(proof_hash)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("scan_finding_bridge: {e}"))?;
    Ok(())
}

pub async fn record_cortex_outcome(
    pool: &PgPool,
    tenant_id: i64,
    finding_pk: i64,
    status: &str,
    external_ref: Option<&str>,
    xdr_had: Option<bool>,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("db: {e}"))?;
    sqlx::query(
        r#"UPDATE scan_finding_bridge
              SET cortex_status = $3,
                  cortex_external_ref = COALESCE($4, cortex_external_ref),
                  cortex_pushed_at = CASE WHEN $3 = 'pushed' THEN now() ELSE cortex_pushed_at END,
                  xdr_had_matching_alert = COALESCE($5, xdr_had_matching_alert),
                  updated_at = now()
            WHERE tenant_id = $1 AND finding_pk = $2"#,
    )
    .bind(tenant_id)
    .bind(finding_pk)
    .bind(status)
    .bind(external_ref)
    .bind(xdr_had)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("scan_finding_bridge: {e}"))?;
    tx.commit().await.map_err(|e| format!("db: {e}"))?;
    Ok(())
}

fn pick_cortex(list: &[IntegrationRecord]) -> Option<IntegrationRecord> {
    list.iter()
        .find(|i| {
            let p = i.provider_type.as_str();
            p == "cortex_xsiam"
                || p == "cortex_xsoar"
                || p == "cortex"
                || i.id == "cortex_xsiam"
                || i.id == "cortex_xsoar"
        })
        .cloned()
}

fn auto_push_enabled(config: &Value) -> bool {
    match config.get("auto_push_proven") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => {
            let t = s.trim().to_ascii_lowercase();
            t == "1" || t == "true" || t == "yes"
        }
        _ => false,
    }
}

fn cve_of(raw: &Value) -> Option<String> {
    raw.get("cve")
        .or_else(|| raw.get("cve_id"))
        .or_else(|| nested_raw(raw).get("cve"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn to_finding_row(b: &BridgeRow) -> FindingRow {
    let proof = proof_artifact(&b.raw_data)
        .map(|_kind| {
            b.raw_data
                .get("proof")
                .or_else(|| b.raw_data.get("poc"))
                .or_else(|| b.raw_data.get("poc_exploit"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    let poc_exploit = b
        .raw_data
        .get("poc_exploit")
        .or_else(|| b.raw_data.get("poc"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    FindingRow {
        id: b.id,
        finding_id: b.finding_id.clone(),
        title: b.title.clone(),
        severity: b.severity.clone(),
        source: b.source.clone(),
        target: b.target.clone(),
        client_id: b.client_id,
        raw_data: b.raw_data.clone(),
        discovered_at: b.discovered_at.clone(),
        signature_hash: b.signature_hash.clone(),
        status: if b.status.is_empty() {
            "OPEN".into()
        } else {
            b.status.clone()
        },
        proof,
        poc_exploit,
    }
}

fn classify(row: &BridgeRow) -> (bool, String, String) {
    let fr = to_finding_row(row);
    match push_eligibility(&fr) {
        Ok(gate) => (true, "eligible".into(), gate),
        Err(e) => (false, "ineligible".into(), e),
    }
}

fn map_sql_row(r: sqlx::postgres::PgRow) -> BridgeRow {
    let mut raw_data = r.try_get::<Value, _>("raw_data").unwrap_or(Value::Null);
    let sql_proof = r.try_get::<Option<String>, _>("sql_proof").ok().flatten();
    merge_sql_proof(&mut raw_data, sql_proof);
    let engine_id = r
        .try_get::<Option<String>, _>("bridge_engine")
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            raw_data
                .get("engine")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let proof_kind = r
        .try_get::<Option<String>, _>("proof_kind")
        .ok()
        .flatten()
        .or_else(|| proof_kind_from_raw(&raw_data));
    let target = r
        .try_get::<Option<String>, _>("target")
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            raw_data
                .get("target")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    BridgeRow {
        id: r.try_get("id").unwrap_or(0),
        finding_id: r.try_get("finding_id").unwrap_or_default(),
        title: r.try_get("title").unwrap_or_default(),
        severity: r.try_get("severity").unwrap_or_default(),
        source: r.try_get("source").unwrap_or_default(),
        status: r.try_get("status").unwrap_or_default(),
        target,
        client_id: r.try_get("client_id").ok().flatten(),
        raw_data,
        discovered_at: r.try_get("discovered_at").unwrap_or_default(),
        signature_hash: r.try_get("signature_hash").unwrap_or_default(),
        report_run_id: r
            .try_get::<Option<i64>, _>("report_run_id")
            .ok()
            .flatten()
            .or_else(|| r.try_get::<Option<i64>, _>("run_id").ok().flatten()),
        engine_id,
        proof_kind,
        cortex_status: r
            .try_get::<Option<String>, _>("cortex_status")
            .ok()
            .flatten()
            .unwrap_or_else(|| "mapped".into()),
        cortex_external_ref: r.try_get("cortex_external_ref").ok().flatten(),
        xdr_had_matching_alert: r.try_get("xdr_had_matching_alert").ok().flatten(),
    }
}

const LIST_SQL: &str = r#"
SELECT v.id, v.finding_id, v.title, v.severity, v.source, v.status,
       COALESCE(v.raw_data->>'target', '') AS target,
       COALESCE(v.raw_data, '{}'::jsonb) AS raw_data,
       COALESCE(v.proof, '') AS sql_proof,
       COALESCE(v.discovered_at::text, '') AS discovered_at,
       COALESCE(v.signature_hash, '') AS signature_hash,
       v.client_id, v.run_id,
       b.engine_id AS bridge_engine, b.report_run_id, b.proof_kind,
       b.cortex_status, b.cortex_external_ref, b.xdr_had_matching_alert
  FROM vulnerabilities v
  LEFT JOIN scan_finding_bridge b
         ON b.tenant_id = v.tenant_id AND b.finding_pk = v.id
 WHERE v.tenant_id = $1
   AND ($2::bigint IS NULL OR v.client_id = $2)
 ORDER BY v.discovered_at DESC NULLS LAST
 LIMIT $3
"#;

const LIST_SQL_FALLBACK: &str = r#"
SELECT v.id, v.finding_id, v.title, v.severity, v.source, v.status,
       COALESCE(v.raw_data->>'target', '') AS target,
       COALESCE(v.raw_data, '{}'::jsonb) AS raw_data,
       COALESCE(v.proof, '') AS sql_proof,
       COALESCE(v.discovered_at::text, '') AS discovered_at,
       COALESCE(v.signature_hash, '') AS signature_hash,
       v.client_id, v.run_id,
       NULL::text AS bridge_engine, v.run_id AS report_run_id, NULL::text AS proof_kind,
       NULL::text AS cortex_status, NULL::text AS cortex_external_ref,
       NULL::boolean AS xdr_had_matching_alert
  FROM vulnerabilities v
 WHERE v.tenant_id = $1
   AND ($2::bigint IS NULL OR v.client_id = $2)
 ORDER BY v.discovered_at DESC NULLS LAST
 LIMIT $3
"#;

async fn load_rows(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    limit: i64,
) -> Result<Vec<BridgeRow>, String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("db: {e}"))?;
    let limit = limit.clamp(1, MAX_LIST);
    let rows = match sqlx::query(LIST_SQL)
        .bind(tenant_id)
        .bind(client_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("scan_finding_bridge") {
                sqlx::query(LIST_SQL_FALLBACK)
                    .bind(tenant_id)
                    .bind(client_id)
                    .bind(limit)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(|e2| format!("db: {e2}"))?
            } else {
                let _ = tx.rollback().await;
                return Err(format!("db: {e}"));
            }
        }
    };
    let _ = tx.commit().await;
    Ok(rows.into_iter().map(map_sql_row).collect())
}

fn row_json(b: &BridgeRow, eligible: bool, gate: &str, xdr: Option<bool>) -> Value {
    let cortex_push = b
        .raw_data
        .get("cortex_push")
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "id": b.id,
        "finding_id": b.finding_id,
        "title": b.title,
        "severity": b.severity,
        "source": b.source,
        "status": b.status,
        "target": b.target,
        "client_id": b.client_id,
        "discovered_at": b.discovered_at,
        "engine_id": b.engine_id,
        "report_run_id": b.report_run_id,
        "proof_kind": b.proof_kind,
        "scan_bridge": b.raw_data.get("scan_bridge").cloned().unwrap_or(Value::Null),
        "live_verdict": live_verdict(&b.raw_data),
        "eligible": eligible,
        "gate": gate,
        "cortex_status": b.cortex_status,
        "cortex_external_ref": b.cortex_external_ref,
        "cortex_push": cortex_push,
        "xdr_had_matching_alert": xdr.or(b.xdr_had_matching_alert),
        "cve": cve_of(&b.raw_data),
        "mitre_attack": b.raw_data.get("mitre_attack"),
        "internet_exposed": b.raw_data.get("internet_exposed").and_then(Value::as_bool).unwrap_or(false),
        "effective_risk": b.raw_data.get("effective_risk"),
    })
}

/// GET /api/findings/scan-cortex-bridge
pub async fn snapshot(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    limit: i64,
    compare_xdr: bool,
) -> Result<Value, (u16, String)> {
    let rows = load_rows(pool, tenant_id, client_id, limit)
        .await
        .map_err(|e| (500, e))?;
    let integrations = load_integrations(pool, tenant_id).await;
    let cortex = pick_cortex(&integrations);
    let cortex_configured = cortex.is_some();
    let cortex_mode = cortex
        .as_ref()
        .map(|i| format!("{:?}", CortexMode::from_config(&i.config)));

    let mut xdr_compared = 0usize;
    let mut items = Vec::with_capacity(rows.len());
    let mut proven = 0usize;
    let mut ineligible = 0usize;
    let mut already_pushed = 0usize;
    let mut blind = 0usize;
    let mut covered = 0usize;

    let sem = Semaphore::new(6);
    for b in &rows {
        let (eligible, _cls, gate) = classify(b);
        if eligible {
            proven += 1;
        } else {
            ineligible += 1;
        }
        if b.cortex_status == "pushed"
            || b.raw_data
                .get("cortex_push")
                .and_then(|v| v.get("external_ref"))
                .is_some()
        {
            already_pushed += 1;
        }
        let mut xdr = b.xdr_had_matching_alert;
        if compare_xdr && eligible && xdr_compared < MAX_XDR_COMPARE {
            if let Some(ref integ) = cortex {
                if CortexMode::from_config(&integ.config) == CortexMode::Xsiam {
                    let _permit = sem.acquire().await.ok();
                    xdr_compared += 1;
                    match xsiam_has_matching_alert(
                        &integ.config,
                        &b.title,
                        cve_of(&b.raw_data).as_deref(),
                    )
                    .await
                    {
                        Ok(v) => xdr = v,
                        Err(e) => {
                            return Err((502, format!("Cortex get_alerts failed: {e}")));
                        }
                    }
                }
            }
        }
        if xdr == Some(false) && eligible {
            blind += 1;
        }
        if xdr == Some(true) {
            covered += 1;
        }
        items.push(row_json(b, eligible, &gate, xdr));
    }

    Ok(json!({
        "ok": true,
        "engine": ENGINE_ID,
        "cortex_configured": cortex_configured,
        "cortex_mode": cortex_mode,
        "compare_xdr": compare_xdr && cortex_configured,
        "xdr_compared": xdr_compared,
        "counts": {
            "mapped": rows.len(),
            "proven_eligible": proven,
            "ineligible": ineligible,
            "already_pushed": already_pushed,
            "xdr_blind_spots": blind,
            "xdr_already_had": covered,
        },
        "items": items,
        "live_only": true,
        "note": if !cortex_configured {
            "Cortex XSIAM/XSOAR is not configured — add api_url/api_key/api_key_id under Integrations. Mapping is still live from scans."
        } else {
            "Proven findings compared against live Cortex APIs. Blind spots are proven Weissman findings XDR did not return."
        },
    }))
}

/// POST /api/findings/scan-cortex-bridge/flush — batch push eligible proven findings.
pub async fn flush(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    ids: &[String],
    dry_run: bool,
) -> Result<Value, (u16, String)> {
    let rows = load_rows(pool, tenant_id, client_id, MAX_LIST)
        .await
        .map_err(|e| (500, e))?;
    let integrations = load_integrations(pool, tenant_id).await;
    if pick_cortex(&integrations).is_none() {
        return Err((
            409,
            "Cortex XSIAM/XSOAR is not configured — add it under Integrations (api_url, api_key, api_key_id)".into(),
        ));
    }
    let wanted: Option<std::collections::HashSet<String>> = if ids.is_empty() {
        None
    } else {
        Some(ids.iter().map(|s| s.trim().to_string()).collect())
    };
    let mut results = Vec::new();
    let mut pushed = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    for b in rows {
        if let Some(ref set) = wanted {
            let id_s = b.id.to_string();
            if !set.contains(&id_s) && !set.contains(&b.finding_id) {
                continue;
            }
        }
        let (eligible, _, gate) = classify(&b);
        if !eligible {
            skipped += 1;
            results.push(json!({
                "id": b.id,
                "finding_id": b.finding_id,
                "ok": false,
                "skipped": true,
                "detail": gate,
            }));
            continue;
        }
        if results.len() >= MAX_FLUSH {
            break;
        }
        match push_finding_to_cortex(pool, tenant_id, &b.id.to_string(), dry_run).await {
            Ok(v) => {
                pushed += 1;
                let xdr = v.get("xdr_had_matching_alert").and_then(Value::as_bool);
                let ext = v.get("external_ref").and_then(Value::as_str);
                if !dry_run {
                    let _ = record_cortex_outcome(pool, tenant_id, b.id, "pushed", ext, xdr).await;
                }
                results.push(v);
            }
            Err((code, detail)) => {
                failed += 1;
                results.push(json!({
                    "id": b.id,
                    "finding_id": b.finding_id,
                    "ok": false,
                    "http_status": code,
                    "detail": detail,
                }));
            }
        }
    }
    Ok(json!({
        "ok": true,
        "dry_run": dry_run,
        "pushed": pushed,
        "skipped": skipped,
        "failed": failed,
        "results": results,
        "cap": MAX_FLUSH,
    }))
}

/// Opt-in auto-export after persist when integration config has `auto_push_proven`.
pub async fn maybe_auto_push(pool: &PgPool, tenant_id: i64, finding_pk: i64, severity: &str) {
    let sev = severity.trim().to_ascii_lowercase();
    if sev != "critical" && sev != "high" {
        return;
    }
    let integrations = load_integrations(pool, tenant_id).await;
    let Some(integ) = pick_cortex(&integrations) else {
        return;
    };
    if !auto_push_enabled(&integ.config) {
        return;
    }
    match push_finding_to_cortex(pool, tenant_id, &finding_pk.to_string(), false).await {
        Ok(v) => {
            let xdr = v.get("xdr_had_matching_alert").and_then(Value::as_bool);
            let ext = v.get("external_ref").and_then(Value::as_str);
            let _ = record_cortex_outcome(pool, tenant_id, finding_pk, "pushed", ext, xdr).await;
        }
        Err((code, detail)) => {
            tracing::warn!(
                target: "scan_finding_bridge",
                tenant_id,
                finding_pk,
                code,
                detail = %detail,
                "auto_push_proven Cortex export failed"
            );
        }
    }
}

async fn backfill_mapped_rows(pool: &PgPool, tenant_id: i64, rows: &[BridgeRow]) {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return;
    };
    for b in rows {
        let engine = if b.engine_id.is_empty() {
            b.source.as_str()
        } else {
            b.engine_id.as_str()
        };
        let kind = b
            .proof_kind
            .clone()
            .or_else(|| proof_kind_from_raw(&b.raw_data));
        if let Err(e) = upsert_mapped_row(
            &mut tx,
            tenant_id,
            b.id,
            &b.finding_id,
            b.report_run_id.unwrap_or(0),
            engine,
            &b.target,
            kind.as_deref(),
            &b.signature_hash,
        )
        .await
        {
            tracing::warn!(
                target: "scan_finding_bridge",
                tenant_id,
                finding_pk = b.id,
                error = %e,
                "historical scan_finding_bridge backfill skipped"
            );
        }
    }
    let _ = tx.commit().await;
}

fn host_matches(target: &str, finding_target: &str) -> bool {
    let t = target.trim().to_ascii_lowercase();
    if t.is_empty() || t == "https://example.com" {
        return true;
    }
    let hay = finding_target.to_ascii_lowercase();
    let needle = t
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(&t);
    hay.contains(needle)
}

/// Production engine: map live DB findings and emit XSIAM coverage-gap findings
/// only when Cortex `get_alerts` actually ran.
pub async fn run_cortex_proven_finding_bridge_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    let Some(pool) = ctx.app_pool.as_deref() else {
        return EngineResult::error(
            "cortex_proven_finding_bridge requires a live app_pool — cannot map scans without Postgres",
        );
    };
    let Some(tenant_id) = ctx.tenant_id else {
        return EngineResult::error(
            "cortex_proven_finding_bridge requires tenant_id — refuse to invent mappings",
        );
    };
    let rows = match load_rows(pool, tenant_id, ctx.client_id, MAX_LIST).await {
        Ok(r) => r,
        Err(e) => return EngineResult::error(format!("scan→finding map failed: {e}")),
    };
    backfill_mapped_rows(pool, tenant_id, &rows).await;
    let filtered: Vec<&BridgeRow> = rows
        .iter()
        .filter(|b| host_matches(target, &b.target))
        .collect();
    if filtered.is_empty() {
        return EngineResult::ok(
            vec![],
            format!(
                "{ENGINE_ID}: no persisted findings for this tenant/target — run a live scan first"
            ),
        );
    }

    let integrations = load_integrations(pool, tenant_id).await;
    let cortex = pick_cortex(&integrations);
    let mut findings = Vec::new();
    let mut compared = 0usize;

    if let Some(integ) = cortex.as_ref() {
        if CortexMode::from_config(&integ.config) == CortexMode::Xsiam {
            let sem = Semaphore::new(6);
            for b in &filtered {
                let (eligible, _, gate) = classify(b);
                if !eligible {
                    continue;
                }
                if compared >= MAX_XDR_COMPARE {
                    break;
                }
                compared += 1;
                let _permit = sem.acquire().await.ok();
                match xsiam_has_matching_alert(
                    &integ.config,
                    &b.title,
                    cve_of(&b.raw_data).as_deref(),
                )
                .await
                {
                    Ok(Some(false)) => {
                        let proof = format!(
                            "XSIAM get_alerts HTTP 2xx returned no alert matching title/CVE. local_finding_id={} engine={} proof_kind={} gate={} cve={}",
                            b.finding_id,
                            b.engine_id,
                            b.proof_kind.as_deref().unwrap_or("-"),
                            gate,
                            cve_of(&b.raw_data).unwrap_or_else(|| "-".into()),
                        );
                        let mut f = crate::engine_probes::finding(
                            ENGINE_ID,
                            &format!("XSIAM blind spot: {}", b.title),
                            &b.severity,
                            "T1562.001",
                            &format!(
                                "Weissman proven finding is not present in live Cortex XSIAM alerts. {proof}"
                            ),
                            &b.target,
                        );
                        if let Some(obj) = f.as_object_mut() {
                            obj.insert("evidence".into(), json!({ "proof": proof }));
                            obj.insert("proof".into(), json!(proof));
                            obj.insert("source_finding_id".into(), json!(b.finding_id));
                            obj.insert("source_engine".into(), json!(b.engine_id));
                            obj.insert("report_run_id".into(), json!(b.report_run_id));
                            obj.insert("verified".into(), json!(true));
                            obj.insert(
                                "verification_method".into(),
                                json!("xsiam_get_alerts_no_match"),
                            );
                        }
                        findings.push(f);
                        let _ = record_cortex_outcome(
                            pool,
                            tenant_id,
                            b.id,
                            "blind_spot",
                            None,
                            Some(false),
                        )
                        .await;
                    }
                    Ok(Some(true)) => {
                        let _ = record_cortex_outcome(
                            pool,
                            tenant_id,
                            b.id,
                            b.cortex_status.as_str(),
                            None,
                            Some(true),
                        )
                        .await;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        return EngineResult::error(format!(
                            "Cortex get_alerts failed — not emitting coverage findings: {e}"
                        ));
                    }
                }
            }
        }
    }

    let mapped = filtered.len();
    let msg = if cortex.is_none() {
        format!(
            "{ENGINE_ID}: mapped {mapped} scan findings; Cortex not configured (no fake XDR coverage)"
        )
    } else {
        format!(
            "{ENGINE_ID}: mapped {mapped} scan findings; compared {compared} proven findings against live XSIAM; {} coverage-gap finding(s)",
            findings.len()
        )
    };
    EngineResult::ok(findings, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_kind_ignores_attestation() {
        let raw = json!({"attestation": {"receipt": "abc"}, "oast": "https://oast"});
        assert_eq!(proof_kind_from_raw(&raw).as_deref(), Some("oast"));
        assert!(proof_kind_from_raw(&json!({"attestation": {"receipt": "abc"}})).is_none());
    }

    #[test]
    fn proof_kind_nested_oast() {
        let raw = json!({"raw": {"oast_callback": "https://oast.example/id"}});
        assert_eq!(proof_kind_from_raw(&raw).as_deref(), Some("oast_callback"));
    }

    #[test]
    fn proof_kind_sql_poc_merge() {
        let mut raw = json!({"title": "x"});
        merge_sql_proof(&mut raw, Some("AUTH bypass replay".into()));
        assert_eq!(proof_kind_from_raw(&raw).as_deref(), Some("poc"));
    }

    #[test]
    fn proof_kind_empty() {
        assert!(proof_kind_from_raw(&json!({"title": "x"})).is_none());
    }

    #[test]
    fn metadata_includes_run_and_engine() {
        let v = metadata_json(9, "redis_security", 0, "10.0.0.8", Some("oast"));
        assert_eq!(v["report_run_id"], 9);
        assert_eq!(v["engine_id"], "redis_security");
        assert_eq!(v["proof_kind"], "oast");
    }

    #[test]
    fn host_filter() {
        assert!(host_matches("", "10.0.0.8"));
        assert!(host_matches(
            "https://api.acme.test",
            "https://api.acme.test/login"
        ));
        assert!(!host_matches("https://other.test", "10.0.0.8"));
    }

    #[test]
    fn auto_push_flag() {
        assert!(auto_push_enabled(&json!({"auto_push_proven": true})));
        assert!(auto_push_enabled(&json!({"auto_push_proven": "true"})));
        assert!(!auto_push_enabled(&json!({})));
    }

    #[test]
    fn classify_rejects_noise() {
        let b = BridgeRow {
            id: 1,
            finding_id: "a".into(),
            title: "Open Redis".into(),
            severity: "high".into(),
            source: "redis_security".into(),
            status: "OPEN".into(),
            target: "10.0.0.8".into(),
            client_id: Some(1),
            raw_data: json!({"live_verification": {"verdict": "NOISE"}}),
            discovered_at: "2026-09-12T00:00:00Z".into(),
            signature_hash: "x".into(),
            report_run_id: Some(1),
            engine_id: "redis_security".into(),
            proof_kind: None,
            cortex_status: "mapped".into(),
            cortex_external_ref: None,
            xdr_had_matching_alert: None,
        };
        let (ok, _, err) = classify(&b);
        assert!(!ok);
        assert!(err.contains("noise"));
    }

    #[test]
    fn classify_accepts_oast_proof() {
        let b = BridgeRow {
            id: 1,
            finding_id: "a".into(),
            title: "SSRF via webhook".into(),
            severity: "high".into(),
            source: "ssrf_advanced".into(),
            status: "OPEN".into(),
            target: "https://api.acme.test".into(),
            client_id: Some(1),
            raw_data: json!({"oast_callback": "https://oast.example/id"}),
            discovered_at: "2026-09-12T00:00:00Z".into(),
            signature_hash: "x".into(),
            report_run_id: Some(1),
            engine_id: "ssrf_advanced".into(),
            proof_kind: Some("oast_callback".into()),
            cortex_status: "mapped".into(),
            cortex_external_ref: None,
            xdr_had_matching_alert: None,
        };
        let (ok, _, gate) = classify(&b);
        assert!(ok);
        assert!(gate.contains("oast"));
    }
}
