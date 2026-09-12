//! Push an evidence-backed finding into Cortex XSIAM / XSOAR.
//!
//! Live-only: refuses noise / false-positive verdicts and findings with no proof
//! artifact. Missing Cortex integration fails visibly (HTTP 409), never fakes delivery.

use serde_json::{json, Value};
use sqlx::PgPool;

use crate::finding_live_verify::{load_finding, FindingRow};
use crate::soar::adapters::cortex_xsiam::xsiam_has_matching_alert;
use crate::soar::adapters::{dispatch, AdapterError};
use crate::soar::engine::build_command;
use crate::soar::integrations::{load_integrations, IntegrationRecord};
use crate::soar::types::ThreatEvidence;

fn live_verdict(raw: &Value) -> Option<String> {
    raw.get("live_verification")
        .and_then(|v| v.get("verdict"))
        .and_then(Value::as_str)
        .map(|s| s.trim().to_ascii_uppercase())
}

/// Live vulnerability proof — **not** the persist-time attestation receipt.
/// Attestation only proves the row was not tampered with in Postgres.
pub(crate) fn proof_artifact(raw: &Value) -> Option<&'static str> {
    if let Some(kind) = proof_artifact_in(raw) {
        return Some(kind);
    }
    if let Some(nested) = raw.get("raw") {
        if let Some(kind) = proof_artifact_in(nested) {
            return Some(kind);
        }
    }
    None
}

fn proof_artifact_in(src: &Value) -> Option<&'static str> {
    for key in [
        "proof",
        "poc",
        "poc_exploit",
        "oast",
        "oast_callback",
        "http_status",
        "http_evidence",
    ] {
        match src.get(key) {
            Some(Value::String(s)) if !s.trim().is_empty() => return Some(key),
            Some(Value::Number(_)) => return Some(key),
            Some(Value::Object(o)) if !o.is_empty() => return Some(key),
            Some(Value::Bool(true)) => return Some(key),
            _ => {}
        }
    }
    match src.get("evidence") {
        Some(Value::String(s)) if !s.trim().is_empty() => return Some("evidence"),
        Some(Value::Object(o)) => {
            if o.get("proof")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.trim().is_empty())
            {
                return Some("evidence.proof");
            }
            if !o.is_empty() {
                return Some("evidence");
            }
        }
        _ => {}
    }
    None
}

pub(crate) fn push_eligibility(row: &FindingRow) -> Result<String, String> {
    match live_verdict(&row.raw_data).as_deref() {
        Some("NOISE") | Some("FALSE_POSITIVE") => {
            Err("finding live-verified as noise/false-positive — not pushing to Cortex".into())
        }
        Some("CONFIRMED") => Ok("live_verdict:CONFIRMED".into()),
        Some("LIKELY_VALID") => Ok("live_verdict:LIKELY_VALID".into()),
        _ => match proof_artifact(&row.raw_data) {
            Some(kind) => Ok(format!("proof_artifact:{kind}")),
            None => Err(
                "no live proof artifact — run Verify on the finding before pushing to Cortex"
                    .into(),
            ),
        },
    }
}

fn cve_of(row: &FindingRow) -> Option<String> {
    row.raw_data
        .get("cve")
        .or_else(|| row.raw_data.get("cve_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
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

async fn persist_push(
    pool: &PgPool,
    tenant_id: i64,
    row_id: i64,
    payload: &Value,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("db: {e}"))?;
    sqlx::query(
        r#"UPDATE vulnerabilities
              SET raw_data = jsonb_set(
                      COALESCE(raw_data, '{}'::jsonb),
                      '{cortex_push}',
                      $1::jsonb,
                      true
                  ),
                  updated_at = now()
            WHERE id = $2 AND tenant_id = $3"#,
    )
    .bind(payload.to_string())
    .bind(row_id)
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("db: {e}"))?;
    tx.commit().await.map_err(|e| format!("db: {e}"))?;
    Ok(())
}

/// Best-effort durable map update so Command Center scan→finding board
/// sees drawer pushes. Missing table must not fail the Cortex ingest.
async fn persist_bridge_push(
    pool: &PgPool,
    tenant_id: i64,
    finding_pk: i64,
    external_ref: Option<&str>,
    xdr_had: Option<bool>,
) -> Result<(), String> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id)
        .await
        .map_err(|e| format!("db: {e}"))?;
    let res = sqlx::query(
        r#"UPDATE scan_finding_bridge
              SET cortex_status = 'pushed',
                  cortex_external_ref = COALESCE($3, cortex_external_ref),
                  cortex_pushed_at = now(),
                  xdr_had_matching_alert = COALESCE($4, xdr_had_matching_alert),
                  updated_at = now()
            WHERE tenant_id = $1 AND finding_pk = $2"#,
    )
    .bind(tenant_id)
    .bind(finding_pk)
    .bind(external_ref)
    .bind(xdr_had)
    .execute(&mut *tx)
    .await;
    match res {
        Ok(_) => {
            tx.commit().await.map_err(|e| format!("db: {e}"))?;
            Ok(())
        }
        Err(e) => {
            let _ = tx.rollback().await;
            let msg = e.to_string();
            if msg.contains("scan_finding_bridge") {
                Ok(())
            } else {
                Err(format!("scan_finding_bridge: {e}"))
            }
        }
    }
}

pub async fn push_finding_to_cortex(
    pool: &PgPool,
    tenant_id: i64,
    id_token: &str,
    dry_run: bool,
) -> Result<Value, (u16, String)> {
    let row = load_finding(pool, tenant_id, id_token).await.map_err(|e| {
        if e == "finding not found" {
            (404, e)
        } else {
            (400, e)
        }
    })?;
    let gate = push_eligibility(&row).map_err(|e| (409, e))?;
    let integrations = load_integrations(pool, tenant_id).await;
    let Some(integration) = pick_cortex(&integrations) else {
        return Err((
            409,
            "Cortex XSIAM/XSOAR is not configured — add it under Integrations (api_url, api_key, api_key_id)".into(),
        ));
    };

    let cve = cve_of(&row);
    let xdr_had = if dry_run {
        None
    } else {
        match xsiam_has_matching_alert(&integration.config, &row.title, cve.as_deref()).await {
            Ok(v) => v,
            Err(AdapterError::Config(e)) => return Err((409, e)),
            Err(e) => return Err((502, e.to_string())),
        }
    };

    let evidence = ThreatEvidence {
        finding_id: Some(row.id),
        title: row.title.clone(),
        severity: row.severity.clone(),
        source: row.source.clone(),
        target: row.target.clone(),
        cve: cve.clone(),
        signature_hash: if row.signature_hash.is_empty() {
            None
        } else {
            Some(row.signature_hash.clone())
        },
        cvss: None,
        epss: None,
        kev: row
            .raw_data
            .get("kev")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        internet_exposed: row
            .raw_data
            .get("internet_exposed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        trigger_kind: "cortex_push".into(),
    };
    let cmd = build_command(
        "siem_ingest",
        tenant_id,
        row.client_id,
        None,
        row.target.clone(),
        json!({}),
        evidence,
        dry_run,
    );

    let outcome = dispatch(&cmd, pool, &integration)
        .await
        .map_err(|e| match e {
            AdapterError::Config(msg) => (409, msg),
            other => (502, other.to_string()),
        })?;

    let record = json!({
        "pushed_at": chrono::Utc::now().to_rfc3339(),
        "provider": outcome.provider,
        "external_ref": outcome.external_ref,
        "detail": outcome.detail,
        "gate": gate,
        "dry_run": dry_run,
        "xdr_had_matching_alert": xdr_had,
    });
    if !dry_run {
        let _ = persist_push(pool, tenant_id, row.id, &record).await;
        let _ = persist_bridge_push(
            pool,
            tenant_id,
            row.id,
            outcome.external_ref.as_deref(),
            xdr_had,
        )
        .await;
    }

    Ok(json!({
        "ok": true,
        "id": row.id,
        "finding_id": row.finding_id,
        "provider": outcome.provider,
        "external_ref": outcome.external_ref,
        "detail": outcome.detail,
        "gate": gate,
        "dry_run": dry_run,
        "xdr_had_matching_alert": xdr_had,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(verdict: Option<&str>, extra: Value) -> FindingRow {
        let mut raw = extra;
        if let Some(v) = verdict {
            raw["live_verification"] = json!({"verdict": v});
        }
        FindingRow {
            id: 1,
            finding_id: "abc".into(),
            title: "Open Redis without AUTH".into(),
            severity: "high".into(),
            source: "redis_security".into(),
            target: "10.0.0.8".into(),
            client_id: Some(1),
            raw_data: raw,
            discovered_at: "2026-09-11T00:00:00Z".into(),
            signature_hash: "deadbeef".into(),
        }
    }

    #[test]
    fn rejects_noise() {
        let err = push_eligibility(&row(Some("NOISE"), json!({}))).unwrap_err();
        assert!(err.contains("noise"));
    }

    #[test]
    fn accepts_confirmed() {
        assert!(push_eligibility(&row(Some("CONFIRMED"), json!({})))
            .unwrap()
            .contains("CONFIRMED"));
    }

    #[test]
    fn accepts_proof_without_verdict() {
        let ok = push_eligibility(&row(
            None,
            json!({"oast_callback": "https://oast.example/id"}),
        ))
        .unwrap();
        assert!(ok.contains("oast"));
    }

    #[test]
    fn rejects_empty_proof() {
        assert!(push_eligibility(&row(None, json!({}))).is_err());
    }

    #[test]
    fn rejects_attestation_only() {
        assert!(push_eligibility(&row(
            None,
            json!({"attestation": {"receipt": "not-a-vuln-proof"}})
        ))
        .is_err());
    }

    #[test]
    fn accepts_nested_engine_payload_oast() {
        let ok = push_eligibility(&row(
            None,
            json!({"raw": {"oast_callback": "https://oast.example/id"}}),
        ))
        .unwrap();
        assert!(ok.contains("oast"));
    }

    #[test]
    fn accepts_evidence_proof_object() {
        let ok = push_eligibility(&row(
            None,
            json!({"evidence": {"proof": "XSIAM get_alerts HTTP 2xx returned no match"}}),
        ))
        .unwrap();
        assert!(ok.contains("evidence"));
    }
}
