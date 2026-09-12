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

const SEALED_MARK: &str = "[SEALED";

fn live_verdict(raw: &Value) -> Option<String> {
    raw.get("live_verification")
        .and_then(|v| v.get("verdict"))
        .and_then(Value::as_str)
        .or_else(|| raw.get("live_verdict").and_then(Value::as_str))
        .map(|s| s.trim().to_ascii_uppercase())
}

fn workflow_status(row: &FindingRow) -> String {
    let from_raw = row
        .raw_data
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("");
    let s = if row.status.trim().is_empty() {
        from_raw
    } else {
        row.status.as_str()
    };
    s.trim().to_ascii_uppercase()
}

fn is_usable_proof_str(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && !t.contains(SEALED_MARK) && t != "••••••••"
}

fn value_is_proof(v: &Value) -> bool {
    match v {
        Value::String(s) => is_usable_proof_str(s),
        Value::Number(n) => n.as_i64() != Some(0) && n.as_u64() != Some(0),
        Value::Object(o) if !o.is_empty() => {
            !o.values().all(|x| matches!(x, Value::Null | Value::Bool(false)))
        }
        Value::Bool(true) => true,
        Value::Array(a) if !a.is_empty() => true,
        _ => false,
    }
}

fn scan_proof_map(obj: &Value) -> Option<&'static str> {
    for key in [
        "oast_callback",
        "oast",
        "poc_exploit",
        "poc",
        "proof",
        "http_evidence",
        "http_status",
        "evidence",
    ] {
        if let Some(v) = obj.get(key) {
            if value_is_proof(v) {
                return Some(key);
            }
        }
    }
    None
}

fn proof_artifact(row: &FindingRow) -> Option<&'static str> {
    if is_usable_proof_str(&row.poc_exploit) {
        return Some("poc_exploit");
    }
    if is_usable_proof_str(&row.proof) {
        return Some("proof");
    }
    if let Some(k) = scan_proof_map(&row.raw_data) {
        return Some(k);
    }
    if let Some(k) = row.raw_data.get("raw").and_then(scan_proof_map) {
        return Some(k);
    }
    row.raw_data.get("evidence").and_then(scan_proof_map)
}

pub(crate) fn push_eligibility(row: &FindingRow) -> Result<String, String> {
    match workflow_status(row).as_str() {
        "FALSE_POSITIVE" | "REJECTED" | "SUPPRESSED" | "NOISE" => {
            return Err(
                "finding workflow status is false-positive/suppressed — not pushing to Cortex"
                    .into(),
            );
        }
        _ => {}
    }
    match live_verdict(&row.raw_data).as_deref() {
        Some("NOISE") | Some("FALSE_POSITIVE") => {
            Err("finding live-verified as noise/false-positive — not pushing to Cortex".into())
        }
        Some("CONFIRMED") => Ok("live_verdict:CONFIRMED".into()),
        Some("LIKELY_VALID") => Ok("live_verdict:LIKELY_VALID".into()),
        _ => match proof_artifact(row) {
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

pub async fn push_finding_to_cortex(
    pool: &PgPool,
    tenant_id: i64,
    id_token: &str,
    dry_run: bool,
) -> Result<Value, (u16, String)> {
    if dry_run {
        return Err((
            400,
            "POST /api/findings/:id/push-cortex is live-only — dry_run is not allowed".into(),
        ));
    }
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
    let xdr_had =
        match xsiam_has_matching_alert(&integration.config, &row.title, cve.as_deref()).await {
            Ok(v) => v,
            Err(AdapterError::Config(e)) => return Err((409, e)),
            Err(e) => return Err((502, e.to_string())),
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
        false,
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
        "dry_run": false,
        "xdr_had_matching_alert": xdr_had,
    });
    let persist_error = persist_push(pool, tenant_id, row.id, &record)
        .await
        .err();

    Ok(json!({
        "ok": true,
        "id": row.id,
        "finding_id": row.finding_id,
        "provider": outcome.provider,
        "external_ref": outcome.external_ref,
        "detail": outcome.detail,
        "gate": gate,
        "dry_run": false,
        "xdr_had_matching_alert": xdr_had,
        "persisted": persist_error.is_none(),
        "persist_error": persist_error,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(verdict: Option<&str>, extra: Value) -> FindingRow {
        row_status("OPEN", verdict, extra)
    }

    fn row_status(status: &str, verdict: Option<&str>, extra: Value) -> FindingRow {
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
            status: status.into(),
            proof: String::new(),
            poc_exploit: String::new(),
        }
    }

    #[test]
    fn rejects_noise() {
        let err = push_eligibility(&row(Some("NOISE"), json!({}))).unwrap_err();
        assert!(err.contains("noise"));
    }

    #[test]
    fn rejects_workflow_false_positive() {
        let err = push_eligibility(&row_status(
            "FALSE_POSITIVE",
            Some("CONFIRMED"),
            json!({"oast_callback": "https://oast.example/id"}),
        ))
        .unwrap_err();
        assert!(err.contains("false-positive"));
    }

    #[test]
    fn attestation_alone_is_not_proof() {
        assert!(push_eligibility(&row(
            None,
            json!({"attestation": {"receipt": "wzat1:deadbeef"}})
        ))
        .is_err());
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
    fn accepts_nested_poc() {
        let ok = push_eligibility(&row(None, json!({"raw": {"poc": "curl -I https://x"}})))
            .unwrap();
        assert!(ok.contains("poc"));
    }

    #[test]
    fn rejects_sealed_placeholder() {
        let mut r = row(None, json!({}));
        r.proof = "[SEALED — use Command Center «Decrypt Exploit Evidence»]".into();
        assert!(push_eligibility(&r).is_err());
    }

    #[test]
    fn rejects_empty_proof() {
        assert!(push_eligibility(&row(None, json!({}))).is_err());
    }
}
