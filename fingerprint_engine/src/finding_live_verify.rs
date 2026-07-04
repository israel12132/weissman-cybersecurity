//! Multi-tier live finding validity verification.
//!
//! Separates confirmed, evidence-backed vulnerabilities from noise and false positives
//! by combining: tamper-evident attestation, evidence gate, client scope alignment,
//! target reachability, optional HTTP PoC replay, and optional engine re-scan.

use crate::engine_dispatch::run_engine;
use crate::remediation_verify::finding_still_present;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyCheck {
    pub id: String,
    pub label: String,
    pub passed: bool,
    pub detail: String,
    pub weight: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LiveVerifyResult {
    pub verdict: String,
    pub confidence: f64,
    pub checks: Vec<VerifyCheck>,
    pub verified_at: String,
    pub reproducible: bool,
    pub recommended_status: Option<String>,
}

struct FindingRow {
    id: i64,
    finding_id: String,
    title: String,
    severity: String,
    source: String,
    target: String,
    client_id: Option<i64>,
    raw_data: Value,
    discovered_at: String,
}

fn push_check(
    checks: &mut Vec<VerifyCheck>,
    id: &str,
    label: &str,
    passed: bool,
    detail: String,
    weight: f64,
) {
    checks.push(VerifyCheck {
        id: id.to_string(),
        label: label.to_string(),
        passed,
        detail,
        weight,
    });
}

fn weighted_confidence(checks: &[VerifyCheck]) -> f64 {
    let total: f64 = checks.iter().map(|c| c.weight).sum();
    if total <= 0.0 {
        return 0.0;
    }
    let passed: f64 = checks
        .iter()
        .filter(|c| c.passed)
        .map(|c| c.weight)
        .sum();
    (passed / total).clamp(0.0, 1.0)
}

fn verdict_from(confidence: f64, reproducible: bool, evidence_ok: bool) -> (&'static str, Option<&'static str>) {
    if !evidence_ok && confidence < 0.35 {
        return ("NOISE", Some("FALSE_POSITIVE"));
    }
    if reproducible && confidence >= 0.75 {
        return ("CONFIRMED", Some("ACKNOWLEDGED"));
    }
    if confidence >= 0.82 {
        return ("CONFIRMED", Some("ACKNOWLEDGED"));
    }
    if confidence >= 0.58 {
        return ("LIKELY_VALID", None);
    }
    if confidence >= 0.38 {
        return ("INCONCLUSIVE", None);
    }
    ("NOISE", Some("FALSE_POSITIVE"))
}

fn parse_client_domains(domains_raw: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(domains_raw)
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

fn target_in_client_scope(target: &str, domains: &[String]) -> bool {
    if domains.is_empty() {
        return true;
    }
    let t = target.trim().to_ascii_lowercase();
    if t.is_empty() {
        return false;
    }
    domains.iter().any(|d| {
        let dom = d
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        t.contains(dom) || dom.contains(&t.replace("https://", "").replace("http://", ""))
    })
}

fn looks_like_url_or_host(s: &str) -> bool {
    let t = s.trim();
    t.starts_with("http://")
        || t.starts_with("https://")
        || (t.contains('.') && !t.contains(' ') && t.len() >= 4)
}

fn extract_probe_url(target: &str, raw: &Value) -> Option<String> {
    for key in ["url", "affected_url", "target_url", "asset_url"] {
        if let Some(u) = raw.get(key).and_then(Value::as_str) {
            let t = u.trim();
            if t.starts_with("http") {
                return Some(t.to_string());
            }
        }
    }
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        return Some(t.to_string());
    }
    if looks_like_url_or_host(t) {
        return Some(format!("https://{}", t.trim_start_matches('/')));
    }
    None
}

fn evidence_markers(raw: &Value) -> Vec<String> {
    let mut markers = Vec::new();
    for key in ["status", "http_status", "response_code"] {
        if let Some(n) = raw.get(key).and_then(Value::as_u64) {
            markers.push(n.to_string());
        }
    }
    if let Some(ev) = raw.get("evidence") {
        if let Some(s) = ev.get("proof").and_then(Value::as_str) {
            for token in ["HTTP/", "status=", "status:", "200", "301", "302", "403", "404", "500"] {
                if s.contains(token) {
                    markers.push(token.to_string());
                }
            }
        }
    }
    markers.sort();
    markers.dedup();
    markers
}

async fn http_probe(url: &str) -> (bool, String, u16) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(3))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
    {
        Ok(c) => c,
        Err(e) => return (false, format!("client: {e}"), 0),
    };
    let resp = match client.head(url).send().await {
        Ok(r) => r,
        Err(_) => match client.get(url).send().await {
            Ok(r) => r,
            Err(e) => return (false, format!("unreachable: {e}"), 0),
        },
    };
    let status = resp.status().as_u16();
    (
        status > 0,
        format!("HTTP {status}"),
        status,
    )
}

async fn replay_curl_proof(proof: &str) -> (bool, String) {
    let proof = proof.trim();
    if !proof.to_ascii_lowercase().starts_with("curl ") {
        return (false, "no curl PoC in evidence".into());
    }
    match crate::verification_sandbox::parse_curl_request(proof) {
        Ok((method, url, headers, body)) => {
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::limited(5))
                .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
                .build()
            {
                Ok(c) => c,
                Err(e) => return (false, format!("client: {e}")),
            };
            let mut req = client.request(method, &url);
            for (k, v) in headers.iter() {
                req = req.header(k, v);
            }
            if let Some(b) = body {
                req = req.body(b);
            }
            match req.send().await {
                Ok(r) => {
                    let st = r.status().as_u16();
                    let body_snip = r.text().await.unwrap_or_default();
                    let snip = body_snip.chars().take(120).collect::<String>();
                    (st > 0, format!("replay HTTP {st} — {snip}"))
                }
                Err(e) => (false, format!("replay failed: {e}")),
            }
        }
        Err(e) => (false, format!("curl parse: {e}")),
    }
}

async fn load_finding(pool: &PgPool, tenant_id: i64, row_id: i64) -> Result<FindingRow, String> {
    let row = sqlx::query(
        r#"SELECT id, finding_id, title, severity, source,
                  COALESCE(raw_data->>'target', '') AS target,
                  client_id, COALESCE(raw_data, '{}'::jsonb) AS raw_data,
                  COALESCE(to_char(discovered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '') AS discovered_at
             FROM vulnerabilities
            WHERE id = $1 AND tenant_id = $2"#,
    )
    .bind(row_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("db: {e}"))?
    .ok_or_else(|| "finding not found".to_string())?;

    Ok(FindingRow {
        id: row.try_get("id").unwrap_or(0),
        finding_id: row.try_get("finding_id").unwrap_or_default(),
        title: row.try_get("title").unwrap_or_default(),
        severity: row.try_get("severity").unwrap_or_default(),
        source: row.try_get("source").unwrap_or_default(),
        target: row.try_get("target").unwrap_or_default(),
        client_id: row.try_get("client_id").ok(),
        raw_data: row
            .try_get::<Value, _>("raw_data")
            .unwrap_or_else(|_| json!({})),
        discovered_at: row.try_get("discovered_at").unwrap_or_default(),
    })
}

async fn load_client_domains(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Vec<String> {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(domains::text, '[]') FROM clients WHERE id = $1 AND tenant_id = $2",
    )
    .bind(client_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    raw.map(|s| parse_client_domains(&s)).unwrap_or_default()
}

/// Run multi-tier live verification for a persisted finding row.
pub async fn verify_finding_live(
    pool: &PgPool,
    tenant_id: i64,
    row_id: i64,
    deep_rescan: bool,
) -> Result<LiveVerifyResult, String> {
    let row = load_finding(pool, tenant_id, row_id).await?;
    let mut checks = Vec::new();

    let att_receipt = row
        .raw_data
        .get("attestation")
        .and_then(|a| a.get("receipt"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let att_ok = !att_receipt.is_empty()
        && crate::finding_attestation::verify_finding(
            &row.finding_id,
            &row.title,
            &row.severity,
            &row.target,
            &row.discovered_at,
            att_receipt,
        );
    push_check(
        &mut checks,
        "attestation",
        "Tamper-evident attestation",
        att_ok,
        if att_receipt.is_empty() {
            "no attestation receipt on row".into()
        } else if att_ok {
            "HMAC receipt matches stored fields".into()
        } else {
            "receipt mismatch — row may have been altered".into()
        },
        0.15,
    );

    let gated = crate::findings_gate::gate_finding(&row.source, &row.target, row.raw_data.clone());
    let evidence_ok = gated.is_some();
    push_check(
        &mut checks,
        "evidence_gate",
        "Evidence quality gate",
        evidence_ok,
        if evidence_ok {
            "actionable proof passes findings gate".into()
        } else {
            "missing or weak proof — likely noise".into()
        },
        0.22,
    );

    let mut scope_ok = true;
    let mut scope_detail = "no client scope configured".to_string();
    if let Some(cid) = row.client_id {
        let domains = load_client_domains(pool, tenant_id, cid).await;
        scope_ok = target_in_client_scope(&row.target, &domains);
        scope_detail = if scope_ok {
            format!("target aligns with client scope ({} domains)", domains.len())
        } else {
            format!(
                "target '{}' outside client scope {:?}",
                row.target,
                domains.iter().take(3).collect::<Vec<_>>()
            )
        };
    }
    push_check(
        &mut checks,
        "scope",
        "Client scope alignment",
        scope_ok,
        scope_detail,
        0.13,
    );

    let url_shape_ok = looks_like_url_or_host(&row.target)
        || extract_probe_url(&row.target, &row.raw_data).is_some();
    push_check(
        &mut checks,
        "target_shape",
        "Target is a real asset URL/host",
        url_shape_ok,
        if url_shape_ok {
            "target looks like a scannable asset".into()
        } else {
            "target is a label/campaign name, not a URL — high noise risk".into()
        },
        0.10,
    );

    let mut reachable = false;
    let mut reach_detail = "no probe URL".to_string();
    if let Some(url) = extract_probe_url(&row.target, &row.raw_data) {
        let (ok, detail, status) = http_probe(&url).await;
        reachable = ok;
        reach_detail = detail;
        let markers = evidence_markers(&row.raw_data);
        if !markers.is_empty() && status > 0 {
            let marker_hit = markers.iter().any(|m| m.parse::<u16>().ok() == Some(status))
                || markers.iter().any(|m| reach_detail.contains(m));
            push_check(
                &mut checks,
                "marker_match",
                "Live response matches evidence markers",
                marker_hit,
                if marker_hit {
                    format!("HTTP {status} consistent with stored evidence")
                } else {
                    format!("HTTP {status} — markers {:?} not matched", markers)
                },
                0.12,
            );
        }
    }
    push_check(
        &mut checks,
        "reachability",
        "Target reachable (live HTTP)",
        reachable,
        reach_detail,
        0.10,
    );

    let proof = row
        .raw_data
        .get("evidence")
        .and_then(|e| e.get("proof"))
        .and_then(Value::as_str)
        .or_else(|| row.raw_data.get("proof").and_then(Value::as_str))
        .unwrap_or("");
    if proof.to_ascii_lowercase().starts_with("curl ") {
        let (replay_ok, replay_detail) = replay_curl_proof(proof).await;
        push_check(
            &mut checks,
            "poc_replay",
            "PoC curl replay",
            replay_ok,
            replay_detail,
            0.18,
        );
    }

    let mut reproducible = false;
    if deep_rescan
        && !row.source.is_empty()
        && !row.target.is_empty()
        && extract_probe_url(&row.target, &row.raw_data).is_some()
    {
        let target = extract_probe_url(&row.target, &row.raw_data).unwrap_or_else(|| row.target.clone());
        let ctx = crate::remediation_verify::verify_context(
            std::sync::Arc::new(pool.clone()),
            tenant_id,
            row.client_id,
        );
        let engine = row.source.clone();
        let fid = row.finding_id.clone();
        let rescan = tokio::time::timeout(
            Duration::from_secs(90),
            run_engine(&engine, &target, &ctx),
        )
        .await;
        match rescan {
            Ok(result) => {
                reproducible = finding_still_present(&fid, &engine, &target, &result.findings);
                push_check(
                    &mut checks,
                    "engine_rescan",
                    "Engine re-scan reproduction",
                    reproducible,
                    if reproducible {
                        format!(
                            "same finding_id reproduced ({} findings on re-scan)",
                            result.findings.len()
                        )
                    } else {
                        format!(
                            "finding not reproduced on live re-scan ({} findings returned)",
                            result.findings.len()
                        )
                    },
                    0.25,
                );
            }
            Err(_) => {
                push_check(
                    &mut checks,
                    "engine_rescan",
                    "Engine re-scan reproduction",
                    false,
                    "re-scan timed out after 90s".into(),
                    0.25,
                );
            }
        }
    }

    let confidence = weighted_confidence(&checks);
    let (verdict, recommended) = verdict_from(confidence, reproducible, evidence_ok);
    let verified_at = chrono::Utc::now().to_rfc3339();

    let result = LiveVerifyResult {
        verdict: verdict.to_string(),
        confidence,
        checks,
        verified_at: verified_at.clone(),
        reproducible,
        recommended_status: recommended.map(str::to_string),
    };

    let payload = json!({
        "verified_at": verified_at,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "reproducible": result.reproducible,
        "checks": result.checks,
        "recommended_status": result.recommended_status,
        "method": "multi_tier_live",
    });

    sqlx::query(
        r#"UPDATE vulnerabilities
              SET raw_data = jsonb_set(
                      COALESCE(raw_data, '{}'::jsonb),
                      '{live_verification}',
                      $1::jsonb,
                      true
                  ),
                  updated_at = now()
            WHERE id = $2 AND tenant_id = $3"#,
    )
    .bind(payload.to_string())
    .bind(row_id)
    .bind(tenant_id)
    .execute(pool)
    .await
    .map_err(|e| format!("persist verification: {e}"))?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_matches_tesla_domains() {
        let domains = vec!["https://www.tesla.com".into(), "tesla.com".into()];
        assert!(target_in_client_scope("https://www.tesla.com/actuator", &domains));
        assert!(!target_in_client_scope("Password Reset Campaign", &domains));
    }

    #[test]
    fn verdict_confirmed_when_high_confidence() {
        let (v, _) = verdict_from(0.9, false, true);
        assert_eq!(v, "CONFIRMED");
    }
}
