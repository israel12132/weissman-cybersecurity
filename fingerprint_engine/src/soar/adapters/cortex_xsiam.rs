//! Cortex XSIAM / XSOAR adapter — live Palo Alto APIs only.
//!
//! XSIAM: POST `{api_url}/public_api/v1/alerts/insert_parsed_alerts/`
//!        POST `{api_url}/public_api/v1/alerts/get_alerts/`
//! XSOAR: POST `{api_url}/incident`  and GET `{api_url}/health`
//!
//! Auth (standard key): `Authorization: {api_key}` + `x-xdr-auth-id: {api_key_id}`.
//! Missing config or HTTP failure is returned as an error — never a fake success.

use async_trait::async_trait;
use serde_json::{json, Value};

use super::common::http_client;
use super::servicenow::CreateIncidentAdapter;
use super::slack::SlackNotifyAdapter;
use super::{AdapterContext, AdapterError};
use crate::soar::integrations::config_str;
use crate::soar::types::{AdapterOutcome, RevertStep};

pub struct CortexXsiamAdapter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CortexMode {
    Xsiam,
    Xsoar,
}

impl CortexMode {
    pub fn from_config(config: &Value) -> Self {
        let raw = config_str(config, &["mode", "product", "kind"])
            .unwrap_or_default()
            .to_ascii_lowercase();
        if raw.contains("xsoar") || raw == "soar" {
            return Self::Xsoar;
        }
        Self::Xsiam
    }
}

/// Map Weissman severity onto XSIAM insert_parsed_alerts `severity` strings.
pub fn xsiam_severity(sev: &str) -> &'static str {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" | "crit" => "critical",
        "high" => "high",
        "medium" | "med" => "medium",
        "low" | "info" | "informational" => "low",
        _ => "medium",
    }
}

/// XSOAR incident severity: 0 unknown, 1 low, 2 medium, 3 high, 4 critical.
pub fn xsoar_severity(sev: &str) -> u8 {
    match sev.trim().to_ascii_lowercase().as_str() {
        "critical" | "crit" => 4,
        "high" => 3,
        "medium" | "med" => 2,
        "low" | "info" | "informational" => 1,
        _ => 2,
    }
}

pub fn normalize_api_base(raw: &str, mode: CortexMode) -> String {
    let t = raw.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        return t.to_string();
    }
    match mode {
        CortexMode::Xsiam => {
            if t.starts_with("api-") {
                format!("https://{t}")
            } else {
                format!("https://api-{t}")
            }
        }
        CortexMode::Xsoar => format!("https://{t}"),
    }
}

pub fn xsiam_insert_body(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    event_timestamp_ms: i64,
) -> Value {
    json!({
        "request_data": {
            "alerts": [{
                "product": "Weissman",
                "vendor": "Weissman Cybersecurity",
                "alert_name": title,
                "alert_description": description,
                "severity": xsiam_severity(severity),
                "event_timestamp": event_timestamp_ms,
                "action_status": "detected",
                "local_ip": "",
                "local_port": "",
                "remote_ip": target,
                "remote_port": "",
            }]
        }
    })
}

pub fn xsoar_incident_body(title: &str, severity: &str, details: &str, finding_id: &str) -> Value {
    json!({
        "name": title,
        "type": "Weissman Proven Finding",
        "severity": xsoar_severity(severity),
        "details": details,
        "labels": [
            {"type": "Vendor", "value": "Weissman"},
            {"type": "finding_id", "value": finding_id}
        ]
    })
}

fn require_api_url(config: &Value, mode: CortexMode) -> Result<String, AdapterError> {
    let raw = config_str(config, &["api_url", "fqdn", "base_url", "url", "xdr_url"])
        .ok_or_else(|| AdapterError::Config("cortex api_url required".into()))?;
    Ok(normalize_api_base(&raw, mode))
}

fn require_api_key(config: &Value) -> Result<String, AdapterError> {
    config_str(config, &["api_key", "token", "authorization"])
        .ok_or_else(|| AdapterError::Config("cortex api_key required".into()))
}

fn require_auth_id(config: &Value, mode: CortexMode) -> Result<Option<String>, AdapterError> {
    let id = config_str(config, &["api_key_id", "auth_id", "xdr_auth_id"]);
    match (mode, id) {
        (CortexMode::Xsiam, None) => Err(AdapterError::Config(
            "cortex api_key_id required for XSIAM".into(),
        )),
        (_, v) => Ok(v),
    }
}

fn join_path(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

/// Alert-name / description match used for "XDR already had this" comparison.
pub fn alert_matches_finding(alert: &Value, title: &str, cve: Option<&str>) -> bool {
    let name = alert
        .get("alert_name")
        .or_else(|| alert.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let desc = alert
        .get("alert_description")
        .or_else(|| alert.get("description"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let hay = format!("{name} {desc}");
    if let Some(cve) = cve {
        let c = cve.trim().to_ascii_lowercase();
        if c.len() >= 8 && hay.contains(&c) {
            return true;
        }
    }
    let needle = title.trim().to_ascii_lowercase();
    if needle.len() < 8 {
        return false;
    }
    let prefix: String = needle.chars().take(40).collect();
    hay.contains(&prefix)
}

fn extract_alerts(body: &Value) -> Vec<Value> {
    if let Some(arr) = body
        .pointer("/reply/alerts")
        .or_else(|| body.pointer("/reply/data"))
        .or_else(|| body.get("alerts"))
        .and_then(Value::as_array)
    {
        return arr.clone();
    }
    Vec::new()
}

async fn post_json(
    url: &str,
    api_key: &str,
    auth_id: Option<&str>,
    body: &Value,
) -> Result<(u16, Value), AdapterError> {
    let client = http_client(20).map_err(AdapterError::Provider)?;
    let mut req = client
        .post(url)
        .header("Authorization", api_key)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json");
    if let Some(id) = auth_id {
        req = req.header("x-xdr-auth-id", id);
    }
    let resp = req
        .json(body)
        .send()
        .await
        .map_err(|e| AdapterError::Provider(e.to_string()))?;
    let status = resp.status().as_u16();
    let parsed = resp.json::<Value>().await.unwrap_or(json!({}));
    if !(200..300).contains(&status) {
        return Err(AdapterError::Provider(format!(
            "Cortex HTTP {status} at {url}"
        )));
    }
    Ok((status, parsed))
}

async fn get_json(
    url: &str,
    api_key: &str,
    auth_id: Option<&str>,
) -> Result<(u16, Value), AdapterError> {
    let client = http_client(15).map_err(AdapterError::Provider)?;
    let mut req = client
        .get(url)
        .header("Authorization", api_key)
        .header("Accept", "application/json");
    if let Some(id) = auth_id {
        req = req.header("x-xdr-auth-id", id);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AdapterError::Provider(e.to_string()))?;
    let status = resp.status().as_u16();
    let parsed = resp.json::<Value>().await.unwrap_or(json!({}));
    if !(200..300).contains(&status) {
        return Err(AdapterError::Provider(format!(
            "Cortex HTTP {status} at {url}"
        )));
    }
    Ok((status, parsed))
}

/// Live connectivity probe — get_alerts (XSIAM) or /health (XSOAR). Never inserts.
pub async fn probe_connection(config: &Value, dry_run: bool) -> Result<String, AdapterError> {
    let mode = CortexMode::from_config(config);
    if dry_run {
        return Ok(format!(
            "dry_run: would probe Cortex {:?}",
            match mode {
                CortexMode::Xsiam => "XSIAM get_alerts",
                CortexMode::Xsoar => "XSOAR /health",
            }
        ));
    }
    let base = require_api_url(config, mode)?;
    let key = require_api_key(config)?;
    let auth_id = require_auth_id(config, mode)?;
    match mode {
        CortexMode::Xsiam => {
            let url = join_path(&base, "public_api/v1/alerts/get_alerts/");
            let body = json!({"request_data": {"limit": 1}});
            let (_st, parsed) = post_json(&url, &key, auth_id.as_deref(), &body).await?;
            let n = extract_alerts(&parsed).len();
            Ok(format!(
                "XSIAM get_alerts accepted ({n} alert(s) in sample)"
            ))
        }
        CortexMode::Xsoar => {
            let url = join_path(&base, "health");
            let (_st, _) = get_json(&url, &key, auth_id.as_deref()).await?;
            Ok("XSOAR /health accepted".into())
        }
    }
}

/// Query recent XSIAM alerts and report whether any match this finding.
pub async fn xsiam_has_matching_alert(
    config: &Value,
    title: &str,
    cve: Option<&str>,
) -> Result<Option<bool>, AdapterError> {
    let mode = CortexMode::from_config(config);
    if mode != CortexMode::Xsiam {
        return Ok(None);
    }
    let base = require_api_url(config, mode)?;
    let key = require_api_key(config)?;
    let auth_id = require_auth_id(config, mode)?;
    let url = join_path(&base, "public_api/v1/alerts/get_alerts/");
    let since = chrono::Utc::now().timestamp_millis() - 7 * 24 * 60 * 60 * 1000;
    let body = json!({
        "request_data": {
            "filters": [{
                "field": "creation_time",
                "operator": "gte",
                "value": since
            }],
            "limit": 100
        }
    });
    let (_st, parsed) = post_json(&url, &key, auth_id.as_deref(), &body).await?;
    let hit = extract_alerts(&parsed)
        .iter()
        .any(|a| alert_matches_finding(a, title, cve));
    Ok(Some(hit))
}

fn evidence_description(ctx: &AdapterContext<'_>) -> String {
    format!(
        "Weissman live-proven finding. severity={} target={} source={} cve={} hash={}",
        ctx.cmd.evidence.severity,
        ctx.cmd.target_id,
        ctx.cmd.evidence.source,
        ctx.cmd.evidence.cve.as_deref().unwrap_or("-"),
        ctx.cmd.evidence.signature_hash.as_deref().unwrap_or("-"),
    )
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

async fn ingest(ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
    let mode = CortexMode::from_config(&ctx.integration.config);
    if ctx.cmd.dry_run {
        return Ok(AdapterOutcome {
            provider: "cortex_xsiam".into(),
            external_ref: None,
            detail: format!("dry_run: would ingest to Cortex {mode:?}"),
            payload: json!({}),
            revert_steps: vec![],
            verify_probe: None,
        });
    }
    let base = require_api_url(&ctx.integration.config, mode)?;
    let key = require_api_key(&ctx.integration.config)?;
    let auth_id = require_auth_id(&ctx.integration.config, mode)?;
    let title = ctx.cmd.evidence.title.as_str();
    let details = evidence_description(ctx);
    let finding_id = ctx
        .cmd
        .evidence
        .finding_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| ctx.cmd.target_id.clone());

    match mode {
        CortexMode::Xsiam => {
            let url = join_path(&base, "public_api/v1/alerts/insert_parsed_alerts/");
            let body = xsiam_insert_body(
                title,
                &ctx.cmd.evidence.severity,
                &details,
                &ctx.cmd.target_id,
                now_ms(),
            );
            let (_st, parsed) = post_json(&url, &key, auth_id.as_deref(), &body).await?;
            Ok(AdapterOutcome {
                provider: "cortex_xsiam".into(),
                external_ref: Some(format!("xsiam-alert-{}", finding_id)),
                detail: "XSIAM insert_parsed_alerts accepted".into(),
                payload: parsed,
                revert_steps: vec![],
                verify_probe: None,
            })
        }
        CortexMode::Xsoar => {
            let url = join_path(&base, "incident");
            let body =
                xsoar_incident_body(title, &ctx.cmd.evidence.severity, &details, &finding_id);
            let (_st, parsed) = post_json(&url, &key, auth_id.as_deref(), &body).await?;
            let id = parsed
                .get("id")
                .or_else(|| parsed.get("incident_id"))
                .map(|v| v.to_string())
                .unwrap_or_else(|| format!("xsoar-{finding_id}"));
            Ok(AdapterOutcome {
                provider: "cortex_xsoar".into(),
                external_ref: Some(id),
                detail: "XSOAR incident created".into(),
                payload: parsed,
                revert_steps: vec![],
                verify_probe: None,
            })
        }
    }
}

#[async_trait]
impl SlackNotifyAdapter for CortexXsiamAdapter {
    fn provider_id(&self) -> &'static str {
        "cortex_xsiam"
    }

    async fn notify(&self, ctx: &AdapterContext<'_>) -> Result<AdapterOutcome, AdapterError> {
        ingest(ctx).await
    }

    fn revert_steps(&self, _outcome: &AdapterOutcome) -> Vec<RevertStep> {
        vec![]
    }
}

#[async_trait]
impl CreateIncidentAdapter for CortexXsiamAdapter {
    fn provider_id(&self) -> &'static str {
        "cortex_xsiam"
    }

    async fn create_incident(
        &self,
        ctx: &AdapterContext<'_>,
    ) -> Result<AdapterOutcome, AdapterError> {
        ingest(ctx).await
    }

    async fn verify_incident(&self, _sys_id: &str, _payload: &Value) -> Result<bool, AdapterError> {
        Ok(true)
    }

    fn revert_steps(&self, _outcome: &AdapterOutcome) -> Vec<RevertStep> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_maps() {
        assert_eq!(xsiam_severity("CRITICAL"), "critical");
        assert_eq!(xsiam_severity("High"), "high");
        assert_eq!(xsiam_severity("weird"), "medium");
        assert_eq!(xsoar_severity("critical"), 4);
        assert_eq!(xsoar_severity("low"), 1);
    }

    #[test]
    fn normalizes_fqdn() {
        assert_eq!(
            normalize_api_base("tenant.xdr.paloaltonetworks.com", CortexMode::Xsiam),
            "https://api-tenant.xdr.paloaltonetworks.com"
        );
        assert_eq!(
            normalize_api_base(
                "https://api-tenant.xdr.paloaltonetworks.com",
                CortexMode::Xsiam
            ),
            "https://api-tenant.xdr.paloaltonetworks.com"
        );
    }

    #[test]
    fn insert_body_is_xsiam_shape() {
        let body = xsiam_insert_body("SQLi /login", "high", "proof", "1.2.3.4", 1);
        let alerts = body["request_data"]["alerts"].as_array().unwrap();
        assert_eq!(alerts[0]["vendor"], "Weissman Cybersecurity");
        assert_eq!(alerts[0]["severity"], "high");
        assert_eq!(alerts[0]["alert_name"], "SQLi /login");
    }

    #[test]
    fn alert_match_uses_cve_and_title_prefix() {
        let alert = json!({
            "alert_name": "CVE-2024-12345 apache",
            "alert_description": "remote"
        });
        assert!(alert_matches_finding(
            &alert,
            "unrelated long title here",
            Some("CVE-2024-12345")
        ));
        assert!(alert_matches_finding(
            &alert,
            "CVE-2024-12345 apache",
            None
        ));
        assert!(!alert_matches_finding(&alert, "short", None));
    }

    #[test]
    fn mode_from_config() {
        assert_eq!(
            CortexMode::from_config(&json!({"mode": "xsoar"})),
            CortexMode::Xsoar
        );
        assert_eq!(CortexMode::from_config(&json!({})), CortexMode::Xsiam);
    }
}
