//! **LIQUID-MATRIX** — Moving Target Defense via TOTP-synchronized routing tokens.
//!
//! Routing rotation is persisted in DB and gateway fingerprint is probed live. SDN dataplane
//! enforcement is operator-configured via `WEISSMAN_LIQUID_MATRIX_SDN_ENFORCED` — never faked.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding, http_client, http_get};
use crate::engine_result::{print_result, EngineResult};
use crate::sovereign_defense_store::{self, LIQUID_MATRIX_ENGINE_ID};
use serde_json::{json, Map, Value};

const MITRE: &str = "T1599";

fn finding_evidence(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    evidence: Map<String, Value>,
) -> Value {
    let mut f = finding(
        LIQUID_MATRIX_ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("evidence".into(), Value::Object(evidence));
    }
    f
}

#[derive(Debug, Clone)]
pub struct LiquidMatrixConfig {
    pub rotation_step_secs: i32,
    pub port_pool_min: i32,
    pub port_pool_max: i32,
    pub probe_gateway: bool,
}

impl LiquidMatrixConfig {
    pub fn from_params(params: &Value) -> Self {
        Self {
            rotation_step_secs: pi64(params, "rotation_step_secs", 3).clamp(1, 60) as i32,
            port_pool_min: pi64(params, "port_pool_min", 30_000).clamp(1024, 65535) as i32,
            port_pool_max: pi64(params, "port_pool_max", 39_999).clamp(1024, 65535) as i32,
            probe_gateway: pbool(params, "probe_gateway", true),
        }
    }
}

fn pi64(p: &Value, k: &str, d: i64) -> i64 {
    p.get(k).and_then(Value::as_i64).unwrap_or(d)
}

fn pbool(p: &Value, k: &str, d: bool) -> bool {
    p.get(k).and_then(Value::as_bool).unwrap_or(d)
}

fn sdn_dataplane_enforced() -> bool {
    matches!(
        std::env::var("WEISSMAN_LIQUID_MATRIX_SDN_ENFORCED").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

pub async fn run_liquid_matrix_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let cfg = LiquidMatrixConfig::from_params(&ctx.job_params);
    let host = extract_host(target);

    let (pool, tenant_id, client_id) = match (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id) {
        (Some(p), Some(t), Some(c)) => (p.clone(), t, c),
        _ => {
            return EngineResult::error(
                "LIQUID-MATRIX requires client_id and database context — select a client in Command Center",
            );
        }
    };

    let rotation = match sovereign_defense_store::rotate_liquid_matrix(
        pool.as_ref(),
        tenant_id,
        client_id,
        cfg.rotation_step_secs,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => return EngineResult::error(format!("rotation: {e}")),
    };

    let mut ev = serde_json::Map::new();
    ev.insert("epoch".into(), json!(rotation.epoch));
    ev.insert("internal_ip".into(), json!(rotation.internal_ip));
    ev.insert("internal_port".into(), json!(rotation.internal_port));
    ev.insert(
        "service_fingerprint".into(),
        json!(rotation.service_fingerprint),
    );
    ev.insert("routing_code".into(), json!(rotation.routing_code));
    ev.insert(
        "rotation_step_secs".into(),
        json!(rotation.rotation_step_secs),
    );
    ev.insert("expires_at".into(), json!(rotation.expires_at.to_rfc3339()));
    ev.insert("routing_persisted".into(), json!(true));
    ev.insert("live_gateway_probe".into(), json!(cfg.probe_gateway));
    let sdn_enforced = sdn_dataplane_enforced();
    ev.insert("sdn_dataplane_enforced".into(), json!(sdn_enforced));
    if !sdn_enforced {
        ev.insert(
            "operator_note".into(),
            json!("MTD routing epoch is live in DB. Set WEISSMAN_LIQUID_MATRIX_SDN_ENFORCED=1 after gateway/SDN integration is wired."),
        );
    }
    ev.insert(
        "legitimate_route".into(),
        json!(format!(
            "http://{}:{}/?rt={}",
            rotation.internal_ip, rotation.internal_port, rotation.routing_code
        )),
    );

    let mut findings = vec![finding_evidence(
        &format!(
            "LIQUID-MATRIX epoch {} — {}:{} ({})",
            rotation.epoch,
            rotation.internal_ip,
            rotation.internal_port,
            rotation.service_fingerprint
        ),
        "info",
        MITRE,
        "Moving-target routing epoch published. Legitimate clients must present the routing_code before connect.",
        &host,
        ev.clone(),
    )];

    if cfg.probe_gateway && !host.is_empty() {
        let url = if target.starts_with("http") {
            target.to_string()
        } else {
            format!("https://{host}")
        };
        let client = http_client().await;
        if let Some(resp) = http_get(&client, &url).await {
            let status = resp.status;
            let server = resp
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("server"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let mut gw = serde_json::Map::new();
            gw.insert("probe_status".into(), json!(status));
            gw.insert("observed_server_header".into(), json!(server));
            gw.insert(
                "mtd_delta".into(),
                json!(if server == rotation.service_fingerprint {
                    "static_fingerprint_matches_current_epoch"
                } else {
                    "external_fingerprint_differs_from_liquid_epoch"
                }),
            );
            findings.push(finding_evidence(
                "LIQUID-MATRIX gateway fingerprint probe",
                if server.is_empty() { "low" } else { "medium" },
                "T1590",
                "Live HTTP probe of gateway Server header vs current liquid-matrix epoch fingerprint.",
                &host,
                gw,
            ));
        }
    }

    let count = findings.len();
    if count == 1 {
        return EngineResult::ok(findings, "LIQUID-MATRIX: epoch rotated".to_string());
    }
    EngineResult::ok(findings, format!("LIQUID-MATRIX: {count} live signal(s)"))
}

pub async fn run_liquid_matrix(target: &str) {
    print_result(run_liquid_matrix_result(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rotation_is_3_seconds() {
        let cfg = LiquidMatrixConfig::from_params(&json!({}));
        assert_eq!(cfg.rotation_step_secs, 3);
    }
}
