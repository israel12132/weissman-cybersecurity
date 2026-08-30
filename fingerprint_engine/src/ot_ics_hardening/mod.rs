//! OT/ICS hardening kernel — passive/active safety interlock + protocol parsers.
//!
//! This module is the production implementation of the OT/ICS hardening blueprint:
//! Modbus TCP, Siemens S7, DNP3 (IEEE 1815), IEC 61850. Writes, Direct Operate,
//! CPU stop, RTU restart, GOOSE injection, and file-transfer objects are
//! structurally impossible from this worker (allow-lists + never-emitted opcodes).

pub mod anomaly;
pub mod parsers;
pub mod plc_decoy;
pub mod policy;
pub mod probes;
pub mod s7plus;
pub mod session;

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding, tcp_open};
use crate::engine_result::{print_result, EngineResult};
use crate::ot_ics_engine::OtFingerprint;
use serde_json::{json, Value};

use anomaly::{CV_FLOOR, MAD_SWITCH, Z_ABS_CAP, Z_ISOLATE};
use parsers::{BER_INLINE_NODES, COTP_ASSEMBLY_CAP, MAX_COTP_FRAGMENT_TIMEOUT};
use policy::{catalog_json, OtSafetyPolicy, ProbeMode, CONTROL_CATALOG, DESTRUCTIVE_FOREVER};
use probes::{
    probe_dnp3_safe, probe_iec61850_mms_safe, probe_modbus_safe, probe_s7_safe,
    HardenedFingerprint, DNP3_PORT, IEC_MMS_PORT, MODBUS_PORT, S7_PORT,
};

pub const ENGINE_SAFETY: &str = "ot_passive_active_safety";
pub const ENGINE_CROWN: &str = "ot_crown_jewel_path";
const MITRE_OT: &str = "T0843";
const MITRE_INHIBIT: &str = "T0836";

impl From<&HardenedFingerprint> for OtFingerprint {
    fn from(h: &HardenedFingerprint) -> Self {
        OtFingerprint {
            host: h.host.clone(),
            port: h.port,
            protocol: h.protocol.clone(),
            vendor_hint: h.vendor_hint.clone(),
            confidence: h.confidence,
            raw_excerpt_hex: h.raw_excerpt_hex.clone(),
            metadata: h.metadata.clone(),
        }
    }
}

fn fp_finding(engine: &str, h: &HardenedFingerprint, target: &str) -> Value {
    let mut f = finding(
        engine,
        &format!(
            "{} on {}:{} ({})",
            h.protocol, h.host, h.port, h.vendor_hint
        ),
        if h.confidence > 0.85 {
            "high"
        } else if h.confidence > 0.6 {
            "medium"
        } else {
            "low"
        },
        MITRE_OT,
        &format!(
            "Hardened parser confirmed {}. confidence={:.2} excerpt={}",
            h.protocol, h.confidence, h.raw_excerpt_hex
        ),
        target,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("ot_metadata".into(), h.metadata.clone());
        obj.insert("probe_mode".into(), json!("safe_read"));
        obj.insert("writes_emitted".into(), json!(false));
    }
    f
}

async fn collect_protocol_fps(host: &str, policy: &OtSafetyPolicy) -> Vec<HardenedFingerprint> {
    let mut out = Vec::new();
    if let Some(fp) = probe_modbus_safe(host, policy).await {
        out.push(fp);
    }
    if let Some(fp) = probe_s7_safe(host, policy).await {
        out.push(fp);
    }
    if let Some(fp) = probe_dnp3_safe(host, policy).await {
        out.push(fp);
    }
    if let Some(fp) = probe_iec61850_mms_safe(host, policy).await {
        // Port 102 is shared with S7; keep IEC finding if COTP/MMS looks distinct
        // or S7 wasn't confirmed.
        if out.iter().all(|e| e.protocol != "s7_iso_tcp") || fp.confidence >= 0.85 {
            out.push(fp);
        }
    }
    out
}

/// Passive/active safety engine — live read-only assessment of the four OT stacks.
pub async fn run_ot_passive_active_safety_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let mut params = if ctx.job_params.is_object() {
        ctx.job_params.clone()
    } else {
        json!({})
    };
    if let Some(jid) = &ctx.job_id {
        if params.get("job_id").is_none() {
            params["job_id"] = json!(jid);
        }
    }
    let mut policy = OtSafetyPolicy::from_job_params(&params);
    policy.tenant_id = ctx.tenant_id;
    policy.client_id = ctx.client_id;

    let mut findings: Vec<Value> = Vec::new();
    findings.push(finding(
        ENGINE_SAFETY,
        &format!(
            "OT safety interlock armed (mode={:?}, max_conn={}, writes=blocked)",
            policy.probe_mode, policy.max_connections_per_host
        ),
        "info",
        MITRE_INHIBIT,
        &format!(
            "Worker will not emit {}. Direct Operate, CPU stop, RTU restart, GOOSE inject, and Modbus writes are structurally blocked. HMAC_ok={} protocol_strict={}.",
            DESTRUCTIVE_FOREVER.join(", "),
            policy.hmac_ok,
            policy.protocol_strict
        ),
        target,
    ));

    if policy.probe_mode == ProbeMode::Passive {
        findings.push(finding(
            ENGINE_SAFETY,
            "Passive mode: no TCP probes issued",
            "info",
            MITRE_OT,
            "Probe mode is Passive. Parse captured frames via the endpoint agent / GOOSE tap; this engine did not open sockets.",
            target,
        ));
        persist_safety_events(ctx, &host, &[], &policy).await;
        return EngineResult::ok(findings, format!("{ENGINE_SAFETY}: passive interlock only"));
    }

    let fps = collect_protocol_fps(&host, &policy).await;
    for fp in &fps {
        if fp
            .metadata
            .get("cpu_control_observed")
            .and_then(Value::as_bool)
            == Some(true)
        {
            findings.push(finding(
                ENGINE_SAFETY,
                &format!("SEV-1: S7 CPU-control opcode observed on {host}"),
                "critical",
                "T0816",
                "Hardened S7 parser observed CPU stop/reset in the response path. Not sent by Weissman. Isolate the engineering station (SOAR isolate_host) and freeze the PLC program.",
                target,
            ));
        }
        if fp
            .metadata
            .get("enumeration_signal")
            .and_then(Value::as_bool)
            == Some(true)
        {
            findings.push(finding(
                ENGINE_SAFETY,
                "Modbus exception 01/02 — function/address enumeration",
                "medium",
                MITRE_OT,
                "Exception Illegal Function / Illegal Data Address on a SafeRead probe. Treat repeated 0x01/0x02 as reconnaissance.",
                target,
            ));
        }
        if fp.metadata.get("gateway_unit").and_then(Value::as_bool) == Some(true) {
            findings.push(finding(
                ENGINE_SAFETY,
                "Modbus Unit ID maps to a serial gateway",
                "high",
                MITRE_OT,
                "Unit 0 or 247–255 typically bridges to legacy serial. Further unit enumeration is blocked to avoid DoS on RTU-over-TCP.",
                target,
            ));
        }
        findings.push(fp_finding(ENGINE_SAFETY, fp, target));
    }

    if fps.is_empty() {
        let mut open = Vec::new();
        if tcp_open(&host, MODBUS_PORT).await {
            open.push("502/modbus");
        }
        if tcp_open(&host, S7_PORT).await {
            open.push("102/s7-or-mms");
        }
        if tcp_open(&host, DNP3_PORT).await {
            open.push("20000/dnp3");
        }
        if open.is_empty() {
            persist_safety_events(ctx, &host, &[], &policy).await;
            return if findings.len() <= 1 {
                empty_ok(ENGINE_SAFETY, target)
            } else {
                EngineResult::ok(
                    findings,
                    format!("{ENGINE_SAFETY}: interlock armed, no OT ports"),
                )
            };
        }
        findings.push(finding(
            ENGINE_SAFETY,
            &format!("OT candidate ports open without protocol confirmation: {}", open.join(", ")),
            "medium",
            MITRE_OT,
            "TCP accepted but the hardened parser did not confirm a valid MBAP/TPKT/DNP3 frame. No writes were attempted.",
            target,
        ));
    }

    persist_safety_events(ctx, &host, &fps, &policy).await;

    EngineResult::ok(
        findings,
        format!(
            "{ENGINE_SAFETY}: {} protocol confirmation(s) on {host} (mode={:?})",
            fps.len(),
            policy.probe_mode
        ),
    )
}

pub async fn run_ot_crown_jewel_path_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = extract_host(target);
    let safety = run_ot_passive_active_safety_result(target, ctx).await;
    if !safety.success {
        return safety;
    }
    let mut merged = safety.findings;

    let ot_count = merged
        .iter()
        .filter(|f| {
            f.get("ot_metadata").is_some()
                || f.get("title")
                    .and_then(Value::as_str)
                    .map(|t| {
                        t.contains("modbus")
                            || t.contains("s7")
                            || t.contains("dnp3")
                            || t.contains("iec61850")
                            || t.contains("IEC")
                            || t.contains("Modbus")
                            || t.contains("DNP3")
                            || t.contains("S7")
                    })
                    .unwrap_or(false)
        })
        .count();

    if ot_count > 0 {
        merged.push(finding(
            ENGINE_CROWN,
            &format!("OT attack-path: {ot_count} live protocol surface(s) toward crown-jewel process"),
            if ot_count >= 2 { "high" } else { "medium" },
            "T0888",
            "Unauthenticated industrial protocol(s) on the assessed host are a lateral stepping-stone into Purdue Level 1/0. Segment with a Level 3.5 firewall, require engineering VPN+MFA, and pin Unit IDs / DNP3 addresses to inventory.",
            target,
        ));
        merged.push(finding(
            ENGINE_CROWN,
            "SOAR playbook recommendation: isolate_host on rogue OT masters (not the PLC)",
            "info",
            "T0814",
            &format!(
                "Z-score isolate threshold is {Z_ISOLATE}. Auto-isolate is {} — default is recommend-only because isolating a controller is itself an operational risk. Target the injecting workstation / rogue master.",
                if std::env::var("WEISSMAN_OT_SOAR_AUTO_ISOLATE").ok().as_deref() == Some("1") {
                    "ENABLED"
                } else {
                    "OFF"
                }
            ),
            target,
        ));
    }

    if let (Some(pool), Some(tenant), Some(client)) =
        (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id)
    {
        match crate::financial_risk::compute_and_store(pool.as_ref(), tenant, client).await {
            Ok(risk) => {
                let sev = if risk.ale_annualised_usd >= 1_000_000 {
                    "critical"
                } else if risk.ale_annualised_usd >= 250_000 {
                    "high"
                } else {
                    "medium"
                };
                merged.push(finding(
                    ENGINE_CROWN,
                    &format!(
                        "FAIR OT blast-radius: ${} ALE / ${} crown jewels",
                        risk.ale_annualised_usd, risk.crown_jewel_value_usd
                    ),
                    sev,
                    "T1595",
                    &format!(
                        "Live FAIR roll-up fused with OT protocol confirmations on {host}. Worst-case SLE ${}. KEV/EPSS already folded into the financial model.",
                        risk.sle_worst_usd
                    ),
                    target,
                ));
            }
            Err(_) => {
                merged.push(finding(
                    ENGINE_CROWN,
                    "FAIR model unavailable for this client yet",
                    "info",
                    "T1595",
                    "Set asset-value rules on the client to price OT crown jewels. Protocol findings above still stand.",
                    target,
                ));
            }
        }

        if let Some(kev) = crate::intel_kev::is_kev_listed(pool.as_ref(), "CVE-2013-2761").await {
            // DNP3 historical KEV example — only emit when the live DNP3 probe confirmed.
            let dnp3_live = merged.iter().any(|f| {
                f.get("title")
                    .and_then(Value::as_str)
                    .map(|t| t.to_ascii_lowercase().contains("dnp3"))
                    .unwrap_or(false)
            });
            if dnp3_live {
                merged.push(finding(
                    ENGINE_CROWN,
                    &format!("CISA KEV: {} ({})", kev.cve, kev.vulnerability_name),
                    "high",
                    MITRE_OT,
                    &format!(
                        "DNP3 confirmed on {host}. KEV {} — {}. Required action: {}",
                        kev.cve, kev.short_description, kev.required_action
                    ),
                    target,
                ));
            }
        }
    }

    EngineResult::ok(
        merged,
        format!("{ENGINE_CROWN}: OT protocol × FAIR × SOAR recommendation on {host}"),
    )
}

async fn persist_safety_events(
    ctx: &EngineRunContext,
    host: &str,
    fps: &[HardenedFingerprint],
    policy: &OtSafetyPolicy,
) {
    let Some(pool) = ctx.app_pool.as_ref() else {
        return;
    };
    let Some(tenant) = ctx.tenant_id else {
        return;
    };
    let client = ctx.client_id;
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool.as_ref(), tenant).await else {
        return;
    };
    let _ = sqlx::query(
        r#"INSERT INTO ot_ics_safety_events
           (tenant_id, client_id, host, protocol, event_kind, severity, detail, binary_signature)
           VALUES ($1, $2, $3, 'ot_kernel', 'interlock_armed', 'info', $4, '')"#,
    )
    .bind(tenant)
    .bind(client)
    .bind(host)
    .bind(json!({
        "probe_mode": policy.probe_mode,
        "hmac_ok": policy.hmac_ok,
        "max_connections_per_host": policy.max_connections_per_host,
        "writes": false,
        "max_gateway_connections": policy.max_gateway_connections,
        "rst_on_release": false,
        "graceful_close_ms": 10,
    }))
    .execute(&mut *tx)
    .await;
    for fp in fps {
        let _ = sqlx::query(
            r#"INSERT INTO ot_ics_safety_events
               (tenant_id, client_id, host, protocol, event_kind, severity, detail, binary_signature)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(tenant)
        .bind(client)
        .bind(host)
        .bind(&fp.protocol)
        .bind("protocol_confirmed")
        .bind(if fp.confidence > 0.85 { "high" } else { "info" })
        .bind(json!({
            "metadata": fp.metadata,
            "probe_mode": policy.probe_mode,
            "port": fp.port,
        }))
        .bind(&fp.raw_excerpt_hex)
        .execute(&mut *tx)
        .await;
        if let Some(cid) = client {
            let ot = OtFingerprint::from(fp);
            let meta = sqlx::types::Json(ot.metadata.clone());
            let _ = sqlx::query(
                r#"INSERT INTO ot_ics_fingerprints
                   (tenant_id, client_id, host, port, protocol, vendor_hint, confidence, raw_excerpt_hex, metadata)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
            )
            .bind(tenant)
            .bind(cid)
            .bind(&ot.host)
            .bind(i32::from(ot.port))
            .bind(&ot.protocol)
            .bind(&ot.vendor_hint)
            .bind(f64::from(ot.confidence))
            .bind(&ot.raw_excerpt_hex)
            .bind(meta)
            .execute(&mut *tx)
            .await;
        }
    }
    let _ = tx.commit().await;
}

pub fn safety_api_document(events: Vec<Value>, fair: Option<Value>) -> Value {
    json!({
        "policy": {
            "probe_mode": "safe_read",
            "max_connections_per_host": 2,
            "max_gateway_connections": 2,
            "write_blocked": true,
            "direct_operate_blocked": true,
            "cpu_control_blocked": true,
            "sbo_required": true,
            "file_transfer_blocked": true,
            "goose_inject_blocked": true,
            "watchdog_ms": 2000,
            "zscore_isolate_threshold": Z_ISOLATE,
            "z_scale": "cv_or_mad",
            "mad_switch": MAD_SWITCH,
            "cv_floor": CV_FLOOR,
            "z_abs_cap": Z_ABS_CAP,
            "cotp_assembly_cap": COTP_ASSEMBLY_CAP,
            "cotp_fragment_timeout_ms": MAX_COTP_FRAGMENT_TIMEOUT.as_millis() as u64,
            "ber_iterative": true,
            "ber_inline_nodes": BER_INLINE_NODES,
            "graceful_close_ms": 10,
            "rst_on_release": false,
            "s7plus_structural": true,
            "plc_decoy": true,
            "soar_auto_isolate": std::env::var("WEISSMAN_OT_SOAR_AUTO_ISOLATE").ok().as_deref() == Some("1"),
            "hmac_required_for_active": true,
            "rls": true,
            "skip_locked_jobs": true,
            "destructive_forever": DESTRUCTIVE_FOREVER,
        },
        "protocols": [
            {"id": "modbus", "port": MODBUS_PORT, "parser": "nom_mbap", "safe_reads": ["01","02","03","04","2b"], "blocked_writes": ["05","06","0f","10","15","16"]},
            {"id": "s7", "port": S7_PORT, "parser": "nom_tpkt_cotp_assembled", "blocked": ["cpu_stop","cpu_reset","db_write"]},
            {"id": "dnp3", "port": DNP3_PORT, "parser": "nom_dnp3_crc", "blocked": ["direct_operate","cold_restart","file_transfer"]},
            {"id": "iec61850", "port": IEC_MMS_PORT, "parser": "nom_mms_ber_iterative", "blocked": ["goose_inject","mms_write"]},
        ],
        "controls": catalog_json(),
        "control_count": CONTROL_CATALOG.len(),
        "events": events,
        "fair": fair,
        "live": true,
    })
}

macro_rules! cli_wrapper_ctx {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target, &EngineRunContext::default()).await);
        }
    };
}
cli_wrapper_ctx!(
    run_ot_passive_active_safety,
    run_ot_passive_active_safety_result
);
cli_wrapper_ctx!(run_ot_crown_jewel_path, run_ot_crown_jewel_path_result);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_document_never_claims_writes() {
        let doc = safety_api_document(vec![], None);
        assert_eq!(doc["policy"]["write_blocked"], json!(true));
        assert_eq!(doc["policy"]["direct_operate_blocked"], json!(true));
        assert_eq!(doc["policy"]["ber_iterative"], json!(true));
        assert_eq!(doc["policy"]["rst_on_release"], json!(false));
        assert_eq!(doc["policy"]["max_gateway_connections"], json!(2));
        assert_eq!(doc["policy"]["z_scale"], json!("cv_or_mad"));
        assert_eq!(doc["policy"]["graceful_close_ms"], json!(10));
        assert_eq!(doc["policy"]["cotp_fragment_timeout_ms"], json!(50));
        assert_eq!(doc["policy"]["plc_decoy"], json!(true));
        assert_eq!(doc["policy"]["s7plus_structural"], json!(true));
        assert_eq!(doc["control_count"], json!(100));
        assert_eq!(doc["live"], json!(true));
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_ot_passive_active_safety_result("", &EngineRunContext::default()).await;
        assert!(!r.success);
    }
}
