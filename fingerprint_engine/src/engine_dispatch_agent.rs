//! Endpoint-agent dispatch — engines that require host-resident collection.
//!
//! Split from `engine_dispatch.rs` for maintainability. Hybrid engines (e.g. CHRONOS)
//! call `run_agent_required_engine` internally without being listed here.

use super::EngineRunContext;
use crate::engine_result::EngineResult;

/// Engines whose detection must run on an enrolled endpoint agent (not from a remote probe).
pub const AGENT_REQUIRED_ENGINES: &[&str] = &[
    // Stealth / EDR (host-only observation)
    "process_hollowing",
    "dll_hijacking_engine",
    "process_inventory",
    "av_bypass_engine",
    "log_tampering_engine",
    "timestomping",
    "anti_debug_evasion",
    "rootkit_simulation",
    "memory_forensics_evasion",
    "usb_enumeration",
    "dns_tunneling_c2",
    "icmp_covert",
    // Malware / persistence (advanced_malware_engines agent_required_ok)
    "bootkit_uefi",
    "persistence_mechanism",
    "polymorphic_engine",
    "ransomware_emulation",
    // Data exfiltration (advanced_data_engines agent_required_ok)
    "acoustic_exfil",
    "em_exfil_engine",
    "optical_exfil",
    "keyboard_acoustic",
    "screen_capture_exfil",
    "clipboard_hijack",
    "insider_exfil",
    "storage_covert_channel",
    // Network / wireless (advanced_network_engines agent_required_ok)
    "arp_spoofing_engine",
    "vlan_hopping_attack",
    "dhcp_attack_engine",
    "wifi_attack_engine",
    "bluetooth_attack_engine",
    "lte_5g_attack",
    "wpa3_attack_engine",
    "packet_injection_engine",
    "network_tap_advanced",
    "multicast_attack",
    "nat_traversal_attack",
    // Mobile (advanced_mobile_engines agent_required_ok)
    "sim_swap_engine",
    "bluetooth_mobile_attack",
    "nfc_relay_attack",
    // Social engineering (advanced_social_engines agent_required_ok)
    "deepfake_voice_engine",
    "pretexting_engine",
    "insider_threat_engine",
    "physical_social_eng",
    // OT / physical bus-level (no remote HTTP/crypto stand-in)
    "lorawan_attack",
    "lora_attack",
    "voltage_glitch_attack",
    "tpm_firmware_attack",
    "cold_boot_attack",
    // Next-Gen Arsenal — host-resident collector (commodity infostealer blast-radius).
    "infostealer_emulation",
    // NOTE: chronos is NOT agent-only — server hybrid runs via chronos_engine::run_chronos_result
];

#[must_use]
pub fn is_agent_required_engine(id: &str) -> bool {
    AGENT_REQUIRED_ENGINES.iter().any(|&k| k == id)
}

/// Dispatch an agent-required engine to the endpoint fleet (or return a status finding).
pub async fn run_agent_required_engine(
    engine_id: &str,
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if let (Some(pool), Some(registry), Some(client_id), Some(tenant_id)) = (
        ctx.app_pool.as_ref(),
        ctx.agents.as_ref(),
        ctx.client_id,
        ctx.tenant_id,
    ) {
        return dispatch_to_agent(
            pool.as_ref(),
            registry,
            tenant_id,
            client_id,
            engine_id,
            target,
            ctx,
        )
        .await;
    }
    let f = serde_json::json!({
        "type": engine_id,
        "category": "agent_required",
        "title": format!("{} requires an enrolled endpoint agent", engine_id),
        "severity": "info",
        "mitre_attack": "",
        "description": "This detection runs on the host. Enrol the Weissman Endpoint Agent on this client and re-run the engine.",
        "target": target,
        "remediation": "Go to Dashboard → Agents → Generate token → run the install command on the affected host.",
        "agent_required": true,
    });
    EngineResult::ok(vec![f], format!("{}: requires endpoint agent", engine_id))
}

/// Merge remote-surface findings with agent dispatch / guidance for hybrid engines.
pub(crate) fn merge_agent_hybrid(
    remote: EngineResult,
    agent: EngineResult,
    engine_id: &str,
) -> EngineResult {
    let mut findings = remote.findings;
    for f in agent.findings {
        let dup = findings.iter().any(|existing| {
            existing.get("title").and_then(|v| v.as_str())
                == f.get("title").and_then(|v| v.as_str())
        });
        if !dup {
            findings.push(f);
        }
    }
    if findings.is_empty() {
        return EngineResult {
            status: agent.status,
            findings: Vec::new(),
            message: agent.message,
            success: agent.success,
            summary: agent.summary,
            graph_nodes: agent.graph_nodes,
            graph_edges: agent.graph_edges,
        };
    }
    let has_agent_guidance = findings.iter().any(|f| {
        f.get("agent_required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    });
    let msg = if has_agent_guidance {
        format!(
            "{}: {} finding(s) — remote surface probed; endpoint agent recommended for host-resident validation",
            engine_id,
            findings.len()
        )
    } else {
        format!(
            "{}: {} finding(s) (remote surface + agent)",
            engine_id,
            findings.len()
        )
    };
    EngineResult::ok(findings, msg)
}

async fn dispatch_to_agent(
    pool: &sqlx::PgPool,
    registry: &std::sync::Arc<crate::endpoint_agents::AgentRegistry>,
    tenant_id: i64,
    client_id: i64,
    engine: &str,
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    let mut params = if ctx.job_params.is_null() {
        serde_json::json!({})
    } else {
        ctx.job_params.clone()
    };
    if let Some(obj) = params.as_object_mut() {
        obj.entry("priority")
            .or_insert_with(|| serde_json::json!("high"));
        if let Some(job_id) = &ctx.job_id {
            obj.entry("scan_job_id")
                .or_insert_with(|| serde_json::json!(job_id));
        }
    }
    let (task, live_dispatched) = match crate::endpoint_agents::enqueue_and_dispatch_fleet(
        pool,
        registry,
        tenant_id,
        client_id,
        engine,
        Some(target),
        &params,
    )
    .await
    {
        Ok(pair) => pair,
        Err(e) => {
            return EngineResult::ok(
                vec![],
                format!("agent task enqueue failed for {}: {}", engine, e),
            );
        }
    };
    let f = serde_json::json!({
        "type": engine,
        "category": "agent_dispatched",
        "title": if live_dispatched {
            format!("{}: task dispatched to online agent", engine)
        } else {
            format!("{}: task queued for next online agent", engine)
        },
        "severity": "info",
        "mitre_attack": "",
        "description": format!(
            "Detection task {} routed to {} agent for client {}. Findings will stream to the dashboard as the agent reports them.",
            task,
            if live_dispatched { "live" } else { "next" },
            client_id
        ),
        "target": target,
        "task_id": task.to_string(),
        "live_dispatched": live_dispatched,
        "remediation": "View streaming findings under Dashboard → Findings, filtered by source = agent.",
    });
    EngineResult::ok(vec![f], format!("{}: task {} dispatched", engine, task))
}
