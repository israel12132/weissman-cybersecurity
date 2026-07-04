//! **CHRONOS** — zero-day temporal rollback via live process-delta ring buffer + syscall anomaly response.
//!
//! Host observation runs on the Weissman Endpoint Agent (`chronos` capability). Server-side
//! correlates agent findings, `runtime_traces` (eBPF/bpftrace ingest), and persists freeze events.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, extract_host, finding};
use crate::engine_result::{print_result, EngineResult};
use crate::sovereign_defense_store::{self, CHRONOS_ENGINE_ID};
use serde_json::{json, Map, Value};
use sqlx::Row;

const MITRE: &str = "T1055";

fn finding_evidence(
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
    evidence: Map<String, Value>,
) -> Value {
    let mut f = finding(
        CHRONOS_ENGINE_ID,
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
pub struct ChronosConfig {
    pub sample_interval_ms: u64,
    pub observation_window_ms: u64,
    pub auto_freeze: bool,
    pub deploy_ebpf: bool,
    pub ebpf_ssh_host: Option<String>,
    pub ebpf_ssh_user: Option<String>,
    pub ebpf_ssh_key_path: Option<String>,
    pub ebpf_ssh_port: u16,
}

impl ChronosConfig {
    pub fn from_params(params: &Value) -> Self {
        Self {
            sample_interval_ms: pi64(params, "sample_interval_ms", 5).max(1) as u64,
            observation_window_ms: pi64(params, "observation_window_ms", 5000).max(100) as u64,
            auto_freeze: pbool(params, "auto_freeze", true),
            deploy_ebpf: pbool(params, "deploy_ebpf", false),
            ebpf_ssh_host: params
                .get("ebpf_ssh_host")
                .and_then(Value::as_str)
                .map(str::to_string),
            ebpf_ssh_user: params
                .get("ebpf_ssh_user")
                .and_then(Value::as_str)
                .map(str::to_string),
            ebpf_ssh_key_path: params
                .get("ebpf_ssh_key_path")
                .and_then(Value::as_str)
                .map(str::to_string),
            ebpf_ssh_port: pi64(params, "ebpf_ssh_port", 22).clamp(1, 65535) as u16,
        }
    }
}

fn pi64(p: &Value, k: &str, d: i64) -> i64 {
    p.get(k).and_then(Value::as_i64).unwrap_or(d)
}

fn pbool(p: &Value, k: &str, d: bool) -> bool {
    p.get(k).and_then(Value::as_bool).unwrap_or(d)
}

pub async fn run_chronos_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    let cfg = ChronosConfig::from_params(&ctx.job_params);
    let host = extract_host(target);
    let mut findings: Vec<Value> = Vec::new();

    if let (Some(pool), Some(tenant_id), Some(client_id)) =
        (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id)
    {
        let mut tx = match crate::db::begin_tenant_tx(pool.as_ref(), tenant_id).await {
            Ok(t) => t,
            Err(e) => return EngineResult::error(format!("db: {e}")),
        };

        let recent_events = sqlx::query(
            r#"SELECT id, event_type, pid, parent_pid, process_name, syscall_hint, action_taken, created_at
                 FROM chronos_events
                WHERE client_id = $1
                ORDER BY id DESC LIMIT 25"#,
        )
        .bind(client_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();

        for r in &recent_events {
            let et = r.try_get::<String, _>("event_type").unwrap_or_default();
            if et != "anomaly" && et != "freeze" {
                continue;
            }
            let mut ev = serde_json::Map::new();
            ev.insert(
                "event_id".into(),
                json!(r.try_get::<i64, _>("id").unwrap_or(0)),
            );
            ev.insert("event_type".into(), json!(et));
            ev.insert(
                "pid".into(),
                json!(r.try_get::<Option<i32>, _>("pid").ok().flatten()),
            );
            ev.insert(
                "parent_pid".into(),
                json!(r.try_get::<Option<i32>, _>("parent_pid").ok().flatten()),
            );
            ev.insert(
                "process_name".into(),
                json!(r
                    .try_get::<Option<String>, _>("process_name")
                    .ok()
                    .flatten()),
            );
            ev.insert(
                "action_taken".into(),
                json!(r
                    .try_get::<Option<String>, _>("action_taken")
                    .ok()
                    .flatten()),
            );
            findings.push(finding_evidence(
                &format!("CHRONOS {} on host {}", et, host),
                if et == "freeze" { "critical" } else { "high" },
                MITRE,
                "Live CHRONOS event from endpoint delta ring buffer — process freeze or syscall anomaly detected.",
                &host,
                ev,
            ));
        }

        let traces = sqlx::query(
            r#"SELECT function_name, payload_hash, metadata, created_at
                 FROM runtime_traces
                WHERE client_id = $1
                ORDER BY id DESC LIMIT 50"#,
        )
        .bind(client_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_default();

        let shell_syscalls = traces
            .iter()
            .filter(|r| {
                let fn_name = r
                    .try_get::<Option<String>, _>("function_name")
                    .ok()
                    .flatten()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                fn_name.contains("exec") || fn_name.contains("clone") || fn_name.contains("openat")
            })
            .count();

        if shell_syscalls >= 3 {
            let mut ev = serde_json::Map::new();
            ev.insert("syscall_hits".into(), json!(shell_syscalls));
            ev.insert("source".into(), json!("runtime_traces"));
            findings.push(finding_evidence(
                "CHRONOS eBPF syscall burst — possible shell spawn chain",
                "high",
                "T1059",
                "Multiple exec/clone/openat events in runtime_traces within recent window — correlate with agent freeze.",
                &host,
                ev,
            ));
        }

        let _ = tx.commit().await;

        if cfg.deploy_ebpf {
            if let (Some(ssh_host), Some(ssh_user), Some(key_path)) = (
                cfg.ebpf_ssh_host.as_deref(),
                cfg.ebpf_ssh_user.as_deref(),
                cfg.ebpf_ssh_key_path.as_deref(),
            ) {
                let ingest = format!(
                    "{}/api/clients/{}/runtime-traces",
                    std::env::var("WEISSMAN_PUBLIC_URL")
                        .unwrap_or_else(|_| "http://127.0.0.1:8000".into()),
                    client_id
                );
                let auth = crate::ebpf_deploy::SshAuth::Key {
                    key_path: std::path::PathBuf::from(key_path),
                };
                let pool_c = pool.clone();
                let host_s = ssh_host.to_string();
                let user_s = ssh_user.to_string();
                let cid = client_id.to_string();
                tokio::spawn(async move {
                    let _ = crate::ebpf_deploy::deploy_and_stream_ebpf(
                        &host_s,
                        cfg.ebpf_ssh_port,
                        &user_s,
                        &auth,
                        &cid,
                        &ingest,
                    )
                    .await;
                    if let Err(e) = sovereign_defense_store::insert_chronos_event(
                        pool_c.as_ref(),
                        tenant_id,
                        client_id,
                        "ebpf_block",
                        None,
                        None,
                        None,
                        Some("sys_enter_execve"),
                        Some("ebpf_stream_started"),
                        json!({ "ssh_host": host_s }),
                        json!({}),
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "chronos: ebpf event persist failed");
                    }
                });
                findings.push(finding_evidence(
                    "CHRONOS eBPF ring-buffer stream armed",
                    "info",
                    MITRE,
                    "bpftrace syscall stream deployed via SSH; events ingest to runtime_traces.",
                    &host,
                    Map::from_iter([("ssh_host".into(), json!(ssh_host))]),
                ));
            }
        }
    }

    let agent_params = json!({
        "sample_interval_ms": cfg.sample_interval_ms,
        "observation_window_ms": cfg.observation_window_ms,
        "auto_freeze": cfg.auto_freeze,
    });
    let mut agent_ctx = ctx.clone();
    agent_ctx.job_params = agent_params;
    let agent_result =
        crate::engine_dispatch::run_agent_required_engine(CHRONOS_ENGINE_ID, target, &agent_ctx)
            .await;

    for f in &agent_result.findings {
        findings.push(f.clone());
        if let (Some(pool), Some(tenant_id), Some(client_id)) =
            (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id)
        {
            if let Some(obj) = f.as_object() {
                let title = obj.get("title").and_then(Value::as_str).unwrap_or("");
                if title.contains("freeze")
                    || title.contains("anomaly")
                    || title.contains("shell spawn")
                {
                    let ev = obj.get("evidence").cloned().unwrap_or(json!({}));
                    let pid = ev.get("pid").and_then(Value::as_i64).map(|p| p as i32);
                    let ppid = ev
                        .get("parent_pid")
                        .and_then(Value::as_i64)
                        .map(|p| p as i32);
                    let pname = ev
                        .get("process_name")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    let action = ev
                        .get("action_taken")
                        .and_then(Value::as_str)
                        .or_else(|| obj.get("description").and_then(Value::as_str))
                        .map(str::to_string);
                    let et = if title.to_ascii_lowercase().contains("freeze") {
                        "freeze"
                    } else {
                        "anomaly"
                    };
                    if let Err(e) = sovereign_defense_store::insert_chronos_event(
                        pool.as_ref(),
                        tenant_id,
                        client_id,
                        et,
                        pid,
                        ppid,
                        pname.as_deref(),
                        Some("execve"),
                        action.as_deref(),
                        ev,
                        json!({ "source": "endpoint_agent" }),
                    )
                    .await
                    {
                        findings.push(finding_evidence(
                            "CHRONOS event persist warning",
                            "info",
                            MITRE,
                            &format!("Agent signal recorded but DB persist failed: {e}"),
                            &host,
                            Map::from_iter([("persist_error".into(), json!(e.to_string()))]),
                        ));
                    }
                }
            }
        }
    }

    let count = findings.len();
    if count == 0 {
        return empty_ok(
            CHRONOS_ENGINE_ID,
            "CHRONOS: no anomalies in observation window",
        );
    }
    EngineResult::ok(findings, format!("CHRONOS: {count} live signal(s)"))
}

pub async fn run_chronos(target: &str) {
    print_result(run_chronos_result(target, &EngineRunContext::default()).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_5ms_sample() {
        let cfg = ChronosConfig::from_params(&json!({}));
        assert_eq!(cfg.sample_interval_ms, 5);
        assert_eq!(cfg.observation_window_ms, 5000);
        assert!(cfg.auto_freeze);
    }
}
