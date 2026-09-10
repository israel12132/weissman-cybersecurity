//! Privilege Escalation & Credential Access — 500-check defensive engine.
//!
//! Live host + remote + platform evidence. This module **audits** privilege and
//! credential posture. It does not implement Hell's Gate, dump LSASS, steal
//! tokens, or execute UAC bypasses.

pub mod catalog;
mod eval;
mod host;
mod persist;
mod platform;
mod proc_guard;
mod remote;

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::finding;
use crate::engine_result::{print_result, EngineResult};
use catalog::{Domain, CHECK_COUNT, DOMAIN_COUNT};
use eval::{CheckStatus, Coverage};
use serde_json::{json, Value};

pub const ENGINE_ID: &str = "privilege_escalation_credential_access";

fn pbool(params: &Value, key: &str, default: bool) -> bool {
    params
        .get(key)
        .and_then(|v| match v {
            Value::Bool(b) => Some(*b),
            Value::String(s) => Some(matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )),
            _ => None,
        })
        .unwrap_or(default)
}

fn max_findings(params: &Value) -> usize {
    params
        .get("max_findings")
        .and_then(Value::as_u64)
        .unwrap_or(200)
        .clamp(20, 500) as usize
}

fn domain_enabled(params: &Value, d: Domain) -> bool {
    let key = match d {
        Domain::SyscallIntegrity => "check_syscall",
        Domain::LsassProtection => "check_lsass",
        Domain::TokenHardening => "check_token",
        Domain::UacPrevention => "check_uac",
        Domain::ServiceTaskAudit => "check_service",
        Domain::KernelDriver => "check_kernel",
        Domain::CredentialVault => "check_vault",
        Domain::AgentTelemetry => "check_telemetry",
        Domain::RlsPartitioning => "check_rls",
        Domain::ZeroFabrication => "check_cicd",
    };
    pbool(params, key, true)
}

fn lock_disabled_domains(params: &Value, cov: &mut Coverage) {
    for d in Domain::all() {
        if !domain_enabled(params, d) {
            let ids: Vec<u16> = catalog::checks_for_domain(d).iter().map(|c| c.id).collect();
            eval::force(cov, &ids, CheckStatus::Na, "domain disabled by operator");
        }
    }
}

fn remediation(d: Domain) -> &'static str {
    match d {
        Domain::SyscallIntegrity => {
            "Keep W^X (no RWX pages), enable yama.ptrace_scope≥1, kptr_restrict≥1, and never ship Hell's Gate stubs. Audit /proc/<pid>/maps for anonymous +x pages."
        }
        Domain::LsassProtection => {
            "Enable RunAsPPL / Credential Guard (Windows) or yama.ptrace_scope + kernel lockdown (Linux). Never persist LSASS dumps."
        }
        Domain::TokenHardening => {
            "Remove SeDebugPrivilege / CAP_SYS_PTRACE from workstation users, lock docker.sock, delete NOPASSWD sudo."
        }
        Domain::UacPrevention => {
            "Set EnableLUA=1, ConsentPromptBehaviorAdmin=2 (Always Notify), PromptOnSecureDesktop=1. On Linux: remove NOPASSWD."
        }
        Domain::ServiceTaskAudit => {
            "Harden service/unit ACLs, quote ImagePath, move binaries out of Temp, alert on SYSTEM scheduled tasks."
        }
        Domain::KernelDriver => {
            "Enable Secure Boot + HVCI/VBS, block known-vulnerable drivers, disable unprivileged eBPF."
        }
        Domain::CredentialVault => {
            "chmod 600 credential files, disable WDigest/cleartext, treat readable browser Login Data as blast-radius — do not exfiltrate it."
        }
        Domain::AgentTelemetry => {
            "Cap scanner CPU (Performance Guard at 90%), batch + zstd telemetry over TLS, HMAC heartbeats."
        }
        Domain::RlsPartitioning => {
            "FORCE RLS on every tenant table, sslmode=verify-full, BYPASSRLS only on weissman_auth, SET LOCAL app.current_tenant_id on every write."
        }
        Domain::ZeroFabrication => {
            "Keep verify_engine_wiring.mjs and full_audit_gate.sh green. JWT ≥48 chars. No stub findings."
        }
    }
}

fn severity_for(d: Domain, evidence: &str) -> &'static str {
    let e = evidence.to_ascii_lowercase();
    if e.contains("shadow") && e.contains("readable")
        || e.contains("rwx mapping")
        || e.contains("docker.sock is writable")
        || (e.contains("jwt_secret length") && e.contains('<'))
        || e.contains("2375")
    {
        return "critical";
    }
    if matches!(
        d,
        Domain::LsassProtection | Domain::CredentialVault | Domain::KernelDriver
    ) {
        "high"
    } else if matches!(
        d,
        Domain::TokenHardening | Domain::UacPrevention | Domain::ServiceTaskAudit
    ) {
        "high"
    } else {
        "medium"
    }
}

pub async fn run_priv_esc_cred_access_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let params = &ctx.job_params;
    let mut cov = Coverage::new();

    for d in Domain::all() {
        if !domain_enabled(params, d) {
            let ids: Vec<u16> = catalog::checks_for_domain(d).iter().map(|c| c.id).collect();
            eval::apply(
                &mut cov,
                &ids,
                CheckStatus::Na,
                "domain disabled by operator",
            );
        }
    }

    let host = host::collect();
    if domain_enabled(params, Domain::SyscallIntegrity)
        || domain_enabled(params, Domain::LsassProtection)
        || domain_enabled(params, Domain::TokenHardening)
        || domain_enabled(params, Domain::UacPrevention)
        || domain_enabled(params, Domain::ServiceTaskAudit)
        || domain_enabled(params, Domain::KernelDriver)
        || domain_enabled(params, Domain::CredentialVault)
        || domain_enabled(params, Domain::AgentTelemetry)
    {
        host::apply_snapshot(&mut cov, &host);
    }

    let remote = if pbool(params, "check_remote", true) {
        remote::probe(target, ctx).await
    } else {
        remote::RemoteSurface {
            host: crate::engine_probes::extract_host(target),
            open_ports: vec![],
            leak_hits: vec![],
            docker_unauth: false,
        }
    };
    if pbool(params, "check_remote", true) {
        remote::apply_remote(&mut cov, &remote);
    }

    let plat = if domain_enabled(params, Domain::RlsPartitioning)
        || domain_enabled(params, Domain::ZeroFabrication)
        || domain_enabled(params, Domain::AgentTelemetry)
    {
        platform::collect(ctx).await
    } else {
        platform::PlatformSnapshot::default()
    };
    if domain_enabled(params, Domain::RlsPartitioning)
        || domain_enabled(params, Domain::ZeroFabrication)
        || domain_enabled(params, Domain::AgentTelemetry)
    {
        platform::apply_platform(&mut cov, &plat);
    }

    if ctx.app_pool.is_none() || ctx.tenant_id.is_none() {
        eval::apply(
            &mut cov,
            &[401, 441],
            CheckStatus::NotObserved,
            "no tenant pool in this run — coverage rows not persisted (findings still emitted)",
        );
    }

    lock_disabled_domains(params, &mut cov);

    let persisted = if ctx.app_pool.is_some() && ctx.tenant_id.is_some() {
        match persist::persist_coverage(ctx, &host.hostname, &cov).await {
            Ok(n) => {
                eval::apply(
                    &mut cov,
                    &[409, 419, 441],
                    CheckStatus::Pass,
                    &format!("bulk UPSERT {n} control rows under SET LOCAL app.current_tenant_id"),
                );
                Some(n)
            }
            Err(e) => {
                tracing::warn!(error = %e, "privilege_escalation coverage persist failed");
                eval::apply(
                    &mut cov,
                    &[409],
                    CheckStatus::Fail,
                    &format!("coverage persist failed: {e}"),
                );
                None
            }
        }
    } else {
        None
    };
    lock_disabled_domains(params, &mut cov);

    let counts = cov.counts();
    let evaluated = counts.pass + counts.fail;
    let score = if evaluated == 0 {
        100u32
    } else {
        (counts.pass * 100) / evaluated
    };
    let grade = match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    };

    let mut domain_scores = serde_json::Map::new();
    for d in Domain::all() {
        let slice = catalog::checks_for_domain(d);
        let mut p = 0u32;
        let mut f = 0u32;
        for c in &slice {
            match cov.slots[(c.id - 1) as usize].status {
                CheckStatus::Pass => p += 1,
                CheckStatus::Fail => f += 1,
                _ => {}
            }
        }
        let ds = if p + f == 0 { 100 } else { (p * 100) / (p + f) };
        domain_scores.insert(
            d.slug().into(),
            json!({ "label": d.label(), "pass": p, "fail": f, "score": ds }),
        );
    }

    let coverage_json: Vec<Value> = cov
        .slots
        .iter()
        .map(|s| {
            json!({
                "id": s.check.id,
                "domain": s.check.domain.slug(),
                "mitre": s.check.mitre,
                "title": s.check.title,
                "status": s.status.slug(),
                "evidence": s.evidence,
            })
        })
        .collect();

    let mut findings = Vec::new();
    let cap = max_findings(params);
    for slot in &cov.slots {
        if slot.status != CheckStatus::Fail {
            continue;
        }
        if findings.len() >= cap {
            break;
        }
        let d = slot.check.domain;
        let mut f = finding(
            ENGINE_ID,
            &slot.check.title,
            severity_for(d, &slot.evidence),
            slot.check.mitre,
            &format!("{} — {}", d.label(), slot.evidence),
            target,
        );
        if let Some(obj) = f.as_object_mut() {
            obj.insert("category".into(), json!("failed_control"));
            obj.insert("check_id".into(), json!(slot.check.id));
            obj.insert("domain".into(), json!(d.slug()));
            obj.insert("evidence".into(), json!({ "detail": slot.evidence }));
            obj.insert("remediation".into(), json!(remediation(d)));
        }
        findings.push(f);
    }

    if ctx.agents.is_none() {
        let mut f = finding(
            ENGINE_ID,
            "PAC-agent Windows LSA/UAC registry requires an enrolled endpoint agent",
            "info",
            "T1548.002",
            "Linux/CI ran live analogs (ptrace, shadow, sudo, maps). Windows EnableLUA/WDigest/RunAsPPL is queried in-process via Win32 RegOpenKeyExW on the agent — never via reg.exe.",
            target,
        );
        if let Some(obj) = f.as_object_mut() {
            obj.insert("category".into(), json!("agent_guidance"));
        }
        findings.push(f);
    }

    let mut posture = finding(
        ENGINE_ID,
        &format!("PAC-500 posture {grade} ({score}/100) — {CHECK_COUNT} controls / {DOMAIN_COUNT} domains"),
        if score >= 80 { "info" } else { "medium" },
        "T1068",
        "Defensive auditor. Findings are configuration and memory-map evidence, not exploit output.",
        target,
    );
    if let Some(obj) = posture.as_object_mut() {
        obj.insert("category".into(), json!("posture_summary"));
        obj.insert(
            "evidence".into(),
            json!({
                "score": score,
                "grade": grade,
                "persisted_rows": persisted,
                "counts": {
                    "pass": counts.pass,
                    "fail": counts.fail,
                    "na": counts.na,
                    "not_observed": counts.not_observed,
                    "evaluated": evaluated,
                },
                "domain_scores": domain_scores,
                "host": host::snapshot_json(&host),
                "remote": remote::remote_json(&remote),
                "platform": platform::platform_json(&plat),
                "coverage": coverage_json,
            }),
        );
        obj.insert(
            "remediation".into(),
            json!("Work failed controls from critical → high. Do not implement offensive syscall stubs or LSASS dumps to verify these checks."),
        );
    }
    findings.insert(0, posture);

    let mut nodes = vec![crate::cloud_hunter::GraphNode {
        id: "auditor".into(),
        label: "Weissman auditor".into(),
        node_type: "root".into(),
        status: "secure".into(),
        cname_target: None,
        raw_finding: None,
    }];
    let mut edges = Vec::new();
    for d in Domain::all() {
        let fails = cov.domain_fail(d);
        if fails == 0 {
            continue;
        }
        let id = d.slug().to_string();
        nodes.push(crate::cloud_hunter::GraphNode {
            id: id.clone(),
            label: format!("{} ({fails} fail)", d.label()),
            node_type: "exposed".into(),
            status: "exposed".into(),
            cname_target: None,
            raw_finding: Some(json!({ "fail": fails, "domain": d.slug() })),
        });
        edges.push(crate::cloud_hunter::GraphEdge {
            id: format!("auditor-{id}"),
            from_id: "auditor".into(),
            to_id: id,
            edge_type: "exposes".into(),
        });
    }

    EngineResult::ok_with_graph(
        findings,
        "privilege escalation & credential access audit complete",
        nodes,
        edges,
    )
}

pub async fn run_priv_esc_cred_access(target: &str) {
    let r = run_priv_esc_cred_access_result(target, &EngineRunContext::default()).await;
    print_result(r);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn engine_runs_against_localhost() {
        let r = run_priv_esc_cred_access_result("127.0.0.1", &EngineRunContext::default()).await;
        assert!(r.success, "{}", r.message);
        assert!(
            r.findings
                .iter()
                .any(|f| f.get("category").and_then(|v| v.as_str()) == Some("posture_summary")),
            "missing posture_summary"
        );
        let posture = r
            .findings
            .iter()
            .find(|f| f.get("category").and_then(|v| v.as_str()) == Some("posture_summary"))
            .unwrap();
        let cov = posture
            .get("evidence")
            .and_then(|e| e.get("coverage"))
            .and_then(|v| v.as_array())
            .expect("coverage array");
        assert_eq!(cov.len(), 500);
        assert!(
            posture
                .get("evidence")
                .and_then(|e| e.get("counts"))
                .and_then(|c| c.get("evaluated"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                > 0,
            "expected live evaluations"
        );
    }

    #[tokio::test]
    async fn disabling_a_domain_marks_na() {
        let ctx = EngineRunContext {
            job_params: json!({"check_uac": false, "check_remote": false}),
            ..EngineRunContext::default()
        };
        let r = run_priv_esc_cred_access_result("127.0.0.1", &ctx).await;
        assert!(r.success);
        let posture = r
            .findings
            .iter()
            .find(|f| f.get("category").and_then(|v| v.as_str()) == Some("posture_summary"))
            .unwrap();
        let cov = posture
            .get("evidence")
            .and_then(|e| e.get("coverage"))
            .and_then(|v| v.as_array())
            .unwrap();
        let uac_na = cov
            .iter()
            .filter(|c| {
                c.get("domain").and_then(|v| v.as_str()) == Some("uac_prevention")
                    && c.get("status").and_then(|v| v.as_str()) == Some("na")
            })
            .count();
        assert_eq!(uac_na, 50);
    }

    #[test]
    fn source_never_spawns_reg_exe() {
        let joined = [
            include_str!("mod.rs"),
            include_str!("host.rs"),
            include_str!("remote.rs"),
            include_str!("platform.rs"),
            include_str!("persist.rs"),
            include_str!("proc_guard.rs"),
            include_str!("eval.rs"),
            include_str!("catalog.rs"),
        ]
        .concat();
        // Needles are split so this test source cannot self-match.
        let spawn_reg = ["Command::new(", "\"reg\")"].concat();
        let spawn_reg_exe = ["Command::new(", "\"reg.exe\")"].concat();
        let unsafe_block = ["un", "safe {"].concat();
        let unsafe_fn = ["un", "safe fn"].concat();
        let inline_asm = ["a", "sm!"].concat();
        assert!(!joined.contains(&spawn_reg));
        assert!(!joined.contains(&spawn_reg_exe));
        assert!(!joined.contains(&unsafe_block));
        assert!(!joined.contains(&unsafe_fn));
        assert!(!joined.contains(&inline_asm));
    }
}
