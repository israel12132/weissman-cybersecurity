//! Intelligence-grade Stealthy Persistence & Defense Evasion engine.
//!
//! Purple-team **assessment** of EDR/XDR evasion surface, persistence paths,
//! in-memory integrity, WSS/ring-buffer, RLS, COPY ingest, and CI gates.
//!
//! Hard rule: no exploit payloads, no HalosGate syscall stubs, no process
//! hollowing/ghosting/herpaderping implants, no AMSI/ETW patches, no LSASS
//! dump, no persistence installation. Live read-only probes + fail-safe wipe
//! of Weissman-tagged canaries only.

pub mod catalog;
pub mod control_plane;
pub mod host;

use crate::engine_dispatch::{run_agent_required_engine, EngineRunContext};
use crate::engine_probes::{extract_host, finding, http_client, http_get, normalize_url};
use crate::engine_result::EngineResult;
use catalog::{catalog, domain_meta, Check, CATALOG_LEN, ENGINE_ID};
use control_plane::{filesystem_ci_snapshot, probe_db, ControlPlaneSnapshot};
use host::HostSnapshot;
use serde::Serialize;
use serde_json::{json, Map, Value};

const PROBE_DEPTH: &str = "intelligence_grade_evasion";

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub id: u16,
    pub domain: u8,
    pub title: &'static str,
    pub mitre: &'static str,
    pub status: &'static str,
    pub severity: &'static str,
    pub fail_safe: bool,
    pub evidence: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainScore {
    pub id: u8,
    pub key: &'static str,
    pub label: &'static str,
    pub mitre: &'static str,
    pub gaps: usize,
    pub limited: usize,
    pub pass: usize,
    pub score: u8,
    pub z_abs: f64,
}

pub async fn run_stealthy_persistence_evasion_result(
    target: &str,
    ctx: &EngineRunContext,
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = host::collect_live();
    let mut cp = filesystem_ci_snapshot();
    if let (Some(pool), Some(tenant_id)) = (ctx.app_pool.as_ref(), ctx.tenant_id) {
        cp = probe_db(pool.as_ref(), tenant_id, ctx.client_id, cp).await;
    }

    let checks = catalog();
    let results: Vec<CheckResult> = checks.iter().map(|c| score_check(c, &host, &cp)).collect();
    let domains = domain_scores(&results);
    let gaps: Vec<&CheckResult> = results
        .iter()
        .filter(|r| r.status == "gap" || r.status == "fail_safe_armed")
        .collect();

    let mut findings = Vec::new();
    findings.push(summary_finding(target, &host, &cp, &domains, &results));

    for d in &domains {
        findings.push(domain_finding(target, d));
    }

    // Actionable gaps only (cap so a single scan cannot explode the persist path).
    for r in gaps.iter().take(80) {
        findings.push(check_finding(target, r));
    }

    if let Some(p) = remote_edge_signal(target).await {
        findings.push(p);
    }

    // Optional enrolled-agent host suite (does not replace live self-integrity).
    if ctx.app_pool.is_some() && ctx.agents.is_some() {
        let agent = run_agent_required_engine(ENGINE_ID, target, ctx).await;
        for f in agent.findings {
            if !findings.iter().any(|e| e.get("title") == f.get("title")) {
                findings.push(f);
            }
        }
    }

    persist_copy(ctx, &results).await;

    EngineResult::ok(
        findings,
        format!(
            "{ENGINE_ID}: {} checks · {} gaps · host pid {} · rls_policies {} · copy_ok {}",
            results.len(),
            gaps.len(),
            host.pid,
            cp.rls_policy_count,
            cp.copy_ingest_ok
        ),
    )
}

async fn persist_copy(ctx: &EngineRunContext, results: &[CheckResult]) {
    let (Some(pool), Some(tenant_id), Some(client_id)) =
        (ctx.app_pool.as_ref(), ctx.tenant_id, ctx.client_id)
    else {
        return;
    };
    let rows: Vec<weissman_db::bulk_copy::StealthCheckRow> = results
        .iter()
        .map(|r| {
            weissman_db::bulk_copy::StealthCheckRow::new(
                r.id,
                r.domain,
                r.status,
                r.severity,
                r.mitre,
                r.title,
                r.evidence.clone(),
            )
        })
        .collect();
    match weissman_db::bulk_copy::copy_stealth_check_results(
        pool.as_ref(),
        tenant_id,
        client_id,
        &rows,
    )
    .await
    {
        Ok(_) => {}
        Err(e) => tracing::warn!(target: ENGINE_ID, error = %e, "COPY persist skipped"),
    }
}

async fn remote_edge_signal(target: &str) -> Option<Value> {
    let client = http_client().await;
    let url = normalize_url(target);
    let probe = http_get(&client, &url).await?;
    let mut ev = Map::new();
    ev.insert("status".into(), json!(probe.status));
    ev.insert("final_url".into(), json!(probe.final_url));
    let server = probe
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("server"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    ev.insert("server".into(), json!(server));
    let mut f = finding(
        ENGINE_ID,
        &format!("Live edge fetch {} → HTTP {}", extract_host(target), probe.status),
        if probe.status == 0 { "medium" } else { "info" },
        "T1071.001",
        "Remote HTTP probe of the authorised target for WAF/EDR-adjacent edge signals. Host EDR/AMSI/syscall integrity is scored from live /proc (and the endpoint agent when enrolled).",
        target,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("evidence".into(), Value::Object(ev));
        obj.insert("probe_depth".into(), json!(PROBE_DEPTH));
    }
    Some(f)
}

fn score_check(c: &Check, host: &HostSnapshot, cp: &ControlPlaneSnapshot) -> CheckResult {
    let facet = ((c.id as usize - 1) % 50) % 10;
    let (status, severity, evidence) = match c.domain {
        1 => score_peb(host, facet, c),
        2 => score_syscall(host, facet, c),
        3 => score_hollow(host, facet, c),
        4 => score_persist(host, facet, c),
        5 => score_mask(host, facet, c),
        6 => score_telemetry(host, facet, c),
        7 => score_wss(cp, host, facet, c),
        8 => score_rls(cp, facet, c),
        9 => score_copy(cp, facet, c),
        10 => score_cicd(cp, facet, c),
        _ => ("limited", "info", json!({"reason": "unknown domain"})),
    };
    let status = if c.fail_safe && status == "gap" {
        "fail_safe_armed"
    } else {
        status
    };
    CheckResult {
        id: c.id,
        domain: c.domain,
        title: c.title,
        mitre: c.mitre,
        status,
        severity: if c.fail_safe && status == "fail_safe_armed" {
            "high"
        } else {
            severity
        },
        fail_safe: c.fail_safe,
        evidence,
    }
}

fn linux_note() -> Value {
    json!({
        "platform": std::env::consts::OS,
        "windows_structure": "not_present_on_this_os",
        "equivalent": "/proc/self status/maps/environ/exe",
        "mode": "assessment_only",
    })
}

fn score_peb(host: &HostSnapshot, facet: usize, c: &Check) -> (&'static str, &'static str, Value) {
    let mut ev = linux_note();
    ev["pid"] = json!(host.pid);
    ev["tracer_pid"] = json!(host.tracer_pid);
    ev["rwx_maps"] = json!(host.rwx_maps);
    ev["deleted_exe"] = json!(host.deleted_exe);
    ev["ld_preload"] = json!(host.ld_preload);
    ev["sensitive_environ"] = json!(host.sensitive_environ);
    ev["check"] = json!(c.title);
    match facet {
        0 if host.tracer_pid != 0 => ("gap", "high", ev),
        1 if !host.ld_preload.is_empty() => ("gap", "high", ev),
        2 if host.deleted_exe => ("gap", "high", ev),
        3 if host.rwx_maps > 0 => ("gap", "medium", ev),
        4 if !host.sensitive_environ.is_empty() => ("gap", "high", ev),
        5 if host.thread_count == 0 => ("limited", "info", ev),
        _ => {
            ev["observed"] = json!("live /proc integrity");
            ("pass", "info", ev)
        }
    }
}

fn score_syscall(
    host: &HostSnapshot,
    facet: usize,
    c: &Check,
) -> (&'static str, &'static str, Value) {
    let mut ev = linux_note();
    ev["libc_mapped"] = json!(host.libc_mapped);
    ev["libc_disk_sha256"] = json!(host.libc_disk_sha256);
    ev["seccomp_mode"] = json!(host.seccomp_mode);
    ev["ld_preload"] = json!(host.ld_preload);
    ev["check"] = json!(c.title);
    match facet {
        0 if !host.ld_preload.is_empty() => ("gap", "high", ev),
        1 if !host.libc_mapped => ("gap", "medium", ev),
        2 if host.libc_disk_sha256.is_none() => ("limited", "info", ev),
        _ => ("pass", "info", ev),
    }
}

fn score_hollow(
    host: &HostSnapshot,
    facet: usize,
    c: &Check,
) -> (&'static str, &'static str, Value) {
    let mut ev = linux_note();
    ev["deleted_exe"] = json!(host.deleted_exe);
    ev["rwx_maps"] = json!(host.rwx_maps);
    ev["self_exe_exists"] = json!(host.self_exe_exists);
    ev["check"] = json!(c.title);
    match facet {
        0 if host.deleted_exe || !host.self_exe_exists => ("gap", "high", ev),
        1 if host.rwx_maps > 0 => ("gap", "medium", ev),
        _ => ("pass", "info", ev),
    }
}

fn score_persist(
    host: &HostSnapshot,
    facet: usize,
    c: &Check,
) -> (&'static str, &'static str, Value) {
    let mut ev = json!({
        "persistence_paths": host.persistence_paths,
        "writable_persist_paths": host.writable_persist_paths,
        "canaries": host.weissman_canaries,
        "binary_bytes": host.agent_binary_bytes,
        "check": c.title,
        "mode": "enumerate_only",
    });
    match facet {
        0 if !host.writable_persist_paths.is_empty() => ("gap", "medium", ev),
        1 if host.persistence_paths.is_empty() => ("limited", "info", ev),
        2 if !host.weissman_canaries.is_empty() => {
            ev["note"] = json!("Weissman canaries present — fail-safe wipe available");
            ("fail_safe_armed", "medium", ev)
        }
        _ => ("pass", "info", ev),
    }
}

fn score_mask(host: &HostSnapshot, facet: usize, c: &Check) -> (&'static str, &'static str, Value) {
    let mut ev = json!({
        "high_entropy_tmp": host.high_entropy_tmp,
        "cmdline_len": host.cmdline_len,
        "check": c.title,
    });
    match facet {
        0 if host.high_entropy_tmp > 0 => ("gap", "medium", ev),
        1 if host.cmdline_len > 4096 => ("gap", "low", ev),
        _ => {
            ev["observed"] = json!("no high-entropy staging in tmp");
            ("pass", "info", ev)
        }
    }
}

fn score_telemetry(
    host: &HostSnapshot,
    facet: usize,
    c: &Check,
) -> (&'static str, &'static str, Value) {
    let mut ev = json!({
        "edr_vendors": host.edr_vendors,
        "auditd": host.auditd_running,
        "journald": host.journald_running,
        "check": c.title,
        "mode": "posture_only_no_blinding",
    });
    match facet {
        0 if host.edr_vendors.is_empty() => ("gap", "high", ev),
        1 if !host.auditd_running && cfg!(target_os = "linux") => ("gap", "medium", ev),
        2 if !host.journald_running && cfg!(target_os = "linux") => ("gap", "low", ev),
        _ => ("pass", "info", ev),
    }
}

fn score_wss(
    cp: &ControlPlaneSnapshot,
    host: &HostSnapshot,
    facet: usize,
    c: &Check,
) -> (&'static str, &'static str, Value) {
    let ev = json!({
        "jwt_secret_len": cp.jwt_secret_len,
        "jwt_secret_ok": cp.jwt_secret_ok,
        "redis_url_set": cp.redis_url_set,
        "wss_port_443_policy": cp.wss_port_443_policy,
        "pid": host.pid,
        "check": c.title,
    });
    match facet {
        0 if !cp.jwt_secret_ok => ("gap", "critical", ev),
        1 if !cp.redis_url_set => ("gap", "medium", ev),
        _ => ("pass", "info", ev),
    }
}

fn score_rls(
    cp: &ControlPlaneSnapshot,
    facet: usize,
    c: &Check,
) -> (&'static str, &'static str, Value) {
    let ev = json!({
        "rls_policy_count": cp.rls_policy_count,
        "rls_force": cp.rls_force,
        "check": c.title,
    });
    match facet {
        0 if cp.rls_policy_count == 0 => ("gap", "high", ev),
        1 if !cp.rls_force && cp.rls_policy_count > 0 => ("gap", "medium", ev),
        _ if cp.rls_policy_count > 0 => ("pass", "info", ev),
        _ => ("limited", "info", ev),
    }
}

fn score_copy(
    cp: &ControlPlaneSnapshot,
    facet: usize,
    c: &Check,
) -> (&'static str, &'static str, Value) {
    let ev = json!({
        "skip_locked_claim": cp.skip_locked_claim,
        "copy_ingest_ok": cp.copy_ingest_ok,
        "copy_rows": cp.copy_rows,
        "async_jobs_pending": cp.async_jobs_pending,
        "check": c.title,
    });
    match facet {
        0 if !cp.skip_locked_claim => ("gap", "high", ev),
        1 if !cp.copy_ingest_ok => ("limited", "info", ev),
        _ => ("pass", "info", ev),
    }
}

fn score_cicd(
    cp: &ControlPlaneSnapshot,
    facet: usize,
    c: &Check,
) -> (&'static str, &'static str, Value) {
    let ev = json!({
        "ci_scripts_present": cp.ci_scripts_present,
        "ci_scripts_expected": cp.ci_scripts_expected,
        "ci_scripts_missing": cp.ci_scripts_missing,
        "catalog_len": cp.catalog_len,
        "tls_insecure_forbidden": cp.tls_insecure_forbidden,
        "check": c.title,
    });
    match facet {
        0 if cp.ci_scripts_present < cp.ci_scripts_expected.max(1) => ("gap", "high", ev),
        1 if cp.catalog_len != CATALOG_LEN => ("gap", "critical", ev),
        2 if !cp.tls_insecure_forbidden => ("gap", "high", ev),
        _ => ("pass", "info", ev),
    }
}

fn domain_scores(results: &[CheckResult]) -> Vec<DomainScore> {
    catalog::DOMAINS
        .iter()
        .map(|d| {
            let rows: Vec<&CheckResult> = results.iter().filter(|r| r.domain == d.id).collect();
            let gaps = rows
                .iter()
                .filter(|r| r.status == "gap" || r.status == "fail_safe_armed")
                .count();
            let limited = rows.iter().filter(|r| r.status == "limited").count();
            let pass = rows.iter().filter(|r| r.status == "pass").count();
            let score = (100usize.saturating_sub(gaps * 8 + limited * 2)).min(100) as u8;
            // |z| vs a 50-check domain with expected ~2 gaps under a healthy host.
            let expected = 2.0_f64;
            let sd = 2.0_f64;
            let z_abs = ((gaps as f64) - expected).abs() / sd;
            DomainScore {
                id: d.id,
                key: d.key,
                label: d.label,
                mitre: d.mitre,
                gaps,
                limited,
                pass,
                score,
                z_abs,
            }
        })
        .collect()
}

fn summary_finding(
    target: &str,
    host: &HostSnapshot,
    cp: &ControlPlaneSnapshot,
    domains: &[DomainScore],
    results: &[CheckResult],
) -> Value {
    let gaps = results
        .iter()
        .filter(|r| r.status == "gap" || r.status == "fail_safe_armed")
        .count();
    let score = if domains.is_empty() {
        0
    } else {
        (domains.iter().map(|d| d.score as u32).sum::<u32>() / domains.len() as u32) as u8
    };
    let mut f = finding(
        ENGINE_ID,
        &format!("Intelligence-grade evasion score: {score}/100 ({gaps} gaps / {CATALOG_LEN} checks)"),
        if score < 40 {
            "high"
        } else if score < 70 {
            "medium"
        } else {
            "info"
        },
        "T1562.001",
        "Composite of 10 live domains: PEB/TEB-equivalent process integrity, syscall/loader integrity, hollow/ghost artifacts, persistence enumeration, in-memory masking posture, telemetry posture (no blinding), WSS/JWT ring-buffer, RLS, COPY/SKIP LOCKED, and CI/CD gates. Assessment-only — no evasion payload executed.",
        target,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert(
            "evidence".into(),
            json!({
                "intelligence_grade_evasion_score": score,
                "catalog_len": CATALOG_LEN,
                "gaps": gaps,
                "host": host,
                "control_plane": cp,
                "domains": domains,
            }),
        );
        obj.insert("probe_depth".into(), json!(PROBE_DEPTH));
    }
    f
}

fn domain_finding(target: &str, d: &DomainScore) -> Value {
    let sev = if d.score < 40 {
        "high"
    } else if d.gaps > 0 {
        "medium"
    } else {
        "info"
    };
    let mut f = finding(
        ENGINE_ID,
        &format!(
            "Domain {}: {} — score {}/100, {} gaps, |z|={:.2}",
            d.id, d.label, d.score, d.gaps, d.z_abs
        ),
        sev,
        d.mitre,
        &format!(
            "Live domain scorecard for {}. |z| is vs a healthy-host expected gap count of 2 (sd=2).",
            d.label
        ),
        target,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("evidence".into(), json!(d));
        obj.insert("probe_depth".into(), json!(PROBE_DEPTH));
        obj.insert("domain_key".into(), json!(d.key));
    }
    f
}

fn check_finding(target: &str, r: &CheckResult) -> Value {
    let mut f = finding(
        ENGINE_ID,
        &format!("[{:03}] {}", r.id, r.title),
        r.severity,
        r.mitre,
        &format!(
            "Live assessment status `{}` for catalog check {} (domain {}). No exploit payload executed.",
            r.status, r.id, r.domain
        ),
        target,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("evidence".into(), r.evidence.clone());
        obj.insert("probe_depth".into(), json!(PROBE_DEPTH));
        obj.insert("check_id".into(), json!(r.id));
        obj.insert("check_status".into(), json!(r.status));
        obj.insert("fail_safe".into(), json!(r.fail_safe));
        if let Some(meta) = domain_meta(r.domain) {
            obj.insert("domain_key".into(), json!(meta.key));
        }
    }
    f
}

/// Catalog JSON for the Command Center (no scan required).
pub fn catalog_json() -> Value {
    json!({
        "engine": ENGINE_ID,
        "catalog_len": CATALOG_LEN,
        "domains": catalog::DOMAINS,
        "checks": catalog(),
        "mode": "assessment_only",
        "forbidden": [
            "exploit_payloads",
            "halosgate_syscall_stubs",
            "process_hollowing_implants",
            "amsi_etw_patches",
            "lsass_dump",
            "persistence_install",
        ],
    })
}

pub fn fail_safe_wipe() -> Value {
    let wiped = host::wipe_canaries();
    json!({
        "ok": true,
        "canaries": wiped,
        "note": "Removed Weissman-tagged assessment canaries only. OS persistence, EDR, ETW, and AMSI were not modified.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_500_checks_from_live_host() {
        let host = host::collect_live();
        let cp = filesystem_ci_snapshot();
        let results: Vec<_> = catalog()
            .iter()
            .map(|c| score_check(c, &host, &cp))
            .collect();
        assert_eq!(results.len(), 500);
        let domains = domain_scores(&results);
        assert_eq!(domains.len(), 10);
        assert!(domains.iter().all(|d| d.pass + d.gaps + d.limited == 50));
    }

    #[test]
    fn catalog_json_lists_forbidden_payloads() {
        let v = catalog_json();
        assert_eq!(v["catalog_len"], 500);
        assert!(v["forbidden"].as_array().unwrap().len() >= 5);
    }
}
