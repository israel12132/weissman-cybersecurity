//! Host-resident ntdll syscall-stub integrity check (Hell's Gate / Halo's Gate).
//!
//! On Windows x64 the agent walks the live EAT, recovers SSNs, and reports every
//! Nt/Zw export whose prologue is a user-mode JMP (EDR hook). On any other OS
//! the detection returns no findings — a network/Linux host has no ntdll to scan,
//! and we never fabricate a Windows hook.

use super::finding;
use crate::direct_syscalls::{global_resolver, SyscallResolver};
use serde_json::{json, Value};

pub async fn run(engine: &str) -> anyhow::Result<Vec<Value>> {
    // The EAT walk is microseconds; run inline so CI/operator dry-run stays sub-millisecond
    // instead of paying a spawn_blocking thread-pool hop.
    scan(engine)
}

fn scan(engine: &str) -> anyhow::Result<Vec<Value>> {
    if !cfg!(all(windows, target_arch = "x86_64")) {
        return Ok(Vec::new());
    }
    let Some(resolver) = live_or_none() else {
        let mut extras = serde_json::Map::new();
        extras.insert("os".into(), json!(std::env::consts::OS));
        extras.insert("arch".into(), json!(std::env::consts::ARCH));
        extras.insert("ntdll_mapped".into(), json!(false));
        return Ok(vec![finding(
            engine,
            "ntdll EAT could not be mapped for syscall-stub inspection",
            "info",
            "T1562.001",
            "The agent walked the PEB for ntdll.dll but could not parse a PE32+ export table. No hook finding is emitted without that evidence.",
            extras,
        )]);
    };

    let hooked_n = resolver.hooked_count();
    let mut extras = serde_json::Map::new();
    extras.insert("ntdll_mapped".into(), json!(true));
    extras.insert("exports_scanned".into(), json!(resolver.exports_scanned()));
    extras.insert("target_exports_resolved".into(), json!(resolver.len()));
    extras.insert("hooked_stubs".into(), json!(hooked_n));
    extras.insert(
        "hooked_hashes".into(),
        Value::Array(
            resolver
                .entries()
                .iter()
                .filter(|e| e.hooked)
                .take(32)
                .map(|e| json!({ "hash": format!("{:016x}", e.hash), "ssn": e.ssn, "rva": e.rva }))
                .collect(),
        ),
    );

    if hooked_n == 0 {
        Ok(vec![finding(
            engine,
            &format!(
                "ntdll Nt/Zw stubs unhooked ({} of {} Nt/Zw exports scanned via Hell's Gate)",
                resolver.len(),
                resolver.exports_scanned()
            ),
            "info",
            "T1562.001",
            "Every resolved Nt/Zw prologue matched `mov r10, rcx; mov eax, SSN`. No user-mode JMP detour was observed; Halo's Gate was not required.",
            extras,
        )])
    } else {
        Ok(vec![finding(
            engine,
            &format!("User-mode syscall hooks on {hooked_n} ntdll export(s)"),
            "high",
            "T1562.001",
            "One or more Nt/Zw stubs begin with a JMP (0xE9/FF25) rather than the canonical syscall prologue. Halo's Gate recovered the real SSN from neighboring stubs. This is the user-mode EDR/AV detour surface — or an unhook attempt.",
            extras,
        )])
    }
}

fn live_or_none() -> Option<&'static SyscallResolver> {
    global_resolver()
}
