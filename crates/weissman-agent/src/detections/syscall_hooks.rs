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
    Ok(findings_from_resolver(engine, resolver))
}

pub(crate) fn findings_from_resolver(engine: &str, resolver: &SyscallResolver) -> Vec<Value> {
    let hooked_n = resolver.hooked_count();
    let mut extras = serde_json::Map::new();
    extras.insert("ntdll_mapped".into(), json!(true));
    extras.insert("exports_scanned".into(), json!(resolver.exports_scanned()));
    extras.insert("target_exports_resolved".into(), json!(resolver.len()));
    extras.insert("hooked_stubs".into(), json!(hooked_n));
    extras.insert("scan_capped".into(), json!(resolver.scan_capped()));
    extras.insert(
        "declared_image_size".into(),
        json!(resolver.declared_image_size()),
    );
    extras.insert("hook_hash_alg".into(), json!("murmur3-64"));
    extras.insert(
        "eat_hash_collisions".into(),
        json!(resolver.hash_collisions()),
    );
    extras.insert(
        "halos_cascade_blocked".into(),
        json!(resolver.cascade_blocked()),
    );
    extras.insert(
        "hooked_targets".into(),
        Value::Array(
            resolver
                .entries()
                .iter()
                .filter(|e| e.hooked)
                .take(32)
                .map(|e| {
                    json!({
                        "alg": "sha256-64",
                        "hash": format!("{:016x}", e.hash),
                        "ssn": e.ssn,
                        "rva": e.rva
                    })
                })
                .collect(),
        ),
    );
    extras.insert(
        "hooked_eat".into(),
        Value::Array(
            resolver
                .hook_map()
                .iter()
                .filter(|e| e.hooked)
                .map(|e| {
                    json!({
                        "alg": "murmur3-64",
                        "mmh": format!("{:016x}", e.mmh),
                        "ssn": e.ssn,
                        "rva": e.rva,
                        "cascade_blocked": e.cascade_blocked
                    })
                })
                .collect(),
        ),
    );

    let mut out = Vec::new();
    if resolver.scan_capped() {
        out.push(finding(
            engine,
            "ntdll mapping exceeds 16 MiB scan ceiling — possible EDR memory bloating",
            "high",
            "T1562.001",
            "LDR SizeOfImage (or the copied image) is larger than MAX_NTDLL_SCAN_LIMIT (16 MiB). The agent scanned only the first 16 MiB and did not walk the bloated remainder.",
            extras.clone(),
        ));
    }
    if resolver.hash_collisions() > 0 {
        out.push(finding(
            engine,
            &format!(
                "eat-hook inventory hash collisions on {} MurmurHash3 value(s)",
                resolver.hash_collisions()
            ),
            "medium",
            "T1562.001",
            "Two or more Nt/Zw names hashed to the same MurmurHash3 digest under this agent's per-process seed. Both rows are kept so SOC is not blinded. SHA-256 dispatch is unaffected.",
            extras.clone(),
        ));
    }
    if resolver.cascade_blocked() > 0 {
        out.push(finding(
            engine,
            &format!(
                "Halo's Gate cascade block on {} ntdll export(s) — EDR hooked the target and all ±{} neighbors",
                resolver.cascade_blocked(),
                crate::direct_syscalls::ssn::MAX_HALOS_GATE_NEIGHBOR_DEPTH
            ),
            "high",
            "T1562.001",
            "The hooked stub had no remaining syscall;ret tail and no clean Hell's Gate neighbor within MAX_HALOS_GATE_NEIGHBOR_DEPTH. Dispatch did not issue a guessed SSN. This is active EDR cascade hooking (or an unhook race), not a resolver bypass.",
            extras.clone(),
        ));
    }
    if hooked_n == 0 {
        out.push(finding(
            engine,
            &format!(
                "ntdll Nt/Zw stubs unhooked ({} Nt/Zw exports scanned; {} SHA-256 dispatch targets)",
                resolver.exports_scanned(),
                resolver.len()
            ),
            "info",
            "T1562.001",
            "Every resolved Nt/Zw prologue matched `mov r10, rcx; mov eax, SSN`, or a hooked prologue recovered SSN from the syscall;ret tail / Halo's Gate. No user-mode JMP detour was observed on scanned exports.",
            extras,
        ));
    } else {
        out.push(finding(
            engine,
            &format!("User-mode syscall hooks on {hooked_n} ntdll export(s)"),
            "high",
            "T1562.001",
            "One or more Nt/Zw stubs begin with a JMP (0xE9/FF25) rather than the canonical syscall prologue. SSN was recovered from the remaining syscall;ret tail or from Halo's Gate neighbors. This is the user-mode EDR/AV detour surface — or an unhook attempt.",
            extras,
        ));
    }
    out
}

fn live_or_none() -> Option<&'static SyscallResolver> {
    global_resolver()
}

#[cfg(test)]
mod tests {
    use super::findings_from_resolver;
    use crate::direct_syscalls::fixtures::synthetic_ntdll;
    use crate::direct_syscalls::pe::MAX_NTDLL_SCAN_LIMIT;
    use crate::direct_syscalls::SyscallResolver;

    #[test]
    fn capped_scan_emits_memory_bloat_finding() {
        let mut img = synthetic_ntdll(false);
        img.resize(MAX_NTDLL_SCAN_LIMIT + 0x1000, 0);
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("resolver");
        let findings = findings_from_resolver("syscall_evasion", &resolver);
        let blob = serde_json::to_string(&findings).expect("json");
        assert!(blob.contains("16 MiB"));
        assert!(blob.contains("scan_capped"));
        assert!(blob.contains("murmur3-64"));
        assert!(blob.contains("halos_cascade_blocked"));
        assert!(!blob.contains("fnv1a"));
    }
}
