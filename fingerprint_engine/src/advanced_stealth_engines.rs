//! Advanced Stealth/Evasion engines — real HTTP/security-header analysis. No simulation.

use crate::engine_probes::{
    empty_ok, finding, has_header, header_value, http_client, http_get, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

pub async fn run_process_hollowing_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "process_hollowing",
        t,
        "Process hollowing / injection requires host memory inspection",
        "T1055.012 hollowing swaps code inside a live process — invisible to HTTP/DNS probes. The Weissman agent monitors cross-process memory writes, suspicious section mappings, and hollowed-image signatures.",
    )
}
cli_wrapper!(run_process_hollowing, run_process_hollowing_result);

pub async fn run_dll_hijacking_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "dll_hijacking_engine",
        t,
        "DLL search-order / phantom-DLL hijacking requires host filesystem + loader inspection",
        "T1574.001 plants a malicious DLL in a writable path earlier in a legitimate process's search order — a host filesystem/loader condition with no network signal. The Weissman agent audits DLL search paths, unsigned module loads, and phantom-DLL write targets.",
    )
}
cli_wrapper!(run_dll_hijacking_engine, run_dll_hijacking_engine_result);

pub async fn run_living_off_land_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();

    let script_paths = [
        "/scripts/",
        "/js/",
        "/static/js/",
        "/assets/js/",
        "/api/exec",
        "/api/run",
        "/download/",
        "/powershell",
        "/shell",
        "/bin/",
        "/tools/",
    ];
    let script_content_types = [
        "application/javascript",
        "text/javascript",
        "application/x-powershell",
        "text/plain",
        "application/octet-stream",
    ];

    for path in script_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status >= 200 && p.status < 400 {
                if let Some(ct) = header_value(&p.headers, "content-type") {
                    let ct_low = ct.to_ascii_lowercase();
                    if script_content_types.iter().any(|s| ct_low.contains(s)) {
                        findings.push(finding(
                            "living_off_land",
                            &format!("Script-friendly content-type on {}", path),
                            "medium",
                            "T1218",
                            &format!(
                                "{} serves Content-Type '{}' — review for LOLBin/script delivery (mshta, regsvr32, powershell download cradle).",
                                p.final_url, ct
                            ),
                            t,
                        ));
                    }
                }
            }
        }
    }

    let dangerous_ext = [
        ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".dll", ".scr", ".msi",
    ];
    let upload_bases = [
        "/upload/",
        "/uploads/",
        "/files/",
        "/static/",
        "/media/",
        "/assets/",
        "/download/",
    ];
    for upload_base in upload_bases {
        for ext in dangerous_ext {
            let url = format!("{}{}probe{}", base.trim_end_matches('/'), upload_base, ext);
            if let Some(p) = http_get(&client, &url).await {
                if p.status == 200 && !p.body.trim().is_empty() {
                    findings.push(finding(
                        "living_off_land",
                        &format!("Dangerous extension reachable under {}{}", upload_base, ext),
                        "high",
                        "T1218",
                        &format!(
                            "{} returned HTTP 200 for a {} file — attackers may host LOLBins for download-and-execute chains.",
                            p.final_url, ext
                        ),
                        t,
                    ));
                }
            }
        }
    }

    if let Some(p) = http_get(&client, &base).await {
        let body_low = p.body.to_ascii_lowercase();
        for ext in dangerous_ext {
            if body_low.contains(ext) {
                findings.push(finding(
                    "living_off_land",
                    &format!("Page references {} artifacts", ext),
                    "medium",
                    "T1218",
                    &format!(
                        "Response from {} links to or mentions '{}' — verify these are not user-uploaded script payloads.",
                        p.final_url, ext
                    ),
                    t,
                ));
                break;
            }
        }
        if !has_header(&p.headers, "x-content-type-options") {
            findings.push(finding(
                "living_off_land",
                "Missing X-Content-Type-Options (MIME sniffing aids LOLBin delivery)",
                "low",
                "T1218",
                &format!(
                    "{} lacks X-Content-Type-Options: nosniff — browsers may misinterpret uploaded script content.",
                    p.final_url
                ),
                t,
            ));
        }
    }

    if findings.is_empty() {
        empty_ok("living_off_land", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!(
                "living_off_land: {} remote LOLBin surface signal(s)",
                findings.len()
            ),
        )
    }
}
cli_wrapper!(run_living_off_land, run_living_off_land_result);

pub async fn run_sandbox_evasion_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "sandbox_evasion",
        t,
        "Sandbox-evasion detection requires detonation telemetry",
        "T1497 environment checks (VM artifacts, user-activity, timing) run inside the sample on the host to decide whether to detonate — not observable over HTTP. The Weissman agent performs instrumented detonation and flags environment-fingerprinting behavior.",
    )
}
cli_wrapper!(run_sandbox_evasion, run_sandbox_evasion_result);

pub async fn run_rootkit_surface_probe_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "rootkit_surface_probe",
        t,
        "Rootkit assessment requires kernel/host integrity inspection",
        "T1014 rootkits hide processes, files and sockets from userland by patching the kernel or hooking syscalls — a network scan cannot see what the kernel is told to hide. The Weissman agent cross-checks kernel structures, SSDT/IDT hooks, and hidden-object discrepancies.",
    )
}
cli_wrapper!(run_rootkit_surface_probe, run_rootkit_surface_probe_result);

/// Legacy CLI name — delegates to live EDR surface probe.
pub async fn run_rootkit_simulation_result(t: &str) -> EngineResult {
    run_rootkit_surface_probe_result(t).await
}
cli_wrapper!(run_rootkit_simulation, run_rootkit_simulation_result);

pub async fn run_memory_forensics_evasion_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "memory_forensics_evasion",
        t,
        "Memory-forensics evasion requires live-memory acquisition",
        "T1055/T1620 direct-kernel-object manipulation, unlinked pages and anti-dump tricks defeat post-mortem analysis in RAM — a network probe cannot see process memory. The Weissman agent runs volatile-memory integrity checks and detects hidden/unlinked artifacts.",
    )
}
cli_wrapper!(
    run_memory_forensics_evasion,
    run_memory_forensics_evasion_result
);

pub async fn run_av_bypass_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "av_bypass_engine",
        t,
        "AV/EDR bypass validation requires host endpoint telemetry",
        "T1562.001 bypass (userland unhooking, AMSI patching, direct syscalls) manipulates the local security stack inside a process — invisible to a remote probe. The Weissman agent detects hook tampering, AMSI/ETW patching, and direct-syscall stubs.",
    )
}
cli_wrapper!(run_av_bypass_engine, run_av_bypass_engine_result);

pub async fn run_dns_tunneling_c2_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let host = crate::engine_probes::extract_host(t);
    let txts = crate::engine_probes::dns_txt(&host).await;
    let mut findings: Vec<Value> = Vec::new();
    for r in txts.iter() {
        if r.len() > 200 {
            findings.push(finding(
                "dns_tunneling_c2",
                "Unusually long TXT record (possible tunnel)",
                "medium",
                "T1071.004",
                &format!(
                    "TXT record on {} is {} chars — long records can carry C2 payloads.",
                    host,
                    r.len()
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("dns_tunneling_c2", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("dns_tunneling_c2: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_dns_tunneling_c2, run_dns_tunneling_c2_result);

pub async fn run_steganography_c2_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if let Some(ct) = header_value(&p.headers, "content-type") {
            if ct.starts_with("image/") && p.body.len() > 500_000 {
                findings.push(finding(
                    "steganography_c2",
                    "Large image asset",
                    "info",
                    "T1027.003",
                    &format!(
                        "{} delivers a {} of {} B — review for hidden payload via stego analysis.",
                        p.final_url,
                        ct,
                        p.body.len()
                    ),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("steganography_c2", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("steganography_c2: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_steganography_c2, run_steganography_c2_result);

pub async fn run_https_c2_masquerade_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let server = header_value(&p.headers, "server").unwrap_or("");
        if server.is_empty() {
            findings.push(finding(
                "https_c2_masquerade",
                "No Server header (could be domain-fronting/proxy)",
                "info",
                "T1090.004",
                &format!(
                    "Response from {} lacks Server header — typical of CDN/domain fronting.",
                    p.final_url
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok("https_c2_masquerade", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("https_c2_masquerade: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_https_c2_masquerade, run_https_c2_masquerade_result);

pub async fn run_icmp_covert_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "icmp_covert",
        t,
        "ICMP covert-channel detection requires packet-level traffic inspection",
        "T1095 covert channels tunnel data inside ICMP echo payloads and inter-packet timing — detectable only by inspecting the packet stream, not HTTP headers. The Weissman agent / network sensor performs ICMP payload-entropy and timing analysis.",
    )
}
cli_wrapper!(run_icmp_covert, run_icmp_covert_result);

pub async fn run_rop_chain_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "rop_chain_engine",
        t,
        "ROP/JOP chain execution requires host runtime inspection",
        "T1055 return/jump-oriented programming reuses in-memory gadgets while exploiting a live process — there is no network-observable signal. The Weissman agent enforces CFI / shadow-stack telemetry and detects gadget-chain execution.",
    )
}
cli_wrapper!(run_rop_chain_engine, run_rop_chain_engine_result);

pub async fn run_heap_exploitation_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "heap_exploitation",
        t,
        "Heap exploitation requires host memory / runtime instrumentation",
        "T1055 heap grooming, use-after-free and allocator-metadata corruption happen inside a live process's memory — invisible to HTTP/DNS probes. The Weissman agent instruments allocator telemetry and flags heap-spray / corruption patterns at runtime.",
    )
}
cli_wrapper!(run_heap_exploitation, run_heap_exploitation_result);

pub async fn run_timing_evasion_engine_result(t: &str) -> EngineResult {
    crate::timing_sidechannel_engine::run_timing_sidechannel_result(t).await
}
cli_wrapper!(run_timing_evasion_engine, run_timing_evasion_engine_result);

pub async fn run_log_tampering_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "log_tampering_engine",
        t,
        "Log-tampering detection requires audit-trail integrity telemetry",
        "T1562.008 clears or modifies audit logs on the host or in the cloud control plane — confirmable only against the actual log store, not response headers. The Weissman agent + SIEM integration verify append-only audit-chain integrity and detect gaps/clears.",
    )
}
cli_wrapper!(run_log_tampering_engine, run_log_tampering_engine_result);

pub async fn run_jit_spray_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "jit_spray",
        t,
        "JIT spray requires host JIT-page inspection",
        "T1055 JIT spray writes executable gadgets into a JIT compiler's code cache on the victim host — not observable from a remote probe. The Weissman agent monitors RWX JIT pages and anomalous code-cache growth.",
    )
}
cli_wrapper!(run_jit_spray, run_jit_spray_result);

pub async fn run_com_hijacking_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "com_hijacking",
        t,
        "COM hijacking requires host registry inspection",
        "T1546.015 redirects a COM CLSID to an attacker DLL via HKCU registry keys, executed on the host — no remote signal. The Weissman agent audits COM CLSID registrations and hijackable InprocServer32 entries.",
    )
}
cli_wrapper!(run_com_hijacking, run_com_hijacking_result);

pub async fn run_network_traffic_masking_result(t: &str) -> EngineResult {
    crate::stealth_engine::run_stealth_engine_result(t).await
}
cli_wrapper!(
    run_network_traffic_masking,
    run_network_traffic_masking_result
);

pub async fn run_anti_debug_evasion_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "anti_debug_evasion",
        t,
        "Anti-debug technique detection requires host process telemetry",
        "T1622 anti-debugging (IsDebuggerPresent, timing checks, INT3 scanning) runs inside the target process against a debugger — invisible to a network probe. The Weissman agent correlates anti-debug API usage and process self-inspection.",
    )
}
cli_wrapper!(run_anti_debug_evasion, run_anti_debug_evasion_result);

pub async fn run_parent_pid_spoof_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "parent_pid_spoof",
        t,
        "Parent-PID spoofing requires host process-tree telemetry",
        "T1134.004 forges a process's parent to blend malicious children under a trusted process — a host process-creation event invisible to network probes. The Weissman agent reconstructs the true process tree and flags PPID/creator mismatches.",
    )
}
cli_wrapper!(run_parent_pid_spoof, run_parent_pid_spoof_result);
