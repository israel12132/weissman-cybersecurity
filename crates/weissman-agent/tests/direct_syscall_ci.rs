//! CI/CD: Hell's Gate / Halo's Gate resolution latency and dry-run honesty.

use std::time::{Duration, Instant};
use weissman_agent::direct_syscalls::fixtures::{synthetic_ntdll, FIXTURE_SSN_ALLOCATE};
use weissman_agent::direct_syscalls::{
    weissman_allocate_virtual_memory, SyscallResolver, MEM_COMMIT, MEM_RESERVE,
    NT_ALLOCATE_VIRTUAL_MEMORY, NT_CURRENT_PROCESS, PAGE_READWRITE, STATUS_NOT_IMPLEMENTED,
};
use weissman_agent::probe::run_dry;

#[test]
fn hells_gate_halos_gate_parse_and_resolve_under_one_millisecond() {
    let img = synthetic_ntdll(true);
    let start = Instant::now();
    let resolver = SyscallResolver::from_pe_bytes(&img).expect("parse hooked ntdll fixture");
    let parse_elapsed = start.elapsed();
    let lookup_start = Instant::now();
    let entry = resolver
        .resolve_by_hash(NT_ALLOCATE_VIRTUAL_MEMORY)
        .expect("allocate hash");
    let lookup_elapsed = lookup_start.elapsed();

    println!(
        "[CI/CD] Direct syscall EAT parse {:?}; hash resolve {:?}",
        parse_elapsed, lookup_elapsed
    );
    assert!(
        parse_elapsed < Duration::from_millis(1),
        "EAT parse {parse_elapsed:?} must be sub-millisecond"
    );
    assert!(
        lookup_elapsed < Duration::from_millis(1),
        "SSN resolve {lookup_elapsed:?} must be sub-millisecond"
    );
    assert!(entry.hooked);
    assert_eq!(entry.ssn, FIXTURE_SSN_ALLOCATE);
}

#[test]
fn allocate_is_not_implemented_off_windows_and_does_not_panic() {
    let start = Instant::now();
    unsafe {
        let mut base = std::ptr::null_mut();
        let mut region_size = 4096usize;
        let status = weissman_allocate_virtual_memory(
            NT_CURRENT_PROCESS,
            &mut base,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if cfg!(all(windows, target_arch = "x86_64")) {
            assert_eq!(status, 0, "Windows allocation should return STATUS_SUCCESS");
            assert!(!base.is_null());
        } else {
            assert_eq!(status, STATUS_NOT_IMPLEMENTED);
            assert!(base.is_null());
        }
    }
    let duration = start.elapsed();
    println!("[CI/CD] Direct syscall dispatch latency: {duration:?}");
    assert!(
        duration < Duration::from_millis(5),
        "dispatch wrapper {duration:?} must stay in the millisecond budget"
    );
}

#[tokio::test]
async fn syscall_evasion_dry_run_never_fabricates() {
    let report = run_dry("syscall_evasion")
        .await
        .expect("syscall_evasion detection");
    let encoded = serde_json::to_string(&report).expect("json");
    println!("[CI/CD] syscall_evasion dry-run: {encoded}");
    assert!(report.outcome == "finding_detected" || report.outcome == "no_vulnerability_found");
    assert!(!report.fabrication_detected);
    assert!(!encoded.contains("fabrication_detected"));
}

#[tokio::test]
async fn process_hollowing_dry_run_is_evidence_backed() {
    let report = run_dry("process_hollowing")
        .await
        .expect("process_hollowing detection");
    assert!(!report.fabrication_detected);
    assert!(report.outcome == "finding_detected" || report.outcome == "no_vulnerability_found");
}
