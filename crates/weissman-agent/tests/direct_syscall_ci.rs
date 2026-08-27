//! CI/CD: Hell's Gate / Halo's Gate resolution latency and dry-run honesty.

use std::time::{Duration, Instant};
use weissman_agent::direct_syscalls::fixtures::{synthetic_ntdll, FIXTURE_SSN_ALLOCATE};
use weissman_agent::direct_syscalls::{
    weissman_allocate_virtual_memory, SyscallResolver, MEM_COMMIT, MEM_RESERVE,
    NT_ALLOCATE_VIRTUAL_MEMORY, NT_CURRENT_PROCESS, PAGE_READWRITE, STATUS_NOT_IMPLEMENTED,
};
use weissman_agent::probe::run_dry;

/// Quiet-host EAT parse is tens of microseconds. GitHub-hosted runners under
/// `cargo test --workspace` add 1–2 ms of scheduler noise to a single sample
/// (observed 1.87 ms parse / 995 µs lookup on ubuntu-latest). Gate the *median*
/// of warmed-up samples at 10 ms so a real regression (sleep, I/O, subprocess)
/// still fails while CI noise does not.
const CI_LATENCY_CEILING: Duration = Duration::from_millis(10);
const LATENCY_SAMPLES: usize = 32;

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

#[test]
fn hells_gate_halos_gate_parse_and_resolve_is_fast() {
    let img = synthetic_ntdll(true);
    // Page in the fixture and parser so the timed samples are not cold-start.
    let _ = SyscallResolver::from_pe_bytes(&img).expect("warmup parse");

    let mut parse_samples = Vec::with_capacity(LATENCY_SAMPLES);
    let mut resolver = None;
    for _ in 0..LATENCY_SAMPLES {
        let start = Instant::now();
        resolver = Some(SyscallResolver::from_pe_bytes(&img).expect("parse hooked ntdll fixture"));
        parse_samples.push(start.elapsed());
    }
    let resolver = resolver.expect("resolver");

    let mut lookup_samples = Vec::with_capacity(LATENCY_SAMPLES);
    for _ in 0..LATENCY_SAMPLES {
        let start = Instant::now();
        let entry = resolver
            .resolve_by_hash(NT_ALLOCATE_VIRTUAL_MEMORY)
            .expect("allocate hash");
        lookup_samples.push(start.elapsed());
        assert!(entry.hooked);
        assert_eq!(entry.ssn, FIXTURE_SSN_ALLOCATE);
    }

    let parse_min = parse_samples.iter().min().copied().unwrap();
    let parse_max = parse_samples.iter().max().copied().unwrap();
    let lookup_min = lookup_samples.iter().min().copied().unwrap();
    let lookup_max = lookup_samples.iter().max().copied().unwrap();
    let parse_med = median(parse_samples);
    let lookup_med = median(lookup_samples);
    println!(
        "[CI/CD] Direct syscall EAT parse min={parse_min:?} median={parse_med:?} max={parse_max:?}; hash resolve min={lookup_min:?} median={lookup_med:?} max={lookup_max:?}"
    );
    assert!(
        parse_med < CI_LATENCY_CEILING,
        "EAT parse median {parse_med:?} must stay under {CI_LATENCY_CEILING:?}"
    );
    assert!(
        lookup_med < CI_LATENCY_CEILING,
        "SSN resolve median {lookup_med:?} must stay under {CI_LATENCY_CEILING:?}"
    );
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
