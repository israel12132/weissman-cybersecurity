//! NUMA-aware Tokio worker pinning (Linux + optional `numa` feature via hwloc).
//! Set `WEISSMAN_NUMA_PIN=1` on multi-socket hosts when built with `--features numa`.
//! Optional explicit CPU list: `WEISSMAN_TOKIO_CPU_AFFINITY=0,1,8-11` binds each worker round-robin (libc);
//! when set, it overrides `WEISSMAN_NUMA_PIN`. Pair with external `taskset` / cgroup for the vLLM process on P-cores.

use std::io;

/// Parse `WEISSMAN_TOKIO_CPU_AFFINITY`: comma-separated entries, each a single id or `start-end` inclusive.
pub fn parse_cpu_affinity_list(raw: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let start = a.trim().parse::<usize>().ok();
            let end = b.trim().parse::<usize>().ok();
            if let (Some(s), Some(e)) = (start, end) {
                if s <= e {
                    out.extend(s..=e);
                }
            }
        } else if let Ok(n) = part.parse::<usize>() {
            out.push(n);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn tokio_cpu_affinity_cpus() -> Vec<usize> {
    std::env::var("WEISSMAN_TOKIO_CPU_AFFINITY")
        .ok()
        .map(|s| parse_cpu_affinity_list(s.trim()))
        .filter(|v| !v.is_empty())
        .unwrap_or_default()
}

/// Count physical cores from `/proc/cpuinfo` (`physical id` + `core id` pairs).
/// Falls back to `available_parallelism` (logical CPUs) when the file is missing.
#[must_use]
pub fn physical_cpu_count() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
            if let Some(n) = parse_physical_cpus_from_cpuinfo(&text) {
                if n > 0 {
                    return n;
                }
            }
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}

/// Parse unique `(physical id, core id)` pairs from a `/proc/cpuinfo` dump.
#[must_use]
pub fn parse_physical_cpus_from_cpuinfo(text: &str) -> Option<usize> {
    use std::collections::BTreeSet;
    let mut phys: Option<u32> = None;
    let mut core: Option<u32> = None;
    let mut set = BTreeSet::new();
    let mut flush = |phys: &mut Option<u32>, core: &mut Option<u32>| {
        if let (Some(p), Some(c)) = (*phys, *core) {
            set.insert((p, c));
        }
        *phys = None;
        *core = None;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            flush(&mut phys, &mut core);
            continue;
        }
        if let Some(rest) = line.strip_prefix("physical id") {
            phys = rest
                .rsplit_once(':')
                .and_then(|(_, v)| v.trim().parse().ok());
        } else if let Some(rest) = line.strip_prefix("core id") {
            core = rest
                .rsplit_once(':')
                .and_then(|(_, v)| v.trim().parse().ok());
        }
    }
    flush(&mut phys, &mut core);
    if set.is_empty() {
        None
    } else {
        Some(set.len())
    }
}

/// Worker-thread count: `WEISSMAN_TOKIO_WORKER_THREADS` or physical cores.
#[must_use]
pub fn tokio_worker_threads() -> usize {
    std::env::var("WEISSMAN_TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(physical_cpu_count)
        .max(1)
}

/// Tokio LIFO slot stays on unless `WEISSMAN_TOKIO_DISABLE_LIFO_SLOT=1`.
/// The slot reuses the current worker for wakeups and avoids extra context switches
/// on short HTTP handlers.
#[must_use]
pub fn tokio_lifo_slot_enabled() -> bool {
    !std::env::var("WEISSMAN_TOKIO_DISABLE_LIFO_SLOT")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Build multi-threaded runtime; optionally pins each worker thread to successive PUs.
pub fn build_scan_runtime() -> io::Result<tokio::runtime::Runtime> {
    let threads = tokio_worker_threads();
    let blocking = (threads.saturating_mul(4)).clamp(16, 512);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .enable_all()
        .worker_threads(threads)
        .max_blocking_threads(blocking);
    // Tokio's LIFO slot is enabled by default (avoids extra worker hand-offs on short
    // HTTP handlers). `disable_lifo_slot` is tokio_unstable-only; we keep the default.
    if !tokio_lifo_slot_enabled() {
        tracing::warn!(
            target: "hpc_runtime",
            "WEISSMAN_TOKIO_DISABLE_LIFO_SLOT is set but tokio requires tokio_unstable to disable the LIFO slot; leaving it enabled"
        );
    }
    tracing::info!(
        target: "hpc_runtime",
        worker_threads = threads,
        max_blocking_threads = blocking,
        lifo_slot = tokio_lifo_slot_enabled(),
        "tokio runtime sized to physical cores"
    );

    #[cfg(target_os = "linux")]
    {
        let cpus = tokio_cpu_affinity_cpus();
        if !cpus.is_empty() {
            let cpus = std::sync::Arc::new(cpus);
            let idx = std::sync::atomic::AtomicUsize::new(0);
            builder.on_thread_start(move || {
                let n = cpus.len();
                if n == 0 {
                    return;
                }
                let i = idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % n;
                let _ = linux_affinity::bind_current_thread_to_cpu(cpus[i]);
            });
        } else if std::env::var("WEISSMAN_NUMA_PIN")
            .map(|v| matches!(v.trim(), "1" | "true" | "yes"))
            .unwrap_or(false)
        {
            #[cfg(feature = "numa")]
            {
                if let Some(plan) = linux_numa::pu_binding_plan() {
                    let idx = std::sync::atomic::AtomicUsize::new(0);
                    let plan = std::sync::Arc::new(plan);
                    builder.on_thread_start(move || {
                        let n = plan.len();
                        if n == 0 {
                            return;
                        }
                        let i = idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % n;
                        plan[i].bind_current_thread();
                    });
                }
            }
        }
    }

    builder.build()
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux_affinity {
    // SAFETY: This module is the sole justified exception to the crate-wide `unsafe_code = "deny"`
    // policy. It calls `libc::sched_setaffinity` directly because there is no stable safe Rust API
    // for CPU-affinity binding on Linux. The invariants are:
    //   1. `cpu` is validated to be < `libc::CPU_SETSIZE` before use.
    //   2. `cpu_set_t` is zero-initialized via `std::mem::zeroed` (valid bit pattern: all zeros).
    //   3. Only the current thread (PID 0) is affected; no cross-thread memory is accessed.
    //   4. This code is compiled only on Linux (`#[cfg(target_os = "linux")]`).
    use std::io;

    pub(super) fn bind_current_thread_to_cpu(cpu: usize) -> io::Result<()> {
        // SAFETY: See module-level safety comment. cpu < CPU_SETSIZE is asserted below.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut set);
            if cpu >= libc::CPU_SETSIZE as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cpu id >= CPU_SETSIZE",
                ));
            }
            libc::CPU_SET(cpu, &mut set);
            let rc = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "numa"))]
mod linux_numa {
    use hwlocality::{
        cpu::binding::CpuBindingFlags, cpu::cpuset::CpuSet, object::types::ObjectType,
        topology::Topology,
    };

    pub(super) struct PuBind {
        topo: std::sync::Arc<Topology>,
        mask: CpuSet,
    }

    impl PuBind {
        pub(super) fn bind_current_thread(&self) {
            let flags = CpuBindingFlags::THREAD;
            let _ = self.topo.bind_cpu(&self.mask, flags);
        }
    }

    pub(super) fn pu_binding_plan() -> Option<Vec<PuBind>> {
        let topo = Topology::new().ok()?;
        let topo = std::sync::Arc::new(topo);
        let allowed = topo.allowed_cpuset().clone_target();
        let mut out = Vec::new();
        for pu in topo.objects_with_type(ObjectType::PU) {
            let Some(pu_cs) = pu.cpuset() else {
                continue;
            };
            let mut bind_set = pu_cs.clone_target();
            bind_set &= allowed.clone();
            if bind_set.is_empty() {
                continue;
            }
            bind_set.singlify();
            if bind_set.is_empty() {
                continue;
            }
            out.push(PuBind {
                topo: topo.clone(),
                mask: bind_set,
            });
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }
}

/// Bind the **current** OS thread to one logical CPU (Linux `sched_setaffinity`). No-op on non-Linux.
#[cfg(target_os = "linux")]
pub fn bind_current_thread_to_cpu(cpu: usize) -> io::Result<()> {
    linux_affinity::bind_current_thread_to_cpu(cpu)
}

#[cfg(not(target_os = "linux"))]
pub fn bind_current_thread_to_cpu(_cpu: usize) -> io::Result<()> {
    Ok(())
}

// --- Genesis Protocol: split research vs client-scan affinity (pair with second worker + WEISSMAN_TOKIO_CPU_AFFINITY) ---

/// CPUs for the eternal research loop thread (`WEISSMAN_GENESIS_RESEARCH_CPU_AFFINITY`, default `0-15`).
#[must_use]
pub fn genesis_research_cpu_list() -> Vec<usize> {
    std::env::var("WEISSMAN_GENESIS_RESEARCH_CPU_AFFINITY")
        .ok()
        .map(|s| parse_cpu_affinity_list(s.trim()))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| parse_cpu_affinity_list("0-15"))
}

/// Documented client-scan range (`WEISSMAN_GENESIS_CLIENT_SCAN_CPU_AFFINITY`, default `16-31`); apply on scan worker process.
#[must_use]
pub fn genesis_client_scan_cpu_list() -> Vec<usize> {
    std::env::var("WEISSMAN_GENESIS_CLIENT_SCAN_CPU_AFFINITY")
        .ok()
        .map(|s| parse_cpu_affinity_list(s.trim()))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| parse_cpu_affinity_list("16-31"))
}

/// Pin current thread to the first Genesis research CPU (no-op if list empty or non-Linux bind fails).
pub fn bind_current_thread_genesis_research() {
    let cpus = genesis_research_cpu_list();
    if let Some(&c) = cpus.first() {
        let _ = bind_current_thread_to_cpu(c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mixed_singletons_and_ranges() {
        assert_eq!(
            parse_cpu_affinity_list("0,1,8-11"),
            vec![0, 1, 8, 9, 10, 11]
        );
    }

    #[test]
    fn parse_sorts_and_dedups() {
        assert_eq!(parse_cpu_affinity_list("3,1,2,2,1"), vec![1, 2, 3]);
        // overlapping range + singleton
        assert_eq!(parse_cpu_affinity_list("2-4,3,5"), vec![2, 3, 4, 5]);
    }

    #[test]
    fn parse_ignores_empty_and_invalid_parts() {
        assert_eq!(parse_cpu_affinity_list(""), Vec::<usize>::new());
        assert_eq!(parse_cpu_affinity_list("   "), Vec::<usize>::new());
        assert_eq!(parse_cpu_affinity_list("x,5,y"), vec![5]);
        assert_eq!(parse_cpu_affinity_list(",,7,,"), vec![7]);
    }

    #[test]
    fn parse_reversed_range_is_skipped() {
        // start > end contributes nothing
        assert_eq!(parse_cpu_affinity_list("5-3"), Vec::<usize>::new());
        assert_eq!(parse_cpu_affinity_list("10-8,1"), vec![1]);
    }

    #[test]
    fn parse_single_element_range() {
        assert_eq!(parse_cpu_affinity_list("4-4"), vec![4]);
    }

    #[test]
    fn parse_tolerates_internal_whitespace() {
        assert_eq!(parse_cpu_affinity_list(" 0 - 2 "), vec![0, 1, 2]);
        assert_eq!(parse_cpu_affinity_list(" 1 , 3 "), vec![1, 3]);
    }

    #[test]
    fn cpuinfo_counts_unique_physical_cores() {
        let sample = "\
processor\t: 0
physical id\t: 0
core id\t: 0

processor\t: 1
physical id\t: 0
core id\t: 0

processor\t: 2
physical id\t: 0
core id\t: 1

processor\t: 3
physical id\t: 0
core id\t: 1
";
        assert_eq!(parse_physical_cpus_from_cpuinfo(sample), Some(2));
    }

    #[test]
    fn worker_threads_at_least_one() {
        assert!(tokio_worker_threads() >= 1);
        assert!(physical_cpu_count() >= 1);
        assert!(tokio_lifo_slot_enabled());
    }
}
