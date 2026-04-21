//! NUMA-aware Tokio worker pinning (Linux + hwloc). Set `WEISSMAN_NUMA_PIN=1` on multi-socket hosts.
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

/// Build multi-threaded runtime; optionally pins each worker thread to successive PUs.
pub fn build_scan_runtime() -> io::Result<tokio::runtime::Runtime> {
    let threads = std::env::var("WEISSMAN_TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .max(1)
        });

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all().worker_threads(threads);

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

    builder.build()
}

#[cfg(target_os = "linux")]
mod linux_affinity {
    // SAFETY: This module is the sole justified exception to the crate-wide `unsafe_code = "deny"`
    // policy. It calls `libc::sched_setaffinity` directly because there is no stable safe Rust API
    // for CPU-affinity binding on Linux. The invariants are:
    //   1. `cpu` is validated to be < `libc::CPU_SETSIZE` before use.
    //   2. `cpu_set_t` is zero-initialized via `std::mem::zeroed` (valid bit pattern: all zeros).
    //   3. Only the current thread (PID 0) is affected; no cross-thread memory is accessed.
    //   4. This code is compiled only on Linux (`#[cfg(target_os = "linux")]`).
    #[allow(unsafe_code)]
    use std::io;

    #[allow(unsafe_code)]
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
            let rc = libc::sched_setaffinity(
                0,
                std::mem::size_of::<libc::cpu_set_t>(),
                &set,
            );
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux_numa {
    use hwlocality::{
        cpu::binding::CpuBindingFlags,
        cpu::cpuset::CpuSet,
        object::types::ObjectType,
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
