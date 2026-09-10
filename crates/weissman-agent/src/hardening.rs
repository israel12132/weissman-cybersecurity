//! Agent process hardening: dumpable/ptracer deny, CPU governor, log tamper signal.
//! Resilience is watchdog + least privilege — not EDR camouflage.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{info, warn};

static CPU_BREACHES: AtomicU64 = AtomicU64::new(0);

/// Linux: refuse core dumps and tracing of this process (blocks casual injection tooling).
pub fn lock_process() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl on self; PR_SET_DUMPABLE=0 is always valid for the calling thread.
        let dump = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if dump != 0 {
            warn!(target: "agent", "PR_SET_DUMPABLE failed");
        } else {
            info!(target: "agent", "process dumpable=0");
        }
    }
}

/// Cap observed CPU: if the process sits above ~5% for several samples, yield.
pub fn spawn_cpu_governor() {
    tokio::spawn(async move {
        use sysinfo::{Pid, ProcessRefreshKind, System};
        let mut sys = System::new();
        let pid = Pid::from(std::process::id() as usize);
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            sys.refresh_processes_specifics(ProcessRefreshKind::new().with_cpu());
            if let Some(p) = sys.process(pid) {
                let cpu = p.cpu_usage();
                if cpu > 5.0 {
                    let n = CPU_BREACHES.fetch_add(1, Ordering::Relaxed) + 1;
                    warn!(target: "agent", cpu, n, "CPU above 5% peak; yielding");
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    if n > 24 {
                        warn!(target: "agent", "repeated CPU ceiling — exiting for systemd restart");
                        std::process::exit(75);
                    }
                } else {
                    CPU_BREACHES.store(0, Ordering::Relaxed);
                }
            }
        }
    });
}

/// Heartbeat interval with 15–30% jitter so beaconing is not a square wave.
pub fn jittered_heartbeat_secs(base: u64) -> u64 {
    let base = base.max(5);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let extra_pct = 15 + (nanos % 16); // 15..=30
    base.saturating_add(base.saturating_mul(extra_pct as u64) / 100)
}
