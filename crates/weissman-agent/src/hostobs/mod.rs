//! Native host observation — processes and listening ports without CLI tools.
//!
//! Sampling goes through the kernel's own process/network tables:
//!   * Linux  — direct `/proc` reads (`open`/`getdents`/`read` via the Rust runtime;
//!              never `ps`, `lsof`, or libprocps).
//!   * macOS  — `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_ALL)` plus `proc_pidinfo`
//!              for sockets.
//!   * Windows — `NtQuerySystemInformation(SystemProcessInformation)` only
//!              (no ToolHelp — that API is an EDR tripwire on unsigned
//!              binaries) and `GetExtendedTcpTable` for listeners.
//!
//! This is the agent's own inventory path, not an EDR-unhooking / direct-syscall
//! stub. Spawning `ps`/`lsof` is what lights up attacker-controlled process
//! monitors; reading the kernel tables does not.

use std::fmt;

/// Kernel-table read failed. Never coerce this into `process_count = 0` —
/// an empty numeric sample looks like mass process death to the server UEBA
/// detector (`Z < -6`) and can fire isolate_host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleError {
    pub kind: SampleErrorKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleErrorKind {
    /// NtQuerySystemInformation / sysctl / /proc readdir failed or was blocked.
    Syscall,
    /// The table came back with zero live processes. A running agent is itself
    /// a process, so this is a parse/permission failure, not a quiet host.
    EmptyTable,
}

impl SampleError {
    #[must_use]
    pub fn syscall(detail: impl Into<String>) -> Self {
        Self {
            kind: SampleErrorKind::Syscall,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn empty_table() -> Self {
        Self {
            kind: SampleErrorKind::EmptyTable,
            detail: "process_table_empty".into(),
        }
    }
}

impl fmt::Display for SampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            SampleErrorKind::Syscall => "syscall",
            SampleErrorKind::EmptyTable => "empty_table",
        };
        write!(f, "{kind}:{}", self.detail)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: String,
    pub uid: Option<u32>,
    pub rss_bytes: u64,
    pub vmem_bytes: u64,
}

impl ProcessRecord {
    #[must_use]
    pub fn basename_lower(&self) -> String {
        let n = self.name.trim().to_ascii_lowercase();
        let base = n.rsplit(['/', '\\']).next().unwrap_or(&n);
        base.strip_suffix(".exe").unwrap_or(base).to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenPort {
    pub port: u16,
}

impl fmt::Display for ListenPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.port)
    }
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows as platform;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::{ListenPort, ProcessRecord, SampleError};
    pub fn list_processes(_full: bool) -> Vec<ProcessRecord> {
        Vec::new()
    }
    pub fn sample_process_table(_full: bool) -> Result<Vec<ProcessRecord>, SampleError> {
        Err(SampleError::syscall("unsupported_os"))
    }
    pub fn list_listen_ports() -> Vec<ListenPort> {
        Vec::new()
    }
}

/// Full process table (name, parent, exe, memory). Used by inventory / hollowing.
/// On syscall failure this is empty — callers other than UEBA treat that as
/// "no observations this tick", not as a numeric zero for z-score.
#[must_use]
pub fn list_processes() -> Vec<ProcessRecord> {
    platform::list_processes(true)
}

/// Process table for UEBA. Distinguishes "syscall failed" from a real inventory
/// so the agent can set `sampling_failed` instead of emitting `process_count = 0`.
pub fn sample_process_table() -> Result<Vec<ProcessRecord>, SampleError> {
    platform::sample_process_table(true)
}

/// Fast process table (pid / name / parent only). Used by CHRONOS 5 ms deltas.
#[must_use]
pub fn list_processes_light() -> Vec<ProcessRecord> {
    platform::list_processes(false)
}

/// Listening TCP ports, sorted and de-duplicated.
#[must_use]
pub fn list_listen_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = platform::list_listen_ports()
        .into_iter()
        .map(|p| p.port)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Unique UIDs observed in the process table (Linux/macOS). Windows returns 0/1.
#[must_use]
pub fn unique_user_count(procs: &[ProcessRecord]) -> usize {
    let mut uids: Vec<u32> = procs.iter().filter_map(|p| p.uid).collect();
    uids.sort_unstable();
    uids.dedup();
    uids.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_at_least_this_process() {
        let me = std::process::id();
        let procs = list_processes();
        assert!(
            !procs.is_empty(),
            "native process table was empty — sampling is dead"
        );
        assert!(
            procs.iter().any(|p| p.pid == me),
            "current pid {me} missing from {} native records",
            procs.len()
        );
        assert!(
            procs.iter().any(|p| !p.name.trim().is_empty()),
            "every process name was empty"
        );
    }

    #[test]
    fn light_table_is_populated() {
        let light = list_processes_light();
        assert!(!light.is_empty());
        assert!(light.iter().any(|p| p.pid == std::process::id()));
    }

    #[test]
    fn listen_ports_are_unique_and_sorted() {
        let ports = list_listen_ports();
        let mut expected = ports.clone();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(ports, expected);
    }

    #[test]
    fn basename_strips_path_and_exe() {
        let p = ProcessRecord {
            pid: 1,
            ppid: None,
            name: "/usr/sbin/nginx".into(),
            exe: String::new(),
            uid: None,
            rss_bytes: 0,
            vmem_bytes: 0,
        };
        assert_eq!(p.basename_lower(), "nginx");
        let w = ProcessRecord {
            pid: 2,
            ppid: None,
            name: r"C:\Windows\System32\powershell.exe".into(),
            exe: String::new(),
            uid: None,
            rss_bytes: 0,
            vmem_bytes: 0,
        };
        assert_eq!(w.basename_lower(), "powershell");
    }

    #[test]
    fn windows_hostobs_never_calls_toolhelp() {
        let src = include_str!("windows.rs");
        assert!(
            !src.contains("Process32FirstW")
                && !src.contains("Process32NextW")
                && !src.contains("TH32CS_SNAPPROCESS")
                && !src.contains("Diagnostics::ToolHelp"),
            "ToolHelp APIs must stay out of the Windows hostobs path"
        );
    }

    #[test]
    fn windows_ntapi_failure_is_sample_error_not_zero_count() {
        let src = include_str!("windows.rs");
        assert!(
            src.contains("sample_process_table"),
            "Windows must expose sample_process_table"
        );
        assert!(
            src.contains("SampleError"),
            "NTAPI failure must surface SampleError, not an empty Vec for UEBA"
        );
        assert!(
            !src.contains("report an empty sample"),
            "empty-sample path was the Alert Storm bug"
        );
    }

    #[test]
    fn sample_process_table_succeeds_on_this_host() {
        let procs = sample_process_table().expect("live process table must be readable");
        assert!(
            !procs.is_empty(),
            "a running agent cannot observe an empty process table"
        );
        assert!(procs.iter().any(|p| p.pid == std::process::id()));
    }
}
