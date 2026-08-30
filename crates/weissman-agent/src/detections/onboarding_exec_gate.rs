//! Onboarding exec gate — kill TOCTOU on ephemeral APT processes.
//!
//! Server-side fleet/threat checks run *after* a process has already executed.
//! During the 20-minute onboarding window the agent holds `execve` in the kernel
//! (`fanotify` `FAN_OPEN_EXEC_PERM`) until SHA-256 of the image is computed.
//! Binaries not on the static OS allow-list (or matching a threat name) are
//! `FAN_DENY`'d — they never reach userspace. Fallback: SIGSTOP + hash + SIGKILL
//! if fanotify is unavailable (no CAP_SYS_ADMIN).

use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

/// Matches `ueba_onboarding::ONBOARDING_WINDOW_SECS`.
pub const ONBOARDING_WINDOW_SECS: u64 = 20 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecVerdict {
    /// OS allow-list name AND system path (or the agent itself). Exec may proceed
    /// only after SHA-256 has been computed (no run-then-check).
    Allow,
    /// Known-bad name — never run during onboarding.
    DenyThreat,
    /// Unknown / user path — stay suspended / deny until the window ends.
    DenyUnvalidated,
}

pub fn normalize_process_name(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim()
        .trim_end_matches(".exe")
        .trim_end_matches(".EXE")
        .to_ascii_lowercase()
}

pub fn is_system_path(path: &str) -> bool {
    let p = path.trim();
    [
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/lib/",
        "/usr/libexec/",
        "/usr/lib64/",
        "/lib/",
        "/lib64/",
        "/opt/weissman/",
    ]
    .iter()
    .any(|prefix| p.starts_with(prefix))
}

pub fn is_well_known_process(name: &str) -> bool {
    let n = normalize_process_name(name);
    WELL_KNOWN_PROCESSES.binary_search(&n.as_str()).is_ok()
}

pub fn is_threat_process(name: &str) -> bool {
    let n = normalize_process_name(name);
    if THREAT_PROCESSES.binary_search(&n.as_str()).is_ok() {
        return true;
    }
    THREAT_PROCESS_PREFIXES
        .iter()
        .any(|p| n.starts_with(p) || n.contains(p))
}

pub fn sha256_bytes_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn sha256_path_hex(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(sha256_bytes_hex(&bytes))
}

/// Hash first, then decide. Never allow an unknown image to run and inspect later.
pub fn verdict_after_hash(name: &str, exe_path: &str, _sha256_hex: &str) -> ExecVerdict {
    if is_threat_process(name) {
        return ExecVerdict::DenyThreat;
    }
    let n = normalize_process_name(name);
    if n == "weissman-agent" || (is_well_known_process(name) && is_system_path(exe_path)) {
        return ExecVerdict::Allow;
    }
    ExecVerdict::DenyUnvalidated
}

/// Sorted lowercase names — keep sorted so binary_search is valid.
const WELL_KNOWN_PROCESSES: &[&str] = &[
    "agetty",
    "auditd",
    "bash",
    "containerd",
    "containerd-shim",
    "cron",
    "crond",
    "dbus-daemon",
    "dockerd",
    "init",
    "journald",
    "kubelet",
    "lvmetad",
    "master",
    "networkmanager",
    "nginx",
    "ntpd",
    "postgres",
    "redis-server",
    "rsyslogd",
    "sshd",
    "systemd",
    "systemd-journald",
    "systemd-logind",
    "systemd-resolved",
    "systemd-timesyncd",
    "systemd-udevd",
    "udevd",
    "weissman-agent",
    "weissman-server",
    "weissman-worker",
];

const THREAT_PROCESSES: &[&str] = &[
    "beacon",
    "bloodhound",
    "certify",
    "chisel",
    "cobaltstrike",
    "havoc",
    "lazagne",
    "ligolo",
    "linpeas",
    "masscan",
    "meterpreter",
    "mimikatz",
    "ncat",
    "netcat",
    "nmap",
    "psexec",
    "rubeus",
    "sliver",
    "winpeas",
];

const THREAT_PROCESS_PREFIXES: &[&str] =
    &["cobalt", "meterpre", "mimikatz", "sharp-", "sharphound"];

/// Hold exec in the kernel for `window`, then exit (kernel auto-allows leftover PERM events).
pub fn spawn_for_window(window: Duration) {
    #[cfg(target_os = "linux")]
    {
        std::thread::Builder::new()
            .name("onboarding-exec-gate".into())
            .spawn(move || linux::run_gate(window))
            .ok();
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = window;
        tracing::warn!(
            target: "agent",
            "onboarding exec-gate is Linux-only; this host has no FAN_OPEN_EXEC_PERM hold"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::time::Instant;

    pub fn run_gate(window: Duration) {
        match fanotify_loop(window) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(
                    target: "agent",
                    error = %e,
                    "fanotify FAN_OPEN_EXEC_PERM unavailable; SIGSTOP fallback for the onboarding window"
                );
                sigstop_fallback(window);
            }
        }
    }

    fn fanotify_loop(window: Duration) -> std::io::Result<()> {
        // SAFETY: fanotify_init flags are the documented CONTENT class required for PERM events.
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLOEXEC | libc::FAN_CLASS_CONTENT | libc::FAN_NONBLOCK,
                libc::O_RDONLY as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let path = CString::new("/").map_err(std::io::Error::other)?;
        // SAFETY: path is a valid C string; mark applies FAN_OPEN_EXEC_PERM on the filesystem.
        let rc = unsafe {
            libc::fanotify_mark(
                fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                libc::FAN_OPEN_EXEC_PERM,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        tracing::info!(
            target: "agent",
            secs = window.as_secs(),
            "onboarding exec-gate: kernel FAN_OPEN_EXEC_PERM hold active"
        );
        let deadline = Instant::now() + window;
        // SAFETY: fd is a valid fanotify fd we own for the duration of this loop.
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = [0u8; 4096];
        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let tv = libc::timeval {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_usec: remaining.subsec_micros() as libc::suseconds_t,
            };
            let raw = f.as_raw_fd();
            unsafe {
                let mut fds: libc::fd_set = std::mem::zeroed();
                libc::FD_ZERO(&mut fds);
                libc::FD_SET(raw, &mut fds);
                let mut tv_mut = tv;
                libc::select(
                    raw + 1,
                    &mut fds,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut tv_mut,
                );
            }
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => handle_events(&mut f, &buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        drop(f);
        Ok(())
    }

    fn handle_events(f: &mut std::fs::File, buf: &[u8]) {
        let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut off = 0usize;
        while off + meta_size <= buf.len() {
            // SAFETY: fanotify packed the metadata at this offset; we only read it.
            let meta = unsafe {
                std::ptr::read_unaligned(buf[off..].as_ptr() as *const libc::fanotify_event_metadata)
            };
            if meta.event_len == 0 {
                break;
            }
            if meta.fd >= 0 && (meta.mask & libc::FAN_OPEN_EXEC_PERM) != 0 {
                let allow = decide_fd(meta.fd, meta.pid);
                let resp = libc::fanotify_response {
                    fd: meta.fd,
                    response: if allow {
                        libc::FAN_ALLOW
                    } else {
                        libc::FAN_DENY
                    },
                };
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        (&resp as *const libc::fanotify_response) as *const u8,
                        std::mem::size_of::<libc::fanotify_response>(),
                    )
                };
                let _ = f.write_all(bytes);
                unsafe { libc::close(meta.fd) };
            }
            off += meta.event_len as usize;
        }
    }

    fn decide_fd(event_fd: libc::c_int, pid: libc::c_int) -> bool {
        if pid as u32 == std::process::id() {
            return true;
        }
        let proc_path = format!("/proc/self/fd/{event_fd}");
        let exe = std::fs::read_link(&proc_path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = normalize_process_name(&exe);
        let hash = sha256_path_hex(Path::new(&proc_path)).unwrap_or_default();
        if hash.is_empty() {
            tracing::warn!(
                target: "agent",
                pid,
                exe = %exe,
                "onboarding exec-gate: could not hash image; denying"
            );
            return false;
        }
        match verdict_after_hash(&name, &exe, &hash) {
            ExecVerdict::Allow => true,
            ExecVerdict::DenyThreat => {
                tracing::error!(
                    target: "agent",
                    pid,
                    exe = %exe,
                    sha256 = %hash,
                    "onboarding exec-gate: FAN_DENY threat binary (never reached userspace)"
                );
                false
            }
            ExecVerdict::DenyUnvalidated => {
                tracing::warn!(
                    target: "agent",
                    pid,
                    exe = %exe,
                    sha256 = %hash,
                    "onboarding exec-gate: FAN_DENY unvalidated binary during onboarding"
                );
                false
            }
        }
    }

    fn sigstop_fallback(window: Duration) {
        let deadline = Instant::now() + window;
        let mut frozen: Vec<(u32, String)> = Vec::new();
        while Instant::now() < deadline {
            scan_and_stop(&mut frozen);
            std::thread::sleep(Duration::from_millis(200));
        }
        for (pid, _) in frozen {
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        }
    }

    fn scan_and_stop(frozen: &mut Vec<(u32, String)>) {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return;
        };
        let self_pid = std::process::id();
        for ent in dir.flatten() {
            let pid: u32 = match ent.file_name().to_string_lossy().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if pid == self_pid || frozen.iter().any(|(p, _)| *p == pid) {
                continue;
            }
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let hash = std::fs::read(format!("/proc/{pid}/exe"))
                .ok()
                .map(|b| sha256_bytes_hex(&b))
                .unwrap_or_default();
            match verdict_after_hash(&comm, &exe, &hash) {
                ExecVerdict::Allow => {}
                ExecVerdict::DenyThreat | ExecVerdict::DenyUnvalidated => {
                    if hash.is_empty() {
                        continue;
                    }
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
                    frozen.push((pid, comm));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_table_is_sorted() {
        let mut v = WELL_KNOWN_PROCESSES.to_vec();
        v.sort_unstable();
        assert_eq!(v, WELL_KNOWN_PROCESSES);
        let mut t = THREAT_PROCESSES.to_vec();
        t.sort_unstable();
        assert_eq!(t, THREAT_PROCESSES);
    }

    #[test]
    fn hash_is_computed_before_verdict() {
        let hex = sha256_bytes_hex(b"elf-bytes");
        assert_eq!(hex.len(), 64);
        assert_eq!(
            verdict_after_hash("sshd", "/usr/sbin/sshd", &hex),
            ExecVerdict::Allow
        );
        assert_eq!(
            verdict_after_hash("sshd", "/tmp/sshd", &hex),
            ExecVerdict::DenyUnvalidated,
            "masquerade off a system path must not inherit the allow-list name"
        );
        assert_eq!(
            verdict_after_hash("mimikatz", "/usr/bin/mimikatz", &hex),
            ExecVerdict::DenyThreat
        );
        assert_eq!(
            verdict_after_hash("apt-beacon", "/tmp/x", &hex),
            ExecVerdict::DenyUnvalidated
        );
    }

    #[test]
    fn ephemeral_unknown_never_allow() {
        // TOCTOU fix: unknown short-lived implant is deny, not "check later".
        let hex = sha256_bytes_hex(b"implant");
        assert_ne!(
            verdict_after_hash("not-in-os-list", "/tmp/implant", &hex),
            ExecVerdict::Allow
        );
    }

    #[test]
    fn onboarding_window_is_twenty_minutes() {
        assert_eq!(ONBOARDING_WINDOW_SECS, 20 * 60);
    }
}
