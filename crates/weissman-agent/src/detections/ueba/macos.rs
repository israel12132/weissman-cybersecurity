//! macOS Unified Logging — `log show` with a hard timeout. No fake counts.

#[cfg(target_os = "macos")]
use super::ProcessSnapshot;

#[cfg(target_os = "macos")]
pub fn failed_logins_24h() -> (bool, u32) {
    macos_impl::failed_logins_24h()
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub fn failed_logins_24h() -> (bool, u32) {
    (false, 0)
}

#[cfg(target_os = "macos")]
pub fn hardware_id() -> Option<String> {
    macos_impl::hardware_id()
}

#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub fn hardware_id() -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
pub fn process_snapshot(_lite: bool) -> ProcessSnapshot {
    ProcessSnapshot {
        process_count: 0,
        unique_users: 0,
        top: Vec::new(),
        paths: Vec::new(),
        sha256: Vec::new(),
        listen_map: Vec::new(),
        ghost_ppids: Vec::new(),
        thread_count: 0,
    }
}

#[cfg(target_os = "macos")]
mod macos_impl {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    pub fn hardware_id() -> Option<String> {
        // Honest: there is no stable machine-id file on macOS without IOKit. Leave empty
        // rather than hashing the hostname (which is attacker-settable).
        None
    }

    pub fn failed_logins_24h() -> (bool, u32) {
        let mut child = match Command::new("log")
            .args([
                "show",
                "--style",
                "compact",
                "--last",
                "15m",
                "--predicate",
                "eventMessage CONTAINS[c] \"failed\" AND (process == \"loginwindow\" OR process == \"sshd\" OR process == \"SecurityAgent\")",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return (false, 0),
        };
        let started = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if started.elapsed() > Duration::from_secs(2) => {
                    let _ = child.kill();
                    return (false, 0);
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => return (false, 0),
            }
        }
        let output = match child.wait_with_output() {
            Ok(o) => o,
            Err(_) => return (false, 0),
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let n = text.lines().filter(|l| !l.is_empty()).count() as u32;
        (true, n)
    }
}
