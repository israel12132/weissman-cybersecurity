//! Cold-start onboarding must not blindly train the UEBA baseline.
//!
//! A 20-minute quiet window that copies every new process/port into `learned_set`
//! lets an APT persist during agent install and become "normal" forever. New
//! items are admitted to the baseline only after active validation:
//!   1. Global well-known OS / runtime binaries and ports
//!   2. Fleet whitelist (same item already trained on other healthy agents)
//!   3. Threat signatures (known C2 / dual-use attack tools)
//! Unvalidated and threat-matched items never enter `learned_set` during onboarding.

use std::collections::HashSet;

/// Architect-mandated quiet window. Matches ~24 samples at ~50s if the agent is hot,
/// but we key off wall-clock `enrolled_at` so a slow host cannot extend the hole.
pub const ONBOARDING_WINDOW_SECS: i64 = 20 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingVerdict {
    /// Safe to record as legitimate baseline.
    AllowBaseline,
    /// Known-bad / dual-use attack tooling — never baseline, always alert.
    Threat,
    /// Not on the fleet/OS allow-list — alert, hold out of learned_set.
    Unvalidated,
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

pub fn is_well_known_port(port: i64) -> bool {
    matches!(
        port,
        22 | 53
            | 80
            | 123
            | 443
            | 445
            | 587
            | 993
            | 995
            | 2376
            | 2377
            | 2379
            | 2380
            | 3306
            | 5432
            | 6379
            | 6443
            | 8000
            | 8080
            | 8443
            | 9200
            | 10250
            | 10255
    )
}

/// High ports commonly used by reverse shells / C2 during the first minutes on a box.
pub fn is_suspicious_onboarding_port(port: i64) -> bool {
    matches!(
        port,
        4444 | 4445 | 5555 | 6666 | 6667 | 1337 | 31337 | 12345 | 65000 | 65535
    )
}

pub fn classify_process(name: &str, fleet: &HashSet<String>) -> OnboardingVerdict {
    if is_threat_process(name) {
        return OnboardingVerdict::Threat;
    }
    let n = normalize_process_name(name);
    if is_well_known_process(name) || fleet.contains(&n) {
        return OnboardingVerdict::AllowBaseline;
    }
    OnboardingVerdict::Unvalidated
}

pub fn classify_port(port: i64, fleet: &HashSet<String>) -> OnboardingVerdict {
    let key = port.to_string();
    if is_suspicious_onboarding_port(port) {
        return OnboardingVerdict::Threat;
    }
    if is_well_known_port(port) || fleet.contains(&key) {
        return OnboardingVerdict::AllowBaseline;
    }
    OnboardingVerdict::Unvalidated
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
    "explorer",
    "firewalld",
    "init",
    "journald",
    "kubelet",
    "lsass",
    "lvmetad",
    "master",
    "networkmanager",
    "nginx",
    "ntpd",
    "postgres",
    "redis-server",
    "rsyslogd",
    "services",
    "smss",
    "sshd",
    "svchost",
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
    "wininit",
    "winlogon",
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
    fn systemd_is_baseline_mimikatz_is_threat() {
        let fleet = HashSet::new();
        assert_eq!(
            classify_process("systemd", &fleet),
            OnboardingVerdict::AllowBaseline
        );
        assert_eq!(
            classify_process("/usr/bin/sshd", &fleet),
            OnboardingVerdict::AllowBaseline
        );
        assert_eq!(
            classify_process("mimikatz.exe", &fleet),
            OnboardingVerdict::Threat
        );
        assert_eq!(
            classify_process("weird-apt-implants.sh", &fleet),
            OnboardingVerdict::Unvalidated
        );
    }

    #[test]
    fn fleet_whitelist_admits_unknown_but_peer_known() {
        let mut fleet = HashSet::new();
        fleet.insert("acme-collector".into());
        assert_eq!(
            classify_process("acme-collector", &fleet),
            OnboardingVerdict::AllowBaseline
        );
    }

    #[test]
    fn reverse_shell_port_is_threat_ssh_is_ok() {
        let fleet = HashSet::new();
        assert_eq!(classify_port(22, &fleet), OnboardingVerdict::AllowBaseline);
        assert_eq!(classify_port(4444, &fleet), OnboardingVerdict::Threat);
        assert_eq!(classify_port(49152, &fleet), OnboardingVerdict::Unvalidated);
    }

    #[test]
    fn onboarding_window_is_twenty_minutes() {
        assert_eq!(ONBOARDING_WINDOW_SECS, 20 * 60);
    }

    #[test]
    fn threat_signature_beats_fleet_whitelist() {
        let mut fleet = HashSet::new();
        fleet.insert("mimikatz".into());
        fleet.insert("4444".into());
        assert_eq!(
            classify_process("mimikatz", &fleet),
            OnboardingVerdict::Threat
        );
        assert_eq!(classify_port(4444, &fleet), OnboardingVerdict::Threat);
    }
}
