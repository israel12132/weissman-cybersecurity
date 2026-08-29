//! Onboarding hijack controls for UEBA categorical learning.
//!
//! During the 15–30 minute grace window, ports and processes are **not** blindly
//! unioned into `learned_set`. Each new item must:
//!   1. Fail closed against compiled offensive signatures.
//!   2. Fail closed against live `threat_ingest_events` (process names and
//!      SHA-256 of `/proc/<pid>/exe` when the agent sent `top_process_hashes`).
//!   3. Appear on the hard OS/name Global Fleet Whitelist **or** have its
//!      SHA-256 on the sovereign allow-list (`WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST`).
//!
//! Fleet majority is **never** a Learn grant: a poisoned golden image would
//! otherwise bless the backdoor into every new agent's `learned_set`.
//! A miss on (3) or a hit on (1)/(2) stays out of the baseline and pages the SOC.

use std::collections::HashMap;

const FLEET_PROCESS_ALLOW: &[&str] = &[
    "systemd",
    "systemd-journald",
    "systemd-logind",
    "systemd-udevd",
    "systemd-resolved",
    "systemd-timesyncd",
    "sshd",
    "ssh",
    "cron",
    "crond",
    "rsyslogd",
    "rsyslog",
    "dbus-daemon",
    "dbus-broker",
    "networkmanager",
    "chronyd",
    "ntpd",
    "irqbalance",
    "udevd",
    "agetty",
    "bash",
    "sh",
    "dash",
    "zsh",
    "python3",
    "python",
    "java",
    "node",
    "nginx",
    "httpd",
    "apache2",
    "postgres",
    "postgresql",
    "mysqld",
    "redis-server",
    "dockerd",
    "containerd",
    "kubelet",
    "containerd-shim",
    "containerd-shim-runc-v2",
    "crio",
    "snapd",
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "services.exe",
    "winlogon.exe",
    "dwm.exe",
    "explorer.exe",
    "msmpeng.exe",
    "securityhealthservice.exe",
    "runtimebroker.exe",
    "searchhost.exe",
    "system",
    "registry",
    "smss.exe",
];

const FLEET_PORT_ALLOW: &[u16] = &[
    22, 25, 53, 67, 68, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445,
    464, 465, 514, 546, 547, 587, 631, 636, 993, 995, 1433, 2049, 2376, 2379, 2380, 3306, 3389,
    5432, 5985, 5986, 6379, 6443, 6514, 8080, 8443, 9090, 9100, 10250, 27017,
];

const PROCESS_SIGNATURE_DENY: &[&str] = &[
    "mimikatz",
    "mimikatz.exe",
    "beacon",
    "beacon.exe",
    "meterpreter",
    "cobaltstrike",
    "cobalt-strike",
    "sliver",
    "sliver-client",
    "havoc",
    "mythic",
    "empire",
    "covenant",
    "ncat",
    "nc",
    "nc.exe",
    "netcat",
    "psexec",
    "psexesvc",
    "psexesvc.exe",
    "procdump",
    "lazagne",
    "rubeus",
    "sharphound",
    "bloodhound",
    "chisel",
    "ligolo",
    "ligolo-ng",
    "xmrig",
    "kinsing",
    "kdevtmpfsi",
    "kworkerds",
    "masscan",
    "hydra",
    "hashcat",
    "secretsdump",
    "wmiexec",
    "smbexec",
    "atexec",
    "evil-winrm",
    "certipy",
    "responder",
    "mitm6",
    "ntlmrelayx",
];

const PORT_SIGNATURE_DENY: &[u16] = &[4444, 4445, 5555, 6666, 6667, 1337, 12345, 31337, 50050];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingDecision {
    /// Add to `learned_set`, do not page.
    Learn,
    /// Keep out of `learned_set` and fire a high-severity anomaly.
    RejectAndAlert,
}

fn env_allowlist(var: &str) -> Vec<String> {
    std::env::var(var)
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn norm_item(item: &str) -> String {
    item.trim().to_ascii_lowercase()
}

#[must_use]
pub fn signature_denies(metric: &str, item: &str) -> bool {
    let n = norm_item(item);
    if n.is_empty() {
        return false;
    }
    if metric == "open_ports" {
        if let Ok(p) = n.parse::<u16>() {
            return PORT_SIGNATURE_DENY.contains(&p);
        }
        return false;
    }
    PROCESS_SIGNATURE_DENY.iter().any(|s| {
        let base = n.rsplit(['/', '\\']).next().unwrap_or(&n);
        n == *s || base == *s || base == format!("{s}.exe")
    })
}

#[must_use]
pub fn on_global_whitelist(metric: &str, item: &str) -> bool {
    let n = norm_item(item);
    if n.is_empty() {
        return false;
    }
    if metric == "open_ports" {
        let extra = env_allowlist("WEISSMAN_UEBA_FLEET_PORT_ALLOWLIST");
        if extra.iter().any(|x| x == &n) {
            return true;
        }
        return n
            .parse::<u16>()
            .ok()
            .is_some_and(|p| FLEET_PORT_ALLOW.contains(&p));
    }
    let extra = env_allowlist("WEISSMAN_UEBA_FLEET_PROCESS_ALLOWLIST");
    if extra.iter().any(|x| x == &n) {
        return true;
    }
    let base = n.rsplit(['/', '\\']).next().unwrap_or(&n);
    FLEET_PROCESS_ALLOW
        .iter()
        .any(|s| n == *s || base == *s || base == format!("{s}.exe"))
}

/// SHA-256 (64 hex) of an on-disk binary, compared to the sovereign
/// `WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST`. Empty / malformed hashes never match.
#[must_use]
pub fn on_sovereign_binary_allowlist(hash: Option<&str>) -> bool {
    let Some(h) = hash.map(str::trim).filter(|s| s.len() == 64) else {
        return false;
    };
    if !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let n = h.to_ascii_lowercase();
    env_allowlist("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST")
        .iter()
        .any(|x| x == &n)
}

/// Look up the agent-reported SHA-256 for a process name (`top_process_hashes`).
#[must_use]
pub fn item_binary_hash<'a>(
    item: &str,
    hashes: Option<&'a HashMap<String, String>>,
) -> Option<&'a str> {
    let map = hashes?;
    if let Some(h) = map.get(item) {
        return Some(h.as_str());
    }
    let base = item.rsplit(['/', '\\']).next().unwrap_or(item);
    if let Some(h) = map.get(base) {
        return Some(h.as_str());
    }
    map.iter().find_map(|(k, v)| {
        let kbase = k.rsplit(['/', '\\']).next().unwrap_or(k);
        (kbase.eq_ignore_ascii_case(base) || k.eq_ignore_ascii_case(item)).then_some(v.as_str())
    })
}

#[must_use]
pub fn decide_onboarding_item(
    metric: &str,
    item: &str,
    sig_hit: bool,
    ti_hit: bool,
    on_whitelist: bool,
    on_sovereign_hash: bool,
) -> OnboardingDecision {
    if sig_hit || ti_hit {
        return OnboardingDecision::RejectAndAlert;
    }
    if on_whitelist || on_sovereign_hash {
        return OnboardingDecision::Learn;
    }
    let _ = metric;
    let _ = item;
    OnboardingDecision::RejectAndAlert
}

/// Live TI: process names (len ≥ 4) against `threat_ingest_events`. When the
/// agent sent a SHA-256, also match that hex in `exploit_signature_json`.
/// Ports use signatures only — substring `"22"` would false-hit CVE years.
pub async fn threat_intel_hit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    metric: &str,
    item: &str,
    binary_hash: Option<&str>,
) -> bool {
    if metric == "open_ports" {
        return false;
    }
    let n = norm_item(item);
    if n.len() >= 4 {
        let hit = sqlx::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                SELECT 1 FROM threat_ingest_events
                 WHERE tenant_id = $1
                   AND (
                     position($2 in lower(title)) > 0
                     OR position($2 in lower(coalesce(exploit_signature_json, ''))) > 0
                   )
            )"#,
        )
        .bind(tenant_id)
        .bind(&n)
        .fetch_one(&mut **tx)
        .await
        .unwrap_or(false);
        if hit {
            return true;
        }
    }
    let Some(h) = binary_hash.map(str::trim).filter(|s| s.len() == 64) else {
        return false;
    };
    if !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let h = h.to_ascii_lowercase();
    sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS(
                SELECT 1 FROM threat_ingest_events
                 WHERE tenant_id = $1
                   AND position($2 in lower(coalesce(exploit_signature_json, ''))) > 0
            )"#,
    )
    .bind(tenant_id)
    .bind(&h)
    .fetch_one(&mut **tx)
    .await
    .unwrap_or(false)
}

/// Another agent in this tenant, past onboarding grace, already learned the item.
///
/// **Do not use this to grant Learn.** Golden-image fleets would launder a
/// backdoor into `learned_set`. Kept for SOC telemetry / forensics only.
pub async fn fleet_consensus_hit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: i64,
    agent_id: &str,
    metric: &str,
    item: &str,
    grace_secs: i64,
) -> bool {
    let n = norm_item(item);
    if n.is_empty() {
        return false;
    }
    sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS(
                SELECT 1
                  FROM agent_metric_baselines b
                  INNER JOIN endpoint_agents e
                    ON e.tenant_id = b.tenant_id
                   AND e.agent_uuid::text = b.agent_id
                 WHERE b.tenant_id = $1
                   AND b.metric_name = $2
                   AND b.hour_of_week = 0
                   AND b.agent_id <> $3
                   AND b.learned_set @> jsonb_build_array($4::text)
                   AND e.enrolled_at <= now() - make_interval(secs => $5::int)
            )"#,
    )
    .bind(tenant_id)
    .bind(metric)
    .bind(agent_id)
    .bind(&n)
    .bind(grace_secs)
    .fetch_one(&mut **tx)
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_and_443_are_fleet_baseline() {
        assert!(on_global_whitelist("top_processes", "sshd"));
        assert!(on_global_whitelist("top_processes", "/usr/sbin/sshd"));
        assert!(on_global_whitelist("open_ports", "22"));
        assert!(on_global_whitelist("open_ports", "443"));
        assert!(!on_global_whitelist("top_processes", "kdevtmpfsi"));
        assert!(!on_global_whitelist("open_ports", "4444"));
    }

    #[test]
    fn signatures_catch_c2_and_offensive_tools() {
        assert!(signature_denies("open_ports", "4444"));
        assert!(signature_denies("top_processes", "mimikatz.exe"));
        assert!(signature_denies("top_processes", "kdevtmpfsi"));
        assert!(signature_denies("top_processes", "nc"));
        assert!(!signature_denies("open_ports", "22"));
        assert!(!signature_denies("top_processes", "sshd"));
    }

    #[test]
    fn onboarding_rejects_unknown_and_malicious() {
        assert_eq!(
            decide_onboarding_item("top_processes", "sshd", false, false, true, false),
            OnboardingDecision::Learn
        );
        assert_eq!(
            decide_onboarding_item("top_processes", "beacon", true, false, false, false),
            OnboardingDecision::RejectAndAlert
        );
        assert_eq!(
            decide_onboarding_item("top_processes", "sshd", true, false, true, false),
            OnboardingDecision::RejectAndAlert,
            "signature overrides whitelist"
        );
        assert_eq!(
            decide_onboarding_item("top_processes", "acme-app", false, false, false, false),
            OnboardingDecision::RejectAndAlert
        );
        assert_eq!(
            decide_onboarding_item("top_processes", "acme-app", false, false, false, true),
            OnboardingDecision::Learn,
            "sovereign SHA-256 allow-list may Learn; fleet majority must not"
        );
        assert!(!on_sovereign_binary_allowlist(None));
    }

    #[test]
    fn golden_image_fleet_majority_is_not_a_learn_path() {
        let detector = include_str!("ueba_detector.rs");
        assert!(
            !detector.contains("fleet_consensus_hit"),
            "detector must not Learn from fleet consensus (golden-image poisoning)"
        );
        assert_eq!(
            decide_onboarding_item("top_processes", "backdoor", false, false, false, false),
            OnboardingDecision::RejectAndAlert
        );
    }

    #[test]
    fn sovereign_hash_allowlist_is_64_hex() {
        let prev = std::env::var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST").ok();
        std::env::set_var(
            "WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        assert!(on_sovereign_binary_allowlist(Some(
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        )));
        assert!(!on_sovereign_binary_allowlist(Some("deadbeef")));
        match prev {
            Some(v) => std::env::set_var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST", v),
            None => std::env::remove_var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST"),
        }
    }
}
