//! Onboarding hijack controls for UEBA categorical learning.
//!
//! During the 15–30 minute grace window, ports and processes are **not** blindly
//! unioned into `learned_set`. Each new item must:
//!   1. Fail closed against compiled offensive signatures.
//!   2. Fail closed against live `threat_ingest_events` (process names and
//!      SHA-256 of `/proc/<pid>/exe` when the agent sent `top_process_hashes`).
//!   3. Appear on the hard OS/name Global Fleet Whitelist **or** have its
//!      SHA-256 on the sovereign allow-list: packaged update file, local DB
//!      (`ueba_sovereign_binary_allowlist` **only when `sovereign_signature` verifies**
//!      against the compiled Ed25519 public key), `WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST`,
//!      or `WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST_FILE`. Never an outbound HTTP call.
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

const PACKAGED_ALLOWLIST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../crates/weissman-db/data/ueba_sovereign_binary_allowlist.txt"
));

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

fn parse_hash_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .collect()
}

fn offline_file_allowlist() -> Vec<String> {
    let path = match std::env::var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST_FILE") {
        Ok(p) if !p.trim().is_empty() => p,
        _ => return Vec::new(),
    };
    std::fs::read_to_string(path)
        .map(|t| parse_hash_lines(&t))
        .unwrap_or_default()
}

fn packaged_allowlist() -> Vec<String> {
    parse_hash_lines(PACKAGED_ALLOWLIST)
}

fn normalize_sha256(hash: Option<&str>) -> Option<String> {
    let h = hash.map(str::trim).filter(|s| s.len() == 64)?;
    if !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(h.to_ascii_lowercase())
}

fn local_source_hits() -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for h in parse_hash_lines(
        &std::env::var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST")
            .unwrap_or_default()
            .replace(',', "\n"),
    ) {
        out.push((h, "env"));
    }
    for h in offline_file_allowlist() {
        out.push((h, "offline_file"));
    }
    for h in packaged_allowlist() {
        out.push((h, "packaged"));
    }
    out
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

/// SHA-256 (64 hex) of an on-disk binary, compared to local sovereign sources
/// (env, offline file, packaged update). Empty / malformed hashes never match.
/// The live detector also consults `ueba_sovereign_binary_allowlist` in the
/// local database — never an outbound HTTP call. DB rows grant Learn only when
/// `sovereign_signature` verifies against the compiled public key.
#[must_use]
pub fn on_sovereign_binary_allowlist(hash: Option<&str>) -> bool {
    let Some(n) = normalize_sha256(hash) else {
        return false;
    };
    local_source_hits().iter().any(|(x, _)| x == &n)
}

/// Upsert packaged / env / USB hashes into the local catalog **only when** we can
/// attach a platform Ed25519 signature. Unsigned inserts are refused (a DB
/// writer must not bless a hash by itself). Learn still uses env/file/packaged.
pub async fn seed_sovereign_allowlist(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) {
    let Some(seed) = crate::ueba_sovereign_sign::signing_seed_from_env() else {
        return;
    };
    for (sha, source) in local_source_hits() {
        let Some(sig) = crate::ueba_sovereign_sign::sign_sha256_hex(&seed, &sha) else {
            tracing::error!(
                target: "ueba_onboarding",
                sha256 = %sha,
                "UEBA allow-list seed skipped: WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY does not match the compiled public key"
            );
            continue;
        };
        let _ = sqlx::query(
            r#"INSERT INTO ueba_sovereign_binary_allowlist (sha256, source, sovereign_signature)
               VALUES ($1, $2, $3)
               ON CONFLICT (sha256) DO UPDATE
                 SET sovereign_signature = EXCLUDED.sovereign_signature
               WHERE ueba_sovereign_binary_allowlist.sovereign_signature = ''"#,
        )
        .bind(&sha)
        .bind(source)
        .bind(&sig)
        .execute(&mut **tx)
        .await;
    }
}

fn db_signature_grants_learn(sha256_hex: &str, signature_hex: &str) -> bool {
    crate::ueba_sovereign_sign::verify_sha256_hex(sha256_hex, signature_hex)
}

/// Offline-first Learn grant: env, packaged file, USB drop, or a **signed** local DB row.
pub async fn on_sovereign_binary_allowlist_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    hash: Option<&str>,
) -> bool {
    if on_sovereign_binary_allowlist(hash) {
        return true;
    }
    let Some(n) = normalize_sha256(hash) else {
        return false;
    };
    seed_sovereign_allowlist(tx).await;
    let sig: Option<String> = sqlx::query_scalar(
        r#"SELECT sovereign_signature FROM ueba_sovereign_binary_allowlist WHERE sha256 = $1"#,
    )
    .bind(&n)
    .fetch_optional(&mut **tx)
    .await
    .ok()
    .flatten();
    sig.as_deref()
        .is_some_and(|s| db_signature_grants_learn(&n, s))
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

    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
        let _env = ENV_LOCK.blocking_lock();
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

    #[test]
    fn sovereign_allowlist_is_offline_first() {
        let src = include_str!("ueba_onboarding.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(prod.contains("ueba_sovereign_binary_allowlist"));
        assert!(prod.contains("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST_FILE"));
        assert!(
            !prod.contains("reqwest"),
            "sovereign allow-list must not call outbound HTTP"
        );
    }

    #[test]
    fn packaged_allowlist_file_has_no_placeholder_hashes() {
        assert!(
            packaged_allowlist().is_empty(),
            "packaged catalog must not ship placeholder SHA-256 values"
        );
    }

    #[test]
    fn db_learn_requires_sovereign_signature_in_source() {
        let src = include_str!("ueba_onboarding.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(prod.contains("sovereign_signature"));
        assert!(prod.contains("verify_sha256_hex"));
        assert!(
            !prod.contains("SELECT EXISTS(\n                SELECT 1 FROM ueba_sovereign_binary_allowlist WHERE sha256"),
            "DB Learn must not EXISTS on sha256 alone"
        );
    }

    #[tokio::test]
    async fn unsigned_db_row_does_not_grant_learn() {
        let _env = ENV_LOCK.lock().await;
        let url = match std::env::var("TEST_DATABASE_URL") {
            Ok(u) if !u.trim().is_empty() => u,
            _ => {
                eprintln!("SKIP unsigned_db_row_does_not_grant_learn: no TEST_DATABASE_URL");
                return;
            }
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("connect");
        let hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut tx = pool.begin().await.expect("tx");
        sqlx::query(
            r#"INSERT INTO ueba_sovereign_binary_allowlist (sha256, source, sovereign_signature)
               VALUES ($1, 'packaged', '')
               ON CONFLICT (sha256) DO UPDATE SET sovereign_signature = ''"#,
        )
        .bind(hash)
        .execute(&mut *tx)
        .await
        .expect("insert unsigned catalog hash");
        let prev_hash = std::env::var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST").ok();
        let prev_key = std::env::var("WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY").ok();
        std::env::remove_var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST");
        std::env::remove_var("WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY");
        let hit = on_sovereign_binary_allowlist_tx(&mut tx, Some(hash)).await;
        match prev_hash {
            Some(v) => std::env::set_var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST", v),
            None => std::env::remove_var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST"),
        }
        match prev_key {
            Some(v) => std::env::set_var("WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY", v),
            None => std::env::remove_var("WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY"),
        }
        assert!(
            !hit,
            "an unsigned DB row must not grant Learn (TOCTOU / catalog injection)"
        );
        let forged = "11".repeat(64);
        sqlx::query(
            r#"UPDATE ueba_sovereign_binary_allowlist
                  SET sovereign_signature = $2
                WHERE sha256 = $1"#,
        )
        .bind(hash)
        .bind(&forged)
        .execute(&mut *tx)
        .await
        .expect("inject forged signature");
        let forged_hit = on_sovereign_binary_allowlist_tx(&mut tx, Some(hash)).await;
        assert!(!forged_hit, "a forged Ed25519 blob must not grant Learn");
        let _ = sqlx::query("DELETE FROM ueba_sovereign_binary_allowlist WHERE sha256 = $1")
            .bind(hash)
            .execute(&mut *tx)
            .await;
        tx.commit().await.expect("cleanup");
    }

    #[tokio::test]
    async fn signed_db_row_grants_learn_when_platform_key_is_set() {
        let _env = ENV_LOCK.lock().await;
        let url = match std::env::var("TEST_DATABASE_URL") {
            Ok(u) if !u.trim().is_empty() => u,
            _ => {
                eprintln!(
                    "SKIP signed_db_row_grants_learn_when_platform_key_is_set: no TEST_DATABASE_URL"
                );
                return;
            }
        };
        let Some(seed) = crate::ueba_sovereign_sign::signing_seed_from_env() else {
            eprintln!(
                "SKIP signed_db_row_grants_learn_when_platform_key_is_set: no WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY"
            );
            return;
        };
        let hash = "ccccccccccccccccaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let Some(sig) = crate::ueba_sovereign_sign::sign_sha256_hex(&seed, hash) else {
            panic!(
                "WEISSMAN_UEBA_SOVEREIGN_SIGNING_KEY is set but does not match EMBEDDED_SOVEREIGN_PUBKEY"
            );
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .expect("connect");
        let mut tx = pool.begin().await.expect("tx");
        sqlx::query(
            r#"INSERT INTO ueba_sovereign_binary_allowlist (sha256, source, sovereign_signature)
               VALUES ($1, 'packaged', $2)
               ON CONFLICT (sha256) DO UPDATE SET sovereign_signature = EXCLUDED.sovereign_signature"#,
        )
        .bind(hash)
        .bind(&sig)
        .execute(&mut *tx)
        .await
        .expect("insert signed catalog hash");
        let prev = std::env::var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST").ok();
        std::env::remove_var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST");
        let hit = on_sovereign_binary_allowlist_tx(&mut tx, Some(hash)).await;
        match prev {
            Some(v) => std::env::set_var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST", v),
            None => std::env::remove_var("WEISSMAN_UEBA_BINARY_HASH_ALLOWLIST"),
        }
        assert!(hit, "a platform-signed DB row must grant Learn");
        let _ = sqlx::query("DELETE FROM ueba_sovereign_binary_allowlist WHERE sha256 = $1")
            .bind(hash)
            .execute(&mut *tx)
            .await;
        tx.commit().await.expect("cleanup");
    }
}
