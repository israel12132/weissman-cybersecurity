//! ITDR seed — identity threat detection over authentication events.
//!
//! The platform had no identity-threat coverage. This is a real, deterministic detector set over
//! normalized auth events:
//!
//!   * **impossible travel** — two successful logins for one user from different countries closer
//!     in time than any plausible travel,
//!   * **password spray** — one source IP failing logins across many distinct users in a window,
//!   * **brute force** — many failed logins for one user in a window,
//!   * **MFA fatigue** — a burst of MFA prompts for one user followed by a success.
//!
//! Pure, no I/O, fully unit-tested. Slots behind any IdP event source (Entra ID, Okta, auth logs).

use serde::Serialize;

/// A normalized authentication event.
#[derive(Debug, Clone)]
pub struct AuthEvent {
    pub ts: i64,
    pub user: String,
    pub ip: String,
    pub country: String,
    pub success: bool,
    pub mfa_prompted: bool,
}

impl AuthEvent {
    pub fn new(
        ts: i64,
        user: &str,
        ip: &str,
        country: &str,
        success: bool,
        mfa_prompted: bool,
    ) -> Self {
        Self {
            ts,
            user: user.to_string(),
            ip: ip.to_string(),
            country: country.to_string(),
            success,
            mfa_prompted,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ItdrConfig {
    /// Minimum seconds that must separate successful logins from two different countries; a smaller
    /// gap is physically impossible travel.
    pub impossible_travel_min_secs: i64,
    pub spray_window_secs: i64,
    pub spray_min_users: usize,
    pub brute_window_secs: i64,
    pub brute_min_failures: usize,
    pub mfa_window_secs: i64,
    pub mfa_min_prompts: usize,
}

impl Default for ItdrConfig {
    fn default() -> Self {
        Self {
            impossible_travel_min_secs: 2 * 3600, // 2h between countries
            spray_window_secs: 600,
            spray_min_users: 5,
            brute_window_secs: 300,
            brute_min_failures: 10,
            mfa_window_secs: 120,
            mfa_min_prompts: 5,
        }
    }
}

/// An identity-threat detection.
#[derive(Debug, Clone, Serialize)]
pub struct ItdrFinding {
    pub kind: String,
    pub subject: String,
    pub severity: String,
    pub mitre: String,
    pub evidence: serde_json::Value,
}

fn group_by<'a, K, F>(
    events: &'a [AuthEvent],
    key: F,
) -> std::collections::BTreeMap<K, Vec<&'a AuthEvent>>
where
    K: Ord,
    F: Fn(&AuthEvent) -> K,
{
    let mut m: std::collections::BTreeMap<K, Vec<&AuthEvent>> = std::collections::BTreeMap::new();
    for e in events {
        m.entry(key(e)).or_default().push(e);
    }
    m
}

/// Max number of timestamps that fall within any `window`-second sliding window.
fn max_in_window(sorted_ts: &[i64], window: i64) -> usize {
    let mut best = 0;
    let mut l = 0;
    for r in 0..sorted_ts.len() {
        while sorted_ts[r] - sorted_ts[l] > window {
            l += 1;
        }
        best = best.max(r - l + 1);
    }
    best
}

/// Detect impossible travel: consecutive successful logins from different countries too close in time.
pub fn detect_impossible_travel(events: &[AuthEvent], cfg: &ItdrConfig) -> Vec<ItdrFinding> {
    let mut out = Vec::new();
    for (user, mut evs) in group_by(events, |e| e.user.clone()) {
        evs.retain(|e| e.success);
        evs.sort_by_key(|e| e.ts);
        for w in evs.windows(2) {
            let (a, b) = (w[0], w[1]);
            if a.country != b.country && (b.ts - a.ts) < cfg.impossible_travel_min_secs {
                out.push(ItdrFinding {
                    kind: "impossible_travel".to_string(),
                    subject: user.clone(),
                    severity: "high".to_string(),
                    mitre: "T1078".to_string(),
                    evidence: serde_json::json!({
                        "from_country": a.country, "to_country": b.country,
                        "gap_secs": b.ts - a.ts, "min_plausible_secs": cfg.impossible_travel_min_secs,
                        "from_ip": a.ip, "to_ip": b.ip,
                    }),
                });
                break; // one per user is enough to alert
            }
        }
    }
    out
}

/// Detect password spray: a single IP failing across many distinct users within a window.
pub fn detect_password_spray(events: &[AuthEvent], cfg: &ItdrConfig) -> Vec<ItdrFinding> {
    let mut out = Vec::new();
    for (ip, mut evs) in group_by(events, |e| e.ip.clone()) {
        evs.retain(|e| !e.success);
        evs.sort_by_key(|e| e.ts);
        let mut l = 0usize;
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        let mut distinct = 0usize;
        let mut best = 0usize;
        for r in 0..evs.len() {
            let u = evs[r].user.as_str();
            let c = counts.entry(u).or_insert(0);
            if *c == 0 {
                distinct += 1;
            }
            *c += 1;
            while evs[r].ts - evs[l].ts > cfg.spray_window_secs {
                let lu = evs[l].user.as_str();
                if let Some(cc) = counts.get_mut(lu) {
                    *cc -= 1;
                    if *cc == 0 {
                        distinct -= 1;
                    }
                }
                l += 1;
            }
            best = best.max(distinct);
        }
        if best >= cfg.spray_min_users {
            out.push(ItdrFinding {
                kind: "password_spray".to_string(),
                subject: ip.clone(),
                severity: "high".to_string(),
                mitre: "T1110.003".to_string(),
                evidence: serde_json::json!({
                    "distinct_users_in_window": best,
                    "window_secs": cfg.spray_window_secs,
                    "threshold": cfg.spray_min_users,
                }),
            });
        }
    }
    out
}

/// Detect brute force: many failed logins for one user in a window.
pub fn detect_brute_force(events: &[AuthEvent], cfg: &ItdrConfig) -> Vec<ItdrFinding> {
    let mut out = Vec::new();
    for (user, mut evs) in group_by(events, |e| e.user.clone()) {
        evs.retain(|e| !e.success);
        evs.sort_by_key(|e| e.ts);
        let ts: Vec<i64> = evs.iter().map(|e| e.ts).collect();
        let peak = max_in_window(&ts, cfg.brute_window_secs);
        if peak >= cfg.brute_min_failures {
            out.push(ItdrFinding {
                kind: "brute_force".to_string(),
                subject: user.clone(),
                severity: if peak >= cfg.brute_min_failures * 3 {
                    "high"
                } else {
                    "medium"
                }
                .to_string(),
                mitre: "T1110.001".to_string(),
                evidence: serde_json::json!({
                    "failures_in_window": peak,
                    "window_secs": cfg.brute_window_secs,
                    "threshold": cfg.brute_min_failures,
                }),
            });
        }
    }
    out
}

/// Detect MFA fatigue: a burst of MFA prompts for one user, followed by a success.
pub fn detect_mfa_fatigue(events: &[AuthEvent], cfg: &ItdrConfig) -> Vec<ItdrFinding> {
    let mut out = Vec::new();
    for (user, mut evs) in group_by(events, |e| e.user.clone()) {
        evs.sort_by_key(|e| e.ts);
        let prompt_ts: Vec<i64> = evs
            .iter()
            .filter(|e| e.mfa_prompted)
            .map(|e| e.ts)
            .collect();
        let peak = max_in_window(&prompt_ts, cfg.mfa_window_secs);
        if peak < cfg.mfa_min_prompts {
            continue;
        }
        // Require a successful login at/after the first prompt (the fatigue "approve").
        let first_prompt = *prompt_ts.first().unwrap();
        let approved = evs.iter().any(|e| e.success && e.ts >= first_prompt);
        if approved {
            out.push(ItdrFinding {
                kind: "mfa_fatigue".to_string(),
                subject: user.clone(),
                severity: "high".to_string(),
                mitre: "T1621".to_string(),
                evidence: serde_json::json!({
                    "prompts_in_window": peak,
                    "window_secs": cfg.mfa_window_secs,
                    "threshold": cfg.mfa_min_prompts,
                    "approved_after_burst": true,
                }),
            });
        }
    }
    out
}

/// Run all ITDR detectors.
pub fn analyze(events: &[AuthEvent], cfg: &ItdrConfig) -> Vec<ItdrFinding> {
    let mut v = detect_impossible_travel(events, cfg);
    v.extend(detect_password_spray(events, cfg));
    v.extend(detect_brute_force(events, cfg));
    v.extend(detect_mfa_fatigue(events, cfg));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impossible_travel_fires_for_country_jump() {
        let cfg = ItdrConfig::default();
        let evs = vec![
            AuthEvent::new(1000, "alice", "1.1.1.1", "US", true, false),
            AuthEvent::new(1000 + 600, "alice", "2.2.2.2", "DE", true, false), // 10 min later, US→DE
        ];
        let hits = detect_impossible_travel(&evs, &cfg);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, "impossible_travel");
    }

    #[test]
    fn impossible_travel_ok_when_enough_time() {
        let cfg = ItdrConfig::default();
        let evs = vec![
            AuthEvent::new(0, "alice", "1.1.1.1", "US", true, false),
            AuthEvent::new(3 * 3600, "alice", "2.2.2.2", "DE", true, false), // 3h apart
        ];
        assert!(detect_impossible_travel(&evs, &cfg).is_empty());
    }

    #[test]
    fn password_spray_fires_for_many_users_one_ip() {
        let cfg = ItdrConfig::default();
        let evs: Vec<AuthEvent> = (0..6)
            .map(|i| {
                AuthEvent::new(
                    100 + i as i64 * 10,
                    &format!("user{i}"),
                    "9.9.9.9",
                    "US",
                    false,
                    false,
                )
            })
            .collect();
        let hits = detect_password_spray(&evs, &cfg);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].subject, "9.9.9.9");
    }

    #[test]
    fn password_spray_quiet_for_few_users() {
        let cfg = ItdrConfig::default();
        let evs: Vec<AuthEvent> = (0..3)
            .map(|i| {
                AuthEvent::new(
                    100 + i as i64 * 10,
                    &format!("user{i}"),
                    "9.9.9.9",
                    "US",
                    false,
                    false,
                )
            })
            .collect();
        assert!(detect_password_spray(&evs, &cfg).is_empty());
    }

    #[test]
    fn brute_force_fires_for_repeated_failures() {
        let cfg = ItdrConfig::default();
        let evs: Vec<AuthEvent> = (0..12)
            .map(|i| AuthEvent::new(1000 + i as i64 * 10, "bob", "5.5.5.5", "US", false, false))
            .collect();
        let hits = detect_brute_force(&evs, &cfg);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].subject, "bob");
    }

    #[test]
    fn brute_force_spread_out_is_quiet() {
        let cfg = ItdrConfig::default();
        // 12 failures but 10 minutes apart → never 10 within a 5-minute window.
        let evs: Vec<AuthEvent> = (0..12)
            .map(|i| AuthEvent::new(i as i64 * 600, "bob", "5.5.5.5", "US", false, false))
            .collect();
        assert!(detect_brute_force(&evs, &cfg).is_empty());
    }

    #[test]
    fn mfa_fatigue_fires_on_burst_then_success() {
        let cfg = ItdrConfig::default();
        let mut evs: Vec<AuthEvent> = (0..6)
            .map(|i| AuthEvent::new(1000 + i as i64 * 10, "carol", "3.3.3.3", "US", false, true))
            .collect();
        evs.push(AuthEvent::new(1100, "carol", "3.3.3.3", "US", true, false)); // approved
        let hits = detect_mfa_fatigue(&evs, &cfg);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, "mfa_fatigue");
    }

    #[test]
    fn mfa_fatigue_quiet_without_success() {
        let cfg = ItdrConfig::default();
        let evs: Vec<AuthEvent> = (0..6)
            .map(|i| AuthEvent::new(1000 + i as i64 * 10, "carol", "3.3.3.3", "US", false, true))
            .collect();
        assert!(detect_mfa_fatigue(&evs, &cfg).is_empty());
    }

    #[test]
    fn analyze_aggregates() {
        let cfg = ItdrConfig::default();
        let evs = vec![
            AuthEvent::new(0, "alice", "1.1.1.1", "US", true, false),
            AuthEvent::new(600, "alice", "2.2.2.2", "DE", true, false),
        ];
        let all = analyze(&evs, &cfg);
        assert!(all.iter().any(|f| f.kind == "impossible_travel"));
    }
}
