//! Threat Emulation Engine — runs known APT group TTPs against the target and checks detection.

use crate::engine_probes::{extract_host, tcp_open};
use crate::engine_result::{EngineResult, print_result};
use serde_json::json;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AptHttpClass {
    Blocked,
    AuthChallenged,
    Open,
    Absent,
}

fn classify_apt_http(status: u16) -> AptHttpClass {
    if matches!(status, 403 | 406 | 429 | 503) {
        AptHttpClass::Blocked
    } else if status == 401 {
        AptHttpClass::AuthChallenged
    } else if matches!(status, 200 | 301 | 302) {
        AptHttpClass::Open
    } else {
        AptHttpClass::Absent
    }
}

/// (severity, label, blocked, auth_challenged, path_exists)
fn apt_http_verdict(status: u16) -> Option<(&'static str, &'static str, bool, bool, bool)> {
    match classify_apt_http(status) {
        AptHttpClass::Absent => None,
        AptHttpClass::Blocked => Some((
            "info",
            "BLOCKED — security control detected APT-style request",
            true,
            false,
            false,
        )),
        AptHttpClass::AuthChallenged => Some((
            "info",
            "AUTH CHALLENGED — path exists but the server required credentials (HTTP 401 is not an undetected high-risk hit)",
            false,
            true,
            true,
        )),
        AptHttpClass::Open => Some((
            "high",
            "NOT BLOCKED — APT-style request reached target without detection",
            false,
            false,
            true,
        )),
    }
}

fn extra_ttp_severity(status: u16) -> Option<&'static str> {
    match classify_apt_http(status) {
        AptHttpClass::Absent => None,
        AptHttpClass::Open if status == 200 => Some("high"),
        AptHttpClass::Open | AptHttpClass::AuthChallenged | AptHttpClass::Blocked => Some("info"),
    }
}

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn normalize_target(target: &str) -> String {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

/// Known APT group TTP emulation scenarios mapped to MITRE ATT&CK.
struct AptScenario {
    group: &'static str,
    technique: &'static str,
    mitre: &'static str,
    user_agent: &'static str,
    path: &'static str,
    extra_paths: &'static [&'static str],
    extra_ports: &'static [u16],
    description: &'static str,
}

pub const APT_SCENARIO_COUNT: usize = 7;

const APT_SCENARIOS: &[AptScenario] = &[
    AptScenario {
        group: "Lazarus Group (HIDDEN COBRA)",
        technique: "T1595.002 - Active Scanning: Vulnerability Scanning",
        mitre: "T1595.002",
        user_agent: "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        path: "/wp-login.php",
        extra_paths: &["/xmlrpc.php", "/wp-json/"],
        extra_ports: &[],
        description: "Lazarus Group commonly targets WordPress admin panels with IE9 User-Agent strings on Windows 7 (EOL systems), consistent with their operational security profile targeting legacy infrastructure.",
    },
    AptScenario {
        group: "APT28 / Fancy Bear (Sofacy)",
        technique: "T1190 - Exploit Public-Facing Application",
        mitre: "T1190",
        user_agent: "python-requests/2.18.4",
        path: "/owa/auth/logon.aspx",
        extra_paths: &["/ecp/", "/ews/exchange.asmx"],
        extra_ports: &[],
        description: "APT28 extensively targets Outlook Web Access (OWA) using scripted HTTP clients. This emulation checks if OWA is exposed and accessible to automated probing without alerting controls.",
    },
    AptScenario {
        group: "APT29 / Cozy Bear (The Dukes)",
        technique: "T1078 - Valid Accounts",
        mitre: "T1078",
        user_agent: "curl/7.74.0",
        path: "/api/v1/auth/token",
        extra_paths: &["/.well-known/openid-configuration", "/login"],
        extra_ports: &[],
        description: "APT29 focuses on OAuth token theft and credential abuse via API endpoints. This emulation probes token endpoints using minimal curl-like user agents consistent with their tooling.",
    },
    AptScenario {
        group: "APT41 (Double Dragon)",
        technique: "T1190 - Supply Chain Compromise via CI/CD",
        mitre: "T1195.002",
        user_agent: "Go-http-client/1.1",
        path: "/api/json",
        extra_paths: &["/jenkins/", "/gitlab/"],
        extra_ports: &[],
        description: "APT41 targets CI/CD systems (Jenkins) for supply chain compromise. Probing with Go HTTP client UA is consistent with their toolset. Jenkins /api/json without auth is a common initial access vector.",
    },
    AptScenario {
        group: "Sandworm Team (Voodoo Bear)",
        technique: "T1190 - VPN/Edge Device Exploitation",
        mitre: "T1190",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        path: "/remote/login",
        extra_paths: &["/remote/logincheck", "/dana-na/"],
        extra_ports: &[],
        description: "Sandworm exploits internet-facing VPN and remote access portals (Fortinet, Pulse Secure). Probing /remote/login with standard Windows browser UA emulates their initial access reconnaissance.",
    },
    AptScenario {
        group: "Kimsuky (Black Banshee)",
        technique: "T1566.002 - Phishing via Link",
        mitre: "T1566.002",
        user_agent: "Mozilla/5.0 (X11; Linux x86_64)",
        path: "/.git/config",
        extra_paths: &["/phpinfo.php", "/.env"],
        extra_ports: &[],
        description: "Kimsuky performs source code reconnaissance before spear-phishing campaigns. Checking for exposed .git/config reveals repository URLs and branch names used in targeted phishing.",
    },
    AptScenario {
        group: "Equation Group (NSA-TAO)",
        technique: "T1021.002 - SMB/Windows Admin Shares",
        mitre: "T1210",
        user_agent: "Microsoft-WebDAV-MiniRedir/10.0.19041",
        path: "/webdav/",
        extra_paths: &[],
        extra_ports: &[445, 139],
        description: "Equation Group tooling (EternalBlue, DoublePulsar) targets SMB and WebDAV. Probing WebDAV endpoints with Windows WebDAV client UA emulates their lateral movement techniques.",
    },
];

/// Number of live APT TTP emulation scenarios (safe HTTP GETs, no payloads).
pub const APT_SCENARIO_COUNT: usize = APT_SCENARIOS.len();

pub async fn run_threat_emulation_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    for scenario in APT_SCENARIOS {
        let url = format!("{}{}", base.trim_end_matches('/'), scenario.path);
        let resp = client
            .get(&url)
            .header("User-Agent", scenario.user_agent)
            .send()
            .await;

        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                if let Some((severity, detection_result, blocked, auth_challenged, path_exists)) =
                    apt_http_verdict(status)
                {
                    findings.push(json!({
                        "type": "threat_emulation",
                        "title": format!("[{}] {} — {}", scenario.group, scenario.technique, detection_result),
                        "severity": severity,
                        "mitre_attack": scenario.mitre,
                        "description": format!(
                            "APT emulation: {} | TTP: {} | {}. HTTP {} on {}. {}",
                            scenario.group, scenario.technique,
                            detection_result, status, url, scenario.description
                        ),
                        "value": url,
                        "apt_group": scenario.group,
                        "ttp": scenario.technique,
                        "emulated_user_agent": scenario.user_agent,
                        "http_status": status,
                        "blocked": blocked,
                        "auth_challenged": auth_challenged,
                        "path_exists": path_exists
                    }));

                    // Control-gap: same path with a browser UA vs the APT UA.
                    if let Ok(browser) = client
                        .get(&url)
                        .header(
                            "User-Agent",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        )
                        .send()
                        .await
                    {
                        let bstatus = browser.status().as_u16();
                        if bstatus != status {
                            findings.push(json!({
                                "type": "threat_emulation",
                                "title": format!("[{}] UA differential on {} (APT {} vs browser {})", scenario.group, scenario.path, status, bstatus),
                                "severity": "medium",
                                "mitre_attack": "T1562",
                                "description": format!(
                                    "APT UA {} returned HTTP {} while a browser UA returned HTTP {} on {}. This is a live detection-gap, not an exploit.",
                                    scenario.user_agent, status, bstatus, url
                                ),
                                "apt_group": scenario.group,
                                "http_status_apt": status,
                                "http_status_browser": bstatus,
                                "control_gap": true
                            }));
                        }
                    }
                }
            }
            Err(_) => {
                // Transport failure is not a detection signal — still try extra paths/ports.
            }
        }

        for extra in scenario.extra_paths {
            let extra_url = format!("{}{}", base.trim_end_matches('/'), extra);
            if let Ok(r) = client
                .get(&extra_url)
                .header("User-Agent", scenario.user_agent)
                .send()
                .await
            {
                let status = r.status().as_u16();
                if let Some(severity) = extra_ttp_severity(status) {
                    findings.push(json!({
                        "type": "threat_emulation",
                        "title": format!("[{}] extra TTP path {} — HTTP {}", scenario.group, extra, status),
                        "severity": severity,
                        "mitre_attack": scenario.mitre,
                        "description": format!(
                            "{} extra path {} returned HTTP {} with the group's UA. Live TTP surface, not a payload.",
                            scenario.group, extra_url, status
                        ),
                        "apt_group": scenario.group,
                        "http_status": status,
                        "auth_challenged": classify_apt_http(status) == AptHttpClass::AuthChallenged,
                        "value": extra_url
                    }));
                }
            }
        }
        let host = extract_host(&base);
        for port in scenario.extra_ports {
            if tcp_open(&host, *port).await {
                findings.push(json!({
                    "type": "threat_emulation",
                    "title": format!("[{}] TTP port {}/tcp open", scenario.group, port),
                    "severity": "high",
                    "mitre_attack": scenario.mitre,
                    "description": format!(
                        "{} emulation observed TCP/{} open on {}. Port adjacency only — no exploit payload.",
                        scenario.group, port, host
                    ),
                    "apt_group": scenario.group,
                    "port": port
                }));
            }
        }
    }

    let unblocked = findings
        .iter()
        .filter(|f| {
            f.get("blocked").and_then(|b| b.as_bool()) == Some(false)
                && f.get("auth_challenged").and_then(|b| b.as_bool()) != Some(true)
                && f.get("path_exists").and_then(|p| p.as_bool()) == Some(true)
        })
        .count();

    // Summary only when at least one APT-relevant surface actually existed; otherwise the scan is
    // honestly empty (no present attack surface, no summary noise).
    if !findings.is_empty() {
        findings.push(json!({
            "type": "threat_emulation",
            "title": format!("Threat Emulation Summary: {}/{} APT scenarios NOT detected", unblocked, APT_SCENARIOS.len()),
            "severity": if unblocked > 3 { "critical" } else if unblocked > 0 { "high" } else { "info" },
            "mitre_attack": "T1595",
            "description": format!(
                "{} out of {} APT TTP emulation scenarios reached the target without triggering a block. \
                Review WAF, EDR, and SIEM rules for the undetected techniques. \
                Groups emulated: Lazarus, APT28, APT29, APT41, Sandworm, Kimsuky, Equation Group.",
                unblocked, APT_SCENARIOS.len()
            ),
            "value": base,
            "total_scenarios": APT_SCENARIOS.len(),
            "undetected_count": unblocked
        }));
    }

    EngineResult::ok(
        findings.clone(),
        format!(
            "ThreatEmulation: {}/{} APT scenarios undetected on {}",
            unblocked,
            APT_SCENARIOS.len(),
            base
        ),
    )
}

pub async fn run_threat_emulation(target: &str) {
    print_result(run_threat_emulation_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_target_preserves_scheme() {
        assert_eq!(normalize_target("http://x"), "http://x");
        assert_eq!(normalize_target("https://x"), "https://x");
    }

    #[test]
    fn normalize_target_adds_https() {
        assert_eq!(normalize_target("example.com"), "https://example.com");
        assert_eq!(normalize_target("  example.com  "), "https://example.com");
    }

    #[test]
    fn normalize_target_empty_yields_bare_scheme() {
        // no empty-guard here: trimmed empty input still gets the scheme prefix
        assert_eq!(normalize_target(""), "https://");
        assert_eq!(normalize_target("   "), "https://");
    }

    #[test]
    fn apt_401_is_info_auth_challenge_not_high_undetected() {
        assert_eq!(classify_apt_http(401), AptHttpClass::AuthChallenged);
        let v = apt_http_verdict(401).expect("401 is a live surface");
        assert_eq!(v.0, "info");
        assert!(!v.2, "401 is not a WAF block");
        assert!(v.3, "401 is an auth challenge");
        let open = apt_http_verdict(200).unwrap();
        assert_eq!(open.0, "high");
        assert!(apt_http_verdict(404).is_none());
        assert_eq!(extra_ttp_severity(401), Some("info"));
        assert_eq!(extra_ttp_severity(200), Some("high"));
        assert!(extra_ttp_severity(404).is_none());
    }

    #[test]
    fn apt_scenarios_are_well_formed() {
        assert_eq!(APT_SCENARIOS.len(), APT_SCENARIO_COUNT);
        for s in APT_SCENARIOS {
            assert!(!s.group.is_empty());
            assert!(!s.technique.is_empty());
            assert!(!s.mitre.is_empty());
            assert!(!s.user_agent.is_empty());
            assert!(!s.description.is_empty());
            assert!(s.path.starts_with('/'), "path must be relative: {}", s.path);
            for p in s.extra_paths {
                assert!(p.starts_with('/'), "extra path must be relative: {p}");
            }
        }
        assert!(APT_SCENARIOS.iter().any(|s| !s.extra_ports.is_empty()));
    }
}
