//! Threat Emulation Engine — runs known APT group TTPs against the target and checks detection.

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

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
    description: &'static str,
}

const APT_SCENARIOS: &[AptScenario] = &[
    AptScenario {
        group: "Lazarus Group (HIDDEN COBRA)",
        technique: "T1595.002 - Active Scanning: Vulnerability Scanning",
        mitre: "T1595.002",
        user_agent: "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        path: "/wp-login.php",
        description: "Lazarus Group commonly targets WordPress admin panels with IE9 User-Agent strings on Windows 7 (EOL systems), consistent with their operational security profile targeting legacy infrastructure.",
    },
    AptScenario {
        group: "APT28 / Fancy Bear (Sofacy)",
        technique: "T1190 - Exploit Public-Facing Application",
        mitre: "T1190",
        user_agent: "python-requests/2.18.4",
        path: "/owa/auth/logon.aspx",
        description: "APT28 extensively targets Outlook Web Access (OWA) using scripted HTTP clients. This emulation checks if OWA is exposed and accessible to automated probing without alerting controls.",
    },
    AptScenario {
        group: "APT29 / Cozy Bear (The Dukes)",
        technique: "T1078 - Valid Accounts",
        mitre: "T1078",
        user_agent: "curl/7.74.0",
        path: "/api/v1/auth/token",
        description: "APT29 focuses on OAuth token theft and credential abuse via API endpoints. This emulation probes token endpoints using minimal curl-like user agents consistent with their tooling.",
    },
    AptScenario {
        group: "APT41 (Double Dragon)",
        technique: "T1190 - Supply Chain Compromise via CI/CD",
        mitre: "T1195.002",
        user_agent: "Go-http-client/1.1",
        path: "/api/json",
        description: "APT41 targets CI/CD systems (Jenkins) for supply chain compromise. Probing with Go HTTP client UA is consistent with their toolset. Jenkins /api/json without auth is a common initial access vector.",
    },
    AptScenario {
        group: "Sandworm Team (Voodoo Bear)",
        technique: "T1190 - VPN/Edge Device Exploitation",
        mitre: "T1190",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        path: "/remote/login",
        description: "Sandworm exploits internet-facing VPN and remote access portals (Fortinet, Pulse Secure). Probing /remote/login with standard Windows browser UA emulates their initial access reconnaissance.",
    },
    AptScenario {
        group: "Kimsuky (Black Banshee)",
        technique: "T1566.002 - Phishing via Link",
        mitre: "T1566.002",
        user_agent: "Mozilla/5.0 (X11; Linux x86_64)",
        path: "/.git/config",
        description: "Kimsuky performs source code reconnaissance before spear-phishing campaigns. Checking for exposed .git/config reveals repository URLs and branch names used in targeted phishing.",
    },
    AptScenario {
        group: "Equation Group (NSA-TAO)",
        technique: "T1021.002 - SMB/Windows Admin Shares",
        mitre: "T1210",
        user_agent: "Microsoft-WebDAV-MiniRedir/10.0.19041",
        path: "/webdav/",
        description: "Equation Group tooling (EternalBlue, DoublePulsar) targets SMB and WebDAV. Probing WebDAV endpoints with Windows WebDAV client UA emulates their lateral movement techniques.",
    },
];

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
                let blocked = matches!(status, 403 | 406 | 429 | 503);
                let found = matches!(status, 200 | 301 | 302 | 401);

                let (severity, detection_result) = if blocked {
                    ("info", "BLOCKED — security control detected APT-style request")
                } else if found {
                    ("high", "NOT BLOCKED — APT-style request reached target without detection")
                } else {
                    ("low", "Path not found — attack surface not present")
                };

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
                    "path_exists": found
                }));
            }
            Err(e) => {
                findings.push(json!({
                    "type": "threat_emulation",
                    "title": format!("[{}] {} — Connection failed", scenario.group, scenario.technique),
                    "severity": "info",
                    "mitre_attack": scenario.mitre,
                    "description": format!("APT emulation request to {} failed: {}", url, e),
                    "value": url,
                    "apt_group": scenario.group
                }));
            }
        }
    }

    let unblocked = findings.iter().filter(|f| f.get("blocked").and_then(|b| b.as_bool()) == Some(false) && f.get("path_exists").and_then(|p| p.as_bool()) == Some(true)).count();

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

    EngineResult::ok(
        findings.clone(),
        format!("ThreatEmulation: {}/{} APT scenarios undetected on {}", unblocked, APT_SCENARIOS.len(), base),
    )
}

pub async fn run_threat_emulation(target: &str) {
    print_result(run_threat_emulation_result(target).await);
}
