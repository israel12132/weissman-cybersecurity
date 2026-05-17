//! Typosquatting Active Monitor — checks for recently registered packages typosquatting the target on NPM/PyPI.

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

async fn build_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn extract_org_name(target: &str) -> String {
    let t = target.trim();
    let stripped = t
        .strip_prefix("https://")
        .or_else(|| t.strip_prefix("http://"))
        .unwrap_or(t);
    let host = stripped.split('/').next().unwrap_or(stripped);
    // Return the first part of the domain (org name)
    host.split('.').next().unwrap_or(host).to_string()
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if a[i - 1] == b[j - 1] {
                dp[i - 1][j - 1]
            } else {
                1 + dp[i - 1][j - 1].min(dp[i - 1][j]).min(dp[i][j - 1])
            };
        }
    }
    dp[m][n]
}

fn generate_typos(name: &str) -> Vec<String> {
    let mut typos = Vec::new();
    let chars: Vec<char> = name.chars().collect();

    // Omission (drop one character)
    for i in 0..chars.len() {
        let t: String = chars.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, c)| c).collect();
        if !t.is_empty() && t != name { typos.push(t); }
    }

    // Addition (double one character)
    for i in 0..chars.len() {
        let mut t = String::new();
        for (j, c) in chars.iter().enumerate() {
            t.push(*c);
            if j == i { t.push(*c); }
        }
        if t != name { typos.push(t); }
    }

    // Substitution (common keyboard neighbors)
    let neighbors: &[(&str, &str)] = &[
        ("a", "s"), ("s", "a"), ("d", "f"), ("f", "d"),
        ("o", "0"), ("0", "o"), ("1", "l"), ("l", "1"),
        ("i", "1"), ("e", "3"), ("3", "e"),
    ];
    for (from, to) in neighbors {
        if name.contains(from) {
            typos.push(name.replacen(from, to, 1));
        }
    }

    // Hyphen/underscore swap
    if name.contains('-') { typos.push(name.replace('-', "_")); }
    if name.contains('_') { typos.push(name.replace('_', "-")); }

    // Prefix/suffix confusion
    typos.push(format!("{}-js", name));
    typos.push(format!("{}-py", name));
    typos.push(format!("py{}", name));
    typos.push(format!("node-{}", name));

    typos.sort();
    typos.dedup();
    typos.retain(|t| t != name && !t.is_empty());
    typos
}

pub async fn run_typosquatting_monitor_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let org = extract_org_name(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    let typos = generate_typos(&org);

    // Check each typo on NPM
    for typo in typos.iter().take(15) {
        let npm_url = format!("https://registry.npmjs.org/{}", typo);
        let resp = match client.get(&npm_url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if resp.status().as_u16() != 200 {
            continue;
        }
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            let pkg_name = data.get("name").and_then(|n| n.as_str()).unwrap_or(typo);
            let dist = levenshtein(pkg_name, &org);
            let severity = if dist <= 1 { "critical" } else { "high" };

            // Check publish time to identify recent registrations
            let created = data
                .get("time")
                .and_then(|t| t.get("created"))
                .and_then(|c| c.as_str())
                .unwrap_or("unknown");

            findings.push(json!({
                "type": "typosquatting_monitor",
                "title": format!("NPM typosquat risk: '{}' resembles '{}'", pkg_name, org),
                "severity": severity,
                "mitre_attack": "T1195.001",
                "description": format!(
                    "NPM package '{}' (edit distance {} from '{}') exists and was first published {}. \
                    This may be a typosquatting attack targeting developers who mistype package names. \
                    Verify the package is legitimate and report to NPM security if malicious.",
                    pkg_name, dist, org, created
                ),
                "value": npm_url,
                "edit_distance": dist,
                "package_name": pkg_name,
                "registry": "npm",
                "first_published": created
            }));
        }
    }

    // Check each typo on PyPI
    for typo in typos.iter().take(10) {
        let pypi_url = format!("https://pypi.org/pypi/{}/json", typo);
        let resp = match client.get(&pypi_url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        if resp.status().as_u16() != 200 {
            continue;
        }
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            let pkg_name = data
                .get("info")
                .and_then(|i| i.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or(typo);
            let dist = levenshtein(pkg_name, &org);
            let severity = if dist <= 1 { "critical" } else { "high" };

            findings.push(json!({
                "type": "typosquatting_monitor",
                "title": format!("PyPI typosquat risk: '{}' resembles '{}'", pkg_name, org),
                "severity": severity,
                "mitre_attack": "T1195.001",
                "description": format!(
                    "PyPI package '{}' (edit distance {} from '{}') exists. \
                    This may be a dependency confusion or typosquatting attack. \
                    Report to PyPI security at security@pypi.org if confirmed malicious.",
                    pkg_name, dist, org
                ),
                "value": pypi_url,
                "edit_distance": dist,
                "package_name": pkg_name,
                "registry": "pypi"
            }));
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("TyposquattingMonitor: {} findings for org '{}'", findings.len(), org),
    )
}

pub async fn run_typosquatting_monitor(target: &str) {
    print_result(run_typosquatting_monitor_result(target).await);
}
