//! Kill Chain Planner Engine — reconnaissance chain mapped to MITRE ATT&CK phases.
//! MITRE: T1595 (Active Scanning).

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

fn normalize_target(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

pub async fn run_kill_chain_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }

    let client = build_client().await;
    let base = normalize_target(target);
    let mut findings = Vec::new();

    // Phase 1: Reconnaissance — GET /
    if let Ok(resp) = client.get(&base).send().await {
        let status = resp.status().as_u16();
        let server = resp
            .headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        let powered_by = resp
            .headers()
            .get("x-powered-by")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        findings.push(json!({
            "type": "kill_chain",
            "title": "Phase 1 — Reconnaissance: Target Fingerprint",
            "severity": "info",
            "mitre_attack": "T1595",
            "phase": "Reconnaissance",
            "description": format!(
                "Target {} is reachable (HTTP {}). Server: '{}', X-Powered-By: '{}', Content-Type: '{}'.",
                base, status, server, powered_by, content_type
            )
        }));
    }

    // Phase 1: Reconnaissance — robots.txt
    let robots_url = format!("{}/robots.txt", base);
    let mut disallowed_paths: Vec<String> = Vec::new();
    if let Ok(resp) = client.get(&robots_url).send().await {
        let status = resp.status().as_u16();
        if status == 200 {
            let body = resp.text().await.unwrap_or_default();
            for line in body.lines() {
                let line = line.trim();
                if line.to_lowercase().starts_with("disallow:") {
                    let path = line[9..].trim().to_string();
                    if !path.is_empty() && path != "/" {
                        disallowed_paths.push(path);
                    }
                }
            }
            findings.push(json!({
                "type": "kill_chain",
                "title": "Phase 1 — Reconnaissance: robots.txt Found",
                "severity": "info",
                "mitre_attack": "T1595",
                "phase": "Reconnaissance",
                "description": format!(
                    "robots.txt found at {}. Discovered {} disallowed paths: {}",
                    robots_url,
                    disallowed_paths.len(),
                    disallowed_paths.join(", ")
                )
            }));
        }
    }

    // Phase 1: Reconnaissance — sitemap.xml
    let sitemap_url = format!("{}/sitemap.xml", base);
    let mut sitemap_paths: Vec<String> = Vec::new();
    if let Ok(resp) = client.get(&sitemap_url).send().await {
        let status = resp.status().as_u16();
        if status == 200 {
            let body = resp.text().await.unwrap_or_default();
            // Extract loc entries from sitemap
            for chunk in body.split("<loc>") {
                if let Some(end) = chunk.find("</loc>") {
                    let loc = chunk[..end].trim().to_string();
                    if !loc.is_empty() && loc.starts_with("http") {
                        sitemap_paths.push(loc);
                    }
                }
            }
            findings.push(json!({
                "type": "kill_chain",
                "title": "Phase 1 — Reconnaissance: sitemap.xml Found",
                "severity": "info",
                "mitre_attack": "T1595",
                "phase": "Reconnaissance",
                "description": format!(
                    "sitemap.xml found at {}. Contains {} URL entries. Sitemaps reveal the complete URL structure of the application.",
                    sitemap_url, sitemap_paths.len()
                )
            }));

            // Check sitemap paths for admin-like patterns
            let admin_patterns = ["admin", "dashboard", "panel", "manage", "control", "backend"];
            let admin_paths: Vec<&String> = sitemap_paths
                .iter()
                .filter(|p| {
                    let lower = p.to_lowercase();
                    admin_patterns.iter().any(|pat| lower.contains(pat))
                })
                .collect();

            if !admin_paths.is_empty() {
                findings.push(json!({
                    "type": "kill_chain",
                    "title": "Phase 2 — Resource Development: Admin Paths in Sitemap",
                    "severity": "high",
                    "mitre_attack": "T1595",
                    "phase": "Resource Development",
                    "description": format!(
                        "Admin/management paths found in sitemap.xml: {}. These provide initial access targets.",
                        admin_paths.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    )
                }));
            }
        }
    }

    // Phase 2: Resource Development — security.txt
    let security_txt_url = format!("{}/.well-known/security.txt", base);
    if let Ok(resp) = client.get(&security_txt_url).send().await {
        let status = resp.status().as_u16();
        if status == 200 {
            let body = resp.text().await.unwrap_or_default();
            let contact = body
                .lines()
                .find(|l| l.to_lowercase().starts_with("contact:"))
                .unwrap_or("")
                .to_string();
            findings.push(json!({
                "type": "kill_chain",
                "title": "Phase 2 — Resource Development: security.txt Found",
                "severity": "info",
                "mitre_attack": "T1595",
                "phase": "Resource Development",
                "description": format!(
                    "security.txt found at {}. Contact: '{}'. This confirms the security program and may reveal bug bounty scope or contact channels.",
                    security_txt_url, contact
                )
            }));
        }
    }

    // Phase 1: Reconnaissance — humans.txt
    let humans_url = format!("{}/humans.txt", base);
    if let Ok(resp) = client.get(&humans_url).send().await {
        let status = resp.status().as_u16();
        if status == 200 {
            let body = resp.text().await.unwrap_or_default();
            findings.push(json!({
                "type": "kill_chain",
                "title": "Phase 1 — Reconnaissance: humans.txt Found",
                "severity": "info",
                "mitre_attack": "T1595",
                "phase": "Reconnaissance",
                "description": format!(
                    "humans.txt found at {} ({} bytes). May reveal team names, technologies, or development details.",
                    humans_url, body.len()
                )
            }));
        }
    }

    // Phase 3: Initial Access — probe disallowed paths from robots.txt
    for disallowed in disallowed_paths.iter().take(5) {
        if disallowed.contains('*') || disallowed.len() < 2 {
            continue;
        }
        let url = format!("{}{}", base, disallowed);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 || status == 403 {
                let severity = if status == 200 { "high" } else { "medium" };
                findings.push(json!({
                    "type": "kill_chain",
                    "title": format!("Phase 3 — Initial Access: Disallowed Path Accessible: {}", disallowed),
                    "severity": severity,
                    "mitre_attack": "T1595",
                    "phase": "Initial Access",
                    "description": format!(
                        "robots.txt disallowed path {} returned HTTP {}. {} paths are often disallowed because they contain sensitive content.",
                        url, status,
                        if status == 200 { "This" } else { "This restricted" }
                    )
                }));
            }
        }
    }

    EngineResult::ok(findings.clone(), format!("Kill Chain: {} findings", findings.len()))
}

pub async fn run_kill_chain(target: &str) {
    print_result(run_kill_chain_result(target).await);
}
