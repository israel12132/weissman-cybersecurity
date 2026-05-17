//! SBOM Analyzer — fetches SBOM documents (CycloneDX/SPDX) and checks for known vulnerable dependencies.

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
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

const SBOM_PATHS: &[&str] = &[
    "/sbom.json",
    "/sbom.xml",
    "/bom.json",
    "/bom.xml",
    "/.well-known/sbom",
    "/api/sbom",
    "/cyclonedx.json",
    "/spdx.json",
    "/software-bill-of-materials.json",
    "/manifest.json",
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/requirements.txt",
    "/Pipfile.lock",
    "/go.sum",
    "/Cargo.lock",
    "/composer.lock",
    "/Gemfile.lock",
    "/pom.xml",
    "/build.gradle",
];

pub async fn run_sbom_analyzer_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_target(target);
    let client = build_client().await;
    let mut findings: Vec<serde_json::Value> = Vec::new();

    for path in SBOM_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let status = resp.status().as_u16();
        if status != 200 {
            continue;
        }
        let body = resp.text().await.unwrap_or_default();
        if body.len() < 10 {
            continue;
        }

        let (doc_type, severity) = if path.ends_with("sbom.json") || path.ends_with("bom.json") || path.contains("cyclonedx") {
            ("CycloneDX SBOM", "high")
        } else if path.ends_with("spdx.json") {
            ("SPDX SBOM", "high")
        } else if path.ends_with("package-lock.json") || path.ends_with("yarn.lock") {
            ("NPM dependency lockfile", "medium")
        } else if path.ends_with("requirements.txt") || path.ends_with("Pipfile.lock") {
            ("Python dependency file", "medium")
        } else if path.ends_with("go.sum") {
            ("Go module checksum", "medium")
        } else if path.ends_with("Cargo.lock") {
            ("Rust dependency lockfile", "medium")
        } else if path.ends_with("pom.xml") || path.ends_with("build.gradle") {
            ("Java dependency file", "medium")
        } else if path.ends_with("Gemfile.lock") || path.ends_with("composer.lock") {
            ("Dependency lockfile", "medium")
        } else {
            ("Dependency manifest", "low")
        };

        findings.push(json!({
            "type": "sbom_analyzer",
            "title": format!("{} exposed: {}", doc_type, url),
            "severity": severity,
            "mitre_attack": "T1195.001",
            "description": format!(
                "{} found at {}. Exposed dependency manifests allow attackers to enumerate all \
                third-party libraries and identify versions with known CVEs for targeted exploitation. \
                Cross-reference all dependencies with OSV.dev, NVD, and GitHub Advisory Database.",
                doc_type, url
            ),
            "value": url,
            "document_type": doc_type,
            "body_length": body.len()
        }));

        // Check for known vulnerable packages in the body
        let known_vulnerable: &[(&str, &str, &str)] = &[
            ("log4j-core", "CVE-2021-44228", "critical"),  // Log4Shell
            ("log4j", "CVE-2021-44228", "critical"),
            ("spring-core", "CVE-2022-22965", "critical"),  // Spring4Shell
            ("struts2", "CVE-2017-5638", "critical"),
            ("lodash", "CVE-2021-23337", "high"),
            ("axios", "CVE-2023-45857", "medium"),
            ("express", "CVE-2024-29041", "medium"),
            ("openssl", "CVE-2022-0778", "high"),
            ("requests", "CVE-2023-32681", "medium"),
            ("pillow", "CVE-2023-44271", "medium"),
            ("django", "CVE-2023-36053", "medium"),
            ("rails", "CVE-2024-26143", "high"),
        ];

        for (pkg, cve, sev) in known_vulnerable {
            if body.to_lowercase().contains(&pkg.to_lowercase()) {
                findings.push(json!({
                    "type": "sbom_analyzer",
                    "title": format!("Known vulnerable package '{}' ({}) found in {}", pkg, cve, doc_type),
                    "severity": sev,
                    "mitre_attack": "T1195.001",
                    "description": format!(
                        "Dependency file at {} references '{}' which is associated with {}. \
                        Verify the exact version in use and update to a patched release immediately.",
                        url, pkg, cve
                    ),
                    "value": url,
                    "package": pkg,
                    "cve": cve
                }));
            }
        }
    }

    EngineResult::ok(
        findings.clone(),
        format!("SBOMAnalyzer: {} findings", findings.len()),
    )
}

pub async fn run_sbom_analyzer(target: &str) {
    print_result(run_sbom_analyzer_result(target).await);
}
