//! SBOM Analyzer — fetches dependency manifests, parses components, matches known CVE patterns.
//! MITRE: T1195.001 (Supply Chain Compromise: Dependency).

use crate::engine_probes::{
    empty_ok, finding_with_probe_depth, http_client, http_get, join_url, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::time::Duration;

const SBOM_PROBE_DEPTH: &str = "sbom_dependency_surface";

fn sbom_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    extra: Value,
) -> Value {
    let mut f = finding_with_probe_depth(
        "sbom_analyzer",
        title,
        severity,
        "T1195.001",
        description,
        target,
        SBOM_PROBE_DEPTH,
    );
    if let Some(obj) = f.as_object_mut() {
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    f
}

const SBOM_PATHS: &[(&str, &str)] = &[
    ("/sbom.json", "cyclonedx"),
    ("/bom.json", "cyclonedx"),
    ("/cyclonedx.json", "cyclonedx"),
    ("/spdx.json", "spdx"),
    ("/.well-known/sbom", "sbom"),
    ("/api/sbom", "sbom"),
    ("/package-lock.json", "npm-lock"),
    ("/yarn.lock", "yarn-lock"),
    ("/requirements.txt", "pip"),
    ("/Pipfile.lock", "pip-lock"),
    ("/go.sum", "go-sum"),
    ("/Cargo.lock", "cargo-lock"),
    ("/composer.lock", "composer-lock"),
    ("/Gemfile.lock", "gem-lock"),
    ("/pom.xml", "maven"),
];

/// Known vulnerable (package_substring, version_substring, cve, severity)
const KNOWN_VULNS: &[(&str, &str, &str, &str)] = &[
    ("log4j-core", "2.14", "CVE-2021-44228", "critical"),
    ("log4j", "2.14", "CVE-2021-44228", "critical"),
    ("spring-core", "5.3.17", "CVE-2022-22965", "critical"),
    ("struts2-core", "2.3", "CVE-2017-5638", "critical"),
    ("lodash", "4.17.20", "CVE-2021-23337", "high"),
    ("axios", "0.21.0", "CVE-2023-45857", "medium"),
    ("openssl", "1.0.2", "CVE-2022-0778", "high"),
    ("django", "3.2", "CVE-2023-36053", "medium"),
    ("pillow", "9.0", "CVE-2023-44271", "medium"),
];

fn extract_components(body: &str, doc_kind: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if doc_kind == "cyclonedx" || body.contains("\"components\"") {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            if let Some(comps) = v.get("components").and_then(|c| c.as_array()) {
                for c in comps {
                    let name = c
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    let version = c
                        .get("version")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !name.is_empty() {
                        out.push((name, version));
                    }
                }
            }
        }
    }
    if doc_kind == "npm-lock" || body.contains("\"lockfileVersion\"") {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            if let Some(pkgs) = v.get("packages").and_then(|p| p.as_object()) {
                for (path, meta) in pkgs {
                    if path.is_empty() || !path.contains("node_modules") {
                        continue;
                    }
                    let name = path.rsplit("node_modules/").next().unwrap_or(path).to_string();
                    let version = meta
                        .get("version")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !name.is_empty() && !version.is_empty() {
                        out.push((name, version));
                    }
                }
            }
        }
    }
    if doc_kind == "pip" {
        for line in body.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let (name, ver) = l
                .split_once("==")
                .or_else(|| l.split_once(">="))
                .or_else(|| l.split_once("~="))
                .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
                .unwrap_or_else(|| (l.to_string(), String::new()));
            out.push((name, ver));
        }
    }
    out
}

fn match_known_vulns(components: &[(String, String)]) -> Vec<Value> {
    let mut hits = Vec::new();
    for (name, version) in components {
        let name_lc = name.to_ascii_lowercase();
        let ver_lc = version.to_ascii_lowercase();
        for (pkg, vuln_ver, cve, sev) in KNOWN_VULNS {
            if name_lc.contains(&pkg.to_ascii_lowercase())
                && (ver_lc.is_empty() || ver_lc.contains(&vuln_ver.to_ascii_lowercase()))
            {
                hits.push(json!({
                    "package": name,
                    "version": version,
                    "cve": cve,
                    "severity": sev
                }));
            }
        }
    }
    hits
}

pub async fn run_sbom_analyzer_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();

    for (path, doc_kind) in SBOM_PATHS {
        let url = join_url(&base, path);
        let Some(probe) = http_get(&client, &url).await else {
            continue;
        };
        if probe.status != 200 || probe.body.len() < 12 {
            continue;
        }

        let looks_like_manifest = probe.body.contains('{')
            || probe.body.contains("lockfileVersion")
            || probe.body.contains("==")
            || probe.body.contains("<dependency>")
            || *doc_kind == "pip";
        if !looks_like_manifest {
            continue;
        }

        findings.push(sbom_finding(
            &format!("Dependency manifest exposed: {}", path.trim_start_matches('/')),
            "medium",
            &format!(
                "Live dependency document at {} (HTTP 200, {} bytes, kind={}). \
                 Exposed manifests enable precise CVE targeting across the software supply chain.",
                probe.final_url,
                probe.body.len(),
                doc_kind
            ),
            target,
            json!({ "url": probe.final_url, "document_type": doc_kind, "body_length": probe.body.len() }),
        ));

        let components = extract_components(&probe.body, doc_kind);
        let vulns = match_known_vulns(&components);
        for v in vulns {
            let pkg = v.get("package").and_then(|p| p.as_str()).unwrap_or("?");
            let cve = v.get("cve").and_then(|c| c.as_str()).unwrap_or("?");
            let sev = v.get("severity").and_then(|s| s.as_str()).unwrap_or("high");
            let ver = v.get("version").and_then(|s| s.as_str()).unwrap_or("");
            findings.push(sbom_finding(
                &format!("Known vulnerable dependency: {} ({})", pkg, cve),
                sev,
                &format!(
                    "Manifest at {} references '{}' version '{}' associated with {}. \
                     Verify patch level against OSV/NVD and upgrade immediately.",
                    probe.final_url, pkg, ver, cve
                ),
                target,
                v.clone(),
            ));
        }
    }

    if findings.is_empty() {
        empty_ok("sbom_analyzer", target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("sbom_analyzer: {} live finding(s)", n))
    }
}

pub async fn run_sbom_analyzer(target: &str) {
    print_result(run_sbom_analyzer_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclonedx_components_parsed() {
        let body = r#"{"components":[{"name":"lodash","version":"4.17.20"}]}"#;
        let c = extract_components(body, "cyclonedx");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].0, "lodash");
    }

    #[test]
    fn vuln_match_finds_log4j() {
        let hits = match_known_vulns(&[("log4j-core".into(), "2.14.1".into())]);
        assert!(!hits.is_empty());
    }
}
