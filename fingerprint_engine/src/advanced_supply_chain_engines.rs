//! Advanced Supply-chain engines — real package-registry probes.
//!
//! For each supported ecosystem we attempt to enumerate the user-supplied "package" identifier
//! against the public registry. The target may be a package name or a domain whose dependency
//! manifest is published. If no public match is found, we emit no finding.

use crate::engine_probes::{empty_ok, finding, http_client, http_get, normalize_url};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

async fn registry_probe(t: &str, engine_id: &str, title: &str, registry_url: &str, mitre: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let url = registry_url.replace("{}", &urlencoding::encode(t.trim()));
    if let Some(p) = http_get(&client, &url).await {
        if p.status == 200 {
            findings.push(finding(
                engine_id,
                title,
                "info",
                mitre,
                &format!("Public registry record found at {} (HTTP 200, {} B).", p.final_url, p.body.len()),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok(engine_id, t)
    } else {
        EngineResult::ok(findings.clone(), format!("{}: {}", engine_id, findings.len()))
    }
}

pub async fn run_npm_package_attack_result(t: &str) -> EngineResult {
    registry_probe(t, "npm_package_attack", "npm registry record exists", "https://registry.npmjs.org/{}", "T1195.001").await
}
cli_wrapper!(run_npm_package_attack, run_npm_package_attack_result);

pub async fn run_pypi_supply_chain_result(t: &str) -> EngineResult {
    registry_probe(t, "pypi_supply_chain", "PyPI registry record exists", "https://pypi.org/pypi/{}/json", "T1195.001").await
}
cli_wrapper!(run_pypi_supply_chain, run_pypi_supply_chain_result);

pub async fn run_github_actions_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    for path in [".github/workflows/", ".gitlab-ci.yml", ".github/dependabot.yml"] {
        let url = format!("{}/{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && (p.body.contains("on:") || p.body.contains("stages:")) {
                findings.push(finding(
                    "github_actions_attack",
                    "CI workflow exposed",
                    "medium",
                    "T1195.002",
                    &format!("{} returned a CI workflow document.", p.final_url),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() { empty_ok("github_actions_attack", t) }
    else { EngineResult::ok(findings.clone(), format!("github_actions_attack: {}", findings.len())) }
}
cli_wrapper!(run_github_actions_attack, run_github_actions_attack_result);

pub async fn run_docker_image_poison_result(t: &str) -> EngineResult {
    registry_probe(t, "docker_image_poison", "Docker Hub image exists", "https://hub.docker.com/v2/repositories/{}/", "T1195.002").await
}
cli_wrapper!(run_docker_image_poison, run_docker_image_poison_result);

pub async fn run_maven_supply_chain_result(t: &str) -> EngineResult {
    registry_probe(t, "maven_supply_chain", "Maven Central artifact exists", "https://search.maven.org/solrsearch/select?q={}&rows=5&wt=json", "T1195.001").await
}
cli_wrapper!(run_maven_supply_chain, run_maven_supply_chain_result);

pub async fn run_compiler_backdoor_result(t: &str) -> EngineResult {
    // Remote-observable: published build attestations + provenance docs the target should
    // expose if they participate in Sigstore / SLSA / Reproducible-Builds.
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    let prov_paths = [
        "/.well-known/sigstore",
        "/.well-known/slsa-provenance.json",
        "/security.txt",
        "/.well-known/security.txt",
        "/SHA256SUMS",
        "/checksums.txt",
    ];
    let mut found_any = false;
    for path in prov_paths.iter() {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && !p.body.trim().is_empty() {
                found_any = true;
                findings.push(finding(
                    "compiler_backdoor",
                    &format!("Build attestation found: {}", path),
                    "info",
                    "T1195",
                    &format!("{} present ({} B). Reproducible-build attestation reduces compiler-backdoor risk.", p.final_url, p.body.len()),
                    t,
                ));
            }
        }
    }
    if !found_any {
        findings.push(finding(
            "compiler_backdoor",
            "No public build attestation",
            "medium",
            "T1195",
            "No SLSA / Sigstore / reproducible-build attestation discovered. Without published provenance, supply-chain trojan detection relies entirely on internal CI.",
            t,
        ));
    }
    EngineResult::ok(findings.clone(), format!("compiler_backdoor: {}", findings.len()))
}
cli_wrapper!(run_compiler_backdoor, run_compiler_backdoor_result);

pub async fn run_open_source_backdoor_result(t: &str) -> EngineResult {
    crate::sbom_analyzer_engine::run_sbom_analyzer_result(t).await
}
cli_wrapper!(run_open_source_backdoor, run_open_source_backdoor_result);

pub async fn run_cdn_poisoning_engine_result(t: &str) -> EngineResult {
    crate::cache_poisoning_engine::run_cache_poisoning_result(t).await
}
cli_wrapper!(run_cdn_poisoning_engine, run_cdn_poisoning_engine_result);

pub async fn run_software_signing_attack_result(t: &str) -> EngineResult {
    crate::sbom_analyzer_engine::run_sbom_analyzer_result(t).await
}
cli_wrapper!(run_software_signing_attack, run_software_signing_attack_result);

pub async fn run_build_system_compromise_result(t: &str) -> EngineResult {
    crate::cicd_pipeline_engine::run_cicd_pipeline_result(t).await
}
cli_wrapper!(run_build_system_compromise, run_build_system_compromise_result);

pub async fn run_dependency_confusion_result(t: &str) -> EngineResult {
    crate::supply_chain_engine::run_supply_chain_result(t, None).await
}
cli_wrapper!(run_dependency_confusion, run_dependency_confusion_result);

pub async fn run_update_hijacking_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    for path in ["/update.xml", "/autoupdate.json", "/latest.yml", "/RELEASES"] {
        let url = format!("{}{}", normalize_url(t).trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 && (p.body.contains("version") || p.body.contains("download") || p.body.contains("signature")) {
                findings.push(finding(
                    "update_hijacking",
                    "Public auto-update manifest",
                    "medium",
                    "T1195.002",
                    &format!("Manifest at {} is publicly reachable. Verify signature pinning + TLS.", p.final_url),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() { empty_ok("update_hijacking", t) }
    else { EngineResult::ok(findings.clone(), format!("update_hijacking: {}", findings.len())) }
}
cli_wrapper!(run_update_hijacking, run_update_hijacking_result);

pub async fn run_sbom_forgery_engine_result(t: &str) -> EngineResult {
    crate::sbom_analyzer_engine::run_sbom_analyzer_result(t).await
}
cli_wrapper!(run_sbom_forgery_engine, run_sbom_forgery_engine_result);

pub async fn run_third_party_api_attack_result(t: &str) -> EngineResult {
    crate::supply_chain_engine::run_supply_chain_result(t, None).await
}
cli_wrapper!(run_third_party_api_attack, run_third_party_api_attack_result);

pub async fn run_iac_supply_chain_result(t: &str) -> EngineResult {
    crate::iac_misconfig_engine::run_iac_misconfig_result(t).await
}
cli_wrapper!(run_iac_supply_chain, run_iac_supply_chain_result);
