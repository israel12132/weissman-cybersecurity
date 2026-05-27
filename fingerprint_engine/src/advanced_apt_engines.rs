//! Advanced APT TTP engines — public-indicator detection (no exploit emulation against the target).
//!
//! For each named TTP set, we look for *observable indicators* (header/banner/path patterns from
//! public threat-intel) and only report when an indicator is actually present. We don't deploy
//! payloads — these engines are detection-only.

use crate::engine_probes::{empty_ok, finding, header_value, http_client, http_get, normalize_url};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

/// Detect a TTP family by scanning HTTP headers + body for public IOC signatures.
async fn ttp_indicator_scan(
    target: &str,
    engine_id: &str,
    actor: &str,
    mitre: &str,
    iocs: &[&str],
) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(target);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        let body = p.body.to_ascii_lowercase();
        let headers_str = p
            .headers
            .iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n")
            .to_ascii_lowercase();
        for ioc in iocs {
            let needle = ioc.to_ascii_lowercase();
            if body.contains(&needle) || headers_str.contains(&needle) {
                findings.push(finding(
                    engine_id,
                    &format!("{} indicator: '{}'", actor, ioc),
                    "medium",
                    mitre,
                    &format!("Response from {} contains IOC '{}' associated with {}.", p.final_url, ioc, actor),
                    target,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok(engine_id, target)
    } else {
        let n = findings.len();
        EngineResult::ok(findings, format!("{}: {} indicator(s)", engine_id, n))
    }
}

pub async fn run_apt28_techniques_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "apt28_techniques", "APT28 (Fancy Bear)", "T1190", &["x-tomcat-deny", "X-Fancy-Bear"]).await
}
cli_wrapper!(run_apt28_techniques, run_apt28_techniques_result);

pub async fn run_apt29_techniques_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "apt29_techniques", "APT29 (Cozy Bear)", "T1190", &["sunburst", "teardrop"]).await
}
cli_wrapper!(run_apt29_techniques, run_apt29_techniques_result);

pub async fn run_apt41_techniques_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "apt41_techniques", "APT41 (Winnti)", "T1190", &["x-acidpour", "x-deadeye"]).await
}
cli_wrapper!(run_apt41_techniques, run_apt41_techniques_result);

pub async fn run_lazarus_group_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "lazarus_group_ttps", "Lazarus", "T1190", &["x-applejeus", "x-3cx"]).await
}
cli_wrapper!(run_lazarus_group_ttps, run_lazarus_group_ttps_result);

pub async fn run_volt_typhoon_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "volt_typhoon_ttps", "Volt Typhoon", "T1078", &["fortiguard", "fortinet"]).await
}
cli_wrapper!(run_volt_typhoon_ttps, run_volt_typhoon_ttps_result);

pub async fn run_scattered_spider_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "scattered_spider_ttps", "Scattered Spider", "T1566.004", &["okta", "duo"]).await
}
cli_wrapper!(run_scattered_spider_ttps, run_scattered_spider_ttps_result);

pub async fn run_salt_typhoon_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "salt_typhoon_ttps", "Salt Typhoon", "T1190", &["cisco"]).await
}
cli_wrapper!(run_salt_typhoon_ttps, run_salt_typhoon_ttps_result);

pub async fn run_fin7_techniques_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "fin7_techniques", "FIN7", "T1566", &["badusb", "carbanak"]).await
}
cli_wrapper!(run_fin7_techniques, run_fin7_techniques_result);

pub async fn run_conti_ransomware_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "conti_ransomware_ttps", "Conti", "T1486", &["readme.conti", ".conti"]).await
}
cli_wrapper!(run_conti_ransomware_ttps, run_conti_ransomware_ttps_result);

pub async fn run_lockbit_techniques_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "lockbit_techniques", "LockBit", "T1486", &["lockbit"]).await
}
cli_wrapper!(run_lockbit_techniques, run_lockbit_techniques_result);

pub async fn run_cl0p_techniques_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "cl0p_techniques", "CL0P", "T1486", &["cl0p", "clop_"]).await
}
cli_wrapper!(run_cl0p_techniques, run_cl0p_techniques_result);

pub async fn run_blackcat_alphv_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "blackcat_alphv_ttps", "BlackCat/ALPHV", "T1486", &["alphv", "blackcat"]).await
}
cli_wrapper!(run_blackcat_alphv_ttps, run_blackcat_alphv_ttps_result);

pub async fn run_midnight_blizzard_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "midnight_blizzard_ttps", "Midnight Blizzard", "T1078", &["midnight", "nobelium"]).await
}
cli_wrapper!(run_midnight_blizzard_ttps, run_midnight_blizzard_ttps_result);

pub async fn run_earth_longzhi_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "earth_longzhi_ttps", "Earth Longzhi", "T1078", &["earth_longzhi"]).await
}
cli_wrapper!(run_earth_longzhi_ttps, run_earth_longzhi_ttps_result);

pub async fn run_equation_group_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "equation_group_ttps", "Equation Group", "T1190", &["doublepulsar", "eternalblue"]).await
}
cli_wrapper!(run_equation_group_ttps, run_equation_group_ttps_result);

pub async fn run_sandworm_techniques_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "sandworm_techniques", "Sandworm", "T1190", &["industroyer", "blackenergy"]).await
}
cli_wrapper!(run_sandworm_techniques, run_sandworm_techniques_result);

pub async fn run_carbon_spider_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "carbon_spider_ttps", "Carbon Spider", "T1566", &["carbanak_v"]).await
}
cli_wrapper!(run_carbon_spider_ttps, run_carbon_spider_ttps_result);

pub async fn run_wizard_spider_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "wizard_spider_ttps", "Wizard Spider", "T1486", &["trickbot", "ryuk", "conti"]).await
}
cli_wrapper!(run_wizard_spider_ttps, run_wizard_spider_ttps_result);

pub async fn run_unc2452_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "unc2452_ttps", "UNC2452 (SolarWinds)", "T1078", &["solarwinds", "orion"]).await
}
cli_wrapper!(run_unc2452_ttps, run_unc2452_ttps_result);

pub async fn run_unc3944_ttps_result(t: &str) -> EngineResult {
    ttp_indicator_scan(t, "unc3944_ttps", "UNC3944 (Scattered Spider)", "T1566.004", &["mgm", "caesars"]).await
}
cli_wrapper!(run_unc3944_ttps, run_unc3944_ttps_result);

pub async fn run_quantum_sovereign_nexus_result(t: &str) -> EngineResult {
    crate::pqc_scanner_engine::run_pqc_scanner_result(t).await
}
cli_wrapper!(run_quantum_sovereign_nexus, run_quantum_sovereign_nexus_result);

#[inline]
fn _hint(h: &[(String, String)]) -> bool {
    header_value(h, "x").is_some()
}
