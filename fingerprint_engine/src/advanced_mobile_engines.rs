//! Advanced Mobile-engines — public app-store / mobile-API probes.

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

async fn store_probe(t: &str, engine_id: &str, mitre: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let q = urlencoding::encode(t.trim());
    let urls = [
        format!("https://play.google.com/store/apps/details?id={}", q),
        format!("https://itunes.apple.com/lookup?bundleId={}", q),
    ];
    for url in urls.iter() {
        if let Some(p) = http_get(&client, url).await {
            if p.status == 200 && p.body.len() > 500 {
                findings.push(finding(
                    engine_id,
                    "Public app-store record",
                    "info",
                    mitre,
                    &format!("Store page reachable at {}.", url),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() { empty_ok(engine_id, t) }
    else { EngineResult::ok(findings.clone(), format!("{}: {}", engine_id, findings.len())) }
}

pub async fn run_android_malware_engine_result(t: &str) -> EngineResult { store_probe(t, "android_malware_engine", "T1444").await }
cli_wrapper!(run_android_malware_engine, run_android_malware_engine_result);

pub async fn run_ios_exploit_engine_result(t: &str) -> EngineResult { store_probe(t, "ios_exploit_engine", "T1444").await }
cli_wrapper!(run_ios_exploit_engine, run_ios_exploit_engine_result);

pub async fn run_mobile_mitm_result(t: &str) -> EngineResult {
    crate::pki_tls_engine::run_pki_tls_result(t).await
}
cli_wrapper!(run_mobile_mitm, run_mobile_mitm_result);

pub async fn run_ssl_pinning_bypass_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if crate::engine_probes::header_value(&p.headers, "public-key-pins").is_none() {
            findings.push(finding(
                "ssl_pinning_bypass",
                "No public-key-pins header",
                "low",
                "T1556",
                &format!("{} does not advertise HPKP — mobile MITM possible with rooted device.", p.final_url),
                t,
            ));
        }
    }
    if findings.is_empty() { empty_ok("ssl_pinning_bypass", t) }
    else { EngineResult::ok(findings.clone(), format!("ssl_pinning_bypass: {}", findings.len())) }
}
cli_wrapper!(run_ssl_pinning_bypass, run_ssl_pinning_bypass_result);

pub async fn run_android_intent_attack_result(t: &str) -> EngineResult { store_probe(t, "android_intent_attack", "T1444").await }
cli_wrapper!(run_android_intent_attack, run_android_intent_attack_result);

pub async fn run_ios_url_scheme_attack_result(t: &str) -> EngineResult { store_probe(t, "ios_url_scheme_attack", "T1444").await }
cli_wrapper!(run_ios_url_scheme_attack, run_ios_url_scheme_attack_result);

pub async fn run_mobile_overlay_attack_result(t: &str) -> EngineResult { store_probe(t, "mobile_overlay_attack", "T1404").await }
cli_wrapper!(run_mobile_overlay_attack, run_mobile_overlay_attack_result);

pub async fn run_sim_swap_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "sim_swap_engine",
        t,
        "SIM-swap detection requires telco API integration",
        "Carrier number-porting events are not visible to a network probe; integrate with Twilio Lookup / Telesign / direct MNO API to surface IMSI changes.",
    )
}
cli_wrapper!(run_sim_swap_engine, run_sim_swap_engine_result);

pub async fn run_mobile_banking_trojan_result(t: &str) -> EngineResult { store_probe(t, "mobile_banking_trojan", "T1444").await }
cli_wrapper!(run_mobile_banking_trojan, run_mobile_banking_trojan_result);

pub async fn run_app_store_attack_result(t: &str) -> EngineResult { store_probe(t, "app_store_attack", "T1195").await }
cli_wrapper!(run_app_store_attack, run_app_store_attack_result);

pub async fn run_mdm_bypass_engine_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "mdm_bypass_engine",
        t,
        "MDM bypass detection requires Intune / Workspace ONE API",
        "Profile-removal and jailbreak hints come from the MDM management API — connect it in Integrations.",
    )
}
cli_wrapper!(run_mdm_bypass_engine, run_mdm_bypass_engine_result);

pub async fn run_bluetooth_mobile_attack_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "bluetooth_mobile_attack",
        t,
        "Mobile Bluetooth attack detection requires on-device sensor",
        "BlueBorne / KNOB attacks exploit local BT stack; deploy the iOS/Android mobile agent.",
    )
}
cli_wrapper!(run_bluetooth_mobile_attack, run_bluetooth_mobile_attack_result);

pub async fn run_nfc_relay_attack_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "nfc_relay_attack",
        t,
        "NFC relay attack detection requires NFC-capable agent",
        "Payment-card relays happen between NFC radios; the mobile agent reports anomalous NFC HCE sessions.",
    )
}
cli_wrapper!(run_nfc_relay_attack, run_nfc_relay_attack_result);

pub async fn run_mobile_spyware_engine_result(t: &str) -> EngineResult { store_probe(t, "mobile_spyware_engine", "T1444").await }
cli_wrapper!(run_mobile_spyware_engine, run_mobile_spyware_engine_result);

pub async fn run_react_native_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let url = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    if let Some(p) = http_get(&client, &url).await {
        if p.body.contains("react-native") || p.body.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__") {
            findings.push(finding(
                "react_native_attack",
                "React-native fingerprint",
                "info",
                "T1190",
                &format!("{} ships React/RN code — review bundle for hardcoded secrets.", p.final_url),
                t,
            ));
        }
    }
    if findings.is_empty() { empty_ok("react_native_attack", t) }
    else { EngineResult::ok(findings.clone(), format!("react_native_attack: {}", findings.len())) }
}
cli_wrapper!(run_react_native_attack, run_react_native_attack_result);
