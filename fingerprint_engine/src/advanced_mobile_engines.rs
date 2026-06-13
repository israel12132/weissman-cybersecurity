//! Advanced Mobile engines — public app-store, deep-link, and mobile-backend API probes.

use crate::engine_probes::{
    detect_secrets, empty_ok, finding_with_probe_depth, header_value, http_client, http_get,
    normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::Value;

const MOBILE_PROBE_DEPTH: &str = "mobile_api_surface";

fn mobile_finding(
    engine_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    description: &str,
    target: &str,
) -> Value {
    finding_with_probe_depth(
        engine_id,
        title,
        severity,
        mitre,
        description,
        target,
        MOBILE_PROBE_DEPTH,
    )
}

macro_rules! cli_wrapper {
    ($name:ident, $result_fn:ident) => {
        pub async fn $name(target: &str) {
            print_result($result_fn(target).await);
        }
    };
}

const MOBILE_API_PATHS: &[(&str, &str)] = &[
    ("/api/mobile", "Mobile REST API"),
    ("/api/v1/mobile", "Mobile REST API v1"),
    ("/api/v1/register", "Mobile registration endpoint"),
    ("/api/v1/login", "Mobile login endpoint"),
    ("/api/push/register", "Push notification registration"),
    ("/mobile/api", "Mobile API gateway"),
    ("/graphql", "GraphQL mobile backend"),
    ("/api/v1/devices", "Device enrollment API"),
    ("/api/v1/user/profile", "Mobile user profile API"),
];

const MOBILE_ASSET_PATHS: &[(&str, &str)] = &[
    (
        "/.well-known/apple-app-site-association",
        "Apple Universal Links (AASA)",
    ),
    ("/.well-known/assetlinks.json", "Android App Links"),
    ("/manifest.json", "Web/PWA manifest"),
    ("/index.bundle", "React Native bundle"),
    ("/cordova.js", "Cordova runtime"),
    ("/flutter_service_worker.js", "Flutter service worker"),
    ("/api/config/mobile", "Mobile app config"),
    ("/api/v1/app/config", "Mobile app config v1"),
];

/// Flag over-broad Universal-Link (AASA) / App-Link (assetlinks) wildcard paths that let
/// any URL on the domain open the mobile app — enabling deep-link / OAuth-redirect hijacking.
fn deep_link_overbroad_finding(engine_id: &str, body: &str, url: &str, t: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(body).ok()?;
    let mut overbroad = false;
    if let Some(details) = v.pointer("/applinks/details").and_then(Value::as_array) {
        for d in details {
            if let Some(paths) = d.get("paths").and_then(Value::as_array) {
                if paths
                    .iter()
                    .any(|p| p.as_str().is_some_and(|s| s == "*" || s == "/*" || s == "/"))
                {
                    overbroad = true;
                }
            }
            if let Some(comps) = d.get("components").and_then(Value::as_array) {
                if comps.iter().any(|c| {
                    c.get("/")
                        .and_then(Value::as_str)
                        .is_some_and(|s| s == "*" || s == "/*")
                }) {
                    overbroad = true;
                }
            }
        }
    }
    if !overbroad {
        return None;
    }
    Some(mobile_finding(
        engine_id,
        "Over-broad Universal/App-Link pattern (deep-link hijack risk)",
        "medium",
        "T1416",
        &format!(
            "{} declares a wildcard deep-link path ('*' / '/*') — every URL on this domain opens the mobile app, enabling deep-link / OAuth-redirect interception (token theft). Scope paths to the exact authenticated routes only.",
            url
        ),
        t,
    ))
}

async fn probe_mobile_api_surface(
    t: &str,
    engine_id: &str,
    mitre: &str,
    extra_paths: &[(&str, &str)],
) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();

    for (path, label) in MOBILE_API_PATHS.iter().chain(extra_paths.iter()) {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            let api_signal = p.status < 500
                && p.status != 404
                && (p.body.contains("\"token\"")
                    || p.body.contains("\"access_token\"")
                    || p.body.contains("\"user\"")
                    || p.body.contains("\"data\"")
                    || p.body.contains("graphql")
                    || p.body.contains("Unauthorized")
                    || p.body.contains("application/json")
                    || header_value(&p.headers, "content-type")
                        .is_some_and(|ct| ct.contains("json")));
            if api_signal {
                findings.push(mobile_finding(
                    engine_id,
                    &format!("{} reachable", label),
                    if p.status == 401 || p.status == 403 {
                        "medium"
                    } else {
                        "high"
                    },
                    mitre,
                    &format!(
                        "{} responded HTTP {} — mobile backend surface exposed; review auth and rate limits.",
                        p.final_url, p.status
                    ),
                    t,
                ));
            }
        }
    }

    for (path, label) in MOBILE_ASSET_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status != 200 || p.body.len() <= 32 {
                continue;
            }
            let relevant = path.contains("apple-app-site-association")
                || path.contains("assetlinks")
                || path.contains("bundle")
                || path.contains("cordova")
                || path.contains("flutter")
                || p.body.contains("\"applinks\"")
                || p.body.contains("\"apps\"")
                || p.body.contains("ReactNative");
            if !relevant {
                continue;
            }
            findings.push(mobile_finding(
                engine_id,
                &format!("{} published", label),
                "info",
                mitre,
                &format!("{} is publicly readable.", p.final_url),
                t,
            ));
            // Real check: hardcoded secrets embedded in the publicly-downloadable asset.
            let secrets = detect_secrets(&p.body);
            if !secrets.is_empty() {
                findings.push(mobile_finding(
                    engine_id,
                    &format!("Hardcoded secret in mobile asset: {}", label),
                    "critical",
                    "T1552.001",
                    &format!(
                        "{} embeds credential material ({}). Mobile bundles/configs are trivially downloaded and decompiled — rotate these secrets immediately and move them server-side.",
                        p.final_url,
                        secrets.join(", ")
                    ),
                    t,
                ));
            }
            // Real check: over-broad deep-link patterns (Universal/App-Link hijacking).
            if path.contains("apple-app-site-association") || path.contains("assetlinks") {
                if let Some(f) = deep_link_overbroad_finding(engine_id, &p.body, &p.final_url, t) {
                    findings.push(f);
                }
            }
        }
    }

    if findings.is_empty() {
        empty_ok(engine_id, t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("{}: {}", engine_id, findings.len()),
        )
    }
}

async fn store_probe(t: &str, engine_id: &str, mitre: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let q = urlencoding::encode(t.trim());
    let play_url = format!("https://play.google.com/store/apps/details?id={}", q);
    if let Some(p) = http_get(&client, &play_url).await {
        if p.status == 200 && p.body.contains("itemprop=\"name\"") {
            findings.push(mobile_finding(
                engine_id,
                "Google Play listing found",
                "info",
                mitre,
                &format!("Play Store page reachable for bundle id {}.", q),
                t,
            ));
        }
    }
    let itunes_url = format!("https://itunes.apple.com/lookup?bundleId={}", q);
    if let Some(p) = http_get(&client, &itunes_url).await {
        if p.status == 200
            && p.body.contains("\"resultCount\"")
            && !p.body.contains("\"resultCount\":0")
        {
            findings.push(mobile_finding(
                engine_id,
                "App Store listing found",
                "info",
                mitre,
                &format!(
                    "iTunes lookup returned a published app for bundle id {}.",
                    q
                ),
                t,
            ));
        }
    }
    if findings.is_empty() {
        empty_ok(engine_id, t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("{}: {}", engine_id, findings.len()),
        )
    }
}

pub async fn run_android_malware_engine_result(t: &str) -> EngineResult {
    store_probe(t, "android_malware_engine", "T1444").await
}
cli_wrapper!(
    run_android_malware_engine,
    run_android_malware_engine_result
);

pub async fn run_ios_exploit_engine_result(t: &str) -> EngineResult {
    store_probe(t, "ios_exploit_engine", "T1444").await
}
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
        let ct = header_value(&p.headers, "content-type").unwrap_or_default();
        if url.starts_with("http://") {
            findings.push(mobile_finding(
                "ssl_pinning_bypass",
                "Mobile API served over cleartext HTTP",
                "high",
                "T1556",
                &format!(
                    "{} is reachable without TLS — certificate pinning cannot protect this channel.",
                    p.final_url
                ),
                t,
            ));
        } else if ct.contains("json") && !p.body.contains("Strict-Transport-Security") {
            if header_value(&p.headers, "strict-transport-security").is_none() {
                findings.push(mobile_finding(
                    "ssl_pinning_bypass",
                    "JSON mobile API without HSTS",
                    "medium",
                    "T1556",
                    &format!(
                        "{} serves JSON without Strict-Transport-Security — downgrade/MITM risk on first connect.",
                        p.final_url
                    ),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("ssl_pinning_bypass", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("ssl_pinning_bypass: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_ssl_pinning_bypass, run_ssl_pinning_bypass_result);

pub async fn run_android_intent_attack_result(t: &str) -> EngineResult {
    probe_mobile_api_surface(
        t,
        "android_intent_attack",
        "T1444",
        &[("/.well-known/assetlinks.json", "Android App Links manifest")],
    )
    .await
}
cli_wrapper!(run_android_intent_attack, run_android_intent_attack_result);

pub async fn run_ios_url_scheme_attack_result(t: &str) -> EngineResult {
    probe_mobile_api_surface(
        t,
        "ios_url_scheme_attack",
        "T1444",
        &[(
            "/.well-known/apple-app-site-association",
            "Apple Universal Links manifest",
        )],
    )
    .await
}
cli_wrapper!(run_ios_url_scheme_attack, run_ios_url_scheme_attack_result);

pub async fn run_mobile_overlay_attack_result(t: &str) -> EngineResult {
    probe_mobile_api_surface(t, "mobile_overlay_attack", "T1404", &[]).await
}
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

pub async fn run_mobile_banking_trojan_result(t: &str) -> EngineResult {
    probe_mobile_api_surface(
        t,
        "mobile_banking_trojan",
        "T1444",
        &[
            ("/api/v1/banking", "Mobile banking API"),
            ("/api/v1/payments", "Mobile payments API"),
        ],
    )
    .await
}
cli_wrapper!(run_mobile_banking_trojan, run_mobile_banking_trojan_result);

pub async fn run_app_store_attack_result(t: &str) -> EngineResult {
    store_probe(t, "app_store_attack", "T1195").await
}
cli_wrapper!(run_app_store_attack, run_app_store_attack_result);

pub async fn run_mdm_bypass_engine_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    let mdm_paths: &[(&str, &str, &[&str])] = &[
        (
            "/manage/ServerHealth.action",
            "VMware Workspace ONE",
            &["Workspace ONE", "ServerHealth"],
        ),
        (
            "/enrollmentserver/Discovery.svc",
            "Microsoft Intune / Windows MDM",
            &["EnrollmentServer", "DiscoveryService"],
        ),
        ("/v1/server/health", "Jamf Pro", &["Jamf", "health"]),
        ("/api/users/auth", "Jamf Pro auth", &["Jamf", "auth"]),
        ("/MDM/Configuration", "MobileIron", &["MobileIron", "MDM"]),
        (
            "/.well-known/airwatch-mdm",
            "AirWatch / Workspace ONE",
            &["airwatch", "Workspace"],
        ),
    ];
    for (path, vendor, markers) in mdm_paths {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            let marker_hit = markers.iter().any(|m| p.body.contains(m));
            if p.status == 200 && marker_hit {
                findings.push(mobile_finding(
                    "mdm_bypass_engine",
                    &format!("Public {} endpoint reachable", vendor),
                    "medium",
                    "T1556",
                    &format!(
                        "{} returned HTTP 200 with {} markers — MDM admin/enrollment should not be internet-facing.",
                        p.final_url, vendor
                    ),
                    t,
                ));
            } else if p.status == 401 && marker_hit {
                findings.push(mobile_finding(
                    "mdm_bypass_engine",
                    &format!("{} endpoint exposed (auth required)", vendor),
                    "low",
                    "T1556",
                    &format!(
                        "{} is reachable (HTTP 401) — confirms {} surface; restrict to VPN.",
                        p.final_url, vendor
                    ),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("mdm_bypass_engine", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("mdm_bypass_engine: {}", findings.len()),
        )
    }
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
cli_wrapper!(
    run_bluetooth_mobile_attack,
    run_bluetooth_mobile_attack_result
);

pub async fn run_nfc_relay_attack_result(t: &str) -> EngineResult {
    crate::engine_probes::agent_required_ok(
        "nfc_relay_attack",
        t,
        "NFC relay attack detection requires NFC-capable agent",
        "Payment-card relays happen between NFC radios; the mobile agent reports anomalous NFC HCE sessions.",
    )
}
cli_wrapper!(run_nfc_relay_attack, run_nfc_relay_attack_result);

pub async fn run_mobile_spyware_engine_result(t: &str) -> EngineResult {
    store_probe(t, "mobile_spyware_engine", "T1444").await
}
cli_wrapper!(run_mobile_spyware_engine, run_mobile_spyware_engine_result);

pub async fn run_react_native_attack_result(t: &str) -> EngineResult {
    if t.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let client = http_client().await;
    let base = normalize_url(t);
    let mut findings: Vec<Value> = Vec::new();
    for path in ["/index.bundle", "/main.jsbundle", "/assets/index.bundle"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200
                && (p.body.contains("__d(")
                    || p.body.contains("react-native")
                    || p.body.len() > 4096)
            {
                findings.push(mobile_finding(
                    "react_native_attack",
                    "React Native JS bundle exposed",
                    "high",
                    "T1190",
                    &format!(
                        "{} ships a React Native bundle — decompile for hardcoded API keys and deep-link handlers.",
                        p.final_url
                    ),
                    t,
                ));
                // Real check: extract hardcoded secrets straight from the shipped bundle.
                let secrets = detect_secrets(&p.body);
                if !secrets.is_empty() {
                    findings.push(mobile_finding(
                        "react_native_attack",
                        "Hardcoded secret in React Native bundle",
                        "critical",
                        "T1552.001",
                        &format!(
                            "{} embeds credential material ({}) directly in the JS bundle — extractable by anyone who downloads the app. Rotate immediately and move secrets behind the backend.",
                            p.final_url,
                            secrets.join(", ")
                        ),
                        t,
                    ));
                }
                break;
            }
        }
    }
    if findings.is_empty() {
        if let Some(p) = http_get(&client, &base).await {
            if p.body.contains("react-native") || p.body.contains("__REACT_DEVTOOLS_GLOBAL_HOOK__")
            {
                findings.push(mobile_finding(
                    "react_native_attack",
                    "React Native fingerprint in HTML",
                    "info",
                    "T1190",
                    &format!(
                        "{} references React Native — review web shell and API endpoints.",
                        p.final_url
                    ),
                    t,
                ));
            }
        }
    }
    if findings.is_empty() {
        empty_ok("react_native_attack", t)
    } else {
        EngineResult::ok(
            findings.clone(),
            format!("react_native_attack: {}", findings.len()),
        )
    }
}
cli_wrapper!(run_react_native_attack, run_react_native_attack_result);
