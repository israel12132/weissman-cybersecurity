//! Optional Cloudflare **IPv4 /24** access rule when a deception canary fires (EventBridge or `/api/deception/triggered`).
//! Gated by explicit env acknowledgement — broad blocks can cut off legitimate users on shared prefixes.

use chrono::Utc;
use serde_json::{json, Value};
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use tracing::{info, warn};

pub fn blackhole_enabled() -> bool {
    matches!(
        env::var("WEISSMAN_DECEPTION_CF_BLACKHOLE_ENABLE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) && matches!(
        env::var("WEISSMAN_DECEPTION_CF_BLACKHOLE_I_ACKNOWLEDGE_ISP_IMPACT").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn cf_token() -> Option<String> {
    env::var("WEISSMAN_CF_API_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn cf_zone_id() -> Option<String> {
    env::var("WEISSMAN_CF_ZONE_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn ipv4_slash24(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
}

async fn cf_block_asn(token: &str, zone_id: &str, asn: u64) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(25))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
    );
    let body = json!({
        "mode": "block",
        "configuration": { "target": "asn", "value": asn.to_string() },
        "notes": format!("weissman deception canary ASN {}", Utc::now().to_rfc3339())
    });
    let r = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        let st = r.status();
        let txt = r.text().await.unwrap_or_default();
        return Err(format!("cloudflare access_rules(asn): {} {}", st, txt));
    }
    Ok(())
}

async fn cf_block_cidr(token: &str, zone_id: &str, cidr: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(25))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules"
    );
    let body = json!({
        "mode": "block",
        "configuration": { "target": "ip_range", "value": cidr },
        "notes": format!("weissman deception canary blackhole {}", Utc::now().to_rfc3339())
    });
    let r = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        let st = r.status();
        let txt = r.text().await.unwrap_or_default();
        return Err(format!("cloudflare access_rules: {} {}", st, txt));
    }
    Ok(())
}

/// Best-effort extraction of an IPv4 from common CloudTrail / GuardDuty / forwarder shapes.
pub fn sniff_ipv4_from_json(v: &Value, depth: u32) -> Option<Ipv4Addr> {
    if depth > 28 {
        return None;
    }
    match v {
        Value::String(s) => {
            let t = s.trim();
            if let Ok(IpAddr::V4(ip)) = t.parse::<IpAddr>() {
                return Some(ip);
            }
            None
        }
        Value::Object(m) => {
            for key in [
                "sourceIPAddress",
                "source_ip",
                "clientIp",
                "remoteIp",
                "ipAddress",
                "client_ip",
                "remote_addr",
                "sourceipaddress",
            ] {
                if let Some(inner) = m.get(key) {
                    if let Some(ip) = sniff_ipv4_from_json(inner, depth + 1) {
                        return Some(ip);
                    }
                }
            }
            for val in m.values() {
                if let Some(ip) = sniff_ipv4_from_json(val, depth + 1) {
                    return Some(ip);
                }
            }
            None
        }
        Value::Array(a) => {
            for x in a {
                if let Some(ip) = sniff_ipv4_from_json(x, depth + 1) {
                    return Some(ip);
                }
            }
            None
        }
        _ => None,
    }
}

/// Extract numeric ASN from GuardDuty / CloudTrail style JSON.
pub fn sniff_asn_from_json(v: &Value, depth: u32) -> Option<u64> {
    if depth > 28 {
        return None;
    }
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        Value::Object(m) => {
            for key in [
                "asn",
                "ASN",
                "autonomousSystemNumber",
                "autonomous_system_number",
                "sourceAsn",
                "source_asn",
            ] {
                if let Some(inner) = m.get(key) {
                    if let Some(a) = sniff_asn_from_json(inner, depth + 1) {
                        return Some(a);
                    }
                }
            }
            for val in m.values() {
                if let Some(a) = sniff_asn_from_json(val, depth + 1) {
                    return Some(a);
                }
            }
            None
        }
        Value::Array(a) => {
            for x in a {
                if let Some(a) = sniff_asn_from_json(x, depth + 1) {
                    return Some(a);
                }
            }
            None
        }
        _ => None,
    }
}

/// Prefer blocking the whole AS when telemetry includes an ASN; fall back to IPv4 /24.
pub async fn maybe_blackhole_from_canary_payload(payload: &Value, source_ip: Option<IpAddr>) {
    if !blackhole_enabled() {
        return;
    }
    let Some(token) = cf_token() else {
        warn!(target: "deception_cf_blackhole", "WEISSMAN_CF_API_TOKEN missing");
        return;
    };
    let Some(zone_id) = cf_zone_id() else {
        warn!(target: "deception_cf_blackhole", "WEISSMAN_CF_ZONE_ID missing");
        return;
    };
    if let Some(asn) = sniff_asn_from_json(payload, 0) {
        if asn > 0 && asn <= 4_294_967_295 {
            match cf_block_asn(&token, &zone_id, asn).await {
                Ok(()) => {
                    info!(
                        target: "deception_cf_blackhole",
                        "blocked ASN {} after deception canary",
                        asn
                    );
                }
                Err(e) => {
                    warn!(target: "deception_cf_blackhole", "ASN block failed: {}; trying /24", e);
                    maybe_blackhole_source_ip(source_ip).await;
                }
            }
            return;
        }
    }
    maybe_blackhole_source_ip(source_ip).await;
}

/// Fire-and-forget: block attacker /24 on IPv4 when enabled and creds present.
pub async fn maybe_blackhole_source_ip(source_ip: Option<IpAddr>) {
    if !blackhole_enabled() {
        return;
    }
    let Some(IpAddr::V4(v4)) = source_ip else {
        return;
    };
    let allow_private = matches!(
        env::var("WEISSMAN_DECEPTION_CF_BLACKHOLE_ALLOW_PRIVATE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    );
    if !allow_private
        && (v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified())
    {
        tracing::debug!(
            target: "deception_cf_blackhole",
            "skip private/bogon {}",
            v4
        );
        return;
    }
    let Some(token) = cf_token() else {
        warn!(target: "deception_cf_blackhole", "WEISSMAN_CF_API_TOKEN missing");
        return;
    };
    let Some(zone_id) = cf_zone_id() else {
        warn!(target: "deception_cf_blackhole", "WEISSMAN_CF_ZONE_ID missing");
        return;
    };
    let cidr = ipv4_slash24(v4);
    match cf_block_cidr(&token, &zone_id, &cidr).await {
        Ok(()) => info!(
            target: "deception_cf_blackhole",
            "blocked CIDR {} after deception canary",
            cidr
        ),
        Err(e) => warn!(target: "deception_cf_blackhole", "{}", e),
    }
}
