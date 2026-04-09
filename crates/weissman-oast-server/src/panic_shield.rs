//! Optional "panic shield" hooks: Cloudflare WAF + zone security level.
//!
//! **Safety:** Disabled by default. Enabling can block large IPv4 ranges and impact legitimate users.
//! Requires explicit acknowledgement env vars plus Cloudflare credentials.

use chrono::Utc;
use serde_json::json;
use std::env;
use std::net::IpAddr;
use tracing::{info, warn};

fn shield_enabled() -> bool {
    matches!(
        env::var("WEISSMAN_PANIC_SHIELD_ENABLE").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) && matches!(
        env::var("WEISSMAN_PANIC_SHIELD_I_ACKNOWLEDGE_BROAD_IMPACT").as_deref(),
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

fn host_is_sovereign_trap(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host).to_lowercase();
    h.split('.')
        .next()
        .map(|l| l.starts_with("trap-"))
        .unwrap_or(false)
}

fn ipv4_slash24(ip: std::net::Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
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
        "notes": format!("weissman panic-shield auto {}", Utc::now().to_rfc3339())
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
        return Err(format!("cloudflare access_rules: {st} {txt}"));
    }
    Ok(())
}

async fn cf_under_attack(token: &str, zone_id: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(25))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level"
    );
    let body = json!({ "value": "under_attack" });
    let r = client
        .patch(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        let st = r.status();
        let txt = r.text().await.unwrap_or_default();
        return Err(format!("cloudflare security_level: {st} {txt}"));
    }
    Ok(())
}

/// Fire-and-forget reaction to sovereign `trap-*` OAST hits (Host and/or `/i/:token` path).
pub async fn maybe_react_to_trap_hit(
    source_ip: Option<IpAddr>,
    host: &str,
    path_token: Option<&str>,
) {
    let sovereign = host_is_sovereign_trap(host)
        || path_token
            .map(|t| t.trim().starts_with("trap-"))
            .unwrap_or(false);
    if !sovereign {
        return;
    }
    if !shield_enabled() {
        return;
    }
    let Some(token) = cf_token() else {
        warn!(target: "panic_shield", "WEISSMAN_CF_API_TOKEN missing");
        return;
    };
    let Some(zone) = cf_zone_id() else {
        warn!(target: "panic_shield", "WEISSMAN_CF_ZONE_ID missing");
        return;
    };
    let dry = matches!(
        env::var("WEISSMAN_PANIC_SHIELD_DRY_RUN").as_deref(),
        Ok("1") | Ok("true")
    );
    let Some(IpAddr::V4(v4)) = source_ip else {
        warn!(target: "panic_shield", "skip non-IPv4 source for /24 block");
        return;
    };
    let cidr = ipv4_slash24(v4);
    if dry {
        info!(
            target: "panic_shield",
            dry_run = true,
            %cidr,
            "would block /24 and enable under_attack"
        );
        return;
    }
    if let Err(e) = cf_block_cidr(&token, &zone, &cidr).await {
        warn!(target: "panic_shield", error = %e, "block cidr failed");
        return;
    }
    info!(target: "panic_shield", %cidr, "blocked /24 via Cloudflare access rule");
    if matches!(
        env::var("WEISSMAN_PANIC_SHIELD_UNDER_ATTACK").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    ) {
        if let Err(e) = cf_under_attack(&token, &zone).await {
            warn!(target: "panic_shield", error = %e, "under_attack mode failed");
        }
    }
}
