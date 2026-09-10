//! Weissman Gate — software NGFW control plane (policy persist + dataplane health).
//!
//! Dataplane is a Linux nftables/eBPF gateway started separately. This module never
//! pretends the firewall is up: status is derived from `WEISSMAN_VNGFW_ADMIN` HTTP
//! or local `nft list table inet weissman_gate`.

use serde_json::{json, Value};
use sqlx::PgPool;

pub async fn load_policy(pool: &PgPool, tenant_id: i64) -> Value {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return json!({ "rules": [] });
    };
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT value FROM system_configs WHERE tenant_id = $1 AND key = 'vngfw_policy'",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten();
    let _ = tx.commit().await;
    raw.and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({ "rules": [], "default_action": "allow" }))
}

pub async fn save_policy(pool: &PgPool, tenant_id: i64, policy: &Value) -> Result<(), String> {
    let Ok(mut tx) = crate::db::begin_tenant_tx(pool, tenant_id).await else {
        return Err("database unavailable".into());
    };
    sqlx::query(
        r#"INSERT INTO system_configs (tenant_id, key, value, description)
           VALUES ($1, 'vngfw_policy', $2, 'Weissman Gate unified App/User/Content policy')
           ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value"#,
    )
    .bind(tenant_id)
    .bind(policy.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

pub async fn dataplane_status() -> Value {
    let admin = std::env::var("WEISSMAN_VNGFW_ADMIN").unwrap_or_default();
    let nft_present;
    let mut nft_table = false;
    #[cfg(target_os = "linux")]
    {
        nft_present = tokio::process::Command::new("nft")
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        if nft_present {
            nft_table = tokio::process::Command::new("nft")
                .args(["list", "table", "inet", "weissman_gate"])
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        nft_present = false;
    }
    let mut admin_http = json!(null);
    if !admin.trim().is_empty() {
        if let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
        {
            match client.get(admin.trim()).send().await {
                Ok(r) => {
                    admin_http = json!({
                        "url": admin.trim(),
                        "status": r.status().as_u16(),
                        "ok": r.status().is_success(),
                    });
                }
                Err(e) => {
                    admin_http = json!({
                        "url": admin.trim(),
                        "ok": false,
                        "error": e.to_string(),
                    });
                }
            }
        }
    }
    let ztna_url = std::env::var("WEISSMAN_ZTNA_PROXY").unwrap_or_default();
    let mut ztna = json!({ "ok": false, "configured": !ztna_url.trim().is_empty() });
    if !ztna_url.trim().is_empty() {
        if let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
        {
            match client.get(ztna_url.trim()).send().await {
                Ok(r) => {
                    ztna = json!({
                        "ok": r.status().is_success(),
                        "configured": true,
                        "url": ztna_url.trim(),
                        "status": r.status().as_u16(),
                    });
                }
                Err(e) => {
                    ztna = json!({
                        "ok": false,
                        "configured": true,
                        "url": ztna_url.trim(),
                        "error": e.to_string(),
                    });
                }
            }
        }
    }
    let farm = std::env::var("WEISSMAN_DETONATION_URL").unwrap_or_default();
    let mut detonation = json!({ "ok": false, "configured": !farm.trim().is_empty() });
    if !farm.trim().is_empty() {
        if let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
        {
            match client.get(farm.trim()).send().await {
                Ok(r) => {
                    detonation = json!({
                        "ok": r.status().is_success(),
                        "configured": true,
                        "url": farm.trim(),
                        "status": r.status().as_u16(),
                    });
                }
                Err(e) => {
                    detonation = json!({
                        "ok": false,
                        "configured": true,
                        "error": e.to_string(),
                    });
                }
            }
        }
    }
    let live = admin_http.get("ok").and_then(Value::as_bool).unwrap_or(false) || nft_table;
    json!({
        "ok": true,
        "dataplane_live": live,
        "nft_present": nft_present,
        "nft_table_weissman_gate": nft_table,
        "admin": admin_http,
        "ztna": ztna,
        "detonation": detonation,
        "note": if live {
            "Weissman Gate dataplane responded."
        } else {
            "Dataplane is down — set WEISSMAN_VNGFW_ADMIN or load nft table inet weissman_gate. This is not a simulated firewall."
        }
    })
}

fn sanitize_action(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "accept" | "allow" => Some("accept"),
        "drop" => Some("drop"),
        "reject" => Some("reject"),
        _ => None,
    }
}

fn sanitize_proto(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some("tcp"),
        "udp" => Some("udp"),
        _ => None,
    }
}

fn sanitize_cidr(raw: &str) -> Option<String> {
    let s = raw.trim();
    let (ip, prefix) = match s.split_once('/') {
        Some((a, b)) => (a, b),
        None => (s, "32"),
    };
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for p in &parts {
        let n: u8 = p.parse().ok()?;
        let _ = n;
    }
    let pref: u8 = prefix.parse().ok()?;
    if pref > 32 {
        return None;
    }
    Some(format!("{ip}/{pref}"))
}

/// Render nftables snippets from the unified policy (preview only unless apply=true + root).
pub fn policy_to_nft(policy: &Value) -> String {
    let mut out = String::from(
        "table inet weissman_gate {\n  chain forward {\n    type filter hook forward priority 0; policy drop;\n",
    );
    if let Some(rules) = policy.get("rules").and_then(Value::as_array) {
        for r in rules {
            let Some(action) =
                sanitize_action(r.get("action").and_then(Value::as_str).unwrap_or("drop"))
            else {
                continue;
            };
            let Some(proto) =
                sanitize_proto(r.get("proto").and_then(Value::as_str).unwrap_or("tcp"))
            else {
                continue;
            };
            let dport = r.get("dport").and_then(Value::as_u64).unwrap_or(0);
            if !(1..=65535).contains(&dport) {
                continue;
            }
            let saddr = sanitize_cidr(r.get("saddr").and_then(Value::as_str).unwrap_or("0.0.0.0/0"))
                .unwrap_or_else(|| "0.0.0.0/0".into());
            out.push_str(&format!(
                "    ip saddr {saddr} {proto} dport {dport} {action}\n"
            ));
        }
    }
    if policy
        .get("default_action")
        .and_then(Value::as_str)
        .unwrap_or("allow")
        == "allow"
    {
        out.push_str("    accept\n");
    }
    out.push_str("  }\n}\n");
    out
}

/// Load the rendered ruleset into the local kernel. Refuses unless
/// `WEISSMAN_VNGFW_APPLY=1` so a Command Center click cannot rewrite host
/// nftables by accident.
pub async fn apply_nft(policy: &Value) -> Result<String, String> {
    let apply = std::env::var("WEISSMAN_VNGFW_APPLY").unwrap_or_default();
    if apply != "1" && !apply.eq_ignore_ascii_case("true") {
        return Err(
            "Refusing to mutate host nftables. Set WEISSMAN_VNGFW_APPLY=1 on the Gate host, then retry."
                .into(),
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        return Err("Weissman Gate nft apply is Linux-only".into());
    }
    #[cfg(target_os = "linux")]
    {
        let rules = policy_to_nft(policy);
        let tmp = std::env::temp_dir().join("weissman_gate.nft");
        tokio::fs::write(&tmp, rules.as_bytes())
            .await
            .map_err(|e| format!("write nft file: {e}"))?;
        let flush = tokio::process::Command::new("nft")
            .args(["delete", "table", "inet", "weissman_gate"])
            .status()
            .await;
        let _ = flush;
        let nft_file = tmp.to_string_lossy().into_owned();
        let st = tokio::process::Command::new("nft")
            .args(["-f", &nft_file])
            .status()
            .await
            .map_err(|e| format!("nft spawn: {e}"))?;
        if !st.success() {
            return Err("nft -f weissman_gate.nft failed (need CAP_NET_ADMIN / nft installed)".into());
        }
        Ok("nft table inet weissman_gate loaded".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_render_includes_rule() {
        let p = json!({
            "default_action": "drop",
            "rules": [{ "action": "accept", "proto": "tcp", "dport": 443, "saddr": "10.0.0.0/8" }]
        });
        let s = policy_to_nft(&p);
        assert!(s.contains("dport 443"));
        assert!(s.contains("weissman_gate"));
    }
}
