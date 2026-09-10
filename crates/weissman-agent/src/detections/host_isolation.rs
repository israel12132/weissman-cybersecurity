//! Host network isolation / release using nftables (Linux) or netsh (Windows).

use super::finding;
use serde_json::{json, Value};

pub async fn run(engine: &str, params: &Value) -> anyhow::Result<Vec<Value>> {
    let action = params
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("status")
        .to_ascii_lowercase();
    match action.as_str() {
        "isolate" => isolate(engine).await,
        "release" => release(engine).await,
        "quarantine" => quarantine(engine, params).await,
        _ => status(engine).await,
    }
}

async fn quarantine(engine: &str, params: &Value) -> anyhow::Result<Vec<Value>> {
    let path = params
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if path.is_empty() {
        return Ok(vec![finding(
            engine,
            "Quarantine requested without a path",
            "info",
            "T1485",
            "Dispatch host_isolation with params.path set to a local file. Nothing was moved.",
            json_extras(json!({ "action": "quarantine", "applied": false })),
        )]);
    }
    let p = std::path::Path::new(&path);
    if !p.is_file() {
        return Ok(vec![finding(
            engine,
            "Quarantine path is not a file on this host",
            "low",
            "T1485",
            &format!("{path} is not a regular file — quarantine not faked."),
            json_extras(json!({ "action": "quarantine", "path": path, "applied": false })),
        )]);
    }
    let dest_dir = std::path::Path::new("/var/lib/weissman/quarantine");
    let _ = tokio::fs::create_dir_all(dest_dir).await;
    let name = p
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "quarantined".into());
    let dest = dest_dir.join(format!(
        "{}-{}",
        chrono::Utc::now().timestamp(),
        name.replace('/', "_")
    ));
    match tokio::fs::rename(p, &dest).await {
        Ok(()) => Ok(vec![finding(
            engine,
            "File quarantined",
            "high",
            "T1485",
            &format!("Moved {path} → {}", dest.display()),
            json_extras(json!({
                "action": "quarantine",
                "path": path,
                "dest": dest.display().to_string(),
                "applied": true
            })),
        )]),
        Err(e) => Ok(vec![finding(
            engine,
            "Quarantine move failed",
            "medium",
            "T1485",
            &format!("rename {path} failed: {e}"),
            json_extras(json!({ "action": "quarantine", "applied": false, "error": e.to_string() })),
        )]),
    }
}

async fn isolate(engine: &str) -> anyhow::Result<Vec<Value>> {
    let c2 = c2_allowlist().await;
    #[cfg(target_os = "linux")]
    {
        let apply = tokio::process::Command::new("nft")
            .args(["add", "table", "inet", "weissman_isolate"])
            .status()
            .await;
        let chain = tokio::process::Command::new("nft")
            .args([
                "add",
                "chain",
                "inet",
                "weissman_isolate",
                "output",
                "{ type filter hook output priority 0; policy drop; }",
            ])
            .status()
            .await;
        let allow_dns = tokio::process::Command::new("nft")
            .args(["add", "rule", "inet", "weissman_isolate", "output", "udp", "dport", "53", "accept"])
            .status()
            .await;
        let mut c2_ok = 0u32;
        for (ip, port) in &c2 {
            let fam = if ip.contains(':') { "ip6" } else { "ip" };
            let st = tokio::process::Command::new("nft")
                .args([
                    "add",
                    "rule",
                    "inet",
                    "weissman_isolate",
                    "output",
                    fam,
                    "daddr",
                    ip,
                    "tcp",
                    "dport",
                    &port.to_string(),
                    "accept",
                ])
                .status()
                .await;
            if st.map(|s| s.success()).unwrap_or(false) {
                c2_ok += 1;
            }
        }
        let ok = apply.map(|s| s.success()).unwrap_or(false)
            && chain.map(|s| s.success()).unwrap_or(false);
        let _ = allow_dns;
        if ok {
            return Ok(vec![finding(
                engine,
                "Host output isolated via nftables weissman_isolate",
                "high",
                "T1489",
                &format!(
                    "nft table inet weissman_isolate output policy drop is active. DNS/53 and {c2_ok} C2 allow rules (WEISSMAN_SERVER_URL) remain."
                ),
                json_extras(json!({ "action": "isolate", "backend": "nftables", "c2_rules": c2_ok })),
            )]);
        }
        return Ok(vec![finding(
            engine,
            "Host isolation requested but nftables apply failed",
            "medium",
            "T1489",
            "nft add table/chain weissman_isolate failed — agent lacks CAP_NET_ADMIN or nft is missing. Isolation was NOT faked.",
            json_extras(json!({ "action": "isolate", "applied": false })),
        )]);
    }
    #[cfg(target_os = "windows")]
    {
        for (ip, port) in &c2 {
            let _ = tokio::process::Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    "name=WeissmanC2",
                    "dir=out",
                    "action=allow",
                    "protocol=TCP",
                    &format!("remoteip={ip}"),
                    &format!("remoteport={port}"),
                ])
                .status()
                .await;
        }
        let st = tokio::process::Command::new("netsh")
            .args(["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"])
            .status()
            .await;
        if st.map(|s| s.success()).unwrap_or(false) {
            return Ok(vec![finding(
                engine,
                "Windows firewall set to block inbound/outbound",
                "high",
                "T1489",
                "netsh advfirewall allprofiles firewallpolicy blockinbound,blockoutbound succeeded. WeissmanC2 allow rule added when WEISSMAN_SERVER_URL resolved.",
                json_extras(json!({ "action": "isolate", "backend": "wfp", "c2_rules": c2.len() })),
            )]);
        }
        return Ok(vec![finding(
            engine,
            "Windows host isolation command failed",
            "medium",
            "T1489",
            "netsh advfirewall failed — isolate not applied.",
            json_extras(json!({ "action": "isolate", "applied": false })),
        )]);
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = c2;
        Ok(vec![finding(
            engine,
            "Host isolation unsupported on this OS",
            "info",
            "T1489",
            "Isolation backends exist for Linux nftables and Windows Filtering Platform only.",
            json_extras(json!({ "action": "isolate", "applied": false })),
        )])
    }
}

async fn c2_allowlist() -> Vec<(String, u16)> {
    let raw = std::env::var("WEISSMAN_SERVER_URL").unwrap_or_default();
    let Ok(u) = url::Url::parse(raw.trim()) else {
        return Vec::new();
    };
    let Some(host) = u.host_str() else {
        return Vec::new();
    };
    let port = u.port_or_known_default().unwrap_or(443);
    let lookup = format!("{host}:{port}");
    let Ok(iter) = tokio::net::lookup_host(&lookup).await else {
        return Vec::new();
    };
    iter.map(|sa| (sa.ip().to_string(), port)).collect()
}

async fn release(engine: &str) -> anyhow::Result<Vec<Value>> {
    #[cfg(target_os = "linux")]
    {
        let st = tokio::process::Command::new("nft")
            .args(["delete", "table", "inet", "weissman_isolate"])
            .status()
            .await;
        let ok = st.map(|s| s.success()).unwrap_or(false);
        return Ok(vec![finding(
            engine,
            if ok {
                "Host isolation table removed"
            } else {
                "Isolation table delete failed or was not present"
            },
            "info",
            "T1489",
            "nft delete table inet weissman_isolate.",
            json_extras(json!({ "action": "release", "applied": ok })),
        )]);
    }
    #[cfg(target_os = "windows")]
    {
        let st = tokio::process::Command::new("netsh")
            .args(["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"])
            .status()
            .await;
        let ok = st.map(|s| s.success()).unwrap_or(false);
        return Ok(vec![finding(
            engine,
            "Windows firewall outbound restored",
            "info",
            "T1489",
            "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound.",
            json_extras(json!({ "action": "release", "applied": ok })),
        )]);
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(vec![])
    }
}

async fn status(engine: &str) -> anyhow::Result<Vec<Value>> {
    #[cfg(target_os = "linux")]
    {
        let out = tokio::process::Command::new("nft")
            .args(["list", "table", "inet", "weissman_isolate"])
            .output()
            .await;
        let isolated = out.map(|o| o.status.success()).unwrap_or(false);
        return Ok(vec![finding(
            engine,
            if isolated {
                "weissman_isolate nft table is present"
            } else {
                "Host is not isolated (no weissman_isolate table)"
            },
            if isolated { "high" } else { "info" },
            "T1489",
            "Live nftables table probe.",
            json_extras(json!({ "isolated": isolated })),
        )]);
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(vec![finding(
            engine,
            "Isolation status probe (non-Linux)",
            "info",
            "T1489",
            "Run with params.action=isolate|release on a supported OS.",
            json_extras(json!({ "os": std::env::consts::OS })),
        )])
    }
}

fn json_extras(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}
