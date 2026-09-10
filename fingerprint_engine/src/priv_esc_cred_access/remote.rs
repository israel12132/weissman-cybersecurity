//! Remote surface probes — Windows privilege / credential ports and HTTP leak paths.
//!
//! Connect-only. Never authenticates, never dumps SAM/NTDS, never sends UAC bypass
//! COM activation. An open port is attack-surface evidence, not a credential.

use super::eval::{apply, CheckStatus, Coverage};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    extract_host, http_client, http_get, join_url, normalize_url, tcp_open,
};
use serde_json::{json, Value};

const WINDOWS_PRIV_PORTS: &[(u16, &'static str, &'static [u16])] = &[
    (
        445,
        "SMB (credential relay / PsExec class)",
        &[108, 201, 301],
    ),
    (139, "NetBIOS session", &[108, 301]),
    (135, "RPC endpoint mapper", &[114, 207]),
    (88, "Kerberos", &[113, 140]),
    (389, "LDAP", &[110, 331]),
    (636, "LDAPS", &[110]),
    (3268, "Global Catalog", &[110]),
    (3389, "RDP", &[334, 344]),
    (5985, "WinRM HTTP", &[118, 131]),
    (5986, "WinRM HTTPS", &[118, 131]),
    (2375, "Docker API unauthenticated", &[108, 345]),
];

const LEAK_PATHS: &[&str] = &[
    "/.git/config",
    "/web.config",
    "/appsettings.json",
    "/.env",
    "/backup/sam",
    "/ntds.dit",
];

pub struct RemoteSurface {
    pub host: String,
    pub open_ports: Vec<(u16, String)>,
    pub leak_hits: Vec<(String, u16)>,
    pub docker_unauth: bool,
}

pub async fn probe(target: &str, ctx: &EngineRunContext) -> RemoteSurface {
    let host = extract_host(target);
    let mut futs = Vec::new();
    for (port, _, _) in WINDOWS_PRIV_PORTS {
        let h = host.clone();
        let p = *port;
        futs.push(async move { (p, tcp_open(&h, p).await) });
    }
    let results = futures::future::join_all(futs).await;
    let mut open_ports = Vec::new();
    let mut docker_unauth = false;
    for (port, open) in results {
        if open {
            let label = WINDOWS_PRIV_PORTS
                .iter()
                .find(|(p, _, _)| *p == port)
                .map(|(_, l, _)| (*l).to_string())
                .unwrap_or_else(|| format!("tcp/{port}"));
            if port == 2375 {
                docker_unauth = true;
            }
            open_ports.push((port, label));
        }
    }

    let url_like =
        target.contains("http://") || target.contains("https://") || target.contains("/api");
    let looks_http = ctx
        .job_params
        .get("check_http_leaks")
        .and_then(Value::as_bool)
        .unwrap_or(url_like);
    let mut leak_hits = Vec::new();
    if looks_http && !host.is_empty() {
        let client = http_client().await;
        let base = normalize_url(target);
        for path in LEAK_PATHS {
            let url = join_url(&base, path);
            if let Some(resp) = http_get(&client, &url).await {
                if (200..400).contains(&resp.status) && resp.body.len() > 8 {
                    leak_hits.push((url, resp.status));
                }
            }
        }
    }

    RemoteSurface {
        host,
        open_ports,
        leak_hits,
        docker_unauth,
    }
}

pub fn apply_remote(cov: &mut Coverage, remote: &RemoteSurface) {
    if remote.open_ports.is_empty() {
        apply(
            cov,
            &[108, 301, 334],
            CheckStatus::Pass,
            &format!(
                "no Windows privilege/credential ports open on {}",
                remote.host
            ),
        );
    }
    for (port, label) in &remote.open_ports {
        let ids = WINDOWS_PRIV_PORTS
            .iter()
            .find(|(p, _, _)| p == port)
            .map(|(_, _, ids)| *ids)
            .unwrap_or(&[108][..]);
        apply(
            cov,
            ids,
            CheckStatus::Fail,
            &format!("{} tcp/{} OPEN on {}", label, port, remote.host),
        );
    }
    if remote.docker_unauth {
        apply(
            cov,
            &[108, 345],
            CheckStatus::Fail,
            "Docker Engine API tcp/2375 reachable without TLS — host takeover / credential path",
        );
    }
    if remote.leak_hits.is_empty() {
        apply(
            cov,
            &[304, 347],
            CheckStatus::Pass,
            "no HTTP credential-leak paths returned 2xx/3xx with a body",
        );
    } else {
        let list = remote
            .leak_hits
            .iter()
            .map(|(u, s)| format!("{u} ({s})"))
            .collect::<Vec<_>>()
            .join(", ");
        apply(
            cov,
            &[304, 347, 311],
            CheckStatus::Fail,
            &format!("HTTP leak surface (bodies not stored): {list}"),
        );
    }
}

pub fn remote_json(r: &RemoteSurface) -> Value {
    json!({
        "host": r.host,
        "open_ports": r.open_ports.iter().map(|(p, l)| json!({"port": p, "label": l})).collect::<Vec<_>>(),
        "leak_hits": r.leak_hits.iter().map(|(u, s)| json!({"url": u, "status": s})).collect::<Vec<_>>(),
        "docker_unauth": r.docker_unauth,
    })
}
