//! Archival Intelligence: Wayback Machine + AlienVault OTX. Historical URLs fed into target_paths.

use crate::stealth_engine;
use reqwest::Url;
use std::collections::HashSet;
use std::time::Duration;

const TIMEOUT_SECS: u64 = 15;

fn client(stealth: Option<&stealth_engine::StealthConfig>) -> reqwest::Client {
    match stealth {
        Some(s) => stealth_engine::build_client(s, TIMEOUT_SECS),
        None => reqwest::Client::builder()
            .timeout(Duration::from_secs(TIMEOUT_SECS))
            .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
            .user_agent("Weissman-Archival/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
    }
}

fn domain_from_target(target: &str) -> String {
    let t = target.trim();
    if let Some(rest) = t.strip_prefix("https://") {
        rest.split('/').next().unwrap_or(rest).to_string()
    } else if let Some(rest) = t.strip_prefix("http://") {
        rest.split('/').next().unwrap_or(rest).to_string()
    } else {
        t.split('/').next().unwrap_or(t).to_string()
    }
}

/// Query Wayback Machine CDX API for historical URLs (path list) for the domain.
pub async fn wayback_paths_for_domain(
    domain: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> Vec<String> {
    let domain = domain_from_target(domain);
    if domain.is_empty() {
        return vec![];
    }
    let c = client(stealth);
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url={}/*&output=json&collapse=urlpath&limit=2000",
        urlencoding::encode(&domain)
    );
    if let Some(s) = stealth {
        stealth_engine::apply_jitter(s);
    }
    let resp = match c.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    if !resp.status().is_success() {
        return vec![];
    }
    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return vec![],
    };
    let rows: Vec<Vec<serde_json::Value>> = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let mut paths = HashSet::new();
    for (i, row) in rows.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if let Some(uri) = row.get(2).and_then(|v| v.as_str()) {
            if let Ok(u) = Url::parse(uri) {
                let path = u.path().to_string();
                if path.len() > 1 && path.len() < 500 {
                    paths.insert(path);
                }
            }
        }
    }
    paths.into_iter().collect()
}

/// AlienVault OTX: pulse URLs and hostname URLs for the domain (passive DNS / historical).
pub async fn otx_urls_for_domain(
    domain: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> Vec<String> {
    let domain = domain_from_target(domain);
    if domain.is_empty() {
        return vec![];
    }
    let c = client(stealth);
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list?limit=100",
        urlencoding::encode(&domain)
    );
    if let Some(s) = stealth {
        stealth_engine::apply_jitter(s);
    }
    let resp = match c.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    if !resp.status().is_success() {
        return vec![];
    }
    let body = match resp.text().await {
        Ok(b) => b,
        Err(_) => return vec![],
    };
    let data: serde_json::Value = match serde_json::from_str(&body) {
        Ok(d) => d,
        Err(_) => return vec![],
    };
    let mut paths = HashSet::new();
    let empty: Vec<serde_json::Value> = vec![];
    let urls = data
        .get("url_list")
        .and_then(|u| u.as_array())
        .unwrap_or(&empty);
    for u in urls {
        if let Some(s) = u.as_str() {
            if let Ok(parsed) = Url::parse(s) {
                if parsed
                    .host_str()
                    .map(|h| h == domain || domain.ends_with(h))
                    .unwrap_or(false)
                {
                    let path = parsed.path().to_string();
                    if path.len() > 1 && path.len() < 500 {
                        paths.insert(path);
                    }
                }
            }
        }
    }
    paths.into_iter().collect()
}

/// Run both archival sources and merge into a single list of paths (no duplicates).
pub async fn run_archival_discovery(
    target: &str,
    stealth: Option<&stealth_engine::StealthConfig>,
) -> Vec<String> {
    let domain = domain_from_target(target);
    if domain.is_empty() {
        return vec![];
    }
    let (wayback, otx) = tokio::join!(
        wayback_paths_for_domain(&domain, stealth),
        otx_urls_for_domain(&domain, stealth),
    );
    let mut set = HashSet::new();
    for p in wayback {
        set.insert(if p.starts_with('/') {
            p
        } else {
            format!("/{}", p)
        });
    }
    for p in otx {
        set.insert(if p.starts_with('/') {
            p
        } else {
            format!("/{}", p)
        });
    }
    set.into_iter().collect()
}
