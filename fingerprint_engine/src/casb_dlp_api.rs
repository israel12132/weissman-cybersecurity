//! Live CASB / DLP over Microsoft Graph and Google APIs.
//! Missing tokens produce info findings — never synthetic grants or leaked mail.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::finding;
use crate::soar::integrations::config_str;
use serde_json::Value;

pub struct CasbTokens {
    pub graph: Option<String>,
    pub google: Option<String>,
}

pub async fn load_tokens(ctx: &EngineRunContext) -> CasbTokens {
    let mut graph = std::env::var("WEISSMAN_GRAPH_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let mut google = std::env::var("WEISSMAN_GOOGLE_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let (Some(pool), Some(tenant_id)) = (ctx.app_pool.as_ref(), ctx.tenant_id) {
        let cfg = crate::itdr_connectors::load_connector_config(pool.as_ref(), tenant_id).await;
        if graph.is_none() {
            graph = token_from_cfg(&cfg, &["entra", "azuread", "microsoft", "graph"]);
        }
        if google.is_none() {
            google = token_from_cfg(&cfg, &["google", "workspace"]);
        }
    }
    CasbTokens { graph, google }
}

fn token_from_cfg(cfg: &Value, providers: &[&str]) -> Option<String> {
    for p in providers {
        if let Some(slice) = cfg.get(*p) {
            if let Some(t) = config_str(slice, &["access_token", "token", "graph_token"]) {
                return Some(t);
            }
        }
        if let Some(nested) = cfg.get("connectors").and_then(|c| c.get(*p)) {
            if let Some(t) = config_str(nested, &["access_token", "token", "graph_token"]) {
                return Some(t);
            }
        }
    }
    config_str(cfg, &["access_token", "graph_token", "token"])
}

pub async fn graph_casb_findings(target: &str, token: &str) -> Vec<Value> {
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let grants = client
        .get("https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=50")
        .bearer_auth(token)
        .send()
        .await;
    match grants {
        Ok(r) if r.status().is_success() => {
            if let Ok(body) = r.json::<Value>().await {
                let n = body
                    .get("value")
                    .and_then(Value::as_array)
                    .map(|a| a.len())
                    .unwrap_or(0);
                let high_priv = body
                    .get("value")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter(|g| {
                                let scope = g.get("scope").and_then(Value::as_str).unwrap_or("");
                                scope.contains("Mail.Read")
                                    || scope.contains("Files.ReadWrite.All")
                                    || scope.contains("Directory.ReadWrite")
                            })
                            .count()
                    })
                    .unwrap_or(0);
                out.push(finding(
                    "casb_saas_posture",
                    &format!("Entra OAuth grants inventoried ({n})"),
                    if high_priv > 0 { "high" } else { "info" },
                    "T1528",
                    &format!(
                        "Graph oauth2PermissionGrants returned {n} grants; {high_priv} include Mail.Read / Files.ReadWrite.All / Directory.ReadWrite."
                    ),
                    target,
                ));
            }
        }
        Ok(r) => {
            out.push(finding(
                "casb_saas_posture",
                "Microsoft Graph OAuth-grant query failed",
                "medium",
                "T1528",
                &format!("GET oauth2PermissionGrants HTTP {}", r.status()),
                target,
            ));
        }
        Err(e) => {
            out.push(finding(
                "casb_saas_posture",
                "Microsoft Graph unreachable",
                "medium",
                "T1528",
                &format!("{e}"),
                target,
            ));
        }
    }

    let sps = client
        .get("https://graph.microsoft.com/v1.0/servicePrincipals?$top=25&$select=displayName,appId,homepage")
        .bearer_auth(token)
        .send()
        .await;
    if let Ok(r) = sps {
        if r.status().is_success() {
            if let Ok(body) = r.json::<Value>().await {
                let names: Vec<String> = body
                    .get("value")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.get("displayName").and_then(Value::as_str))
                            .map(|s| s.to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                if !names.is_empty() {
                    out.push(finding(
                        "casb_saas_posture",
                        "Entra service principals discovered (shadow-SaaS inventory)",
                        "info",
                        "T1078",
                        &format!("Graph servicePrincipals: {}", names.join(", ")),
                        target,
                    ));
                }
            }
        }
    }
    out
}

pub async fn graph_dlp_findings(target: &str, token: &str) -> Vec<Value> {
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let resp = client
        .get("https://graph.microsoft.com/v1.0/me/messages?$top=8&$select=subject,bodyPreview,hasAttachments")
        .bearer_auth(token)
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => {
            if let Ok(body) = r.json::<Value>().await {
                let msgs = body.get("value").and_then(Value::as_array).cloned().unwrap_or_default();
                let hay: String = msgs
                    .iter()
                    .filter_map(|m| m.get("bodyPreview").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("\n");
                let hits = dlp_hits(&hay);
                if hits.is_empty() {
                    out.push(finding(
                        "dlp_content_scan",
                        &format!("Graph mailbox sample scanned ({} messages, no DLP pattern)", msgs.len()),
                        "info",
                        "T1114",
                        "GET /me/messages bodyPreview did not match PAN/SSN/secret regexes.",
                        target,
                    ));
                } else {
                    for h in hits {
                        out.push(finding(
                            "dlp_content_scan",
                            &format!("DLP pattern in Graph mail preview: {h}"),
                            "high",
                            "T1530",
                            "Live Microsoft Graph message preview matched a sensitive-data pattern.",
                            target,
                        ));
                    }
                }
            }
        }
        Ok(r) => {
            out.push(finding(
                "dlp_content_scan",
                "Graph mail DLP query failed (token may lack Mail.Read)",
                "info",
                "T1114",
                &format!("GET /me/messages HTTP {}", r.status()),
                target,
            ));
        }
        Err(e) => {
            out.push(finding(
                "dlp_content_scan",
                "Graph mail DLP unreachable",
                "medium",
                "T1114",
                &format!("{e}"),
                target,
            ));
        }
    }
    out
}

pub async fn google_casb_findings(target: &str, token: &str) -> Vec<Value> {
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let resp = client
        .get("https://www.googleapis.com/oauth2/v3/tokeninfo")
        .query(&[("access_token", token)])
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => {
            if let Ok(body) = r.json::<Value>().await {
                let scope = body.get("scope").and_then(Value::as_str).unwrap_or("");
                let aud = body.get("aud").and_then(Value::as_str).unwrap_or("");
                out.push(finding(
                    "casb_saas_posture",
                    "Google OAuth token scopes inventoried",
                    if scope.contains("gmail") || scope.contains("drive") {
                        "medium"
                    } else {
                        "info"
                    },
                    "T1528",
                    &format!("tokeninfo aud={aud} scope={scope}"),
                    target,
                ));
            }
        }
        Ok(r) => {
            out.push(finding(
                "casb_saas_posture",
                "Google tokeninfo failed",
                "medium",
                "T1528",
                &format!("HTTP {}", r.status()),
                target,
            ));
        }
        Err(e) => {
            out.push(finding(
                "casb_saas_posture",
                "Google tokeninfo unreachable",
                "medium",
                "T1528",
                &format!("{e}"),
                target,
            ));
        }
    }
    out
}

pub async fn google_dlp_findings(target: &str, token: &str) -> Vec<Value> {
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let list = client
        .get("https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=5")
        .bearer_auth(token)
        .send()
        .await;
    match list {
        Ok(r) if r.status().is_success() => {
            if let Ok(body) = r.json::<Value>().await {
                let ids: Vec<String> = body
                    .get("messages")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|m| m.get("id").and_then(Value::as_str).map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let mut hay = String::new();
                for id in ids.iter().take(5) {
                    if let Ok(msg) = client
                        .get(format!(
                            "https://gmail.googleapis.com/gmail/v1/users/me/messages/{id}?format=metadata&metadataHeaders=Subject"
                        ))
                        .bearer_auth(token)
                        .send()
                        .await
                    {
                        if let Ok(j) = msg.json::<Value>().await {
                            if let Some(snip) = j.get("snippet").and_then(Value::as_str) {
                                hay.push_str(snip);
                                hay.push('\n');
                            }
                        }
                    }
                }
                let hits = dlp_hits(&hay);
                if hits.is_empty() {
                    out.push(finding(
                        "dlp_content_scan",
                        &format!("Gmail snippets scanned ({} messages, no DLP pattern)", ids.len()),
                        "info",
                        "T1114",
                        "Gmail API snippets did not match PAN/SSN/secret regexes.",
                        target,
                    ));
                } else {
                    for h in hits {
                        out.push(finding(
                            "dlp_content_scan",
                            &format!("DLP pattern in Gmail snippet: {h}"),
                            "high",
                            "T1530",
                            "Live Gmail API snippet matched a sensitive-data pattern.",
                            target,
                        ));
                    }
                }
            }
        }
        Ok(r) => {
            out.push(finding(
                "dlp_content_scan",
                "Gmail DLP query failed (token may lack gmail.readonly)",
                "info",
                "T1114",
                &format!("HTTP {}", r.status()),
                target,
            ));
        }
        Err(e) => {
            out.push(finding(
                "dlp_content_scan",
                "Gmail API unreachable",
                "medium",
                "T1114",
                &format!("{e}"),
                target,
            ));
        }
    }
    out
}

fn dlp_hits(hay: &str) -> Vec<&'static str> {
    let mut hits = Vec::new();
    if regex::Regex::new(r"\b(?:\d[ -]*?){13,19}\b")
        .ok()
        .map(|re| re.is_match(hay))
        .unwrap_or(false)
    {
        hits.push("payment-card");
    }
    if regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")
        .ok()
        .map(|re| re.is_match(hay))
        .unwrap_or(false)
    {
        hits.push("ssn");
    }
    if regex::Regex::new(r"(?i)(api[_-]?key|secret|bearer [a-z0-9\-_\.]{20,})")
        .ok()
        .map(|re| re.is_match(hay))
        .unwrap_or(false)
    {
        hits.push("secret");
    }
    hits
}
