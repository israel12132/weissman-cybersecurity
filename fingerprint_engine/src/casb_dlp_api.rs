//! Live CASB / DLP over Microsoft Graph and Google APIs.
//! Missing tokens produce info findings — never synthetic grants or leaked mail.

use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::finding;
use crate::soar::integrations::config_str;
use serde_json::Value;

fn graph_value_array(body: &Value) -> Option<&Vec<Value>> {
    body.get("value").and_then(Value::as_array)
}

/// Gmail omits `messages` for a confirmed empty mailbox. A present non-array is unreadable.
fn gmail_message_ids(body: &Value) -> Option<Vec<String>> {
    match body.get("messages") {
        None => Some(Vec::new()),
        Some(v) => v.as_array().map(|a| {
            a.iter()
                .filter_map(|m| m.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        }),
    }
}

#[derive(Debug, Clone, Default)]
pub struct CasbTokens {
    pub graph: Option<String>,
    pub google: Option<String>,
    /// True when ITDR connector config could not be read. Missing tokens are
    /// then unconfirmed — never advertise "no connectors configured".
    pub connector_store_unavailable: bool,
}

impl CasbTokens {
    /// Store-down must never look like a confirmed missing-token posture.
    pub fn store_unavailable_finding(&self, engine_id: &str, target: &str) -> Option<Value> {
        if !self.connector_store_unavailable {
            return None;
        }
        Some(finding(
            engine_id,
            if engine_id.contains("dlp") {
                "DLP connector store unavailable — token inventory not confirmed"
            } else {
                "CASB connector store unavailable — token inventory not confirmed"
            },
            "medium",
            "T1078",
            "ITDR connector config could not be read. Missing Graph/Google tokens are not confirmed. Set WEISSMAN_GRAPH_TOKEN / WEISSMAN_GOOGLE_TOKEN or restore the store. Not faked.",
            target,
        ))
    }

    /// Confirmed tokenless (store readable, env + connectors empty).
    pub fn confirmed_tokenless_finding(&self, engine_id: &str, target: &str) -> Option<Value> {
        if self.connector_store_unavailable || self.graph.is_some() || self.google.is_some() {
            return None;
        }
        Some(finding(
            engine_id,
            if engine_id.contains("dlp") {
                "No Graph/Google DLP token — mailbox DLP did not run"
            } else {
                "No Graph/Google CASB token — HTTP SaaS discovery only"
            },
            "info",
            "T1078",
            "Set WEISSMAN_GRAPH_TOKEN / WEISSMAN_GOOGLE_TOKEN or persist IdP tokens via PUT /api/itdr/connectors. Not faked.",
            target,
        ))
    }
}

/// Merge ITDR connector config into env-sourced tokens. A store error sets
/// `connector_store_unavailable` instead of pretending the tenant has no connectors.
pub(crate) fn apply_connector_config(tokens: &mut CasbTokens, cfg: Result<Value, String>) {
    match cfg {
        Ok(cfg) => {
            if tokens.graph.is_none() {
                tokens.graph = token_from_cfg(&cfg, &["entra", "azuread", "microsoft", "graph"]);
            }
            if tokens.google.is_none() {
                tokens.google = token_from_cfg(&cfg, &["google", "workspace"]);
            }
        }
        Err(_) => tokens.connector_store_unavailable = true,
    }
}

pub async fn load_tokens(ctx: &EngineRunContext) -> CasbTokens {
    let mut tokens = CasbTokens {
        graph: std::env::var("WEISSMAN_GRAPH_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        google: std::env::var("WEISSMAN_GOOGLE_TOKEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        connector_store_unavailable: false,
    };
    if let (Some(pool), Some(tenant_id)) = (ctx.app_pool.as_ref(), ctx.tenant_id) {
        apply_connector_config(
            &mut tokens,
            crate::itdr_connectors::load_connector_config(pool.as_ref(), tenant_id).await,
        );
    } else {
        // No pool/tenant means the connector inventory was never consulted.
        tokens.connector_store_unavailable = true;
    }
    tokens
}

fn casb_http_client(engine_id: &str, target: &str) -> Result<reqwest::Client, Value> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| {
            finding(
                engine_id,
                "CASB/DLP HTTP client could not be built",
                "medium",
                "T1078",
                &format!("{e}"),
                target,
            )
        })
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
    let client = match casb_http_client("casb_saas_posture", target) {
        Ok(c) => c,
        Err(f) => return vec![f],
    };
    let mut out = Vec::new();
    let grants = client
        .get("https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=50")
        .bearer_auth(token)
        .send()
        .await;
    match grants {
        Ok(r) if r.status().is_success() => match r.json::<Value>().await {
            Ok(body) => match graph_value_array(&body) {
                Some(arr) => {
                    let n = arr.len();
                    let high_priv = arr
                        .iter()
                        .filter(|g| {
                            let scope = g.get("scope").and_then(Value::as_str).unwrap_or("");
                            scope.contains("Mail.Read")
                                || scope.contains("Files.ReadWrite.All")
                                || scope.contains("Directory.ReadWrite")
                        })
                        .count();
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
                None => {
                    out.push(finding(
                        "casb_saas_posture",
                        "Microsoft Graph OAuth-grant body unreadable",
                        "medium",
                        "T1528",
                        "GET oauth2PermissionGrants returned HTTP 200 but `value` was missing or not an array. Inventory is not a clean empty grant list.",
                        target,
                    ));
                }
            },
            Err(_) => {
                out.push(finding(
                    "casb_saas_posture",
                    "Microsoft Graph OAuth-grant body unreadable",
                    "medium",
                    "T1528",
                    "GET oauth2PermissionGrants returned HTTP 200 but JSON could not be parsed. Inventory is not a clean empty grant list.",
                    target,
                ));
            }
        },
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
    match sps {
        Ok(r) if r.status().is_success() => match r.json::<Value>().await {
            Ok(body) => match graph_value_array(&body) {
                Some(arr) => {
                    let names: Vec<String> = arr
                        .iter()
                        .filter_map(|x| x.get("displayName").and_then(Value::as_str))
                        .map(|s| s.to_string())
                        .collect();
                    let evidence = if names.is_empty() {
                        "Graph servicePrincipals returned an empty value array.".to_string()
                    } else {
                        format!("Graph servicePrincipals: {}", names.join(", "))
                    };
                    out.push(finding(
                        "casb_saas_posture",
                        &format!("Entra service principals inventoried ({})", names.len()),
                        "info",
                        "T1078",
                        &evidence,
                        target,
                    ));
                }
                None => {
                    out.push(finding(
                        "casb_saas_posture",
                        "Microsoft Graph service-principal body unreadable",
                        "medium",
                        "T1078",
                        "GET servicePrincipals returned HTTP 200 but `value` was missing or not an array. Inventory is not a clean empty SP list.",
                        target,
                    ));
                }
            },
            Err(_) => {
                out.push(finding(
                    "casb_saas_posture",
                    "Microsoft Graph service-principal body unreadable",
                    "medium",
                    "T1078",
                    "GET servicePrincipals returned HTTP 200 but JSON could not be parsed. Inventory is not a clean empty SP list.",
                    target,
                ));
            }
        },
        Ok(r) => {
            out.push(finding(
                "casb_saas_posture",
                "Microsoft Graph service-principal query failed",
                "medium",
                "T1078",
                &format!("GET servicePrincipals HTTP {}", r.status()),
                target,
            ));
        }
        Err(e) => {
            out.push(finding(
                "casb_saas_posture",
                "Microsoft Graph service principals unreachable",
                "medium",
                "T1078",
                &format!("{e}"),
                target,
            ));
        }
    }
    out
}

pub async fn graph_dlp_findings(target: &str, token: &str) -> Vec<Value> {
    let client = match casb_http_client("dlp_content_scan", target) {
        Ok(c) => c,
        Err(f) => return vec![f],
    };
    let mut out = Vec::new();
    let resp = client
        .get("https://graph.microsoft.com/v1.0/me/messages?$top=8&$select=subject,bodyPreview,hasAttachments")
        .bearer_auth(token)
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => match r.json::<Value>().await {
            Ok(body) => match graph_value_array(&body) {
                Some(msgs) => {
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
                None => {
                    out.push(finding(
                        "dlp_content_scan",
                        "Graph mail DLP body unreadable",
                        "medium",
                        "T1114",
                        "GET /me/messages returned HTTP 200 but `value` was missing or not an array. Mailbox DLP is not a clean empty scan.",
                        target,
                    ));
                }
            },
            Err(_) => {
                out.push(finding(
                    "dlp_content_scan",
                    "Graph mail DLP body unreadable",
                    "medium",
                    "T1114",
                    "GET /me/messages returned HTTP 200 but JSON could not be parsed. Mailbox DLP is not a clean empty scan.",
                    target,
                ));
            }
        },
        Ok(r) => {
            out.push(finding(
                "dlp_content_scan",
                "Graph mail DLP query failed (token may lack Mail.Read)",
                "medium",
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

fn google_tokeninfo_scope_finding(target: &str, body: &Value) -> Value {
    let Some(scope_val) = body.get("scope") else {
        return finding(
            "casb_saas_posture",
            "Google tokeninfo scope missing",
            "medium",
            "T1528",
            "tokeninfo JSON omitted scope; scopes are not confirmed empty.",
            target,
        );
    };
    let Some(scope) = scope_val.as_str() else {
        return finding(
            "casb_saas_posture",
            "Google tokeninfo scope unreadable",
            "medium",
            "T1528",
            "tokeninfo scope was present but not a string. Scopes are not confirmed empty.",
            target,
        );
    };
    let aud = body.get("aud").and_then(Value::as_str).unwrap_or("");
    finding(
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
    )
}

pub async fn google_casb_findings(target: &str, token: &str) -> Vec<Value> {
    let client = match casb_http_client("casb_saas_posture", target) {
        Ok(c) => c,
        Err(f) => return vec![f],
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
                out.push(google_tokeninfo_scope_finding(target, &body));
            } else {
                out.push(finding(
                    "casb_saas_posture",
                    "Google tokeninfo body unreadable",
                    "medium",
                    "T1528",
                    "tokeninfo returned HTTP 200 but JSON could not be parsed. Scopes are not confirmed empty.",
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
    let client = match casb_http_client("dlp_content_scan", target) {
        Ok(c) => c,
        Err(f) => return vec![f],
    };
    let mut out = Vec::new();
    let list = client
        .get("https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=5")
        .bearer_auth(token)
        .send()
        .await;
    match list {
        Ok(r) if r.status().is_success() => {
            match r.json::<Value>().await {
                Ok(body) => match gmail_message_ids(&body) {
                    Some(ids) => {
                    let mut hay = String::new();
                    let mut scanned = 0usize;
                    let mut unread = 0usize;
                    for id in ids.iter().take(5) {
                        match client
                            .get(format!(
                                "https://gmail.googleapis.com/gmail/v1/users/me/messages/{id}?format=metadata&metadataHeaders=Subject"
                            ))
                            .bearer_auth(token)
                            .send()
                            .await
                        {
                            Ok(msg) if msg.status().is_success() => {
                                match msg.json::<Value>().await {
                                    Ok(j) => {
                                        match j.get("snippet").and_then(Value::as_str) {
                                            Some(snip) => {
                                                scanned += 1;
                                                hay.push_str(snip);
                                                hay.push('\n');
                                            }
                                            None => {
                                                unread += 1;
                                                out.push(finding(
                                                    "dlp_content_scan",
                                                    "Gmail DLP message had no snippet",
                                                    "medium",
                                                    "T1114",
                                                    &format!("GET messages/{id} returned HTTP 200 without a snippet. Content is not confirmed empty."),
                                                    target,
                                                ));
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        unread += 1;
                                        out.push(finding(
                                            "dlp_content_scan",
                                            "Gmail DLP message body unreadable",
                                            "medium",
                                            "T1114",
                                            &format!("GET messages/{id} returned HTTP 200 but JSON could not be parsed. Snippet is not confirmed empty."),
                                            target,
                                        ));
                                    }
                                }
                            }
                            Ok(msg) => {
                                unread += 1;
                                out.push(finding(
                                    "dlp_content_scan",
                                    "Gmail DLP message query failed",
                                    "medium",
                                    "T1114",
                                    &format!("GET messages/{id} HTTP {}", msg.status()),
                                    target,
                                ));
                            }
                            Err(e) => {
                                unread += 1;
                                out.push(finding(
                                    "dlp_content_scan",
                                    "Gmail DLP message unreachable",
                                    "medium",
                                    "T1114",
                                    &format!("GET messages/{id}: {e}"),
                                    target,
                                ));
                            }
                        }
                    }
                    let hits = dlp_hits(&hay);
                    if unread == 0 && hits.is_empty() {
                        out.push(finding(
                            "dlp_content_scan",
                            &format!("Gmail snippets scanned ({scanned} messages, no DLP pattern)"),
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
                    None => {
                        out.push(finding(
                            "dlp_content_scan",
                            "Gmail DLP list messages field unreadable",
                            "medium",
                            "T1114",
                            "GET users/me/messages returned HTTP 200 but `messages` was not an array. Mailbox DLP is not a clean empty scan.",
                            target,
                        ));
                    }
                }
                Err(_) => {
                    out.push(finding(
                        "dlp_content_scan",
                        "Gmail DLP list body unreadable",
                        "medium",
                        "T1114",
                        "GET users/me/messages returned HTTP 200 but JSON could not be parsed. Mailbox DLP is not a clean empty scan.",
                        target,
                    ));
                }
            }
        }
        Ok(r) => {
            out.push(finding(
                "dlp_content_scan",
                "Gmail DLP query failed (token may lack gmail.readonly)",
                "medium",
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn store_down_is_never_confirmed_tokenless() {
        let mut tokens = CasbTokens::default();
        apply_connector_config(&mut tokens, Err("database unavailable".into()));
        assert!(tokens.connector_store_unavailable);
        let f = tokens
            .store_unavailable_finding("casb_saas_posture", "example.com")
            .expect("store-down must emit a finding");
        assert_eq!(f["severity"], "medium");
        assert!(f["title"].as_str().unwrap().contains("unavailable"));
        assert!(tokens
            .confirmed_tokenless_finding("casb_saas_posture", "example.com")
            .is_none());
    }

    #[test]
    fn readable_empty_connectors_are_confirmed_tokenless() {
        let mut tokens = CasbTokens::default();
        apply_connector_config(&mut tokens, Ok(json!({})));
        assert!(!tokens.connector_store_unavailable);
        let f = tokens
            .confirmed_tokenless_finding("casb_saas_posture", "example.com")
            .expect("empty connectors are a confirmed gap");
        assert_eq!(f["severity"], "info");
        assert!(f["title"].as_str().unwrap().contains("CASB"));
        assert!(tokens
            .store_unavailable_finding("casb_saas_posture", "example.com")
            .is_none());
        let dlp = tokens
            .confirmed_tokenless_finding("dlp_content_scan", "example.com")
            .expect("DLP tokenless must name DLP, not CASB");
        assert!(dlp["title"].as_str().unwrap().contains("DLP"));
        assert!(!dlp["title"].as_str().unwrap().contains("CASB"));
    }

    #[test]
    fn env_token_survives_store_down_and_skips_tokenless_info() {
        let mut tokens = CasbTokens {
            graph: Some("env-graph".into()),
            google: None,
            connector_store_unavailable: false,
        };
        apply_connector_config(&mut tokens, Err("database unavailable".into()));
        assert_eq!(tokens.graph.as_deref(), Some("env-graph"));
        assert!(tokens.connector_store_unavailable);
        assert!(tokens
            .confirmed_tokenless_finding("casb_saas_posture", "example.com")
            .is_none());
        assert!(tokens
            .store_unavailable_finding("casb_saas_posture", "example.com")
            .is_some());
    }

    #[test]
    fn connector_config_fills_missing_env_tokens() {
        let mut tokens = CasbTokens::default();
        apply_connector_config(
            &mut tokens,
            Ok(json!({
                "entra": { "access_token": "graph-from-cfg" },
                "google": { "token": "google-from-cfg" }
            })),
        );
        assert_eq!(tokens.graph.as_deref(), Some("graph-from-cfg"));
        assert_eq!(tokens.google.as_deref(), Some("google-from-cfg"));
    }

    #[tokio::test]
    async fn missing_pool_is_store_down_not_tokenless() {
        let ctx = crate::engine_dispatch::EngineRunContext::default();
        let tokens = load_tokens(&ctx).await;
        assert!(tokens.connector_store_unavailable);
        assert!(tokens
            .confirmed_tokenless_finding("casb_saas_posture", "example.com")
            .is_none());
        let f = tokens
            .store_unavailable_finding("casb_saas_posture", "example.com")
            .expect("unconsulted store must not look tokenless");
        assert_eq!(f["severity"], "medium");
    }

    #[test]
    fn dlp_store_down_title_is_not_casb() {
        let mut tokens = CasbTokens::default();
        apply_connector_config(&mut tokens, Err("database unavailable".into()));
        let f = tokens
            .store_unavailable_finding("dlp_content_scan", "example.com")
            .expect("store-down");
        assert!(f["title"].as_str().unwrap().contains("DLP"));
        assert!(!f["title"].as_str().unwrap().contains("CASB"));
    }

    #[test]
    fn google_missing_scope_is_not_inventoried_empty() {
        let f = google_tokeninfo_scope_finding("example.com", &json!({"aud": "app"}));
        assert_eq!(f["severity"], "medium");
        assert!(f["title"].as_str().unwrap().contains("scope missing"));
        assert!(!f["title"].as_str().unwrap().contains("inventoried"));
        let empty_ok = google_tokeninfo_scope_finding("example.com", &json!({"scope": ""}));
        assert!(empty_ok["title"].as_str().unwrap().contains("inventoried"));
    }

    #[test]
    fn gmail_dlp_unreadable_bodies_are_medium_not_empty_ok() {
        let src = include_str!("casb_dlp_api.rs");
        assert!(src.contains("Gmail DLP list body unreadable"));
        assert!(src.contains("Gmail DLP message body unreadable"));
        assert!(src.contains("Gmail DLP message had no snippet"));
        assert!(src.contains("Gmail DLP list messages field unreadable"));
        assert!(src.contains("unread == 0 && hits.is_empty()"));
    }

    #[test]
    fn graph_missing_value_is_not_clean_empty_inventory() {
        let src = include_str!("casb_dlp_api.rs");
        assert!(src.contains("`value` was missing or not an array"));
        assert!(src.contains("Microsoft Graph service-principal body unreadable"));
        assert!(src.contains("fn graph_value_array"));
    }
}
