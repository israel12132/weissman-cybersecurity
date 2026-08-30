//! Playbook action-DSL allow-list + SSRF-safe URL checks at save time.
//!
//! Execution still runs [`crate::security_hardening::validate_outbound_url`] (DNS +
//! private-IP). This module is the first gate: a playbook that posts to
//! `http://169.254.169.254/` cannot be persisted.

use serde_json::{json, Value};
use std::net::IpAddr;
use url::Url;

/// Action kinds the builder and API will persist. Unknown kinds are rejected.
pub const ALLOWED_ACTION_KINDS: &[&str] = &[
    "set_status",
    "slack_notify",
    "webhook",
    "open_pr",
    "isolate_host",
    "page_oncall",
    "http_post",
    "create_incident",
];

const URL_ACTIONS: &[&str] = &["webhook", "http_post", "slack_notify"];

const BLOCKED_HOSTS: &[&str] = &[
    "metadata",
    "metadata.google.internal",
    "169.254.169.254",
    "169.254.169.253",
    "fd00:ec2::254",
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
];

/// Validate and return a cleaned actions JSON array. Rejects unknown kinds and
/// webhook URLs that resolve (as a literal host) to a private / link-local / metadata address.
pub fn sanitize_actions_dsl(actions: &Value) -> Result<Value, String> {
    let arr = actions
        .as_array()
        .ok_or_else(|| "actions must be a JSON array".to_string())?;
    if arr.len() > 32 {
        return Err("playbook may have at most 32 actions".into());
    }
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let kind = item
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if kind.is_empty() {
            return Err(format!("action[{i}]: kind required"));
        }
        if !ALLOWED_ACTION_KINDS.contains(&kind.as_str()) {
            return Err(format!(
                "action[{i}]: kind '{kind}' is not in the allow-list"
            ));
        }
        let mut params = item.get("params").cloned().unwrap_or_else(|| json!({}));
        if URL_ACTIONS.contains(&kind.as_str()) {
            if let Some(url) = first_url(&params) {
                validate_webhook_url_static(url)?;
            }
        }
        if let Some(obj) = params.as_object_mut() {
            if let Some(secret) = obj.get("secret").cloned() {
                if let Some(s) = secret.as_str() {
                    if s.len() > 512 {
                        return Err(format!("action[{i}]: secret too long"));
                    }
                }
            }
        }
        out.push(json!({
            "kind": kind,
            "params": params,
        }));
    }
    Ok(Value::Array(out))
}

fn first_url(params: &Value) -> Option<&str> {
    params
        .get("url")
        .or_else(|| params.get("webhook_url"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Synchronous host/scheme check (no DNS). Blocks literal private IPs and metadata hosts.
pub fn validate_webhook_url_static(raw: &str) -> Result<(), String> {
    let u = raw.trim();
    if u.is_empty() || u.len() > 2048 {
        return Err("invalid webhook url length".into());
    }
    let parsed = Url::parse(u).map_err(|_| "invalid webhook URL".to_string())?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("only http and https webhook URLs are allowed".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "missing webhook host".to_string())?
        .to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    if BLOCKED_HOSTS.iter().any(|h| *h == host)
        || host.ends_with(".internal")
        || host.ends_with(".localhost")
    {
        return Err(format!("webhook host '{host}' is blocked"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(format!(
                "webhook host '{host}' is a private/reserved address"
            ));
        }
    }
    Ok(())
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_documentation()
                || v.octets()[0] == 0
                || (v.octets()[0] == 169 && v.octets()[1] == 254)
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.is_unique_local()
                || v.is_unicast_link_local()
                || v.segments()[0] == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_kind() {
        let err = sanitize_actions_dsl(&json!([{"kind": "rm_rf", "params": {}}])).unwrap_err();
        assert!(err.contains("allow-list"));
    }

    #[test]
    fn rejects_metadata_literal() {
        let err = sanitize_actions_dsl(&json!([{
            "kind": "webhook",
            "params": {"url": "http://169.254.169.254/latest/meta-data/"}
        }]))
        .unwrap_err();
        assert!(err.contains("private") || err.contains("blocked"));
    }

    #[test]
    fn rejects_localhost() {
        assert!(validate_webhook_url_static("http://localhost/hook").is_err());
        assert!(validate_webhook_url_static("http://127.0.0.1/hook").is_err());
    }

    #[test]
    fn allows_public_https() {
        assert!(validate_webhook_url_static("https://hooks.slack.com/services/T/B/X").is_ok());
        let cleaned = sanitize_actions_dsl(&json!([{
            "kind": "webhook",
            "params": {"url": "https://hooks.slack.com/services/T/B/X", "template": "{{title}}"}
        }]))
        .unwrap();
        assert_eq!(cleaned[0]["kind"], "webhook");
    }

    #[test]
    fn set_status_needs_no_url() {
        let cleaned = sanitize_actions_dsl(&json!([{
            "kind": "set_status",
            "params": {"status": "IN_PROGRESS"}
        }]))
        .unwrap();
        assert_eq!(cleaned.as_array().unwrap().len(), 1);
    }
}
