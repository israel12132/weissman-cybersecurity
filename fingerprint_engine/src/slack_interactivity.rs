//! Slack interactive heal approval: verify Slack's request signature, build Block Kit approval
//! messages, and sign/verify the tamper-evident action values that carry the tenant/client/finding
//! a button acts on. The HTTP endpoint lives in the server handlers; this module is the reusable,
//! unit-tested core.

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::crypto_engine::sha256_hex;

type HmacSha256 = Hmac<Sha256>;

const ACTION_DOMAIN: &str = "weissman-slack-heal-action-v1|";

/// Verify a Slack request signature (`v0=<hex>`) over `v0:{timestamp}:{body}` with the app signing
/// secret. Pure HMAC check — the caller separately enforces timestamp freshness.
#[must_use]
pub fn verify_slack_signature(
    signing_secret: &str,
    timestamp: &str,
    body: &[u8],
    signature: &str,
) -> bool {
    if signing_secret.is_empty() || timestamp.is_empty() {
        return false;
    }
    let sig = signature.trim();
    let sig = sig.strip_prefix("v0=").unwrap_or(sig);
    let Ok(mut mac) = HmacSha256::new_from_slice(signing_secret.as_bytes()) else {
        return false;
    };
    mac.update(b"v0:");
    mac.update(timestamp.as_bytes());
    mac.update(b":");
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    crate::security_hardening::constant_time_hmac_hex_eq(&expected, sig)
}

/// How long a signed Slack approval button stays valid. Bounds replay of a captured button from
/// "forever" to this window. (A strict one-time guarantee would additionally need a server-stored,
/// atomically-consumed nonce — a follow-up requiring persistence.) Env-tunable; default 24h,
/// clamped to a sane range.
fn action_ttl_secs() -> i64 {
    std::env::var("WEISSMAN_SLACK_ACTION_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n >= 60 && *n <= 7 * 24 * 3600)
        .unwrap_or(24 * 3600)
}

/// Digest bound to a specific (tenant, client, finding) heal action AND an expiry, so a captured
/// button cannot be replayed after it expires and the expiry itself is tamper-evident.
fn action_digest(tenant_id: i64, client_id: i64, finding_id: &str, exp: i64) -> String {
    sha256_hex(format!("{ACTION_DOMAIN}{tenant_id}|{client_id}|{finding_id}|{exp}").as_bytes())
}

/// Sign a Slack button value so the callback can trust the (tenant, client, finding) it carries and
/// reject it once expired. Returns `None` when attestation is disabled (no key) — Slack approval
/// requires a signing key.
#[must_use]
pub fn sign_action_value(tenant_id: i64, client_id: i64, finding_id: &str) -> Option<String> {
    let exp = chrono::Utc::now().timestamp() + action_ttl_secs();
    let receipt =
        crate::finding_attestation::attest(&action_digest(tenant_id, client_id, finding_id, exp))?;
    Some(format!("{tenant_id}:{client_id}:{finding_id}:{exp}:{receipt}"))
}

/// Verify + parse a signed Slack button value back into (tenant, client, finding). Rejects malformed,
/// tampered, and expired values.
#[must_use]
pub fn verify_action_value(value: &str) -> Option<(i64, i64, String)> {
    let mut parts = value.splitn(5, ':');
    let tenant_id: i64 = parts.next()?.parse().ok()?;
    let client_id: i64 = parts.next()?.parse().ok()?;
    let finding_id = parts.next()?.to_string();
    let exp: i64 = parts.next()?.parse().ok()?;
    let receipt = parts.next()?;
    if finding_id.is_empty() || receipt.is_empty() {
        return None;
    }
    // Reject expired approvals so a captured button can't be replayed indefinitely.
    if chrono::Utc::now().timestamp() > exp {
        return None;
    }
    if crate::finding_attestation::verify(
        &action_digest(tenant_id, client_id, &finding_id, exp),
        receipt,
    ) {
        Some((tenant_id, client_id, finding_id))
    } else {
        None
    }
}

/// The action a Slack interaction is requesting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackHealAction {
    Approve,
    Dismiss,
    Unknown,
}

impl SlackHealAction {
    #[must_use]
    pub fn from_action_id(action_id: &str) -> Self {
        if action_id.starts_with("heal_approve") {
            SlackHealAction::Approve
        } else if action_id.starts_with("heal_dismiss") {
            SlackHealAction::Dismiss
        } else {
            SlackHealAction::Unknown
        }
    }
}

/// Extract the first action's `(action_id, value)` from a Slack `block_actions` payload.
#[must_use]
pub fn parse_interaction(payload: &Value) -> Option<(String, String)> {
    let action = payload.get("actions")?.as_array()?.first()?;
    let action_id = action.get("action_id")?.as_str()?.to_string();
    let value = action
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some((action_id, value))
}

/// Build a Slack Block Kit message proposing a heal, with Approve / Dismiss buttons and (optionally)
/// a link to the PR. `approve_value` / `dismiss_value` are signed action values.
#[must_use]
pub fn build_heal_approval_blocks(
    finding_id: &str,
    title: &str,
    verdict: &str,
    pr_url: Option<&str>,
    approve_value: &str,
    dismiss_value: &str,
) -> Value {
    let header = format!("🛡️ Weissman Auto-Heal — approval needed");
    let context = format!(
        "*{}*\nFinding `{}` · sandbox verdict: `{}`",
        title, finding_id, verdict
    );
    let mut elements = vec![
        json!({
            "type": "button",
            "style": "primary",
            "text": { "type": "plain_text", "text": "Approve & heal" },
            "action_id": "heal_approve",
            "value": approve_value,
        }),
        json!({
            "type": "button",
            "text": { "type": "plain_text", "text": "Dismiss" },
            "action_id": "heal_dismiss",
            "value": dismiss_value,
        }),
    ];
    if let Some(url) = pr_url.filter(|u| !u.trim().is_empty()) {
        elements.push(json!({
            "type": "button",
            "text": { "type": "plain_text", "text": "View PR" },
            "action_id": "heal_view",
            "url": url,
        }));
    }
    json!({
        "blocks": [
            { "type": "header", "text": { "type": "plain_text", "text": header } },
            { "type": "section", "text": { "type": "mrkdwn", "text": context } },
            { "type": "actions", "elements": elements },
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slack_signature_roundtrip() {
        let secret = "8f742231b10e8888abcd99yyyzzz85a5";
        let ts = "1531420618";
        let body = b"token=xyz&payload=%7B%7D";
        // Compute the expected signature the same way Slack does.
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(b"v0:");
        mac.update(ts.as_bytes());
        mac.update(b":");
        mac.update(body);
        let expected = format!("v0={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_slack_signature(secret, ts, body, &expected));
        // Tampered body / secret / signature must fail.
        assert!(!verify_slack_signature(secret, ts, b"different", &expected));
        assert!(!verify_slack_signature("wrong", ts, body, &expected));
        assert!(!verify_slack_signature(secret, ts, body, "v0=deadbeef"));
        assert!(!verify_slack_signature("", ts, body, &expected));
    }

    #[test]
    fn action_digest_is_deterministic_and_specific() {
        let a = action_digest(1, 2, "F-1", 1000);
        assert_eq!(a, action_digest(1, 2, "F-1", 1000));
        assert_ne!(a, action_digest(1, 2, "F-2", 1000));
        assert_ne!(a, action_digest(9, 2, "F-1", 1000));
        // The expiry is part of the signed digest, so it can't be altered without breaking the sig.
        assert_ne!(a, action_digest(1, 2, "F-1", 2000));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn action_from_id() {
        assert_eq!(
            SlackHealAction::from_action_id("heal_approve"),
            SlackHealAction::Approve
        );
        assert_eq!(
            SlackHealAction::from_action_id("heal_dismiss"),
            SlackHealAction::Dismiss
        );
        assert_eq!(
            SlackHealAction::from_action_id("something_else"),
            SlackHealAction::Unknown
        );
    }

    #[test]
    fn parses_block_actions_payload() {
        let p = json!({
            "type": "block_actions",
            "actions": [ { "action_id": "heal_approve", "value": "1:2:F-1:abc" } ]
        });
        let (aid, val) = parse_interaction(&p).unwrap();
        assert_eq!(aid, "heal_approve");
        assert_eq!(val, "1:2:F-1:abc");
        assert!(parse_interaction(&json!({"actions": []})).is_none());
    }

    #[test]
    fn build_blocks_has_buttons_and_pr() {
        let b =
            build_heal_approval_blocks("F-1", "SQLi", "fixed", Some("https://x/pr/1"), "av", "dv");
        let s = b.to_string();
        assert!(s.contains("heal_approve"));
        assert!(s.contains("heal_dismiss"));
        assert!(s.contains("heal_view"));
        assert!(s.contains("https://x/pr/1"));
        assert!(s.contains("F-1"));
    }

    #[test]
    fn verify_action_value_rejects_malformed() {
        assert!(verify_action_value("not-a-value").is_none());
        assert!(verify_action_value("1:2:F-1:").is_none());
        assert!(verify_action_value("1:2::abc").is_none());
        // An expired value is rejected before signature verification (exp = 100 is far in the past).
        assert!(verify_action_value("1:2:F-1:100:deadbeef").is_none());
    }
}
