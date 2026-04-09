//! Rolling HMAC handshake for outbound vLLM calls (`WEISSMAN_LLM_HANDSHAKE_SECRET`).
//! Upstream vLLM should sit behind a reverse-proxy that rejects requests without a valid
//! `X-Weissman-Llm-Handshake` matching the same secret and 30-second epoch slot.
//! Keep proxy and worker clocks within a few seconds (NTP); pairing with [`crate::llm_json_repair`]
//! handles slightly malformed model JSON after the request is accepted.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const SLOT_SECS: u64 = 30;

#[must_use]
pub fn handshake_header_value() -> Option<String> {
    let secret = std::env::var("WEISSMAN_LLM_HANDSHAKE_SECRET").ok()?;
    let s = secret.trim();
    if s.is_empty() {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let slot = now / SLOT_SECS;
    let msg = format!("v1|{slot}");
    let mut mac = HmacSha256::new_from_slice(s.as_bytes()).ok()?;
    mac.update(msg.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    Some(format!("v1;slot={slot};sig={sig}"))
}

#[must_use]
pub fn apply_to_request(mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    if let Some(v) = handshake_header_value() {
        req = req.header("X-Weissman-Llm-Handshake", v);
    }
    req
}

#[must_use]
pub fn apply_to_blocking_request(
    mut req: reqwest::blocking::RequestBuilder,
) -> reqwest::blocking::RequestBuilder {
    if let Some(v) = handshake_header_value() {
        req = req.header("X-Weissman-Llm-Handshake", v);
    }
    req
}
