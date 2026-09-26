//! Outbound ITSM ticket creation — open a ServiceNow incident or a Jira issue from a finding.
//!
//! The connector credential is stored AES-256-GCM-encrypted at rest (crate::ceo::vault,
//! wzv1: prefix) and is only decrypted in-process immediately before the outbound call; it
//! is never logged and never returned to an API client. Every outbound base_url is
//! (re)validated with crate::security_hardening::validate_outbound_url — SSRF: cloud
//! metadata / internal hosts and private/reserved addresses are rejected unless the operator
//! sets WEISSMAN_ALLOW_PRIVATE_WEBHOOKS=1 for on-prem instances.

pub mod jira;
pub mod servicenow;

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::lookup_host;
use url::Url;

/// Connector kinds — kept in lock-step with the DB CHECK constraint (servicenow, jira).
pub const KIND_SERVICENOW: &str = "servicenow";
pub const KIND_JIRA: &str = "jira";

const ITSM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ITSM_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum ItsmError {
    #[error("connector configuration invalid: {0}")]
    Config(String),
    #[error("outbound target blocked: {0}")]
    Ssrf(String),
    #[error("failed to build HTTP client: {0}")]
    ClientBuild(String),
    #[error("request to ITSM endpoint failed: {0}")]
    Request(String),
    #[error("ITSM endpoint returned HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("could not parse ITSM response: {0}")]
    Decode(String),
}

/// Auth scheme for a connector. Serialized into the encrypted credential blob and back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthScheme {
    /// HTTP Basic (username + secret): ServiceNow, or Jira Cloud (email + API token).
    Basic,
    /// Bearer token (Jira personal-access / OAuth token).
    Bearer,
}

/// Decrypted credential material — deserialized from the wzv1:-decrypted `auth_ref` blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItsmCredential {
    pub scheme: AuthScheme,
    #[serde(default)]
    pub username: String,
    pub secret: String,
}

/// A ready-to-use connector: config plus the already-decrypted credential.
#[derive(Debug, Clone)]
pub struct ItsmConnector {
    pub id: i64,
    pub kind: String,
    pub base_url: String,
    pub project_or_table: String,
    pub default_fields: serde_json::Value,
    pub credential: ItsmCredential,
}

/// The immutable finding facts a ticket is opened from.
#[derive(Debug, Clone)]
pub struct FindingTicketInput {
    /// Human-facing finding id (vulnerabilities.finding_id TEXT).
    pub finding_ref: String,
    /// Short title (vulnerabilities.title).
    pub summary: String,
    pub severity: String,
    /// Description / proof excerpt (already length-bounded by the caller).
    pub details: String,
}

/// External ticket identifiers returned by the vendor.
#[derive(Debug, Clone, Default)]
pub struct CreatedTicket {
    pub external_id: String,
    pub external_key: String,
    pub external_url: String,
}

/// Hardened reqwest client for outbound ITSM calls, PINNED to a pre-vetted set of addresses.
///
/// MAJOR-2 fix (DNS-rebinding SSRF): `validate_outbound_url` resolves + vets the host, but a
/// bare reqwest client would resolve DNS AGAIN at connect time — a TTL-0 record the tenant
/// admin controls could return a public IP during validation and 169.254.169.254 (or an
/// in-cluster address) at connect time. `resolve_to_addrs` pins the connection to exactly the
/// addresses we already vetted, so no second resolution can occur. Strict TLS, no redirects
/// (a 30x could bounce a validated host to an internal one), bounded connect/total timeouts.
pub(crate) fn itsm_client_pinned(
    host: &str,
    addrs: &[SocketAddr],
) -> Result<reqwest::Client, ItsmError> {
    reqwest::Client::builder()
        .connect_timeout(ITSM_CONNECT_TIMEOUT)
        .timeout(ITSM_TOTAL_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("WeissmanEnterprise/", env!("CARGO_PKG_VERSION")))
        .resolve_to_addrs(host, addrs)
        .build()
        .map_err(|e| ItsmError::ClientBuild(e.to_string()))
}

/// Resolve the connector base_url host and return the vetted `SocketAddr`s to pin. Rejects if
/// ANY resolved address is private/reserved (so a host with mixed public+private A-records
/// cannot be used to smuggle an internal target past the public-looking record), unless the
/// operator has set WEISSMAN_ALLOW_PRIVATE_WEBHOOKS=1 for an on-prem deployment.
pub(crate) async fn vetted_addrs(base_url: &str) -> Result<(String, Vec<SocketAddr>), ItsmError> {
    let parsed =
        Url::parse(base_url.trim()).map_err(|_| ItsmError::Ssrf("invalid base_url".to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ItsmError::Ssrf("missing host in base_url".to_string()))?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        lookup_host((host.as_str(), port))
            .await
            .map_err(|_| ItsmError::Ssrf(format!("failed to resolve host '{host}'")))?
            .collect()
    };
    if addrs.is_empty() {
        return Err(ItsmError::Ssrf(format!(
            "host '{host}' resolved to no addresses"
        )));
    }
    let allow_private = std::env::var("WEISSMAN_ALLOW_PRIVATE_WEBHOOKS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !allow_private {
        for a in &addrs {
            if crate::security_hardening::is_private_or_reserved_ip(&a.ip()) {
                return Err(ItsmError::Ssrf(format!(
                    "host '{host}' resolves to a private/reserved address ({}); refusing (DNS-rebind guard)",
                    a.ip()
                )));
            }
        }
    }
    Ok((host, addrs))
}

/// Coarse severity bucket (1 = most severe) both vendors can map onto priority/urgency.
pub(crate) fn severity_rank(severity: &str) -> u8 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => 1,
        "high" => 2,
        "medium" => 3,
        "low" => 4,
        _ => 3,
    }
}

/// Char-bounded truncation (never splits a UTF-8 scalar).
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// MINOR-3 fix: ITSM ticket-id envelopes are tiny; cap the response body so a malicious or
/// compromised (or rebind) endpoint cannot stream an unbounded body into memory. Rejects on a
/// declared Content-Length over the cap, and again on the actual bytes read.
pub(crate) const MAX_ITSM_RESP_BYTES: usize = 256 * 1024;

pub(crate) async fn read_body_bounded(resp: reqwest::Response) -> Result<Vec<u8>, ItsmError> {
    if resp
        .content_length()
        .map(|n| n as usize > MAX_ITSM_RESP_BYTES)
        .unwrap_or(false)
    {
        return Err(ItsmError::Decode(
            "ITSM response exceeds size cap".to_string(),
        ));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ItsmError::Request(e.to_string()))?;
    if bytes.len() > MAX_ITSM_RESP_BYTES {
        return Err(ItsmError::Decode(
            "ITSM response exceeds size cap".to_string(),
        ));
    }
    Ok(bytes.to_vec())
}

/// Dispatch to the correct vendor. SSRF-validates base_url first (async resolve + reject
/// private/reserved) and pins the vetted addresses into the client, then performs the create call.
pub async fn create_ticket(
    connector: &ItsmConnector,
    finding: &FindingTicketInput,
) -> Result<CreatedTicket, ItsmError> {
    crate::security_hardening::validate_outbound_url(connector.base_url.trim())
        .await
        .map_err(ItsmError::Ssrf)?;
    // MAJOR-2 fix: resolve+vet ONCE and pin those exact addresses into the client so reqwest
    // cannot re-resolve to a rebinding target between validation and connect.
    let (host, addrs) = vetted_addrs(connector.base_url.trim()).await?;
    let client = itsm_client_pinned(&host, &addrs)?;
    match connector.kind.as_str() {
        KIND_SERVICENOW => servicenow::create_incident(connector, finding, &client).await,
        KIND_JIRA => jira::create_issue(connector, finding, &client).await,
        other => Err(ItsmError::Config(format!(
            "unknown connector kind '{other}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_copies_are_byte_identical_and_force_rls() {
        let fe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("migrations/20260926101000_itsm_connectors.sql");
        let db = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/weissman-db/migrations/20260926101000_itsm_connectors.sql");
        let a = std::fs::read_to_string(&fe).unwrap();
        let b = std::fs::read_to_string(&db).unwrap();
        assert_eq!(a, b);
        assert!(a.contains("FORCE ROW LEVEL SECURITY"));
        assert!(a.contains("app_current_tenant_id()"));
        assert!(a.contains("kind IN ('servicenow', 'jira')"));
    }

    #[test]
    fn severity_rank_orders_critical_first() {
        assert_eq!(severity_rank("critical"), 1);
        assert!(severity_rank("high") < severity_rank("low"));
        assert_eq!(severity_rank("unknown-sev"), 3);
    }

    #[test]
    fn credential_round_trips_through_json() {
        let blob = serde_json::json!({"scheme":"bearer","username":"","secret":"tok"}).to_string();
        let c: ItsmCredential = serde_json::from_str(&blob).unwrap();
        assert!(matches!(c.scheme, AuthScheme::Bearer));
        assert_eq!(c.secret, "tok");

        let basic = serde_json::json!({"scheme":"basic","username":"u","secret":"p"}).to_string();
        let c2: ItsmCredential = serde_json::from_str(&basic).unwrap();
        assert!(matches!(c2.scheme, AuthScheme::Basic));
        assert_eq!(c2.username, "u");
    }

    #[test]
    fn truncate_is_char_safe() {
        assert_eq!(truncate("abcdef", 3), "abc");
        assert_eq!(truncate("abc", 10), "abc");
        // Multi-byte scalars are counted as one char and never split mid-byte.
        assert_eq!(truncate("héllo", 2).chars().count(), 2);
    }
}
