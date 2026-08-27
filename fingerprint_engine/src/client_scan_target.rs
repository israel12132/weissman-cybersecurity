//! Default scan target for a bound customer: Client Configuration, then Asset Snapshot.
//!
//! Tenant lock (`assigned_client_id`) is **not** a scan target. When a scan is invoked
//! without `target`, the server loads the client's primary domain (then the first
//! verified asset) and uses it. Fail closed with [`ERROR_CODE_NO_DEFAULT`] when nothing
//! is configured. An explicit target is accepted only when it belongs to that client's
//! domains / assets.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::collections::HashSet;
use std::net::IpAddr;
use url::Url;

/// Structured intake error: the bound client has no domain or verified asset to aim at.
pub const ERROR_CODE_NO_DEFAULT: &str = "no_default_scan_target";
/// Explicit target is not in this customer's authorized domains / assets.
pub const ERROR_CODE_OUT_OF_SCOPE: &str = "target_out_of_scope";

pub const NO_DEFAULT_DETAIL: &str = "No default scan target. Add a domain in Client Configuration \
(or verify an asset in the Asset Snapshot), then retry the scan.";

const VERIFIED_ASSET_STATUS: &[&str] = &[
    "verified",
    "live",
    "exposed",
    "active",
    "secure",
    "confirmed",
    "online",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSource {
    Explicit,
    PrimaryDomain,
    VerifiedAsset,
}

impl TargetSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::PrimaryDomain => "client_primary_domain",
            Self::VerifiedAsset => "client_verified_asset",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedScanTarget {
    pub target: String,
    pub host: String,
    pub source: TargetSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanTargetError {
    NoDefault { detail: String },
    OutOfScope { detail: String },
    Internal { detail: String },
}

impl ScanTargetError {
    #[must_use]
    pub fn no_default() -> Self {
        Self::NoDefault {
            detail: NO_DEFAULT_DETAIL.to_string(),
        }
    }

    #[must_use]
    pub fn out_of_scope(host: &str) -> Self {
        Self::OutOfScope {
            detail: format!(
                "target host '{host}' is outside this client's authorized domains and assets"
            ),
        }
    }

    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::NoDefault { .. } => ERROR_CODE_NO_DEFAULT,
            Self::OutOfScope { .. } => ERROR_CODE_OUT_OF_SCOPE,
            Self::Internal { .. } => "internal_error",
        }
    }

    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::NoDefault { .. } => StatusCode::BAD_REQUEST,
            Self::OutOfScope { .. } => StatusCode::FORBIDDEN,
            Self::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::NoDefault { detail }
            | Self::OutOfScope { detail }
            | Self::Internal { detail } => detail.as_str(),
        }
    }

    #[must_use]
    pub fn json_body(&self) -> Value {
        let mut body = json!({
            "ok": false,
            "detail": self.detail(),
            "code": self.error_code(),
            "error_code": self.error_code(),
        });
        if matches!(self, Self::NoDefault { .. }) {
            if let Some(obj) = body.as_object_mut() {
                obj.insert("action".into(), json!("add_client_domain"));
            }
        }
        body
    }
}

impl IntoResponse for ScanTargetError {
    fn into_response(self) -> Response {
        (self.status_code(), Json(self.json_body())).into_response()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientScanScope {
    /// Preferred URL to use when the caller omitted `target`.
    pub default_target: Option<String>,
    pub default_source: Option<TargetSource>,
    /// Normalized hosts (and CIDR/IP tokens) this customer is allowed to scan.
    pub approved_hosts: HashSet<String>,
    /// Ordered scan URLs for run-all: configured domains, else the default asset.
    pub configured_targets: Vec<String>,
    pub client_exists: bool,
}

impl ClientScanScope {
    /// Domains/assets to enqueue when the operator runs every authorized host.
    #[must_use]
    pub fn run_all_targets(&self) -> Vec<String> {
        if !self.configured_targets.is_empty() {
            return self.configured_targets.clone();
        }
        self.default_target.iter().cloned().collect()
    }
}

/// Parse `clients.domains` / config blobs: string arrays, object arrays, CSV.
#[must_use]
pub fn parse_domain_entries(raw: &str) -> Vec<DomainEntry> {
    let t = raw.trim();
    if t.is_empty() {
        return Vec::new();
    }
    if t.starts_with('[') {
        if let Ok(val) = serde_json::from_str::<Value>(t) {
            return entries_from_value(&val);
        }
    }
    if t.starts_with('{') {
        if let Ok(val) = serde_json::from_str::<Value>(t) {
            return entries_from_object_fields(&val);
        }
    }
    t.split([',', '\n', ';'])
        .filter_map(|p| DomainEntry::from_raw(p, false, false))
        .collect()
}

/// Hosts only (for scope allow-lists).
#[must_use]
pub fn hosts_from_blob(raw: &str) -> Vec<String> {
    parse_domain_entries(raw)
        .into_iter()
        .map(|e| e.host)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainEntry {
    pub host: String,
    pub raw: String,
    pub primary: bool,
    pub verified: bool,
}

impl DomainEntry {
    fn from_raw(raw: &str, primary: bool, verified: bool) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        let host = normalize_scope_host(raw)?;
        Some(Self {
            host,
            raw: raw.to_string(),
            primary,
            verified,
        })
    }

    #[must_use]
    pub fn as_target_url(&self) -> String {
        as_scan_target_url(&self.raw)
    }
}

#[must_use]
pub fn as_scan_target_url(raw: &str) -> String {
    let t = raw.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{t}")
    }
}

#[must_use]
pub fn normalize_scope_host(s: &str) -> Option<String> {
    let raw = s.trim().trim_matches('.').trim_start_matches("*.").trim();
    if raw.is_empty() {
        return None;
    }
    let candidate = if raw.contains("://") {
        Url::parse(raw)
            .ok()
            .and_then(|u| u.host_str().map(ToString::to_string))
    } else {
        Url::parse(&format!("https://{raw}"))
            .ok()
            .and_then(|u| u.host_str().map(ToString::to_string))
    };
    candidate.map(|h| h.to_ascii_lowercase())
}

#[must_use]
pub fn extract_target_host(raw: &str) -> Result<String, &'static str> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("target must not be empty");
    }
    let parsed = if t.contains("://") {
        Url::parse(t).map_err(|_| "invalid target URL")?
    } else {
        Url::parse(&format!("https://{t}")).map_err(|_| "invalid target host")?
    };
    let host = parsed.host_str().ok_or("missing target host")?;
    Ok(host.to_ascii_lowercase())
}

#[must_use]
pub fn host_matches_approved(host: &str, approved: &HashSet<String>) -> bool {
    let host = host.trim_end_matches('.');
    if let Ok(ip) = host.parse::<IpAddr>() {
        if approved.iter().any(|d| d == host) {
            return true;
        }
        return approved.iter().any(|token| cidr_contains(token, ip));
    }
    approved.iter().any(|d| {
        if host == d {
            return true;
        }
        host.strip_suffix(d)
            .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// Load configuration + asset snapshot for one customer (RLS-scoped).
pub async fn load_client_scan_scope(
    pool: &PgPool,
    tenant_id: i64,
    client_id: i64,
) -> Result<ClientScanScope, sqlx::Error> {
    let mut tx = crate::db::begin_tenant_tx(pool, tenant_id).await?;
    let row = sqlx::query(
        r#"SELECT
                COALESCE(domains, '[]') AS domains,
                COALESCE(ip_ranges, '[]') AS ip_ranges,
                COALESCE(NULLIF(trim(client_configs), ''), '{}') AS client_configs
           FROM clients
           WHERE tenant_id = $1 AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        let _ = tx.commit().await;
        return Ok(ClientScanScope {
            client_exists: false,
            ..ClientScanScope::default()
        });
    };

    let domains_raw: String = row.try_get("domains").unwrap_or_else(|_| "[]".into());
    let ip_raw: String = row.try_get("ip_ranges").unwrap_or_else(|_| "[]".into());
    let configs_raw: String = row
        .try_get("client_configs")
        .unwrap_or_else(|_| "{}".into());

    let asset_rows = sqlx::query(
        r#"SELECT label, node_type, status
           FROM asm_graph_nodes
           WHERE tenant_id = $1 AND client_id = $2
           ORDER BY id ASC
           LIMIT 80"#,
    )
    .bind(tenant_id)
    .bind(client_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap_or_default();
    let _ = tx.commit().await;

    let assets: Vec<(String, String, String)> = asset_rows
        .iter()
        .map(|r| {
            (
                r.try_get("label").unwrap_or_default(),
                r.try_get("node_type").unwrap_or_default(),
                r.try_get("status").unwrap_or_default(),
            )
        })
        .collect();

    Ok(assemble_scope(&domains_raw, &ip_raw, &configs_raw, &assets))
}

/// Resolve `target` for scan intake. Empty + bound client → default domain/asset.
pub async fn resolve_scan_target(
    pool: &PgPool,
    tenant_id: i64,
    client_id: Option<i64>,
    explicit_target: Option<&str>,
) -> Result<ResolvedScanTarget, ScanTargetError> {
    let explicit = explicit_target.map(str::trim).filter(|s| !s.is_empty());
    if let Some(raw) = explicit {
        let host = extract_target_host(raw).map_err(|e| ScanTargetError::OutOfScope {
            detail: e.to_string(),
        })?;
        if let Some(cid) = client_id {
            let scope = load_client_scan_scope(pool, tenant_id, cid)
                .await
                .map_err(|e| ScanTargetError::Internal {
                    detail: format!("failed loading client scan scope: {e}"),
                })?;
            if scope.approved_hosts.is_empty() {
                return Err(ScanTargetError::no_default());
            }
            if !host_matches_approved(&host, &scope.approved_hosts) {
                return Err(ScanTargetError::out_of_scope(&host));
            }
        }
        return Ok(ResolvedScanTarget {
            target: raw.to_string(),
            host,
            source: TargetSource::Explicit,
        });
    }

    let Some(cid) = client_id else {
        return Err(ScanTargetError::no_default());
    };
    let scope = load_client_scan_scope(pool, tenant_id, cid)
        .await
        .map_err(|e| ScanTargetError::Internal {
            detail: format!("failed loading client scan scope: {e}"),
        })?;
    let Some(target) = scope.default_target.clone() else {
        return Err(ScanTargetError::no_default());
    };
    let host = extract_target_host(&target).unwrap_or_else(|_| target.clone());
    Ok(ResolvedScanTarget {
        target,
        host,
        source: scope.default_source.unwrap_or(TargetSource::PrimaryDomain),
    })
}

fn assemble_scope(
    domains_raw: &str,
    ip_raw: &str,
    configs_raw: &str,
    asset_rows: &[(String, String, String)],
) -> ClientScanScope {
    let mut approved = HashSet::new();
    let domain_entries = parse_domain_entries(domains_raw);
    for e in &domain_entries {
        approved.insert(e.host.clone());
    }

    let config = serde_json::from_str::<Value>(configs_raw).unwrap_or(json!({}));
    let config_entries = entries_from_config(&config);
    for e in &config_entries {
        approved.insert(e.host.clone());
    }

    for host in hosts_from_blob(ip_raw) {
        approved.insert(host);
    }

    let mut verified_assets: Vec<String> = Vec::new();
    let mut other_assets: Vec<String> = Vec::new();
    for (label, node_type, status) in asset_rows {
        let Some(host) = asset_host(label, node_type) else {
            continue;
        };
        approved.insert(host.clone());
        if is_verified_asset_status(status) {
            verified_assets.push(host);
        } else {
            other_assets.push(host);
        }
    }

    let primary = pick_primary_domain(&domain_entries, &config_entries, &config);
    let (default_target, default_source) = if let Some(entry) = primary {
        (
            Some(entry.as_target_url()),
            Some(TargetSource::PrimaryDomain),
        )
    } else if let Some(host) = verified_assets
        .first()
        .cloned()
        .or_else(|| other_assets.first().cloned())
    {
        (
            Some(as_scan_target_url(&host)),
            Some(TargetSource::VerifiedAsset),
        )
    } else {
        (None, None)
    };

    let mut configured_targets: Vec<String> = Vec::new();
    let mut seen_targets = HashSet::new();
    for e in domain_entries.iter().chain(config_entries.iter()) {
        let url = e.as_target_url();
        if seen_targets.insert(url.to_ascii_lowercase()) {
            configured_targets.push(url);
        }
    }
    if configured_targets.is_empty() {
        if let Some(url) = default_target.clone() {
            configured_targets.push(url);
        }
    }

    ClientScanScope {
        default_target,
        default_source,
        approved_hosts: approved,
        configured_targets,
        client_exists: true,
    }
}

fn pick_primary_domain(
    domains: &[DomainEntry],
    config_entries: &[DomainEntry],
    config: &Value,
) -> Option<DomainEntry> {
    if let Some(e) = domains.iter().find(|e| e.primary).cloned() {
        return Some(e);
    }
    if let Some(e) = domains.first().cloned() {
        return Some(e);
    }
    if let Some(raw) = config
        .get("primary_domain")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(e) = DomainEntry::from_raw(raw, true, true) {
            return Some(e);
        }
    }
    if let Some(e) = config_entries.iter().find(|e| e.primary).cloned() {
        return Some(e);
    }
    config_entries.first().cloned()
}

fn entries_from_config(config: &Value) -> Vec<DomainEntry> {
    let mut out = Vec::new();
    out.extend(entries_from_value(
        config.get("domains").unwrap_or(&Value::Null),
    ));
    if let Some(onb) = config.get("onboarding") {
        out.extend(entries_from_value(
            onb.get("domains").unwrap_or(&Value::Null),
        ));
        if let Some(raw) = onb
            .get("primary_domain")
            .and_then(Value::as_str)
            .or_else(|| onb.get("domain").and_then(Value::as_str))
        {
            if let Some(e) = DomainEntry::from_raw(raw, true, false) {
                out.push(e);
            }
        }
    }
    out
}

fn entries_from_value(v: &Value) -> Vec<DomainEntry> {
    match v {
        Value::Array(arr) => arr.iter().filter_map(entry_from_json).collect(),
        Value::String(s) => parse_domain_entries(s),
        Value::Object(_) => entries_from_object_fields(v),
        _ => Vec::new(),
    }
}

fn entries_from_object_fields(obj: &Value) -> Vec<DomainEntry> {
    let mut out = Vec::new();
    for key in ["domains", "hosts", "assets"] {
        if let Some(inner) = obj.get(key) {
            out.extend(entries_from_value(inner));
        }
    }
    if let Some(e) = entry_from_json(obj) {
        out.push(e);
    }
    out
}

fn entry_from_json(v: &Value) -> Option<DomainEntry> {
    match v {
        Value::String(s) => DomainEntry::from_raw(s, false, false),
        Value::Object(map) => {
            let raw = map
                .get("domain")
                .or_else(|| map.get("host"))
                .or_else(|| map.get("url"))
                .or_else(|| map.get("fqdn"))
                .or_else(|| map.get("value"))
                .and_then(Value::as_str)?;
            let primary = map.get("primary").and_then(Value::as_bool).unwrap_or(false)
                || map
                    .get("is_primary")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            let verified = map
                .get("verified")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || map
                    .get("is_verified")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            DomainEntry::from_raw(raw, primary, verified)
        }
        _ => None,
    }
}

fn asset_host(label: &str, node_type: &str) -> Option<String> {
    let nt = node_type.trim().to_ascii_lowercase();
    let looks_typed = matches!(
        nt.as_str(),
        "root" | "subdomain" | "domain" | "host" | "dns" | "asset" | "fqdn" | "apex"
    );
    let host = normalize_scope_host(label)?;
    if looks_typed || looks_like_hostname(&host) {
        Some(host)
    } else {
        None
    }
}

fn looks_like_hostname(host: &str) -> bool {
    host.contains('.') && !host.contains(' ') && host.len() >= 4
}

fn is_verified_asset_status(status: &str) -> bool {
    let s = status.trim().to_ascii_lowercase();
    VERIFIED_ASSET_STATUS.iter().any(|v| *v == s)
}

fn cidr_contains(token: &str, ip: IpAddr) -> bool {
    token
        .parse::<ipnetwork::IpNetwork>()
        .map(|net| net.contains(ip))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_array() {
        let e = parse_domain_entries(r#"["example.com","app.example.com"]"#);
        assert_eq!(e[0].host, "example.com");
        assert_eq!(e[1].host, "app.example.com");
    }

    #[test]
    fn parses_object_array_with_verified_primary() {
        let e = parse_domain_entries(
            r#"[{"domain":"example.com","verified":true,"primary":true},{"host":"cdn.example.com"}]"#,
        );
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].host, "example.com");
        assert!(e[0].primary);
        assert!(e[0].verified);
        assert_eq!(e[1].host, "cdn.example.com");
    }

    #[test]
    fn parses_url_objects() {
        let e = parse_domain_entries(r#"[{"url":"https://www.example.com/path"}]"#);
        assert_eq!(e[0].host, "www.example.com");
        assert_eq!(e[0].as_target_url(), "https://www.example.com/path");
    }

    #[test]
    fn empty_blob_is_empty() {
        assert!(parse_domain_entries("").is_empty());
        assert!(parse_domain_entries("[]").is_empty());
        assert!(hosts_from_blob("   ").is_empty());
    }

    #[test]
    fn host_match_allows_subdomains_not_sibling() {
        let mut approved = HashSet::new();
        approved.insert("example.com".into());
        assert!(host_matches_approved("example.com", &approved));
        assert!(host_matches_approved("api.example.com", &approved));
        assert!(!host_matches_approved("evil-example.com", &approved));
        assert!(!host_matches_approved("example.net", &approved));
    }

    #[test]
    fn assemble_prefers_primary_domain_over_assets() {
        let scope = assemble_scope(r#"["example.com"]"#, "[]", "{}", &[]);
        assert_eq!(scope.default_target.as_deref(), Some("https://example.com"));
        assert_eq!(scope.default_source, Some(TargetSource::PrimaryDomain));
        assert!(scope.approved_hosts.contains("example.com"));
        assert_eq!(scope.run_all_targets(), vec!["https://example.com".to_string()]);
    }

    #[test]
    fn assemble_uses_config_primary_when_domains_empty() {
        let scope = assemble_scope("[]", "[]", r#"{"primary_domain":"example.com"}"#, &[]);
        assert_eq!(scope.default_target.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn assemble_falls_back_to_verified_asset() {
        let assets = vec![("example.com".into(), "root".into(), "verified".into())];
        let scope = assemble_scope("[]", "[]", "{}", &assets);
        assert_eq!(scope.default_target.as_deref(), Some("https://example.com"));
        assert_eq!(scope.default_source, Some(TargetSource::VerifiedAsset));
        assert_eq!(scope.run_all_targets(), vec!["https://example.com".to_string()]);
    }

    #[test]
    fn assemble_empty_has_no_run_all_targets() {
        let scope = assemble_scope("[]", "[]", "{}", &[]);
        assert!(scope.default_target.is_none());
        assert!(scope.run_all_targets().is_empty());
    }

    #[test]
    fn no_default_json_is_structured() {
        let body = ScanTargetError::no_default().json_body();
        assert_eq!(body["error_code"], json!(ERROR_CODE_NO_DEFAULT));
        assert_eq!(body["code"], json!(ERROR_CODE_NO_DEFAULT));
        assert_eq!(body["ok"], json!(false));
        assert_eq!(body["action"], json!("add_client_domain"));
        assert!(body["detail"].as_str().unwrap().contains("Add a domain"));
    }

    #[test]
    fn as_url_preserves_scheme() {
        assert_eq!(as_scan_target_url("example.com"), "https://example.com");
        assert_eq!(
            as_scan_target_url("http://example.com"),
            "http://example.com"
        );
    }
}
