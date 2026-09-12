//! API / GraphQL / cloud-storage intelligence — honest classification + live probes.
//!
//! Fusion engine `api_cloud_intel` combines GraphQL discovery, OpenAPI/Swagger inventory, and
//! multi-cloud object-storage probes. **Every claim is gated by evidence:**
//!
//! * HTTP 401/403 is never "public".
//! * An empty bucket/container listing is never "public data exposure".
//! * GraphQL introspection requires a 2xx JSON body with `data.__schema` — a 403 that echoes
//!   the request query is not introspection.
//! * An OpenAPI "spec" requires a parseable document with a version field and a `paths` object.
//!
//! Defensive only: read-only GETs and safe GraphQL queries (`__typename`, introspection). No
//! exploit payloads.

use crate::arsenal_config::{finding_rich, Evidence};
use crate::engine_probes::{
    empty_ok, extract_host, http_client, http_get, http_post_json, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};

pub const ENGINE_ID: &str = "api_cloud_intel";
const MITRE_STORAGE: &str = "T1530";
const MITRE_API: &str = "T1190";
const MITRE_DISCOVERY: &str = "T1046";

// ── Object storage ───────────────────────────────────────────────────────────

/// How an anonymous object-storage probe should be labelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageListingClass {
    /// HTTP 200 + listing envelope + ≥1 object key. Only this may be called "public".
    PublicObjects,
    /// HTTP 200 + valid listing XML/JSON but zero objects. LIST is open; data is not proven.
    AnonymousListEmpty,
    /// HTTP 401/403 with a storage access-denied marker. Namespace exists; it is not public.
    ExistsDenied,
    /// HTTP 404 / NoSuchBucket / BlobNotFound.
    NotFound,
    /// 401/403 without storage markers (WAF, generic forbidden) — do not claim a bucket exists.
    WafOrUnrelated,
    Inconclusive,
}

impl StorageListingClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicObjects => "public_objects",
            Self::AnonymousListEmpty => "anonymous_list_empty",
            Self::ExistsDenied => "exists_access_denied",
            Self::NotFound => "not_found",
            Self::WafOrUnrelated => "waf_or_unrelated",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// True only when anonymous callers can observe at least one object key.
    #[must_use]
    pub fn is_public_data(self) -> bool {
        matches!(self, Self::PublicObjects)
    }
}

/// Classify an anonymous S3 / GCS / Azure Blob listing response.
#[must_use]
pub fn classify_object_storage(status: u16, body: &str) -> StorageListingClass {
    if matches!(status, 401 | 403) {
        return if storage_access_denied_marker(body) {
            StorageListingClass::ExistsDenied
        } else {
            StorageListingClass::WafOrUnrelated
        };
    }
    if status == 404 || nosuch_bucket(body) {
        return StorageListingClass::NotFound;
    }
    if !(200..300).contains(&status) {
        return StorageListingClass::Inconclusive;
    }

    if let Some(n) = s3_listing_object_count(body) {
        return if n > 0 {
            StorageListingClass::PublicObjects
        } else {
            StorageListingClass::AnonymousListEmpty
        };
    }
    if let Some(n) = azure_blob_object_count(body) {
        return if n > 0 {
            StorageListingClass::PublicObjects
        } else {
            StorageListingClass::AnonymousListEmpty
        };
    }
    if let Some(n) = gcs_object_count(body) {
        return if n > 0 {
            StorageListingClass::PublicObjects
        } else {
            StorageListingClass::AnonymousListEmpty
        };
    }
    StorageListingClass::Inconclusive
}

fn storage_access_denied_marker(body: &str) -> bool {
    let b = body;
    b.contains("AccessDenied")
        || b.contains("InvalidAccessKeyId")
        || b.contains("AllAccessDisabled")
        || b.contains("InvalidSecurity")
        || b.contains("AuthenticationFailed")
        || b.contains("AuthorizationFailure")
        || b.contains("AuthorizationPermissionDenied")
        || b.contains("<Code>AccessDenied</Code>")
        || b.contains("\"error\": \"Forbidden\"")
}

fn nosuch_bucket(body: &str) -> bool {
    let l = body.to_ascii_lowercase();
    l.contains("nosuchbucket")
        || l.contains("the specified bucket does not exist")
        || l.contains("blobnotfound")
        || l.contains("nosuchcontainer")
        || l.contains("\"code\": 404") && l.contains("notfound")
}

/// Count `<Contents>` entries inside an S3 `ListBucketResult`. `None` if this is not an S3 listing.
#[must_use]
pub fn s3_listing_object_count(body: &str) -> Option<usize> {
    if !body.contains("<ListBucketResult") {
        return None;
    }
    Some(count_xml_open(body, "Contents"))
}

/// Count `<Blob>` objects inside Azure `EnumerationResults`. Wrapper `<Blobs>` alone is empty.
#[must_use]
pub fn azure_blob_object_count(body: &str) -> Option<usize> {
    if !body.contains("<EnumerationResults") {
        return None;
    }
    Some(count_xml_open(body, "Blob"))
}

#[must_use]
pub fn gcs_object_count(body: &str) -> Option<usize> {
    let trimmed = body.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    let kind = v.get("kind").and_then(Value::as_str).unwrap_or("");
    if kind != "storage#objects" && kind != "storage#buckets" {
        return None;
    }
    Some(
        v.get("items")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0),
    )
}

fn count_xml_open(body: &str, tag: &str) -> usize {
    let a = format!("<{tag}>");
    let b = format!("<{tag} ");
    body.matches(&a).count() + body.matches(&b).count()
}

/// True when the title **asserts** `token` (negations such as "not public" do not count).
#[must_use]
pub fn title_asserts_token(title: &str, token: &str, negations: &[&str]) -> bool {
    let mut t = title.to_ascii_lowercase();
    for n in negations {
        t = t.replace(n, " ");
    }
    t.contains(token)
}

/// True when the title claims the asset is public. "not public" / "never public" do not.
#[must_use]
pub fn title_asserts_public(title: &str) -> bool {
    title_asserts_token(
        title,
        "public",
        &[
            "not public",
            "never public",
            "non-public",
            "nonpublic",
            "isn't public",
            "isnt public",
            "not a public",
        ],
    )
}

#[must_use]
pub fn title_asserts_exposed(title: &str) -> bool {
    title_asserts_token(
        title,
        "exposed",
        &["not exposed", "never exposed", "unexposed"],
    )
}

#[must_use]
pub fn title_asserts_leak(title: &str) -> bool {
    title_asserts_token(
        title,
        "leak",
        &[
            "not an inventory leak",
            "not a leak",
            "not leaked",
            "no leak",
            "never a leak",
        ],
    )
}

/// A title may claim "public" only for [`StorageListingClass::PublicObjects`].
#[must_use]
pub fn storage_claim_matches_evidence(
    title: &str,
    status: u16,
    class: StorageListingClass,
) -> bool {
    let says_public = title_asserts_public(title);
    if matches!(status, 401 | 403) && says_public {
        return false;
    }
    if says_public && !class.is_public_data() {
        return false;
    }
    if class == StorageListingClass::AnonymousListEmpty && says_public {
        return false;
    }
    true
}

// ── GraphQL ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphqlResponseClass {
    /// 2xx JSON with `data.__schema` — the only class that may be labelled "introspection enabled".
    IntrospectionPublic,
    /// 2xx JSON with `data` (query succeeded anonymously).
    QueryPublic,
    /// GraphQL `errors` array (typically 200/400). Endpoint exists; not a public schema dump.
    GraphQLErrors,
    /// HTTP 401/403. Endpoint may exist; it is **not** public.
    AuthGated,
    /// Body merely repeats request tokens (WAF/error page echo).
    EchoOrUnrelated,
    NotGraphQL,
}

impl GraphqlResponseClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntrospectionPublic => "introspection_public",
            Self::QueryPublic => "query_public",
            Self::GraphQLErrors => "graphql_errors",
            Self::AuthGated => "auth_gated",
            Self::EchoOrUnrelated => "echo_or_unrelated",
            Self::NotGraphQL => "not_graphql",
        }
    }

    #[must_use]
    pub fn is_graphql_endpoint(self) -> bool {
        matches!(
            self,
            Self::IntrospectionPublic | Self::QueryPublic | Self::GraphQLErrors | Self::AuthGated
        )
    }

    #[must_use]
    pub fn is_public_introspection(self) -> bool {
        matches!(self, Self::IntrospectionPublic)
    }
}

/// Classic GraphQL engine error / JSON shapes (independent of HTTP status).
#[must_use]
pub fn graphql_body_shape(body: &str) -> bool {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if v.get("data").is_some() || v.get("errors").is_some() {
            return true;
        }
    }
    let bl = body.to_ascii_lowercase();
    bl.contains("must provide query string")
        || bl.contains("get query missing")
        || bl.contains("cannot query field")
        || bl.contains("must provide an operation")
        || (bl.contains("graphql") && (bl.contains("syntax error") || bl.contains("\"errors\"")))
}

#[must_use]
pub fn classify_graphql_response(status: u16, body: &str) -> GraphqlResponseClass {
    // 401/403 is never public — even if the body echoes `__schema` from the request.
    // Only label AuthGated when the body is actually a GraphQL engine shape.
    if matches!(status, 401 | 403) {
        if graphql_body_shape(body) {
            return GraphqlResponseClass::AuthGated;
        }
        if body.contains("__schema") || body.contains("\"query\"") {
            return GraphqlResponseClass::EchoOrUnrelated;
        }
        return GraphqlResponseClass::NotGraphQL;
    }

    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if (200..300).contains(&status) && v.pointer("/data/__schema").is_some() {
            return GraphqlResponseClass::IntrospectionPublic;
        }
        if (200..300).contains(&status) && v.get("data").is_some() {
            return GraphqlResponseClass::QueryPublic;
        }
        if v.get("errors").is_some() {
            return GraphqlResponseClass::GraphQLErrors;
        }
        // Echo of the request JSON `{"query":"{__schema...}"}` is not a GraphQL engine response.
        if v.get("query").is_some() && v.get("data").is_none() && v.get("errors").is_none() {
            return GraphqlResponseClass::EchoOrUnrelated;
        }
    }

    if graphql_body_shape(body) && (200..500).contains(&status) && status != 401 && status != 403 {
        return GraphqlResponseClass::GraphQLErrors;
    }

    // A 2xx/4xx HTML page that only contains the request's `__schema` token is an echo, not intel.
    if body.contains("__schema") && !json_has_schema_data(body) {
        return GraphqlResponseClass::EchoOrUnrelated;
    }
    GraphqlResponseClass::NotGraphQL
}

fn json_has_schema_data(body: &str) -> bool {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.pointer("/data/__schema").cloned())
        .is_some()
}

/// GraphQL titles must not say "introspection enabled" / "public" on 401/403 or echo bodies.
#[must_use]
pub fn graphql_claim_matches_evidence(
    title: &str,
    status: u16,
    class: GraphqlResponseClass,
) -> bool {
    let t = title.to_ascii_lowercase();
    if matches!(status, 401 | 403) {
        if title_asserts_public(title) || t.contains("introspection enabled") {
            return false;
        }
    }
    if t.contains("introspection enabled") && !class.is_public_introspection() {
        return false;
    }
    if title_asserts_public(title)
        && !matches!(
            class,
            GraphqlResponseClass::IntrospectionPublic | GraphqlResponseClass::QueryPublic
        )
    {
        return false;
    }
    true
}

// ── OpenAPI / Swagger ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenApiClass {
    /// 200 + parseable OAS/Swagger with a version field and a `paths` object.
    PublicSpec,
    /// 401/403 — spec is not public.
    AuthGated,
    /// 200 HTML Swagger UI without a parseable spec body.
    HtmlUiOnly,
    EchoOrUnrelated,
    NotOpenApi,
}

impl OpenApiClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicSpec => "public_spec",
            Self::AuthGated => "auth_gated",
            Self::HtmlUiOnly => "html_ui_only",
            Self::EchoOrUnrelated => "echo_or_unrelated",
            Self::NotOpenApi => "not_openapi",
        }
    }
}

/// Parse an OpenAPI/Swagger document. Returns `(path_count, version)` when structurally valid.
#[must_use]
pub fn parse_openapi_inventory(body: &str) -> Option<(usize, String)> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        let v: Value = serde_json::from_str(body).ok()?;
        let ver = v
            .get("openapi")
            .or_else(|| v.get("swagger"))
            .and_then(Value::as_str)?
            .to_string();
        if ver.is_empty() {
            return None;
        }
        let paths = v.get("paths")?.as_object()?;
        return Some((paths.len(), ver));
    }
    // Conservative YAML: version key at the document start + a paths: mapping.
    let first = trimmed.lines().next().unwrap_or("").trim();
    let ver = if let Some(rest) = first.strip_prefix("openapi:") {
        rest.trim().trim_matches('"').trim_matches('\'').to_string()
    } else if let Some(rest) = first.strip_prefix("swagger:") {
        rest.trim().trim_matches('"').trim_matches('\'').to_string()
    } else {
        return None;
    };
    if ver.is_empty() {
        return None;
    }
    if !(trimmed.contains("\npaths:")
        || trimmed.contains("\npaths :")
        || trimmed.contains("\r\npaths:"))
    {
        return None;
    }
    let path_lines = trimmed
        .lines()
        .filter(|l| {
            let s = l.trim_start();
            s.starts_with('/') && s.contains(':')
        })
        .count();
    Some((path_lines, ver))
}

#[must_use]
pub fn classify_openapi(status: u16, body: &str) -> OpenApiClass {
    if matches!(status, 401 | 403) {
        // A 401/403 is never a public spec. Only call it auth-gated when the
        // body is actually an OpenAPI document (still not public).
        if parse_openapi_inventory(body).is_some() {
            return OpenApiClass::AuthGated;
        }
        return OpenApiClass::NotOpenApi;
    }
    if status != 200 {
        return OpenApiClass::NotOpenApi;
    }
    if parse_openapi_inventory(body).is_some() {
        return OpenApiClass::PublicSpec;
    }
    let bl = body.to_ascii_lowercase();
    if bl.contains("swagger-ui") || bl.contains("swaggerui") || bl.contains("redoc") {
        return OpenApiClass::HtmlUiOnly;
    }
    // Substring "openapi" / "paths" in arbitrary HTML/JS is not a spec.
    if bl.contains("openapi") || bl.contains("swagger") {
        return OpenApiClass::EchoOrUnrelated;
    }
    OpenApiClass::NotOpenApi
}

#[must_use]
pub fn openapi_claim_matches_evidence(title: &str, status: u16, class: OpenApiClass) -> bool {
    if matches!(status, 401 | 403)
        && (title_asserts_public(title)
            || title_asserts_exposed(title)
            || title_asserts_leak(title))
    {
        return false;
    }
    if (title_asserts_exposed(title) || title_asserts_public(title) || title_asserts_leak(title))
        && class != OpenApiClass::PublicSpec
    {
        return false;
    }
    true
}

// ── Finding builders (evidence always matches claim) ─────────────────────────

fn storage_finding(
    engine_id: &str,
    provider: &str,
    url: &str,
    status: u16,
    body: &str,
    target: &str,
    class: StorageListingClass,
) -> Option<Value> {
    let object_count = s3_listing_object_count(body)
        .or_else(|| azure_blob_object_count(body))
        .or_else(|| gcs_object_count(body))
        .unwrap_or(0);
    let excerpt: String = body.chars().take(240).collect();
    let (title, severity, description, confidence) = match class {
        StorageListingClass::PublicObjects => (
            format!("Public {provider} objects listable"),
            "critical",
            format!(
                "{url} returned HTTP {status} with a listing envelope and {object_count} object key(s). Anonymous callers can observe stored objects."
            ),
            0.92,
        ),
        StorageListingClass::AnonymousListEmpty => (
            format!("{provider} anonymous LIST permitted (empty listing)"),
            "info",
            format!(
                "{url} returned HTTP {status} ListBucket/Enumeration listing with 0 object keys. LIST is unauthenticated; this is not evidence of public data."
            ),
            0.55,
        ),
        StorageListingClass::ExistsDenied => (
            format!("{provider} exists (access denied — listing forbidden)"),
            "info",
            format!(
                "{url} returned HTTP {status} AccessDenied. The namespace exists but anonymous listing failed. Do not treat this as a public bucket."
            ),
            0.7,
        ),
        _ => return None,
    };
    debug_assert!(storage_claim_matches_evidence(&title, status, class));
    let ev = Evidence::new()
        .with("url", url)
        .with("http_status", status)
        .with("classification", class.as_str())
        .with("provider", provider)
        .with("object_count", object_count)
        .with("body_excerpt", excerpt)
        .check(
            "anonymous_list_public_objects",
            class.is_public_data(),
            class.as_str(),
        )
        .check(
            "http_401_403_is_not_public",
            !matches!(status, 401 | 403) || !class.is_public_data(),
            status,
        )
        .check(
            "empty_listing_is_not_public",
            class != StorageListingClass::AnonymousListEmpty || !title_asserts_public(&title),
            object_count,
        );
    let mut f = finding_rich(
        engine_id,
        &title,
        severity,
        MITRE_STORAGE,
        &description,
        target,
        confidence,
        ev,
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("classification".into(), json!(class.as_str()));
        o.insert("http_status".into(), json!(status));
        o.insert("evidence_matches_claim".into(), json!(true));
        o.insert("object_count".into(), json!(object_count));
    }
    Some(f)
}

fn graphql_finding(
    engine_id: &str,
    url: &str,
    status: u16,
    body: &str,
    target: &str,
    class: GraphqlResponseClass,
) -> Option<Value> {
    let excerpt: String = body.chars().take(240).collect();
    let (title, severity, description, mitre, confidence) = match class {
        GraphqlResponseClass::IntrospectionPublic => {
            let types = serde_json::from_str::<Value>(body)
                .ok()
                .and_then(|v| {
                    v.pointer("/data/__schema/types")
                        .and_then(Value::as_array)
                        .map(|a| a.len())
                })
                .unwrap_or(0);
            (
                "GraphQL introspection enabled (unauthenticated)".to_string(),
                "high",
                format!(
                    "{url} returned HTTP {status} JSON with data.__schema ({types} types). The type graph is public to anonymous clients."
                ),
                MITRE_API,
                0.9,
            )
        }
        GraphqlResponseClass::QueryPublic => (
            "GraphQL endpoint accepts unauthenticated queries".into(),
            "medium",
            format!("{url} returned HTTP {status} JSON with a `data` payload for a safe __typename probe."),
            MITRE_DISCOVERY,
            0.75,
        ),
        GraphqlResponseClass::GraphQLErrors => (
            "GraphQL endpoint discovered (errors, schema not confirmed)".into(),
            "info",
            format!(
                "{url} returned GraphQL errors (HTTP {status}). Inventory the endpoint; this is not evidence that introspection is public."
            ),
            MITRE_DISCOVERY,
            0.6,
        ),
        GraphqlResponseClass::AuthGated => (
            format!("GraphQL endpoint authentication-gated (HTTP {status})"),
            "info",
            format!(
                "{url} returned HTTP {status}. A 401/403 is not a public GraphQL API and is not introspection. Require auth; do not label this public."
            ),
            MITRE_DISCOVERY,
            0.55,
        ),
        _ => return None,
    };
    debug_assert!(graphql_claim_matches_evidence(&title, status, class));
    let ev = Evidence::new()
        .with("url", url)
        .with("http_status", status)
        .with("classification", class.as_str())
        .with("body_excerpt", excerpt)
        .check(
            "introspection_public",
            class.is_public_introspection(),
            class.as_str(),
        )
        .check(
            "http_401_403_is_not_public",
            !matches!(status, 401 | 403)
                || (!title_asserts_public(&title)
                    && !title.to_ascii_lowercase().contains("introspection enabled")),
            status,
        );
    let mut f = finding_rich(
        engine_id,
        &title,
        severity,
        mitre,
        &description,
        target,
        confidence,
        ev,
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("classification".into(), json!(class.as_str()));
        o.insert("http_status".into(), json!(status));
        o.insert("evidence_matches_claim".into(), json!(true));
        o.insert(
            "owasp_api".into(),
            json!("API9:2023 Improper Inventory Management"),
        );
    }
    Some(f)
}

fn openapi_finding(
    engine_id: &str,
    url: &str,
    status: u16,
    body: &str,
    target: &str,
    class: OpenApiClass,
) -> Option<Value> {
    match class {
        OpenApiClass::PublicSpec => {
            let (path_count, version) = parse_openapi_inventory(body)?;
            let (title, severity, description, confidence) = if path_count == 0 {
                (
                    "OpenAPI document reachable (0 paths — empty inventory)".to_string(),
                    "info",
                    format!(
                        "{url} returned HTTP {status} OpenAPI/Swagger {version} with an empty paths object. Evidence does not show leaked routes."
                    ),
                    0.45,
                )
            } else {
                (
                    format!("Public OpenAPI/Swagger spec ({path_count} paths)"),
                    "medium",
                    format!(
                        "{url} returned HTTP {status} OpenAPI/Swagger {version} with {path_count} path(s). Inventory and auth schemes are visible anonymously."
                    ),
                    0.8,
                )
            };
            debug_assert!(openapi_claim_matches_evidence(&title, status, class));
            let ev = Evidence::new()
                .with("url", url)
                .with("http_status", status)
                .with("classification", class.as_str())
                .with("openapi_version", version.clone())
                .with("path_count", path_count)
                .check("parseable_spec", true, version)
                .check(
                    "empty_paths_not_inventory_leak",
                    path_count > 0 || !title_asserts_leak(&title),
                    path_count,
                );
            let mut f = finding_rich(
                engine_id,
                &title,
                severity,
                MITRE_API,
                &description,
                target,
                confidence,
                ev,
            );
            if let Some(o) = f.as_object_mut() {
                o.insert("classification".into(), json!(class.as_str()));
                o.insert("http_status".into(), json!(status));
                o.insert("evidence_matches_claim".into(), json!(true));
                o.insert("path_count".into(), json!(path_count));
            }
            Some(f)
        }
        OpenApiClass::AuthGated => {
            let title = format!("API spec authentication-gated (HTTP {status})");
            debug_assert!(openapi_claim_matches_evidence(&title, status, class));
            let ev = Evidence::new()
                .with("url", url)
                .with("http_status", status)
                .with("classification", class.as_str())
                .check("http_401_403_is_not_public", true, status);
            let mut f = finding_rich(
                engine_id,
                &title,
                "info",
                MITRE_DISCOVERY,
                &format!(
                    "{url} returned HTTP {status}. A 401/403 is not a public OpenAPI document."
                ),
                target,
                0.5,
                ev,
            );
            if let Some(o) = f.as_object_mut() {
                o.insert("classification".into(), json!(class.as_str()));
                o.insert("http_status".into(), json!(status));
                o.insert("evidence_matches_claim".into(), json!(true));
            }
            Some(f)
        }
        OpenApiClass::HtmlUiOnly => {
            let ev = Evidence::new()
                .with("url", url)
                .with("http_status", status)
                .with("classification", class.as_str())
                .check("html_ui_without_spec", true, "swagger-ui/redoc markup");
            let mut f = finding_rich(
                engine_id,
                "Swagger UI / ReDoc HTML reachable (spec not confirmed)",
                "info",
                MITRE_DISCOVERY,
                &format!(
                    "{url} returned HTTP {status} API-docs UI markup without a parseable openapi/swagger+paths document. Do not claim a leaked spec."
                ),
                target,
                0.4,
                ev,
            );
            if let Some(o) = f.as_object_mut() {
                o.insert("classification".into(), json!(class.as_str()));
                o.insert("http_status".into(), json!(status));
                o.insert("evidence_matches_claim".into(), json!(true));
            }
            Some(f)
        }
        _ => None,
    }
}

// ── Live fused engine ────────────────────────────────────────────────────────

const GRAPHQL_PATHS: &[&str] = &[
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/v1/graphql",
    "/query",
    "/gql",
    "/api/gql",
];

const OPENAPI_PATHS: &[&str] = &[
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
];

const INTROSPECTION_QUERY: &str = r#"query { __schema { queryType { name } types { name } } }"#;

fn push_unique(findings: &mut Vec<Value>, seen: &mut std::collections::HashSet<String>, f: Value) {
    let title = f.get("title").and_then(Value::as_str).unwrap_or("");
    let class = f
        .get("classification")
        .and_then(Value::as_str)
        .unwrap_or("");
    let url = f
        .get("evidence")
        .and_then(|e| e.get("url"))
        .and_then(Value::as_str)
        .unwrap_or("");
    // Auth-gated 401/403 is one intel fact per class, not one finding per guessed path.
    let key = if class.contains("gated") {
        format!("gated|{class}|{title}")
    } else {
        format!("{title}|{url}")
    };
    if seen.insert(key) {
        findings.push(f);
    }
}

fn host_is_loopback_or_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
        || host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host.starts_with("127.")
        || host == "::1"
}

pub async fn run_api_cloud_intel_result(target: &str) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let base = normalize_url(target);
    let host = extract_host(target);
    let client = http_client().await;
    let mut findings: Vec<Value> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // GraphQL — safe queries only.
    let intro = json!({ "query": INTROSPECTION_QUERY });
    let typename_q = json!({ "query": "{ __typename }" });
    for path in GRAPHQL_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_post_json(&client, &url, &typename_q).await {
            let class = classify_graphql_response(p.status, &p.body);
            if let Some(f) =
                graphql_finding(ENGINE_ID, &p.final_url, p.status, &p.body, target, class)
            {
                push_unique(&mut findings, &mut seen, f);
            }
        }
        if let Some(p) = http_post_json(&client, &url, &intro).await {
            let class = classify_graphql_response(p.status, &p.body);
            if class.is_public_introspection() {
                if let Some(f) =
                    graphql_finding(ENGINE_ID, &p.final_url, p.status, &p.body, target, class)
                {
                    push_unique(&mut findings, &mut seen, f);
                }
            }
        }
    }

    // OpenAPI / Swagger inventory (GET only).
    for path in OPENAPI_PATHS {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        if let Some(p) = http_get(&client, &url).await {
            let class = classify_openapi(p.status, &p.body);
            if let Some(f) =
                openapi_finding(ENGINE_ID, &p.final_url, p.status, &p.body, target, class)
            {
                push_unique(&mut findings, &mut seen, f);
            }
        }
    }

    // Multi-cloud anonymous listing — skip loopback/IP targets (no real bucket DNS).
    if !host_is_loopback_or_ip(&host) {
        let label = host.split('.').next().unwrap_or(&host);
        let candidates: Vec<(&str, String)> = vec![
            (
                "AWS S3",
                format!(
                    "https://{}.s3.amazonaws.com/?max-keys=5",
                    host.replace('.', "-")
                ),
            ),
            (
                "AWS S3",
                format!("https://{label}.s3.amazonaws.com/?max-keys=5"),
            ),
            (
                "GCP Storage",
                format!("https://storage.googleapis.com/{host}/"),
            ),
            (
                "GCP Storage",
                format!("https://storage.googleapis.com/{label}/"),
            ),
            (
                "Azure Blob",
                format!(
                    "https://{}.blob.core.windows.net/?comp=list",
                    label.replace('-', "")
                ),
            ),
        ];
        for (provider, url) in &candidates {
            if let Some(p) = http_get(&client, url).await {
                let class = classify_object_storage(p.status, &p.body);
                if let Some(f) = storage_finding(
                    ENGINE_ID,
                    provider,
                    &p.final_url,
                    p.status,
                    &p.body,
                    target,
                    class,
                ) {
                    push_unique(&mut findings, &mut seen, f);
                }
            }
        }
    }

    if findings.is_empty() {
        empty_ok(ENGINE_ID, target)
    } else {
        let n = findings.len();
        EngineResult::ok(
            findings,
            format!("api_cloud_intel: {n} evidence-backed finding(s)"),
        )
    }
}

pub async fn run_api_cloud_intel(target: &str) {
    print_result(run_api_cloud_intel_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    const S3_EMPTY: &str = r#"<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>acme-backup</Name>
  <Prefix></Prefix>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>"#;

    const S3_WITH_OBJECT: &str = r#"<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>acme-backup</Name>
  <Contents>
    <Key>secrets/prod.env</Key>
    <Size>12</Size>
  </Contents>
</ListBucketResult>"#;

    const S3_DENIED: &str = r#"<?xml version="1.0"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
</Error>"#;

    const AZURE_EMPTY: &str = r#"<?xml version="1.0"?>
<EnumerationResults ServiceEndpoint="https://acct.blob.core.windows.net/" ContainerName="data">
  <Blobs></Blobs>
</EnumerationResults>"#;

    const AZURE_WITH_BLOB: &str = r#"<?xml version="1.0"?>
<EnumerationResults ServiceEndpoint="https://acct.blob.core.windows.net/" ContainerName="data">
  <Blobs>
    <Blob><Name>invoice.pdf</Name></Blob>
  </Blobs>
</EnumerationResults>"#;

    const GCS_EMPTY: &str = r#"{"kind": "storage#objects"}"#;
    const GCS_WITH_ITEM: &str = r#"{"kind": "storage#objects", "items": [{"name": "a.txt"}]}"#;

    #[test]
    fn http_403_access_denied_is_not_public_s3() {
        let class = classify_object_storage(403, S3_DENIED);
        assert_eq!(class, StorageListingClass::ExistsDenied);
        assert!(!class.is_public_data());
        assert!(storage_claim_matches_evidence(
            "AWS S3 exists (access denied — listing forbidden)",
            403,
            class
        ));
        assert!(storage_claim_matches_evidence(
            "AWS S3 exists (access denied — not public)",
            403,
            class
        ));
        assert!(!storage_claim_matches_evidence(
            "Public S3 bucket",
            403,
            class
        ));
    }

    #[test]
    fn http_401_is_not_public_storage() {
        let class = classify_object_storage(401, S3_DENIED);
        assert_eq!(class, StorageListingClass::ExistsDenied);
        assert!(!storage_claim_matches_evidence(
            "Public GCS bucket",
            401,
            class
        ));
    }

    #[test]
    fn empty_s3_listing_is_not_public() {
        let class = classify_object_storage(200, S3_EMPTY);
        assert_eq!(class, StorageListingClass::AnonymousListEmpty);
        assert!(!class.is_public_data());
        assert_eq!(s3_listing_object_count(S3_EMPTY), Some(0));
        assert!(!storage_claim_matches_evidence(
            "Public S3 bucket (anonymously listable)",
            200,
            class
        ));
        assert!(storage_claim_matches_evidence(
            "AWS S3 anonymous LIST permitted (empty listing)",
            200,
            class
        ));
    }

    #[test]
    fn s3_listing_with_contents_is_public() {
        let class = classify_object_storage(200, S3_WITH_OBJECT);
        assert_eq!(class, StorageListingClass::PublicObjects);
        assert_eq!(s3_listing_object_count(S3_WITH_OBJECT), Some(1));
        assert!(storage_claim_matches_evidence(
            "Public AWS S3 objects listable",
            200,
            class
        ));
    }

    #[test]
    fn azure_empty_blobs_wrapper_is_not_public() {
        let class = classify_object_storage(200, AZURE_EMPTY);
        assert_eq!(class, StorageListingClass::AnonymousListEmpty);
        assert_eq!(azure_blob_object_count(AZURE_EMPTY), Some(0));
    }

    #[test]
    fn azure_blob_object_is_public() {
        let class = classify_object_storage(200, AZURE_WITH_BLOB);
        assert_eq!(class, StorageListingClass::PublicObjects);
        assert_eq!(azure_blob_object_count(AZURE_WITH_BLOB), Some(1));
    }

    #[test]
    fn gcs_empty_kind_is_not_public() {
        let class = classify_object_storage(200, GCS_EMPTY);
        assert_eq!(class, StorageListingClass::AnonymousListEmpty);
    }

    #[test]
    fn gcs_items_are_public() {
        let class = classify_object_storage(200, GCS_WITH_ITEM);
        assert_eq!(class, StorageListingClass::PublicObjects);
    }

    #[test]
    fn storage_403_without_denied_marker_is_waf_not_bucket() {
        let class = classify_object_storage(403, "<html>Attention Required! Cloudflare</html>");
        assert_eq!(class, StorageListingClass::WafOrUnrelated);
        assert!(storage_finding("x", "AWS S3", "u", 403, "<html>cf</html>", "t", class).is_none());
    }

    #[test]
    fn graphql_403_echoing_schema_is_not_introspection() {
        let echo = r#"{"query":"{__schema{types{name fields{name}}}}"}"#;
        let class = classify_graphql_response(403, echo);
        assert_eq!(class, GraphqlResponseClass::EchoOrUnrelated);
        assert!(!class.is_public_introspection());
        assert!(!graphql_claim_matches_evidence(
            "GraphQL introspection enabled",
            403,
            class
        ));
        let html_echo = "<html>blocked __schema types</html>";
        let class = classify_graphql_response(403, html_echo);
        assert_eq!(class, GraphqlResponseClass::EchoOrUnrelated);
        assert!(!class.is_public_introspection());
        assert!(graphql_finding(ENGINE_ID, "u", 403, echo, "t", class).is_none());
    }

    #[test]
    fn graphql_403_generic_html_is_not_graphql() {
        let class = classify_graphql_response(403, "<html>403 Forbidden</html>");
        assert_eq!(class, GraphqlResponseClass::NotGraphQL);
        assert!(graphql_finding(
            ENGINE_ID,
            "u",
            403,
            "<html>403 Forbidden</html>",
            "t",
            class
        )
        .is_none());
    }

    #[test]
    fn title_negation_does_not_assert_public_or_leak() {
        assert!(!title_asserts_public(
            "AWS S3 exists (access denied — not public)"
        ));
        assert!(!title_asserts_public(
            "S3 anonymous LIST empty (not public data)"
        ));
        assert!(title_asserts_public("Public S3 objects listable"));
        assert!(!title_asserts_leak(
            "OpenAPI document reachable (0 paths — not an inventory leak)"
        ));
        assert!(title_asserts_leak("OpenAPI inventory leak"));
        assert!(!title_asserts_exposed("API spec authentication-gated"));
    }

    #[test]
    fn graphql_401_is_gated_not_public() {
        let class = classify_graphql_response(401, r#"{"errors":[{"message":"Unauthorized"}]}"#);
        assert_eq!(class, GraphqlResponseClass::AuthGated);
        assert!(graphql_claim_matches_evidence(
            "GraphQL endpoint authentication-gated (HTTP 401)",
            401,
            class
        ));
    }

    #[test]
    fn graphql_200_schema_is_introspection() {
        let body =
            r#"{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}}"#;
        let class = classify_graphql_response(200, body);
        assert_eq!(class, GraphqlResponseClass::IntrospectionPublic);
        assert!(graphql_claim_matches_evidence(
            "GraphQL introspection enabled (unauthenticated)",
            200,
            class
        ));
    }

    #[test]
    fn graphql_200_html_echo_is_not_graphql() {
        let class = classify_graphql_response(200, "<html>query {__schema{types{name}}}</html>");
        assert_eq!(class, GraphqlResponseClass::EchoOrUnrelated);
        assert!(!class.is_public_introspection());
    }

    #[test]
    fn graphql_finding_omits_public_on_403() {
        let f = graphql_finding(
            ENGINE_ID,
            "https://t.example/graphql",
            403,
            S3_DENIED,
            "t.example",
            GraphqlResponseClass::AuthGated,
        )
        .unwrap();
        let title = f["title"].as_str().unwrap().to_ascii_lowercase();
        assert!(!title.contains("public"));
        assert!(!title.contains("introspection enabled"));
        assert_eq!(f["http_status"], 403);
        assert_eq!(f["evidence_matches_claim"], true);
    }

    #[test]
    fn openapi_403_is_not_exposed_spec() {
        let class = classify_openapi(403, r#"{"openapi":"3.0.0","paths":{"/users":{}}}"#);
        assert_eq!(class, OpenApiClass::AuthGated);
        assert!(!openapi_claim_matches_evidence(
            "Exposed Swagger/OpenAPI spec",
            403,
            class
        ));
        let f = openapi_finding(
            ENGINE_ID,
            "u",
            403,
            r#"{"openapi":"3.0.0","paths":{"/users":{}}}"#,
            "t",
            class,
        )
        .unwrap();
        let title = f["title"].as_str().unwrap().to_ascii_lowercase();
        assert!(!title.contains("public"));
        assert!(!title.contains("exposed"));
        assert_eq!(f["http_status"], 403);
    }

    #[test]
    fn openapi_403_html_is_not_spec() {
        let class = classify_openapi(403, "<html>forbidden</html>");
        assert_eq!(class, OpenApiClass::NotOpenApi);
        assert!(
            openapi_finding(ENGINE_ID, "u", 403, "<html>forbidden</html>", "t", class).is_none()
        );
    }

    #[test]
    fn openapi_200_html_paths_substring_is_not_spec() {
        let class = classify_openapi(
            200,
            r#"<html><script>const x = {"paths": "/foo"}</script></html>"#,
        );
        assert_ne!(class, OpenApiClass::PublicSpec);
    }

    #[test]
    fn openapi_200_structural_spec_is_public() {
        let body = r#"{"openapi":"3.0.0","paths":{"/users":{"get":{}},"/orders":{"get":{}}}}"#;
        let class = classify_openapi(200, body);
        assert_eq!(class, OpenApiClass::PublicSpec);
        assert_eq!(parse_openapi_inventory(body), Some((2, "3.0.0".into())));
        let f =
            openapi_finding(ENGINE_ID, "https://t/openapi.json", 200, body, "t", class).unwrap();
        assert!(f["title"].as_str().unwrap().contains("2 paths"));
        assert_eq!(f["evidence_matches_claim"], true);
    }

    #[test]
    fn openapi_empty_paths_is_not_inventory_leak() {
        let body = r#"{"openapi":"3.1.0","paths":{}}"#;
        let class = classify_openapi(200, body);
        assert_eq!(class, OpenApiClass::PublicSpec);
        let f = openapi_finding(ENGINE_ID, "u", 200, body, "t", class).unwrap();
        let title = f["title"].as_str().unwrap().to_ascii_lowercase();
        assert!(title.contains("0 paths"));
        assert!(!title.contains("leak"));
        assert_eq!(f["severity"], "info");
    }

    #[test]
    fn storage_finding_403_never_says_public() {
        let f = storage_finding(
            ENGINE_ID,
            "AWS S3",
            "https://acme.s3.amazonaws.com/",
            403,
            S3_DENIED,
            "acme.com",
            StorageListingClass::ExistsDenied,
        )
        .unwrap();
        let title = f["title"].as_str().unwrap().to_ascii_lowercase();
        assert!(!title.contains("public"));
        assert_eq!(f["http_status"], 403);
        assert_eq!(f["classification"], "exists_access_denied");
        assert_eq!(f["evidence_matches_claim"], true);
    }

    #[test]
    fn storage_finding_empty_listing_never_says_public() {
        let f = storage_finding(
            ENGINE_ID,
            "AWS S3",
            "https://acme.s3.amazonaws.com/",
            200,
            S3_EMPTY,
            "acme.com",
            StorageListingClass::AnonymousListEmpty,
        )
        .unwrap();
        let title = f["title"].as_str().unwrap().to_ascii_lowercase();
        assert!(!title.contains("public"));
        assert_eq!(f["object_count"], 0);
    }

    #[test]
    fn loopback_hosts_skip_cloud_dns() {
        assert!(host_is_loopback_or_ip("127.0.0.1"));
        assert!(host_is_loopback_or_ip("localhost"));
        assert!(!host_is_loopback_or_ip("acme.example"));
    }

    #[tokio::test]
    async fn live_403_echo_is_never_public_graphql_or_openapi() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let body = br#"{"query":"{__schema{types{name fields{name}}}}"}"#;
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.write_all(body).await;
            }
        });
        let url = format!("http://127.0.0.1:{}", addr.port());
        let result = run_api_cloud_intel_result(&url).await;
        assert!(result.success, "{}", result.message);
        for f in &result.findings {
            let title = f
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            assert!(
                !title.contains("introspection enabled"),
                "403 echo must not be labelled introspection: {title}"
            );
            assert!(
                !title.contains("public"),
                "403 must not be labelled public: {title}"
            );
            if let Some(st) = f.get("http_status").and_then(Value::as_u64) {
                assert!(
                    st != 401 && st != 403 || !title.contains("exposed"),
                    "401/403 titled exposed: {title}"
                );
            }
        }
    }
}
