//! Module 3: Graph-Theory ASM & Cloud Misconfiguration Hunter.
//! DNS CNAME resolution, dangling DNS (subdomain takeover), exposed S3/Azure storage.
//! Produces nodes and edges for the Attack Surface Graph. No mock data.

use serde::{Deserialize, Serialize};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::TokioAsyncResolver;

/// Known CNAME suffixes that are common subdomain takeover targets when the target service is gone.
const TAKEOVER_CNAME_SUFFIXES: &[&str] = &[
    ".s3.amazonaws.com",
    ".s3-website.",
    ".s3-website-",
    ".s3.",
    ".github.io",
    ".herokuapp.com",
    ".herokuspace.com",
    ".azurewebsites.net",
    ".cloudapp.net",
    ".cloudapp.azure.com",
    ".blob.core.windows.net",
    ".azure-api.net",
    ".trafficmanager.net",
    ".zendesk.com",
    ".fastly.net",
    ".ghost.io",
    ".helpscoutdocs.com",
    ".cargo.run",
    ".pantheonsite.io",
    ".surge.sh",
    ".bitbucket.io",
    ".azurecontainer.io",
    ".cloudfront.net", // only if no default cert / NX
];

/// S3 ListBucketResult and Azure EnumerationResults indicate public directory listing.
const LIST_BUCKET_MARKERS: &[&str] = &[
    "ListBucketResult",
    "ListBlobResult",
    "EnumerationResults",
    "<Contents>",
    "<Blob>",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String, // "root" | "subdomain" | "cloud_target"
    pub status: String,    // "secure" | "exposed" | "takeover"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_finding: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub from_id: String,
    pub to_id: String,
    pub edge_type: String, // "CNAME" | "RESOLVES_TO"
}

/// Resolve CNAME for a domain. Returns the target hostname if CNAME exists (lowercased, no trailing dot).
pub async fn resolve_cname(domain: &str) -> Option<String> {
    let domain = domain.trim().to_lowercase();
    if domain.is_empty() {
        return None;
    }
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let lookup = match resolver.lookup(domain.as_str(), RecordType::CNAME).await {
        Ok(l) => l,
        Err(_) => return None,
    };
    for record in lookup.record_iter() {
        if let Some(trust_dns_resolver::proto::rr::RData::CNAME(cname)) = record.data() {
            let target = cname
                .to_string()
                .to_lowercase()
                .trim_end_matches('.')
                .to_string();
            if !target.is_empty() {
                return Some(target);
            }
        }
    }
    None
}

/// Check if the CNAME target is a known takeover-prone suffix.
pub fn is_known_takeover_suffix(cname_target: &str) -> bool {
    let c = cname_target.trim().to_lowercase();
    TAKEOVER_CNAME_SUFFIXES
        .iter()
        .any(|suffix| c.ends_with(suffix.trim_start_matches('.')))
}

/// Resolve A/AAAA for host. Returns true if at least one IP exists.
pub async fn resolve_a(host: &str) -> bool {
    let host = host.trim().to_lowercase();
    if host.is_empty() {
        return false;
    }
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    match resolver.lookup_ip(host).await {
        Ok(lookup) => lookup.iter().next().is_some(),
        Err(_) => false,
    }
}

/// Check if HTTP response body indicates "no app" / "domain not configured" (takeover).
fn is_provider_error_page(body: &str, status: u16) -> bool {
    if status != 404 && status != 400 && status != 502 && status != 503 {
        return false;
    }
    let body_lower = body.to_lowercase();
    let error_phrases = [
        "no such bucket",
        "the specified bucket does not exist",
        "there isn't a github pages site here",
        "no such app",
        "heroku | no such app",
        "the requested url was not found",
        "azure web app",
        "404 - file or directory not found",
        "you're almost done",
        "domain not configured",
        "this site is temporarily unavailable",
        "repository not found",
        "sorry, this shop is currently unavailable",
    ];
    error_phrases.iter().any(|p| body_lower.contains(p))
}

/// Check if response is public bucket/blob listing (S3 or Azure).
fn is_list_bucket_response(body: &str, status: u16) -> bool {
    if status != 200 {
        return false;
    }
    LIST_BUCKET_MARKERS.iter().any(|m| body.contains(m))
}

/// Run cloud hunter: for each subdomain resolve CNAME, check takeover and exposed storage.
/// Returns (nodes, edges, extra findings for vulnerabilities).
pub async fn run_cloud_hunter(
    root_host: &str,
    subdomains: &[String],
    stealth: Option<&crate::stealth_engine::StealthConfig>,
) -> (Vec<GraphNode>, Vec<GraphEdge>, Vec<serde_json::Value>) {
    let root_host = root_host.trim().to_lowercase();
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut findings = Vec::new();

    let root_id = sanitize_id(&root_host);
    nodes.push(GraphNode {
        id: root_id.clone(),
        label: root_host.clone(),
        node_type: "root".to_string(),
        status: "secure".to_string(),
        cname_target: None,
        raw_finding: None,
    });

    let client = match stealth {
        Some(s) => {
            crate::stealth_engine::apply_jitter(s);
            crate::stealth_engine::build_client(s, 10)
        }
        None => reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
    };

    let add_headers =
        |req: reqwest::RequestBuilder, s: Option<&crate::stealth_engine::StealthConfig>| match s {
            Some(cfg) => req.headers(crate::stealth_engine::random_morph_headers(cfg)),
            None => req,
        };

    for sub in subdomains.iter().take(100) {
        let sub = sub.trim().to_lowercase();
        if sub.is_empty() {
            continue;
        }
        if let Some(s) = stealth {
            crate::stealth_engine::apply_jitter(s);
        }

        let cname_target = resolve_cname(&sub).await;
        let sub_id = sanitize_id(&sub);

        let (status, cname_target_opt, raw_finding) = if let Some(ref cname) = cname_target {
            let cname_lower = cname.trim().to_lowercase();
            let cname_id = sanitize_id(&cname_lower);
            let edge_id = format!("e-{}-{}", sub_id, cname_id);
            edges.push(GraphEdge {
                id: edge_id,
                from_id: sub_id.clone(),
                to_id: cname_id,
                edge_type: "CNAME".to_string(),
            });

            let target_resolves = resolve_a(&cname_lower).await;
            let is_takeover_suffix = is_known_takeover_suffix(&cname_lower);

            let url_https = format!("https://{}", sub);
            let req = add_headers(client.get(&url_https), stealth);
            let (takeover, exposed) = match req.send().await {
                Ok(r) => {
                    let status_code = r.status().as_u16();
                    let body = r.text().await.unwrap_or_default();
                    let takeover = is_takeover_suffix
                        && (!target_resolves || is_provider_error_page(&body, status_code));
                    let exposed = is_list_bucket_response(&body, status_code);
                    (takeover, exposed)
                }
                Err(_) => (is_takeover_suffix && !target_resolves, false),
            };

            if takeover {
                findings.push(serde_json::json!({
                    "type": "cloud_hunter",
                    "subtype": "subdomain_takeover",
                    "asset": "subdomain",
                    "value": sub,
                    "cname_target": cname_lower,
                    "severity": "critical",
                    "title": "Dangling DNS / Subdomain Takeover"
                }));
            }
            if exposed {
                findings.push(serde_json::json!({
                    "type": "cloud_hunter",
                    "subtype": "public_cloud_exposure",
                    "asset": "storage",
                    "value": sub,
                    "cname_target": cname_lower,
                    "severity": "critical",
                    "title": "Public Cloud Storage / Directory Listing"
                }));
            }

            let status = if takeover {
                "takeover".to_string()
            } else if exposed {
                "exposed".to_string()
            } else {
                "secure".to_string()
            };
            let rf = if takeover || exposed {
                Some(
                    serde_json::json!({ "cname": cname_lower, "takeover": takeover, "exposed": exposed }),
                )
            } else {
                None
            };
            (status, Some(cname_lower.clone()), rf)
        } else {
            let url_https = format!("https://{}", sub);
            let req = add_headers(client.get(&url_https), stealth);
            let exposed = match req.send().await {
                Ok(r) => {
                    let status_code = r.status().as_u16();
                    let body = r.text().await.unwrap_or_default();
                    is_list_bucket_response(&body, status_code)
                }
                Err(_) => false,
            };
            if exposed {
                findings.push(serde_json::json!({
                    "type": "cloud_hunter",
                    "subtype": "public_cloud_exposure",
                    "asset": "storage",
                    "value": sub,
                    "severity": "critical",
                    "title": "Public Cloud Storage / Directory Listing"
                }));
            }
            let status = if exposed {
                "exposed".to_string()
            } else {
                "secure".to_string()
            };
            (
                status,
                None,
                if exposed {
                    Some(serde_json::json!({"exposed": true}))
                } else {
                    None
                },
            )
        };

        nodes.push(GraphNode {
            id: sub_id.clone(),
            label: sub.clone(),
            node_type: "subdomain".to_string(),
            status: status.clone(),
            cname_target: cname_target_opt,
            raw_finding: raw_finding,
        });

        if let Some(ref cname) = cname_target {
            let cname_id = sanitize_id(cname);
            if !nodes.iter().any(|n| n.id == cname_id) {
                nodes.push(GraphNode {
                    id: cname_id.clone(),
                    label: cname.clone(),
                    node_type: "cloud_target".to_string(),
                    status: "secure".to_string(),
                    cname_target: None,
                    raw_finding: None,
                });
            }
        }
    }

    (nodes, edges, findings)
}

fn sanitize_id(s: &str) -> String {
    s.replace('.', "_").replace(['/', ':', '?', '#'], "_")
}
