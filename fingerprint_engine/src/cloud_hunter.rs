//! Module 3: Graph-Theory ASM & Cloud Misconfiguration Hunter.
//! DNS CNAME resolution, dangling DNS (subdomain takeover), exposed S3/Azure storage.
//! Produces nodes and edges for the Attack Surface Graph. No mock data.

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{net::runtime::TokioRuntimeProvider, TokioResolver};
use serde::{Deserialize, Serialize};

const CLOUD_HUNTER_PROBE_DEPTH: &str = "cloud_dns_surface";

fn cloud_hunter_finding(
    subtype: &str,
    asset: &str,
    value: &str,
    severity: &str,
    title: &str,
    cname_target: Option<&str>,
) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "type": "cloud_hunter",
        "subtype": subtype,
        "asset": asset,
        "value": value,
        "severity": severity,
        "title": title,
        "probe_depth": CLOUD_HUNTER_PROBE_DEPTH,
    });
    if let Some(cname) = cname_target {
        if let Some(map) = obj.as_object_mut() {
            map.insert("cname_target".to_string(), serde_json::json!(cname));
        }
    }
    obj
}

/// Known CNAME suffixes that are common subdomain takeover targets when the target service is gone.
const TAKEOVER_CNAME_SUFFIXES: &[&str] = &[
    // AWS S3
    ".s3.amazonaws.com",
    ".s3-website.",
    ".s3-website-",
    ".s3.",
    // GitHub / Bitbucket
    ".github.io",
    ".bitbucket.io",
    // Heroku
    ".herokuapp.com",
    ".herokuspace.com",
    // Azure
    ".azurewebsites.net",
    ".cloudapp.net",
    ".cloudapp.azure.com",
    ".blob.core.windows.net",
    ".azure-api.net",
    ".trafficmanager.net",
    ".azurecontainer.io",
    ".azurehdinsight.net",
    ".azureedge.net",
    // Zendesk / Help tools
    ".zendesk.com",
    ".helpscoutdocs.com",
    // CDN / PaaS
    ".fastly.net",
    ".cloudfront.net", // only if no default cert / NX
    // Ghost / CMS
    ".ghost.io",
    // Platform hosting
    ".cargo.run",
    ".pantheonsite.io",
    ".surge.sh",
    // Modern PaaS (high-frequency takeover targets)
    ".netlify.app",
    ".netlify.com",
    ".vercel.app",
    ".vercel.com",
    ".fly.dev",
    ".render.com",
    ".railway.app",
    ".onrender.com",
    ".adaptable.app",
    // Website builders
    ".webflow.io",
    ".squarespace.com",
    ".wixsite.com",
    ".strikingly.com",
    ".pagecloud.com",
    // Docs / dev tools
    ".readthedocs.io",
    ".gitbook.io",
    // E-commerce
    ".myshopify.com",
    ".bigcartel.com",
    // Comms / CRM
    ".freshdesk.com",
    ".desk.com",
    ".uservoice.com",
    ".intercom.io",
];

/// S3 / GCS / Azure markers are classified in `api_cloud_intel` (public = listing + objects).
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
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::default(),
        TokioRuntimeProvider::default(),
    )
    .build()
    .ok()?;
    let lookup = match resolver.lookup(domain.as_str(), RecordType::CNAME).await {
        Ok(l) => l,
        Err(_) => return None,
    };
    for record in lookup.answers() {
        let hickory_resolver::proto::rr::RData::CNAME(cname) = &record.data else {
            continue;
        };
        let target = cname
            .to_string()
            .to_lowercase()
            .trim_end_matches('.')
            .to_string();
        if !target.is_empty() {
            return Some(target);
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
    let resolver = match TokioResolver::builder_with_config(
        ResolverConfig::default(),
        TokioRuntimeProvider::default(),
    )
    .build()
    {
        Ok(r) => r,
        Err(_) => return false,
    };
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
        // AWS S3
        "no such bucket",
        "the specified bucket does not exist",
        "nosuchbucket",
        // GitHub Pages
        "there isn't a github pages site here",
        "404 | github pages",
        // Heroku
        "no such app",
        "heroku | no such app",
        "no app configured at that hostname",
        // Azure
        "the requested url was not found",
        "azure web app",
        "404 - file or directory not found",
        "web app not found",
        // Netlify
        "not found - request id",
        "site not found",
        // Vercel
        "the deployment could not be found",
        "this deployment does not exist",
        "404: this page could not be found",
        // Fly.dev
        "fly.io - 404",
        // Render
        "service not found",
        // Fastly / CDN
        "you're almost done",
        "domain not configured",
        "this site is temporarily unavailable",
        // Pantheon
        "404 error unknown site",
        // Zendesk
        "help center closed",
        // Generic
        "repository not found",
        "sorry, this shop is currently unavailable",
        "project not found",
        "this page is no longer active",
    ];
    error_phrases.iter().any(|p| body_lower.contains(p))
}

/// Check if response is public bucket/blob listing (S3 or Azure).
/// 401/403 and empty listings (ListBucketResult with no objects) are not public.
fn is_list_bucket_response(body: &str, status: u16) -> bool {
    crate::api_cloud_intel::classify_object_storage(status, body).is_public_data()
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
            crate::stealth_engine::apply_jitter(s).await;
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
            crate::stealth_engine::apply_jitter(s).await;
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
                Err(_) => (false, false),
            };

            if takeover {
                findings.push(cloud_hunter_finding(
                    "subdomain_takeover",
                    "subdomain",
                    &sub,
                    "critical",
                    "Dangling DNS / Subdomain Takeover",
                    Some(&cname_lower),
                ));
            }
            if exposed {
                findings.push(cloud_hunter_finding(
                    "public_cloud_exposure",
                    "storage",
                    &sub,
                    "critical",
                    "Public Cloud Storage / Directory Listing",
                    Some(&cname_lower),
                ));
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
                findings.push(cloud_hunter_finding(
                    "public_cloud_exposure",
                    "storage",
                    &sub,
                    "critical",
                    "Public Cloud Storage / Directory Listing",
                    None,
                ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_id_replaces_separators() {
        assert_eq!(sanitize_id("a.b.com"), "a_b_com");
        assert_eq!(sanitize_id("host:80/path?x#y"), "host_80_path_x_y");
    }

    #[test]
    fn takeover_suffix_matches_known_providers() {
        assert!(is_known_takeover_suffix("myapp.herokuapp.com"));
        assert!(is_known_takeover_suffix("bucket.s3.amazonaws.com"));
        assert!(is_known_takeover_suffix("SITE.NETLIFY.APP")); // case-insensitive
        assert!(is_known_takeover_suffix("  x.vercel.app  ")); // trimmed
        assert!(!is_known_takeover_suffix("example.com"));
        assert!(!is_known_takeover_suffix(""));
    }

    #[test]
    fn provider_error_page_requires_error_status_and_phrase() {
        assert!(is_provider_error_page("...NoSuchBucket...", 404));
        assert!(is_provider_error_page(
            "There isn't a GitHub Pages site here",
            404
        ));
        // Right phrase but 200 status -> not an error page.
        assert!(!is_provider_error_page("no such bucket", 200));
        // Error status but no known phrase.
        assert!(!is_provider_error_page("generic not found", 404));
    }

    #[test]
    fn list_bucket_response_only_on_200_with_objects() {
        assert!(is_list_bucket_response(
            "<ListBucketResult><Contents><Key>a</Key></Contents>",
            200
        ));
        assert!(is_list_bucket_response(
            "{\"kind\": \"storage#objects\", \"items\": [{\"name\": \"a\"}]}",
            200
        ));
        // 403 AccessDenied is existence, not public.
        assert!(!is_list_bucket_response("<ListBucketResult>", 403));
        assert!(!is_list_bucket_response(
            "<Error><Code>AccessDenied</Code></Error>",
            403
        ));
        // Empty listing envelope is not public data.
        assert!(!is_list_bucket_response(
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>x</Name></ListBucketResult>",
            200
        ));
        assert!(!is_list_bucket_response("plain page", 200));
    }

    #[test]
    fn cloud_hunter_finding_shape_and_optional_cname() {
        let f = cloud_hunter_finding(
            "subdomain_takeover",
            "subdomain",
            "x.example.com",
            "critical",
            "Dangling DNS",
            Some("x.herokuapp.com"),
        );
        assert_eq!(f["type"], "cloud_hunter");
        assert_eq!(f["subtype"], "subdomain_takeover");
        assert_eq!(f["severity"], "critical");
        assert_eq!(f["probe_depth"], CLOUD_HUNTER_PROBE_DEPTH);
        assert_eq!(f["cname_target"], "x.herokuapp.com");
        // Without a cname target the key is absent.
        let f2 = cloud_hunter_finding(
            "public_cloud_exposure",
            "storage",
            "y",
            "critical",
            "T",
            None,
        );
        assert!(f2.get("cname_target").is_none());
    }

    #[test]
    fn graph_node_skips_none_optionals_in_json() {
        let n = GraphNode {
            id: "n1".into(),
            label: "example.com".into(),
            node_type: "root".into(),
            status: "secure".into(),
            cname_target: None,
            raw_finding: None,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&n).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj["node_type"], "root");
        assert!(!obj.contains_key("cname_target"));
        assert!(!obj.contains_key("raw_finding"));
    }

    #[test]
    fn graph_edge_roundtrips() {
        let e = GraphEdge {
            id: "e-a-b".into(),
            from_id: "a".into(),
            to_id: "b".into(),
            edge_type: "CNAME".into(),
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(v["edge_type"], "CNAME");
        assert_eq!(v["from_id"], "a");
    }
}
