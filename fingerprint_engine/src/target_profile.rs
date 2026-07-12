//! Target Intelligence & Engine-Selection Engine.
//!
//! Given a single scan target this module deterministically derives a rich
//! profile — **what** it is (asset class, service, technology), **where** it
//! lives (network class, hosting / cloud / CDN provenance, geo & registry hints
//! from the TLD), **who** owns it (registrable domain, managed platform,
//! attribution evidence) and **why** it matters (sensitivity tier) — and then
//! **selects and prioritizes** the engine set most relevant to that profile,
//! backed by the *authoritative* engine→group taxonomy (`engine_requirements`).
//!
//! Design contract:
//! * **Pure & deterministic.** The passive tier derives everything from the
//!   target string plus the embedded engine catalog. There is no DNS / network
//!   I/O on this hot path, so `classify` is cheap, side-effect-free and safe to
//!   call per job. Active enrichment (DNS, ASN, TLS certificate, banners) layers
//!   on top via probe engines; the structured fields here are the seed.
//! * **Reorder-first, never blind-drop.** `prioritize` reorders the engine list
//!   so the most relevant engines run first but keeps *every* engine — full
//!   coverage is preserved, nothing is silently pruned. `select` additionally
//!   exposes a *recommended focus set* and a per-engine rationale for
//!   explainability ("this is what the target is, and this is why we picked
//!   these engines").
//! * **Backwards compatible.** The original public surface (`TargetProfile`
//!   fields `host/scheme/port/ip_family/is_private/hints`, `IpFamily`,
//!   `classify`, `relevance`, `prioritize`) is preserved so existing callers and
//!   tests are unaffected; the deep intelligence is additive.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::engine_requirements;

// ---------------------------------------------------------------------------
// Core enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

/// Where, on the network, the literal address sits (only meaningful for literal
/// IP targets; hostnames are `Unknown` until actively resolved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkClass {
    #[default]
    Unknown,
    /// Globally routable.
    Public,
    /// RFC 1918 (10/8, 172.16/12, 192.168/16).
    PrivateRfc1918,
    Loopback,
    LinkLocal,
    /// Carrier-grade NAT, RFC 6598 (100.64/10).
    Cgnat,
    /// Documentation / example ranges (RFC 5737 / RFC 3849).
    Documentation,
    Multicast,
    /// IPv6 unique-local (fc00::/7).
    UniqueLocalV6,
    Unspecified,
}

/// Coarse registry / geopolitical class of the target's top-level domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TldClass {
    #[default]
    Unknown,
    Generic,
    CountryCode,
    Government,
    Military,
    Education,
    Financial,
    Infrastructure,
    /// Tor hidden service (`.onion`).
    Onion,
    /// RFC 6762 / RFC 8375 internal namespaces (`.local`, `.internal`, `.home.arpa`).
    Internal,
}

/// Synthesised primary classification of the asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AssetClass {
    #[default]
    Unknown,
    WebApp,
    ApiEndpoint,
    NetworkHost,
    MailServer,
    NameServer,
    Database,
    RemoteAccess,
    CloudService,
    ObjectStore,
    IdentityProvider,
    AiEndpoint,
    OtDevice,
}

impl AssetClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AssetClass::Unknown => "unknown",
            AssetClass::WebApp => "web_app",
            AssetClass::ApiEndpoint => "api_endpoint",
            AssetClass::NetworkHost => "network_host",
            AssetClass::MailServer => "mail_server",
            AssetClass::NameServer => "name_server",
            AssetClass::Database => "database",
            AssetClass::RemoteAccess => "remote_access",
            AssetClass::CloudService => "cloud_service",
            AssetClass::ObjectStore => "object_store",
            AssetClass::IdentityProvider => "identity_provider",
            AssetClass::AiEndpoint => "ai_endpoint",
            AssetClass::OtDevice => "ot_device",
        }
    }
}

/// How much care the engagement owes this asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sensitivity {
    #[default]
    Standard,
    Elevated,
    Critical,
}

impl Sensitivity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Sensitivity::Standard => "standard",
            Sensitivity::Elevated => "elevated",
            Sensitivity::Critical => "critical",
        }
    }
}

/// Coarse category of an inferred L7 service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    Web,
    Tls,
    Mail,
    Dns,
    Database,
    RemoteAccess,
    Ldap,
    Smb,
    Ot,
    FileTransfer,
    Other,
}

/// An inferred service (from scheme / well-known port).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    pub port: u16,
    pub name: &'static str,
    pub kind: ServiceKind,
}

// ---------------------------------------------------------------------------
// Provenance ("who / where")
// ---------------------------------------------------------------------------

/// Attribution & hosting provenance derived from the target string.
#[derive(Debug, Clone, Default)]
pub struct Provenance {
    /// eTLD+1 (registrable domain) via the embedded public-suffix set.
    pub registrable_domain: Option<String>,
    /// Sub-domain labels below the registrable domain, if any.
    pub subdomain: Option<String>,
    /// Effective public suffix (eTLD), e.g. `com`, `co.uk`.
    pub public_suffix: Option<String>,
    pub tld_class: TldClass,
    /// Where the asset appears to be hosted, if a known platform suffix matched.
    pub hosting_provider: Option<&'static str>,
    /// Category of the hosting platform (`cloud` | `cdn` | `object-store` | `saas`).
    pub hosting_category: Option<&'static str>,
    pub network_class: NetworkClass,
    /// Internationalised domain (contains non-ASCII or punycode labels).
    pub idn: bool,
    /// Mixed-script label — a classic homograph / spoofing signal.
    pub homograph_risk: bool,
    /// IPs the host actively resolved to (populated by `enrich_dns`; empty until
    /// active enrichment runs).
    pub resolved_ips: Vec<IpAddr>,
    /// Human-readable "why we concluded this" trail.
    pub evidence: Vec<String>,
}

// ---------------------------------------------------------------------------
// TargetProfile
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct TargetProfile {
    // --- backwards-compatible core surface ---
    pub host: String,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub ip_family: Option<IpFamily>,
    pub is_private: bool,
    /// Coarse class hints: "ip" | "hostname" | "web" | "tls" | "network".
    pub hints: Vec<&'static str>,

    // --- deep classification (additive) ---
    /// URL path (when the target was a URL), lower-cased; drives path signals.
    pub path: Option<String>,
    pub asset_class: AssetClass,
    pub service: Option<Service>,
    pub sensitivity: Sensitivity,
    pub provenance: Provenance,
    /// Rich structured facets (superset of `hints`) used by the selector and
    /// surfaced for explainability.
    pub facets: Vec<&'static str>,
    /// Overall classification confidence, 0..=100.
    pub confidence: u8,
}

// ---------------------------------------------------------------------------
// Static knowledge tables
// ---------------------------------------------------------------------------

/// The full Public Suffix List (publicsuffix.org), normalized to ASCII a-labels
/// and embedded at build time. `*.x` marks a wildcard rule, `!x` an exception;
/// ICANN + PRIVATE sections are merged (browser eTLD+1 semantics).
static PUBLIC_SUFFIX_LIST: &str = include_str!("../../shared/public_suffix_list.psl");

/// Parsed PSL: exact rules, wildcard tails (the part after `*.`), and exception
/// tails (the part after `!`). Built once from the embedded list.
struct PslData {
    rules: std::collections::HashSet<&'static str>,
    wildcards: std::collections::HashSet<&'static str>,
    exceptions: std::collections::HashSet<&'static str>,
}

fn psl() -> &'static PslData {
    static PSL: std::sync::OnceLock<PslData> = std::sync::OnceLock::new();
    PSL.get_or_init(|| {
        let mut rules = std::collections::HashSet::new();
        let mut wildcards = std::collections::HashSet::new();
        let mut exceptions = std::collections::HashSet::new();
        for line in PUBLIC_SUFFIX_LIST.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            if let Some(exc) = line.strip_prefix('!') {
                exceptions.insert(exc);
            } else if let Some(tail) = line.strip_prefix("*.") {
                wildcards.insert(tail);
            } else {
                rules.insert(line);
            }
        }
        PslData {
            rules,
            wildcards,
            exceptions,
        }
    })
}

/// Managed-hosting suffixes → (provider, category). Category ∈
/// `cloud` | `cdn` | `object-store` | `saas`. Longest match wins.
static HOSTING_SUFFIXES: &[(&str, &str, &str)] = &[
    // AWS
    ("s3.amazonaws.com", "Amazon S3", "object-store"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk", "cloud"),
    ("cloudfront.net", "Amazon CloudFront", "cdn"),
    ("awsapps.com", "Amazon Web Services", "cloud"),
    ("amazonaws.com", "Amazon Web Services", "cloud"),
    (
        "awsglobalaccelerator.com",
        "AWS Global Accelerator",
        "cloud",
    ),
    // Azure
    (
        "blob.core.windows.net",
        "Azure Blob Storage",
        "object-store",
    ),
    ("azurewebsites.net", "Azure App Service", "cloud"),
    ("azure-api.net", "Azure API Management", "cloud"),
    ("azureedge.net", "Azure CDN", "cdn"),
    ("cloudapp.azure.com", "Microsoft Azure", "cloud"),
    ("trafficmanager.net", "Azure Traffic Manager", "cloud"),
    ("azurecontainer.io", "Azure Container Instances", "cloud"),
    ("sharepoint.com", "Microsoft SharePoint", "saas"),
    // Google / Firebase
    (
        "storage.googleapis.com",
        "Google Cloud Storage",
        "object-store",
    ),
    ("appspot.com", "Google App Engine", "cloud"),
    ("run.app", "Google Cloud Run", "cloud"),
    ("web.app", "Firebase Hosting", "cloud"),
    ("firebaseapp.com", "Firebase Hosting", "cloud"),
    ("googleusercontent.com", "Google", "cloud"),
    ("withgoogle.com", "Google", "cloud"),
    // Cloudflare
    ("pages.dev", "Cloudflare Pages", "cloud"),
    ("workers.dev", "Cloudflare Workers", "cloud"),
    ("r2.dev", "Cloudflare R2", "object-store"),
    ("cloudflare.net", "Cloudflare", "cdn"),
    // Other CDNs / clouds
    ("fastly.net", "Fastly", "cdn"),
    ("akamaiedge.net", "Akamai", "cdn"),
    ("akamai.net", "Akamai", "cdn"),
    ("edgekey.net", "Akamai", "cdn"),
    (
        "digitaloceanspaces.com",
        "DigitalOcean Spaces",
        "object-store",
    ),
    ("ondigitalocean.app", "DigitalOcean App Platform", "cloud"),
    ("herokuapp.com", "Heroku", "cloud"),
    ("herokudns.com", "Heroku", "cloud"),
    ("onrender.com", "Render", "cloud"),
    ("fly.dev", "Fly.io", "cloud"),
    ("netlify.app", "Netlify", "cloud"),
    ("vercel.app", "Vercel", "cloud"),
    ("oraclecloud.com", "Oracle Cloud", "cloud"),
    ("github.io", "GitHub Pages", "cloud"),
    ("githubusercontent.com", "GitHub", "cloud"),
    ("gitlab.io", "GitLab Pages", "cloud"),
    ("azurefd.net", "Azure Front Door", "cdn"),
    ("cloudfunctions.net", "Google Cloud Functions", "cloud"),
    // Identity / SSO providers (IdP) — high-value SSO / federation / phishing
    // surface. Customer tenants live as sub-domains of these (e.g.
    // `acme.okta.com`, `login.microsoftonline.com`), so the registrable-domain
    // suffix match catches them and flags the target as an identity provider.
    ("okta.com", "Okta", "identity"),
    ("oktapreview.com", "Okta", "identity"),
    ("okta-emea.com", "Okta", "identity"),
    ("auth0.com", "Auth0", "identity"),
    ("onelogin.com", "OneLogin", "identity"),
    ("pingidentity.com", "Ping Identity", "identity"),
    ("pingone.com", "Ping Identity", "identity"),
    ("jumpcloud.com", "JumpCloud", "identity"),
    ("duosecurity.com", "Cisco Duo", "identity"),
    ("microsoftonline.com", "Microsoft Entra ID", "identity"),
    ("b2clogin.com", "Azure AD B2C", "identity"),
    ("sts.windows.net", "Microsoft Entra ID (STS)", "identity"),
    // SaaS
    ("myshopify.com", "Shopify", "saas"),
    ("wpengine.com", "WP Engine", "saas"),
    ("wordpress.com", "WordPress.com", "saas"),
    ("squarespace.com", "Squarespace", "saas"),
    ("zendesk.com", "Zendesk", "saas"),
    ("salesforce.com", "Salesforce", "saas"),
    ("force.com", "Salesforce", "saas"),
    ("atlassian.net", "Atlassian", "saas"),
    ("service-now.com", "ServiceNow", "saas"),
];

/// Hostnames whose registrable domain implies source-control / package / CI
/// supply-chain surface.
static SUPPLY_CHAIN_DOMAINS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "npmjs.com",
    "pypi.org",
    "rubygems.org",
    "packagist.org",
    "crates.io",
    "hub.docker.com",
    "quay.io",
    "jfrog.io",
    "nexus.io",
    "circleci.com",
    "travis-ci.com",
    "jenkins.io",
];

/// Well-known port → service. Used to infer the L7 service without probing.
static PORT_SERVICES: &[(u16, &str, ServiceKind)] = &[
    (21, "ftp", ServiceKind::FileTransfer),
    (22, "ssh", ServiceKind::RemoteAccess),
    (23, "telnet", ServiceKind::RemoteAccess),
    (25, "smtp", ServiceKind::Mail),
    (53, "dns", ServiceKind::Dns),
    (80, "http", ServiceKind::Web),
    (110, "pop3", ServiceKind::Mail),
    (139, "netbios-ssn", ServiceKind::Smb),
    (143, "imap", ServiceKind::Mail),
    (389, "ldap", ServiceKind::Ldap),
    (443, "https", ServiceKind::Tls),
    (445, "smb", ServiceKind::Smb),
    (465, "smtps", ServiceKind::Mail),
    (587, "submission", ServiceKind::Mail),
    (636, "ldaps", ServiceKind::Ldap),
    (993, "imaps", ServiceKind::Mail),
    (995, "pop3s", ServiceKind::Mail),
    (1433, "mssql", ServiceKind::Database),
    (1521, "oracle", ServiceKind::Database),
    (1723, "pptp", ServiceKind::RemoteAccess),
    (2049, "nfs", ServiceKind::FileTransfer),
    (2375, "docker", ServiceKind::Other),
    (2376, "docker-tls", ServiceKind::Other),
    (3000, "http-alt", ServiceKind::Web),
    (3306, "mysql", ServiceKind::Database),
    (3389, "rdp", ServiceKind::RemoteAccess),
    (5000, "http-alt", ServiceKind::Web),
    (5432, "postgresql", ServiceKind::Database),
    (5601, "kibana", ServiceKind::Web),
    (5900, "vnc", ServiceKind::RemoteAccess),
    (5985, "winrm", ServiceKind::RemoteAccess),
    (5986, "winrm-tls", ServiceKind::RemoteAccess),
    (6379, "redis", ServiceKind::Database),
    (8000, "http-alt", ServiceKind::Web),
    (8080, "http-proxy", ServiceKind::Web),
    (8443, "https-alt", ServiceKind::Tls),
    (8888, "http-alt", ServiceKind::Web),
    (9000, "http-alt", ServiceKind::Web),
    (9200, "elasticsearch", ServiceKind::Database),
    (9300, "elasticsearch", ServiceKind::Database),
    (9443, "https-alt", ServiceKind::Tls),
    (10443, "https-alt", ServiceKind::Tls),
    (11211, "memcached", ServiceKind::Database),
    (15672, "rabbitmq", ServiceKind::Other),
    (27017, "mongodb", ServiceKind::Database),
    // OT / ICS
    (102, "iso-tsap-s7", ServiceKind::Ot),
    (502, "modbus", ServiceKind::Ot),
    (789, "redlion", ServiceKind::Ot),
    (1911, "fox-tridium", ServiceKind::Ot),
    (1962, "pcworx", ServiceKind::Ot),
    (2404, "iec-104", ServiceKind::Ot),
    (4840, "opc-ua", ServiceKind::Ot),
    (9600, "omron-fins", ServiceKind::Ot),
    (20000, "dnp3", ServiceKind::Ot),
    (44818, "ethernet-ip", ServiceKind::Ot),
    (47808, "bacnet", ServiceKind::Ot),
];

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    // strip userinfo (user:pass@host)
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // [ipv6]:port
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
    }
    // host:port (only when a single colon — avoids splitting bare IPv6)
    if authority.matches(':').count() == 1 {
        if let Some((h, p)) = authority.split_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h, Some(port));
            }
        }
    }
    (authority, None)
}

fn network_class(ip: IpAddr) -> NetworkClass {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() {
                NetworkClass::Loopback
            } else if v4.is_unspecified() {
                NetworkClass::Unspecified
            } else if v4.is_link_local() {
                NetworkClass::LinkLocal
            } else if v4.is_private() {
                NetworkClass::PrivateRfc1918
            } else if o[0] == 100 && (64..=127).contains(&o[1]) {
                NetworkClass::Cgnat
            } else if v4.is_multicast() {
                NetworkClass::Multicast
            } else if (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
            {
                NetworkClass::Documentation
            } else {
                NetworkClass::Public
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                NetworkClass::Loopback
            } else if v6.is_unspecified() {
                NetworkClass::Unspecified
            } else if v6.is_multicast() {
                NetworkClass::Multicast
            } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                NetworkClass::LinkLocal
            } else if (v6.segments()[0] & 0xfe00) == 0xfc00 {
                NetworkClass::UniqueLocalV6
            } else if v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8 {
                NetworkClass::Documentation
            } else {
                NetworkClass::Public
            }
        }
    }
}

fn is_private_class(nc: NetworkClass) -> bool {
    matches!(
        nc,
        NetworkClass::PrivateRfc1918
            | NetworkClass::Loopback
            | NetworkClass::LinkLocal
            | NetworkClass::UniqueLocalV6
    )
}

/// Curated, high-confidence CDN/edge IPv4 ranges for attributing *who hosts a
/// target* from its resolved IP when the hostname is opaque — a custom domain
/// fronted by a CDN, the exact case where the passive string tier is blind.
///
/// Deliberately limited to ranges that are **small, stable, and published by the
/// operator** (Cloudflare and Fastly). Large, frequently-churning cloud ranges
/// (AWS/GCP/Azure) are intentionally omitted rather than risk stale or wrong
/// attribution — an honest curated seed, not an exhaustive IP-to-ASN map. Values
/// are `(network octets, prefix, provider, category)`.
static CDN_V4_RANGES: &[([u8; 4], u8, &str, &str)] = &[
    // Cloudflare — https://www.cloudflare.com/ips-v4 (stable for years).
    ([173, 245, 48, 0], 20, "Cloudflare", "cdn"),
    ([103, 21, 244, 0], 22, "Cloudflare", "cdn"),
    ([103, 22, 200, 0], 22, "Cloudflare", "cdn"),
    ([103, 31, 4, 0], 22, "Cloudflare", "cdn"),
    ([141, 101, 64, 0], 18, "Cloudflare", "cdn"),
    ([108, 162, 192, 0], 18, "Cloudflare", "cdn"),
    ([190, 93, 240, 0], 20, "Cloudflare", "cdn"),
    ([188, 114, 96, 0], 20, "Cloudflare", "cdn"),
    ([197, 234, 240, 0], 22, "Cloudflare", "cdn"),
    ([198, 41, 128, 0], 17, "Cloudflare", "cdn"),
    ([162, 158, 0, 0], 15, "Cloudflare", "cdn"),
    ([104, 16, 0, 0], 13, "Cloudflare", "cdn"),
    ([104, 24, 0, 0], 14, "Cloudflare", "cdn"),
    ([172, 64, 0, 0], 13, "Cloudflare", "cdn"),
    ([131, 0, 72, 0], 22, "Cloudflare", "cdn"),
    // Fastly — anycast edge (https://api.fastly.com/public-ip-list).
    ([151, 101, 0, 0], 16, "Fastly", "cdn"),
    ([199, 232, 0, 0], 16, "Fastly", "cdn"),
];

/// Curated, high-confidence CDN/edge IPv6 ranges (see [`CDN_V4_RANGES`]).
static CDN_V6_RANGES: &[([u16; 8], u8, &str, &str)] = &[
    // Cloudflare — https://www.cloudflare.com/ips-v6
    ([0x2606, 0x4700, 0, 0, 0, 0, 0, 0], 32, "Cloudflare", "cdn"),
    ([0x2803, 0xf800, 0, 0, 0, 0, 0, 0], 32, "Cloudflare", "cdn"),
    ([0x2405, 0xb500, 0, 0, 0, 0, 0, 0], 32, "Cloudflare", "cdn"),
    ([0x2405, 0x8100, 0, 0, 0, 0, 0, 0], 32, "Cloudflare", "cdn"),
    ([0x2a06, 0x98c0, 0, 0, 0, 0, 0, 0], 29, "Cloudflare", "cdn"),
    ([0x2c0f, 0xf248, 0, 0, 0, 0, 0, 0], 32, "Cloudflare", "cdn"),
    // Fastly
    ([0x2a04, 0x4e40, 0, 0, 0, 0, 0, 0], 32, "Fastly", "cdn"),
];

fn v4_in_cidr(ip: Ipv4Addr, net: [u8; 4], prefix: u8) -> bool {
    let ip = u32::from_be_bytes(ip.octets());
    let net = u32::from_be_bytes(net);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (ip & mask) == (net & mask)
}

fn v6_in_cidr(ip: Ipv6Addr, net: [u16; 8], prefix: u8) -> bool {
    let ip = u128::from(ip);
    let net = net
        .iter()
        .fold(0u128, |acc, seg| (acc << 16) | u128::from(*seg));
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    (ip & mask) == (net & mask)
}

/// Attribute a hosting/CDN provider from a public IP against the curated edge
/// ranges. Returns `(provider, category)` or `None` when the IP is not in a
/// known range (the honest default — no guessing).
fn provider_from_ip(ip: IpAddr) -> Option<(&'static str, &'static str)> {
    match ip {
        IpAddr::V4(v4) => CDN_V4_RANGES
            .iter()
            .find(|(net, pfx, _, _)| v4_in_cidr(v4, *net, *pfx))
            .map(|(_, _, name, kind)| (*name, *kind)),
        IpAddr::V6(v6) => CDN_V6_RANGES
            .iter()
            .find(|(net, pfx, _, _)| v6_in_cidr(v6, *net, *pfx))
            .map(|(_, _, name, kind)| (*name, *kind)),
    }
}

/// Number of labels in the effective public suffix of an ASCII a-label host,
/// per the embedded Public Suffix List (wildcard + exception aware). O(labels):
/// each suffix slice is looked up against the rule sets. Defaults to a single
/// label (the bare TLD) when no rule matches.
fn public_suffix_len(host_ascii: &str) -> usize {
    let labels: Vec<&str> = host_ascii.split('.').collect();
    let n = labels.len();
    if n == 0 {
        return 0;
    }
    // Byte offset in `host_ascii` where each label's suffix slice begins.
    let mut offsets = Vec::with_capacity(n);
    let mut off = 0usize;
    for l in &labels {
        offsets.push(off);
        off += l.len() + 1; // + '.'
    }
    let p = psl();
    // Exception rules win outright: the public suffix is the rule minus its
    // leftmost label.
    for i in 0..n {
        if p.exceptions.contains(&host_ascii[offsets[i]..]) {
            return (n - i).saturating_sub(1).max(1);
        }
    }
    // Longest matching normal/wildcard rule (smallest i => longest suffix).
    for i in 0..n {
        if p.rules.contains(&host_ascii[offsets[i]..]) {
            return n - i;
        }
        // A wildcard rule `*.<suffix(i+1)>` treats label i as the wildcard.
        if i + 1 < n && p.wildcards.contains(&host_ascii[offsets[i + 1]..]) {
            return n - i;
        }
    }
    1
}

/// Lower-case ASCII a-label form of a host (punycode-encodes IDN labels), so the
/// full PSL — which is stored in a-label form — applies to internationalised
/// hostnames too. Falls back to a plain lower-case if idna encoding fails.
fn to_ascii_host(host: &str) -> String {
    if host.is_ascii() {
        host.to_ascii_lowercase()
    } else {
        idna::domain_to_ascii(host).unwrap_or_else(|_| host.to_ascii_lowercase())
    }
}

/// Returns (registrable_domain, subdomain, public_suffix) for a hostname, or
/// `None` for literal IPs / bare public suffixes. IDN hosts are normalized to
/// punycode a-labels first so the full PSL applies.
fn registrable_domain(host: &str) -> Option<(String, Option<String>, String)> {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    let ascii = to_ascii_host(trimmed);
    let labels: Vec<&str> = ascii.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    let suffix_len = public_suffix_len(&ascii);
    if suffix_len >= labels.len() {
        return None; // whole host is a public suffix
    }
    let reg_start = labels.len() - suffix_len - 1;
    let registrable = labels[reg_start..].join(".");
    let public_suffix = labels[reg_start + 1..].join(".");
    let subdomain = if reg_start > 0 {
        Some(labels[..reg_start].join("."))
    } else {
        None
    };
    Some((registrable, subdomain, public_suffix))
}

fn hosting_for(host: &str) -> Option<(&'static str, &'static str)> {
    let host = host.to_lowercase();
    let mut best: Option<(&'static str, &'static str, usize)> = None;
    for (suffix, provider, category) in HOSTING_SUFFIXES {
        let dotted = format!(".{suffix}");
        if host == *suffix || host.ends_with(&dotted) {
            let len = suffix.len();
            if best.map_or(true, |(_, _, blen)| len > blen) {
                best = Some((provider, category, len));
            }
        }
    }
    best.map(|(p, c, _)| (p, c))
}

fn service_for(port: u16) -> Option<Service> {
    PORT_SERVICES
        .iter()
        .find(|(p, _, _)| *p == port)
        .map(|(port, name, kind)| Service {
            port: *port,
            name,
            kind: *kind,
        })
}

fn tld_class_for(host: &str, public_suffix: Option<&str>) -> TldClass {
    let host = host.to_lowercase();
    if host.ends_with(".onion") {
        return TldClass::Onion;
    }
    for internal in [
        ".local",
        ".internal",
        ".home.arpa",
        ".lan",
        ".corp",
        ".intranet",
    ] {
        if host.ends_with(internal) {
            return TldClass::Internal;
        }
    }
    // Inspect the effective public-suffix labels (e.g. `gov.uk` → ["gov","uk"]),
    // not raw substrings, so brand names like "governance.com" are not
    // mis-classified as government.
    let suffix = public_suffix
        .map(str::to_string)
        .unwrap_or_else(|| host.rsplit('.').next().unwrap_or_default().to_string());
    let labels: Vec<&str> = suffix.split('.').collect();
    let last = labels.last().copied().unwrap_or_default();

    // Single-label authoritative TLDs.
    match last {
        "gov" => return TldClass::Government,
        "mil" => return TldClass::Military,
        "edu" => return TldClass::Education,
        "int" | "arpa" => return TldClass::Infrastructure,
        "bank" | "insurance" => return TldClass::Financial,
        _ => {}
    }
    // Second-level registry markers (only meaningful within a multi-label
    // suffix, so single-label ccTLDs like `.ac`/`.re` are not false positives).
    if labels.len() > 1 {
        let has = |s: &str| labels.iter().any(|l| *l == s);
        if has("mil") || has("idf") {
            return TldClass::Military;
        }
        if has("gov")
            || has("gob")
            || has("gouv")
            || has("govt")
            || has("go")
            || has("gc")
            || has("muni")
            || has("lg")
        {
            return TldClass::Government;
        }
        if has("edu") || has("ac") || has("ed") || has("k12") || has("sch") {
            return TldClass::Education;
        }
    }
    if last.len() == 2 {
        TldClass::CountryCode
    } else {
        TldClass::Generic
    }
}

/// Rough Unicode script bucket of an alphabetic char (only the buckets we care
/// about for confusable/homograph detection).
fn script_bucket(c: char) -> Option<u8> {
    match c {
        'a'..='z' | 'A'..='Z' => Some(1), // Latin
        '\u{0400}'..='\u{04FF}' | '\u{0500}'..='\u{052F}' => Some(2), // Cyrillic
        '\u{0370}'..='\u{03FF}' => Some(3), // Greek
        '\u{0530}'..='\u{058F}' => Some(4), // Armenian
        _ if c.is_alphabetic() && !c.is_ascii() => Some(5), // Other non-ASCII letter
        _ => None,
    }
}

/// (is_idn, homograph_risk) for a raw host string. Punycode labels are decoded
/// via idna so mixed-script (confusable) detection also covers `xn--` hosts.
fn idn_analysis(host: &str) -> (bool, bool) {
    let has_puny = host
        .split('.')
        .any(|l| l.to_ascii_lowercase().starts_with("xn--"));
    let has_non_ascii = !host.is_ascii();
    let idn = has_puny || has_non_ascii;
    if !idn {
        return (false, false);
    }
    // Analyse the Unicode form so raw-unicode and punycode hosts are treated
    // alike; on decode failure fall back to the raw string.
    let unicode = if has_puny {
        let (u, res) = idna::domain_to_unicode(host);
        if res.is_ok() {
            u
        } else {
            host.to_string()
        }
    } else {
        host.to_string()
    };
    let homograph = unicode.split('.').any(|label| {
        let mut buckets = [false; 6];
        for c in label.chars() {
            if let Some(b) = script_bucket(c) {
                buckets[b as usize] = true;
            }
        }
        let distinct = buckets.iter().filter(|&&x| x).count();
        // Latin mixed with another script in one label.
        distinct > 1 && buckets[1]
    });
    (idn, homograph)
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

impl TargetProfile {
    #[must_use]
    pub fn classify(target: &str) -> Self {
        let t = target.trim();
        let (scheme, rest) = match t.find("://") {
            Some(i) => (Some(t[..i].to_lowercase()), &t[i + 3..]),
            None => (None, t),
        };
        // Split authority from path/query/fragment.
        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(i) => (&rest[..i], Some(rest[i..].to_lowercase())),
            None => (rest, None),
        };
        let (host_raw, port) = split_host_port(authority);
        let host = host_raw.to_string();

        let ip = host.parse::<IpAddr>().ok();
        let ip_family = ip.map(|a| {
            if a.is_ipv4() {
                IpFamily::V4
            } else {
                IpFamily::V6
            }
        });
        let net_class = ip.map(network_class).unwrap_or_default();
        let is_private = ip
            .map(|a| is_private_class(network_class(a)))
            .unwrap_or(false);

        // --- backwards-compatible coarse `hints` (unchanged semantics) ---
        let mut hints: Vec<&'static str> = Vec::new();
        hints.push(if ip.is_some() { "ip" } else { "hostname" });
        match scheme.as_deref() {
            Some("https") => {
                hints.push("web");
                hints.push("tls");
            }
            Some("http") => hints.push("web"),
            Some("ftp") | Some("ssh") | Some("smb") | Some("rdp") => hints.push("network"),
            _ => {}
        }
        if matches!(port, Some(443 | 8443 | 9443 | 10443)) && !hints.contains(&"tls") {
            hints.push("tls");
        }
        if matches!(port, Some(80 | 443 | 8080 | 8000 | 8443)) && !hints.contains(&"web") {
            hints.push("web");
        }

        // --- rich facets + provenance ---
        let service = port.and_then(service_for);
        let mut facets: Vec<&'static str> = Vec::new();
        let mut evidence: Vec<String> = Vec::new();
        let push = |f: &'static str, fs: &mut Vec<&'static str>| {
            if !fs.contains(&f) {
                fs.push(f);
            }
        };

        if ip.is_some() {
            push("ip", &mut facets);
            push("network", &mut facets);
            evidence.push(format!(
                "literal {} address ({:?})",
                scheme_family(ip_family),
                net_class
            ));
        } else {
            push("hostname", &mut facets);
        }
        if is_private_class(net_class) {
            push("private-network", &mut facets);
        }
        if net_class == NetworkClass::Cgnat {
            push("cgnat", &mut facets);
        }

        // Scheme-driven facets.
        match scheme.as_deref() {
            Some("https") => {
                push("web", &mut facets);
                push("tls", &mut facets);
            }
            Some("http") => push("web", &mut facets),
            Some("ftp") => push("file-transfer", &mut facets),
            Some("ssh") => push("remote-access", &mut facets),
            Some("smb") => push("smb", &mut facets),
            Some("rdp") => push("remote-access", &mut facets),
            Some("ldap" | "ldaps") => push("identity", &mut facets),
            _ => {}
        }
        if matches!(port, Some(443 | 8443 | 9443 | 10443)) {
            push("tls", &mut facets);
        }

        // Service-driven facets.
        if let Some(svc) = service {
            match svc.kind {
                ServiceKind::Web => push("web", &mut facets),
                ServiceKind::Tls => {
                    push("web", &mut facets);
                    push("tls", &mut facets);
                }
                ServiceKind::Mail => push("mail", &mut facets),
                ServiceKind::Dns => push("dns", &mut facets),
                ServiceKind::Database => push("database", &mut facets),
                ServiceKind::RemoteAccess => push("remote-access", &mut facets),
                ServiceKind::Ldap => push("identity", &mut facets),
                ServiceKind::Smb => push("smb", &mut facets),
                ServiceKind::Ot => {
                    push("ot", &mut facets);
                    push("ics", &mut facets);
                }
                ServiceKind::FileTransfer => push("file-transfer", &mut facets),
                ServiceKind::Other => {}
            }
            evidence.push(format!("port {} → {} ({:?})", svc.port, svc.name, svc.kind));
        }

        // A registrable domain with no non-web service is, overwhelmingly, a
        // website — treat bare hostnames as web unless a non-web service is
        // already implied.
        let non_web_service = facets.iter().any(|f| {
            matches!(
                *f,
                "database"
                    | "mail"
                    | "dns"
                    | "remote-access"
                    | "smb"
                    | "ot"
                    | "identity"
                    | "file-transfer"
            )
        });
        if ip.is_none() && !non_web_service {
            push("web", &mut facets);
        }

        // Path-driven facets.
        if let Some(p) = path.as_deref() {
            if p.contains("graphql") {
                push("graphql", &mut facets);
                push("http-api", &mut facets);
            }
            if p.contains("/api/")
                || p.starts_with("/api")
                || p.contains("/v1/")
                || p.contains("/v2/")
                || p.contains("/rest/")
                || p.contains("swagger")
                || p.contains("openapi")
                || p.contains("/graphql")
            {
                push("http-api", &mut facets);
            }
            if p.contains("/wp-")
                || p.contains("wp-admin")
                || p.contains("wp-login")
                || p.contains("wp-json")
            {
                push("wordpress", &mut facets);
                push("cms", &mut facets);
            }
            if p.contains("/oauth")
                || p.contains("/saml")
                || p.contains("/openid")
                || p.contains("/sso")
                || p.contains("/auth")
                || p.contains("/login")
                || p.contains("/.well-known/openid")
            {
                push("identity", &mut facets);
            }
            if p.contains("/v1/chat")
                || p.contains("/chat/completions")
                || p.contains("/v1/completions")
                || p.contains("/completions")
                || p.contains("/v1/messages")
                || p.contains("/generate")
                || p.contains("/invoke")
                || p.contains("/inference")
            {
                push("ai-endpoint", &mut facets);
                push("http-api", &mut facets);
            }
            if p.contains("/.git") {
                push("supply-chain", &mut facets);
            }
        }

        // Host-substring technology / AI hints (evidence-only heuristics).
        let host_l = host.to_lowercase();
        if [
            "llm",
            "openai",
            "bedrock",
            "inference",
            "ai-",
            "-ai",
            ".ai.",
        ]
        .iter()
        .any(|m| host_l.contains(m))
        {
            push("ai-endpoint", &mut facets);
        }

        // Provenance: registrable domain, hosting, TLD class, IDN.
        let mut provenance = Provenance {
            network_class: net_class,
            ..Default::default()
        };
        if let Some((reg, sub, suffix)) = registrable_domain(&host) {
            evidence.push(format!("registrable domain {reg} (eTLD {suffix})"));
            provenance.registrable_domain = Some(reg.clone());
            provenance.subdomain = sub;
            provenance.public_suffix = Some(suffix.clone());
            provenance.tld_class = tld_class_for(&host, Some(&suffix));
            if SUPPLY_CHAIN_DOMAINS.iter().any(|d| *d == reg) {
                push("supply-chain", &mut facets);
            }
        } else if ip.is_none() {
            provenance.tld_class = tld_class_for(&host, None);
        }
        if let Some((provider, category)) = hosting_for(&host) {
            provenance.hosting_provider = Some(provider);
            provenance.hosting_category = Some(category);
            evidence.push(format!("hosted on {provider} ({category})"));
            match category {
                "cloud" | "object-store" => {
                    push("cloud", &mut facets);
                    if category == "object-store" {
                        push("object-store", &mut facets);
                    }
                }
                "cdn" => push("cdn", &mut facets),
                "saas" => {
                    push("saas", &mut facets);
                    push("web", &mut facets);
                }
                "identity" => {
                    // SSO / federation endpoint — drives IdP/SAML/Kerberos
                    // engine selection and the IdentityProvider asset class.
                    push("identity", &mut facets);
                    push("web", &mut facets);
                }
                _ => {}
            }
            let pl = provider.to_lowercase();
            if pl.contains("amazon") || pl.contains("aws") {
                push("cloud-aws", &mut facets);
            } else if pl.contains("azure") || pl.contains("microsoft") {
                push("cloud-azure", &mut facets);
            } else if pl.contains("google") || pl.contains("firebase") {
                push("cloud-gcp", &mut facets);
            }
        }

        // TLD-class facets.
        match provenance.tld_class {
            TldClass::Government => push("gov", &mut facets),
            TldClass::Military => push("mil", &mut facets),
            TldClass::Education => push("edu", &mut facets),
            TldClass::Financial => push("bank", &mut facets),
            TldClass::Onion => push("onion", &mut facets),
            _ => {}
        }

        let (idn, homograph) = idn_analysis(&host);
        provenance.idn = idn;
        provenance.homograph_risk = homograph;
        if homograph {
            push("homograph-risk", &mut facets);
            evidence.push("mixed-script label — homograph/spoofing risk".to_string());
        } else if idn {
            push("punycode", &mut facets);
        }
        provenance.evidence = evidence;

        // Synthesis: asset class, sensitivity, confidence.
        let asset_class = synth_asset_class(&facets, ip.is_some());
        let sensitivity = synth_sensitivity(&facets, provenance.tld_class);
        let confidence = synth_confidence(
            scheme.is_some(),
            ip.is_some(),
            port.is_some(),
            service.is_some(),
            provenance.registrable_domain.is_some(),
            provenance.hosting_provider.is_some(),
            &host,
        );

        Self {
            host,
            scheme,
            port,
            ip_family,
            is_private,
            hints,
            path,
            asset_class,
            service,
            sensitivity,
            provenance,
            facets,
            confidence,
        }
    }

    /// True when the profile carries a given rich facet.
    #[must_use]
    pub fn has(&self, facet: &str) -> bool {
        self.facets.iter().any(|f| *f == facet)
    }

    /// Serialize the full profile to JSON for the API / UI.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "host": self.host,
            "scheme": self.scheme,
            "port": self.port,
            "path": self.path,
            "ip_family": self.ip_family.map(|f| format!("{f:?}")),
            "is_private": self.is_private,
            "asset_class": self.asset_class.as_str(),
            "sensitivity": self.sensitivity.as_str(),
            "confidence": self.confidence,
            "facets": self.facets,
            "hints": self.hints,
            "service": self.service.map(|s| serde_json::json!({
                "port": s.port,
                "name": s.name,
                "kind": format!("{:?}", s.kind),
            })),
            "provenance": {
                "registrable_domain": self.provenance.registrable_domain,
                "subdomain": self.provenance.subdomain,
                "public_suffix": self.provenance.public_suffix,
                "tld_class": format!("{:?}", self.provenance.tld_class),
                "hosting_provider": self.provenance.hosting_provider,
                "hosting_category": self.provenance.hosting_category,
                "network_class": format!("{:?}", self.provenance.network_class),
                "idn": self.provenance.idn,
                "homograph_risk": self.provenance.homograph_risk,
                "resolved_ips": self.provenance.resolved_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "evidence": self.provenance.evidence,
            },
        })
    }

    // ---- Active enrichment ---------------------------------------------

    /// Active DNS enrichment: resolve the host's A/AAAA records and fold the
    /// results back into the profile. This turns the passive, string-derived
    /// "seed" into a network-verified profile — most importantly it detects a
    /// hostname that actually resolves into RFC1918/loopback/ULA space (which
    /// the passive tier cannot know) and marks the target private. Returns true
    /// if at least one address was resolved. No-op for literal-IP targets.
    ///
    /// Performs one DNS lookup, so call it off the hot classification path (e.g.
    /// once per scan job), not per engine.
    pub async fn enrich_dns(&mut self) -> bool {
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        use hickory_resolver::TokioResolver;

        if self.ip_family.is_some() || self.host.trim().is_empty() {
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
        let ips: Vec<IpAddr> = match resolver.lookup_ip(self.host.as_str()).await {
            Ok(lookup) => lookup.iter().collect(),
            Err(_) => return false,
        };
        if ips.is_empty() {
            return false;
        }
        self.apply_resolved_ips(ips);
        true
    }

    /// Fold resolved IPs into the profile (pure — unit-testable without DNS):
    /// record the addresses, and if any resolves into private/internal space,
    /// flip the profile to private and set the network class accordingly.
    fn apply_resolved_ips(&mut self, ips: Vec<IpAddr>) {
        if ips.is_empty() {
            return;
        }
        let mut effective = self.provenance.network_class;
        for ip in &ips {
            let nc = network_class(*ip);
            if is_private_class(nc) {
                effective = nc;
                self.is_private = true;
                if !self.facets.contains(&"private-network") {
                    self.facets.push("private-network");
                }
            } else if effective == NetworkClass::Unknown {
                effective = nc;
            }
        }
        self.provenance.network_class = effective;
        self.provenance.evidence.push(format!(
            "resolved to {} IP(s); network class {:?}",
            ips.len(),
            effective
        ));

        // Attribute the hosting/CDN provider from a public resolved IP when the
        // hostname did not reveal one — catches custom domains fronted by a CDN,
        // which the passive string tier is blind to. High-confidence curated
        // ranges only; never overwrites a hostname-derived provider.
        if self.provenance.hosting_provider.is_none() {
            if let Some((provider, kind, ip)) = ips
                .iter()
                .filter(|ip| !is_private_class(network_class(**ip)))
                .find_map(|ip| provider_from_ip(*ip).map(|(p, k)| (p, k, *ip)))
            {
                self.provenance.hosting_provider = Some(provider);
                self.provenance.hosting_category = Some(kind);
                if kind == "cdn" && !self.facets.contains(&"cdn") {
                    self.facets.push("cdn");
                }
                if !self.facets.contains(&"cdn-fronted") {
                    self.facets.push("cdn-fronted");
                }
                self.provenance.evidence.push(format!(
                    "resolved IP {ip} in {provider} {kind} range — origin likely behind the edge"
                ));
            }
        }

        self.provenance.resolved_ips = ips;
        self.confidence = self.confidence.saturating_add(10).min(100);
    }

    // ---- Selection scoring ---------------------------------------------

    /// Legacy substring signal on the engine id vs the coarse target class.
    /// Preserved verbatim so id-only (non-catalog) engine names score exactly as
    /// they always did; the taxonomy affinity layers on top for real engines.
    fn id_signal(&self, engine_id: &str) -> i32 {
        let id = engine_id;
        let web = self.hints.contains(&"web");
        let tls = self.hints.contains(&"tls");
        let is_ip = self.hints.contains(&"ip");
        let mut score = 0;

        if web
            && (id.contains("http")
                || id.contains("web")
                || id.contains("xss")
                || id.contains("sqli")
                || id.contains("api")
                || id.contains("graphql")
                || id.contains("cache")
                || id.contains("ssrf")
                || id.contains("cors")
                || id.contains("upload"))
        {
            score += 5;
        }
        if tls
            && (id.contains("tls")
                || id.contains("ssl")
                || id.contains("cert")
                || id.contains("pqc"))
        {
            score += 4;
        }
        if is_ip
            && (id.contains("port")
                || id.contains("smb")
                || id.contains("netbios")
                || id.contains("network")
                || id.contains("dns")
                || id.contains("tcp")
                || id.contains("scan"))
        {
            score += 4;
        }
        if is_ip
            && (id.contains("xss")
                || id.contains("graphql")
                || id.contains("wordpress")
                || id.contains("cms"))
        {
            score -= 2;
        }
        if self.ip_family == Some(IpFamily::V6) && id.contains("ipv4") {
            score -= 3;
        }
        // A CDN-fronted origin (attributed from the resolved edge IP) makes
        // origin-discovery and WAF-evasion the high-value moves — the real
        // attack surface sits behind the edge, not on it. Additive and gated on
        // the facet, so non-fronted targets score exactly as before.
        if self.has("cdn-fronted")
            && (id.contains("origin") || id.contains("waf") || id.contains("bypass"))
        {
            score += 5;
        }
        score
    }

    /// Affinity for an engine's authoritative group under this profile. Returns
    /// 0 for engine ids absent from the catalog (e.g. synthetic test ids), which
    /// keeps id-only scoring identical to the legacy behaviour.
    fn group_affinity(&self, group: &str) -> i32 {
        match group {
            "recon" => 3, // discovery is always worth doing first
            "web" => {
                if self.has("ot") {
                    -6
                } else if self.has("web") {
                    let mut s = 7;
                    if self.has("http-api") || self.has("graphql") {
                        s += 3;
                    }
                    s
                } else if self.has("ip") {
                    -6
                } else if self.has("database")
                    || self.has("remote-access")
                    || self.has("dns")
                    || self.has("mail")
                {
                    -3
                } else {
                    0
                }
            }
            "network" => {
                let mut s = 1;
                if self.has("network") || self.has("ip") {
                    s += 5;
                }
                if self.has("database")
                    || self.has("remote-access")
                    || self.has("smb")
                    || self.has("dns")
                {
                    s += 3;
                }
                if self.has("ot") {
                    s += 2;
                }
                s
            }
            "cloud" => {
                if self.has("ot") {
                    -6
                } else if self.has("cloud") {
                    8
                } else if self.has("object-store") {
                    6
                } else if self.has("ip") {
                    -4
                } else if self.has("hostname") {
                    1
                } else {
                    0
                }
            }
            "ot" => {
                if self.has("ot") || self.has("ics") {
                    9
                } else {
                    -8 // intrusive & irrelevant off-OT; sink hard but keep (reorder-only)
                }
            }
            "crypto" => {
                let mut s = 1;
                if self.has("tls") {
                    s += 5;
                }
                if self.has("mail") {
                    s += 4;
                }
                if self.has("identity") {
                    s += 3;
                }
                if self.has("web") {
                    s += 2;
                }
                s
            }
            "ai" => {
                if self.has("ai-endpoint") {
                    9
                } else if self.has("http-api") {
                    1
                } else {
                    -3
                }
            }
            "apt" => {
                let mut s = 2;
                if self.has("web") || self.has("cloud") {
                    s += 1;
                }
                s
            }
            "stealth" => 0, // evasion modifiers; neutral
            "supply_chain" => {
                if self.has("supply-chain") {
                    7
                } else if self.has("cloud") {
                    1
                } else {
                    -4
                }
            }
            "data" => {
                let mut s = -1;
                if self.has("private-network") {
                    s += 1;
                }
                s
            }
            "malware" => -3, // host-side; mostly agent-required
            "mobile" => {
                if self.has("mobile-backend") {
                    7
                } else {
                    -5
                }
            }
            "social" => {
                let mut s = -4;
                if self.has("mail") {
                    s += 1;
                }
                s
            }
            "defense" => 0,
            _ => 0,
        }
    }

    /// Taxonomy-aware affinity for a real engine id (group affinity + provider &
    /// capability refinements). Zero for ids not in the catalog.
    fn taxonomy_affinity(&self, engine_id: &str) -> i32 {
        let Some(taxon) = engine_requirements::engine_taxon(engine_id) else {
            return 0;
        };
        let mut score = self.group_affinity(&taxon.group);
        if taxon.group == "cloud" {
            let id = engine_id;
            if self.has("cloud-aws")
                && (id.contains("aws")
                    || id.contains("s3")
                    || id.contains("ec2")
                    || id.contains("iam")
                    || id.contains("lambda")
                    || id.contains("eks")
                    || id.contains("rds"))
            {
                score += 3;
            }
            if self.has("cloud-azure") && (id.contains("azure") || id.contains("entra")) {
                score += 3;
            }
            if self.has("cloud-gcp")
                && (id.contains("gcp") || id.contains("gke") || id.contains("gcs"))
            {
                score += 3;
            }
        }
        // Remote scans cannot get detections from agent-only engines; sink them a
        // touch so remote-capable probes lead.
        if taxon.kind == "agent_required" {
            score -= 2;
        }
        score
    }

    /// Relevance score for an engine id under this profile (higher = run
    /// earlier). Combines the authoritative group affinity with the legacy
    /// id-substring signal. Scores may be negative; the engine is still kept.
    #[must_use]
    pub fn relevance(&self, engine_id: &str) -> i32 {
        self.id_signal(engine_id) + self.taxonomy_affinity(engine_id)
    }

    /// Return the engine ids reordered by descending relevance (stable for equal
    /// scores). Reorder-only — no engine is dropped.
    #[must_use]
    pub fn prioritize(&self, engine_ids: &[String]) -> Vec<String> {
        let mut indexed: Vec<(usize, &String)> = engine_ids.iter().enumerate().collect();
        indexed
            .sort_by(|(ia, a), (ib, b)| self.relevance(b).cmp(&self.relevance(a)).then(ia.cmp(ib)));
        indexed.into_iter().map(|(_, s)| s.clone()).collect()
    }

    /// Explainable selection: rank every engine, attach a per-engine rationale,
    /// and surface a recommended *focus set* (the clearly-relevant engines).
    /// Coverage is preserved — `ranked` contains every input engine.
    #[must_use]
    pub fn select(&self, engine_ids: &[String]) -> EngineSelection {
        let mut ranked: Vec<EngineChoice> = engine_ids
            .iter()
            .enumerate()
            .map(|(idx, id)| {
                let score = self.relevance(id);
                let group = engine_requirements::engine_group(id);
                EngineChoice {
                    engine_id: id.clone(),
                    score,
                    group,
                    recommended: score >= FOCUS_THRESHOLD,
                    reason: self.reason_for(score, group),
                    order: idx,
                }
            })
            .collect();
        ranked.sort_by(|a, b| b.score.cmp(&a.score).then(a.order.cmp(&b.order)));

        let focus: Vec<String> = ranked
            .iter()
            .filter(|c| c.recommended)
            .map(|c| c.engine_id.clone())
            .collect();

        EngineSelection {
            profile_summary: self.summary(),
            asset_class: self.asset_class,
            confidence: self.confidence,
            rationale: self.rationale(),
            focus,
            ranked,
        }
    }

    fn reason_for(&self, score: i32, group: Option<&'static str>) -> String {
        match group {
            Some(g) => format!(
                "group `{g}` affinity {:+} for {} target (score {score})",
                self.group_affinity(g),
                self.asset_class.as_str()
            ),
            None => format!(
                "id-signal score {score} for {} target",
                self.asset_class.as_str()
            ),
        }
    }

    /// One-line human summary of the target ("what/where/who").
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = vec![self.asset_class.as_str().to_string()];
        if let Some(svc) = self.service {
            parts.push(format!("{}:{}", svc.name, svc.port));
        } else if let Some(p) = self.port {
            parts.push(format!("port {p}"));
        }
        if let Some(reg) = &self.provenance.registrable_domain {
            parts.push(reg.clone());
        }
        if let Some(provider) = self.provenance.hosting_provider {
            parts.push(format!("@ {provider}"));
        }
        if self.provenance.tld_class != TldClass::Unknown
            && self.provenance.tld_class != TldClass::Generic
            && self.provenance.tld_class != TldClass::CountryCode
        {
            parts.push(format!("{:?}", self.provenance.tld_class));
        }
        if self.is_private {
            parts.push("private-network".to_string());
        }
        format!(
            "{} [{}%, sensitivity={}]",
            parts.join(" · "),
            self.confidence,
            self.sensitivity.as_str()
        )
    }

    fn rationale(&self) -> Vec<String> {
        let mut r = Vec::new();
        r.push(format!(
            "asset classified as {} (confidence {}%)",
            self.asset_class.as_str(),
            self.confidence
        ));
        if !self.facets.is_empty() {
            r.push(format!("facets: {}", self.facets.join(", ")));
        }
        r.extend(self.provenance.evidence.iter().cloned());
        r
    }
}

fn scheme_family(f: Option<IpFamily>) -> &'static str {
    match f {
        Some(IpFamily::V4) => "IPv4",
        Some(IpFamily::V6) => "IPv6",
        None => "IP",
    }
}

fn synth_asset_class(facets: &[&'static str], is_ip: bool) -> AssetClass {
    let has = |f: &str| facets.iter().any(|x| *x == f);
    if has("ot") {
        AssetClass::OtDevice
    } else if has("ai-endpoint") {
        AssetClass::AiEndpoint
    } else if has("database") {
        AssetClass::Database
    } else if has("mail") {
        AssetClass::MailServer
    } else if has("dns") {
        AssetClass::NameServer
    } else if has("object-store") {
        AssetClass::ObjectStore
    } else if has("identity") {
        AssetClass::IdentityProvider
    } else if has("remote-access") || has("smb") {
        AssetClass::NetworkHost
    } else if has("cloud") && !has("web") {
        AssetClass::CloudService
    } else if has("http-api") || has("graphql") {
        AssetClass::ApiEndpoint
    } else if has("web") {
        AssetClass::WebApp
    } else if is_ip {
        AssetClass::NetworkHost
    } else {
        AssetClass::Unknown
    }
}

fn synth_sensitivity(facets: &[&'static str], tld: TldClass) -> Sensitivity {
    let has = |f: &str| facets.iter().any(|x| *x == f);
    if has("ot")
        || matches!(
            tld,
            TldClass::Government | TldClass::Military | TldClass::Financial
        )
    {
        Sensitivity::Critical
    } else if matches!(
        tld,
        TldClass::Education | TldClass::Infrastructure | TldClass::Onion
    ) || has("identity")
        || has("homograph-risk")
    {
        Sensitivity::Elevated
    } else {
        Sensitivity::Standard
    }
}

#[allow(clippy::fn_params_excessive_bools)]
fn synth_confidence(
    has_scheme: bool,
    is_ip: bool,
    has_port: bool,
    has_service: bool,
    has_reg: bool,
    has_hosting: bool,
    host: &str,
) -> u8 {
    if host.is_empty() {
        return 0;
    }
    let mut c: u32 = 40;
    if has_scheme {
        c += 20;
    }
    if is_ip {
        c += 15;
    }
    if has_port {
        c += 10;
    }
    if has_service {
        c += 10;
    }
    if has_reg {
        c += 10;
    }
    if has_hosting {
        c += 5;
    }
    c.min(100) as u8
}

// ---------------------------------------------------------------------------
// Selection result types
// ---------------------------------------------------------------------------

/// Score at or above which an engine is considered clearly relevant to the
/// target and included in the recommended focus set.
const FOCUS_THRESHOLD: i32 = 6;

/// One engine's placement in a target-aware selection.
#[derive(Debug, Clone)]
pub struct EngineChoice {
    pub engine_id: String,
    pub score: i32,
    pub group: Option<&'static str>,
    /// In the recommended focus set (clearly relevant to this target).
    pub recommended: bool,
    /// Human-readable justification.
    pub reason: String,
    /// Original position (used as a stable tie-breaker).
    order: usize,
}

/// Explainable, target-aware engine selection. `ranked` preserves every input
/// engine (reorder-only); `focus` is the advisory high-relevance subset.
#[derive(Debug, Clone)]
pub struct EngineSelection {
    pub profile_summary: String,
    pub asset_class: AssetClass,
    pub confidence: u8,
    pub rationale: Vec<String>,
    pub focus: Vec<String>,
    pub ranked: Vec<EngineChoice>,
}

impl EngineSelection {
    /// Serialize the selection to JSON for the API / UI. `ranked` is capped to
    /// the top `limit` engines to keep the payload compact.
    #[must_use]
    pub fn to_json(&self, limit: usize) -> serde_json::Value {
        serde_json::json!({
            "profile_summary": self.profile_summary,
            "asset_class": self.asset_class.as_str(),
            "confidence": self.confidence,
            "rationale": self.rationale,
            "focus": self.focus,
            "focus_count": self.focus.len(),
            "engine_count": self.ranked.len(),
            "ranked": self.ranked.iter().take(limit).map(|c| serde_json::json!({
                "engine_id": c.engine_id,
                "score": c.score,
                "group": c.group,
                "recommended": c.recommended,
                "reason": c.reason,
            })).collect::<Vec<_>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    // --- original behaviour (preserved) ---

    #[test]
    fn classifies_web_url() {
        let p = TargetProfile::classify("https://example.com/login?x=1");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.scheme.as_deref(), Some("https"));
        assert!(p.ip_family.is_none());
        assert!(
            p.hints.contains(&"web") && p.hints.contains(&"tls") && p.hints.contains(&"hostname")
        );
    }

    #[test]
    fn classifies_ipv4_with_port() {
        let p = TargetProfile::classify("10.0.0.5:445");
        assert_eq!(p.host, "10.0.0.5");
        assert_eq!(p.port, Some(445));
        assert_eq!(p.ip_family, Some(IpFamily::V4));
        assert!(p.is_private);
        assert!(p.hints.contains(&"ip"));
    }

    #[test]
    fn classifies_ipv6() {
        let p = TargetProfile::classify("[2001:db8::1]:443");
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port, Some(443));
        assert_eq!(p.ip_family, Some(IpFamily::V6));
        assert!(p.hints.contains(&"tls"));
    }

    #[test]
    fn prioritizes_web_engines_for_web_target_and_keeps_all() {
        let p = TargetProfile::classify("https://example.com");
        let engines = ids(&["smb_netbios", "xss_reflected", "tls_audit", "port_scan"]);
        let ordered = p.prioritize(&engines);
        assert_eq!(ordered.len(), engines.len());
        let pos = |name: &str| ordered.iter().position(|e| e == name).unwrap();
        assert!(pos("xss_reflected") < pos("smb_netbios"));
        assert!(pos("tls_audit") < pos("smb_netbios"));
    }

    #[test]
    fn prioritizes_network_engines_for_bare_ip() {
        let p = TargetProfile::classify("10.0.0.5");
        let engines = ids(&["xss_reflected", "smb_netbios", "port_scan"]);
        let ordered = p.prioritize(&engines);
        let pos = |name: &str| ordered.iter().position(|e| e == name).unwrap();
        assert!(pos("smb_netbios") < pos("xss_reflected"));
        assert!(pos("port_scan") < pos("xss_reflected"));
    }

    // --- deep classification ---

    #[test]
    fn extracts_registrable_domain_and_subdomain() {
        let p = TargetProfile::classify("https://api.staging.example.co.uk/v1/users");
        assert_eq!(
            p.provenance.registrable_domain.as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(p.provenance.public_suffix.as_deref(), Some("co.uk"));
        assert_eq!(p.provenance.subdomain.as_deref(), Some("api.staging"));
        assert_eq!(p.asset_class, AssetClass::ApiEndpoint);
        assert!(p.has("http-api"));
    }

    #[test]
    fn strips_userinfo_from_authority() {
        let p = TargetProfile::classify("https://user:pass@example.com/");
        assert_eq!(p.host, "example.com");
    }

    #[test]
    fn detects_cloud_hosting_provenance() {
        let p = TargetProfile::classify("https://assets.myapp.s3.amazonaws.com/");
        assert_eq!(p.provenance.hosting_provider, Some("Amazon S3"));
        assert!(p.has("cloud"));
        assert!(p.has("cloud-aws"));
        assert!(p.has("object-store"));
    }

    #[test]
    fn detects_azure_provenance() {
        let p = TargetProfile::classify("https://portal.azurewebsites.net/");
        assert_eq!(p.provenance.hosting_provider, Some("Azure App Service"));
        assert!(p.has("cloud-azure"));
    }

    #[test]
    fn detects_identity_provider_from_hostname() {
        // An Okta customer tenant → identity facet, IdentityProvider asset class,
        // and Elevated sensitivity (SSO/federation surface).
        let p = TargetProfile::classify("https://acme.okta.com/");
        assert_eq!(p.provenance.hosting_provider, Some("Okta"));
        assert!(p.has("identity"));
        assert_eq!(p.asset_class, AssetClass::IdentityProvider);
        assert_eq!(p.sensitivity, Sensitivity::Elevated);

        // Azure AD / Entra ID login endpoint.
        let p2 = TargetProfile::classify("https://login.microsoftonline.com/");
        assert_eq!(p2.provenance.hosting_provider, Some("Microsoft Entra ID"));
        assert!(p2.has("identity"));
        assert_eq!(p2.asset_class, AssetClass::IdentityProvider);
    }

    #[test]
    fn azure_storage_and_sql_are_not_misclassified_as_identity() {
        // Regression guard: broad `windows.net` was rejected precisely because
        // these non-identity Azure services share the parent domain.
        let sql = TargetProfile::classify("https://myserver.database.windows.net/");
        assert!(!sql.has("identity"), "Azure SQL is not an identity provider");
        let blob = TargetProfile::classify("https://acct.blob.core.windows.net/");
        assert_eq!(blob.provenance.hosting_provider, Some("Azure Blob Storage"));
        assert!(!blob.has("identity"));
    }

    #[test]
    fn identity_provider_ranks_identity_engines_first() {
        let p = TargetProfile::classify("https://sso.acme.okta.com/");
        let engines = ids(&["saml_attack", "kerberoast", "wordpress_scan", "scada_ics"]);
        let ordered = p.prioritize(&engines);
        let pos = |name: &str| ordered.iter().position(|e| e == name).unwrap();
        assert!(pos("saml_attack") < pos("scada_ics"));
        assert!(pos("kerberoast") < pos("scada_ics"));
    }

    #[test]
    fn infers_database_from_port() {
        let p = TargetProfile::classify("db.internal.example.com:5432");
        assert_eq!(p.asset_class, AssetClass::Database);
        assert!(p.has("database"));
        assert!(!p.has("web"), "a database port must not be treated as web");
    }

    #[test]
    fn infers_ot_from_modbus_port() {
        let p = TargetProfile::classify("10.20.0.9:502");
        assert_eq!(p.asset_class, AssetClass::OtDevice);
        assert_eq!(p.sensitivity, Sensitivity::Critical);
        assert!(p.has("ot"));
    }

    #[test]
    fn infers_mail_server() {
        let p = TargetProfile::classify("mail.example.com:587");
        assert_eq!(p.asset_class, AssetClass::MailServer);
        assert!(p.has("mail"));
    }

    #[test]
    fn government_tld_is_critical() {
        let p = TargetProfile::classify("https://portal.gov.uk/");
        assert_eq!(p.provenance.tld_class, TldClass::Government);
        assert_eq!(p.sensitivity, Sensitivity::Critical);
    }

    #[test]
    fn israeli_gov_tld_detected() {
        let p = TargetProfile::classify("https://services.gov.il/");
        assert_eq!(p.provenance.tld_class, TldClass::Government);
    }

    #[test]
    fn detects_ai_endpoint_from_path() {
        let p = TargetProfile::classify("https://api.example.com/v1/chat/completions");
        assert_eq!(p.asset_class, AssetClass::AiEndpoint);
        assert!(p.has("ai-endpoint"));
    }

    #[test]
    fn detects_homograph_risk() {
        // Cyrillic 'а' (U+0430) spoofing Latin 'a' in "apple".
        let p = TargetProfile::classify("https://\u{0430}pple.com/");
        assert!(p.provenance.idn);
        assert!(p.provenance.homograph_risk);
        assert!(p.has("homograph-risk"));
    }

    #[test]
    fn cgnat_range_classified() {
        let p = TargetProfile::classify("100.64.1.1");
        assert_eq!(p.provenance.network_class, NetworkClass::Cgnat);
        assert!(p.has("cgnat"));
    }

    #[test]
    fn supply_chain_domain_flagged() {
        let p = TargetProfile::classify("https://github.com/org/repo");
        assert!(p.has("supply-chain"));
    }

    #[test]
    fn bare_hostname_defaults_to_web() {
        let p = TargetProfile::classify("example.com");
        assert!(p.has("web"));
        assert_eq!(p.asset_class, AssetClass::WebApp);
    }

    // --- full Public Suffix List coverage ---

    #[test]
    fn psl_simple_and_multilabel() {
        let p = TargetProfile::classify("https://a.b.example.co.uk/");
        assert_eq!(
            p.provenance.registrable_domain.as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(p.provenance.public_suffix.as_deref(), Some("co.uk"));
        assert_eq!(p.provenance.subdomain.as_deref(), Some("a.b"));
    }

    #[test]
    fn psl_private_section_github_io() {
        // github.io is a PRIVATE-section public suffix in the full PSL, so the
        // registrable "site" is the whole label — proving the full list loaded,
        // not the old curated subset.
        let p = TargetProfile::classify("https://myproject.github.io/");
        assert_eq!(
            p.provenance.registrable_domain.as_deref(),
            Some("myproject.github.io")
        );
        assert_eq!(p.provenance.public_suffix.as_deref(), Some("github.io"));
    }

    #[test]
    fn psl_wildcard_and_exception_rules() {
        // *.ck is a wildcard suffix; !www.ck is an exception (www.ck IS registrable).
        let wild = TargetProfile::classify("http://foo.bar.ck/");
        assert_eq!(
            wild.provenance.registrable_domain.as_deref(),
            Some("foo.bar.ck")
        );
        let exception = TargetProfile::classify("http://www.ck/");
        assert_eq!(
            exception.provenance.registrable_domain.as_deref(),
            Some("www.ck")
        );
    }

    #[test]
    fn psl_kawasaki_exception() {
        // *.kawasaki.jp wildcard + !city.kawasaki.jp exception.
        let p = TargetProfile::classify("https://www.city.kawasaki.jp/");
        assert_eq!(
            p.provenance.registrable_domain.as_deref(),
            Some("city.kawasaki.jp")
        );
        assert_eq!(p.provenance.subdomain.as_deref(), Some("www"));
    }

    #[test]
    fn psl_idn_host_normalized_to_punycode() {
        // Unicode ccTLD рф → punycode xn--p1ai; registrable domain must resolve.
        let p = TargetProfile::classify(
            "https://\u{043F}\u{0440}\u{0438}\u{043C}\u{0435}\u{0440}.\u{0440}\u{0444}/",
        );
        let reg = p.provenance.registrable_domain.as_deref().unwrap_or("");
        assert!(reg.ends_with("xn--p1ai"), "got {reg}");
        assert!(reg.is_ascii());
    }

    #[test]
    fn punycode_homograph_decoded_and_flagged() {
        // Punycode of "аpple" (Cyrillic а) — must be decoded and flagged, which
        // the previous hot-path-only implementation could not do.
        let p = TargetProfile::classify("https://xn--pple-43d.com/");
        assert!(p.provenance.idn);
        assert!(p.provenance.homograph_risk);
    }

    // --- active DNS enrichment (pure fold, no network) ---

    #[test]
    fn resolved_private_ip_marks_target_private() {
        let mut p = TargetProfile::classify("https://intranet.example.com/");
        assert!(!p.is_private, "public until resolved");
        let before = p.confidence;
        p.apply_resolved_ips(vec!["10.1.2.3".parse().unwrap()]);
        assert!(p.is_private);
        assert!(p.has("private-network"));
        assert_eq!(p.provenance.network_class, NetworkClass::PrivateRfc1918);
        assert_eq!(p.provenance.resolved_ips.len(), 1);
        assert!(p.confidence >= before);
    }

    #[test]
    fn resolved_public_ip_keeps_public() {
        let mut p = TargetProfile::classify("https://example.com/");
        p.apply_resolved_ips(vec!["93.184.216.34".parse().unwrap()]);
        assert!(!p.is_private);
        assert_eq!(p.provenance.network_class, NetworkClass::Public);
        assert_eq!(p.provenance.resolved_ips.len(), 1);
    }

    #[test]
    fn resolved_cdn_ip_attributes_provider_when_host_opaque() {
        // Opaque custom domain — hostname reveals no provider.
        let mut p = TargetProfile::classify("https://portal.acme-corp.example/");
        assert_eq!(p.provenance.hosting_provider, None, "opaque before resolve");
        // Resolves into Cloudflare's 104.16.0.0/13.
        p.apply_resolved_ips(vec!["104.18.32.47".parse().unwrap()]);
        assert_eq!(p.provenance.hosting_provider, Some("Cloudflare"));
        assert_eq!(p.provenance.hosting_category, Some("cdn"));
        assert!(p.has("cdn"));
        assert!(p.has("cdn-fronted"));
    }

    #[test]
    fn resolved_fastly_v6_ip_attributes_provider() {
        let mut p = TargetProfile::classify("https://media.opaque-host.example/");
        // Fastly IPv6 2a04:4e40::/32.
        p.apply_resolved_ips(vec!["2a04:4e40::1".parse().unwrap()]);
        assert_eq!(p.provenance.hosting_provider, Some("Fastly"));
        assert!(p.has("cdn-fronted"));
    }

    #[test]
    fn hostname_derived_provider_is_not_overwritten_by_ip() {
        // s3.amazonaws.com is attributed from the hostname; even if it resolves
        // into a CDN range, the hostname signal must win (no clobber).
        let mut p = TargetProfile::classify("https://data.myapp.s3.amazonaws.com/");
        assert_eq!(p.provenance.hosting_provider, Some("Amazon S3"));
        p.apply_resolved_ips(vec!["104.18.32.47".parse().unwrap()]);
        assert_eq!(
            p.provenance.hosting_provider,
            Some("Amazon S3"),
            "hostname attribution must not be clobbered by IP attribution"
        );
    }

    #[test]
    fn non_cdn_public_ip_yields_no_provider() {
        let mut p = TargetProfile::classify("https://plain.opaque-host.example/");
        p.apply_resolved_ips(vec!["93.184.216.34".parse().unwrap()]);
        assert_eq!(p.provenance.hosting_provider, None, "no guessing on unknown IP");
        assert!(!p.has("cdn-fronted"));
    }

    #[test]
    fn cidr_matcher_respects_prefix_boundaries() {
        // 104.16.0.0/13 covers 104.16–104.23; 104.24.0.0/14 covers 104.24–104.27.
        assert!(provider_from_ip("104.16.0.1".parse().unwrap()).is_some());
        assert!(provider_from_ip("104.23.255.254".parse().unwrap()).is_some());
        // 8.8.8.8 (Google DNS) is deliberately not in the curated CDN set.
        assert!(provider_from_ip("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn cdn_fronted_target_boosts_origin_and_waf_engines() {
        let mut p = TargetProfile::classify("https://portal.opaque-corp.example/");
        p.apply_resolved_ips(vec!["104.18.32.47".parse().unwrap()]); // Cloudflare edge
        assert!(p.has("cdn-fronted"));
        let engines = ids(&["origin_discovery", "waf_bypass", "wordpress_scan", "osint"]);
        let ordered = p.prioritize(&engines);
        let pos = |name: &str| ordered.iter().position(|e| e == name).unwrap();
        // Behind an edge, origin discovery + WAF evasion outrank a generic CMS scan.
        assert!(pos("origin_discovery") < pos("wordpress_scan"));
        assert!(pos("waf_bypass") < pos("wordpress_scan"));
    }

    // --- taxonomy-backed selection over REAL engine ids ---

    #[test]
    fn real_web_target_ranks_web_group_above_ot() {
        let p = TargetProfile::classify("https://shop.example.com/");
        let engines = ids(&["scada_ics", "bola_idor", "graphql_attack", "osint"]);
        let ordered = p.prioritize(&engines);
        let pos = |name: &str| ordered.iter().position(|e| e == name).unwrap();
        // web engines and recon beat an OT engine on a web target.
        assert!(pos("bola_idor") < pos("scada_ics"));
        assert!(pos("graphql_attack") < pos("scada_ics"));
        assert!(pos("osint") < pos("scada_ics"));
    }

    #[test]
    fn real_ot_target_ranks_ot_group_first() {
        let p = TargetProfile::classify("10.20.0.9:502");
        let engines = ids(&["bola_idor", "scada_ics", "osint"]);
        let ordered = p.prioritize(&engines);
        let pos = |name: &str| ordered.iter().position(|e| e == name).unwrap();
        assert!(pos("scada_ics") < pos("bola_idor"));
    }

    #[test]
    fn cloud_target_prefers_matching_provider_engine() {
        let p = TargetProfile::classify("https://data.myapp.s3.amazonaws.com/");
        let engines = ids(&["azure_attack", "aws_attack", "gcp_attack"]);
        let ordered = p.prioritize(&engines);
        assert_eq!(ordered.first().map(String::as_str), Some("aws_attack"));
    }

    #[test]
    fn select_reports_focus_and_preserves_coverage() {
        let p = TargetProfile::classify("https://api.example.com/graphql");
        let engines = ids(&[
            "graphql_attack",
            "bola_idor",
            "scada_ics",
            "osint",
            "smb_netbios",
        ]);
        let selection = p.select(&engines);
        // Nothing dropped.
        assert_eq!(selection.ranked.len(), engines.len());
        // The GraphQL engine is clearly relevant and recommended.
        assert!(selection.focus.iter().any(|e| e == "graphql_attack"));
        // OT engine is not recommended for a web/API target.
        assert!(!selection.focus.iter().any(|e| e == "scada_ics"));
        // Summary/rationale are populated for explainability.
        assert!(!selection.profile_summary.is_empty());
        assert!(!selection.rationale.is_empty());
        assert!(selection.confidence > 0);
    }

    #[test]
    fn agent_required_engines_sink_below_remote_probes_on_web() {
        let p = TargetProfile::classify("https://example.com/");
        // process_hollowing is agent_required (stealth group); bola_idor is a
        // remote web probe.
        let engines = ids(&["process_hollowing", "bola_idor"]);
        let ordered = p.prioritize(&engines);
        let pos = |name: &str| ordered.iter().position(|e| e == name).unwrap();
        assert!(pos("bola_idor") < pos("process_hollowing"));
    }

    #[test]
    fn confidence_higher_for_fully_specified_target() {
        let vague = TargetProfile::classify("example.org");
        let precise = TargetProfile::classify("https://api.example.co.uk:443/v1/users");
        assert!(precise.confidence > vague.confidence);
    }
}
