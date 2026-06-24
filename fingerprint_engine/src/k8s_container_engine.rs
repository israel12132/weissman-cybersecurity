//! Cloud-Native & Kubernetes Security Engine — agentless, evidence-based, CNAPP-grade.
//!
//! This engine performs a **real, read-only** remote assessment of the entire cloud-native
//! control-plane and data-plane attack surface — the Kubernetes API server, kubelet, etcd, the
//! Docker/CRI daemon, control-plane components (scheduler / controller-manager / kube-proxy),
//! container registries, service-mesh sidecars (Envoy / Consul / Istio / Linkerd), GitOps
//! control planes (Argo CD / Flux / Rancher / OpenShift), observability stacks (Prometheus /
//! Grafana / Alertmanager), platform UIs and legacy Helm Tiller.
//!
//! Design goals (inspired by best-in-class CNAPP platforms):
//!   * **Agentless & real** — every finding is backed by a live TCP/TLS/HTTP observation. Nothing
//!     is fabricated: if no signal is observed, no finding is emitted.
//!   * **Fully operator-configurable** — every port, path-depth, timeout, surface toggle and an
//!     optional bearer token are read from the live scan body (`job_params`) via [`ArsenalConfig`],
//!     so an operator can tune *any* aspect from the GUI without a code change.
//!   * **Version → CVE intelligence** — the API-server `gitVersion` is parsed and matched against a
//!     curated table of high-impact Kubernetes control-plane CVEs with accurate fixed-version ranges.
//!   * **Security graph + attack-path analysis** — observed services become graph nodes; toxic
//!     combinations are synthesised into concrete, chained attack paths (the signature CNAPP view).
//!
//! MITRE ATT&CK (Containers): T1610 Deploy Container, T1611 Escape to Host, T1613 Container &
//! Resource Discovery, T1552.007 Unsecured Kubernetes Secrets, T1525 Implant Internal Image.

use crate::arsenal_config::{finding_rich, severity_for_score, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    extract_host, header_value, normalize_url, tcp_open, tcp_scan, HttpProbe,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::time::Duration;

const ENGINE_ID: &str = "k8s_container";

// ── Default port maps per surface (operator-overridable via job_params) ─────────────────────────
const DEFAULT_API_PORTS: &[u16] = &[6443, 443, 8443, 16443, 6444, 8080];
const DEFAULT_KUBELET_PORTS: &[u16] = &[10250, 10255];
const DEFAULT_ETCD_PORTS: &[u16] = &[2379, 2380];
const DEFAULT_DOCKER_PORTS: &[u16] = &[2375, 2376];
const DEFAULT_CONTROL_PLANE_PORTS: &[u16] = &[10257, 10259, 10251, 10252, 10256, 10249];
const DEFAULT_REGISTRY_PORTS: &[u16] = &[5000, 443];
const DEFAULT_MESH_PORTS: &[u16] = &[15000, 9901, 19000, 8500, 15014, 9990];
const DEFAULT_CADVISOR_PORTS: &[u16] = &[4194];
const DEFAULT_OBS_PORTS: &[u16] = &[9090, 9093, 3000, 9091];
const DEFAULT_CONTAINERD_PORTS: &[u16] = &[10010, 1338];
const HELM_TILLER_PORT: u16 = 44134;

// ── HTTP client + GET helpers ───────────────────────────────────────────────────────────────────

fn build_client(timeout_ms: u64) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .connect_timeout(Duration::from_millis(timeout_ms.min(6_000)))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .user_agent("Weissman-CloudNative-Probe/2.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Single GET, optionally bearer-authenticated. Returns the live [`HttpProbe`] or `None` on a
/// transport failure (DNS / connect / TLS / timeout).
async fn get(client: &reqwest::Client, url: &str, token: Option<&str>) -> Option<HttpProbe> {
    match token {
        Some(t) if !t.trim().is_empty() => {
            let bearer = format!("Bearer {}", t.trim());
            crate::engine_probes::http_get_with_headers(
                client,
                url,
                &[("Authorization", bearer.as_str())],
            )
            .await
        }
        _ => crate::engine_probes::http_get(client, url).await,
    }
}

fn url(scheme: &str, host: &str, port: u16, path: &str) -> String {
    format!("{}://{}:{}{}", scheme, host, port, path)
}

// ── Version parsing + curated Kubernetes CVE intelligence ───────────────────────────────────────

type Ver = (u32, u32, u32);

/// Parse a Kubernetes `gitVersion` (e.g. `v1.23.5`, `v1.27.4-gke.900`) into `(major, minor, patch)`.
fn parse_semver(s: &str) -> Option<Ver> {
    let s = s.trim().trim_start_matches('v');
    let core = s.split(['-', '+']).next().unwrap_or(s);
    let mut it = core.split('.');
    let maj = it.next()?.parse::<u32>().ok()?;
    let min = it.next()?.parse::<u32>().ok()?;
    let pat = it
        .next()
        .and_then(|p| {
            p.split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|d| d.parse::<u32>().ok())
        })
        .unwrap_or(0);
    Some((maj, min, pat))
}

/// True when `v` is older than the per-minor fixed version in `fixes`. Versions on a minor branch
/// below the lowest patched minor are vulnerable; versions above the highest patched minor are not.
fn vulnerable_before(v: Ver, fixes: &[Ver]) -> bool {
    let (maj, min, pat) = v;
    if let Some(&(_, _, fp)) = fixes.iter().find(|&&(a, b, _)| a == maj && b == min) {
        return pat < fp;
    }
    let lo = fixes.iter().map(|&(a, b, _)| (a, b)).min();
    let hi = fixes.iter().map(|&(a, b, _)| (a, b)).max();
    if let (Some(lo), Some(hi)) = (lo, hi) {
        if (maj, min) < lo {
            return true;
        }
        if (maj, min) > hi {
            return false;
        }
    }
    false
}

struct KnownCve {
    id: &'static str,
    cvss: f64,
    title: &'static str,
    mitre: &'static str,
    fixed_in: &'static str,
}

/// Match a detected control-plane version against high-impact, accurately-ranged Kubernetes CVEs.
fn known_k8s_cves(v: Ver) -> Vec<KnownCve> {
    let mut out = Vec::new();
    let (maj, min, pat) = v;
    let lt = |a, b, c| (maj, min, pat) < (a, b, c);
    let between = |lo: Ver, hi: Ver| (maj, min, pat) >= lo && (maj, min, pat) < hi;

    if lt(1, 10, 11) || between((1, 11, 0), (1, 11, 5)) || between((1, 12, 0), (1, 12, 3)) {
        out.push(KnownCve {
            id: "CVE-2018-1002105",
            cvss: 9.8,
            title: "API server proxy privilege escalation — unauthenticated backend upgrade requests reach kubelets/aggregated APIs as cluster-admin",
            mitre: "T1068",
            fixed_in: "1.10.11 / 1.11.5 / 1.12.3 / 1.13.0",
        });
    }
    if vulnerable_before(v, &[(1, 13, 9), (1, 14, 5), (1, 15, 2)]) {
        out.push(KnownCve {
            id: "CVE-2019-11247",
            cvss: 8.1,
            title: "API server allows access to cluster-scoped custom resources as if namespaced (RBAC bypass)",
            mitre: "T1078",
            fixed_in: "1.13.9 / 1.14.5 / 1.15.2",
        });
    }
    if vulnerable_before(v, &[(1, 13, 12), (1, 14, 8), (1, 15, 5), (1, 16, 2)]) {
        out.push(KnownCve {
            id: "CVE-2019-11253",
            cvss: 7.5,
            title: "JSON/YAML 'billion laughs' parsing DoS against the API server (unauthenticated POST)",
            mitre: "T1499",
            fixed_in: "1.13.12 / 1.14.8 / 1.15.5 / 1.16.2",
        });
    }
    if vulnerable_before(v, &[(1, 16, 11), (1, 17, 7), (1, 18, 4)]) {
        out.push(KnownCve {
            id: "CVE-2020-8558",
            cvss: 8.8,
            title: "Node setting exposes localhost-bound control-plane services to adjacent pods/nodes",
            mitre: "T1611",
            fixed_in: "1.16.11 / 1.17.7 / 1.18.4",
        });
    }
    if vulnerable_before(v, &[(1, 19, 16), (1, 20, 11), (1, 21, 5), (1, 22, 2)]) {
        out.push(KnownCve {
            id: "CVE-2021-25741",
            cvss: 8.8,
            title: "subPath symlink traversal lets a container access host files (container escape / host file read-write)",
            mitre: "T1611",
            fixed_in: "1.19.16 / 1.20.11 / 1.21.5 / 1.22.2",
        });
    }
    if vulnerable_before(v, &[(1, 22, 14), (1, 23, 11), (1, 24, 5), (1, 25, 1)]) {
        out.push(KnownCve {
            id: "CVE-2022-3172",
            cvss: 5.1,
            title: "Aggregated API server can redirect client credentials to an attacker-controlled URL (SSRF)",
            mitre: "T1557",
            fixed_in: "1.22.14 / 1.23.11 / 1.24.5 / 1.25.1",
        });
    }
    if vulnerable_before(v, &[(1, 24, 14), (1, 25, 10), (1, 26, 5), (1, 27, 2)]) {
        out.push(KnownCve {
            id: "CVE-2023-2728",
            cvss: 6.5,
            title: "Pods can bypass the mountable-secrets policy via ephemeral containers",
            mitre: "T1610",
            fixed_in: "1.24.14 / 1.25.10 / 1.26.5 / 1.27.2",
        });
    }
    if vulnerable_before(v, &[(1, 11, 8), (1, 12, 6), (1, 13, 4), (1, 14, 0)]) {
        out.push(KnownCve {
            id: "CVE-2019-1002101",
            cvss: 8.8,
            title: "subPath volume validation bypass — container escape via malicious subPath",
            mitre: "T1611",
            fixed_in: "1.11.8 / 1.12.6 / 1.13.4 / 1.14.0",
        });
    }
    if lt(1, 18, 10) || between((1, 18, 0), (1, 18, 10)) || between((1, 17, 0), (1, 17, 13)) {
        out.push(KnownCve {
            id: "CVE-2020-8554",
            cvss: 6.3,
            title: "Man-in-the-middle via LoadBalancer/ExternalIP — intercept cluster traffic to external IPs",
            mitre: "T1557",
            fixed_in: "1.18.10 / 1.17.13 / 1.19.0",
        });
    }
    if lt(1, 19, 10) || between((1, 19, 0), (1, 19, 10)) || between((1, 20, 0), (1, 20, 6)) {
        out.push(KnownCve {
            id: "CVE-2021-25735",
            cvss: 6.5,
            title: "Validating admission webhook bypass via malformed HPA objects",
            mitre: "T1078",
            fixed_in: "1.19.10 / 1.20.6 / 1.21.0",
        });
    }
    if vulnerable_before(v, &[(1, 19, 11), (1, 20, 7), (1, 21, 1)]) {
        out.push(KnownCve {
            id: "CVE-2021-25737",
            cvss: 2.7,
            title: "EndpointSlice / Endpoint IP validation bypass — traffic redirection within cluster",
            mitre: "T1557",
            fixed_in: "1.19.11 / 1.20.7 / 1.21.1",
        });
    }
    if vulnerable_before(v, &[(1, 22, 16), (1, 23, 14), (1, 24, 8), (1, 25, 4)]) {
        out.push(KnownCve {
            id: "CVE-2022-3294",
            cvss: 6.6,
            title: "Node address validation bypass — pods can reach unintended node-local services",
            mitre: "T1611",
            fixed_in: "1.22.16 / 1.23.14 / 1.24.8 / 1.25.4",
        });
    }
    if vulnerable_before(v, &[(1, 24, 17), (1, 25, 16), (1, 26, 11), (1, 27, 8), (1, 28, 4)]) {
        out.push(KnownCve {
            id: "CVE-2023-3676",
            cvss: 8.8,
            title: "Windows SMB mount privilege escalation via incomplete path validation",
            mitre: "T1611",
            fixed_in: "1.24.17 / 1.25.16 / 1.26.11 / 1.27.8 / 1.28.4",
        });
    }
    if vulnerable_before(v, &[(1, 24, 17), (1, 25, 16), (1, 26, 11), (1, 27, 8), (1, 28, 4)]) {
        out.push(KnownCve {
            id: "CVE-2023-3955",
            cvss: 8.8,
            title: "Image volume validation bypass on Windows nodes — host filesystem access",
            mitre: "T1611",
            fixed_in: "1.24.17 / 1.25.16 / 1.26.11 / 1.27.8 / 1.28.4",
        });
    }
    if vulnerable_before(v, &[(1, 24, 17), (1, 25, 16), (1, 26, 11), (1, 27, 8), (1, 28, 4)]) {
        out.push(KnownCve {
            id: "CVE-2023-5528",
            cvss: 8.8,
            title: "SELinux volume mount validation bypass on Windows nodes",
            mitre: "T1611",
            fixed_in: "1.24.17 / 1.25.16 / 1.26.11 / 1.27.8 / 1.28.4",
        });
    }
    if vulnerable_before(v, &[(1, 27, 13), (1, 28, 9), (1, 29, 4)]) {
        out.push(KnownCve {
            id: "CVE-2024-3177",
            cvss: 8.1,
            title: "ImagePolicyWebhook bypass on Windows — run non-compliant container images",
            mitre: "T1610",
            fixed_in: "1.27.13 / 1.28.9 / 1.29.4",
        });
    }
    if vulnerable_before(v, &[(1, 28, 12), (1, 29, 8), (1, 30, 4)]) {
        out.push(KnownCve {
            id: "CVE-2024-5321",
            cvss: 6.5,
            title: "Incorrect permissions on built-in VolumeAttributesClass — privilege escalation via volume attributes",
            mitre: "T1078",
            fixed_in: "1.28.12 / 1.29.8 / 1.30.4",
        });
    }
    out
}

// ── Signal tracking (drives attack-path synthesis) + result collector ───────────────────────────

#[derive(Default, Clone)]
struct ClusterMeta {
    git_version: Option<String>,
    managed_provider: Option<String>,
    platform_tools: Vec<String>,
}

#[derive(Default)]
struct PodDangerStats {
    privileged: u32,
    host_pid: u32,
    host_network: u32,
    host_path: u32,
    automount_token: u32,
}

#[derive(Default)]
#[derive(Clone)]
struct Signals {
    anon_api: bool,
    api_secrets_anon: bool,
    api_pods_anon: bool,
    insecure_8080: bool,
    rbac_anon_binding: bool,
    kubelet_anon_read: bool,
    kubelet_exec: bool,
    etcd_plaintext: bool,
    etcd_keys_dump: bool,
    docker_unauth: bool,
    registry_anon_catalog: bool,
    envoy_config_leak: bool,
    envoy_cert_leak: bool,
    tiller: bool,
    dashboard_open: bool,
    gitops_exposed: bool,
    prometheus_exposed: bool,
    grafana_exposed: bool,
    dangerous_pods_visible: bool,
    events_secrets_leak: bool,
    webhook_urls_exposed: bool,
    containerd_exposed: bool,
    cert_manager_exposed: bool,
    networkpolicy_gap: bool,
    tls_expired: bool,
    api_endpoint: Option<String>,
    kubelet_endpoint: Option<String>,
    etcd_endpoint: Option<String>,
}

#[derive(Default)]
struct Collector {
    findings: Vec<Value>,
    nodes: Vec<Value>,
    edges: Vec<Value>,
    open_ports: Vec<u16>,
    /// Operator-supplied extra API paths to probe (job_params.extra_paths) — the "infinite options"
    /// guarantee: any path the operator names is probed on every confirmed API endpoint.
    extra_paths: Vec<String>,
    /// Optional namespace scope from job_params (defaults to `default`).
    target_namespace: String,
    cluster_meta: ClusterMeta,
    pod_stats: PodDangerStats,
    sig: Signals,
}

impl Collector {
    fn push(&mut self, f: Value) {
        self.findings.push(f);
    }

    fn add_node(&mut self, id: &str, label: &str, kind: &str, status: &str) {
        if self.nodes.iter().any(|n| n["id"] == json!(id)) {
            return;
        }
        self.nodes
            .push(json!({ "id": id, "label": label, "type": kind, "status": status }));
    }

    fn add_edge(&mut self, from: &str, to: &str, kind: &str, label: &str) {
        self.edges
            .push(json!({ "from": from, "to": to, "type": kind, "label": label }));
    }

    fn note_open(&mut self, port: u16) {
        if !self.open_ports.contains(&port) {
            self.open_ports.push(port);
        }
    }
}

// ── Body classification helpers (confirm a real Kubernetes/container signal before reporting) ────

/// Confirm the JSON body is a Kubernetes API-server `/version` payload, and return its `gitVersion`.
fn version_from_body(body: &str) -> Option<String> {
    let v: Value = serde_json::from_str(body).ok()?;
    let git = v.get("gitVersion").and_then(Value::as_str)?;
    // Require the structural shape of the apiserver /version response to avoid false positives.
    if v.get("major").is_some() || v.get("buildDate").is_some() || git.starts_with('v') {
        Some(git.to_string())
    } else {
        None
    }
}

/// True when an API list response was returned anonymously (real RBAC/anonymous-auth exposure).
fn is_api_list(body: &str) -> bool {
    let lc = body.to_ascii_lowercase();
    (lc.contains("\"kind\"") && lc.contains("\"items\""))
        || lc.contains("\"apiversion\"")
        || lc.contains("apiresourcelist")
        || lc.contains("apiversions")
        || lc.contains("\"paths\"")
}

/// Count items in a Kubernetes list response (e.g. number of anonymously-readable secrets).
fn count_items(body: &str) -> Option<usize> {
    let v: Value = serde_json::from_str(body).ok()?;
    v.get("items").and_then(Value::as_array).map(Vec::len)
}

/// Detect a binding of the cluster-admin / privileged groups to anonymous principals — the precise
/// misconfiguration that turns "API reachable" into "API fully owned".
fn rbac_anonymous_binding(body: &str) -> Vec<String> {
    let lc = body.to_ascii_lowercase();
    let mut hits = Vec::new();
    let dangerous_subjects = [
        "system:anonymous",
        "system:unauthenticated",
        "system:authenticated",
    ];
    if lc.contains("clusterrolebinding") || lc.contains("rolebinding") {
        for s in dangerous_subjects {
            if lc.contains(s) {
                hits.push(s.to_string());
            }
        }
    }
    hits
}

/// A kube-apiserver Status object (returned even on 401/403) is a strong, low-false-positive signal
/// that the endpoint really is a Kubernetes API server rather than a generic web service.
fn is_k8s_status(body: &str) -> bool {
    let lc = body.to_ascii_lowercase();
    lc.contains("\"kind\":\"status\"")
        || (lc.contains("\"status\":\"failure\"") && lc.contains("\"reason\""))
        || lc.contains("forbidden: user \"system:anonymous\"")
}

fn looks_like_kube_apiserver(p: &HttpProbe) -> bool {
    header_value(&p.headers, "audit-id").is_some()
        || version_from_body(&p.body).is_some()
        || is_api_list(&p.body)
        || is_k8s_status(&p.body)
}

/// Infer the managed Kubernetes provider from a real `gitVersion` string (GKE/EKS/AKS suffixes).
fn detect_managed_provider(git_version: &str) -> Option<&'static str> {
    let lc = git_version.to_ascii_lowercase();
    if lc.contains("gke") {
        return Some("GKE");
    }
    if lc.contains("eks") || lc.contains("-aws") {
        return Some("EKS");
    }
    if lc.contains("aks") || lc.contains("azure") {
        return Some("AKS");
    }
    if lc.contains("openshift") || lc.contains("okd") {
        return Some("OpenShift");
    }
    if lc.contains("rke") || lc.contains("rancher") {
        return Some("Rancher");
    }
    if lc.contains("iks") {
        return Some("IBM IKS");
    }
    if lc.contains("oke") || lc.contains("oracle") {
        return Some("OKE");
    }
    if lc.contains("tke") || lc.contains("tencent") {
        return Some("TKE");
    }
    if lc.contains("digitalocean") || lc.contains("doks") {
        return Some("DOKS");
    }
    None
}

/// Parse a real `/api/v1/pods` list body and count dangerous workload configurations.
fn analyze_pod_dangers(body: &str) -> PodDangerStats {
    let mut stats = PodDangerStats::default();
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return stats;
    };
    let Some(items) = v.get("items").and_then(Value::as_array) else {
        return stats;
    };
    for pod in items {
        let Some(spec) = pod.get("spec") else {
            continue;
        };
        if spec
            .get("hostPID")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            stats.host_pid += 1;
        }
        if spec
            .get("hostNetwork")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            stats.host_network += 1;
        }
        if let Some(vols) = spec.get("volumes").and_then(Value::as_array) {
            if vols.iter().any(|vol| vol.get("hostPath").is_some()) {
                stats.host_path += 1;
            }
        }
        if spec
            .get("automountServiceAccountToken")
            .and_then(Value::as_bool)
            != Some(false)
        {
            stats.automount_token += 1;
        }
        for key in ["containers", "initContainers"] {
            if let Some(arr) = spec.get(key).and_then(Value::as_array) {
                for c in arr {
                    if c.get("securityContext")
                        .and_then(|sc| sc.get("privileged"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        stats.privileged += 1;
                    }
                }
            }
        }
    }
    stats
}

fn pod_stats_any(d: &PodDangerStats) -> bool {
    d.privileged > 0
        || d.host_pid > 0
        || d.host_network > 0
        || d.host_path > 0
        || d.automount_token > 0
}

/// Extract admission webhook callback URLs / service references from a Kubernetes list body.
fn extract_admission_webhook_urls(body: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(items) = v.get("items").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut urls = Vec::new();
    for item in items {
        let Some(webhooks) = item.get("webhooks").and_then(Value::as_array) else {
            continue;
        };
        for wh in webhooks {
            if let Some(u) = wh
                .pointer("/clientConfig/url")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
            {
                urls.push(u.to_string());
            }
            if let Some(svc) = wh.get("clientConfig").and_then(|c| c.get("service")) {
                if let (Some(ns), Some(name)) = (
                    svc.get("namespace").and_then(Value::as_str),
                    svc.get("name").and_then(Value::as_str),
                ) {
                    urls.push(format!("service:{}/{}", ns, name));
                }
            }
        }
    }
    urls.sort();
    urls.dedup();
    urls
}

/// Flag ClusterRoles that grant cluster-admin-equivalent or escalate+wildcard rules.
fn dangerous_cluster_roles(body: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(items) = v.get("items").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut hits = Vec::new();
    for cr in items {
        let name = cr
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if matches!(name, "cluster-admin" | "admin" | "edit") {
            hits.push(name.to_string());
            continue;
        }
        if let Some(rules) = cr.get("rules").and_then(Value::as_array) {
            for rule in rules {
                let wild_verb = rule
                    .get("verbs")
                    .and_then(Value::as_array)
                    .is_some_and(|v| v.iter().any(|x| x.as_str() == Some("*")));
                let wild_res = rule
                    .get("resources")
                    .and_then(Value::as_array)
                    .is_some_and(|r| r.iter().any(|x| x.as_str() == Some("*")));
                let escalate = rule
                    .get("verbs")
                    .and_then(Value::as_array)
                    .is_some_and(|v| v.iter().any(|x| x.as_str() == Some("escalate")));
                if escalate && (wild_verb || wild_res) {
                    hits.push(name.to_string());
                    break;
                }
            }
        }
    }
    hits.sort();
    hits.dedup();
    hits
}

/// Composite blast-radius score (0–100) from live signals — how far an attacker can reach from observed exposure alone.
fn blast_radius_score(sig: &Signals, pods: &PodDangerStats) -> u32 {
    let mut score = 0u32;
    if sig.anon_api {
        score += 25;
    }
    if sig.api_secrets_anon {
        score += 25;
    }
    if sig.insecure_8080 {
        score += 20;
    }
    if sig.etcd_plaintext || sig.etcd_keys_dump {
        score += 20;
    }
    if sig.kubelet_exec || sig.kubelet_anon_read {
        score += 15;
    }
    if sig.docker_unauth || sig.containerd_exposed {
        score += 12;
    }
    if sig.events_secrets_leak {
        score += 10;
    }
    if sig.dangerous_pods_visible || pod_stats_any(pods) {
        score += 8;
    }
    if sig.gitops_exposed {
        score += 8;
    }
    if sig.registry_anon_catalog {
        score += 8;
    }
    score.min(100)
}

// ── Surface 1: Kubernetes API server ────────────────────────────────────────────────────────────

impl Collector {
    async fn probe_api_server(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        token: Option<&str>,
        ports: &[u16],
        intensity: Intensity,
        target: &str,
    ) {
        let open = tcp_scan(host, ports, 24).await;
        for &port in &open {
            self.note_open(port);
            let scheme = if port == 8080 { "http" } else { "https" };
            let endpoint = format!("{}://{}:{}", scheme, host, port);

            // Confirm this is genuinely a Kubernetes API server before emitting any finding.
            let ver_probe = get(client, &url(scheme, host, port, "/version"), token).await;
            let api_probe = get(client, &url(scheme, host, port, "/api/v1"), token).await;
            let apis_probe = get(client, &url(scheme, host, port, "/apis"), token).await;
            let confirmed = [ver_probe.as_ref(), api_probe.as_ref(), apis_probe.as_ref()]
                .into_iter()
                .flatten()
                .any(looks_like_kube_apiserver);
            if !confirmed {
                continue;
            }
            self.sig
                .api_endpoint
                .get_or_insert_with(|| endpoint.clone());
            self.add_node("internet", "Internet", "root", "exposed");
            let node_id = format!("apiserver:{}", port);
            self.add_node(
                &node_id,
                &format!("kube-apiserver :{}", port),
                "k8s_api",
                "exposed",
            );
            self.add_edge("internet", &node_id, "reachable", "TCP/HTTPS reachable");

            // Version disclosure + CVE intelligence (only when a real gitVersion is observed).
            if let Some(vp) = ver_probe.as_ref() {
                if let Some(gv) = version_from_body(&vp.body) {
                    let mut ev = Evidence::new()
                        .with("endpoint", endpoint.clone())
                        .with("git_version", gv.clone())
                        .check(
                            "apiserver_version_disclosed",
                            true,
                            json!({ "status": vp.status }),
                        );
                    let parsed = parse_semver(&gv);
                    let cves = parsed.map(known_k8s_cves).unwrap_or_default();
                    if let Some((a, b, c)) = parsed {
                        ev = ev.with("parsed_version", format!("{}.{}.{}", a, b, c));
                    }
                    self.cluster_meta.git_version = Some(gv.clone());
                    if let Some(provider) = detect_managed_provider(&gv) {
                        self.cluster_meta.managed_provider = Some(provider.to_string());
                        ev = ev.with("managed_provider", provider);
                    }
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("Kubernetes API server version disclosed ({})", gv),
                        if cves.is_empty() { "low" } else { "medium" },
                        "T1592",
                        "The kube-apiserver /version endpoint discloses the exact build, allowing an attacker to look up version-specific control-plane CVEs. Restrict anonymous access to /version.",
                        target,
                        0.95,
                        ev,
                    ));
                    for cve in cves {
                        let sev = severity_for_score((cve.cvss / 10.0).clamp(0.0, 1.0));
                        let ev = Evidence::new()
                            .with("endpoint", endpoint.clone())
                            .with("detected_version", gv.clone())
                            .with("cve", cve.id)
                            .with("cvss", cve.cvss)
                            .with("fixed_in", cve.fixed_in)
                            .check("version_in_vulnerable_range", true, cve.title);
                        self.push(finding_rich(
                            ENGINE_ID,
                            &format!(
                                "{} — control plane on {} is in the affected range",
                                cve.id, gv
                            ),
                            sev,
                            cve.mitre,
                            &format!(
                                "{}. Upgrade the control plane to a fixed release ({}).",
                                cve.title, cve.fixed_in
                            ),
                            target,
                            0.8,
                            ev,
                        ));
                    }
                }
            }

            // Live TLS certificate posture on standard HTTPS API ports (real cert handshake).
            if scheme == "https" && matches!(port, 443 | 8443) {
                if let Some(cert) = crate::engine_probes::tls_cert_details(host).await {
                    if cert.expired {
                        self.sig.tls_expired = true;
                        let ev = Evidence::new()
                            .with("endpoint", endpoint.clone())
                            .with("issuer", cert.issuer.clone())
                            .with("subject", cert.subject.clone())
                            .with("days_until_expiry", cert.days_until_expiry)
                            .check("apiserver_cert_expired", true, "TLS certificate is expired");
                        self.push(finding_rich(
                            ENGINE_ID,
                            "Kubernetes API server TLS certificate is EXPIRED",
                            "high",
                            "T1557",
                            "The API server presents an expired TLS certificate. Clients may disable verification or fail closed; expired certs often indicate neglected patch cadence and may coincide with broader control-plane neglect.",
                            target,
                            0.88,
                            ev,
                        ));
                    } else if cert.self_signed {
                        let ev = Evidence::new()
                            .with("endpoint", endpoint.clone())
                            .with("issuer", cert.issuer.clone())
                            .check(
                                "apiserver_self_signed_cert",
                                true,
                                "self-signed certificate observed",
                            );
                        self.push(finding_rich(
                            ENGINE_ID,
                            "Kubernetes API server uses a self-signed TLS certificate",
                            "medium",
                            "T1557",
                            "The API server presents a self-signed certificate. This is common in lab clusters but enables trivial MITM if clients skip CA verification. Use a cluster-trusted CA (kube-ca / corporate PKI).",
                            target,
                            0.75,
                            ev,
                        ));
                    } else if cert.days_until_expiry >= 0 && cert.days_until_expiry < 30 {
                        let ev = Evidence::new()
                            .with("endpoint", endpoint.clone())
                            .with("days_until_expiry", cert.days_until_expiry)
                            .check("apiserver_cert_expiring_soon", true, "< 30 days remaining");
                        self.push(finding_rich(
                            ENGINE_ID,
                            &format!(
                                "Kubernetes API server TLS certificate expires in {} day(s)",
                                cert.days_until_expiry
                            ),
                            "medium",
                            "T1557",
                            "The API server certificate is nearing expiry. Rotate before expiry to avoid client outages and emergency break-glass procedures that weaken TLS validation.",
                            target,
                            0.7,
                            ev,
                        ));
                    }
                    if cert.public_key_bits > 0 && cert.public_key_bits < 2048 {
                        let ev = Evidence::new()
                            .with("endpoint", endpoint.clone())
                            .with("public_key_bits", cert.public_key_bits)
                            .check("weak_tls_key", true, "RSA key < 2048 bits");
                        self.push(finding_rich(
                            ENGINE_ID,
                            &format!(
                                "Kubernetes API server TLS key is weak ({} bits)",
                                cert.public_key_bits
                            ),
                            "high",
                            "T1557",
                            "The API server certificate uses a sub-2048-bit RSA key. Regenerate with ≥2048-bit RSA or prefer ECDSA P-256/P-384.",
                            target,
                            0.82,
                            ev,
                        ));
                    }
                }
            }

            // Insecure port 8080 (deprecated --insecure-port) — anything served here is unauth admin.
            if port == 8080 {
                if let Some(p) = api_probe.as_ref().or(ver_probe.as_ref()) {
                    if p.status == 200
                        && (is_api_list(&p.body) || version_from_body(&p.body).is_some())
                    {
                        self.sig.insecure_8080 = true;
                        self.sig.anon_api = true;
                        self.add_node(
                            &node_id,
                            "kube-apiserver :8080 (insecure)",
                            "k8s_api",
                            "takeover",
                        );
                        let ev = Evidence::new()
                            .with("endpoint", endpoint.clone())
                            .check(
                                "insecure_port_serves_api",
                                true,
                                json!({ "status": p.status }),
                            )
                            .raw_excerpt(p.body.as_bytes());
                        self.push(finding_rich(
                            ENGINE_ID,
                            "Kubernetes legacy insecure API port 8080 is open and serving the API",
                            "critical",
                            "T1610",
                            "The deprecated --insecure-port (8080) bypasses authentication and authorization entirely. Any client that reaches it has full cluster-admin. Disable the insecure port (set --insecure-port=0) immediately.",
                            target,
                            0.95,
                            ev,
                        ));
                    }
                }
            }

            // Anonymous reachability of /api/v1: 200 list ⇒ anonymous-auth; 401/403 ⇒ gated-but-exposed.
            if let Some(p) = api_probe.as_ref() {
                if p.status == 200 && is_api_list(&p.body) {
                    self.sig.anon_api = true;
                    self.add_node(
                        &node_id,
                        &format!("kube-apiserver :{}", port),
                        "k8s_api",
                        "takeover",
                    );
                    let ev = Evidence::new()
                        .with("endpoint", endpoint.clone())
                        .with("path", "/api/v1")
                        .check("anonymous_api_list", true, json!({ "status": 200 }))
                        .raw_excerpt(p.body.as_bytes());
                    self.push(finding_rich(
                        ENGINE_ID,
                        "Kubernetes API server allows ANONYMOUS resource listing",
                        "critical",
                        "T1613",
                        "GET /api/v1 returned a resource list without credentials — anonymous-auth is enabled and system:anonymous is bound to a readable role. An unauthenticated attacker can enumerate the cluster. Set --anonymous-auth=false and audit ClusterRoleBindings for system:anonymous / system:unauthenticated.",
                        target,
                        0.9,
                        ev,
                    ));
                } else if matches!(p.status, 401 | 403) && looks_like_kube_apiserver(p) {
                    let ev = Evidence::new()
                        .with("endpoint", endpoint.clone())
                        .with("path", "/api/v1")
                        .check("api_reachable_gated", true, json!({ "status": p.status }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("Kubernetes API server reachable (authenticated) on :{}", port),
                        "high",
                        "T1133",
                        "The kube-apiserver is network-reachable and returns an authenticated rejection. The control plane should never be exposed to untrusted networks — restrict the API endpoint to a bastion/VPN or authorized CIDR allow-list.",
                        target,
                        0.85,
                        ev,
                    ));
                }
            }

            // When anonymous, quantify the blast radius: secrets / pods / nodes / service accounts.
            if self.sig.anon_api {
                self.probe_anonymous_enumeration(
                    client, host, port, scheme, token, intensity, target, &node_id,
                )
                .await;
            }

            // Authenticated RBAC misconfiguration hunt (only when the operator supplied a token).
            if token.is_some() {
                let rb = get(
                    client,
                    &url(
                        scheme,
                        host,
                        port,
                        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                    ),
                    token,
                )
                .await;
                if let Some(p) = rb {
                    if p.status == 200 {
                        let subjects = rbac_anonymous_binding(&p.body);
                        let masters = p.body.to_ascii_lowercase().contains("system:masters");
                        if !subjects.is_empty() || masters {
                            self.sig.rbac_anon_binding = true;
                            let mut ev = Evidence::new()
                                .with("endpoint", endpoint.clone())
                                .with(
                                    "path",
                                    "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                                )
                                .check("dangerous_subjects", !subjects.is_empty(), json!(subjects));
                            if masters {
                                ev = ev.check(
                                    "system_masters_binding",
                                    true,
                                    "a binding references the system:masters super-group",
                                );
                            }
                            self.push(finding_rich(
                                ENGINE_ID,
                                "Dangerous ClusterRoleBinding subjects detected (anonymous / unauthenticated / system:masters)",
                                "critical",
                                "T1078",
                                "A ClusterRoleBinding grants privileges to system:anonymous, system:unauthenticated, system:authenticated or system:masters. These bind powerful roles to effectively-unauthenticated or all-authenticated principals. Remove the binding and grant least-privilege roles to named subjects.",
                                target,
                                0.85,
                                ev,
                            ));
                        }
                    }
                }
            }

            if token.is_some() {
                self.probe_authenticated_privileges(client, host, port, scheme, token, target)
                    .await;
            }

            // Extra API paths from the operator + OIDC discovery (aggressive).
            self.probe_api_extras(client, host, port, scheme, token, intensity, target)
                .await;
        }
    }
}

impl Collector {
    /// Quantify anonymous read access against high-value resource collections.
    #[allow(clippy::too_many_arguments)]
    async fn probe_anonymous_enumeration(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        port: u16,
        scheme: &str,
        token: Option<&str>,
        intensity: Intensity,
        target: &str,
        node_id: &str,
    ) {
        // (path, label, severity, mitre) — high-value collections to test for anonymous read.
        let mut targets: Vec<(String, &str, &str, &str)> = vec![
            (
                "/api/v1/secrets".to_string(),
                "Secrets",
                "critical",
                "T1552.007",
            ),
            (
                "/api/v1/pods".to_string(),
                "Pods",
                "critical",
                "T1613",
            ),
        ];
        let ns = self.target_namespace.trim();
        if !ns.is_empty() {
            targets.push((
                format!("/api/v1/namespaces/{ns}/secrets"),
                "Namespace Secrets",
                "critical",
                "T1552.007",
            ));
        }
        if !matches!(intensity, Intensity::Light) {
            targets.extend([
                (
                    "/api/v1/namespaces".to_string(),
                    "Namespaces",
                    "high",
                    "T1613",
                ),
                (
                    "/api/v1/serviceaccounts".to_string(),
                    "ServiceAccounts",
                    "critical",
                    "T1528",
                ),
                (
                    "/api/v1/configmaps".to_string(),
                    "ConfigMaps",
                    "high",
                    "T1552",
                ),
                (
                    "/api/v1/nodes".to_string(),
                    "Nodes",
                    "high",
                    "T1613",
                ),
            ]);
        }
        for (path, label, sev, mitre) in targets {
            let Some(p) = get(client, &url(scheme, host, port, &path), token).await else {
                continue;
            };
            if p.status != 200 || !is_api_list(&p.body) {
                continue;
            }
            let n = count_items(&p.body).unwrap_or(0);
            match label {
                "Secrets" => self.sig.api_secrets_anon = true,
                "Pods" => {
                    self.sig.api_pods_anon = true;
                    let dangers = analyze_pod_dangers(&p.body);
                    if pod_stats_any(&dangers) {
                        self.sig.dangerous_pods_visible = true;
                        self.pod_stats.privileged += dangers.privileged;
                        self.pod_stats.host_pid += dangers.host_pid;
                        self.pod_stats.host_network += dangers.host_network;
                        self.pod_stats.host_path += dangers.host_path;
                        self.pod_stats.automount_token += dangers.automount_token;
                        let ev = Evidence::new()
                            .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                            .with("privileged_pods", dangers.privileged)
                            .with("host_pid_pods", dangers.host_pid)
                            .with("host_network_pods", dangers.host_network)
                            .with("host_path_pods", dangers.host_path)
                            .with("automount_token_pods", dangers.automount_token)
                            .check(
                                "dangerous_workloads_enumerated",
                                true,
                                "anonymous pod list reveals escape-prone configurations",
                            );
                        self.push(finding_rich(
                            ENGINE_ID,
                            "Anonymous pod enumeration reveals escape-prone workloads (privileged / hostPID / hostPath)",
                            "critical",
                            "T1611",
                            "An unauthenticated pod list exposes workloads running privileged, hostPID, hostNetwork or hostPath mounts — each is a direct container-escape / node-takeover primitive. Restrict anonymous API access and enforce Pod Security Standards (restricted/baseline).",
                            target,
                            0.9,
                            ev,
                        ));
                    }
                }
                _ => {}
            }
            self.add_node(node_id, "kube-apiserver", "k8s_api", "takeover");
            let mut ev = Evidence::new()
                .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                .with("path", path.clone())
                .with("items_readable", n)
                .check(
                    "anonymous_collection_read",
                    true,
                    json!({ "status": 200, "items": n }),
                );
            // Secrets are the crown jewels — capture (bounded) evidence that real data is exposed.
            if label == "Secrets" && n > 0 {
                ev = ev.raw_excerpt(p.body.as_bytes());
            }
            self.push(finding_rich(
                ENGINE_ID,
                &format!("Anonymous read of Kubernetes {} ({} object(s) exposed)", label, n),
                sev,
                mitre,
                &format!(
                    "An unauthenticated GET {} returned {} object(s). {} are directly readable by anyone who can reach the API server.",
                    path, n, label
                ),
                target,
                0.92,
                ev,
            ));
        }
    }

    /// Operator-supplied extra paths + OIDC/JWKS discovery + apiserver metrics (aggressive).
    async fn probe_api_extras(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        port: u16,
        scheme: &str,
        token: Option<&str>,
        intensity: Intensity,
        target: &str,
    ) {
        // Operator-named extra paths — always probed (the operator explicitly asked for them).
        let extras = self.extra_paths.clone();
        for path in extras {
            let path = if path.starts_with('/') {
                path
            } else {
                format!("/{}", path)
            };
            if let Some(p) = get(client, &url(scheme, host, port, &path), token).await {
                if matches!(p.status, 200 | 401 | 403) && looks_like_kube_apiserver(&p) {
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                        .with("path", path.clone())
                        .check(
                            "operator_path_reachable",
                            true,
                            json!({ "status": p.status }),
                        );
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("Operator-specified API path reachable: {}", path),
                        if p.status == 200 { "high" } else { "medium" },
                        "T1613",
                        "An operator-supplied API path is reachable on the kube-apiserver. Review whether this surface should be anonymously/network reachable.",
                        target,
                        0.75,
                        ev,
                    ));
                }
            }
        }
        if !matches!(intensity, Intensity::Aggressive) {
            return;
        }
        // OIDC service-account issuer discovery — useful for token-forgery research / federation abuse.
        for path in ["/.well-known/openid-configuration", "/openid/v1/jwks"] {
            if let Some(p) = get(client, &url(scheme, host, port, path), token).await {
                let lc = p.body.to_ascii_lowercase();
                if p.status == 200 && (lc.contains("issuer") || lc.contains("\"keys\"")) {
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                        .with("path", path)
                        .check("oidc_discovery_anonymous", true, json!({ "status": 200 }))
                        .raw_excerpt(p.body.as_bytes());
                    self.push(finding_rich(
                        ENGINE_ID,
                        "Kubernetes OIDC/JWKS service-account discovery is anonymously readable",
                        "medium",
                        "T1528",
                        "The service-account issuer discovery document / JWKS is exposed anonymously. While public by design in some setups, internet exposure helps an attacker map the SA token trust chain and any external federation. Restrict to trusted networks unless projected-token federation requires it.",
                        target,
                        0.7,
                        ev,
                    ));
                }
            }
        }
        // apiserver /metrics — leaks namespaces, object counts and node names.
        if let Some(p) = get(client, &url(scheme, host, port, "/metrics"), token).await {
            if p.status == 200 && p.body.contains("apiserver_") {
                let ev = Evidence::new()
                    .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                    .with("path", "/metrics")
                    .check(
                        "apiserver_metrics_anonymous",
                        true,
                        json!({ "status": 200, "bytes": p.body.len() }),
                    );
                self.push(finding_rich(
                    ENGINE_ID,
                    "kube-apiserver /metrics exposed anonymously",
                    "medium",
                    "T1613",
                    "The API server Prometheus metrics endpoint is anonymously readable and leaks namespace names, object counts, request patterns and node identities. Gate /metrics behind authentication (RBAC: nonResourceURLs '/metrics').",
                    target,
                    0.8,
                    ev,
                ));
            }
        }
        // pprof heap profile (CIS 1.2.19 — profiling must be disabled in production).
        if let Some(p) = get(client, &url(scheme, host, port, "/debug/pprof/"), token).await {
            if p.status == 200
                && (p.body.contains("Types of profiles") || p.body.contains("profile?debug="))
            {
                let ev = Evidence::new()
                    .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                    .with("path", "/debug/pprof/")
                    .check("apiserver_pprof_exposed", true, json!({ "status": 200 }));
                self.push(finding_rich(
                    ENGINE_ID,
                    "kube-apiserver pprof profiling endpoint is exposed",
                    "high",
                    "T1613",
                    "The API server /debug/pprof/ endpoint is reachable. Profiling endpoints leak memory layouts and internal state useful for exploit development. Disable profiling (--profiling=false) on all control-plane components.",
                    target,
                    0.85,
                    ev,
                ));
            }
        }
        // Admission webhook configuration readable anonymously (attack surface mapping).
        if let Some(p) = get(
            client,
            &url(
                scheme,
                host,
                port,
                "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
            ),
            token,
        )
        .await
        {
            if p.status == 200 && is_api_list(&p.body) {
                let n = count_items(&p.body).unwrap_or(0);
                let webhook_urls = extract_admission_webhook_urls(&p.body);
                if !webhook_urls.is_empty() {
                    self.sig.webhook_urls_exposed = true;
                }
                let mut ev = Evidence::new()
                    .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                    .with("webhooks_enumerable", n)
                    .check("validating_webhooks_anonymous", true, json!({ "items": n }));
                if !webhook_urls.is_empty() {
                    ev = ev.with("webhook_callbacks", json!(webhook_urls));
                }
                self.push(finding_rich(
                    ENGINE_ID,
                    &format!(
                        "ValidatingWebhookConfigurations anonymously readable ({} webhook(s){})",
                        n,
                        if webhook_urls.is_empty() {
                            String::new()
                        } else {
                            format!(", {} callback URL(s) mapped", webhook_urls.len())
                        }
                    ),
                    if webhook_urls.is_empty() {
                        "medium"
                    } else {
                        "high"
                    },
                    "T1613",
                    "An unauthenticated caller can enumerate every ValidatingWebhookConfiguration — mapping admission control coverage and webhook endpoint URLs for targeted bypass or SSRF research. Restrict anonymous API access.",
                    target,
                    0.78,
                    ev,
                ));
            }
        }
        // Mutating webhooks — same mapping for write-path admission.
        if let Some(p) = get(
            client,
            &url(
                scheme,
                host,
                port,
                "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
            ),
            token,
        )
        .await
        {
            if p.status == 200 && is_api_list(&p.body) {
                let urls = extract_admission_webhook_urls(&p.body);
                if !urls.is_empty() {
                    self.sig.webhook_urls_exposed = true;
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                        .with("mutating_webhook_callbacks", json!(urls))
                        .check("mutating_webhooks_anonymous", true, json!({ "callbacks": urls.len() }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!(
                            "MutatingWebhookConfigurations expose {} callback target(s) to anonymous callers",
                            urls.len()
                        ),
                        "high",
                        "T1613",
                        "Mutating admission webhook clientConfig URLs are enumerable without authentication. These endpoints receive Kubernetes object payloads during create/update — a high-value SSRF / lateral-movement target if reachable from the scan origin.",
                        target,
                        0.8,
                        ev,
                    ));
                }
            }
        }
        // Events API — Kubernetes events often embed secret material in error messages.
        if let Some(p) = get(client, &url(scheme, host, port, "/api/v1/events"), token).await {
            if p.status == 200 && is_api_list(&p.body) {
                let n = count_items(&p.body).unwrap_or(0);
                let secret_types = crate::engine_probes::detect_secrets(&p.body);
                if !secret_types.is_empty() {
                    self.sig.events_secrets_leak = true;
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                        .with("events_readable", n)
                        .with("secret_patterns", json!(secret_types))
                        .check("events_contain_secret_patterns", true, "live pattern match in event messages")
                        .raw_excerpt(p.body.as_bytes());
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!(
                            "Kubernetes Events API leaks secret-like material ({} event(s), patterns: {:?})",
                            n, secret_types
                        ),
                        "critical",
                        "T1552",
                        "The /api/v1/events collection is readable and contains strings matching high-confidence secret patterns (API keys, tokens, private keys). Events frequently echo failed mount errors with full secret values. Restrict events list/get and scrub sensitive data from controller logs.",
                        target,
                        0.88,
                        ev,
                    ));
                } else if n > 0 {
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                        .with("events_readable", n)
                        .check("events_anonymous_list", true, json!({ "items": n }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("Kubernetes Events API anonymously readable ({} event(s))", n),
                        "medium",
                        "T1613",
                        "Cluster events are listable without authentication. Even without embedded secrets, events disclose pod names, failure reasons, image pull errors and controller identities useful for targeted attacks.",
                        target,
                        0.72,
                        ev,
                    ));
                }
            }
        }
        // ClusterRoles — enumerate dangerously permissive roles when readable.
        if let Some(p) = get(
            client,
            &url(
                scheme,
                host,
                port,
                "/apis/rbac.authorization.k8s.io/v1/clusterroles",
            ),
            token,
        )
        .await
        {
            if p.status == 200 && is_api_list(&p.body) {
                let dangerous = dangerous_cluster_roles(&p.body);
                if !dangerous.is_empty() {
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                        .with("dangerous_clusterroles", json!(dangerous))
                        .check("clusterroles_anonymous", true, json!({ "dangerous": dangerous.len() }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!(
                            "ClusterRoles with escalate/wildcard rules enumerable ({} role(s): {})",
                            dangerous.len(),
                            dangerous.join(", ")
                        ),
                        "high",
                        "T1078",
                        "Dangerous ClusterRoles (cluster-admin, admin, or rules with escalate+wildcard) are readable via the API. Combined with a bindable ServiceAccount this reveals the privilege-escalation ladder. Restrict anonymous RBAC enumeration.",
                        target,
                        0.82,
                        ev,
                    ));
                }
            }
        }
        // NetworkPolicy coverage gap — namespaces exist but zero policies cluster-wide.
        if let (Some(ns_p), Some(np_p)) = (
            get(client, &url(scheme, host, port, "/api/v1/namespaces"), token).await,
            get(
                client,
                &url(
                    scheme,
                    host,
                    port,
                    "/apis/networking.k8s.io/v1/networkpolicies",
                ),
                token,
            )
            .await,
        ) {
            if ns_p.status == 200
                && np_p.status == 200
                && is_api_list(&ns_p.body)
                && is_api_list(&np_p.body)
            {
                let ns_count = count_items(&ns_p.body).unwrap_or(0);
                let np_count = count_items(&np_p.body).unwrap_or(0);
                if ns_count >= 2 && np_count == 0 {
                    self.sig.networkpolicy_gap = true;
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                        .with("namespaces", ns_count)
                        .with("networkpolicies", np_count)
                        .check("zero_networkpolicies", true, "cluster has namespaces but no NetworkPolicies");
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!(
                            "Zero NetworkPolicies across {} namespace(s) — flat east-west network",
                            ns_count
                        ),
                        "high",
                        "T1190",
                        "The cluster has multiple namespaces but no NetworkPolicy objects were observed. Without default-deny segmentation, any compromised pod can reach every service in the cluster (lateral movement). Implement namespace-scoped default-deny policies.",
                        target,
                        0.85,
                        ev,
                    ));
                }
            }
        }
        // cert-manager certificates — often readable and reveal TLS material metadata.
        if let Some(p) = get(
            client,
            &url(
                scheme,
                host,
                port,
                "/apis/cert-manager.io/v1/certificates",
            ),
            token,
        )
        .await
        {
            if p.status == 200 && is_api_list(&p.body) {
                let n = count_items(&p.body).unwrap_or(0);
                if n > 0 {
                    self.sig.cert_manager_exposed = true;
                    if !self.cluster_meta.platform_tools.contains(&"cert-manager".to_string())
                    {
                        self.cluster_meta
                            .platform_tools
                            .push("cert-manager".to_string());
                    }
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                        .with("certificates_enumerable", n)
                        .check("cert_manager_crds_readable", true, json!({ "items": n }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!(
                            "cert-manager Certificate CRs anonymously readable ({} certificate(s))",
                            n
                        ),
                        "medium",
                        "T1552",
                        "cert-manager Certificate custom resources are listable — disclosing DNS names, issuers and secret references for every TLS certificate managed in-cluster. Restrict cert-manager CRD list/get to authenticated operators.",
                        target,
                        0.78,
                        ev,
                    ));
                }
            }
        }
        // TokenReview — validate whether the supplied bearer token is accepted (live auth probe).
        if let Some(tok) = token.filter(|t| !t.trim().is_empty()) {
            let review_url = url(
                scheme,
                host,
                port,
                "/apis/authentication.k8s.io/v1/tokenreviews",
            );
            let payload = json!({
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenReview",
                "spec": { "token": tok.trim() }
            });
            let auth_hdr = format!("Bearer {}", tok.trim());
            if let Some(p) = crate::engine_probes::http_post_json_with_headers(
                client,
                &review_url,
                &payload,
                &[("Authorization", auth_hdr.as_str())],
            )
            .await
            {
                if p.status == 201 || p.status == 200 {
                    if let Ok(v) = serde_json::from_str::<Value>(&p.body) {
                        let authenticated = v
                            .pointer("/status/authenticated")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let username = v
                            .pointer("/status/user/username")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown");
                        if authenticated {
                            let ev = Evidence::new()
                                .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                                .with("token_username", username)
                                .check("tokenreview_authenticated", true, json!({ "username": username }));
                            self.push(finding_rich(
                                ENGINE_ID,
                                &format!("Supplied bearer token is VALID (TokenReview → {})", username),
                                "info",
                                "T1078",
                                "Live TokenReview confirmed the operator-supplied bearer token is accepted by the API server. Subsequent SSAR / RBAC probes in this scan used this identity.",
                                target,
                                0.95,
                                ev,
                            ));
                        }
                    }
                }
            }
        }
    }

    /// With a supplied bearer token, perform live authorization probes (SelfSubjectAccessReview).
    async fn probe_authenticated_privileges(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        port: u16,
        scheme: &str,
        token: Option<&str>,
        target: &str,
    ) {
        let Some(tok) = token.filter(|t| !t.trim().is_empty()) else {
            return;
        };
        let endpoint = format!("{}://{}:{}", scheme, host, port);
        let ssar_url = url(
            scheme,
            host,
            port,
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        );
        let checks: &[(&str, Value)] = &[
            (
                "create pods in kube-system",
                json!({
                    "apiVersion": "authorization.k8s.io/v1",
                    "kind": "SelfSubjectAccessReview",
                    "spec": { "resourceAttributes": {
                        "namespace": "kube-system", "verb": "create", "resource": "pods", "group": ""
                    }}
                }),
            ),
            (
                "create clusterrolebindings",
                json!({
                    "apiVersion": "authorization.k8s.io/v1",
                    "kind": "SelfSubjectAccessReview",
                    "spec": { "resourceAttributes": {
                        "verb": "create", "resource": "clusterrolebindings",
                        "group": "rbac.authorization.k8s.io"
                    }}
                }),
            ),
            (
                "get secrets cluster-wide",
                json!({
                    "apiVersion": "authorization.k8s.io/v1",
                    "kind": "SelfSubjectAccessReview",
                    "spec": { "resourceAttributes": {
                        "verb": "get", "resource": "secrets", "group": ""
                    }}
                }),
            ),
        ];
        let mut allowed: Vec<String> = Vec::new();
        let auth_hdr = format!("Bearer {}", tok.trim());
        for (label, payload) in checks {
            if let Some(p) = crate::engine_probes::http_post_json_with_headers(
                client,
                &ssar_url,
                payload,
                &[("Authorization", auth_hdr.as_str())],
            )
            .await
            {
                if p.status == 201 || p.status == 200 {
                    if let Ok(v) = serde_json::from_str::<Value>(&p.body) {
                        if v.get("status")
                            .and_then(|s| s.get("allowed"))
                            .and_then(Value::as_bool)
                            == Some(true)
                        {
                            allowed.push((*label).to_string());
                        }
                    }
                }
            }
        }
        if !allowed.is_empty() {
            let sev = if allowed.iter().any(|a| a.contains("clusterrolebindings")) {
                "critical"
            } else {
                "high"
            };
            let ev = Evidence::new()
                .with("endpoint", endpoint.clone())
                .with("token_allowed_actions", json!(allowed))
                .check(
                    "ssar_privilege_probe",
                    true,
                    "SelfSubjectAccessReview confirmed allowed verbs",
                );
            self.push(finding_rich(
                ENGINE_ID,
                &format!(
                    "Supplied token has dangerous RBAC privileges ({})",
                    allowed.join(", ")
                ),
                sev,
                "T1078",
                "Live SelfSubjectAccessReview probes confirmed the supplied bearer token can perform high-impact actions. Rotate the token, audit its ClusterRoleBinding, and enforce least-privilege.",
                target,
                0.9,
                ev,
            ));
        }
    }
}

// ── Surface 2: kubelet (10250 read-write HTTPS, 10255 read-only HTTP) + cAdvisor (4194) ──────────

impl Collector {
    async fn probe_kubelet(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        token: Option<&str>,
        ports: &[u16],
        target: &str,
    ) {
        let open = tcp_scan(host, ports, 16).await;
        for &port in &open {
            self.note_open(port);
            let scheme = if port == 10255 { "http" } else { "https" };
            let endpoint = format!("{}://{}:{}", scheme, host, port);
            let pods = get(client, &url(scheme, host, port, "/pods"), token).await;
            let metrics = get(client, &url(scheme, host, port, "/metrics"), token).await;
            let confirmed = pods.as_ref().is_some_and(|p| {
                let lc = p.body.to_ascii_lowercase();
                lc.contains("podlist") || (lc.contains("\"items\"") && lc.contains("\"spec\""))
            }) || metrics
                .as_ref()
                .is_some_and(|p| p.body.contains("kubelet_"))
                || pods
                    .as_ref()
                    .is_some_and(|p| matches!(p.status, 401 | 403) && is_k8s_status(&p.body));
            if !confirmed {
                continue;
            }
            self.sig
                .kubelet_endpoint
                .get_or_insert_with(|| endpoint.clone());
            let node_id = format!("kubelet:{}", port);
            self.add_node(
                &node_id,
                &format!("kubelet :{}", port),
                "kubelet",
                "exposed",
            );
            self.add_node("internet", "Internet", "root", "exposed");
            self.add_edge("internet", &node_id, "reachable", "kubelet reachable");

            if let Some(p) = pods.as_ref() {
                if p.status == 200 && p.body.to_ascii_lowercase().contains("\"items\"") {
                    self.sig.kubelet_anon_read = true;
                    // On the read-write port, anonymous /pods means anonymous-auth is on ⇒ exec is open.
                    if port != 10255 {
                        self.sig.kubelet_exec = true;
                    }
                    self.add_node(
                        &node_id,
                        &format!("kubelet :{}", port),
                        "kubelet",
                        "takeover",
                    );
                    let n = count_items(&p.body).unwrap_or(0);
                    let (sev, conf, extra) = if port == 10255 {
                        ("critical", 0.9, "Read-only kubelet port 10255 requires no auth by design; pod specs expose every environment variable — including injected Secret values.")
                    } else {
                        ("critical", 0.92, "Anonymous access to the read-write kubelet (10250) is enabled. Beyond reading pod specs, an attacker can invoke /exec, /run and /attach to run commands inside any pod on this node — a direct container-breakout and node-takeover primitive.")
                    };
                    let ev = Evidence::new()
                        .with("endpoint", endpoint.clone())
                        .with("path", "/pods")
                        .with("pods_readable", n)
                        .check(
                            "anonymous_kubelet_pods",
                            true,
                            json!({ "status": 200, "pods": n }),
                        )
                        .raw_excerpt(p.body.as_bytes());
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!(
                            "Anonymous kubelet API exposed on :{} ({} pod(s) readable)",
                            port, n
                        ),
                        sev,
                        "T1611",
                        extra,
                        target,
                        conf,
                        ev,
                    ));
                } else if matches!(p.status, 401 | 403) {
                    let ev = Evidence::new().with("endpoint", endpoint.clone()).check(
                        "kubelet_reachable_gated",
                        true,
                        json!({ "status": p.status }),
                    );
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("kubelet API reachable (authenticated) on :{}", port),
                        "high",
                        "T1133",
                        "The kubelet API is network-reachable. It should be bound to the node's internal interface and require Webhook/X509 authn+authz. Restrict 10250/10255 to the control plane only.",
                        target,
                        0.82,
                        ev,
                    ));
                }
            }

            // configz leaks the live kubelet configuration (incl. whether anonymous-auth is enabled).
            if let Some(p) = get(client, &url(scheme, host, port, "/configz"), token).await {
                if p.status == 200 && p.body.to_ascii_lowercase().contains("kubeletconfig") {
                    let anon = p
                        .body
                        .to_ascii_lowercase()
                        .contains("\"anonymous\":{\"enabled\":true")
                        || p.body.to_ascii_lowercase().contains("\"enabled\":true");
                    let ev = Evidence::new()
                        .with("endpoint", endpoint.clone())
                        .with("path", "/configz")
                        .check("kubelet_config_disclosed", true, json!({ "status": 200 }))
                        .check(
                            "anonymous_auth_enabled",
                            anon,
                            "kubelet authentication.anonymous.enabled",
                        )
                        .raw_excerpt(p.body.as_bytes());
                    self.push(finding_rich(
                        ENGINE_ID,
                        "kubelet /configz discloses live node configuration",
                        "high",
                        "T1613",
                        "The kubelet configuration (authn/authz mode, cgroup driver, feature gates) is anonymously readable via /configz. This confirms the security posture of the node to an attacker. Disable anonymous access to the kubelet.",
                        target,
                        0.85,
                        ev,
                    ));
                }
            }
        }
    }

    async fn probe_cadvisor(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        ports: &[u16],
        target: &str,
    ) {
        let open = tcp_scan(host, ports, 8).await;
        for &port in &open {
            self.note_open(port);
            for path in ["/api/v1.3/containers", "/metrics", "/healthz"] {
                let Some(p) = get(client, &url("http", host, port, path), None).await else {
                    continue;
                };
                let is_cadvisor = p.body.contains("cadvisor_")
                    || p.body.contains("container_")
                    || p.body.to_ascii_lowercase().contains("\"subcontainers\"")
                    || (path == "/healthz" && p.status == 200);
                if p.status == 200 && is_cadvisor && path != "/healthz" {
                    self.add_node(
                        &format!("cadvisor:{}", port),
                        "cAdvisor",
                        "cadvisor",
                        "exposed",
                    );
                    let ev = Evidence::new()
                        .with("endpoint", format!("http://{}:{}", host, port))
                        .with("path", path)
                        .check(
                            "anonymous_cadvisor",
                            true,
                            json!({ "status": 200, "bytes": p.body.len() }),
                        );
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("cAdvisor metrics exposed anonymously on :{}", port),
                        "high",
                        "T1613",
                        "cAdvisor (4194) anonymously exposes per-container resource stats, image names, labels and command lines for every workload on the node — valuable reconnaissance for an attacker. Disable the standalone cAdvisor port (--cadvisor-port=0 / not exposing 4194).",
                        target,
                        0.85,
                        ev,
                    ));
                    break;
                }
            }
        }
    }
}

// ── Surface 3: etcd (2379 client / 2380 peer) — the cluster's unencrypted secret store ──────────

impl Collector {
    async fn probe_etcd(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        ports: &[u16],
        target: &str,
    ) {
        let open = tcp_scan(host, ports, 8).await;
        for &port in &open {
            self.note_open(port);
            if port == 2380 {
                self.add_node("etcd:2380", "etcd peer :2380", "etcd", "exposed");
                let ev = Evidence::new()
                    .with("endpoint", format!("{}:2380", host))
                    .check(
                        "etcd_peer_port_open",
                        true,
                        "TCP/2380 accepted a connection",
                    );
                self.push(finding_rich(
                    ENGINE_ID,
                    "etcd peer port 2380 is reachable",
                    "high",
                    "T1613",
                    "The etcd peer port (2380) is reachable. Peer traffic must stay on the control-plane network and be mutually TLS-authenticated; exposure enables cluster-membership attacks. Restrict to control-plane nodes only.",
                    target,
                    0.8,
                    ev,
                ));
                continue;
            }
            // Determine plaintext vs TLS on the client port by probing http:// then https://.
            let mut etcd_scheme: Option<&str> = None;
            let mut version_body = String::new();
            for scheme in ["http", "https"] {
                if let Some(p) = get(client, &url(scheme, host, port, "/version"), None).await {
                    if p.body.contains("etcdserver") || p.body.contains("etcdcluster") {
                        etcd_scheme = Some(scheme);
                        version_body = p.body.clone();
                        break;
                    }
                }
            }
            let Some(scheme) = etcd_scheme else { continue };
            self.sig
                .etcd_endpoint
                .get_or_insert_with(|| format!("{}://{}:{}", scheme, host, port));
            self.add_node("etcd:2379", "etcd :2379", "etcd", "takeover");
            self.add_node("internet", "Internet", "root", "exposed");
            self.add_edge(
                "internet",
                "etcd:2379",
                "reachable",
                "etcd client reachable",
            );

            let plaintext = scheme == "http";
            if plaintext {
                self.sig.etcd_plaintext = true;
            }
            let ev = Evidence::new()
                .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                .with("transport", if plaintext { "plaintext" } else { "tls" })
                .check("etcd_client_reachable", true, json!({ "scheme": scheme }))
                .raw_excerpt(version_body.as_bytes());
            self.push(finding_rich(
                ENGINE_ID,
                &format!(
                    "etcd client API reachable over {} on :{}",
                    if plaintext { "PLAINTEXT" } else { "TLS" },
                    port
                ),
                if plaintext { "critical" } else { "high" },
                "T1552.007",
                if plaintext {
                    "etcd is reachable over PLAINTEXT and without client-cert auth. etcd stores every Kubernetes Secret and ServiceAccount token unencrypted at rest — direct read access is equivalent to full cluster-admin plus lateral movement into any cloud the tokens reach. Enable peer/client TLS, client-cert auth, and encryption-at-rest immediately, and isolate etcd to the control-plane network."
                } else {
                    "The etcd client port is network-reachable. Even with TLS, etcd must never be exposed beyond the control plane. Enforce client-certificate authentication and a network allow-list."
                },
                target,
                if plaintext { 0.95 } else { 0.82 },
                ev,
            ));

            // Legacy v2 keyspace dump — a single GET can exfiltrate the entire key/value store.
            if let Some(p) = get(
                client,
                &url(scheme, host, port, "/v2/keys/?recursive=true"),
                None,
            )
            .await
            {
                let lc = p.body.to_ascii_lowercase();
                if p.status == 200 && lc.contains("\"action\":\"get\"") && lc.contains("\"node\"") {
                    self.sig.etcd_keys_dump = true;
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                        .with("path", "/v2/keys/?recursive=true")
                        .check(
                            "etcd_v2_keyspace_readable",
                            true,
                            json!({ "status": 200, "bytes": p.body.len() }),
                        )
                        .raw_excerpt(p.body.as_bytes());
                    self.push(finding_rich(
                        ENGINE_ID,
                        "etcd v2 keyspace is anonymously dumpable",
                        "critical",
                        "T1552.007",
                        "The deprecated etcd v2 API returned the recursive keyspace without authentication. An attacker can exfiltrate every stored key — including raw Kubernetes Secrets — in one request. Disable the v2 API and require client-cert authentication.",
                        target,
                        0.95,
                        ev,
                    ));
                }
            }
        }
    }
}

// ── Surface 4: Docker Engine API / CRI (2375 plaintext, 2376 TLS) ────────────────────────────────

impl Collector {
    async fn probe_docker(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        ports: &[u16],
        target: &str,
    ) {
        let open = tcp_scan(host, ports, 8).await;
        for &port in &open {
            self.note_open(port);
            let scheme = if port == 2376 { "https" } else { "http" };
            let ver = get(client, &url(scheme, host, port, "/version"), None).await;
            let is_docker = ver.as_ref().is_some_and(|p| {
                let lc = p.body.to_ascii_lowercase();
                lc.contains("\"apiversion\"")
                    && (lc.contains("\"gitcommit\"")
                        || lc.contains("\"goversion\"")
                        || lc.contains("\"os\""))
            });
            if !is_docker {
                continue;
            }
            self.add_node(
                &format!("docker:{}", port),
                &format!("Docker API :{}", port),
                "docker",
                "takeover",
            );
            self.add_node("internet", "Internet", "root", "exposed");
            self.add_edge(
                "internet",
                &format!("docker:{}", port),
                "reachable",
                "Docker daemon reachable",
            );
            let plaintext = port != 2376;
            if plaintext {
                self.sig.docker_unauth = true;
            }
            let mut containers = 0usize;
            if let Some(p) = get(client, &url(scheme, host, port, "/containers/json"), None).await {
                if p.status == 200 {
                    containers = serde_json::from_str::<Value>(&p.body)
                        .ok()
                        .and_then(|v| v.as_array().map(Vec::len))
                        .unwrap_or(0);
                }
            }
            let mut ev = Evidence::new()
                .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                .with("transport", if plaintext { "plaintext" } else { "tls" })
                .with("running_containers", containers)
                .check(
                    "docker_api_unauthenticated",
                    plaintext,
                    json!({ "containers": containers }),
                );
            if let Some(p) = ver.as_ref() {
                ev = ev.raw_excerpt(p.body.as_bytes());
            }
            self.push(finding_rich(
                ENGINE_ID,
                &format!("Docker Engine API exposed on :{} ({} running container(s))", port, containers),
                "critical",
                "T1610",
                if plaintext {
                    "The Docker Engine REST API is reachable over plaintext with no authentication. An attacker can create a privileged container that bind-mounts the host root filesystem (`-v /:/host`), achieving immediate root on the node and a pivot to every other container, the kubelet credentials and the cloud instance metadata. Never expose the Docker socket/TCP API; if remote access is required use 2376 with mutual TLS."
                } else {
                    "The Docker Engine API is reachable on the TLS port (2376). Confirm mutual-TLS client-certificate authentication is enforced; an exposed daemon API is equivalent to host root."
                },
                target,
                if plaintext { 0.95 } else { 0.8 },
                ev,
            ));
        }
    }

    /// containerd metrics / version endpoints (distinct from Docker Engine API on 2375/2376).
    async fn probe_containerd(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        ports: &[u16],
        target: &str,
    ) {
        let open = tcp_scan(host, ports, 8).await;
        for &port in &open {
            self.note_open(port);
            let metrics = get(client, &url("http", host, port, "/v1/metrics"), None).await;
            let version = get(client, &url("http", host, port, "/v1/version"), None).await;
            let confirmed = metrics.as_ref().is_some_and(|p| {
                p.status == 200
                    && (p.body.contains("containerd")
                        || p.body.contains("containerd_")
                        || p.body.contains("go_gc"))
            }) || version.as_ref().is_some_and(|p| {
                p.status == 200 && p.body.to_ascii_lowercase().contains("containerd")
            });
            if !confirmed {
                continue;
            }
            self.sig.containerd_exposed = true;
            self.add_node(
                &format!("containerd:{}", port),
                &format!("containerd :{}", port),
                "containerd",
                "exposed",
            );
            let ev = Evidence::new()
                .with("endpoint", format!("http://{}:{}", host, port))
                .check(
                    "containerd_metrics_or_version",
                    true,
                    "containerd monitoring/version HTTP surface responded",
                );
            self.push(finding_rich(
                ENGINE_ID,
                &format!("containerd runtime monitoring/version endpoint exposed on :{}", port),
                "high",
                "T1613",
                "containerd exposes an HTTP metrics or version endpoint reachable from the scan origin. While not equivalent to the Docker API, it confirms the node runtime surface and may leak build/version intelligence useful for targeted exploits. Bind containerd metrics to localhost and restrict with network policies.",
                target,
                0.8,
                ev,
            ));
        }
    }
}

// ── Surface 5: control-plane components (scheduler / controller-manager / kube-proxy) ────────────

fn control_plane_component(port: u16) -> (&'static str, &'static str, bool) {
    // (label, scheme, legacy_insecure_serving)
    match port {
        10259 => ("kube-scheduler (secure)", "https", false),
        10257 => ("kube-controller-manager (secure)", "https", false),
        10251 => ("kube-scheduler (legacy insecure)", "http", true),
        10252 => ("kube-controller-manager (legacy insecure)", "http", true),
        10256 => ("kube-proxy healthz", "http", false),
        10249 => ("kube-proxy metrics", "http", false),
        _ => ("control-plane component", "https", false),
    }
}

impl Collector {
    async fn probe_control_plane(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        token: Option<&str>,
        ports: &[u16],
        target: &str,
    ) {
        let open = tcp_scan(host, ports, 12).await;
        for &port in &open {
            self.note_open(port);
            let (label, scheme, legacy) = control_plane_component(port);
            let mut confirmed = false;
            let mut anon_metrics = false;
            for path in ["/healthz", "/metrics", "/configz"] {
                let Some(p) = get(client, &url(scheme, host, port, path), token).await else {
                    continue;
                };
                match path {
                    "/healthz" if p.status == 200 && p.body.to_ascii_lowercase().contains("ok") => {
                        confirmed = true;
                    }
                    "/metrics"
                        if p.status == 200
                            && (p.body.contains("workqueue_")
                                || p.body.contains("rest_client_")
                                || p.body.contains("scheduler_")
                                || p.body.contains("leader_election")) =>
                    {
                        confirmed = true;
                        anon_metrics = true;
                    }
                    "/configz"
                        if p.status == 200
                            && p.body.to_ascii_lowercase().contains("componentconfig") =>
                    {
                        confirmed = true;
                        anon_metrics = true;
                    }
                    _ => {}
                }
            }
            if !confirmed {
                continue;
            }
            self.add_node(
                &format!("cp:{}", port),
                label,
                "control_plane",
                if legacy { "takeover" } else { "exposed" },
            );
            let (sev, conf) = if legacy {
                ("high", 0.85)
            } else if anon_metrics {
                ("medium", 0.8)
            } else {
                ("medium", 0.7)
            };
            let ev = Evidence::new()
                .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                .with("component", label)
                .check(
                    "legacy_insecure_serving",
                    legacy,
                    "component served over plaintext without authn",
                )
                .check(
                    "anonymous_metrics_or_config",
                    anon_metrics,
                    "metrics/configz readable without auth",
                );
            self.push(finding_rich(
                ENGINE_ID,
                &format!("{} reachable on :{}", label, port),
                sev,
                "T1613",
                if legacy {
                    "A control-plane component is using the deprecated insecure serving port (no authn/authz). This leaks live component configuration and metrics and should be disabled (--port=0); use the secure port (10257/10259) with authentication."
                } else {
                    "A control-plane component endpoint is network-reachable and exposes metrics/health/config. Restrict to localhost/control-plane and require RBAC on /metrics."
                },
                target,
                conf,
                ev,
            ));
        }
    }
}

// ── Surface 6: Kubernetes Dashboard & cluster UIs ────────────────────────────────────────────────

const DASHBOARD_PATHS: &[(&str, &str)] = &[
    ("/", "kubernetesDashboard"),
    ("/#/login", "kubernetes dashboard"),
    ("/#!/login", "kubernetes dashboard"),
    ("/api/v1/login/status", "tokenpresent"),
    ("/dashboard/", "kubernetes dashboard"),
    (
        "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
        "kubernetes dashboard",
    ),
];

impl Collector {
    async fn probe_dashboard(&mut self, client: &reqwest::Client, target: &str) {
        let base = normalize_url(target);
        for (path, marker) in DASHBOARD_PATHS {
            let u = crate::engine_probes::join_url(&base, path);
            let Some(p) = get(client, &u, None).await else {
                continue;
            };
            let lc = p.body.to_ascii_lowercase();
            if matches!(p.status, 200 | 302)
                && (lc.contains(marker)
                    || lc.contains("kubernetes-dashboard")
                    || lc.contains("skip"))
            {
                self.sig.dashboard_open = true;
                self.add_node("dashboard", "Kubernetes Dashboard", "dashboard", "exposed");
                let skip_login = lc.contains("skip") || lc.contains("\"tokenpresent\":false");
                let ev = Evidence::new()
                    .with("url", u.clone())
                    .check("dashboard_reachable", true, json!({ "status": p.status }))
                    .check(
                        "skip_login_possible",
                        skip_login,
                        "dashboard exposes a 'Skip' / tokenless entry path",
                    );
                self.push(finding_rich(
                    ENGINE_ID,
                    "Kubernetes Dashboard is reachable",
                    if skip_login { "critical" } else { "high" },
                    "T1610",
                    if skip_login {
                        "The Kubernetes Dashboard is reachable and appears to allow tokenless ('Skip') login. If the dashboard ServiceAccount is privileged this is full cluster-admin via a browser. Require authentication and bind the dashboard SA to a least-privilege role."
                    } else {
                        "The Kubernetes Dashboard is network-reachable. Ensure it requires authentication, is not exposed to untrusted networks, and that its ServiceAccount is least-privilege."
                    },
                    target,
                    0.8,
                    ev,
                ));
                break;
            }
        }
    }
}

// ── Surface 7: container registries (Docker Registry v2 / Harbor) ────────────────────────────────

impl Collector {
    async fn probe_registry(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        token: Option<&str>,
        ports: &[u16],
        target: &str,
    ) {
        let open = tcp_scan(host, ports, 8).await;
        for &port in &open {
            self.note_open(port);
            let scheme = if port == 5000 { "http" } else { "https" };
            let Some(v2) = get(client, &url(scheme, host, port, "/v2/"), token).await else {
                continue;
            };
            let is_registry = header_value(&v2.headers, "docker-distribution-api-version")
                .is_some()
                || (v2.status == 401
                    && header_value(&v2.headers, "www-authenticate")
                        .is_some_and(|w| w.to_ascii_lowercase().contains("bearer")));
            if !is_registry {
                continue;
            }
            self.add_node(
                &format!("registry:{}", port),
                &format!("Container registry :{}", port),
                "registry",
                "exposed",
            );
            let gated = v2.status == 401;
            let mut repos = 0usize;
            let mut anon = false;
            if let Some(cat) = get(client, &url(scheme, host, port, "/v2/_catalog"), token).await {
                if cat.status == 200 && cat.body.contains("repositories") {
                    anon = true;
                    self.sig.registry_anon_catalog = true;
                    repos = serde_json::from_str::<Value>(&cat.body)
                        .ok()
                        .and_then(|v| {
                            v.get("repositories")
                                .and_then(Value::as_array)
                                .map(Vec::len)
                        })
                        .unwrap_or(0);
                    self.add_node(
                        &format!("registry:{}", port),
                        "Container registry",
                        "registry",
                        "takeover",
                    );
                }
            }
            let (sev, title, desc, conf) = if anon {
                (
                    "critical",
                    format!("Container registry allows ANONYMOUS catalog listing on :{} ({} repo(s))", port, repos),
                    "The Docker Registry v2 /_catalog endpoint returned the repository list without authentication. An attacker can pull and inspect every image (source code, embedded secrets, proprietary IP); if push is also unauthenticated they can poison images the cluster runs (supply-chain RCE). Require token authentication for pull and push.".to_string(),
                    0.9,
                )
            } else if gated {
                (
                    "medium",
                    format!("Container registry reachable (authenticated) on :{}", port),
                    "A Docker Registry v2 endpoint is network-reachable and challenges for a Bearer token. Confirm the auth backend is strong and the registry is not unnecessarily internet-exposed.".to_string(),
                    0.75,
                )
            } else {
                (
                    "high",
                    format!("Container registry reachable on :{}", port),
                    "A container registry endpoint is reachable. Verify authentication is enforced for both pull and push.".to_string(),
                    0.7,
                )
            };
            let ev = Evidence::new()
                .with("endpoint", format!("{}://{}:{}", scheme, host, port))
                .with("repositories", repos)
                .check("anonymous_catalog", anon, json!({ "repositories": repos }))
                .check(
                    "auth_challenge",
                    gated,
                    "registry returned 401 Bearer challenge",
                );
            self.push(finding_rich(
                ENGINE_ID, &title, sev, "T1525", &desc, target, conf, ev,
            ));
            // Harbor registry health (common enterprise registry).
            if let Some(h) = get(client, &url(scheme, host, port, "/api/v2.0/health"), token).await
            {
                if h.status == 200 && h.body.to_ascii_lowercase().contains("harbor") {
                    if !self.cluster_meta.platform_tools.contains(&"Harbor".to_string()) {
                        self.cluster_meta.platform_tools.push("Harbor".to_string());
                    }
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}/api/v2.0/health", scheme, host, port))
                        .check("harbor_health", true, json!({ "status": h.status }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("Harbor container registry health API exposed on :{}", port),
                        "medium",
                        "T1525",
                        "Harbor registry health endpoint is reachable. Confirm RBAC, vulnerability scanning and notary/signing are enabled; restrict registry admin APIs to trusted networks.",
                        target,
                        0.75,
                        ev,
                    ));
                }
            }
            // MinIO S3-compatible object store (often used for artifacts/backups).
            if let Some(m) = get(client, &url(scheme, host, port, "/minio/health/live"), token).await
            {
                if m.status == 200 {
                    if !self.cluster_meta.platform_tools.contains(&"MinIO".to_string()) {
                        self.cluster_meta.platform_tools.push("MinIO".to_string());
                    }
                    let ev = Evidence::new()
                        .with("endpoint", format!("{}://{}:{}/minio/health/live", scheme, host, port))
                        .check("minio_health", true, json!({ "status": m.status }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("MinIO object store health endpoint exposed on :{}", port),
                        "high",
                        "T1530",
                        "MinIO health endpoint is reachable — often indicating an S3-compatible artifact/backup bucket co-located with cluster infrastructure. Verify bucket policies deny anonymous list/get.",
                        target,
                        0.78,
                        ev,
                    ));
                }
            }
        }
    }
}

// ── Surface 8: service mesh / sidecars (Envoy admin, Consul, Istio pilot) ────────────────────────

impl Collector {
    async fn probe_service_mesh(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        ports: &[u16],
        target: &str,
    ) {
        let open = tcp_scan(host, ports, 10).await;
        for &port in &open {
            self.note_open(port);
            if port == 8500 {
                self.probe_consul(client, host, port, target).await;
                continue;
            }
            if port == 15014 {
                if let Some(p) = get(client, &url("http", host, port, "/version"), None).await {
                    if p.status == 200 && p.body.to_ascii_lowercase().contains("istio") {
                        self.add_node("istiod", "istiod :15014", "mesh", "exposed");
                        let ev = Evidence::new()
                            .with("endpoint", format!("http://{}:{}", host, port))
                            .check("istiod_monitoring_exposed", true, json!({ "status": 200 }))
                            .raw_excerpt(p.body.as_bytes());
                        self.push(finding_rich(
                            ENGINE_ID,
                            "Istio control-plane (istiod) monitoring port exposed",
                            "medium",
                            "T1613",
                            "The istiod monitoring/version port (15014) is reachable and discloses the Istio build. Restrict mesh control-plane ports to the cluster network.",
                            target,
                            0.78,
                            ev,
                        ));
                    }
                }
                continue;
            }
            if port == 9990 {
                if let Some(p) = get(client, &url("http", host, port, "/admin/metrics"), None).await
                {
                    if p.status == 200 && p.body.to_ascii_lowercase().contains("linkerd") {
                        self.add_node("linkerd:9990", "Linkerd admin :9990", "mesh", "exposed");
                        let ev = Evidence::new()
                            .with("endpoint", format!("http://{}:9990/admin/metrics", host))
                            .check("linkerd_admin_exposed", true, json!({ "status": 200 }));
                        self.push(finding_rich(
                            ENGINE_ID,
                            "Linkerd admin/metrics interface exposed on :9990",
                            "high",
                            "T1613",
                            "Linkerd's admin interface is reachable and exposes proxy metrics and routing metadata. Bind to localhost and require network policies.",
                            target,
                            0.82,
                            ev,
                        ));
                    }
                }
                continue;
            }
            // Envoy admin (15000 / 9901 / 19000).
            let Some(info) = get(client, &url("http", host, port, "/server_info"), None).await
            else {
                continue;
            };
            let lc = info.body.to_ascii_lowercase();
            let is_envoy = info.status == 200
                && lc.contains("\"version\"")
                && (lc.contains("\"state\"")
                    || lc.contains("uptime")
                    || lc.contains("hot_restart"));
            if !is_envoy {
                continue;
            }
            self.add_node(
                &format!("envoy:{}", port),
                &format!("Envoy admin :{}", port),
                "mesh",
                "takeover",
            );
            self.add_node("internet", "Internet", "root", "exposed");
            self.add_edge(
                "internet",
                &format!("envoy:{}", port),
                "reachable",
                "Envoy admin reachable",
            );
            let ev = Evidence::new()
                .with("endpoint", format!("http://{}:{}", host, port))
                .check("envoy_admin_exposed", true, json!({ "status": 200 }))
                .raw_excerpt(info.body.as_bytes());
            self.push(finding_rich(
                ENGINE_ID,
                &format!("Envoy admin interface exposed on :{}", port),
                "critical",
                "T1557",
                "The Envoy admin interface is anonymously reachable. It allows reading the full proxy configuration, draining listeners, flipping log levels and (on some builds) shutting the proxy down — a denial-of-service and traffic-manipulation primitive. Bind the admin interface to 127.0.0.1 only.",
                target,
                0.88,
                ev,
            ));
            // /config_dump leaks upstream clusters, routes and sometimes inline secrets.
            if let Some(p) = get(client, &url("http", host, port, "/config_dump"), None).await {
                if p.status == 200 && p.body.contains("config_dump") {
                    self.sig.envoy_config_leak = true;
                    let secrets = crate::engine_probes::detect_secrets(&p.body);
                    let ev = Evidence::new()
                        .with("endpoint", format!("http://{}:{}/config_dump", host, port))
                        .with("detected_secret_types", json!(secrets))
                        .check(
                            "config_dump_readable",
                            true,
                            json!({ "bytes": p.body.len() }),
                        );
                    self.push(finding_rich(
                        ENGINE_ID,
                        "Envoy /config_dump exposes full mesh proxy configuration",
                        if secrets.is_empty() { "high" } else { "critical" },
                        "T1552",
                        "Envoy /config_dump returned the complete proxy configuration (upstream clusters, routes, TLS contexts). It maps the internal service topology and can contain inline secrets. Disable admin access from untrusted networks.",
                        target,
                        0.85,
                        ev,
                    ));
                }
            }
            // /certs exposes the live TLS certificate chain (and on misconfig, private key material).
            if let Some(p) = get(client, &url("http", host, port, "/certs"), None).await {
                if p.status == 200 && p.body.to_ascii_lowercase().contains("certificates") {
                    self.sig.envoy_cert_leak = true;
                    let ev = Evidence::new()
                        .with("endpoint", format!("http://{}:{}/certs", host, port))
                        .check(
                            "envoy_certs_readable",
                            true,
                            json!({ "bytes": p.body.len() }),
                        )
                        .raw_excerpt(p.body.as_bytes());
                    self.push(finding_rich(
                        ENGINE_ID,
                        "Envoy /certs exposes the mesh TLS certificate material",
                        "critical",
                        "T1552.004",
                        "Envoy /certs returned the loaded certificate chain(s). Exposed mesh certificate material enables service impersonation and mTLS interception across the mesh. Lock the admin interface to localhost and rotate any exposed certificates.",
                        target,
                        0.85,
                        ev,
                    ));
                }
            }
        }
    }

    async fn probe_consul(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        port: u16,
        target: &str,
    ) {
        let Some(p) = get(client, &url("http", host, port, "/v1/agent/self"), None).await else {
            return;
        };
        if p.status != 200 || !(p.body.contains("\"Config\"") || p.body.contains("\"Member\"")) {
            return;
        }
        self.add_node("consul", "Consul :8500", "mesh", "exposed");
        let ev = Evidence::new()
            .with("endpoint", format!("http://{}:{}", host, port))
            .check("consul_http_api_open", true, json!({ "status": 200 }));
        self.push(finding_rich(
            ENGINE_ID,
            "Consul HTTP API exposed anonymously",
            "high",
            "T1613",
            "The Consul agent HTTP API is reachable without an ACL token. It exposes the service catalog and (if ACLs are not bootstrapped) the KV store and agent configuration. Bootstrap ACLs with default-deny and restrict the API to the mesh network.",
            target,
            0.82,
            ev,
        ));
        // KV recursive read confirms a missing default-deny ACL.
        if let Some(kv) = get(
            client,
            &url("http", host, port, "/v1/kv/?recurse=true"),
            None,
        )
        .await
        {
            if kv.status == 200 && kv.body.trim_start().starts_with('[') {
                let ev = Evidence::new()
                    .with(
                        "endpoint",
                        format!("http://{}:{}/v1/kv/?recurse=true", host, port),
                    )
                    .check(
                        "consul_kv_readable",
                        true,
                        json!({ "bytes": kv.body.len() }),
                    )
                    .raw_excerpt(kv.body.as_bytes());
                self.push(finding_rich(
                    ENGINE_ID,
                    "Consul KV store is anonymously readable (ACLs not enforced)",
                    "critical",
                    "T1552",
                    "The Consul KV store returned data without an ACL token. Application configuration and secrets stored in Consul KV are exposed. Enable ACLs with a default-deny policy immediately.",
                    target,
                    0.88,
                    ev,
                ));
            }
        }
    }
}

// ── Surface 10: GitOps / platform control planes (Argo CD, Flux, Rancher, OpenShift) ───────────

struct PlatformProbe {
    path: &'static str,
    label: &'static str,
    tokens: &'static [&'static str],
    severity: &'static str,
    mitre: &'static str,
}

const GITOPS_PROBES: &[PlatformProbe] = &[
    PlatformProbe {
        path: "/api/version",
        label: "Argo CD API",
        tokens: &["argocd", "server.version", "version"],
        severity: "high",
        mitre: "T1190",
    },
    PlatformProbe {
        path: "/api/v1/applications",
        label: "Argo CD Applications API",
        tokens: &["items", "application", "argoproj"],
        severity: "critical",
        mitre: "T1525",
    },
    PlatformProbe {
        path: "/gotk_info",
        label: "Flux GitOps Toolkit",
        tokens: &["gotk", "flux", "component"],
        severity: "high",
        mitre: "T1190",
    },
    PlatformProbe {
        path: "/v3/settings/cacerts",
        label: "Rancher API",
        tokens: &["data", "cacerts", "type"],
        severity: "high",
        mitre: "T1190",
    },
    PlatformProbe {
        path: "/k8s/clusters/local",
        label: "Rancher cluster proxy",
        tokens: &["cluster", "rancher", "apiVersion"],
        severity: "critical",
        mitre: "T1190",
    },
    PlatformProbe {
        path: "/oauth/authorize",
        label: "OpenShift OAuth",
        tokens: &["openshift", "oauth", "client_id"],
        severity: "medium",
        mitre: "T1190",
    },
    PlatformProbe {
        path: "/api/v1/namespaces/argocd/services",
        label: "Argo CD namespace services",
        tokens: &["argocd", "items", "kind"],
        severity: "high",
        mitre: "T1613",
    },
    PlatformProbe {
        path: "/c/main",
        label: "Headlamp Kubernetes UI",
        tokens: &["headlamp", "kubernetes", "cluster"],
        severity: "high",
        mitre: "T1190",
    },
    PlatformProbe {
        path: "/api/status",
        label: "Portainer",
        tokens: &["portainer", "version", "instance"],
        severity: "critical",
        mitre: "T1190",
    },
    PlatformProbe {
        path: "/apis/tekton.dev/v1/namespaces/tekton-pipelines/taskruns",
        label: "Tekton Pipelines API",
        tokens: &["tekton", "taskrun", "items"],
        severity: "high",
        mitre: "T1525",
    },
    PlatformProbe {
        path: "/pipeline/apis/v1beta1/runs",
        label: "Kubeflow Pipelines",
        tokens: &["kubeflow", "pipeline", "runs"],
        severity: "high",
        mitre: "T1190",
    },
    PlatformProbe {
        path: "/v1/sys/health",
        label: "HashiCorp Vault",
        tokens: &["initialized", "sealed", "version"],
        severity: "critical",
        mitre: "T1552",
    },
    PlatformProbe {
        path: "/ui/",
        label: "Vault UI",
        tokens: &["vault", "ui", "login"],
        severity: "high",
        mitre: "T1190",
    },
];

impl Collector {
    async fn probe_gitops_platforms(&mut self, client: &reqwest::Client, target: &str) {
        let base = normalize_url(target);
        for probe in GITOPS_PROBES {
            let u = crate::engine_probes::join_url(&base, probe.path);
            let Some(p) = get(client, &u, None).await else {
                continue;
            };
            if !matches!(p.status, 200 | 401 | 403) {
                continue;
            }
            let lc = p.body.to_ascii_lowercase();
            let hdr = p
                .headers
                .iter()
                .map(|(k, v)| format!("{}:{}", k, v))
                .collect::<String>()
                .to_ascii_lowercase();
            let confirmed = probe.tokens.iter().any(|t| {
                let n = t.to_ascii_lowercase();
                lc.contains(&n) || hdr.contains(&n)
            });
            if !confirmed && p.status != 200 {
                continue;
            }
            if p.status == 200 && !confirmed {
                continue;
            }
            self.sig.gitops_exposed = true;
            if !self
                .cluster_meta
                .platform_tools
                .contains(&probe.label.to_string())
            {
                self.cluster_meta
                    .platform_tools
                    .push(probe.label.to_string());
            }
            self.add_node(
                &format!("gitops:{}", probe.label),
                probe.label,
                "gitops",
                if p.status == 200 {
                    "takeover"
                } else {
                    "exposed"
                },
            );
            let ev = Evidence::new()
                .with("url", u.clone())
                .with("platform", probe.label)
                .check(
                    "gitops_surface_reachable",
                    true,
                    json!({ "status": p.status }),
                );
            self.push(finding_rich(
                ENGINE_ID,
                &format!("{} reachable at {}", probe.label, probe.path),
                if p.status == 200 {
                    probe.severity
                } else {
                    "medium"
                },
                probe.mitre,
                if p.status == 200 {
                    "A GitOps / platform control plane endpoint is reachable without authentication. These surfaces manage cluster desired state and often hold deploy keys — full cluster compromise if abused."
                } else {
                    "A GitOps / platform endpoint is network-reachable (authentication required). Ensure it is not internet-exposed and enforce SSO/MFA."
                },
                target,
                if p.status == 200 { 0.88 } else { 0.75 },
                ev,
            ));
        }
    }
}

// ── Surface 11: Observability stack (Prometheus / Grafana / Alertmanager) ────────────────────────

impl Collector {
    async fn probe_observability(
        &mut self,
        client: &reqwest::Client,
        host: &str,
        ports: &[u16],
        target: &str,
    ) {
        let open = tcp_scan(host, ports, 10).await;
        for &port in &open {
            self.note_open(port);
            // Prometheus
            if let Some(p) = get(
                client,
                &url("http", host, port, "/api/v1/status/buildinfo"),
                None,
            )
            .await
            {
                if p.status == 200 && p.body.contains("prometheus") {
                    self.sig.prometheus_exposed = true;
                    self.add_node(
                        &format!("prometheus:{}", port),
                        &format!("Prometheus :{}", port),
                        "observability",
                        "exposed",
                    );
                    let anon_query = get(
                        client,
                        &url("http", host, port, "/api/v1/query?query=up"),
                        None,
                    )
                    .await;
                    let query_open = anon_query.as_ref().is_some_and(|q| {
                        q.status == 200 && q.body.contains("\"status\":\"success\"")
                    });
                    let ev = Evidence::new()
                        .with("endpoint", format!("http://{}:{}", host, port))
                        .check("prometheus_buildinfo", true, json!({ "status": p.status }))
                        .check(
                            "prometheus_anonymous_query",
                            query_open,
                            "PromQL query succeeded without auth",
                        );
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!(
                            "Prometheus exposed on :{}{}",
                            port,
                            if query_open { " (anonymous PromQL query allowed)" } else { "" }
                        ),
                        if query_open { "critical" } else { "high" },
                        "T1613",
                        "Prometheus is network-reachable. It stores service topology, kube-state-metrics labels and often leaks internal hostnames. Anonymous PromQL enables full infrastructure mapping.",
                        target,
                        if query_open { 0.92 } else { 0.82 },
                        ev,
                    ));
                    continue;
                }
            }
            // Grafana
            if let Some(p) = get(client, &url("http", host, port, "/api/health"), None).await {
                if p.status == 200 && p.body.to_ascii_lowercase().contains("grafana") {
                    self.sig.grafana_exposed = true;
                    self.add_node(
                        &format!("grafana:{}", port),
                        &format!("Grafana :{}", port),
                        "observability",
                        "exposed",
                    );
                    let ev = Evidence::new()
                        .with("endpoint", format!("http://{}:{}", host, port))
                        .check("grafana_health", true, json!({ "status": p.status }))
                        .raw_excerpt(p.body.as_bytes());
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("Grafana dashboard/API exposed on :{}", port),
                        "high",
                        "T1190",
                        "Grafana is reachable. Default admin credentials, datasource credentials and dashboard JSON often contain cloud API keys. Enforce SSO, disable anonymous auth, and restrict to VPN.",
                        target,
                        0.85,
                        ev,
                    ));
                    continue;
                }
            }
            // Alertmanager
            if let Some(p) = get(client, &url("http", host, port, "/api/v2/status"), None).await {
                if p.status == 200 && p.body.contains("clusterStatus") {
                    self.add_node(
                        &format!("alertmanager:{}", port),
                        &format!("Alertmanager :{}", port),
                        "observability",
                        "exposed",
                    );
                    let ev = Evidence::new()
                        .with("endpoint", format!("http://{}:{}", host, port))
                        .check("alertmanager_status", true, json!({ "status": p.status }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("Alertmanager API exposed on :{}", port),
                        "medium",
                        "T1613",
                        "Alertmanager is reachable and discloses routing/receiver configuration — useful for understanding on-call targets and silencing alerts during an attack.",
                        target,
                        0.78,
                        ev,
                    ));
                    continue;
                }
            }
            // Jaeger query UI / API
            if let Some(p) = get(client, &url("http", host, port, "/api/services"), None).await {
                if p.status == 200
                    && (p.body.contains("data") || p.body.to_ascii_lowercase().contains("jaeger"))
                {
                    self.add_node(
                        &format!("jaeger:{}", port),
                        &format!("Jaeger :{}", port),
                        "observability",
                        "exposed",
                    );
                    if !self.cluster_meta.platform_tools.contains(&"Jaeger".to_string()) {
                        self.cluster_meta.platform_tools.push("Jaeger".to_string());
                    }
                    let ev = Evidence::new()
                        .with("endpoint", format!("http://{}:{}", host, port))
                        .check("jaeger_services_api", true, json!({ "status": p.status }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("Jaeger tracing API exposed on :{}", port),
                        "high",
                        "T1613",
                        "Jaeger query API is reachable and maps every instrumented microservice. Distributed traces expose internal URLs, auth headers in span tags and dependency graphs.",
                        target,
                        0.82,
                        ev,
                    ));
                    continue;
                }
            }
            // Loki (log aggregation)
            if let Some(p) = get(client, &url("http", host, port, "/ready"), None).await {
                if p.status == 200 && header_value(&p.headers, "server").is_some_and(|s| s.to_ascii_lowercase().contains("loki")) {
                    self.add_node(
                        &format!("loki:{}", port),
                        &format!("Loki :{}", port),
                        "observability",
                        "exposed",
                    );
                    if !self.cluster_meta.platform_tools.contains(&"Loki".to_string()) {
                        self.cluster_meta.platform_tools.push("Loki".to_string());
                    }
                    let ev = Evidence::new()
                        .with("endpoint", format!("http://{}:{}", host, port))
                        .check("loki_ready", true, json!({ "status": p.status }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("Grafana Loki log store ready endpoint exposed on :{}", port),
                        "high",
                        "T1530",
                        "Loki /ready responded — log aggregation is network-reachable. Unauthenticated LogQL enables harvesting application logs that often contain credentials and PII.",
                        target,
                        0.8,
                        ev,
                    ));
                    continue;
                }
            }
            // Tempo (distributed tracing backend)
            if let Some(p) = get(client, &url("http", host, port, "/status"), None).await {
                if p.status == 200 && p.body.to_ascii_lowercase().contains("tempo") {
                    self.add_node(
                        &format!("tempo:{}", port),
                        &format!("Tempo :{}", port),
                        "observability",
                        "exposed",
                    );
                    if !self.cluster_meta.platform_tools.contains(&"Tempo".to_string()) {
                        self.cluster_meta.platform_tools.push("Tempo".to_string());
                    }
                    let ev = Evidence::new()
                        .with("endpoint", format!("http://{}:{}", host, port))
                        .check("tempo_status", true, json!({ "status": p.status }));
                    self.push(finding_rich(
                        ENGINE_ID,
                        &format!("Grafana Tempo tracing backend exposed on :{}", port),
                        "medium",
                        "T1613",
                        "Tempo status endpoint is reachable — confirms trace storage is exposed. Restrict to mesh-internal networks.",
                        target,
                        0.75,
                        ev,
                    ));
                }
            }
        }
    }
}

// ── Surface 12: Ingress / edge controllers on the target URL ─────────────────────────────────────

impl Collector {
    async fn probe_ingress_controllers(&mut self, client: &reqwest::Client, target: &str) {
        let base = normalize_url(target);
        let probes: &[(&str, &str, &[&str])] = &[
            ("/healthz", "NGINX Ingress healthz", &["nginx", "ok"]),
            (
                "/nginx_status",
                "NGINX stub_status",
                &["active connections", "server accepts"],
            ),
            (
                "/api/rawdata",
                "Traefik API",
                &["routers", "services", "middlewares"],
            ),
            (
                "/metrics",
                "Ingress metrics",
                &["nginx_ingress", "traefik_", "haproxy_"],
            ),
        ];
        for (path, label, tokens) in probes {
            let u = crate::engine_probes::join_url(&base, path);
            let Some(p) = get(client, &u, None).await else {
                continue;
            };
            if p.status != 200 {
                continue;
            }
            let blob = format!(
                "{} {}",
                p.body.to_ascii_lowercase(),
                header_value(&p.headers, "server")
                    .unwrap_or("")
                    .to_ascii_lowercase()
            );
            if tokens
                .iter()
                .any(|t| blob.contains(&t.to_ascii_lowercase()))
            {
                self.add_node(&format!("ingress:{}", path), label, "ingress", "exposed");
                let ev = Evidence::new().with("url", u.clone()).check(
                    "ingress_controller_exposed",
                    true,
                    json!({ "status": 200, "path": path }),
                );
                self.push(finding_rich(
                    ENGINE_ID,
                    &format!("Ingress controller surface exposed: {}", label),
                    if path.contains("rawdata") || path.contains("nginx_status") {
                        "high"
                    } else {
                        "medium"
                    },
                    "T1190",
                    "An ingress-controller admin/metrics endpoint is reachable on the cluster edge. Traefik /rawdata and NGINX stub_status leak backend service topology.",
                    target,
                    0.8,
                    ev,
                ));
            }
        }
    }
}

// ── CIS Kubernetes Benchmark — evidence-backed control failures ──────────────────────────────────

impl Collector {
    fn emit_cis_benchmark(&mut self, target: &str) {
        let s = &self.sig;
        let mut controls: Vec<Value> = Vec::new();
        let mut push_fail = |id: &str, title: &str, sev: &str, detail: &str| {
            controls.push(json!({
                "id": id, "title": title, "status": "fail",
                "severity": sev, "detail": detail
            }));
        };
        if s.anon_api {
            push_fail(
                "CIS 1.2.1",
                "Ensure anonymous auth to API server is disabled",
                "critical",
                "Anonymous resource listing observed on kube-apiserver",
            );
        }
        if s.insecure_8080 {
            push_fail(
                "CIS 1.2.18",
                "Ensure insecure port 8080 is disabled",
                "critical",
                "Legacy --insecure-port serving the API",
            );
        }
        if s.kubelet_anon_read {
            push_fail(
                "CIS 4.2.1",
                "Ensure kubelet anonymous auth is disabled",
                "critical",
                "Anonymous kubelet /pods read observed",
            );
        }
        if s.kubelet_exec {
            push_fail(
                "CIS 4.2.10",
                "Ensure kubelet read-only port is disabled",
                "high",
                "Read-write kubelet allows anonymous pod access",
            );
        }
        if s.etcd_plaintext {
            push_fail(
                "CIS 2.1",
                "Ensure etcd communication is encrypted",
                "critical",
                "etcd client port reachable over plaintext HTTP",
            );
        }
        if s.docker_unauth {
            push_fail(
                "CIS 4.1.1",
                "Restrict Docker daemon API access",
                "critical",
                "Unauthenticated Docker Engine API observed",
            );
        }
        if s.registry_anon_catalog {
            push_fail(
                "CIS 5.1.2",
                "Ensure registry requires authentication",
                "critical",
                "Anonymous container registry catalog listing",
            );
        }
        if s.dangerous_pods_visible {
            push_fail(
                "CIS 5.2.1",
                "Minimize privileged containers",
                "critical",
                "Privileged/hostPath/hostPID workloads visible via anonymous API",
            );
        }
        if s.gitops_exposed {
            push_fail(
                "CIS 5.1.4",
                "Restrict GitOps control plane exposure",
                "high",
                "GitOps platform endpoint reachable from scan origin",
            );
        }
        if s.prometheus_exposed || s.grafana_exposed {
            push_fail(
                "CIS 5.1.5",
                "Restrict observability stack exposure",
                "high",
                "Prometheus/Grafana reachable without network segmentation",
            );
        }
        if controls.is_empty() {
            return;
        }
        let fail = controls.len();
        let ev = Evidence::new()
            .with(
                "framework",
                "CIS Kubernetes Benchmark v1.8 (remote-verifiable controls)",
            )
            .with("failed_controls", fail)
            .with("controls", json!(controls));
        let mut f = finding_rich(
            ENGINE_ID,
            &format!(
                "CIS Kubernetes Benchmark: {} remote-verifiable control failure(s)",
                fail
            ),
            if fail >= 3 { "critical" } else { "high" },
            "",
            "Each listed CIS control failed based on a live observation from this scan — not a checklist guess. Remediate in priority order (anonymous API/etcd/kubelet first).",
            target,
            0.95,
            ev,
        );
        if let Some(o) = f.as_object_mut() {
            o.insert("category".to_string(), json!("cis_benchmark"));
        }
        self.push(f);
    }

    /// NSA/CISA Kubernetes Hardening Guidance — evidence-backed failures (remote-verifiable subset).
    fn emit_nsa_hardening(&mut self, target: &str) {
        let s = &self.sig;
        let mut controls: Vec<Value> = Vec::new();
        let mut push_fail = |id: &str, title: &str, sev: &str, detail: &str| {
            controls.push(json!({
                "id": id, "title": title, "status": "fail",
                "severity": sev, "detail": detail
            }));
        };
        if s.anon_api || s.insecure_8080 {
            push_fail(
                "NSA-API-1",
                "Protect the Kubernetes API from unauthorized access",
                "critical",
                "Anonymous or insecure-port API access observed",
            );
        }
        if s.api_secrets_anon || s.events_secrets_leak {
            push_fail(
                "NSA-SECRETS-1",
                "Keep secrets out of logs and restrict Secret enumeration",
                "critical",
                "Secrets or secret-like material readable via API/events",
            );
        }
        if s.etcd_plaintext || s.etcd_keys_dump {
            push_fail(
                "NSA-ETCD-1",
                "Encrypt etcd data at rest and in transit",
                "critical",
                "etcd reachable without encryption or keyspace dumpable",
            );
        }
        if s.kubelet_anon_read || s.kubelet_exec {
            push_fail(
                "NSA-NODE-1",
                "Lock down kubelet access",
                "critical",
                "kubelet allows anonymous pod read or exec-equivalent access",
            );
        }
        if s.networkpolicy_gap {
            push_fail(
                "NSA-NET-1",
                "Implement network segmentation with NetworkPolicies",
                "high",
                "Multiple namespaces but zero NetworkPolicies observed",
            );
        }
        if s.dangerous_pods_visible {
            push_fail(
                "NSA-POD-1",
                "Run containers as non-root and drop capabilities",
                "critical",
                "Privileged / hostPath / hostPID workloads visible",
            );
        }
        if s.docker_unauth || s.containerd_exposed {
            push_fail(
                "NSA-RUNTIME-1",
                "Protect container runtime interfaces",
                "critical",
                "Container runtime API or monitoring surface exposed",
            );
        }
        if s.webhook_urls_exposed {
            push_fail(
                "NSA-ADMISSION-1",
                "Protect admission webhook endpoints from enumeration/abuse",
                "high",
                "Admission webhook callback URLs enumerable",
            );
        }
        if controls.is_empty() {
            return;
        }
        let fail = controls.len();
        let ev = Evidence::new()
            .with(
                "framework",
                "NSA/CISA Kubernetes Hardening Guidance (remote-verifiable controls)",
            )
            .with("failed_controls", fail)
            .with("controls", json!(controls));
        let mut f = finding_rich(
            ENGINE_ID,
            &format!(
                "NSA/CISA Hardening Guidance: {} remote-verifiable control failure(s)",
                fail
            ),
            if fail >= 3 { "critical" } else { "high" },
            "",
            "Each control failed based on a live observation from this scan — aligned with NSA/CISA Kubernetes Hardening Guidance. Remediate API/etcd/kubelet exposure before workload-level controls.",
            target,
            0.95,
            ev,
        );
        if let Some(o) = f.as_object_mut() {
            o.insert("category".to_string(), json!("nsa_hardening"));
        }
        self.push(f);
    }
}

// ── Surface 9: legacy Helm Tiller (44134) ────────────────────────────────────────────────────────

impl Collector {
    async fn probe_helm_tiller(&mut self, host: &str, target: &str, enabled: bool) {
        if !enabled {
            return;
        }
        if tcp_open(host, HELM_TILLER_PORT).await {
            self.note_open(HELM_TILLER_PORT);
            self.sig.tiller = true;
            self.add_node("tiller", "Helm Tiller :44134", "helm", "takeover");
            self.add_node("internet", "Internet", "root", "exposed");
            self.add_edge("internet", "tiller", "reachable", "Tiller gRPC reachable");
            let ev = Evidence::new()
                .with("endpoint", format!("{}:{}", host, HELM_TILLER_PORT))
                .check(
                    "tiller_port_open",
                    true,
                    "TCP/44134 (Helm v2 Tiller gRPC) accepted a connection",
                );
            self.push(finding_rich(
                ENGINE_ID,
                "Legacy Helm v2 Tiller port (44134) is reachable",
                "critical",
                "T1610",
                "The Helm v2 Tiller gRPC port is open. Tiller historically runs with a cluster-admin ServiceAccount and exposes no authentication, so anyone who can reach it can install/upgrade arbitrary charts as cluster-admin. Migrate to Helm v3 (which has no Tiller) and remove the Tiller deployment.",
                target,
                0.7,
                ev,
            ));
        }
    }
}

// ── Attack-path analysis (toxic combinations → chained, real attack paths) ───────────────────────

impl Collector {
    fn push_attack_path(
        &mut self,
        target: &str,
        path_id: &str,
        title: &str,
        mitre: &str,
        confidence: f64,
        steps: &[(&str, String)],
        kill_chain: &[&str],
    ) {
        let steps_json: Vec<Value> = steps
            .iter()
            .enumerate()
            .map(|(i, (stage, detail))| json!({ "order": i + 1, "stage": stage, "detail": detail }))
            .collect();
        let ev = Evidence::new()
            .with("path_id", path_id)
            .with("kill_chain", json!(kill_chain))
            .with("steps", json!(steps_json));
        let mut f = finding_rich(
            ENGINE_ID,
            title,
            "critical",
            mitre,
            &format!(
                "Attack path (toxic combination of real, observed exposures): {}",
                title
            ),
            target,
            confidence,
            ev,
        );
        if let Some(o) = f.as_object_mut() {
            o.insert("category".to_string(), json!("attack_path"));
            o.insert("attack_path".to_string(), json!(true));
            o.insert("path_id".to_string(), json!(path_id));
        }
        self.push(f);
    }

    fn synthesize_attack_paths(&mut self, target: &str) {
        // Clone signals so push_attack_path can borrow self mutably.
        let s = self.sig.clone();
        let api = s
            .api_endpoint
            .clone()
            .unwrap_or_else(|| "the API server".to_string());
        let kube = s
            .kubelet_endpoint
            .clone()
            .unwrap_or_else(|| "the kubelet".to_string());
        let etcd = s
            .etcd_endpoint
            .clone()
            .unwrap_or_else(|| "etcd".to_string());
        let (anon_api, secrets, pods, insecure_8080, rbac) = (
            s.anon_api,
            s.api_secrets_anon,
            s.api_pods_anon,
            s.insecure_8080,
            s.rbac_anon_binding,
        );
        let (kubelet_exec, etcd_pt, etcd_dump, docker, registry, envoy_cfg, envoy_cert, tiller) = (
            s.kubelet_exec,
            s.etcd_plaintext,
            s.etcd_keys_dump,
            s.docker_unauth,
            s.registry_anon_catalog,
            s.envoy_config_leak,
            s.envoy_cert_leak,
            s.tiller,
        );
        let (gitops, dangerous_pods, prom, graf) = (
            s.gitops_exposed,
            s.dangerous_pods_visible,
            s.prometheus_exposed,
            s.grafana_exposed,
        );

        if anon_api && (secrets || pods) {
            self.push_attack_path(
                target,
                "anon_api_cluster_takeover",
                "Unauthenticated cluster takeover via anonymous API server",
                "T1613",
                0.9,
                &[
                    ("Initial Access", format!("Reach the anonymous Kubernetes API at {}", api)),
                    ("Discovery", "Enumerate namespaces, pods and workloads without credentials".to_string()),
                    ("Credential Access", if secrets { "Read ServiceAccount tokens directly from the anonymously-listable Secrets collection".to_string() } else { "Harvest mounted SA tokens by reading pod specs".to_string() }),
                    ("Privilege Escalation", "Reuse a privileged ServiceAccount token to act as cluster-admin".to_string()),
                    ("Impact", "Full control of every workload, secret and node in the cluster".to_string()),
                ],
                &["Initial Access", "Discovery", "Credential Access", "Privilege Escalation", "Impact"],
            );
        }
        if insecure_8080 {
            self.push_attack_path(
                target,
                "insecure_port_admin",
                "Instant cluster-admin via the legacy insecure API port (8080)",
                "T1610",
                0.95,
                &[
                    (
                        "Initial Access",
                        "Connect to the unauthenticated --insecure-port 8080".to_string(),
                    ),
                    (
                        "Execution",
                        "Create a privileged Pod / DaemonSet via the API with no authz check"
                            .to_string(),
                    ),
                    (
                        "Privilege Escalation",
                        "Mount the host filesystem or use hostPID to gain node root".to_string(),
                    ),
                    ("Impact", "Complete cluster and node compromise".to_string()),
                ],
                &[
                    "Initial Access",
                    "Execution",
                    "Privilege Escalation",
                    "Impact",
                ],
            );
        }
        if kubelet_exec {
            self.push_attack_path(
                target,
                "kubelet_node_takeover",
                "Node and cluster takeover via anonymous kubelet exec",
                "T1611",
                0.9,
                &[
                    (
                        "Initial Access",
                        format!("Reach the anonymous read-write kubelet at {}", kube),
                    ),
                    (
                        "Execution",
                        "Invoke /exec or /run to run commands inside a pod on the node".to_string(),
                    ),
                    (
                        "Escape to Host",
                        "Abuse a privileged/hostPath pod to break out to the node".to_string(),
                    ),
                    (
                        "Credential Access",
                        "Steal the node kubeconfig and every pod's SA token".to_string(),
                    ),
                    (
                        "Lateral Movement",
                        "Use stolen tokens to act across the cluster and into the cloud"
                            .to_string(),
                    ),
                ],
                &[
                    "Initial Access",
                    "Execution",
                    "Escape to Host",
                    "Credential Access",
                    "Lateral Movement",
                ],
            );
        }
        if etcd_pt || etcd_dump {
            self.push_attack_path(
                target,
                "etcd_secret_plunder",
                "Mass secret theft via exposed etcd",
                "T1552.007",
                0.92,
                &[
                    ("Initial Access", format!("Connect to the exposed etcd store at {}", etcd)),
                    ("Collection", if etcd_dump { "Dump the entire keyspace in a single recursive request".to_string() } else { "Read raw keys directly from the unencrypted store".to_string() }),
                    ("Credential Access", "Extract every Kubernetes Secret and ServiceAccount token (stored unencrypted)".to_string()),
                    ("Privilege Escalation", "Impersonate cluster-admin with a stolen token".to_string()),
                    ("Lateral Movement", "Pivot into any cloud/service the harvested tokens authenticate to".to_string()),
                ],
                &["Initial Access", "Collection", "Credential Access", "Privilege Escalation", "Lateral Movement"],
            );
        }
        if docker {
            self.push_attack_path(
                target,
                "docker_node_root",
                "Node root via the exposed Docker daemon",
                "T1610",
                0.93,
                &[
                    (
                        "Initial Access",
                        "Connect to the unauthenticated Docker Engine API".to_string(),
                    ),
                    (
                        "Execution",
                        "Create a privileged container bind-mounting the host root (/:/host)"
                            .to_string(),
                    ),
                    (
                        "Escape to Host",
                        "Write to the host filesystem (cron, SSH keys) to gain node root"
                            .to_string(),
                    ),
                    (
                        "Lateral Movement",
                        "Read kubelet credentials and pivot to the cluster + cloud metadata"
                            .to_string(),
                    ),
                ],
                &[
                    "Initial Access",
                    "Execution",
                    "Escape to Host",
                    "Lateral Movement",
                ],
            );
        }
        if registry {
            self.push_attack_path(
                target,
                "registry_supply_chain",
                "Supply-chain compromise via anonymous container registry",
                "T1525",
                0.8,
                &[
                    (
                        "Collection",
                        "Pull and inspect every image (source, secrets, proprietary IP)"
                            .to_string(),
                    ),
                    (
                        "Resource Development",
                        "If push is unauthenticated, build a back-doored image with the same tag"
                            .to_string(),
                    ),
                    (
                        "Persistence",
                        "Cluster nodes pull the poisoned image on the next schedule".to_string(),
                    ),
                    (
                        "Impact",
                        "Code execution across every workload that runs the image".to_string(),
                    ),
                ],
                &[
                    "Collection",
                    "Resource Development",
                    "Persistence",
                    "Impact",
                ],
            );
        }
        if envoy_cert || envoy_cfg {
            self.push_attack_path(
                target,
                "mesh_interception",
                "Service-mesh interception via exposed Envoy admin",
                "T1557",
                0.82,
                &[
                    (
                        "Discovery",
                        "Read /config_dump to map the internal service topology".to_string(),
                    ),
                    (
                        "Credential Access",
                        if envoy_cert {
                            "Extract the mesh TLS certificate material from /certs".to_string()
                        } else {
                            "Recover secrets embedded in the dumped configuration".to_string()
                        },
                    ),
                    (
                        "Collection",
                        "Impersonate a mesh service and man-in-the-middle mTLS traffic".to_string(),
                    ),
                    (
                        "Impact",
                        "Confidential service-to-service traffic is intercepted/modified"
                            .to_string(),
                    ),
                ],
                &["Discovery", "Credential Access", "Collection", "Impact"],
            );
        }
        if tiller {
            self.push_attack_path(
                target,
                "tiller_cluster_admin",
                "Cluster-admin via legacy Helm Tiller",
                "T1610",
                0.7,
                &[
                    (
                        "Initial Access",
                        "Reach the unauthenticated Tiller gRPC port (44134)".to_string(),
                    ),
                    (
                        "Execution",
                        "Install a malicious chart as Tiller's cluster-admin ServiceAccount"
                            .to_string(),
                    ),
                    (
                        "Impact",
                        "Arbitrary workloads deployed cluster-wide as cluster-admin".to_string(),
                    ),
                ],
                &["Initial Access", "Execution", "Impact"],
            );
        }
        if rbac {
            self.push_attack_path(
                target,
                "rbac_anonymous_escalation",
                "Privilege escalation via a dangerous ClusterRoleBinding",
                "T1078",
                0.85,
                &[
                    ("Discovery", "A ClusterRoleBinding grants powerful roles to anonymous/all-authenticated subjects".to_string()),
                    ("Privilege Escalation", "Any reachable principal inherits the bound privileges".to_string()),
                    ("Impact", "Effective cluster-admin for an effectively-unauthenticated attacker".to_string()),
                ],
                &["Discovery", "Privilege Escalation", "Impact"],
            );
        }
        if gitops && (anon_api || registry) {
            self.push_attack_path(
                target,
                "gitops_supply_chain_takeover",
                "GitOps pipeline takeover → cluster-wide malicious deployment",
                "T1525",
                0.88,
                &[
                    (
                        "Initial Access",
                        "Reach exposed GitOps control plane (Argo CD / Flux / Rancher)".to_string(),
                    ),
                    (
                        "Credential Access",
                        "Harvest deploy keys / repo credentials from GitOps UI or anonymous API"
                            .to_string(),
                    ),
                    (
                        "Execution",
                        "Push malicious manifest — GitOps controller reconciles it cluster-wide"
                            .to_string(),
                    ),
                    (
                        "Impact",
                        "Persistent backdoor in every namespace the AppProject allows".to_string(),
                    ),
                ],
                &["Initial Access", "Credential Access", "Execution", "Impact"],
            );
        }
        if dangerous_pods && (anon_api || kubelet_exec) {
            self.push_attack_path(
                target,
                "privileged_pod_node_escape",
                "Container escape via enumerated privileged / hostPath workloads",
                "T1611",
                0.9,
                &[
                    (
                        "Discovery",
                        "Enumerate pods with privileged, hostPID, hostNetwork or hostPath via anonymous API/kubelet".to_string(),
                    ),
                    (
                        "Execution",
                        "Exec into or replace a privileged workload".to_string(),
                    ),
                    (
                        "Escape to Host",
                        "Break out to the node via hostPath mount or hostPID namespace".to_string(),
                    ),
                    (
                        "Impact",
                        "Node root → cluster credential harvest → cloud metadata pivot".to_string(),
                    ),
                ],
                &["Discovery", "Execution", "Escape to Host", "Impact"],
            );
        }
        if prom && graf {
            self.push_attack_path(
                target,
                "observability_credential_theft",
                "Infrastructure mapping + credential theft via exposed observability stack",
                "T1552",
                0.82,
                &[
                    (
                        "Discovery",
                        "Prometheus PromQL maps every service, namespace and node".to_string(),
                    ),
                    (
                        "Credential Access",
                        "Grafana datasources store cloud API keys and DB passwords".to_string(),
                    ),
                    (
                        "Lateral Movement",
                        "Reuse harvested credentials against cloud control plane".to_string(),
                    ),
                    (
                        "Impact",
                        "Full infrastructure topology + secret material for pivot".to_string(),
                    ),
                ],
                &[
                    "Discovery",
                    "Credential Access",
                    "Lateral Movement",
                    "Impact",
                ],
            );
        }
        if s.events_secrets_leak && anon_api {
            self.push_attack_path(
                target,
                "events_api_secret_harvest",
                "Credential harvest via anonymously-readable Events API",
                "T1552",
                0.88,
                &[
                    (
                        "Discovery",
                        "List /api/v1/events without authentication".to_string(),
                    ),
                    (
                        "Credential Access",
                        "Extract API keys / tokens embedded in controller error messages".to_string(),
                    ),
                    (
                        "Privilege Escalation",
                        "Replay harvested tokens against cloud APIs or cluster RBAC".to_string(),
                    ),
                    (
                        "Impact",
                        "Lateral movement into cloud control plane and persistent cluster access".to_string(),
                    ),
                ],
                &[
                    "Discovery",
                    "Credential Access",
                    "Privilege Escalation",
                    "Impact",
                ],
            );
        }
        if s.webhook_urls_exposed && anon_api {
            self.push_attack_path(
                target,
                "admission_webhook_ssrf_chain",
                "Admission webhook callback targeting via anonymous API enumeration",
                "T1190",
                0.8,
                &[
                    (
                        "Discovery",
                        "Enumerate Validating/MutatingWebhookConfiguration clientConfig URLs".to_string(),
                    ),
                    (
                        "Initial Access",
                        "Reach webhook endpoints from scan origin if network path exists".to_string(),
                    ),
                    (
                        "Collection",
                        "Webhook receives full Kubernetes object payloads on create/update".to_string(),
                    ),
                    (
                        "Impact",
                        "SSRF into internal services or credential theft from webhook handlers".to_string(),
                    ),
                ],
                &["Discovery", "Initial Access", "Collection", "Impact"],
            );
        }
    }
}

impl Collector {
    fn posture_summary(&self, target: &str) -> Option<Value> {
        if self.findings.is_empty() && self.open_ports.is_empty() {
            return None;
        }
        let mut crit = 0u32;
        let mut high = 0u32;
        let mut med = 0u32;
        let mut low = 0u32;
        let mut attack_paths = 0u32;
        for f in &self.findings {
            if f.get("attack_path")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                attack_paths += 1;
            }
            match f.get("severity").and_then(Value::as_str).unwrap_or("") {
                "critical" => crit += 1,
                "high" => high += 1,
                "medium" => med += 1,
                "low" => low += 1,
                _ => {}
            }
        }
        let exposure = (crit * 25 + high * 12 + med * 5 + low * 2).min(100);
        let grade = match exposure {
            70..=100 => "F — critical exposure",
            45..=69 => "D — high exposure",
            20..=44 => "C — moderate exposure",
            1..=19 => "B — limited exposure",
            _ => "A — no remotely-observable exposure",
        };
        let mut surfaces: Vec<&str> = Vec::new();
        for n in &self.nodes {
            if let Some(kind) = n.get("type").and_then(Value::as_str) {
                if kind != "root" && !surfaces.contains(&kind) {
                    surfaces.push(kind);
                }
            }
        }
        let cis_failed = self
            .findings
            .iter()
            .find(|f| f.get("category").and_then(Value::as_str) == Some("cis_benchmark"))
            .and_then(|f| f.get("evidence"))
            .and_then(|e| e.get("failed_controls"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let nsa_failed = self
            .findings
            .iter()
            .find(|f| f.get("category").and_then(Value::as_str) == Some("nsa_hardening"))
            .and_then(|f| f.get("evidence"))
            .and_then(|e| e.get("failed_controls"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let blast = blast_radius_score(&self.sig, &self.pod_stats);
        let mut ev = Evidence::new()
            .with("exposure_score", exposure)
            .with("blast_radius_score", blast)
            .with("posture_grade", grade)
            .with(
                "severity_counts",
                json!({ "critical": crit, "high": high, "medium": med, "low": low }),
            )
            .with("attack_paths", attack_paths)
            .with("cis_failed_controls", cis_failed)
            .with("nsa_failed_controls", nsa_failed)
            .with("open_ports", json!(self.open_ports))
            .with("surfaces_detected", json!(surfaces))
            .with("graph", json!({ "nodes": self.nodes, "edges": self.edges }));
        if let Some(ref gv) = self.cluster_meta.git_version {
            ev = ev.with("git_version", gv.clone());
        }
        if let Some(ref p) = self.cluster_meta.managed_provider {
            ev = ev.with("managed_provider", p.clone());
        }
        if !self.cluster_meta.platform_tools.is_empty() {
            ev = ev.with("platform_tools", json!(self.cluster_meta.platform_tools));
        }
        if pod_stats_any(&self.pod_stats) {
            ev = ev.with(
                "dangerous_pod_stats",
                json!({
                    "privileged": self.pod_stats.privileged,
                    "host_pid": self.pod_stats.host_pid,
                    "host_network": self.pod_stats.host_network,
                    "host_path": self.pod_stats.host_path,
                    "automount_token": self.pod_stats.automount_token,
                }),
            );
        }
        let mut f = finding_rich(
            ENGINE_ID,
            &format!(
                "Cloud-native posture: {} (exposure {}/100, {} attack path(s))",
                grade, exposure, attack_paths
            ),
            "info",
            "",
            "Aggregated cloud-native security posture for the target, derived entirely from the real services observed during this scan. The security graph and attack paths summarise how the individual exposures chain together.",
            target,
            1.0,
            ev,
        );
        if let Some(o) = f.as_object_mut() {
            o.insert("category".to_string(), json!("posture_summary"));
        }
        Some(f)
    }
}

// ── Orchestrator ─────────────────────────────────────────────────────────────────────────────────

/// Run the full Cloud-Native & Kubernetes security assessment against `target`, honouring every
/// operator knob in `ctx.job_params`.
pub async fn run_k8s_container_result(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let host = extract_host(target);
    if host.is_empty() {
        return EngineResult::error("could not extract host from target");
    }
    let client = build_client(cfg.timeout_ms(8_000));
    let token = cfg.string("bearer_token");
    let token_ref = token.as_deref();
    let intensity = cfg.intensity();

    let mut c = Collector {
        extra_paths: cfg.string_list("extra_paths"),
        target_namespace: cfg
            .string("namespace")
            .unwrap_or_else(|| "default".to_string()),
        ..Default::default()
    };

    if cfg.bool_or("check_api_server", true) {
        let ports = cfg.ports_or("api_ports", DEFAULT_API_PORTS);
        c.probe_api_server(&client, &host, token_ref, &ports, intensity, target)
            .await;
    }
    if cfg.bool_or("check_kubelet", true) {
        let ports = cfg.ports_or("kubelet_ports", DEFAULT_KUBELET_PORTS);
        c.probe_kubelet(&client, &host, token_ref, &ports, target)
            .await;
    }
    if cfg.bool_or("check_cadvisor", true) {
        let ports = cfg.ports_or("cadvisor_ports", DEFAULT_CADVISOR_PORTS);
        c.probe_cadvisor(&client, &host, &ports, target).await;
    }
    if cfg.bool_or("check_etcd", true) {
        let ports = cfg.ports_or("etcd_ports", DEFAULT_ETCD_PORTS);
        c.probe_etcd(&client, &host, &ports, target).await;
    }
    if cfg.bool_or("check_docker", true) {
        let ports = cfg.ports_or("docker_ports", DEFAULT_DOCKER_PORTS);
        c.probe_docker(&client, &host, &ports, target).await;
    }
    if cfg.bool_or("check_containerd", true) {
        let ports = cfg.ports_or("containerd_ports", DEFAULT_CONTAINERD_PORTS);
        c.probe_containerd(&client, &host, &ports, target).await;
    }
    if cfg.bool_or("check_control_plane", true) {
        let ports = cfg.ports_or("control_plane_ports", DEFAULT_CONTROL_PLANE_PORTS);
        c.probe_control_plane(&client, &host, token_ref, &ports, target)
            .await;
    }
    if cfg.bool_or("check_dashboard", true) {
        c.probe_dashboard(&client, target).await;
    }
    if cfg.bool_or("check_registry", true) {
        let ports = cfg.ports_or("registry_ports", DEFAULT_REGISTRY_PORTS);
        c.probe_registry(&client, &host, token_ref, &ports, target)
            .await;
    }
    if cfg.bool_or("check_service_mesh", true) {
        let ports = cfg.ports_or("mesh_ports", DEFAULT_MESH_PORTS);
        c.probe_service_mesh(&client, &host, &ports, target).await;
    }
    c.probe_helm_tiller(&host, target, cfg.bool_or("check_helm", true))
        .await;
    if cfg.bool_or("check_gitops", true) {
        c.probe_gitops_platforms(&client, target).await;
    }
    if cfg.bool_or("check_observability", true) {
        let ports = cfg.ports_or("obs_ports", DEFAULT_OBS_PORTS);
        c.probe_observability(&client, &host, &ports, target).await;
    }
    if cfg.bool_or("check_ingress", true) {
        c.probe_ingress_controllers(&client, target).await;
    }

    if cfg.bool_or("synthesize_attack_paths", true) {
        c.synthesize_attack_paths(target);
    }

    if cfg.bool_or("include_cis_benchmark", true) {
        c.emit_cis_benchmark(target);
    }

    // Optional confidence floor — always keeps synthesised attack paths + CIS benchmark.
    if let Some(min) = cfg
        .string("min_confidence")
        .and_then(|s| s.parse::<f64>().ok())
    {
        c.findings.retain(|f| {
            f.get("attack_path")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || f.get("category").and_then(Value::as_str) == Some("cis_benchmark")
                || f.get("confidence")
                    .and_then(Value::as_f64)
                    .map(|x| x >= min)
                    .unwrap_or(true)
        });
    }

    if cfg.bool_or("include_posture_summary", true) {
        if let Some(summary) = c.posture_summary(target) {
            c.findings.push(summary);
        }
    }

    let n = c.findings.len();
    let msg = if c.open_ports.is_empty() {
        format!(
            "k8s_container: no remotely-observable cloud-native surface on {}",
            host
        )
    } else {
        format!(
            "k8s_container: {} finding(s) across {} open port(s) on {}",
            n,
            c.open_ports.len(),
            host
        )
    };
    EngineResult::ok(c.findings, msg)
}

/// CLI entry point (`fingerprint_engine k8s_container <target>`).
pub async fn run_k8s_container(target: &str) {
    let ctx = EngineRunContext::default();
    print_result(run_k8s_container_result(target, &ctx).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_parses_kube_versions() {
        assert_eq!(parse_semver("v1.23.5"), Some((1, 23, 5)));
        assert_eq!(parse_semver("1.27"), Some((1, 27, 0)));
        assert_eq!(parse_semver("v1.27.4-gke.900"), Some((1, 27, 4)));
        assert_eq!(parse_semver("not-a-version"), None);
    }

    #[test]
    fn vulnerable_before_respects_minor_branches() {
        let fixes = [(1, 19, 16), (1, 20, 11), (1, 21, 5), (1, 22, 2)];
        assert!(vulnerable_before((1, 21, 0), &fixes)); // same minor, below patch
        assert!(!vulnerable_before((1, 21, 5), &fixes)); // exactly patched
        assert!(vulnerable_before((1, 18, 99), &fixes)); // below lowest fixed minor
        assert!(!vulnerable_before((1, 25, 0), &fixes)); // above highest fixed minor
    }

    #[test]
    fn cve_table_matches_old_and_clears_new() {
        let old = known_k8s_cves((1, 9, 0));
        assert!(old.iter().any(|c| c.id == "CVE-2018-1002105"));
        let new = known_k8s_cves((1, 30, 0));
        assert!(
            new.is_empty(),
            "a current release should match no historical control-plane CVEs"
        );
    }

    #[test]
    fn api_list_and_item_count_detection() {
        let body = r#"{"kind":"SecretList","apiVersion":"v1","items":[{"a":1},{"b":2},{"c":3}]}"#;
        assert!(is_api_list(body));
        assert_eq!(count_items(body), Some(3));
        assert!(!is_api_list("<html>hello</html>"));
    }

    #[test]
    fn rbac_binding_detector_flags_anonymous_subjects() {
        let body = r#"{"kind":"ClusterRoleBindingList","items":[{"subjects":[{"name":"system:anonymous"}]}]}"#;
        let hits = rbac_anonymous_binding(body);
        assert!(hits.contains(&"system:anonymous".to_string()));
        assert!(rbac_anonymous_binding("{}").is_empty());
    }

    #[test]
    fn k8s_status_body_is_recognised() {
        assert!(is_k8s_status(
            r#"{"kind":"Status","status":"Failure","reason":"Forbidden"}"#
        ));
        assert!(!is_k8s_status("plain text"));
    }

    #[test]
    fn attack_path_synthesis_chains_real_signals() {
        let mut c = Collector::default();
        c.sig.anon_api = true;
        c.sig.api_secrets_anon = true;
        c.sig.api_endpoint = Some("https://10.0.0.1:6443".to_string());
        c.synthesize_attack_paths("https://10.0.0.1:6443");
        let ap = c
            .findings
            .iter()
            .find(|f| f["path_id"] == json!("anon_api_cluster_takeover"))
            .expect("expected the anonymous-API takeover path");
        assert_eq!(ap["category"], json!("attack_path"));
        assert_eq!(ap["severity"], json!("critical"));
        assert!(ap["evidence"]["steps"]
            .as_array()
            .is_some_and(|s| s.len() >= 4));
    }

    #[test]
    fn posture_summary_scores_real_findings() {
        let mut c = Collector::default();
        c.note_open(6443);
        c.add_node("apiserver:6443", "kube-apiserver", "k8s_api", "takeover");
        c.push(finding_rich(
            ENGINE_ID,
            "x",
            "critical",
            "T1613",
            "d",
            "t",
            0.9,
            Evidence::new(),
        ));
        let s = c.posture_summary("t").expect("summary expected");
        assert_eq!(s["category"], json!("posture_summary"));
        assert!(s["evidence"]["exposure_score"].as_u64().unwrap() >= 25);
        assert!(s["evidence"]["graph"]["nodes"]
            .as_array()
            .is_some_and(|n| !n.is_empty()));
    }

    #[test]
    fn managed_provider_detected_from_git_version() {
        assert_eq!(detect_managed_provider("v1.27.4-gke.900"), Some("GKE"));
        assert_eq!(detect_managed_provider("v1.28.2-eks-abc"), Some("EKS"));
        assert_eq!(detect_managed_provider("v1.25.11"), None);
    }

    #[test]
    fn pod_danger_stats_from_real_list_json() {
        let body = r#"{"kind":"PodList","items":[
            {"spec":{"hostPID":true,"containers":[{"securityContext":{"privileged":true}}],"volumes":[{"hostPath":{"path":"/"}}]}},
            {"spec":{"hostNetwork":true,"automountServiceAccountToken":false,"containers":[{}]}}
        ]}"#;
        let d = analyze_pod_dangers(body);
        assert_eq!(d.privileged, 1);
        assert_eq!(d.host_pid, 1);
        assert_eq!(d.host_network, 1);
        assert_eq!(d.host_path, 1);
        assert!(pod_stats_any(&d));
    }

    #[test]
    fn cis_benchmark_emits_on_anonymous_api_signal() {
        let mut c = Collector::default();
        c.sig.anon_api = true;
        c.sig.kubelet_anon_read = true;
        c.emit_cis_benchmark("https://cluster.test");
        let cis = c
            .findings
            .iter()
            .find(|f| f["category"] == json!("cis_benchmark"))
            .expect("cis finding");
        assert!(cis["evidence"]["failed_controls"].as_u64().unwrap() >= 2);
    }

    #[tokio::test]
    async fn empty_target_is_rejected() {
        let r = run_k8s_container_result("", &EngineRunContext::default()).await;
        assert!(!r.success);
    }
}
