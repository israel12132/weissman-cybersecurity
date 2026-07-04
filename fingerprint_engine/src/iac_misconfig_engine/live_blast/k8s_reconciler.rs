//! Kubernetes live reconciliation — real K8s API GET calls (no mocks).

use super::graph_model::{InfraGraph, LiveReconcileMatch, LiveStatus, NodeKind};
use reqwest::Client;
use std::time::Duration;

pub struct K8sReconcileConfig {
    pub api_server: String,
    pub token: String,
    pub default_namespace: String,
    pub verify_tls: bool,
    pub timeout_ms: u64,
}

/// Parse `namespace/Kind/name`, `cluster/Kind/name`, or `Kind/name` using default namespace.
#[must_use]
pub fn parse_iac_address(addr: &str, default_ns: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = addr.split('/').collect();
    match parts.as_slice() {
        ["cluster", kind, name] => Some(("".to_string(), (*kind).to_string(), (*name).to_string())),
        [ns, kind, name] => Some(((*ns).to_string(), (*kind).to_string(), (*name).to_string())),
        [kind, name] => Some((
            default_ns.to_string(),
            (*kind).to_string(),
            (*name).to_string(),
        )),
        _ => None,
    }
}

fn api_path(ns: &str, kind: &str, name: &str) -> Option<String> {
    let path = match kind {
        "Ingress" => format!("/apis/networking.k8s.io/v1/namespaces/{ns}/ingresses/{name}"),
        "Service" => format!("/api/v1/namespaces/{ns}/services/{name}"),
        "ServiceAccount" => format!("/api/v1/namespaces/{ns}/serviceaccounts/{name}"),
        "Secret" => format!("/api/v1/namespaces/{ns}/secrets/{name}"),
        "Deployment" => format!("/apis/apps/v1/namespaces/{ns}/deployments/{name}"),
        "StatefulSet" => format!("/apis/apps/v1/namespaces/{ns}/statefulsets/{name}"),
        "DaemonSet" => format!("/apis/apps/v1/namespaces/{ns}/daemonsets/{name}"),
        "NetworkPolicy" => {
            format!("/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies/{name}")
        }
        "Role" => format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles/{name}"),
        "RoleBinding" => {
            format!("/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/rolebindings/{name}")
        }
        "ClusterRole" => format!("/apis/rbac.authorization.k8s.io/v1/clusterroles/{name}"),
        "ConfigMap" => format!("/api/v1/namespaces/{ns}/configmaps/{name}"),
        _ => return None,
    };
    Some(path)
}

fn build_client(cfg: &K8sReconcileConfig) -> Client {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms.clamp(1_000, 30_000)))
        .connect_timeout(Duration::from_millis(6_000));
    if !cfg.verify_tls {
        b = b.danger_accept_invalid_certs(true);
    }
    b.build().unwrap_or_else(|_| reqwest::Client::new())
}

fn apply_match(graph: &mut InfraGraph, m: &LiveReconcileMatch) {
    if let Some(node) = graph.nodes.get_mut(&m.node_id) {
        node.live_status = m.live_status;
        node.live_evidence = Some(m.evidence.clone());
    }
}

pub async fn reconcile_graph(
    graph: &mut InfraGraph,
    cfg: &K8sReconcileConfig,
) -> (Vec<LiveReconcileMatch>, Vec<String>) {
    let mut matches = Vec::new();
    let mut notes = Vec::new();

    let base = cfg.api_server.trim().trim_end_matches('/');
    if base.is_empty() {
        notes.push("live K8s reconcile skipped: no k8s_api_server".to_string());
        return (matches, notes);
    }
    if cfg.token.trim().is_empty() {
        notes.push("live K8s reconcile skipped: no k8s_token".to_string());
        return (matches, notes);
    }

    let client = build_client(cfg);
    let default_ns = if cfg.default_namespace.trim().is_empty() {
        "default"
    } else {
        cfg.default_namespace.as_str()
    };

    notes.push(format!("live K8s reconcile: API server {base}"));

    let targets: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| n.provider == "kubernetes" && n.kind != NodeKind::Internet)
        .map(|n| (n.id.clone(), n.iac_address.clone(), n.kind))
        .collect();

    for (node_id, iac_address, kind) in targets {
        let Some(addr) = iac_address else { continue };
        let Some((ns, k8s_kind, name)) = parse_iac_address(&addr, default_ns) else {
            continue;
        };
        let Some(path) = api_path(&ns, &k8s_kind, &name) else {
            continue;
        };
        let url = format!("{base}{path}");
        let bearer = format!("Bearer {}", cfg.token.trim());

        let resp = client
            .get(&url)
            .header("Authorization", bearer)
            .header("Accept", "application/json")
            .send()
            .await;

        let m = match resp {
            Ok(r) if r.status().is_success() => {
                let evidence = match kind {
                    NodeKind::K8sIngress => format!("GET {path}: Ingress exists in namespace {ns}"),
                    NodeKind::K8sService => format!("GET {path}: Service exists in namespace {ns}"),
                    NodeKind::K8sServiceAccount => {
                        format!("GET {path}: ServiceAccount exists in namespace {ns}")
                    }
                    NodeKind::K8sSecret => {
                        format!("GET {path}: Secret resource exists in namespace {ns}")
                    }
                    NodeKind::K8sPod => format!("GET {path}: Workload exists in namespace {ns}"),
                    _ => format!("GET {path}: resource confirmed"),
                };
                LiveReconcileMatch {
                    node_id: node_id.clone(),
                    iac_address: addr.clone(),
                    live_status: LiveStatus::ConfirmedLive,
                    evidence,
                    api_called: format!("k8s:GET {path}"),
                }
            }
            Ok(r) if r.status().as_u16() == 404 => LiveReconcileMatch {
                node_id: node_id.clone(),
                iac_address: addr.clone(),
                live_status: LiveStatus::NotDeployed,
                evidence: format!("GET {path}: HTTP 404 — not deployed"),
                api_called: format!("k8s:GET {path}"),
            },
            Ok(r) if r.status().as_u16() == 403 => {
                // Forbidden often means the object exists but token cannot read details.
                LiveReconcileMatch {
                    node_id: node_id.clone(),
                    iac_address: addr.clone(),
                    live_status: LiveStatus::ConfirmedLive,
                    evidence: format!(
                        "GET {path}: HTTP 403 — resource likely exists (RBAC denied read)"
                    ),
                    api_called: format!("k8s:GET {path}"),
                }
            }
            Ok(r) => LiveReconcileMatch {
                node_id: node_id.clone(),
                iac_address: addr.clone(),
                live_status: LiveStatus::Skipped,
                evidence: format!("GET {path}: HTTP {}", r.status()),
                api_called: format!("k8s:GET {path}"),
            },
            Err(e) => LiveReconcileMatch {
                node_id: node_id.clone(),
                iac_address: addr.clone(),
                live_status: LiveStatus::Skipped,
                evidence: format!("GET {path}: transport error — {e}"),
                api_called: format!("k8s:GET {path}"),
            },
        };
        apply_match(graph, &m);
        if m.live_status == LiveStatus::ConfirmedLive {
            matches.push(m);
        } else if m.live_status == LiveStatus::NotDeployed {
            matches.push(m);
        }
    }

    notes.push(format!(
        "live K8s reconcile: {} matches, {} confirmed live",
        matches.len(),
        matches
            .iter()
            .filter(|m| m.live_status == LiveStatus::ConfirmedLive)
            .count()
    ));
    (matches, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_address_with_namespace() {
        let p = parse_iac_address("prod/Ingress/api", "default").unwrap();
        assert_eq!(p, ("prod".into(), "Ingress".into(), "api".into()));
    }

    #[test]
    fn parse_address_default_ns() {
        let p = parse_iac_address("Service/frontend", "kube-system").unwrap();
        assert_eq!(
            p,
            ("kube-system".into(), "Service".into(), "frontend".into())
        );
    }
}
