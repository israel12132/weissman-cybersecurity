//! Kubernetes RBAC proof — live SubjectAccessReview API calls.

use super::graph_model::{EdgeKind, InfraGraph, K8sRbacProof, NodeKind};
use super::k8s_reconciler::K8sReconcileConfig;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

#[derive(Debug, Clone)]
struct SarCheck {
    verb: &'static str,
    resource: &'static str,
    subresource: Option<&'static str>,
}

const SA_CHECKS: &[SarCheck] = &[
    SarCheck {
        verb: "get",
        resource: "secrets",
        subresource: None,
    },
    SarCheck {
        verb: "list",
        resource: "secrets",
        subresource: None,
    },
    SarCheck {
        verb: "create",
        resource: "pods",
        subresource: None,
    },
    SarCheck {
        verb: "get",
        resource: "serviceaccounts",
        subresource: None,
    },
];

fn build_client(cfg: &K8sReconcileConfig) -> Client {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_millis(cfg.timeout_ms.clamp(1_000, 30_000)))
        .connect_timeout(Duration::from_millis(6_000));
    if !cfg.verify_tls {
        b = b.danger_accept_invalid_certs(true);
    }
    b.build().unwrap_or_else(|_| reqwest::Client::new())
}

fn sa_user(ns: &str, name: &str) -> String {
    format!("system:serviceaccount:{ns}:{name}")
}

fn parse_sa_address(addr: &str, default_ns: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = addr.split('/').collect();
    match parts.as_slice() {
        [ns, "ServiceAccount", name] => Some(((*ns).to_string(), (*name).to_string())),
        ["ServiceAccount", name] => Some((default_ns.to_string(), (*name).to_string())),
        _ => None,
    }
}

pub async fn prove_k8s_rbac(
    graph: &mut InfraGraph,
    cfg: &K8sReconcileConfig,
) -> (Vec<K8sRbacProof>, Vec<String>) {
    let mut proofs = Vec::new();
    let mut notes = Vec::new();
    let base = cfg.api_server.trim().trim_end_matches('/');
    if base.is_empty() || cfg.token.trim().is_empty() {
        notes.push("K8s RBAC SAR skipped: no API credentials".to_string());
        return (proofs, notes);
    }

    let client = build_client(cfg);
    let default_ns = if cfg.default_namespace.trim().is_empty() {
        "default"
    } else {
        cfg.default_namespace.as_str()
    };
    let bearer = format!("Bearer {}", cfg.token.trim());

    let sas: Vec<_> = graph
        .nodes
        .values()
        .filter(|n| n.kind == NodeKind::K8sServiceAccount)
        .map(|n| (n.id.clone(), n.iac_address.clone(), n.label.clone()))
        .collect();

    for (sa_id, addr, label) in sas {
        let Some(addr) = addr else { continue };
        let Some((ns, sa_name)) = parse_sa_address(&addr, default_ns) else {
            continue;
        };
        let user = sa_user(&ns, &sa_name);
        for check in SA_CHECKS {
            let body = json!({
                "apiVersion": "authorization.k8s.io/v1",
                "kind": "SubjectAccessReview",
                "spec": {
                    "user": user,
                    "resourceAttributes": {
                        "namespace": ns,
                        "verb": check.verb,
                        "resource": check.resource,
                        "subresource": check.subresource,
                    }
                }
            });
            let url = format!("{base}/apis/authorization.k8s.io/v1/subjectaccessreviews");
            let Ok(resp) = client
                .post(&url)
                .header("Authorization", &bearer)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
            else {
                continue;
            };
            let status = resp.status();
            if !status.is_success() {
                continue;
            }
            let Ok(v) = resp.json::<serde_json::Value>().await else {
                continue;
            };
            let allowed = v
                .get("status")
                .and_then(|s| s.get("allowed"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !allowed {
                continue;
            }
            let evidence = format!(
                "SubjectAccessReview: {user} allowed {}/{} in namespace {ns}",
                check.resource, check.verb
            );
            let proof = K8sRbacProof {
                subject_id: sa_id.clone(),
                resource_id: format!("rbac:{ns}:{}", check.resource),
                verb: check.verb.to_string(),
                resource: check.resource.to_string(),
                namespace: ns.clone(),
                allowed: true,
                evidence: evidence.clone(),
            };
            proofs.push(proof);

            if check.resource == "secrets" {
                let secret_ids: Vec<String> = graph
                    .nodes
                    .values()
                    .filter(|n| n.kind == NodeKind::K8sSecret)
                    .filter(|n| {
                        n.iac_address
                            .as_deref()
                            .map(|a| a.starts_with(&format!("{ns}/")))
                            .unwrap_or(false)
                    })
                    .map(|n| n.id.clone())
                    .collect();
                for sid in secret_ids {
                    graph.add_edge(&sa_id, &sid, EdgeKind::RbacProven, evidence.clone());
                }
            }
            let _ = label;
        }
    }

    graph.k8s_rbac_proofs.extend(proofs.clone());
    notes.push(format!(
        "K8s SubjectAccessReview: {} proven RBAC permissions",
        proofs.len()
    ));
    (proofs, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sa_address() {
        let p = parse_sa_address("prod/ServiceAccount/app", "default").unwrap();
        assert_eq!(p, ("prod".to_string(), "app".to_string()));
    }
}
