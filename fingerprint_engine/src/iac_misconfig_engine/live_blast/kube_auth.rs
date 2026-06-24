//! Auto-discover Kubernetes API credentials — in-cluster SA, kubeconfig, or explicit operator params.

use super::k8s_reconciler::K8sReconcileConfig;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct DiscoveredK8sAuth {
    pub api_server: String,
    pub token: String,
    pub source: String,
}

/// Resolve K8s auth: explicit params beat kubeconfig beat in-cluster service account.
#[must_use]
pub fn resolve_k8s_auth(cfg: &K8sReconcileConfig) -> Option<DiscoveredK8sAuth> {
    if !cfg.api_server.trim().is_empty() && !cfg.token.trim().is_empty() {
        return Some(DiscoveredK8sAuth {
            api_server: cfg.api_server.trim().to_string(),
            token: cfg.token.trim().to_string(),
            source: "explicit".to_string(),
        });
    }
    if let Some(k) = from_kubeconfig(cfg) {
        return Some(k);
    }
    from_in_cluster()
}

fn from_kubeconfig(_cfg: &K8sReconcileConfig) -> Option<DiscoveredK8sAuth> {
    let path = env::var("KUBECONFIG")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(format!("{h}/.kube/config")))
        })
        .filter(|p| p.exists())?;
    let raw = fs::read_to_string(&path).ok()?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&raw).ok()?;
    let clusters = doc.get("clusters")?.as_sequence()?;
    let cluster = clusters.first()?;
    let server = cluster
        .get("cluster")
        .and_then(|c| c.get("server"))
        .and_then(serde_yaml::Value::as_str)?;
    let users = doc.get("users")?.as_sequence()?;
    let user = users.first()?;
    let token = user
        .get("user")
        .and_then(|u| u.get("token"))
        .and_then(serde_yaml::Value::as_str)?;
    if token.trim().is_empty() {
        return None;
    }
    Some(DiscoveredK8sAuth {
        api_server: server.to_string(),
        token: token.to_string(),
        source: format!("kubeconfig:{}", path.display()),
    })
}

fn from_in_cluster() -> Option<DiscoveredK8sAuth> {
    let host = env::var("KUBERNETES_SERVICE_HOST").ok()?;
    let port = env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
    let token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    let token = fs::read_to_string(token_path).ok()?;
    if token.trim().is_empty() {
        return None;
    }
    Some(DiscoveredK8sAuth {
        api_server: format!("https://{host}:{port}"),
        token: token.trim().to_string(),
        source: "in-cluster-serviceaccount".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_beats_empty() {
        let cfg = K8sReconcileConfig {
            api_server: "https://k8s.example".into(),
            token: "tok".into(),
            default_namespace: "default".into(),
            verify_tls: true,
            timeout_ms: 5000,
        };
        let d = resolve_k8s_auth(&cfg).unwrap();
        assert_eq!(d.source, "explicit");
    }
}
