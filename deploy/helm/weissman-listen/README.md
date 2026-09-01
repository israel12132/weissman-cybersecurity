# weissman-listen

Axum `listen(4096)` is silently truncated to `net.core.somaxconn` (often 128).
That sysctl is **namespaced**: a node DaemonSet does not fix default CNI pods.

```bash
helm upgrade --install weissman-listen deploy/helm/weissman-listen \
  --namespace weissman --create-namespace
```

Modes (`--set mode=`):

- `preflight` (default) — Helm pre-install Job exits 1 if somaxconn < 4096.
  The backend Deployment already has a matching read-only initContainer.
- `podSysctl` — ConfigMap with kubelet `allowedUnsafeSysctls` + pod sysctls patch.
- `privilegedInit` — ConfigMap with a privileged init container to merge into
  `weissman-backend` (blocked by PSS Restricted).

`--set daemonSet.enabled=true` for hostNetwork / node-level sysctl only.
