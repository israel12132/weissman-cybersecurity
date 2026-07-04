#!/usr/bin/env bash
# Validate Weissman Kubernetes manifests (dry-run) and optional Kind cluster apply.
# Usage:
#   ./scripts/k8s-kind-smoke.sh           # manifest validation only
#   ./scripts/k8s-kind-smoke.sh --apply   # requires kind cluster "weissman"
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

pass=0
fail=0
ok() { echo "PASS: $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; fail=$((fail + 1)); }

section() { echo ""; echo "== $1 =="; }

section "Manifest files"
for f in \
  deploy/k8s/namespace.yaml \
  deploy/k8s/configmap.yaml \
  deploy/k8s/secret.example.yaml \
  deploy/k8s/backend-deployment.yaml \
  deploy/k8s/worker-deployment.yaml \
  deploy/k8s/worker-hpa.yaml \
  deploy/k8s/network-policies.yaml \
  deploy/k8s/backend-service.yaml \
  deploy/k8s/gateway-deployment.yaml \
  deploy/k8s/gateway-service.yaml \
  deploy/k8s/redis-deployment.yaml \
  deploy/k8s/ingress.yaml
do
  [[ -f "$f" ]] && ok "exists $f" || bad "missing $f"
done

section "kubectl dry-run"
if command -v kubectl >/dev/null 2>&1; then
  if kubectl apply --dry-run=client -f deploy/k8s/namespace.yaml \
    -f deploy/k8s/configmap.yaml \
    -f deploy/k8s/secret.example.yaml \
    -f deploy/k8s/backend-deployment.yaml \
    -f deploy/k8s/worker-deployment.yaml \
    -f deploy/k8s/worker-hpa.yaml \
    -f deploy/k8s/network-policies.yaml \
    -f deploy/k8s/backend-service.yaml \
    -f deploy/k8s/gateway-deployment.yaml \
    -f deploy/k8s/gateway-service.yaml \
    -f deploy/k8s/redis-deployment.yaml \
    -f deploy/k8s/ingress.yaml >/dev/null 2>&1; then
    ok "kubectl dry-run client"
  else
    bad "kubectl dry-run client"
  fi
else
  echo "SKIP: kubectl not installed"
fi

section "Required secret keys in template"
for key in destructive_confirm_secret job_orchestrator_secret metrics_token database_url migrate_url; do
  if grep -q "$key:" deploy/k8s/secret.example.yaml; then
    ok "secret key $key"
  else
    bad "secret key $key"
  fi
done

if [[ "$APPLY" -eq 1 ]]; then
  section "Kind apply"
  if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -qx weissman; then
    kubectl apply -f deploy/k8s/namespace.yaml
    kubectl apply -f deploy/k8s/configmap.yaml -n weissman
    kubectl apply -f deploy/k8s/network-policies.yaml -n weissman
    ok "kind cluster apply (core resources)"
  else
    bad "kind cluster 'weissman' not found — run: kind create cluster --config deploy/kind/kind-config.yaml --name weissman"
  fi
fi

echo ""
echo "K8s smoke: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]] || exit 1
echo "All K8s manifest checks passed."
