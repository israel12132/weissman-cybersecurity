#!/usr/bin/env bash
# Generate a Kubernetes Secret manifest from environment (never commit output).
# Usage:
#   export DATABASE_URL=... WEISSMAN_JWT_SECRET=... (see deploy/k8s/secret.example.yaml)
#   ./scripts/k8s-generate-secrets.sh | kubectl apply -f - -n weissman
set -euo pipefail

require() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "error: $name is required" >&2
    exit 1
  fi
}

require DATABASE_URL
require WEISSMAN_AUTH_DATABASE_URL
require WEISSMAN_MIGRATE_URL
require WEISSMAN_JWT_SECRET
require REDIS_URL
require WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET
require WEISSMAN_PROXY_SIGNING_SECRET
require WEISSMAN_JOB_ORCHESTRATOR_SECRET
require WEISSMAN_METRICS_TOKEN

if [[ "${#WEISSMAN_JWT_SECRET}" -lt 48 ]]; then
  echo "error: WEISSMAN_JWT_SECRET must be >= 48 chars" >&2
  exit 1
fi
for v in WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET WEISSMAN_PROXY_SIGNING_SECRET WEISSMAN_JOB_ORCHESTRATOR_SECRET WEISSMAN_METRICS_TOKEN; do
  val="${!v}"
  if [[ "${#val}" -lt 32 ]]; then
    echo "error: $v must be >= 32 chars" >&2
    exit 1
  fi
done

cat <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: weissman-secrets
  namespace: weissman
type: Opaque
stringData:
  database_url: "${DATABASE_URL}"
  auth_database_url: "${WEISSMAN_AUTH_DATABASE_URL}"
  migrate_url: "${WEISSMAN_MIGRATE_URL}"
  jwt_secret: "${WEISSMAN_JWT_SECRET}"
  redis_url: "${REDIS_URL}"
  admin_email: "${WEISSMAN_ADMIN_EMAIL:-admin@localhost}"
  admin_password: "${WEISSMAN_ADMIN_PASSWORD:-}"
  destructive_confirm_secret: "${WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET}"
  proxy_signing_secret: "${WEISSMAN_PROXY_SIGNING_SECRET}"
  job_orchestrator_secret: "${WEISSMAN_JOB_ORCHESTRATOR_SECRET}"
  metrics_token: "${WEISSMAN_METRICS_TOKEN}"
  integrations_vault_key: "${WEISSMAN_INTEGRATIONS_VAULT_KEY:-}"
  dual_approval_secret: "${WEISSMAN_DUAL_APPROVAL_SECRET:-}"
EOF
