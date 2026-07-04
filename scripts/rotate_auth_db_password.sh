#!/usr/bin/env bash
# Zero-downtime rotation for the weissman_auth database role password.
#
# Usage (rolling deploy — no hard cutover):
#   1. Generate: NEW_PW="$(openssl rand -base64 48)"
#   2. Export maintenance URL (postgres superuser) + new password:
#        export WEISSMAN_AUTH_DB_ROTATION_URL='postgresql://postgres:...@host:5432/weissman'
#        export WEISSMAN_AUTH_ROTATED_PASSWORD="$NEW_PW"
#   3. Run this script — applies ALTER ROLE weissman_auth PASSWORD via maintenance URL.
#   4. Update WEISSMAN_AUTH_DATABASE_URL on each replica to embed $NEW_PW.
#   5. Rolling restart weissman-server + weissman-worker (one replica at a time).
#
# Boot-time sync: when WEISSMAN_MIGRATE_URL is set, weissman-server already runs
# sync_role_passwords_from_env_on_boot() so DATABASE_URL / WEISSMAN_AUTH_DATABASE_URL
# passwords are pushed to Postgres roles after migrations.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -z "${WEISSMAN_AUTH_DB_ROTATION_URL:-}" ]]; then
  echo "WEISSMAN_AUTH_DB_ROTATION_URL is required (postgres superuser or CREATEROLE maintenance URL)" >&2
  exit 1
fi
if [[ -z "${WEISSMAN_AUTH_ROTATED_PASSWORD:-}" ]]; then
  echo "WEISSMAN_AUTH_ROTATED_PASSWORD is required (new weissman_auth password)" >&2
  exit 1
fi
if ((${#WEISSMAN_AUTH_ROTATED_PASSWORD} < 32)); then
  echo "WEISSMAN_AUTH_ROTATED_PASSWORD must be at least 32 characters" >&2
  exit 1
fi

echo "[rotate_auth_db] Applying weissman_auth password via maintenance URL..."
WEISSMAN_AUTH_DB_ROTATION_URL="$WEISSMAN_AUTH_DB_ROTATION_URL" \
WEISSMAN_AUTH_ROTATED_PASSWORD="$WEISSMAN_AUTH_ROTATED_PASSWORD" \
  cargo run -q -p weissman-db --example rotate_auth_password

cat <<EOF

[rotate_auth_db] Password rotated in Postgres.

Next steps (zero downtime):
  1. Update WEISSMAN_AUTH_DATABASE_URL on all replicas with the new password.
  2. Rolling restart weissman-server and weissman-worker (one pod/VM at a time).
  3. Verify: curl -sf "\${WEISSMAN_PUBLIC_BASE_URL}/api/health"
  4. Unset WEISSMAN_AUTH_DB_ROTATION_URL / WEISSMAN_AUTH_ROTATED_PASSWORD from deploy secrets.

EOF
