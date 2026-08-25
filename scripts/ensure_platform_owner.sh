#!/usr/bin/env bash
# Upsert the platform owner (role=ceo, is_superadmin=true) in tenant `default`.
# Credentials come from the environment only — this script never hardcodes an identity.
#
#   WEISSMAN_MASTER_BOOTSTRAP_EMAIL=you@company.com \
#   WEISSMAN_MASTER_BOOTSTRAP_PASSWORD='…' \
#   ./scripts/ensure_platform_owner.sh
#
# Talks to local psql via DATABASE_URL / WEISSMAN_MIGRATE_URL, or to the live Docker
# postgres service when those are unset and compose is up.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

EMAIL="${WEISSMAN_MASTER_BOOTSTRAP_EMAIL:-${WEISSMAN_PLATFORM_OWNER_EMAIL:-}}"
PASSWORD="${WEISSMAN_MASTER_BOOTSTRAP_PASSWORD:-${WEISSMAN_PLATFORM_OWNER_PASSWORD:-}}"
EMAIL="${EMAIL#"${EMAIL%%[![:space:]]*}"}"
EMAIL="${EMAIL%"${EMAIL##*[![:space:]]}"}"
[[ -n "$EMAIL" ]] || { echo "set WEISSMAN_MASTER_BOOTSTRAP_EMAIL" >&2; exit 1; }
[[ -n "$PASSWORD" ]] || { echo "set WEISSMAN_MASTER_BOOTSTRAP_PASSWORD" >&2; exit 1; }

HASH="$(python3 - "$PASSWORD" <<'PY'
import sys, bcrypt
pw = sys.argv[1].encode("utf-8")
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("ascii"))
PY
)"

SQL=$(cat <<'EOF'
SELECT set_config('app.ceo_role_assignment', '1', false);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM tenants WHERE slug = 'default' AND active = true) THEN
    RAISE EXCEPTION 'no active tenant with slug default';
  END IF;
END
$$;
WITH t AS (
  SELECT id FROM tenants WHERE slug = 'default' AND active = true LIMIT 1
),
up AS (
  UPDATE users u
     SET role = 'ceo',
         is_superadmin = true,
         is_active = true,
         password_hash = :'owner_hash',
         updated_at = now()
    FROM t
   WHERE u.tenant_id = t.id
     AND lower(trim(u.email)) = lower(trim(:'owner_email'))
  RETURNING u.id
)
INSERT INTO users (tenant_id, email, password_hash, role, is_superadmin, is_active)
SELECT t.id, trim(:'owner_email'), :'owner_hash', 'ceo', true, true
  FROM t
 WHERE NOT EXISTS (SELECT 1 FROM up);
SELECT u.id, u.email, u.role, u.is_superadmin, u.is_active
  FROM users u
  JOIN tenants t ON t.id = u.tenant_id
 WHERE t.slug = 'default'
   AND lower(trim(u.email)) = lower(trim(:'owner_email'));
EOF
)

# `-c` does not interpolate :variables — feed SQL on stdin.
psql_args=(-v ON_ERROR_STOP=1 -v owner_email="$EMAIL" -v owner_hash="$HASH")
run_sql() {
  psql "${psql_args[@]}" "$@" <<EOSQL
$SQL
EOSQL
}

if [[ -n "${DATABASE_URL:-}" ]]; then
  run_sql "$DATABASE_URL"
elif [[ -n "${WEISSMAN_MIGRATE_URL:-}" ]]; then
  run_sql "$WEISSMAN_MIGRATE_URL"
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
     && docker compose -f docker-compose.yml ps postgres --status running >/dev/null 2>&1; then
  COMPOSE=(docker compose -f docker-compose.yml)
  [[ -f docker-compose.prod.yml ]] && COMPOSE+=(-f docker-compose.prod.yml)
  printf '%s\n' "$SQL" | "${COMPOSE[@]}" exec -T -e PGPASSWORD="${POSTGRES_PASSWORD:-}" postgres \
    psql "${psql_args[@]}" -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-weissman}"
else
  export PGPASSWORD="${PGPASSWORD:-postgres}"
  run_sql -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" \
    -U "${PGUSER:-postgres}" -d "${PGDATABASE:-weissman}"
fi

echo "platform owner upserted: $EMAIL (ceo + is_superadmin)"
