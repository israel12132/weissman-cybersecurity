#!/usr/bin/env bash
# Production recovery checks: DB grant, build binary if needed, curl /api/health until 200.
set -euo pipefail
REPO="${REPO:-/root/weissman-bot}"
cd "$REPO"

if [[ "${EUID:-0}" -ne 0 ]] && ! command -v psql >/dev/null 2>&1; then
  echo "Run as root if psql should use peer auth; otherwise ensure psql is on PATH." >&2
fi

set +H
set -a
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  . ./.env
fi
set +a

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL not set (load .env or export it)." >&2
  exit 1
fi

echo "== GRANT on weissman_prod (requires superuser in DATABASE_URL)"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "GRANT ALL PRIVILEGES ON DATABASE weissman_prod TO postgres;" \
  || echo "WARN: GRANT failed (already granted or insufficient privileges?)"

if command -v nix >/dev/null 2>&1; then
  echo "== nix build . (store binary has libhwloc/openssl RPATH — use this for systemd ExecStart)"
  (cd "$REPO" && nix build . --accept-flake-config --print-build-logs)
  RES_BIN="$REPO/result/bin/weissman-server"
else
  echo "== cargo build -p weissman-server --release (no nix: run under nix develop for LD_LIBRARY_PATH)"
  (cd "$REPO" && cargo build -p weissman-server --release)
  RES_BIN="$REPO/target/release/weissman-server"
fi
if [[ ! -x "$RES_BIN" ]]; then
  echo "FATAL: missing $RES_BIN" >&2
  exit 1
fi

PORT="${PORT:-8000}"
export PORT

echo "== Starting weissman-server ($RES_BIN)"
( cd "$REPO" && bash -c "
  set +H
  set -a
  [[ -f .env ]] && . ./.env
  set +a
  export PORT=\"${PORT}\"
  exec \"$RES_BIN\"
" ) &
SRV_PID=$!
echo "== Waiting for TCP :${PORT} (migrations + bind can take up to ~90s)"
for _ in $(seq 1 120); do
  if ss -tln "sport = :${PORT}" 2>/dev/null | grep -q LISTEN; then
    break
  fi
  sleep 1
done
cleanup() {
  kill "$SRV_PID" 2>/dev/null || true
  pkill -f '[t]arget/release/weissman-server' 2>/dev/null || true
  pkill -f '[r]esult/bin/weissman-server' 2>/dev/null || true
}
trap cleanup EXIT

echo "== curl http://127.0.0.1:${PORT}/api/health until HTTP 200"
ok=0
for _ in $(seq 1 120); do
  code=$(curl -sS -o /tmp/weissman-health.json -w "%{http_code}" --connect-timeout 2 "http://127.0.0.1:${PORT}/api/health" || echo "000")
  if [[ "$code" == "200" ]]; then
    ok=1
    break
  fi
  sleep 1
done

if [[ "$ok" -ne 1 ]]; then
  echo "FAIL: /api/health did not return 200 within 120s (last code=$code)" >&2
  exit 1
fi

echo "== /api/health body (postgres_ok must be true for DB verified):"
cat /tmp/weissman-health.json
echo ""

if ! grep -q '"postgres_ok"[[:space:]]*:[[:space:]]*true' /tmp/weissman-health.json; then
  echo "WARN: postgres_ok is not true — check DATABASE_URL and DB reachability." >&2
  exit 2
fi

echo "OK: HTTP 200 and postgres_ok=true"
