#!/usr/bin/env bash
# Run Playwright live-journey E2E against real backend stack.
# Usage:
#   ./scripts/run_playwright_live_e2e.sh
#   WEISSMAN_E2E_BASE=http://127.0.0.1:8000 ./scripts/run_playwright_live_e2e.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

export WEISSMAN_E2E_BASE="${WEISSMAN_E2E_BASE:-http://127.0.0.1:8000}"
export PLAYWRIGHT_LIVE=1

if [[ -z "${WEISSMAN_ADMIN_PASSWORD:-}" ]]; then
  echo "error: WEISSMAN_ADMIN_PASSWORD required" >&2
  exit 1
fi

echo "== Ensure E2E stack =="
if ! curl -sf "${WEISSMAN_E2E_BASE}/api/health" >/dev/null 2>&1; then
  echo "Starting E2E stack..."
  ./scripts/run_e2e_stack.sh start
  for _ in $(seq 1 60); do
    if curl -sf "${WEISSMAN_E2E_BASE}/api/health" >/dev/null 2>&1; then break; fi
    sleep 2
  done
fi

curl -sf "${WEISSMAN_E2E_BASE}/api/health" >/dev/null || {
  echo "error: backend not healthy at ${WEISSMAN_E2E_BASE}" >&2
  exit 1
}

echo "== Playwright live journey =="
cd frontend
npx playwright install chromium
PLAYWRIGHT_LIVE=1 WEISSMAN_E2E_BASE="$WEISSMAN_E2E_BASE" \
  WEISSMAN_ADMIN_EMAIL="${WEISSMAN_ADMIN_EMAIL:-admin@localhost}" \
  WEISSMAN_ADMIN_PASSWORD="$WEISSMAN_ADMIN_PASSWORD" \
  npm run test:e2e

echo "Playwright live E2E: OK"
