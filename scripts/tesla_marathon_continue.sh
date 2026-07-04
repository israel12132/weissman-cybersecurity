#!/usr/bin/env bash
# Resume Tesla (client 4) production-engine marathon with stable stack settings.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LIMIT="${WEISSMAN_ENGINE_LIMIT:-30}"
OFFSET="${WEISSMAN_ENGINE_START_OFFSET:-0}"
LOG="${TESLA_MARATHON_LOG:-/tmp/weissman-tesla-marathon.log}"

# Pause competing docker backend if still up.
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx weissman-cybersecurity-backend-1; then
  echo "Stopping docker backend (competes for :8000 + DB pool)..."
  docker stop weissman-cybersecurity-backend-1 >/dev/null 2>&1 || true
fi

if ! curl -sf http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
  echo "E2E stack not healthy — run: ./scripts/run_e2e_stack.sh start" >&2
  exit 1
fi

if ! pgrep -f 'target/debug/weissman-worker' >/dev/null 2>&1; then
  echo "Worker down — run: ./scripts/run_e2e_stack.sh start" >&2
  exit 1
fi

echo "Tesla marathon: offset=${OFFSET} limit=${LIMIT} log=${LOG}"
WEISSMAN_E2E_CLIENT_ID=4 \
WEISSMAN_SMOKE_TARGET=https://www.tesla.com \
WEISSMAN_ENGINE_REPORT=.e2e-stack/tesla_engines_live_report.json \
WEISSMAN_ENGINE_START_OFFSET="${OFFSET}" \
WEISSMAN_ENGINE_POLL_MAX="${WEISSMAN_ENGINE_POLL_MAX:-180}" \
WEISSMAN_ENGINE_ENQ_GAP_MS="${WEISSMAN_ENGINE_ENQ_GAP_MS:-6000}" \
WEISSMAN_ENGINE_BATCH_SIZE=1 \
WEISSMAN_ENGINE_LIMIT="${LIMIT}" \
node scripts/verify_all_engines_live.mjs 2>&1 | tee -a "${LOG}"
