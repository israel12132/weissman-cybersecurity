#!/usr/bin/env bash
# Overnight supreme audit orchestrator — runs UI crawl, API matrix, findings verify, engine smoke.
# Logs: /tmp/weissman-overnight-audit.jsonl, /tmp/weissman-overnight-ui-crawl.log
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
LOG="/tmp/weissman-overnight-orchestrator.log"
CYCLE=0

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG"; }

load_env() {
  if [[ -f "$ROOT/.env" ]]; then set -a; source "$ROOT/.env"; set +a; fi
  export DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@127.0.0.1:5432/weissman}"
  export WEISSMAN_E2E_BASE="${WEISSMAN_E2E_BASE:-http://127.0.0.1:8000}"
}

ensure_stack() {
  if ! curl -sf "$WEISSMAN_E2E_BASE/api/health" >/dev/null 2>&1; then
    log "WARN health down — attempting stack start"
    bash "$ROOT/scripts/run_e2e_stack.sh" start >>"$LOG" 2>&1 || true
    sleep 10
  fi
}

run_cycle() {
  CYCLE=$((CYCLE + 1))
  log "=== CYCLE $CYCLE START ==="
  load_env
  ensure_stack

  log "API feature matrix"
  node "$ROOT/scripts/verify_live_feature_matrix.mjs" >>"$LOG" 2>&1 || log "WARN API matrix failed"

  log "Findings + verify audit"
  node "$ROOT/scripts/overnight_supreme_audit.mjs" >>"$LOG" 2>&1 || log "WARN findings audit failed"

  log "UI crawl (Playwright)"
  (cd "$ROOT/frontend" && PLAYWRIGHT_LIVE=1 PLAYWRIGHT_UI_DEV=1 npm run test:e2e -- live-ui-crawl.spec.ts --reporter=line) \
    >> /tmp/weissman-overnight-ui-crawl.log 2>&1 || log "WARN UI crawl had failures — see /tmp/weissman-overnight-ui-crawl.log"

  log "Engine reality audit (static)"
  node "$ROOT/scripts/engine_reality_audit.mjs" >>"$LOG" 2>&1 || log "WARN engine reality audit"

  log "=== CYCLE $CYCLE DONE ==="
}

log "Overnight orchestrator started (pid $$)"
while true; do
  run_cycle
  log "Sleeping 45 minutes before next cycle"
  sleep 2700
done
