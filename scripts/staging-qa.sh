#!/usr/bin/env bash
# Staging QA — offline code audits + optional live smoke (6 static audits +
# cargo check + 1 unit-test file + up to 5 live HTTP probes). The summary below
# prints the actual pass/fail totals for the checks that ran.
# Usage:
#   ./scripts/staging-qa.sh
#   ./scripts/staging-qa.sh --live http://localhost
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LIVE_URL=""
if [[ "${1:-}" == "--live" && -n "${2:-}" ]]; then
  LIVE_URL="${2%/}"
fi

pass=0
fail=0
run() {
  local name="$1"
  shift
  echo ""
  echo "== $name =="
  if "$@"; then
    echo "PASS: $name"
    pass=$((pass + 1))
  else
    echo "FAIL: $name"
    fail=$((fail + 1))
  fi
}

run "engine wiring" node scripts/verify_engine_wiring.mjs
run "engine reality" node scripts/engine_reality_audit.mjs
run "UI audit" node scripts/weissman-ui-audit.mjs
run "command center coverage" node scripts/verify_command_center_coverage.mjs

if command -v cargo >/dev/null 2>&1; then
  run "cargo check server" cargo check -p weissman-server -q
else
  echo "SKIP: cargo not installed"
fi

if [[ -d frontend/node_modules ]] || [[ -f frontend/package-lock.json ]]; then
  run "frontend routeEngineId tests" bash -c 'cd frontend && npm test -- --run src/lib/routeEngineId.test.js'
else
  echo "SKIP: run npm ci in frontend first"
fi

if [[ -n "$LIVE_URL" ]]; then
  run "health" curl -sf "${LIVE_URL}/api/health"
  run "command center" curl -sf "${LIVE_URL}/command-center/"
  run "capabilities" bash -c "curl -sf '${LIVE_URL}/api/engines/capabilities' | head -c 200 >/dev/null"
  run "agent install script" bash -c "curl -sf '${LIVE_URL}/install/agent.sh' | head -c 100 >/dev/null"
  run "terms-he UTF-8" bash -c "curl -sf '${LIVE_URL}/terms-he.html' | grep -q 'תנאי שימוש'"
fi

echo ""
echo "────────────────────────────"
echo "QA summary: $pass passed, $fail failed"
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
echo "All automated QA checks passed."
