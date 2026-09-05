#!/usr/bin/env bash
# One-shot: regenerate sales book + run automated company-readiness QA.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== Weissman company delivery prep =="
node scripts/generate_engine_requirements.mjs
node scripts/generate_platform_encyclopedia.mjs
./scripts/staging-qa.sh
node scripts/generate_engine_target_contract.mjs --check >/dev/null
node scripts/verify_engine_wiring.mjs >/dev/null
node scripts/weissman-ui-audit.mjs >/dev/null

echo ""
echo "OK — product book: docs/sales/viewer/index.html"
echo "OK — readiness:    docs/sales/COMPANY-READINESS-he.md"
echo ""
echo "Next: ./scripts/go_live_check.sh"
echo "Week 1: docs/sales/WEEK-1-GOLIVE-he.md"
