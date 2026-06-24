#!/usr/bin/env bash
# One-shot: regenerate sales book + run automated company-readiness QA.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== Weissman company delivery prep =="
node scripts/generate_platform_encyclopedia.mjs
./scripts/staging-qa.sh
node scripts/verify_engine_wiring.mjs >/dev/null
node scripts/weissman-ui-audit.mjs >/dev/null

echo ""
echo "OK — product book: docs/sales/viewer/index.html"
echo "OK — readiness:    docs/sales/COMPANY-READINESS-he.md"
echo "OK — legal outline: docs/legal/MSA-ORDER-FORM-OUTLINE-he.md"
