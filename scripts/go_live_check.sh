#!/usr/bin/env bash
# Go-live readiness — everything verifiable without production secrets.
# Usage:
#   ./scripts/go_live_check.sh
#   ./scripts/go_live_check.sh --live https://staging.example.com
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LIVE_URL=""
if [[ "${1:-}" == "--live" && -n "${2:-}" ]]; then
  LIVE_URL="${2%/}"
fi

pass=0
fail=0
warn=0

ok() { echo "PASS: $1"; pass=$((pass + 1)); }
bad() { echo "FAIL: $1"; fail=$((fail + 1)); }
note() { echo "WARN: $1"; warn=$((warn + 1)); }

section() { echo ""; echo "== $1 =="; }

section "Delivery prep"
./scripts/prepare_company_delivery.sh >/dev/null && ok "prepare_company_delivery" || bad "prepare_company_delivery"

section "Legal & sales artifacts"
for f in \
  deploy/public/terms.html \
  deploy/public/terms-he.html \
  deploy/public/privacy.html \
  deploy/public/privacy-he.html \
  deploy/public/dpa.html \
  deploy/public/subprocessors.html \
  docs/legal/MSA-ORDER-FORM-OUTLINE-he.md \
  docs/sales/viewer/index.html \
  docs/sales/COMPANY-READINESS-he.md \
  docs/operations/INCIDENT-ONCALL-RUNBOOK-he.md \
  docs/sales/WEEK-1-GOLIVE-he.md
do
  [[ -f "$f" ]] && ok "exists $f" || bad "missing $f"
done

section "Staging config"
[[ -f docker-compose.staging.yml ]] && ok "docker-compose.staging.yml" || bad "staging compose"
[[ -f deploy/env.staging.example ]] && ok "env.staging.example" || bad "env staging"
[[ -f deploy/go-live/paddle-price-ids.sql.example ]] && ok "paddle SQL example" || bad "paddle sql"

section "Secrets hygiene (local .env)"
if [[ -f .env ]]; then
  if grep -qE '^(WEISSMAN_JWT_SECRET|WEISSMAN_ADMIN_PASSWORD)=$' .env 2>/dev/null; then
    note ".env has empty JWT or admin password"
  else
    ok ".env secrets non-empty (if file exists)"
  fi
else
  note "no .env — copy from PRODUCTION.env.template before deploy"
fi

if git remote get-url origin 2>/dev/null | grep -qE 'ghp_|github_pat_|x-access-token'; then
  note "git remote origin contains embedded token — rotate & use SSH (see docs/operations/GIT-CREDENTIALS-SECURITY.md)"
else
  ok "git remote has no obvious embedded token"
fi

section "Build smoke"
if command -v cargo >/dev/null 2>&1; then
  cargo check -p weissman-server -q && ok "cargo check server" || bad "cargo check"
fi

section "Live staging (optional)"
if [[ -n "$LIVE_URL" ]]; then
  ./scripts/staging-qa.sh --live "$LIVE_URL" && ok "staging-qa live" || bad "staging-qa live"
  curl -sf "${LIVE_URL}/terms-he.html" >/dev/null && ok "terms-he served" || bad "terms-he"
  curl -sf "${LIVE_URL}/api/health" >/dev/null && ok "health" || bad "health"
else
  note "skip live checks — run: $0 --live https://your-staging-host"
fi

echo ""
echo "────────────────────────────"
echo "Go-live check: $pass passed, $fail failed, $warn warnings"
[[ "$fail" -eq 0 ]] || exit 1
echo "All automated go-live checks passed."
