#!/usr/bin/env bash
# Live-verify the 7 actionable critical findings + GCS object hashes + executive PDF.
# Usage: ./scripts/generate_executive_critical_verification.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

BASE="${WEISSMAN_E2E_BASE:-http://127.0.0.1:8000}"
EMAIL="${WEISSMAN_ADMIN_EMAIL:-admin@localhost}"
PASSWORD="${WEISSMAN_ADMIN_PASSWORD:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${WEISSMAN_EXEC_REPORT_OUT:-$ROOT/evidence-pack/executive-critical-$STAMP}"
mkdir -p "$OUT_DIR/artifacts"

log() { echo "== $*"; }

CRITICAL_IDS=(7442 7446 7451 7452 7793 7840 10660)
CRITICAL_IDS_CSV="$(IFS=,; echo "${CRITICAL_IDS[*]}")"

log "Login"
if [[ -z "$PASSWORD" ]]; then
  echo "WEISSMAN_ADMIN_PASSWORD required" >&2
  exit 1
fi
TOKEN="$(curl -sf -X POST "$BASE/api/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{console.log(JSON.parse(d).access_token||'')}catch{}})")"
if [[ -z "$TOKEN" ]]; then
  echo "Login failed" >&2
  exit 1
fi

log "Fetch exec KPIs"
curl -sf "$BASE/api/dashboard/exec-kpis" -H "Authorization: Bearer $TOKEN" -o "$OUT_DIR/exec-kpis.json"

log "Platform live verify (POST /api/findings/:id/verify)"
WEISSMAN_BASE="$BASE" WEISSMAN_TOKEN="$TOKEN" OUT_FILE="$OUT_DIR/platform-verify.json" \
  CRITICAL_IDS="$CRITICAL_IDS_CSV" node "$ROOT/scripts/lib/executive_platform_verify.mjs"

log "External GCS bucket verification + object hashes"
ARTIFACT_DIR="$OUT_DIR/artifacts" OUT_FILE="$OUT_DIR/gcs-live-verify.json" \
  node "$ROOT/scripts/lib/executive_gcs_verify.mjs"

log "AD CS + DNS external probes"
OUT_FILE="$OUT_DIR/adcs-dns-verify.json" node "$ROOT/scripts/lib/executive_adcs_dns_verify.mjs"

log "Assemble executive manifest"
MANIFEST="$(OUT_DIR="$OUT_DIR" node "$ROOT/scripts/lib/executive_manifest.mjs")"

log "Render executive PDF"
node scripts/render_executive_critical_pdf.mjs "$MANIFEST" "$OUT_DIR/executive-critical-report.pdf"

echo ""
echo "Executive verification pack OK → $OUT_DIR"
echo "  Manifest: $MANIFEST"
echo "  PDF:      $OUT_DIR/executive-critical-report.pdf"
echo "  GCS artifacts: $OUT_DIR/artifacts/"
