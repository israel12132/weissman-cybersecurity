#!/usr/bin/env bash
# Generate auditor Evidence Pack (JSON + PDF): wiring, SBOM, security signatures, NIST/SOC2 mapping.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${WEISSMAN_EVIDENCE_OUT:-$ROOT/evidence-pack/$STAMP}"
mkdir -p "$OUT_DIR"

log() { echo "== $*"; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

run_audit() {
  local name="$1"
  shift
  local logfile="$OUT_DIR/audit-${name}.log"
  if "$@" >"$logfile" 2>&1; then
    echo "PASS"
  else
    echo "FAIL"
  fi
}

log "Engine wiring audit"
WIRING_STATUS="$(run_audit wiring node scripts/verify_engine_wiring.mjs)"
REALITY_STATUS="$(run_audit reality node scripts/engine_reality_audit.mjs)"
UI_STATUS="$(run_audit ui node scripts/weissman-ui-audit.mjs)"
SCAN_WIRING_STATUS="$(run_audit scan-wiring node scripts/verify_engine_scan_wiring.mjs)"

log "SBOM collection"
# Track SBOM provenance so a lockfile stub is never disguised as the real
# trivy-generated CycloneDX document. The stub keeps its own filename.
SBOM_PATH="$ROOT/sbom-cyclonedx.json"
SBOM_SOURCE="none"
if [[ -f "$SBOM_PATH" ]]; then
  SBOM_SOURCE="prebuilt"
elif command -v trivy >/dev/null 2>&1; then
  if trivy fs --format cyclonedx --output "$SBOM_PATH" "$ROOT"; then
    SBOM_SOURCE="trivy"
  fi
fi
if [[ ! -f "$SBOM_PATH" ]] && [[ -f "$ROOT/frontend/package-lock.json" ]]; then
  log "Fallback npm SBOM stub from lockfile hash (NOT a real SBOM)"
  SBOM_PATH="$OUT_DIR/sbom-stub.json"
  SBOM_SOURCE="lockfile-stub"
  node -e "
    const fs=require('fs');
    const lock=fs.readFileSync('frontend/package-lock.json','utf8');
    fs.writeFileSync('$SBOM_PATH', JSON.stringify({
      bomFormat:'CycloneDX', specVersion:'1.5',
      metadata:{ component:{ name:'weissman-frontend-lockfile-stub' }},
      components:[{ type:'library', name:'npm-lockfile', version: lock.slice(0,64) }]
    }, null, 2));
  "
fi

SBOM_SHA=""
COMPONENT_COUNT=0
SBOM_OUT_NAME=""
if [[ -f "$SBOM_PATH" ]]; then
  SBOM_SHA="$(sha256_file "$SBOM_PATH")"
  if [[ "$SBOM_SOURCE" == "lockfile-stub" ]]; then
    # Keep the stub under its own name — never copy it to sbom-cyclonedx.json,
    # which reads as a genuine SBOM to an auditor.
    SBOM_OUT_NAME="sbom-stub.json"
  else
    SBOM_OUT_NAME="sbom-cyclonedx.json"
    cp "$SBOM_PATH" "$OUT_DIR/$SBOM_OUT_NAME"
  fi
  COMPONENT_COUNT="$(node -e "
    const j=JSON.parse(require('fs').readFileSync('$OUT_DIR/$SBOM_OUT_NAME','utf8'));
    console.log((j.components||[]).length);
  ")"
fi

log "Security signatures"
GIT_COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_BRANCH="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
CARGO_LOCK_SHA=""
PKG_LOCK_SHA=""
[[ -f "$ROOT/Cargo.lock" ]] && CARGO_LOCK_SHA="$(sha256_file "$ROOT/Cargo.lock")"
[[ -f "$ROOT/frontend/package-lock.json" ]] && PKG_LOCK_SHA="$(sha256_file "$ROOT/frontend/package-lock.json")"

log "Compliance mapping (NIST CSF / SOC2)"
COMPLIANCE_JSON="$OUT_DIR/compliance-api.json"
# Default is 'unavailable' (backend not reachable / no live pack) — never a
# fabricated static catalog. A 409 from the unified gate becomes 'blocked'.
COMPLIANCE_SOURCE="unavailable"
COMPLIANCE_FAIL=0
BASE="${WEISSMAN_E2E_BASE:-http://127.0.0.1:8000}"
EMAIL="${WEISSMAN_ADMIN_EMAIL:-admin@localhost}"
PASSWORD="${WEISSMAN_ADMIN_PASSWORD:-}"

if [[ -n "$PASSWORD" ]] && curl -sf "${BASE}/api/health" >/dev/null 2>&1; then
  TOKEN="$(node -e "
    fetch('${BASE}/api/login', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ email:'${EMAIL}', password:process.env.PW, tenant_slug:'${WEISSMAN_E2E_TENANT:-default}' })
    }).then(r=>r.json()).then(d=>process.stdout.write(d.access_token||d.token||'')).catch(()=>process.exit(0));
  " PW="$PASSWORD" 2>/dev/null || true)"
  if [[ -n "${TOKEN:-}" ]]; then
    CLIENT_ID="$(curl -sf -H "Authorization: Bearer $TOKEN" "${BASE}/api/clients" | node -e "
      let d=''; process.stdin.on('data',c=>d+=c); process.stdin.on('end',()=>{
        try {
          const arr=JSON.parse(d);
          const c=(Array.isArray(arr)?arr:[])[0];
          process.stdout.write(String(c?.id||''));
        } catch { process.stdout.write(''); }
      });
    ")"
    if [[ -n "$CLIENT_ID" ]]; then
      # Capture the status code — `curl -f` collapses a 409 gate BLOCK into the
      # same exit as "no backend". 200 → live-api; 409 → the unified compliance
      # gate is screaming (inconsistent_control_mappings) and the pack must FAIL;
      # anything else → unavailable.
      HTTP_CODE="$(curl -sS -H "Authorization: Bearer $TOKEN" "${BASE}/api/compliance/evidence-pack/${CLIENT_ID}" -o "$COMPLIANCE_JSON" -w '%{http_code}' 2>/dev/null || echo 000)"
      case "$HTTP_CODE" in
        200) COMPLIANCE_SOURCE="live-api" ;;
        409) COMPLIANCE_SOURCE="blocked"; COMPLIANCE_FAIL=1 ;;
        *)   COMPLIANCE_SOURCE="unavailable" ;;
      esac
    fi
  fi
fi

MANIFEST="$OUT_DIR/evidence-pack.json"
node - <<NODE
const fs = require('fs');
const path = require('path');

// No fabricated static catalog: the previous complianceStatic block asserted
// controls_mapped counts (108/64/93) that exist nowhere in the code or DB and
// would be printed verbatim into a customer-facing PDF. Compliance is now taken
// ONLY from a live 200 response; otherwise it is null with an explicit source.
const complianceSource = '$COMPLIANCE_SOURCE';
let liveCompliance = null;
const apiPath = '$COMPLIANCE_JSON';
if (complianceSource === 'live-api' && fs.existsSync(apiPath) && fs.statSync(apiPath).size > 10) {
  try { liveCompliance = JSON.parse(fs.readFileSync(apiPath, 'utf8')); } catch {}
}

const manifest = {
  packet_type: 'weissman-audit-evidence-pack-v1',
  generated_at: new Date().toISOString(),
  provenance: {
    git_commit: '$GIT_COMMIT',
    git_branch: '$GIT_BRANCH',
    generator: 'scripts/generate_audit_evidence_pack.sh',
  },
  wiring_audits: [
    { name: 'verify_engine_wiring', status: '$WIRING_STATUS' },
    { name: 'engine_reality_audit', status: '$REALITY_STATUS' },
    { name: 'weissman_ui_audit', status: '$UI_STATUS' },
    { name: 'verify_engine_scan_wiring', status: '$SCAN_WIRING_STATUS' },
  ],
  security_signatures: {
    cargo_lock_sha256: '$CARGO_LOCK_SHA',
    package_lock_sha256: '$PKG_LOCK_SHA',
    sbom_sha256: '$SBOM_SHA',
  },
  sbom: {
    path: '$SBOM_OUT_NAME',
    sha256: '$SBOM_SHA',
    component_count: Number('$COMPONENT_COUNT') || 0,
    source: '$SBOM_SOURCE',
  },
  compliance: liveCompliance,
  compliance_source: complianceSource,
  notes: 'Verify SHA256 hashes against CI artifacts and git commit.',
};

fs.writeFileSync('$MANIFEST', JSON.stringify(manifest, null, 2));
NODE

log "Render PDF"
node scripts/render_evidence_pack_pdf.mjs "$MANIFEST" "$OUT_DIR/evidence-pack.pdf"

FAIL=0
for s in "$WIRING_STATUS" "$REALITY_STATUS" "$UI_STATUS" "$SCAN_WIRING_STATUS"; do
  [[ "$s" == "PASS" ]] || FAIL=1
done
[[ -f "$OUT_DIR/evidence-pack.json" ]] || FAIL=1
[[ -f "$OUT_DIR/evidence-pack.pdf" ]] || FAIL=1
[[ -n "$SBOM_SHA" ]] || FAIL=1
# A 409 from the unified compliance gate is a real BLOCK, not a missing backend —
# never emit an "OK" pack over it.
[[ "$COMPLIANCE_FAIL" -eq 0 ]] || { echo "Compliance gate returned 409 (blocked) — pack is not audit-ready" >&2; FAIL=1; }
# For a pack intended for external delivery (WEISSMAN_EVIDENCE_STRICT=1), refuse a
# lockfile-stub SBOM and an unavailable/blocked compliance source. Offline dev
# runs (strict unset) still succeed so the local gates keep working.
if [[ "${WEISSMAN_EVIDENCE_STRICT:-0}" == "1" ]]; then
  [[ "$SBOM_SOURCE" != "lockfile-stub" ]] || { echo "SBOM is a lockfile stub — not acceptable for external delivery" >&2; FAIL=1; }
  [[ "$COMPLIANCE_SOURCE" == "live-api" ]] || { echo "Compliance source is '$COMPLIANCE_SOURCE' — external delivery requires live-api" >&2; FAIL=1; }
fi

if [[ "$FAIL" -ne 0 ]]; then
  echo "Evidence pack generation FAILED — see $OUT_DIR" >&2
  exit 1
fi

echo "Evidence pack OK → $OUT_DIR"
echo "  JSON: $OUT_DIR/evidence-pack.json"
echo "  PDF:  $OUT_DIR/evidence-pack.pdf"
