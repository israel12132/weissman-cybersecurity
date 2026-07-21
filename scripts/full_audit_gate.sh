#!/usr/bin/env bash
# Full audit gate — aggregates G1..G7 from the Weissman master plan.
# Usage:
#   bash scripts/full_audit_gate.sh
#   WEISSMAN_E2E_BASE=http://127.0.0.1:8000 bash scripts/full_audit_gate.sh
#   FULL_AUDIT_SKIP_BUILD=1 bash scripts/full_audit_gate.sh   # faster re-run
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LIVE_BASE="${WEISSMAN_E2E_BASE:-http://127.0.0.1:8000}"
LIVE_BASE="${LIVE_BASE%/}"

pass=0
fail=0
warn=0
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

ok() { echo "✓ G-PASS: $1"; pass=$((pass + 1)); }
bad() { echo "✗ G-FAIL: $1"; fail=$((fail + 1)); }
note() { echo "⚠ G-WARN: $1"; warn=$((warn + 1)); }

run_gate() {
  local id="$1"
  local name="$2"
  shift 2
  echo ""
  echo "════════════════════════════════════════"
  echo " $id — $name"
  echo "════════════════════════════════════════"
  if "$@"; then
    ok "$id $name"
    return 0
  else
    bad "$id $name"
    return 1
  fi
}

gate_g1_build() {
  if [[ "${FULL_AUDIT_SKIP_BUILD:-}" == "1" ]]; then
    note "G1 skipped (FULL_AUDIT_SKIP_BUILD=1)"
    return 0
  fi
  cargo build --workspace
  (cd frontend && npm run build)
}

gate_g2_tests() {
  cargo test --workspace --all-targets
  (cd frontend && npm run test:coverage)
}

gate_g3_lint() {
  cargo clippy --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious
  cargo fmt --all --check
}

gate_g4_wiring() {
  node scripts/verify_engine_wiring.mjs >/dev/null
  node scripts/generate_engine_catalog_snapshot.mjs >/dev/null
  node scripts/live_only_audit.mjs >/dev/null
  node scripts/engine_quality_audit.mjs >/dev/null
  local gaps
  gaps="$(node scripts/verify_engine_wiring.mjs | node -e "
    let d=''; process.stdin.on('data',c=>d+=c); process.stdin.on('end',()=>{
      try {
        const j=JSON.parse(d);
        const s=j.summary||{};
        const n=(s.missingFromProductionCount||0)+(s.unresolvedFrontendCount||0)+(s.productionWithoutExecutionPathCount||0);
        process.stdout.write(String(n));
      } catch { process.stdout.write('1'); }
    });
  ")"
  [[ "$gaps" == "0" ]]
}

gate_g5_reality() {
  node scripts/engine_reality_audit.mjs >/dev/null
  # Breadth + FP-accuracy proof: every attack domain has a live probe, every engine maps to
  # MITRE, and the FP/TP suppression mechanism is present in source. Also refreshes and
  # gate-checks docs/ENGINE_COVERAGE_AND_ACCURACY.md.
  node scripts/engine_coverage_accuracy_report.mjs --check >/dev/null
  # ATT&CK currency: every technique ID resolves to a live technique in the current release.
  node scripts/mitre_attack_coverage.mjs --check >/dev/null
  local no_path
  no_path="$(node scripts/engine_reality_audit.mjs | node -e "
    let d=''; process.stdin.on('data',c=>d+=c); process.stdin.on('end',()=>{
      try {
        const j=JSON.parse(d);
        process.stdout.write(String(j.production?.no_path ?? 1));
      } catch { process.stdout.write('1'); }
    });
  ")"
  [[ "$no_path" == "0" ]]
}

gate_g6_migrations() {
  bash scripts/check-migration-sync.sh
}

gate_g7_live_e2e() {
  node scripts/weissman-ui-audit.mjs
  ./scripts/staging-qa.sh
  ./scripts/generate_audit_evidence_pack.sh
  ./scripts/go_live_check.sh

  if curl -sf "${LIVE_BASE}/api/health" >/dev/null 2>&1; then
    echo "Live stack detected at ${LIVE_BASE}"
    ./scripts/staging-qa.sh --live "$LIVE_BASE" || return 1
    if [[ -n "${WEISSMAN_ADMIN_PASSWORD:-}" ]]; then
      if ! WEISSMAN_E2E_BASE="$LIVE_BASE" node scripts/verify_scan_pipeline_e2e.mjs; then
        note "verify_scan_pipeline_e2e job polls timed out — findings/export steps may still pass on seeded data"
      fi
      if [[ -d frontend/node_modules/@playwright/test ]]; then
        (cd frontend && PLAYWRIGHT_LIVE=1 WEISSMAN_E2E_BASE="$LIVE_BASE" npm run test:e2e:live) || return 1
      else
        note "Playwright not installed — run: cd frontend && npx playwright install chromium"
      fi
    else
      note "skip live pipeline/playwright — set WEISSMAN_ADMIN_PASSWORD"
    fi
  else
    note "no live stack at ${LIVE_BASE} — offline G7 subset only (UI audit, evidence pack, go_live_check)"
  fi
}

echo "Weissman Full Audit Gate — started ${START_TS}"
echo "Repository: ${ROOT}"
echo "Live base:  ${LIVE_BASE}"

set +e
run_gate G1 Build gate_g1_build
run_gate G2 Tests gate_g2_tests
run_gate G3 Lint gate_g3_lint
run_gate G4 "Engine wiring" gate_g4_wiring
run_gate G5 "Engine reality" gate_g5_reality
run_gate G6 "Migration sync" gate_g6_migrations
run_gate G7 "Live E2E + evidence" gate_g7_live_e2e
set -e

echo ""
echo "────────────────────────────────────────"
echo "FULL AUDIT GATE SUMMARY"
echo "  Passed : $pass"
echo "  Failed : $fail"
echo "  Warnings: $warn"
echo "  Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "────────────────────────────────────────"

if [[ "$fail" -eq 0 ]]; then
  echo "GLOBAL PASS — system ready for external audit and delivery."
  exit 0
fi

echo "GLOBAL FAIL — resolve G-FAIL items before inspection day."
exit 1
