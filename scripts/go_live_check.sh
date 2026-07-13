#!/usr/bin/env bash
# Go-live readiness — production infra, secrets contract, migrations, agents, OT engines.
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

section "Staging & TLS contract"
[[ -f docker-compose.staging.yml ]] && ok "docker-compose.staging.yml" || bad "staging compose"
[[ -f deploy/env.staging.example ]] && ok "env.staging.example" || bad "env staging"
[[ -f deploy/Caddyfile.staging ]] && ok "Caddyfile.staging" || bad "Caddyfile.staging"
if grep -q 'WEISSMAN_COOKIE_SECURE: "1"' docker-compose.staging.yml; then
  ok "staging compose enforces COOKIE_SECURE=1"
else
  bad "staging compose missing COOKIE_SECURE=1"
fi
if grep -q 'WEISSMAN_COOKIE_SECURE=1' deploy/env.staging.example; then
  ok "env.staging.example COOKIE_SECURE=1"
else
  bad "env.staging.example missing COOKIE_SECURE=1"
fi
[[ -f deploy/go-live/paddle-price-ids.sql.example ]] && ok "paddle SQL example" || bad "paddle sql"

section "Kubernetes manifests"
if ./scripts/k8s-kind-smoke.sh >/dev/null 2>&1; then
  ok "k8s manifest smoke"
else
  bad "k8s manifest smoke"
fi
for key in destructive_confirm_secret job_orchestrator_secret metrics_token; do
  if grep -q "$key:" deploy/k8s/secret.example.yaml; then
    ok "k8s secret template: $key"
  else
    bad "k8s secret template missing $key"
  fi
done
[[ -f deploy/k8s/worker-hpa.yaml ]] && ok "worker HPA manifest" || bad "worker HPA"
[[ -f deploy/k8s/network-policies.yaml ]] && ok "network policies manifest" || bad "network policies"

section "Production secrets contract"
for var in WEISSMAN_JWT_SECRET WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET WEISSMAN_JOB_ORCHESTRATOR_SECRET WEISSMAN_METRICS_TOKEN; do
  if grep -q "^${var}=" PRODUCTION.env.template; then
    ok "PRODUCTION.env.template lists $var"
  else
    bad "PRODUCTION.env.template missing $var"
  fi
done

section "Database migrations"
if [[ -d crates/weissman-db/migrations ]] && ls crates/weissman-db/migrations/*.sql >/dev/null 2>&1; then
  ok "weissman-db migrations present ($(ls crates/weissman-db/migrations/*.sql | wc -l | tr -d ' ') files)"
else
  bad "weissman-db migrations missing"
fi
if [[ -d fingerprint_engine/migrations ]] && ls fingerprint_engine/migrations/*.sql >/dev/null 2>&1; then
  ok "fingerprint_engine migrations present"
else
  bad "fingerprint_engine migrations missing"
fi

section "Agent binary wiring"
if ./scripts/verify_docker_build_integrity.sh >/dev/null 2>&1; then
  ok "docker build integrity (agent COPY in Dockerfile)"
else
  bad "docker build integrity"
fi
if grep -q 'WEISSMAN_AGENT_BIN_DIR' deploy/backend.Dockerfile docker-compose.staging.yml; then
  ok "WEISSMAN_AGENT_BIN_DIR configured"
else
  bad "WEISSMAN_AGENT_BIN_DIR not configured"
fi

section "Critical OT engines (8)"
OT_EXPECTED=(
  avionics_adsb_attack
  maritime_ais_attack
  ev_charging_ocpp_attack
  smart_grid_dlms_attack
  rail_signaling_attack
  building_automation_attack
  robotics_ros2_attack
  ot_sis_triton_attack
)
OT_FILE="fingerprint_engine/src/critical_infra/mod.rs"
for id in "${OT_EXPECTED[@]}"; do
  if grep -q "\"$id\"" "$OT_FILE"; then
    ok "OT engine registered: $id"
  else
    bad "OT engine missing: $id"
  fi
done

section "Monitoring (Prometheus + Grafana)"
if grep -q 'credentials_file: /etc/prometheus/metrics_token' monitoring/prometheus.yml \
  && grep -q 'type: Bearer' monitoring/prometheus.yml; then
  ok "prometheus Bearer auth enabled"
else
  bad "prometheus Bearer auth not configured"
fi
[[ -f monitoring/grafana/dashboards/soar-verification.json ]] && ok "Grafana SOAR dashboard" || bad "Grafana SOAR dashboard"
[[ -f monitoring/grafana/dashboards/agent-fleet-health.json ]] && ok "Grafana Agent dashboard" || bad "Grafana Agent dashboard"
[[ -f monitoring/grafana/provisioning/dashboards/dashboards.yml ]] && ok "Grafana dashboard provisioning" || bad "Grafana provisioning"

section "Disaster recovery (PITR + RTO/RPO)"
[[ -f docs/operations/DISASTER-RECOVERY.md ]] && ok "DR runbook" || bad "DR runbook"
if grep -qi 'RPO' docs/operations/DISASTER-RECOVERY.md && grep -qi 'RTO' docs/operations/DISASTER-RECOVERY.md; then
  ok "DR doc documents RTO/RPO"
else
  bad "DR doc missing RTO/RPO"
fi
[[ -x scripts/backup_pitr_setup.sh ]] && ok "PITR setup script" || bad "PITR setup script"
[[ -x scripts/backup_restore_verify.sh ]] && ok "PITR restore-verify script" || bad "PITR restore-verify script (recoverability unproven)"
# Existence of a backup is not recoverability — require a recent successful restore drill.
RV_MARKER="${WEISSMAN_PITR_BASE_DIR:-/var/backups/weissman/base}/.last_restore_verify_ok"
if [[ -f "$RV_MARKER" ]]; then
  RV_TS="$(cat "$RV_MARKER" 2>/dev/null || echo 0)"
  RV_AGE=$(( $(date -u +%s) - ${RV_TS:-0} ))
  if [[ "$RV_AGE" -lt 172800 ]]; then
    ok "restore verified within 48h ($((RV_AGE/3600))h ago)"
  else
    bad "last restore-verify is stale ($((RV_AGE/86400))d ago) — run scripts/backup_restore_verify.sh"
  fi
else
  note "no restore-verify marker yet — run scripts/backup_restore_verify.sh nightly"
fi

section "Secrets hygiene (local .env)"
if [[ -f .env ]]; then
  if grep -qE '^(WEISSMAN_JWT_SECRET|WEISSMAN_ADMIN_PASSWORD)=$' .env 2>/dev/null; then
    note ".env has empty JWT or admin password"
  else
    ok ".env secrets non-empty (if file exists)"
  fi
  if grep -q '^WEISSMAN_COOKIE_SECURE=1' .env 2>/dev/null && grep -q '^WEISSMAN_PUBLIC_BASE_URL=http://' .env 2>/dev/null; then
    note "COOKIE_SECURE=1 with HTTP PUBLIC_BASE_URL — use https:// or staging-tls profile"
  fi
else
  note "no .env — copy from PRODUCTION.env.template before deploy"
fi

if git remote get-url origin 2>/dev/null | grep -qE 'ghp_|github_pat_|x-access-token'; then
  note "git remote origin contains embedded token — rotate & use SSH"
else
  ok "git remote has no obvious embedded token"
fi

section "Build smoke"
if command -v cargo >/dev/null 2>&1; then
  cargo check -p weissman-server -q && ok "cargo check server" || bad "cargo check"
fi

section "Live staging (optional)"
if [[ -n "$LIVE_URL" ]]; then
  if [[ "$LIVE_URL" == http://* ]] && grep -q 'WEISSMAN_COOKIE_SECURE=1' deploy/env.staging.example 2>/dev/null; then
    note "live URL is HTTP but staging requires Secure cookies — use https://"
  fi
  ./scripts/staging-qa.sh --live "$LIVE_URL" && ok "staging-qa live" || bad "staging-qa live"
  curl -sf "${LIVE_URL}/terms-he.html" >/dev/null && ok "terms-he served" || bad "terms-he"
  curl -sf "${LIVE_URL}/api/health" >/dev/null && ok "health" || bad "health"
  code="$(curl -s -o /dev/null -w '%{http_code}' "${LIVE_URL}/api/metrics" || true)"
  if [[ "$code" == "401" ]]; then
    ok "metrics endpoint requires auth (401 without token)"
  else
    note "metrics returned HTTP $code (expected 401 without Bearer when token configured)"
  fi
else
  note "skip live checks — run: $0 --live https://your-staging-host"
fi

echo ""
echo "────────────────────────────"
echo "Go-live check: $pass passed, $fail failed, $warn warnings"
[[ "$fail" -eq 0 ]] || exit 1
echo "All automated go-live checks passed (100%)."
