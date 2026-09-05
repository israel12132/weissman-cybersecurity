#!/usr/bin/env bash
# Contract test: every alert rule must route to a receiver that actually delivers.
#
# WHY THIS EXISTS
# CI proves the alert RULES fire (promtool test rules) and go_live_check.sh proves
# the delivery SECRETS are real before go-live. Nothing checked the piece between
# them: alertmanager.yml itself was never validated by anything. Its top-level
# route falls through to the `default` receiver, which has no delivery config at
# all — so a rule labelled `severity: page` instead of `critical`, or a renamed
# receiver, produces an alert that fires correctly, routes silently to a no-op,
# and pages nobody. That is the same shape as the four-day outage that motivated
# the alert-rules job.
#
# Checks:
#   1. alertmanager.yml parses (amtool check-config), including templates.
#   2. Every severity that appears on a real alert rule resolves to a receiver
#      other than the no-op `default`.
#   3. The Watchdog dead-man's switch reaches the heartbeat receiver.
#
#   ./scripts/verify_alert_delivery_routes.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${ROOT}/monitoring/alertmanager.yml"
RULES_DIR="${ROOT}/monitoring/alerts"
NOOP_RECEIVER="default"

if ! command -v amtool >/dev/null 2>&1; then
  echo "error: amtool not found (install from the prometheus/alertmanager release)" >&2
  exit 2
fi

echo "1. Alertmanager config syntax"
amtool check-config "$CONFIG"

echo
echo "2. Severity routing"
# Severities carried by actual alert rules. `none` belongs to Watchdog, which is
# routed by alertname rather than severity and is asserted separately below.
mapfile -t SEVERITIES < <(
  grep -rhoE "severity: ['\"]?[a-z]+" "$RULES_DIR"/*.yml \
    | sed -E "s/severity: ['\"]?//" \
    | sort -u \
    | grep -v '^none$'
)

if [[ ${#SEVERITIES[@]} -eq 0 ]]; then
  echo "error: no severity labels found under $RULES_DIR — rules missing?" >&2
  exit 1
fi

fail=0
for sev in "${SEVERITIES[@]}"; do
  receiver="$(amtool config routes test --config.file="$CONFIG" "severity=$sev" | tr -d '[:space:]')"
  if [[ -z "$receiver" || "$receiver" == "$NOOP_RECEIVER" ]]; then
    echo "  FAIL severity=$sev -> '${receiver:-<none>}' (no delivery configured)" >&2
    fail=1
  else
    echo "  OK   severity=$sev -> $receiver"
  fi
done

echo
echo "3. Watchdog dead-man's switch"
watchdog="$(amtool config routes test --config.file="$CONFIG" alertname=Watchdog severity=none | tr -d '[:space:]')"
if [[ "$watchdog" != "watchdog-heartbeat" ]]; then
  echo "  FAIL Watchdog -> '${watchdog:-<none>}' (expected watchdog-heartbeat)" >&2
  echo "       The absence of this ping is the only signal that the whole alert path is alive." >&2
  fail=1
else
  echo "  OK   Watchdog -> $watchdog"
fi

if [[ $fail -ne 0 ]]; then
  echo
  echo "Alert delivery route contract FAILED — an alert would fire and reach nobody." >&2
  exit 1
fi

echo
echo "Alert delivery route contract OK: ${#SEVERITIES[@]} severities + Watchdog all reach a delivering receiver"
