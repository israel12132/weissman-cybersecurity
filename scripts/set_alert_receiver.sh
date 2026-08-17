#!/usr/bin/env bash
# Set an Alertmanager receiver secret AND prove an alert actually reaches it.
#
# The stack shipped with all three receivers — including the Watchdog dead-man's-switch whose only
# job is to notice a broken alert pipeline — pointing at RFC-2606 `.invalid` hosts. Alerts fired,
# went nowhere, and nothing noticed for four days. Configuring a receiver is therefore not the
# finish line; delivering through it is. This script does both and refuses to claim success on the
# strength of the write alone.
#
# Usage (the value is read from STDIN, never argv, so it never lands in `ps` or shell history):
#
#   ./scripts/set_alert_receiver.sh slack            # then paste the webhook URL, Enter, Ctrl-D
#   ./scripts/set_alert_receiver.sh pagerduty
#   ./scripts/set_alert_receiver.sh watchdog
#
#   # or pipe from a password manager:
#   pass show weissman/slack-webhook | ./scripts/set_alert_receiver.sh slack
#
#   ./scripts/set_alert_receiver.sh --test-only      # re-run delivery proof, change nothing
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SECRETS_DIR="${ROOT}/monitoring/secrets"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

die() { echo "error: $*" >&2; exit 1; }

am_container() {
  docker ps --filter 'label=com.docker.compose.service=alertmanager' --format '{{.Names}}' 2>/dev/null | head -1
}

# Alertmanager is deliberately NOT published to the host — only Prometheus reaches it, over the
# compose network — and it sits behind the monitoring basic-auth credential. Defaulting to
# http://127.0.0.1:9093 with no auth therefore fails twice over on a correctly deployed stack, and
# a delivery check that cannot reach Alertmanager is worse than none: it reports "inconclusive"
# for a reason that has nothing to do with whether alerts reach anyone. Discover the address.
if [[ -z "${WEISSMAN_ALERTMANAGER_URL:-}" ]]; then
  _am_ct="$(am_container || true)"
  if [[ -n "$_am_ct" ]]; then
    # `docker port` exits NON-ZERO when the port is not published — which is the normal, correct
    # state here. Under `set -e` that killed this script before its first line of output: exit 1,
    # nothing on stdout or stderr. An error path that prints nothing is worse than the error.
    _am_pub="$(docker port "$_am_ct" 9093/tcp 2>/dev/null | head -1 | sed 's/.*://' || true)"
    if [[ -n "${_am_pub:-}" ]]; then
      AM_URL="http://127.0.0.1:${_am_pub}"
    else
      _am_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$_am_ct" 2>/dev/null | awk '{print $1}' || true)"
      if [[ -n "${_am_ip:-}" ]]; then
        AM_URL="http://${_am_ip}:9093"
      fi
    fi
  fi
fi
AM_URL="${AM_URL:-http://127.0.0.1:9093}"

AM_AUTH=()
if [[ -n "${MONITORING_BASIC_AUTH_USER:-}" && -n "${MONITORING_BASIC_AUTH_PASSWORD:-}" ]]; then
  AM_AUTH=(-u "${MONITORING_BASIC_AUTH_USER}:${MONITORING_BASIC_AUTH_PASSWORD}")
fi

am_curl() { curl "${AM_AUTH[@]}" "$@"; }

if ! am_curl -sf -m 10 -o /dev/null "${AM_URL}/-/ready" 2>/dev/null; then
  die "cannot reach Alertmanager at ${AM_URL} — set WEISSMAN_ALERTMANAGER_URL, or check MONITORING_BASIC_AUTH_* in .env"
fi

# Notification counters straight from Alertmanager, so "did it deliver" is answered by
# Alertmanager itself rather than by us assuming.
notif_counts() {
  am_curl -sf -m 10 "${AM_URL}/metrics" 2>/dev/null \
    | awk '/^alertmanager_notifications_total/      {t+=$2}
           /^alertmanager_notifications_failed_total/{f+=$2}
           END {printf "%d %d", t+0, f+0}'
}

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

TARGET="${1:-}"
[[ -n "$TARGET" ]] || usage

if [[ "$TARGET" != "--test-only" ]]; then
  case "$TARGET" in
    slack)     FILE="slack_api_url";         HINT='https://hooks.slack.com/services/T.../B.../...' ;;
    pagerduty) FILE="pagerduty_routing_key"; HINT='32-character Events API v2 routing key' ;;
    watchdog)  FILE="watchdog_url";          HINT='https://... heartbeat URL (healthchecks.io, Better Uptime, ...)' ;;
    -h|--help) usage ;;
    *) die "unknown receiver '$TARGET' (expected: slack | pagerduty | watchdog)" ;;
  esac

  if [[ -t 0 ]]; then
    echo "Paste the value for ${FILE} (${HINT}), then press Enter and Ctrl-D:" >&2
  fi
  VALUE="$(cat)"
  VALUE="${VALUE//$'\n'/}"
  VALUE="${VALUE//$'\r'/}"
  [[ -n "$VALUE" ]] || die "empty value — nothing written"

  # Reject the placeholders explicitly. Writing one of these back would re-create the exact
  # condition this script exists to end, and the go-live gate would keep failing with no clue why.
  case "$VALUE" in
    *.invalid*|*example.com*|*REPLACE*|*CHANGEME*|*changeme*|*placeholder*)
      die "that value is a placeholder — alerts would still reach nobody" ;;
  esac

  # Shape checks. Cheap, and they catch the common paste error (wrong secret in the wrong slot)
  # before it becomes a silent delivery failure at 3am.
  case "$TARGET" in
    slack)
      [[ "$VALUE" == https://hooks.slack.com/* ]] \
        || die "does not look like a Slack webhook (expected https://hooks.slack.com/...)" ;;
    watchdog)
      [[ "$VALUE" == https://* || "$VALUE" == http://* ]] \
        || die "watchdog must be an http(s) URL" ;;
    pagerduty)
      [[ "${#VALUE}" -ge 20 ]] \
        || die "routing key looks too short (${#VALUE} chars; expected ~32)" ;;
  esac

  mkdir -p "$SECRETS_DIR"
  umask 077
  printf '%s' "$VALUE" > "${SECRETS_DIR}/${FILE}"
  chmod 600 "${SECRETS_DIR}/${FILE}"
  echo "wrote ${SECRETS_DIR}/${FILE} (${#VALUE} chars, mode 600)"
  unset VALUE

  CT="$(am_container)"
  if [[ -n "$CT" ]]; then
    # *_file secrets are re-read on reload, so no restart and no dropped alerts.
    if am_curl -sf -m 10 -XPOST "${AM_URL}/-/reload" >/dev/null 2>&1; then
      echo "reloaded Alertmanager"
    else
      docker kill -s HUP "$CT" >/dev/null 2>&1 && echo "reloaded Alertmanager (SIGHUP)" \
        || echo "WARN: could not reload Alertmanager — restart it to pick up the new secret" >&2
    fi
    sleep 2
  else
    echo "WARN: Alertmanager container not found — secret written but not loaded" >&2
  fi
fi

# --- Prove delivery -----------------------------------------------------------------------------
# Fire a real alert through the real pipeline and ask Alertmanager whether the notification
# succeeded. This is the step whose absence let three dead receivers look configured.
echo "--- delivery proof ---"
read -r BEFORE_T BEFORE_F <<<"$(notif_counts)"

STARTS="$(date -u -d '-1 minute' +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%S.000Z)"
ENDS="$(date -u -d '+2 minutes' +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%S.000Z)"

am_curl -sf -m 10 -XPOST "${AM_URL}/api/v2/alerts" -H 'Content-Type: application/json' -d "[{
  \"labels\": {\"alertname\":\"WeissmanAlertDeliveryTest\",\"severity\":\"critical\",\"service\":\"weissman\"},
  \"annotations\": {\"summary\":\"Synthetic test — confirms this receiver reaches a human.\"},
  \"startsAt\": \"${STARTS}\", \"endsAt\": \"${ENDS}\"
}]" >/dev/null || die "could not post a test alert to ${AM_URL}"
echo "posted synthetic alert; waiting for the notification attempt..."

DELIVERED=0
for _ in $(seq 1 15); do
  sleep 2
  read -r NOW_T NOW_F <<<"$(notif_counts)"
  if [[ "${NOW_T:-0}" -gt "${BEFORE_T:-0}" ]]; then
    if [[ "${NOW_F:-0}" -gt "${BEFORE_F:-0}" ]]; then
      echo "FAIL: Alertmanager attempted the notification and it FAILED." >&2
      CT="$(am_container)"
      [[ -n "$CT" ]] && docker logs --since 2m "$CT" 2>&1 | grep -iE 'notify|error' | tail -12 >&2
      exit 1
    fi
    DELIVERED=1
    break
  fi
done

if [[ "$DELIVERED" == "1" ]]; then
  echo "PASS: notification delivered — check the destination for 'WeissmanAlertDeliveryTest'."
  echo "      A counter that went up is Alertmanager's claim; your eyes on the Slack/PagerDuty/"
  echo "      heartbeat side are the actual confirmation. Look now."
else
  echo "INCONCLUSIVE: no notification attempt was recorded within 30s." >&2
  echo "  Most likely the alert did not match a route that uses this receiver, or it was grouped" >&2
  echo "  with an existing alert and suppressed by group_interval. Check:" >&2
  echo "    curl -u <monitoring-user>:<pass> -s ${AM_URL}/api/v2/alerts | grep WeissmanAlertDeliveryTest" >&2
  exit 1
fi
