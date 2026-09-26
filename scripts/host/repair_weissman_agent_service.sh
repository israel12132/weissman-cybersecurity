#!/usr/bin/env bash
# scripts/host/repair_weissman_agent_service.sh — stop the host weissman-agent.service from
# crash-looping and bring its binary up to date with the running platform. Needs root.
#
# Background (2026-09-26 audit): the unit ran an Aug-25 build of crates/weissman-agent that
# tried http://127.0.0.1/api/agents/session (port 80) while the gateway is published on
# 127.0.0.1:8000, so it exited every ~5 s for 16 days (≈263k restarts, 1 GB of journal).
#
#   sudo scripts/host/repair_weissman_agent_service.sh            # point at :8000, refresh binary, restart
#   sudo scripts/host/repair_weissman_agent_service.sh --url http://127.0.0.1:8000
#   sudo scripts/host/repair_weissman_agent_service.sh --disable  # this host does not need an agent
#
# Safe to re-run. Never prints the enrollment token.
set -euo pipefail

UNIT=weissman-agent.service
DROPIN_DIR=/etc/systemd/system/${UNIT}.d
BIN_DIR=/opt/weissman/agent
URL="${WEISSMAN_SERVER_URL:-http://127.0.0.1:8000}"
BACKEND_CONTAINER="${WEISSMAN_BACKEND_CONTAINER:-weissman-cybersecurity-backend-1}"
MODE=repair

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --disable) MODE=disable; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "run with sudo (needs systemctl + /etc/systemd + $BIN_DIR)" >&2; exit 1; }
systemctl cat "$UNIT" >/dev/null 2>&1 || { echo "$UNIT is not installed on this host — nothing to do"; exit 0; }

echo "== $UNIT before =="
systemctl show "$UNIT" -p ActiveState -p SubState -p NRestarts -p ExecMainStartTimestamp | sed 's/^/   /'

if [[ "$MODE" == disable ]]; then
  systemctl disable --now "$UNIT"
  systemctl reset-failed "$UNIT" 2>/dev/null || true
  echo "== $UNIT disabled and stopped =="
else
  # 1) Point the agent at the published gateway via a drop-in (the unit file itself is untouched).
  mkdir -p "$DROPIN_DIR"
  cat > "$DROPIN_DIR/10-server-url.conf" <<CONF
# Written by scripts/host/repair_weissman_agent_service.sh — the gateway is published on
# 127.0.0.1:8000 (WEISSMAN_GATEWAY_BIND/PORT in .env), not on :80.
[Service]
Environment=WEISSMAN_SERVER_URL=${URL}
# Back off instead of hammering a gateway that is down/updating.
RestartSec=30
CONF

  # 2) Refresh the binary from the platform image that is actually running (same code as the
  #    server it talks to). The backend image ships the agent at /srv/bin/agents/<arch>/.
  if command -v docker >/dev/null 2>&1 && docker inspect "$BACKEND_CONTAINER" >/dev/null 2>&1; then
    arch="$(uname -m)"; case "$arch" in x86_64) dir=linux-x86_64-gnu ;; aarch64) dir=linux-aarch64-gnu ;; *) dir="" ;; esac
    if [[ -n "$dir" ]] && docker exec "$BACKEND_CONTAINER" test -x "/srv/bin/agents/$dir/weissman-agent" 2>/dev/null; then
      mkdir -p "$BIN_DIR"
      docker cp "$BACKEND_CONTAINER:/srv/bin/agents/$dir/weissman-agent" "$BIN_DIR/weissman-agent.new"
      chmod 0755 "$BIN_DIR/weissman-agent.new"
      mv -f "$BIN_DIR/weissman-agent.new" "$BIN_DIR/weissman-agent"
      echo "== agent binary refreshed from $BACKEND_CONTAINER ($dir): $(stat -c '%y' "$BIN_DIR/weissman-agent") =="
    else
      echo "!! could not find a matching agent binary in $BACKEND_CONTAINER — keeping the installed one" >&2
    fi
  else
    echo "!! docker/$BACKEND_CONTAINER not reachable — keeping the installed binary" >&2
  fi

  systemctl daemon-reload
  systemctl reset-failed "$UNIT" 2>/dev/null || true
  systemctl restart "$UNIT"
  sleep 8
  echo "== $UNIT after =="
  systemctl show "$UNIT" -p ActiveState -p SubState -p NRestarts | sed 's/^/   /'
  journalctl -u "$UNIT" -n 5 --no-pager -o cat | sed -E 's/(token|secret)[^ ]*/\1 ***/Ig; s/^/   /' || true
fi

# 3) Reclaim the crash-loop journal (keeps the last 200 MB / 14 days of everything).
journalctl --vacuum-size=200M --vacuum-time=14d >/dev/null 2>&1 || true
echo "== journal now: $(journalctl --disk-usage 2>/dev/null | sed -E 's/.*take up //; s/ in the.*//') =="
