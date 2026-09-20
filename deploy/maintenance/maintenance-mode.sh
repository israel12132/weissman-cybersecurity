#!/usr/bin/env bash
# deploy/maintenance/maintenance-mode.sh — OPTIONAL, OPT-IN maintenance flag.
#
# The maintenance page itself is AUTOMATIC: every gateway layer serves it whenever the
# origin cannot answer (502/504/connection failure) and stops the moment the origin
# answers again; the page polls /api/health and reloads on 200. Nothing here is needed
# for that. This flag exists only for ANNOUNCED windows: it writes status.json, which
# the page reads to show "Planned maintenance", the reason and "Expected back by".
# Gateway layers MAY additionally read the flag file to serve the page early
# (before the origin goes away); by default it is OFF and nothing depends on it.
#
#   maintenance-mode.sh on [--reason TEXT] [--until ISO-8601]   announce a window
#   maintenance-mode.sh off                                      clear it
#   maintenance-mode.sh status [--json]                          show the state (exit 0)
#   maintenance-mode.sh is-on                                    exit 0 if on, 1 if off
#
# State directory: $WEISSMAN_MAINTENANCE_STATE_DIR (default: ./state next to this
# script). Files: maintenance.on (flag), status.json (served at /maintenance/status.json).
# --until: ISO-8601 with an offset or Z (2026-09-27T04:00:00+03:00) is stored as given.
# A value WITHOUT an offset ("2026-09-27 04:00") is read as Israel time — the page shows the
# ETA in Israel time, and a VPS clock is usually UTC — override with WEISSMAN_MAINTENANCE_TZ.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${WEISSMAN_MAINTENANCE_STATE_DIR:-$SELF_DIR/state}"
FLAG="$STATE_DIR/maintenance.on"
STATUS="$STATE_DIR/status.json"

usage() {
  sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

die() { echo "maintenance-mode: $*" >&2; exit 2; }

# Minimal JSON string escaping (backslash, quote, control characters).
json_escape() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\r'/}
  s=${s//$'\n'/ }
  s=${s//$'\t'/ }
  printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037'
}

# Accept an ISO-8601 instant as-is; otherwise let GNU date parse it (e.g. "2026-09-27 04:00").
# The bare form is read in Israel time, not the host's zone: an operator types the hour the
# page will display, and a VPS clock is almost always UTC — read there, "04:00" would be
# announced as "07:00 Israel time", three hours late (measured). The zone must exist in the
# host's tzdata; GNU date silently falls back to UTC for an unknown TZ, which is exactly the
# wrong ETA this guards against.
normalize_until() {
  local u=$1 tz="${WEISSMAN_MAINTENANCE_TZ:-Asia/Jerusalem}"
  if [[ $u =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(:[0-9]{2})?(Z|[+-][0-9]{2}:?[0-9]{2})$ ]]; then
    printf '%s' "$u"; return 0
  fi
  [[ -f "/usr/share/zoneinfo/$tz" ]] || die "time zone '$tz' is not installed (tzdata) — pass --until with an offset, e.g. 2026-09-27T04:00:00+03:00"
  if out=$(TZ="$tz" date -d "$u" '+%Y-%m-%dT%H:%M:%S%:z' 2>/dev/null); then
    printf '%s' "$out"; return 0
  fi
  die "--until must be ISO-8601 (e.g. 2026-09-27T04:00:00+03:00), got: $u"
}

cmd_on() {
  local reason="" until=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --reason) [ $# -ge 2 ] || die "--reason needs a value"; reason=$2; shift 2 ;;
      --reason=*) reason=${1#--reason=}; shift ;;
      --until) [ $# -ge 2 ] || die "--until needs a value"; until=$2; shift 2 ;;
      --until=*) until=${1#--until=}; shift ;;
      *) die "unknown option for 'on': $1" ;;
    esac
  done
  [ -n "$until" ] && until=$(normalize_until "$until")
  mkdir -p "$STATE_DIR"
  local since reason_json until_json tmp
  since=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  if [ -n "$reason" ]; then reason_json="\"$(json_escape "$reason")\""; else reason_json=null; fi
  if [ -n "$until" ]; then until_json="\"$(json_escape "$until")\""; else until_json=null; fi
  tmp="$STATUS.tmp.$$"
  printf '{\n  "mode": "planned",\n  "reason": %s,\n  "until": %s,\n  "since": "%s"\n}\n' \
    "$reason_json" "$until_json" "$since" > "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$STATUS"
  printf '%s\n' "$since" > "$FLAG"
  echo "maintenance flag: ON  ($FLAG)"
  echo "status.json:      $STATUS"
  [ -n "$reason" ] && echo "reason:           $reason"
  [ -n "$until" ] && echo "until:            $until"
  echo "note: the page shows automatically whenever the origin is out; this flag only announces the window."
}

cmd_off() {
  rm -f "$FLAG" "$STATUS"
  echo "maintenance flag: OFF (announcement cleared)"
}

cmd_status() {
  local json=0
  [ "${1:-}" = "--json" ] && json=1
  if [ -f "$FLAG" ]; then
    if [ $json -eq 1 ]; then
      if [ -f "$STATUS" ]; then cat "$STATUS"; else printf '{"mode":"planned"}\n'; fi
    else
      echo "maintenance flag: ON  (since $(head -n1 "$FLAG" 2>/dev/null || echo '?'))"
      echo "state dir:        $STATE_DIR"
      [ -f "$STATUS" ] && { echo "status.json:"; sed 's/^/  /' "$STATUS"; } || true
    fi
  else
    if [ $json -eq 1 ]; then printf '{"mode":"off"}\n'; else
      echo "maintenance flag: OFF (page appears automatically only while the origin is out)"
      echo "state dir:        $STATE_DIR"
    fi
  fi
}

case "${1:-}" in
  on) shift; cmd_on "$@" ;;
  off) cmd_off ;;
  status) shift; cmd_status "$@" ;;
  is-on) [ -f "$FLAG" ] ;;
  -h|--help|help|"") usage; [ -n "${1:-}" ] || exit 2 ;;
  *) die "unknown command: $1 (try --help)" ;;
esac
