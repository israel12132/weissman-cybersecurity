#!/usr/bin/env bash
# Sync Nginx upstream with weissman-server PORT from .env; validate binary + listeners; surface FATAL logs.
# Run on the Ubuntu server: sudo bash deploy/fix-weissman-502.sh
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-/root/weissman-bot}"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"
NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/weissman}"
UNIT="${UNIT:-weissman-server.service}"

if [[ "${EUID:-0}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing env file: $ENV_FILE" >&2
  exit 1
fi

# PORT=8080 or PORT="8080"
PORT_LINE=$(grep -E '^[[:space:]]*PORT=' "$ENV_FILE" | tail -n1 || true)
if [[ -z "${PORT_LINE}" ]]; then
  echo "No PORT= line in $ENV_FILE; weissman-server defaults to 8000 in code." >&2
  PORT=8000
else
  PORT="${PORT_LINE#PORT=}"
  PORT="${PORT#\"}"
  PORT="${PORT%\"}"
  PORT="${PORT#\'}"
  PORT="${PORT%\'}"
  PORT="${PORT//[[:space:]]/}"
fi

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; then
  echo "Invalid PORT extracted: ${PORT:-<empty>}" >&2
  exit 1
fi

echo "== Using PORT=$PORT from $ENV_FILE"

if [[ ! -f "$NGINX_SITE" ]]; then
  echo "Missing Nginx site: $NGINX_SITE" >&2
  exit 1
fi

cp -a "$NGINX_SITE" "${NGINX_SITE}.bak.$(date +%Y%m%d%H%M%S)"

# Upstream block: server 127.0.0.1:NNNN;
sed -i -E "s/(server[[:space:]]+127\.0\.0\.1:)[0-9]+;/\1${PORT};/" "$NGINX_SITE"

# Inline proxy_pass (if present instead of upstream name)
sed -i -E "s|proxy_pass[[:space:]]+http://127\.0\.0\.1:[0-9]+/?;|proxy_pass http://127.0.0.1:${PORT};|g" "$NGINX_SITE"

if grep -qE 'server_name[[:space:]]+[^;]*weissmancyber\.com' "$NGINX_SITE" 2>/dev/null; then
  if ! grep -qE 'www\.weissmancyber\.com' "$NGINX_SITE" 2>/dev/null; then
    echo "WARN: $NGINX_SITE has weissmancyber.com but not www.weissmancyber.com — browsers using www.* get the wrong vhost → 502. Add www to server_name or copy deploy/nginx-weissman.conf." >&2
  fi
fi

nginx -t
systemctl reload nginx
echo "== Nginx reloaded (upstream -> 127.0.0.1:${PORT})"

echo ""
echo "== Listening on PORT (expect weissman-server)"
ss -tlnp "sport = :${PORT}" || true

echo ""
echo "== systemd ExecStart + fragment paths"
systemctl cat "$UNIT" 2>/dev/null || { echo "Unit $UNIT not found." >&2; exit 1; }

EXEC_START=$(systemctl show "$UNIT" -p ExecStart --value 2>/dev/null || true)
# ExecStart may be argv0; take first path-like token ending in weissman-server
BIN=""
for tok in $EXEC_START; do
  if [[ "$tok" == *weissman-server ]] && [[ -f "$tok" ]]; then
    BIN="$tok"
    break
  fi
done
if [[ -z "$BIN" ]]; then
  echo "Could not resolve weissman-server binary from ExecStart; check manually:" >&2
  echo "  $EXEC_START" >&2
else
  if [[ -x "$BIN" ]]; then
    echo "ExecStart binary OK: $BIN"
  else
    echo "ExecStart path exists but not executable: $BIN" >&2
    exit 1
  fi
fi

RESULT_BIN="$REPO_ROOT/result/bin/weissman-server"
if [[ -f "$RESULT_BIN" ]]; then
  echo "Nix result binary present: $RESULT_BIN"
  if [[ -n "$BIN" ]] && [[ "$(readlink -f "$BIN" 2>/dev/null)" != "$(readlink -f "$RESULT_BIN" 2>/dev/null)" ]]; then
    echo "NOTE: ExecStart binary path differs from $RESULT_BIN (may be intentional if using another profile)." >&2
  fi
else
  echo "NOTE: $RESULT_BIN not found (run nix build in $REPO_ROOT if you expect it)." >&2
fi

echo ""
echo "== Recent FATAL / panic / Panic (weissman-server)"
journalctl -u weissman-server -n 400 --no-pager 2>/dev/null | grep -E 'FATAL|Panic|panicked|thread.*panicked' || echo "(no matches in last 400 lines)"

echo ""
echo "== curl backend (loopback)"
curl -sS -o /dev/null -w "HTTP %{http_code}\n" --connect-timeout 2 "http://127.0.0.1:${PORT}/" || echo "curl failed (server down or wrong port)"

echo ""
echo "Done."
