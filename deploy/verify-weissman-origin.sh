#!/usr/bin/env bash
# Run on the VPS (SSH). Diagnoses typical Cloudflare 502 causes: dead upstream, port mismatch, www vhost.
# Usage: bash deploy/verify-weissman-origin.sh
#        REPO_ROOT=/opt/weissman bash deploy/verify-weissman-origin.sh
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-/root/weissman-bot}"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"
NGINX_SITE="${NGINX_SITE:-/etc/nginx/sites-available/weissman}"
UNIT="${UNIT:-weissman-server.service}"

echo "== Repo: $REPO_ROOT"

PORT_LINE=$(grep -E '^[[:space:]]*PORT=' "$ENV_FILE" 2>/dev/null | tail -n1 || true)
if [[ -z "${PORT_LINE}" ]]; then
  PORT=8000
  echo "== No PORT= in $ENV_FILE — assuming Rust default $PORT"
else
  PORT="${PORT_LINE#PORT=}"
  PORT="${PORT#\"}"
  PORT="${PORT%\"}"
  PORT="${PORT#\'}"
  PORT="${PORT%\'}"
  PORT="${PORT//[[:space:]]/}"
fi
echo "== Effective PORT (from .env or default): $PORT"

echo ""
echo "== systemd: $UNIT"
if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
  echo "status: active"
else
  echo "status: NOT ACTIVE — run: sudo systemctl status $UNIT"
fi

echo ""
echo "== Listener on :$PORT"
if command -v ss >/dev/null 2>&1; then
  ss -tlnp "sport = :$PORT" 2>/dev/null || true
else
  echo "(ss not installed)"
fi

echo ""
echo "== curl backend (loopback)"
curl -sS -o /dev/null -w "GET /api/health → HTTP %{http_code}\n" --connect-timeout 3 "http://127.0.0.1:${PORT}/api/health" || echo "curl failed"

echo ""
if [[ -f "$NGINX_SITE" ]]; then
  echo "== Nginx upstream lines in $NGINX_SITE"
  grep -E 'server[[:space:]]+127\.0\.0\.1:|proxy_pass[[:space:]]+http://127\.0\.0\.1:' "$NGINX_SITE" || true
  if grep -qE '127\.0\.0\.1:([0-9]+)' "$NGINX_SITE"; then
    NGINX_PORT=$(grep -oE '127\.0\.0\.1:[0-9]+' "$NGINX_SITE" | head -1 | cut -d: -f2)
    if [[ "$NGINX_PORT" != "$PORT" ]]; then
      echo "MISMATCH: Nginx points to port $NGINX_PORT but .env/default expects $PORT → 502. Run: sudo bash $REPO_ROOT/deploy/fix-weissman-502.sh"
    else
      echo "OK: Nginx upstream port matches $PORT"
    fi
  fi
  if grep -q weissmancyber.com "$NGINX_SITE" && ! grep -q www.weissmancyber.com "$NGINX_SITE"; then
    echo "WARN: Hostname www.weissmancyber.com may not match server_name → wrong vhost / 502. Add www to server_name."
  fi
else
  echo "== No file $NGINX_SITE (set NGINX_SITE= if your site lives elsewhere)"
fi

echo ""
echo "== Done."
