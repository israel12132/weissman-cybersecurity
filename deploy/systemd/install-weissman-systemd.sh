#!/usr/bin/env bash
# Install or upgrade Weissman systemd units (production).
# Run on the server: sudo bash deploy/systemd/install-weissman-systemd.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/weissman/app}"
ENV_DIR="${ENV_DIR:-/etc/weissman}"
SERVICE_USER="${SERVICE_USER:-weissman}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_FRONTEND="${SKIP_FRONTEND:-0}"

die() { echo "ERROR: $*" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || die "Run as root (sudo)"

command -v systemctl >/dev/null 2>&1 || die "systemd not found"

echo "[*] Repo:          $REPO_ROOT"
echo "[*] Install to:    $INSTALL_ROOT"
echo "[*] Service user:  $SERVICE_USER"

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  echo "[*] Creating system user $SERVICE_USER"
  useradd --system --home-dir "$INSTALL_ROOT" --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" || true
fi

mkdir -p "$INSTALL_ROOT/bin" "$INSTALL_ROOT/frontend/dist" "$ENV_DIR"

if [[ "$SKIP_BUILD" != "1" ]]; then
  command -v cargo >/dev/null 2>&1 || die "cargo not found — install Rust or SKIP_BUILD=1 with binaries in $INSTALL_ROOT/bin/"
  echo "[*] cargo build --release (weissman-server, weissman-worker)"
  (cd "$REPO_ROOT" && cargo build --release -p weissman-server -p weissman-worker)
  install -o root -g root -m 0755 "$REPO_ROOT/target/release/weissman-server" "$INSTALL_ROOT/bin/weissman-server"
  install -o root -g root -m 0755 "$REPO_ROOT/target/release/weissman-worker" "$INSTALL_ROOT/bin/weissman-worker"
else
  echo "[*] SKIP_BUILD=1 — expecting binaries in $INSTALL_ROOT/bin/"
  [[ -x "$INSTALL_ROOT/bin/weissman-server" ]] || die "missing $INSTALL_ROOT/bin/weissman-server"
  [[ -x "$INSTALL_ROOT/bin/weissman-worker" ]] || die "missing $INSTALL_ROOT/bin/weissman-worker"
fi

if [[ "$SKIP_FRONTEND" != "1" ]]; then
  if command -v npm >/dev/null 2>&1; then
    echo "[*] npm run build (frontend)"
    (cd "$REPO_ROOT/frontend" && npm ci && npm run build)
    rsync -a --delete "$REPO_ROOT/frontend/dist/" "$INSTALL_ROOT/frontend/dist/"
  else
    echo "[!] npm not found — copy $REPO_ROOT/frontend/dist/ to $INSTALL_ROOT/frontend/dist/ after building elsewhere"
  fi
else
  echo "[*] SKIP_FRONTEND=1 — leaving $INSTALL_ROOT/frontend/dist unchanged"
fi

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_ROOT"

UNIT_SRC="$REPO_ROOT/deploy/systemd"
for u in weissman-server.service weissman-worker.service weissman.target; do
  [[ -f "$UNIT_SRC/$u" ]] || die "missing $UNIT_SRC/$u"
  sed -e "s|/opt/weissman/app|$INSTALL_ROOT|g" "$UNIT_SRC/$u" >"/etc/systemd/system/$u.tmp"
  install -o root -g root -m 0644 "/etc/systemd/system/$u.tmp" "/etc/systemd/system/$u"
  rm -f "/etc/systemd/system/$u.tmp"
done

ENV_EXAMPLE="$UNIT_SRC/weissman.env.example"
[[ -f "$ENV_EXAMPLE" ]] || die "missing $ENV_EXAMPLE"
ENV_CREATED=0
if [[ ! -f "$ENV_DIR/weissman.env" ]]; then
  install -o root -g root -m 0600 "$ENV_EXAMPLE" "$ENV_DIR/weissman.env"
  ENV_CREATED=1
fi

systemctl daemon-reload

if [[ "$ENV_CREATED" -eq 1 ]]; then
  echo ""
  echo "[!] Created $ENV_DIR/weissman.env — set DATABASE_URL, WEISSMAN_JWT_SECRET, WEISSMAN_COOKIE_SECURE=1, PORT, then:"
  echo "    sudo systemctl enable --now weissman-server weissman-worker weissman.target"
  echo "    journalctl -u weissman-server -f"
  exit 0
fi

echo ""
echo "[*] Units installed. Start or restart:"
echo "    sudo systemctl enable --now weissman-server weissman-worker weissman.target"
echo "    sudo systemctl restart weissman-server weissman-worker"
echo "    journalctl -u weissman-server -f"
echo "    journalctl -u weissman-worker -f"
