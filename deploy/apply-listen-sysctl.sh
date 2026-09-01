#!/usr/bin/env bash
# Apply listen-queue sysctls so Axum listen(4096) is not silently truncated.
# Safe to run repeatedly. No-op (exit 0) when not root — prints the live somaxconn.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$ROOT/deploy/sysctl.d/99-weissman-listen.conf"

current() {
  cat /proc/sys/net/core/somaxconn 2>/dev/null || echo unknown
}

if [[ "$(id -u)" -ne 0 ]]; then
  echo "WARN: not root; net.core.somaxconn=$(current) (want >=4096). Re-run with sudo."
  exit 0
fi

sysctl -w net.core.somaxconn=4096
sysctl -w net.ipv4.tcp_max_syn_backlog=4096 || true
if [[ -f "$CONF" ]]; then
  install -m 0644 "$CONF" /etc/sysctl.d/99-weissman-listen.conf
  echo "Installed $CONF → /etc/sysctl.d/99-weissman-listen.conf"
fi
echo "somaxconn=$(current)"
