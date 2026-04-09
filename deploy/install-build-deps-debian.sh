#!/usr/bin/env bash
# Debian/Ubuntu: packages required to compile weissman-server / weissman-worker (OpenSSL + native-tls).
# Run on a machine with free disk in / and /var (apt needs cache space).
# Usage: sudo bash deploy/install-build-deps-debian.sh
set -euo pipefail
if [[ "${EUID:-0}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi
apt-get update
apt-get install -y --no-install-recommends \
  build-essential \
  pkg-config \
  libssl-dev \
  libudev-dev \
  libhwloc-dev \
  curl \
  ca-certificates
echo "OK. Install Node separately if you build the frontend (e.g. apt install nodejs npm, or use nvm)."
echo "Then: . \"\$HOME/.cargo/env\" && cargo build --release -p weissman-server -p weissman-worker"
echo "And:  cd frontend && npm ci && npm run build"
