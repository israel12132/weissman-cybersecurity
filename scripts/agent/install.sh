#!/usr/bin/env bash
# Weissman Endpoint Agent — single-command installer for Linux / macOS.
#
# Usage (paste from the dashboard):
#   curl -sSL https://<server>/install/agent.sh | WEISSMAN_TOKEN=... WEISSMAN_SERVER=https://<server> bash
#
# What this script does:
#   1. Verifies environment variables are present.
#   2. Picks the right binary for the host arch.
#   3. Downloads, verifies SHA-256, and installs to /opt/weissman/agent.
#   4. Creates a systemd unit (Linux) or launchd plist (macOS).
#   5. Performs initial enrollment using WEISSMAN_TOKEN, then starts the service.

set -euo pipefail

REQUIRED=("WEISSMAN_TOKEN" "WEISSMAN_SERVER")
for var in "${REQUIRED[@]}"; do
    if [ -z "${!var:-}" ]; then
        echo "[weissman-agent] Missing required env var: $var" >&2
        exit 1
    fi
done

ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$ARCH" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) echo "[weissman-agent] unsupported arch '$ARCH'" >&2; exit 1 ;;
esac
case "$OS" in
    linux) PLATFORM="linux-${ARCH}-gnu" ;;
    darwin) PLATFORM="macos-${ARCH}" ;;
    *) echo "[weissman-agent] unsupported OS '$OS'" >&2; exit 1 ;;
esac

INSTALL_DIR=${WEISSMAN_INSTALL_DIR:-/opt/weissman}
BIN_DIR="${INSTALL_DIR}/agent"
BIN_PATH="${BIN_DIR}/weissman-agent"
mkdir -p "${BIN_DIR}"

BASE_URL="${WEISSMAN_SERVER%/}/install/binaries/${PLATFORM}"
echo "[weissman-agent] downloading ${BASE_URL}/weissman-agent"
curl -sSL --fail "${BASE_URL}/weissman-agent" -o "${BIN_PATH}.tmp"
EXPECTED_SHA=$(curl -sSL --fail "${BASE_URL}/weissman-agent.sha256" | awk '{print $1}')
ACTUAL_SHA=$(sha256sum "${BIN_PATH}.tmp" 2>/dev/null | awk '{print $1}')
if [ -z "${ACTUAL_SHA}" ]; then
    ACTUAL_SHA=$(shasum -a 256 "${BIN_PATH}.tmp" | awk '{print $1}')
fi
if [ "${EXPECTED_SHA}" != "${ACTUAL_SHA}" ]; then
    echo "[weissman-agent] SHA-256 mismatch (expected ${EXPECTED_SHA}, got ${ACTUAL_SHA})" >&2
    rm -f "${BIN_PATH}.tmp"
    exit 2
fi
mv "${BIN_PATH}.tmp" "${BIN_PATH}"
chmod 0755 "${BIN_PATH}"

# Verify it can enroll before installing the service.
ENROLL_OUT=$("${BIN_PATH}" \
    --server-url "${WEISSMAN_SERVER}" \
    --enrollment-token "${WEISSMAN_TOKEN}" \
    --enroll-only 2>/dev/null || true)
if [ -z "${ENROLL_OUT}" ]; then
    echo "[weissman-agent] enrollment failed (check token + WEISSMAN_SERVER)" >&2
    exit 3
fi

ENV_FILE="${INSTALL_DIR}/agent.env"
umask 077
cat > "${ENV_FILE}" <<EOF
WEISSMAN_SERVER_URL=${WEISSMAN_SERVER}
WEISSMAN_ENROLLMENT_TOKEN=${WEISSMAN_TOKEN}
RUST_LOG=info
EOF
chmod 600 "${ENV_FILE}"

if [ "${OS}" = "linux" ]; then
    UNIT=/etc/systemd/system/weissman-agent.service
    cat > "${UNIT}" <<UNIT_EOF
[Unit]
Description=Weissman Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
ExecStart=${BIN_PATH}
Restart=always
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT_EOF
    systemctl daemon-reload
    systemctl enable --now weissman-agent.service
    echo "[weissman-agent] installed and started via systemd"
elif [ "${OS}" = "darwin" ]; then
    PLIST=/Library/LaunchDaemons/io.weissman.agent.plist
    cat > "${PLIST}" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>io.weissman.agent</string>
<key>ProgramArguments</key><array><string>${BIN_PATH}</string></array>
<key>EnvironmentVariables</key><dict>
<key>WEISSMAN_SERVER_URL</key><string>${WEISSMAN_SERVER}</string>
<key>WEISSMAN_ENROLLMENT_TOKEN</key><string>${WEISSMAN_TOKEN}</string>
</dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
</dict></plist>
PLIST_EOF
    launchctl unload "${PLIST}" 2>/dev/null || true
    launchctl load -w "${PLIST}"
    echo "[weissman-agent] installed and started via launchd"
fi

echo "[weissman-agent] online — verify in the dashboard under Agents."
